//! Section merging and layout for single-object linking.
//!
//! Architecture-specific relocation logic lives in parallel modules:
//! - x86_64: x86_64.rs
//! - aarch64: aarch64.rs
//! - riscv: riscv.rs

#![allow(dead_code)]

mod aarch64;
mod dynamic;
mod gc;
pub mod macho;
mod merge;
mod notes;
mod pie;
pub mod resolver;
mod riscv;
mod runtime;
mod symbols;
mod x86_64;

use crate::collections::{HashMap, HashSet};
pub use dynamic::DynamicLinkInfo;
use dynamic::{
    DynamicAddrs, build_dynamic_section_content, build_dynamic_sections, build_plt_got_x86_64,
};
pub(crate) use merge::segment_class;
pub use merge::{
    MergedLayout, MergedSection, ObjectSectionContrib, merge_sections_multi_object,
    merge_sections_single_object,
};
use merge::{align_up, is_allocatable, reserve_start_section};
pub use resolver::LibraryResolver;
pub use symbols::OutputSymbol;
use symbols::{
    collect_gotpcrel_symbol_names, collect_output_symbols, parse_symtab_view,
    resolve_symbols_for_object, symbol_names_by_index,
};

use crate::{
    arch::TargetArch,
    elf::{
        Elf64Header, SectionHeader, Symbol, get_strtab_from_section, get_strtab_string,
        parse_elf64_slice, parse_rela_section, parse_symtab,
    },
    platform::TargetPlatform,
};
use std::path::PathBuf;

/// Pre-parsed object for reuse in multi-object linking.
pub struct ParsedObject {
    pub data: Vec<u8>,
    pub header: Elf64Header,
    pub sections: Vec<SectionHeader>,
    pub names: Vec<String>,
}

/// Parse an ELF64 object's header, section headers, and section names.
fn parse_object(data: Vec<u8>) -> Result<ParsedObject, String> {
    let (header, sections, names) = parse_elf64_slice(&data)?;
    if header.e_type == 1 && names.iter().any(|name| name.starts_with(".gnu.lto_")) {
        return Err("GCC LTO is not supported".into());
    }
    Ok(ParsedObject {
        data,
        header,
        sections,
        names,
    })
}

const SHN_UNDEF: u16 = 0;
const SHN_ABS: u16 = 0xfff1;
const SHN_COMMON: u16 = 0xfff2;
const STB_LOCAL: u8 = 0;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;

const SHF_ALLOC: u64 = 2;
const SHF_EXECINSTR: u64 = 4;
const SHF_WRITE: u64 = 1;
const SHT_PROGBITS: u32 = 1;
const SHT_NOBITS: u32 = 8;
const SHT_SYMTAB: u32 = 2;

#[derive(Debug)]
pub struct LinkResult {
    pub symbols: Vec<OutputSymbol>,
    pub layout: MergedLayout,
    pub e_machine: u16,
    pub symbol_addrs: HashMap<String, u64>,
    pub dynamic: Option<DynamicLinkInfo>,
}

/// Fully link a single ELF64 object: merge sections, resolve symbols, and
/// apply relocations.
pub fn link_single_object(data: &[u8]) -> Result<LinkResult, String> {
    let object = parse_object(data.to_vec())?;
    link_multi_object_parsed(&LinkOptions::default(), &mut [object], None)
}

/// Link settings that come from the command line rather than the objects.
#[derive(Debug, Default, Clone)]
pub struct LinkOptions {
    pub pie: bool,
    pub build_id: bool,
    pub static_link: bool,
    /// `ld --dynamic-linker`.
    pub interpreter: Option<String>,
    /// `ld -L`.
    pub search_paths: Vec<PathBuf>,
    /// `ld -rpath`, joined into one `DT_RUNPATH`.
    pub rpaths: Vec<String>,
    pub library_as_needed: Vec<bool>,
    pub library_positions: Vec<usize>,
    pub object_positions: Vec<usize>,
    pub gc_sections: bool,
    pub gc_roots: Vec<String>,
}

/// Links ELF64 objects with `LinkOptions::default()`. `libs` names the libraries to
/// resolve. Unless `static_link` is set, an x86_64 link that names a shared library
/// (or `c` / `System`) gets PLT and GOT entries for its undefined symbols.
pub fn link_multi_object(objects: &[&[u8]], libs: Option<&[String]>) -> Result<LinkResult, String> {
    link_multi_object_with_options(objects, libs, &LinkOptions::default())
}

pub fn link_multi_object_with_options(
    objects: &[&[u8]],
    libs: Option<&[String]>,
    opts: &LinkOptions,
) -> Result<LinkResult, String> {
    link_elf_objects(objects.iter().map(|s| s.to_vec()).collect(), libs, opts)
}

pub fn link_elf_objects(
    objects: Vec<Vec<u8>>,
    libs: Option<&[String]>,
    opts: &LinkOptions,
) -> Result<LinkResult, String> {
    if objects.is_empty() {
        return Err("no objects to link".into());
    }
    if objects.len() == 1
        && libs.is_none()
        && !opts.gc_sections
        && !opts.pie
        && !opts.static_link
        && !opts.build_id
    {
        return link_single_object(&objects[0]);
    }
    let mut timer = crate::timing::PhaseTimer::new();
    let parsed_results = crate::parallel::map(objects, parse_object);
    let mut parsed: Vec<_> = parsed_results.into_iter().collect::<Result<_, _>>()?;

    timer.mark("parse objects");
    if opts.gc_sections {
        gc::collect(&mut parsed, &opts.gc_roots)?;
        for obj in &mut parsed {
            for (i, section) in obj.sections.iter().enumerate() {
                let offset = obj.header.e_shoff as usize + i * 64;
                obj.data[offset + 8..offset + 16].copy_from_slice(&section.sh_flags.to_le_bytes());
                obj.data[offset + 24..offset + 32]
                    .copy_from_slice(&section.sh_offset.to_le_bytes());
                obj.data[offset + 32..offset + 40].copy_from_slice(&section.sh_size.to_le_bytes());
            }
        }
    }
    link_multi_object_parsed(opts, &mut parsed, libs)
}

fn link_multi_object_parsed(
    opts: &LinkOptions,
    parsed: &mut [ParsedObject],
    libs: Option<&[String]>,
) -> Result<LinkResult, String> {
    if parsed.is_empty() {
        return Err("no objects to link".to_string());
    }

    if opts.static_link {
        if opts.pie {
            return Err("static PIE is not supported".into());
        }
        for obj in parsed.iter() {
            if obj.header.e_type != 1 {
                return Err(
                    "static links require ELF relocatable inputs; shared objects are not supported"
                        .into(),
                );
            }
            if let Some((index, _)) = obj
                .sections
                .iter()
                .enumerate()
                .find(|(_, section)| section.sh_flags & 0x400 != 0 && section.sh_size != 0)
            {
                return Err(format!(
                    "static TLS is not supported (section {}); static glibc requires TLS layout, PT_TLS and thread-pointer relocations",
                    obj.names[index]
                ));
            }
            if let Some((symbols, strings)) = parse_symtab_view(&obj.data, &obj.sections)?
                && let Some(symbol) = symbols
                    .iter()
                    .find(|symbol| symbol.sym_type == 10 && symbol.st_shndx != SHN_UNDEF)
            {
                let name = get_strtab_string(strings, symbol.name_offset).unwrap_or_default();
                return Err(format!(
                    "static GNU IFUNC is not supported: {name}; resolver calls require IRELATIVE relocations and startup relocation tables"
                ));
            }
        }
    }
    let mut timer = crate::timing::PhaseTimer::new();
    let objects: Vec<&[u8]> = parsed.iter().map(|p| p.data.as_slice()).collect();
    let (mut layout, section_contribs, common_offsets) = merge_sections_multi_object(&objects)?;
    notes::merge_properties(&mut layout, parsed)?;
    merge::remap_merge_offsets(parsed, &section_contribs)?;
    let e_machine = parsed[0].header.e_machine;
    let arch = TargetArch::from_elf_machine(e_machine)
        .ok_or_else(|| format!("unsupported machine {}", e_machine))?;

    if opts.pie {
        let base = arch.page_align();
        for section in &mut layout.sections {
            section.vaddr = section.vaddr - 0x400000 + base;
        }
    }

    timer.mark("merge sections");
    let mut global_symbols: HashMap<String, u64> = HashMap::default();
    let mut resolved_by_index_per_object: Vec<Vec<Option<u64>>> = Vec::with_capacity(parsed.len());

    let resolutions =
        crate::parallel::map(parsed.iter().enumerate().collect(), |(obj_idx, obj)| {
            resolve_symbols_for_object(
                &obj.data,
                &layout,
                &obj.sections,
                &obj.names,
                &section_contribs[obj_idx],
                &common_offsets,
            )
        });
    let mut strong_definitions: HashSet<String> = HashSet::default();
    for resolution in resolutions {
        let (resolved, by_index) = resolution?;
        resolved_by_index_per_object.push(by_index);

        for (name, r) in resolved {
            let Some(addr) = r.address else {
                continue;
            };
            if r.is_weak {
                global_symbols.entry(name).or_insert(addr);
            } else if !strong_definitions.insert(name.clone()) {
                return Err(format!("multiple definition of {name}"));
            } else {
                global_symbols.insert(name, addr);
            }
        }
    }

    timer.mark("resolve symbols");
    let mut dynamic_info: Option<DynamicLinkInfo> = None;

    // Resolve library names to sonames.  Any lib matching "c" or "System"
    // (legacy names) as well as any library the resolver can locate as a
    // shared object triggers PLT generation.
    let mut resolver = LibraryResolver::new(arch, TargetPlatform::current());
    for path in opts.search_paths.iter().rev() {
        resolver.add_path(path.clone());
    }
    let has_shared_lib = !opts.static_link
        && libs
            .map(|l| {
                l.iter().any(|x| {
                    if x == "c" || x == "System" {
                        return true;
                    }
                    resolver.resolve(x).map(|r| !r.is_static).unwrap_or(false)
                })
            })
            .unwrap_or(false);

    if has_shared_lib && arch == TargetArch::X86_64 && e_machine == 62 {
        let mut undefined: Vec<String> = Vec::new();
        let mut undefined_seen = HashSet::default();
        for obj in parsed.iter() {
            let Some((symbols, strtab)) = parse_symtab_view(&obj.data, &obj.sections)? else {
                continue;
            };
            let referenced = if opts.gc_sections {
                referenced_symbols(obj)?
            } else {
                HashSet::default()
            };
            for (index, sym) in symbols.iter().enumerate().filter(|(_, sym)| {
                sym.st_shndx == SHN_UNDEF && matches!(sym.bind, STB_GLOBAL | STB_WEAK)
            }) {
                if opts.gc_sections && !referenced.contains(&index) {
                    continue;
                }
                let Some(name) = get_strtab_string(strtab, sym.name_offset) else {
                    continue;
                };
                if !name.is_empty()
                    && name != "_GLOBAL_OFFSET_TABLE_"
                    && !global_symbols.contains_key(&name)
                    && undefined_seen.insert(name.clone())
                {
                    undefined.push(name);
                }
            }
        }
        // Synthetic _start leaves through libc exit(), so it needs a PLT entry.
        if !global_symbols.contains_key("_start") && !undefined.iter().any(|s| s == "exit") {
            undefined.push("exit".to_string());
        }

        let needed = select_needed_libraries(parsed, libs.unwrap_or(&[]), opts, &resolver)?;
        if !needed.is_empty() {
            let (plt_data, got_plt_data) = build_plt_got_x86_64(&undefined, &layout)?;
            let last = layout.sections.last().ok_or("no sections")?;
            let mut vaddr = align_up(last.vaddr + last.data.len() as u64, 16);

            let plt_vaddr = vaddr;
            layout.sections.push(MergedSection {
                entsize: 0,
                sh_type: 1,
                name: ".plt".into(),
                data: plt_data,
                vaddr: plt_vaddr,
                flags: SHF_ALLOC | SHF_EXECINSTR,
                align: 16,
            });
            layout
                .section_by_name
                .insert(".plt".into(), layout.sections.len() - 1);
            vaddr = align_up(vaddr + layout.sections.last().unwrap().data.len() as u64, 8);

            let got_plt_vaddr = vaddr;
            layout.sections.push(MergedSection {
                entsize: 0,
                sh_type: 1,
                name: ".got.plt".into(),
                data: got_plt_data,
                vaddr: got_plt_vaddr,
                flags: SHF_ALLOC | SHF_WRITE,
                align: 8,
            });
            layout
                .section_by_name
                .insert(".got.plt".into(), layout.sections.len() - 1);
            global_symbols
                .entry("_GLOBAL_OFFSET_TABLE_".to_string())
                .or_insert(got_plt_vaddr);
            let got_plt_size = 24 + (undefined.len() as u64) * 8;
            vaddr = align_up(got_plt_vaddr + got_plt_size, 8);

            let (
                dynsym_data,
                dynstr_data,
                rela_plt_data,
                hash_data,
                needed_offsets,
                runpath_offset,
            ) = build_dynamic_sections(&undefined, got_plt_vaddr, &needed, &opts.rpaths)?;
            let dynsym_vaddr = vaddr;
            let dynsym_size = dynsym_data.len() as u64;
            layout.sections.push(MergedSection {
                entsize: 0,
                sh_type: 1,
                name: ".dynsym".into(),
                data: dynsym_data,
                vaddr: dynsym_vaddr,
                flags: SHF_ALLOC,
                align: 8,
            });
            layout
                .section_by_name
                .insert(".dynsym".into(), layout.sections.len() - 1);
            vaddr = align_up(vaddr + dynsym_size, 8);

            let dynstr_vaddr = vaddr;
            let dynstr_size = dynstr_data.len() as u64;
            layout.sections.push(MergedSection {
                entsize: 0,
                sh_type: 1,
                name: ".dynstr".into(),
                data: dynstr_data,
                vaddr: dynstr_vaddr,
                flags: SHF_ALLOC,
                align: 1,
            });
            layout
                .section_by_name
                .insert(".dynstr".into(), layout.sections.len() - 1);
            vaddr = align_up(vaddr + dynstr_size, 8);

            let rela_plt_vaddr = vaddr;
            let rela_plt_size = rela_plt_data.len() as u64;
            layout.sections.push(MergedSection {
                entsize: 0,
                sh_type: 1,
                name: ".rela.plt".into(),
                data: rela_plt_data,
                vaddr: rela_plt_vaddr,
                flags: SHF_ALLOC,
                align: 8,
            });
            layout
                .section_by_name
                .insert(".rela.plt".into(), layout.sections.len() - 1);
            vaddr = align_up(vaddr + rela_plt_size, 8);

            let hash_vaddr = vaddr;
            let hash_size = hash_data.len() as u64;
            layout.sections.push(MergedSection {
                entsize: 0,
                sh_type: 1,
                name: ".hash".into(),
                data: hash_data,
                vaddr: hash_vaddr,
                flags: SHF_ALLOC,
                align: 8,
            });
            layout
                .section_by_name
                .insert(".hash".into(), layout.sections.len() - 1);
            vaddr = align_up(vaddr + hash_size, 8);

            let dynamic_data = build_dynamic_section_content(
                &DynamicAddrs {
                    pie: opts.pie,
                    got_plt_vaddr,
                    dynsym_vaddr,
                    dynstr_vaddr,
                    dynstr_size,
                    rela_plt_vaddr,
                    rela_plt_size,
                    hash_vaddr,
                },
                &needed_offsets,
                runpath_offset,
            )?;
            let dynamic_vaddr = vaddr;
            layout.sections.push(MergedSection {
                entsize: 0,
                sh_type: 1,
                name: ".dynamic".into(),
                data: dynamic_data,
                vaddr: dynamic_vaddr,
                flags: SHF_ALLOC | SHF_WRITE,
                align: 8,
            });
            layout
                .section_by_name
                .insert(".dynamic".into(), layout.sections.len() - 1);

            for (i, sym) in undefined.iter().enumerate() {
                let plt_entry_addr = plt_vaddr + 16 + (i as u64) * 16;
                global_symbols.insert(sym.clone(), plt_entry_addr);
            }

            // ld's --dynamic-linker when given. The default is glibc's on x86-64, which
            // is the only arch this branch runs for; it is wrong under musl.
            let interpreter = opts
                .interpreter
                .clone()
                .unwrap_or_else(|| "/lib64/ld-linux-x86-64.so.2".to_string());
            dynamic_info = Some(DynamicLinkInfo {
                pie: opts.pie,
                needed: needed.clone(),
                plt_symbols: undefined,
                weak_plt_symbols: Vec::new(),
                interpreter: Some(interpreter),
                macho_rebase_addrs: Vec::new(),
                macho_direct_binds: Vec::new(),
            });
        }
    }

    // Pre-scan all objects to find referenced symbol names, assign a GOT slot per
    // unique name, then fill each slot once global_symbols is final (PLT entries
    // included). For external symbols without a definition, the slot stays 0.
    timer.mark("dynamic sections");
    let mut got_symbol_map: HashMap<String, u64> = HashMap::default();
    if arch == TargetArch::X86_64 {
        let mut unique_syms: Vec<String> = Vec::new();
        let mut got_seen: HashSet<String> = HashSet::default();
        for obj in parsed.iter() {
            collect_gotpcrel_symbol_names(
                &obj.data,
                &obj.sections,
                &mut unique_syms,
                &mut got_seen,
            );
        }
        if !unique_syms.is_empty() {
            let got_base = {
                let last = layout.sections.last().ok_or("no sections")?;
                align_up(last.vaddr + last.data.len() as u64, 8)
            };
            let got_data = vec![0u8; unique_syms.len() * 8];
            layout.sections.push(MergedSection {
                entsize: 0,
                sh_type: 1,
                name: ".got".into(),
                data: got_data,
                vaddr: got_base,
                flags: SHF_ALLOC | SHF_WRITE,
                align: 8,
            });
            layout
                .section_by_name
                .insert(".got".into(), layout.sections.len() - 1);
            for (i, name) in unique_syms.iter().enumerate() {
                got_symbol_map.insert(name.clone(), got_base + i as u64 * 8);
            }
        }
    }

    let mut pie_relocations = if opts.pie {
        Some(pie::prepare(
            &mut layout,
            parsed,
            &section_contribs,
            &got_symbol_map,
            &global_symbols,
        )?)
    } else {
        None
    };
    let mut runtime = if let Some(dynamic) = &dynamic_info {
        Some(runtime::prepare(
            &mut layout,
            parsed,
            dynamic,
            libs.unwrap_or(&[]),
            &resolver,
            &got_symbol_map,
            &mut global_symbols,
        )?)
    } else {
        None
    };
    if opts.pie && dynamic_info.is_none() {
        dynamic_info = Some(pie::add_dynamic(
            &mut layout,
            arch,
            opts.interpreter.clone(),
        ));
    }
    if runtime.is_some()
        && let Some(&idx) = layout.section_by_name.get(".got")
    {
        let old = got_symbol_map.values().min().copied().unwrap_or(0);
        let new = layout.sections[idx].vaddr;
        for address in got_symbol_map.values_mut() {
            *address = new + *address - old;
        }
    }
    if !global_symbols.contains_key("_start")
        && (global_symbols.contains_key("main") || global_symbols.contains_key("_main"))
    {
        reserve_start_section(&mut layout);
    }
    if opts.build_id {
        let mut data = Vec::new();
        for value in [4u32, 20, 3] {
            data.extend_from_slice(&value.to_le_bytes());
        }
        data.extend_from_slice(b"GNU\0");
        data.resize(36, 0);
        let end = layout
            .sections
            .iter()
            .map(|s| s.vaddr + s.data.len() as u64)
            .max()
            .unwrap_or(arch.page_align());
        layout
            .section_by_name
            .insert(".note.gnu.build-id".into(), layout.sections.len());
        layout.sections.push(MergedSection {
            name: ".note.gnu.build-id".into(),
            data,
            vaddr: align_up(end, 4),
            align: 4,
            flags: SHF_ALLOC,
            sh_type: 7,
            entsize: 0,
        });
    }
    let moves = merge::layout_segments(&mut layout, arch.page_align());
    let remap = |address: u64| {
        moves
            .iter()
            .find(|&&(start, size, _)| start == address && size != 0)
            .or_else(|| {
                moves
                    .iter()
                    .find(|&&(start, size, _)| address >= start && address < start + size)
            })
            .map_or(address, |&(start, _, new)| new + address - start)
    };
    for value in global_symbols
        .values_mut()
        .chain(got_symbol_map.values_mut())
    {
        *value = remap(*value);
    }
    if let Some(runtime) = &mut runtime {
        runtime.remap(remap);
    }
    if let Some(pending) = &mut pie_relocations {
        pending.remap(remap);
    }
    runtime::remap_generated(&mut layout, remap);
    for (i, obj) in parsed.iter().enumerate() {
        let Some(table) = obj.sections.iter().find(|s| s.sh_type == SHT_SYMTAB) else {
            continue;
        };
        let strings = get_strtab_from_section(&obj.data, &obj.sections[table.sh_link as usize]);
        for (index, record) in get_strtab_from_section(&obj.data, table)
            .as_chunks::<24>()
            .0
            .iter()
            .enumerate()
        {
            let shndx = u16::from_le_bytes(record[6..8].try_into().unwrap()) as usize;
            if obj
                .sections
                .get(shndx)
                .is_none_or(|s| s.sh_flags & SHF_ALLOC == 0)
            {
                continue;
            }
            let name = &obj.names[shndx];
            let Some(contribution) = section_contribs[i].get(name) else {
                continue;
            };
            let symbol = crate::elf::parse_symbol_entry(record, 0)?;
            let address = layout.sections[layout.section_by_name[name]].vaddr
                + contribution.offset_in_merged
                + symbol.st_value;
            let old = resolved_by_index_per_object[i][index].replace(address);
            if symbol.bind != STB_LOCAL
                && let Some(name) = get_strtab_string(strings, symbol.name_offset)
                && global_symbols.get(&name).copied() == old.map(remap)
            {
                global_symbols.insert(name, address);
            }
        }
    }

    // Local symbols and PLT stubs for external functions get their resolved addresses here.
    if let Some(&got_idx) = layout.section_by_name.get(".got") {
        let got_base = layout.sections[got_idx].vaddr;
        for (name, &got_entry_vaddr) in &got_symbol_map {
            if let Some(&sym_addr) = global_symbols.get(name) {
                let off = (got_entry_vaddr - got_base) as usize;
                if off + 8 <= layout.sections[got_idx].data.len() {
                    layout.sections[got_idx].data[off..off + 8]
                        .copy_from_slice(&sym_addr.to_le_bytes());
                }
            }
        }
    }

    validate_undefined(parsed, &global_symbols, opts.gc_sections)?;
    timer.mark("GOT and NOBITS layout");
    for (obj_idx, obj) in parsed.iter().enumerate() {
        let obj_contribs = &section_contribs[obj_idx];
        let obj_by_index = &resolved_by_index_per_object[obj_idx];
        let symbol_names = symbol_names_by_index(&obj.data, &obj.sections)?;

        let weak_definitions: Vec<bool> = parse_symtab_view(&obj.data, &obj.sections)?
            .map(|(symbols, _)| {
                symbols
                    .iter()
                    .map(|sym| {
                        (sym.bind == STB_WEAK || sym.st_shndx == SHN_COMMON)
                            && sym.st_shndx != SHN_UNDEF
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut by_index: Vec<Option<u64>> = Vec::with_capacity(obj_by_index.len());
        for (i, addr) in obj_by_index.iter().enumerate() {
            let resolved_addr = match addr {
                Some(0) => Some(
                    symbol_names
                        .get(i)
                        .and_then(|name| global_symbols.get(name.as_ref()))
                        .copied()
                        .unwrap_or(0),
                ),
                Some(a) if weak_definitions.get(i) == Some(&true) => Some(
                    symbol_names
                        .get(i)
                        .and_then(|name| global_symbols.get(name.as_ref()))
                        .copied()
                        .unwrap_or(*a),
                ),
                Some(a) => Some(*a),
                None => symbol_names
                    .get(i)
                    .and_then(|name| global_symbols.get(name.as_ref()).copied()),
            };
            by_index.push(resolved_addr);
        }

        let got_by_index: Vec<Option<u64>> = symbol_names
            .iter()
            .map(|name| got_symbol_map.get(name.as_ref()).copied())
            .collect();

        let section_off: HashMap<String, u64> = obj_contribs
            .iter()
            .map(|(k, v)| (k.clone(), v.offset_in_merged))
            .collect();

        apply_relocations(
            arch,
            &mut layout,
            &RelocInputs {
                data: &obj.data,
                sections: &obj.sections,
                names: &obj.names,
                symbol_addrs: &by_index,
                got_entries: &got_by_index,
                section_offset: Some(&section_off),
            },
        )?;
    }

    if let Some(runtime) = runtime {
        runtime::finish(&mut layout, &section_contribs, &runtime)?;
    }
    if let Some(pending) = pie_relocations {
        pie::finish(&mut layout, pending)?;
    }
    timer.mark("apply relocations");
    let mut symbols = Vec::new();
    let mut emitted = HashSet::default();
    let output_symbols = crate::parallel::map(parsed.iter().enumerate().collect(), |(i, obj)| {
        collect_output_symbols(
            &obj.data,
            &obj.sections,
            &obj.names,
            &layout,
            |name| section_contribs[i].get(name).map(|c| c.offset_in_merged),
            &global_symbols,
        )
    });
    for result in output_symbols {
        for symbol in result? {
            if symbol.info >> 4 == 0 || emitted.insert(symbol.name.clone()) {
                symbols.push(symbol);
            }
        }
    }
    timer.mark("collect output symbols");
    Ok(LinkResult {
        symbols,
        layout,
        e_machine,
        symbol_addrs: global_symbols,
        dynamic: dynamic_info,
    })
}

fn validate_undefined(
    parsed: &[ParsedObject],
    globals: &HashMap<String, u64>,
    gc_sections: bool,
) -> Result<(), String> {
    for obj in parsed {
        let Some((symbols, strings)) = parse_symtab_view(&obj.data, &obj.sections)? else {
            continue;
        };
        let referenced = if gc_sections {
            Some(referenced_symbols(obj)?)
        } else {
            None
        };
        for (index, symbol) in symbols.iter().enumerate() {
            if symbol.st_shndx != SHN_UNDEF
                || symbol.bind != STB_GLOBAL
                || referenced.as_ref().is_some_and(|set| !set.contains(&index))
            {
                continue;
            }
            if let Some(name) = get_strtab_string(strings, symbol.name_offset)
                && !name.is_empty()
                && !globals.contains_key(&name)
            {
                return Err(format!("undefined symbol {name}"));
            }
        }
    }
    Ok(())
}

fn referenced_symbols(obj: &ParsedObject) -> Result<HashSet<usize>, String> {
    let mut referenced = HashSet::default();
    for section in obj.sections.iter().filter(|s| s.sh_type == 4) {
        if obj
            .sections
            .get(section.sh_info as usize)
            .is_some_and(|s| is_allocatable(s.sh_flags))
        {
            for relocation in parse_rela_section(&obj.data, section)? {
                referenced.insert(relocation.r_sym as usize);
            }
        }
    }
    Ok(referenced)
}

fn select_needed_libraries(
    parsed: &[ParsedObject],
    libs: &[String],
    opts: &LinkOptions,
    resolver: &LibraryResolver,
) -> Result<Vec<String>, String> {
    let mut needed = Vec::new();
    let mut seen = HashSet::default();
    let mut provided = HashSet::default();
    let mut shared_references = HashSet::default();
    let inspect_exports = opts.library_as_needed.iter().any(|&needed| needed);
    for (i, name) in libs.iter().enumerate() {
        if name == "System" {
            continue;
        }
        let library = resolver
            .resolve(name)
            .ok_or_else(|| format!("cannot find -l{name}"))?;
        if library.is_static {
            continue;
        }
        if seen.contains(&library.soname) {
            continue;
        }
        if !inspect_exports {
            seen.insert(library.soname.clone());
            needed.push(library.soname);
            continue;
        }
        let (data, sections) = crate::elf::read_dynamic_tables(&library.path)?;
        let mut exports = HashSet::default();
        let mut library_references = HashSet::default();
        for section in sections.iter().filter(|s| s.sh_type == 11) {
            let strings = get_strtab_from_section(
                &data,
                sections
                    .get(section.sh_link as usize)
                    .ok_or("invalid dynsym link")?,
            );
            for sym in parse_symtab(&data, section)? {
                if sym.bind != STB_LOCAL
                    && let Some(name) = get_strtab_string(strings, sym.name_offset)
                {
                    if sym.st_shndx != SHN_UNDEF {
                        exports.insert(name);
                    } else if sym.bind != STB_WEAK {
                        library_references.insert(name);
                    }
                }
            }
        }
        let mut retain = !opts.library_as_needed.get(i).copied().unwrap_or(false);
        if !retain {
            let count = opts.library_positions.get(i).copied().unwrap_or(usize::MAX);
            let mut definitions = HashSet::default();
            let mut references = shared_references.clone();
            for (_, obj) in parsed.iter().enumerate().filter(|(index, _)| {
                opts.object_positions
                    .get(*index)
                    .copied()
                    .unwrap_or(*index + 1)
                    <= count
            }) {
                if let Some((symbols, strings)) = parse_symtab_view(&obj.data, &obj.sections)? {
                    let referenced = if opts.gc_sections {
                        referenced_symbols(obj)?
                    } else {
                        HashSet::default()
                    };
                    for (index, sym) in symbols
                        .iter()
                        .enumerate()
                        .filter(|(_, s)| s.bind != STB_LOCAL)
                    {
                        if opts.gc_sections
                            && sym.st_shndx == SHN_UNDEF
                            && !referenced.contains(&index)
                        {
                            continue;
                        }
                        if opts.gc_sections
                            && sym.st_shndx != SHN_UNDEF
                            && sym.st_shndx < 0xff00
                            && obj.sections[sym.st_shndx as usize].sh_flags & SHF_ALLOC == 0
                        {
                            continue;
                        }
                        let Some(name) = get_strtab_string(strings, sym.name_offset) else {
                            continue;
                        };
                        if sym.st_shndx != SHN_UNDEF {
                            definitions.insert(name);
                        } else if sym.bind != STB_WEAK {
                            references.insert(name);
                        }
                    }
                }
            }
            if !definitions.contains("_start")
                && (definitions.contains("main") || definitions.contains("_main"))
            {
                references.insert("exit".into());
            }
            retain = references
                .iter()
                .any(|s| !definitions.contains(s) && !provided.contains(s) && exports.contains(s));
        }
        if retain {
            seen.insert(library.soname.clone());
            needed.push(library.soname);
            provided.extend(exports);
            shared_references.extend(library_references);
        }
    }
    Ok(needed)
}

/// Dispatch relocation application to the appropriate architecture handler.
/// Inputs a relocation pass reads from the object being linked.
pub struct RelocInputs<'a> {
    pub data: &'a [u8],
    pub sections: &'a [SectionHeader],
    pub names: &'a [String],
    pub symbol_addrs: &'a [Option<u64>],
    pub got_entries: &'a [Option<u64>],
    pub section_offset: Option<&'a HashMap<String, u64>>,
}

pub fn apply_relocations(
    arch: TargetArch,
    layout: &mut MergedLayout,
    inputs: &RelocInputs<'_>,
) -> Result<(), String> {
    let RelocInputs {
        data,
        sections,
        names,
        symbol_addrs,
        got_entries,
        section_offset,
    } = *inputs;
    match arch {
        TargetArch::X86_64 => x86_64::apply_relocations(
            layout,
            data,
            sections,
            names,
            symbol_addrs,
            got_entries,
            section_offset,
        ),
        TargetArch::AArch64 => {
            aarch64::apply_relocations(layout, data, sections, names, symbol_addrs, section_offset)
        }
        TargetArch::RiscV => {
            riscv::apply_relocations(layout, data, sections, names, symbol_addrs, section_offset)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::merge::merge_object_file;
    use super::symbols::merge_and_resolve;
    use super::*;
    use lamina_platform::{TargetArchitecture, TargetOperatingSystem};

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 16), 0);
        assert_eq!(align_up(1, 16), 16);
        assert_eq!(align_up(15, 16), 16);
        assert_eq!(align_up(16, 16), 16);
        assert_eq!(align_up(17, 16), 32);
    }

    #[test]
    fn test_merge_ras_object() {
        let asm = ".text\n.globl main\nmain:\n  movq $42, %rax\n  ret\n";
        let tmp = std::env::temp_dir().join("weld_merge_test.o");

        let mut ras =
            ras::Ras::new(TargetArchitecture::X86_64, TargetOperatingSystem::Linux).expect("ras");
        ras.assemble(asm, &tmp).expect("assemble");

        let layout = merge_object_file(&tmp).expect("merge");
        let _ = std::fs::remove_file(&tmp);

        assert!(!layout.sections.is_empty());
        assert!(layout.section_by_name.contains_key(".text"));
    }

    #[test]
    fn test_merge_and_resolve() {
        let asm = ".text\n.globl main\nmain:\n  movq $42, %rax\n  ret\n";
        let tmp = std::env::temp_dir().join("weld_resolve_test.o");

        let mut ras =
            ras::Ras::new(TargetArchitecture::X86_64, TargetOperatingSystem::Linux).expect("ras");
        ras.assemble(asm, &tmp).expect("assemble");

        let data = std::fs::read(&tmp).expect("read");
        let _ = std::fs::remove_file(&tmp);

        let (layout, symbols) = merge_and_resolve(&data).expect("merge_and_resolve");
        assert!(!layout.sections.is_empty());
        assert!(layout.section_by_name.contains_key(".text"));
        assert!(symbols.is_empty() || symbols.contains_key("main"));
    }

    #[test]
    fn test_link_single_object() {
        let asm = ".text\n.globl main\nmain:\n  movq $42, %rax\n  ret\n";
        let tmp = std::env::temp_dir().join("weld_link_test.o");

        let mut ras =
            ras::Ras::new(TargetArchitecture::X86_64, TargetOperatingSystem::Linux).expect("ras");
        ras.assemble(asm, &tmp).expect("assemble");

        let data = std::fs::read(&tmp).expect("read");
        let _ = std::fs::remove_file(&tmp);

        let result = link_single_object(&data).expect("link_single_object");
        assert!(!result.layout.sections.is_empty());
        assert!(result.layout.section_by_name.contains_key(".text"));
    }

    #[test]
    fn test_link_multi_object() {
        let asm1 = ".text\n.globl main\nmain:\n  movq $42, %rax\n  ret\n";
        let asm2 = ".text\n.globl foo\nfoo:\n  movq $1, %rax\n  ret\n";
        let tmp1 = std::env::temp_dir().join("weld_multi_1.o");
        let tmp2 = std::env::temp_dir().join("weld_multi_2.o");

        let mut ras =
            ras::Ras::new(TargetArchitecture::X86_64, TargetOperatingSystem::Linux).expect("ras");
        ras.assemble(asm1, &tmp1).expect("assemble");
        ras.assemble(asm2, &tmp2).expect("assemble");

        let d1 = std::fs::read(&tmp1).expect("read");
        let d2 = std::fs::read(&tmp2).expect("read");
        let _ = std::fs::remove_file(&tmp1);
        let _ = std::fs::remove_file(&tmp2);

        let objects: Vec<&[u8]> = vec![&d1, &d2];
        let result = link_multi_object(&objects, None).expect("link_multi_object");
        assert!(!result.layout.sections.is_empty());
        assert!(result.layout.section_by_name.contains_key(".text"));
        let text_idx = result
            .layout
            .section_by_name
            .get(".text")
            .copied()
            .unwrap_or(0);
        let text = &result.layout.sections[text_idx];
        assert!(text.data.len() >= 2);
    }

    #[test]
    fn test_link_aarch64_object() {
        let asm = ".text\n.globl main\nmain:\n  mov x0, #42\n  ret\n";
        let tmp = std::env::temp_dir().join("weld_link_aarch64_test.o");

        let mut ras =
            ras::Ras::new(TargetArchitecture::Aarch64, TargetOperatingSystem::Linux).expect("ras");
        ras.assemble(asm, &tmp).expect("assemble");

        let data = std::fs::read(&tmp).expect("read");
        let _ = std::fs::remove_file(&tmp);

        let result = link_single_object(&data).expect("link_single_object");
        assert!(!result.layout.sections.is_empty());
        assert!(result.layout.section_by_name.contains_key(".text"));
        assert_eq!(result.e_machine, 183);
    }
}
