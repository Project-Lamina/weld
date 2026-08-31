//! Section merging and layout for single-object linking.
//!
//! Architecture-specific relocation logic lives in parallel modules:
//! - x86_64: x86_64.rs
//! - aarch64: aarch64.rs
//! - riscv: riscv.rs

#![allow(dead_code)]

mod aarch64;
pub mod macho;
pub mod resolver;
mod riscv;
mod x86_64;

pub use resolver::LibraryResolver;

use crate::{
    arch::TargetArch,
    elf::{
        Elf64Header, SectionHeader, Symbol, get_strtab_from_section, get_strtab_string,
        parse_elf64_slice, parse_rela_section, parse_symtab, reloc_type::R_X86_64_GOTPCREL,
    },
    platform::TargetPlatform,
};
use std::{collections::HashMap, path::Path, thread};

/// Return type for symbol-table parsing: a list of symbols and the raw string table.
type SymtabView<'a> = Option<(Vec<Symbol>, &'a [u8])>;

/// Resolved symbol table paired with per-section virtual-address overrides.
type ResolvedSymbols = (HashMap<String, ResolvedSymbol>, Vec<Option<u64>>);

/// Four binary blobs produced when building ELF dynamic sections:
/// `.dynsym`, `.dynstr`, `.rela.plt`, and `.hash` (SysV DT_HASH).
type DynSectionQuad = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Standard SysV ELF hash function (used by DT_HASH).
fn elf_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &b in name {
        h = (h << 4).wrapping_add(b as u32);
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

/// Build a SysV (.hash / DT_HASH) table over the dynamic symbol table.
/// `sym_names[i]` is the name of dynsym entry `i + 1` (entry 0 is the reserved
/// null symbol). The dynamic linker requires this to resolve symbols by name.
fn build_sysv_hash(sym_names: &[&str]) -> Vec<u8> {
    let nchain = (sym_names.len() + 1) as u32; // +1 for STN_UNDEF at index 0
    let nbucket = nchain.max(1);
    let mut buckets = vec![0u32; nbucket as usize];
    let mut chains = vec![0u32; nchain as usize];

    for (i, name) in sym_names.iter().enumerate() {
        let sym_idx = (i + 1) as u32; // real symbols start at dynsym index 1
        let b = (elf_hash(name.as_bytes()) % nbucket) as usize;
        // Prepend into the bucket's chain.
        chains[sym_idx as usize] = buckets[b];
        buckets[b] = sym_idx;
    }

    let mut out = Vec::with_capacity((2 + nbucket as usize + nchain as usize) * 4);
    out.extend_from_slice(&nbucket.to_le_bytes());
    out.extend_from_slice(&nchain.to_le_bytes());
    for b in &buckets {
        out.extend_from_slice(&b.to_le_bytes());
    }
    for c in &chains {
        out.extend_from_slice(&c.to_le_bytes());
    }
    out
}

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
    Ok(ParsedObject {
        data,
        header,
        sections,
        names,
    })
}

const SHN_UNDEF: u16 = 0;
const SHN_ABS: u16 = 0xfff1;
const STB_LOCAL: u8 = 0;

const SHF_ALLOC: u64 = 2;
const SHF_EXECINSTR: u64 = 4;
const SHF_WRITE: u64 = 1;
const SHT_PROGBITS: u32 = 1;
const SHT_NOBITS: u32 = 8;
const SHT_SYMTAB: u32 = 2;

#[derive(Debug, Clone)]
pub struct MergedSection {
    pub name: String,
    pub data: Vec<u8>,
    pub vaddr: u64,
    pub flags: u64,
    pub align: u64,
}

#[derive(Debug, Clone)]
pub struct MergedLayout {
    pub sections: Vec<MergedSection>,
    pub section_by_name: HashMap<String, usize>,
}

#[derive(Debug, Clone)]
pub struct ResolvedSymbol {
    pub address: Option<u64>,
    pub size: u64,
    pub is_defined: bool,
}

#[derive(Debug, Default)]
pub struct DynamicLinkInfo {
    pub needed: Vec<String>,
    pub plt_symbols: Vec<String>,
    pub weak_plt_symbols: Vec<String>,
    pub interpreter: Option<String>,
    pub macho_rebase_addrs: Vec<u64>,
    pub macho_direct_binds: Vec<(u64, String, bool, i64)>,
}

#[derive(Debug)]
pub struct LinkResult {
    pub layout: MergedLayout,
    pub e_machine: u16,
    pub symbol_addrs: HashMap<String, u64>,
    pub dynamic: Option<DynamicLinkInfo>,
}

fn align_up(value: u64, align: u64) -> u64 {
    if align == 0 {
        return value;
    }
    (value + align - 1) & !(align - 1)
}

fn is_allocatable(flags: u64) -> bool {
    (flags & SHF_ALLOC) != 0
}

fn section_merge_order(name: &str) -> usize {
    match name {
        ".text" => 0,
        ".rodata" => 1,
        ".data" => 2,
        ".bss" => 3,
        _ => 4,
    }
}

fn collect_mergeable_sections<'a>(
    sections: &'a [SectionHeader],
    names: &[String],
) -> Vec<(String, &'a SectionHeader)> {
    let mut to_merge: Vec<(String, &SectionHeader)> = sections
        .iter()
        .enumerate()
        .filter(|(_, sh)| {
            (sh.sh_type == SHT_PROGBITS || sh.sh_type == SHT_NOBITS) && is_allocatable(sh.sh_flags)
        })
        .map(|(i, sh)| (names.get(i).cloned().unwrap_or_default(), sh))
        .collect();

    to_merge.sort_by_key(|(name, _)| section_merge_order(name));
    to_merge
}

fn read_section_data(data: &[u8], sh: &SectionHeader) -> Vec<u8> {
    if sh.sh_size == 0 {
        return Vec::new();
    }
    match sh.sh_type {
        SHT_PROGBITS => {
            let start = sh.sh_offset as usize;
            let end = start + sh.sh_size as usize;
            data.get(start..end).unwrap_or(&[]).to_vec()
        }
        // NOBITS has no bytes in the object, but layout advances vaddr by its size and
        // the segment's file size is taken from data.len(). Returning nothing left .bss
        // outside the mapping and let anything placed after it alias the same address.
        // Zeroes cost file size; the alternative is a memory size separate from the
        // file size carried through the segment builder and the ELF writer.
        SHT_NOBITS => vec![0u8; sh.sh_size as usize],
        _ => Vec::new(),
    }
}

fn default_flags_for_section(name: &str) -> u64 {
    match name {
        ".text" => SHF_ALLOC | SHF_EXECINSTR,
        ".rodata" => SHF_ALLOC,
        ".data" | ".bss" => SHF_ALLOC | SHF_WRITE,
        _ => SHF_ALLOC,
    }
}

fn append_merged_section(
    layout: &mut MergedLayout,
    name: &str,
    contribs: &[(Vec<u8>, u64)],
    align: u64,
    flags: u64,
    vaddr: &mut u64,
) {
    let total_size: u64 = contribs.iter().map(|(_, size)| *size).sum();
    if total_size == 0 {
        return;
    }

    let mut merged_bytes = Vec::new();
    for (data, _) in contribs {
        merged_bytes.extend_from_slice(data);
    }

    let align = align.max(1);
    *vaddr = align_up(*vaddr, align);

    let idx = layout.sections.len();
    layout.section_by_name.insert(name.to_string(), idx);
    layout.sections.push(MergedSection {
        name: name.to_string(),
        data: merged_bytes,
        vaddr: *vaddr,
        flags,
        align,
    });

    *vaddr += total_size;
}

/// Merge allocatable sections from a single ELF64 object into a linear layout
/// starting at the architecture-conventional load base (`0x400000`).
pub fn merge_sections_single_object(data: &[u8]) -> Result<MergedLayout, String> {
    let (_header, sections, names) = parse_elf64_slice(data)?;
    let to_merge = collect_mergeable_sections(&sections, &names);

    let mut layout = MergedLayout {
        sections: Vec::new(),
        section_by_name: HashMap::new(),
    };

    let mut vaddr: u64 = 0x400000;

    for (name, sh) in &to_merge {
        let align = sh.sh_addralign.max(1);
        vaddr = align_up(vaddr, align);

        let data_slice = read_section_data(data, sh);

        let merged = MergedSection {
            name: name.clone(),
            data: data_slice,
            vaddr,
            flags: sh.sh_flags,
            align,
        };

        let idx = layout.sections.len();
        layout.section_by_name.insert(name.clone(), idx);
        layout.sections.push(merged);

        vaddr += sh.sh_size;
    }

    Ok(layout)
}

/// Read an ELF64 object file from `path` and merge its allocatable sections.
pub fn merge_object_file(path: &Path) -> Result<MergedLayout, String> {
    let data = std::fs::read(path).map_err(|e| format!("read failed: {}", e))?;
    merge_sections_single_object(&data)
}

/// Per-object section contribution: offset within merged section, size.
#[derive(Debug, Clone)]
pub struct ObjectSectionContrib {
    pub offset_in_merged: u64,
    pub size: u64,
}

/// Merge sections from multiple objects. Same e_machine required.
pub fn merge_sections_multi_object(
    objects: &[&[u8]],
) -> Result<(MergedLayout, Vec<HashMap<String, ObjectSectionContrib>>), String> {
    if objects.is_empty() {
        return Err("no objects to merge".to_string());
    }

    let first_header = parse_elf64_slice(objects[0])?.0;
    let e_machine = first_header.e_machine;

    let mut section_contribs: Vec<HashMap<String, ObjectSectionContrib>> =
        Vec::with_capacity(objects.len());
    let mut merged_data: HashMap<String, Vec<(Vec<u8>, u64)>> = HashMap::new();
    let mut section_cumul: HashMap<String, u64> = HashMap::new();
    let mut section_aligns: HashMap<String, u64> = HashMap::new();
    let mut section_flags: HashMap<String, u64> = HashMap::new();

    for obj_data in objects {
        let (header, sections, names) = parse_elf64_slice(obj_data)?;
        if header.e_machine != e_machine {
            return Err(format!(
                "e_machine mismatch: {} vs {}",
                header.e_machine, e_machine
            ));
        }

        let mut obj_contribs = HashMap::new();

        for (name, sh) in collect_mergeable_sections(&sections, &names) {
            let data_slice = read_section_data(obj_data, sh);

            let size = sh.sh_size;
            let align = sh.sh_addralign.max(1);
            // Each contribution starts at its own alignment, not wherever the previous
            // one happened to end. Without the pad an object promising 16-byte data can
            // land at an odd offset and no error says so.
            let raw = *section_cumul.get(&name).unwrap_or(&0);
            let offset_in_merged = align_up(raw, align);
            let pad = offset_in_merged - raw;
            section_cumul.insert(name.clone(), offset_in_merged + size);

            section_aligns
                .entry(name.clone())
                .and_modify(|a| *a = (*a).max(align))
                .or_insert(align);

            section_flags
                .entry(name.clone())
                .and_modify(|f| *f |= sh.sh_flags)
                .or_insert(sh.sh_flags);

            let entry = merged_data.entry(name.clone()).or_default();
            if pad > 0 {
                entry.push((vec![0u8; pad as usize], pad));
            }
            entry.push((data_slice, size));

            obj_contribs.insert(
                name,
                ObjectSectionContrib {
                    offset_in_merged,
                    size,
                },
            );
        }

        section_contribs.push(obj_contribs);
    }

    let section_order = [".text", ".rodata", ".data", ".bss"];
    let mut layout = MergedLayout {
        sections: Vec::new(),
        section_by_name: HashMap::new(),
    };

    let mut vaddr: u64 = 0x400000;

    for &sec_name in &section_order {
        let Some(contribs) = merged_data.get(sec_name) else {
            continue;
        };
        let align = section_aligns.get(sec_name).copied().unwrap_or(1);
        let flags = section_flags
            .get(sec_name)
            .copied()
            .unwrap_or_else(|| default_flags_for_section(sec_name));
        append_merged_section(&mut layout, sec_name, contribs, align, flags, &mut vaddr);
    }

    let mut extra_sections: Vec<&str> = merged_data
        .keys()
        .map(String::as_str)
        .filter(|name| !section_order.contains(name))
        .collect();
    extra_sections.sort_unstable();

    for name in extra_sections {
        let Some(contribs) = merged_data.get(name) else {
            continue;
        };
        let align = section_aligns.get(name).copied().unwrap_or(1);
        let flags = section_flags
            .get(name)
            .copied()
            .unwrap_or_else(|| default_flags_for_section(name));
        append_merged_section(&mut layout, name, contribs, align, flags, &mut vaddr);
    }

    Ok((layout, section_contribs))
}

fn parse_symtab_view<'a>(
    data: &'a [u8],
    sections: &'a [SectionHeader],
) -> Result<SymtabView<'a>, String> {
    let Some(symtab_sh) = sections.iter().find(|sh| sh.sh_type == SHT_SYMTAB) else {
        return Ok(None);
    };

    let strtab_idx = symtab_sh.sh_link as usize;
    let strtab_sh = sections.get(strtab_idx).ok_or("symtab sh_link invalid")?;
    let strtab = get_strtab_from_section(data, strtab_sh);
    let symbols = parse_symtab(data, symtab_sh)?;

    Ok(Some((symbols, strtab)))
}

fn resolve_symbols_with_offsets<F>(
    data: &[u8],
    layout: &MergedLayout,
    sections: &[SectionHeader],
    names: &[String],
    mut section_offset: F,
) -> Result<ResolvedSymbols, String>
where
    F: FnMut(&str) -> Option<u64>,
{
    let Some((symbols, strtab)) = parse_symtab_view(data, sections)? else {
        return Ok((HashMap::new(), Vec::new()));
    };

    let mut resolved = HashMap::new();
    let mut by_index: Vec<Option<u64>> = Vec::with_capacity(symbols.len());

    for sym in &symbols {
        let name = get_strtab_string(strtab, sym.name_offset)
            .unwrap_or_else(|| format!("<sym_{}>", sym.name_offset));

        let (address, is_defined) = match sym.st_shndx {
            SHN_UNDEF => (None, false),
            SHN_ABS => (Some(sym.st_value), true),
            shndx => {
                let section_name = names.get(shndx as usize).map(String::as_str).unwrap_or("");
                if let Some(&merged_idx) = layout.section_by_name.get(section_name) {
                    let merged = &layout.sections[merged_idx];
                    let base_offset = section_offset(section_name).unwrap_or(0);
                    (Some(merged.vaddr + base_offset + sym.st_value), true)
                } else {
                    (None, false)
                }
            }
        };

        by_index.push(address);
        // A local name is private to its object. Same-object relocations still find it
        // through by_index; only cross-object lookup must not see it.
        if !name.is_empty() && sym.bind != STB_LOCAL {
            resolved.insert(
                name,
                ResolvedSymbol {
                    address,
                    size: sym.st_size,
                    is_defined,
                },
            );
        }
    }

    Ok((resolved, by_index))
}

/// Collect the names of all symbols referenced by `R_X86_64_GOTPCREL`
/// relocations in `data`. New names are appended to `out`; duplicates are
/// skipped.
fn collect_gotpcrel_symbol_names(data: &[u8], sections: &[SectionHeader], out: &mut Vec<String>) {
    const SHT_RELA: u32 = 4;
    let sym_names = match symbol_names_by_index_raw(data, sections) {
        Some(v) => v,
        None => return,
    };
    for rela_sh in sections.iter().filter(|s| s.sh_type == SHT_RELA) {
        let Ok(relas) = parse_rela_section(data, rela_sh) else {
            continue;
        };
        for rel in relas {
            if rel.r_type != R_X86_64_GOTPCREL {
                continue;
            }
            if let Some(name) = sym_names.get(rel.r_sym as usize) {
                if !name.is_empty() && !out.contains(name) {
                    out.push(name.clone());
                }
            }
        }
    }
}

/// Like `symbol_names_by_index` but returns `None` on parse failure instead
/// of `Err`, for use in best-effort pre-scans.
fn symbol_names_by_index_raw(data: &[u8], sections: &[SectionHeader]) -> Option<Vec<String>> {
    let (symbols, strtab) = parse_symtab_view(data, sections).ok()??;
    Some(
        symbols
            .iter()
            .map(|sym| {
                get_strtab_string(strtab, sym.name_offset)
                    .unwrap_or_else(|| format!("<sym_{}>", sym.name_offset))
            })
            .collect(),
    )
}

fn symbol_names_by_index(data: &[u8], sections: &[SectionHeader]) -> Result<Vec<String>, String> {
    let Some((symbols, strtab)) = parse_symtab_view(data, sections)? else {
        return Ok(Vec::new());
    };

    Ok(symbols
        .iter()
        .map(|sym| {
            get_strtab_string(strtab, sym.name_offset)
                .unwrap_or_else(|| format!("<sym_{}>", sym.name_offset))
        })
        .collect())
}

pub fn resolve_symbols(
    data: &[u8],
    layout: &MergedLayout,
    sections: &[SectionHeader],
    names: &[String],
) -> Result<ResolvedSymbols, String> {
    resolve_symbols_with_offsets(data, layout, sections, names, |_| Some(0))
}

fn resolve_symbols_for_object(
    data: &[u8],
    layout: &MergedLayout,
    sections: &[SectionHeader],
    names: &[String],
    obj_contribs: &HashMap<String, ObjectSectionContrib>,
) -> Result<ResolvedSymbols, String> {
    resolve_symbols_with_offsets(data, layout, sections, names, |section_name| {
        obj_contribs
            .get(section_name)
            .map(|contrib| contrib.offset_in_merged)
    })
}

/// Merge sections and resolve symbols for a single ELF64 object in one step.
pub fn merge_and_resolve(
    data: &[u8],
) -> Result<(MergedLayout, HashMap<String, ResolvedSymbol>), String> {
    let (_header, sections, names) = parse_elf64_slice(data)?;
    let layout = merge_sections_single_object(data)?;
    let (symbols, _by_index) = resolve_symbols(data, &layout, &sections, &names)?;
    Ok((layout, symbols))
}

/// Fully link a single ELF64 object: merge sections, resolve symbols, and
/// apply relocations.
pub fn link_single_object(data: &[u8]) -> Result<LinkResult, String> {
    let (header, sections, names) = parse_elf64_slice(data)?;
    let mut layout = merge_sections_single_object(data)?;
    let (resolved, by_index) = resolve_symbols(data, &layout, &sections, &names)?;
    let arch = TargetArch::from_elf_machine(header.e_machine)
        .ok_or_else(|| format!("unsupported machine {}", header.e_machine))?;
    apply_relocations(
        arch,
        &mut layout,
        data,
        &sections,
        &names,
        &by_index,
        &[],
        None,
    )?;
    let symbol_addrs: HashMap<String, u64> = resolved
        .into_iter()
        .filter_map(|(name, r)| r.address.map(|a| (name, a)))
        .collect();
    Ok(LinkResult {
        layout,
        e_machine: header.e_machine,
        symbol_addrs,
        dynamic: None,
    })
}

/// Link multiple object files. Same e_machine required.
/// When libs is Some and contains "c" or "System", adds PLT/GOT for undefined symbols.
pub fn link_multi_object(objects: &[&[u8]], libs: Option<&[String]>) -> Result<LinkResult, String> {
    if objects.is_empty() {
        return Err("no objects to link".to_string());
    }
    if objects.len() == 1 && libs.is_none() {
        return link_single_object(objects[0]);
    }

    let owned: Vec<Vec<u8>> = objects.iter().map(|s| s.to_vec()).collect();
    let handles: Vec<_> = owned
        .into_iter()
        .map(|data| thread::spawn(move || parse_object(data)))
        .collect();
    let mut parsed = Vec::with_capacity(handles.len());
    for h in handles {
        parsed.push(h.join().map_err(|_| "thread join failed".to_string())??);
    }

    link_multi_object_parsed(&parsed, libs)
}

fn link_multi_object_parsed(
    parsed: &[ParsedObject],
    libs: Option<&[String]>,
) -> Result<LinkResult, String> {
    if parsed.is_empty() {
        return Err("no objects to link".to_string());
    }
    if parsed.len() == 1 && libs.is_none() {
        return link_single_object(&parsed[0].data);
    }

    let objects: Vec<&[u8]> = parsed.iter().map(|p| p.data.as_slice()).collect();
    let (mut layout, section_contribs) = merge_sections_multi_object(&objects)?;
    let e_machine = parsed[0].header.e_machine;
    let arch = TargetArch::from_elf_machine(e_machine)
        .ok_or_else(|| format!("unsupported machine {}", e_machine))?;

    let mut global_symbols: HashMap<String, u64> = HashMap::new();
    let mut resolved_by_index_per_object: Vec<Vec<Option<u64>>> = Vec::with_capacity(parsed.len());

    for (obj_idx, obj) in parsed.iter().enumerate() {
        let obj_contribs = &section_contribs[obj_idx];
        let (resolved, by_index) = resolve_symbols_for_object(
            &obj.data,
            &layout,
            &obj.sections,
            &obj.names,
            obj_contribs,
        )?;
        resolved_by_index_per_object.push(by_index);

        for (name, r) in resolved {
            if let Some(addr) = r.address {
                global_symbols.entry(name).or_insert(addr);
            }
        }
    }

    let mut dynamic_info: Option<DynamicLinkInfo> = None;

    // Resolve library names to sonames.  Any lib matching "c" or "System"
    // (legacy names) as well as any library the resolver can locate as a
    // shared object triggers PLT generation.
    let resolver = LibraryResolver::new(arch, TargetPlatform::current());
    let has_shared_lib = libs
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
        for (obj_idx, obj) in parsed.iter().enumerate() {
            let obj_by_index = &resolved_by_index_per_object[obj_idx];
            let symbol_names = symbol_names_by_index(&obj.data, &obj.sections)?;
            for (i, addr) in obj_by_index.iter().enumerate() {
                if addr.is_none()
                    && let Some(name) = symbol_names.get(i)
                    && !name.is_empty()
                    && !global_symbols.contains_key(name)
                    && !undefined.contains(name)
                {
                    undefined.push(name.clone());
                }
            }
        }

        if !undefined.is_empty() {
            let (plt_data, got_plt_data) = build_plt_got_x86_64(&undefined, &layout)?;
            let last = layout.sections.last().ok_or("no sections")?;
            let mut vaddr = align_up(last.vaddr + last.data.len() as u64, 16);

            let plt_vaddr = vaddr;
            layout.sections.push(MergedSection {
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
                name: ".got.plt".into(),
                data: got_plt_data,
                vaddr: got_plt_vaddr,
                flags: SHF_ALLOC | SHF_WRITE,
                align: 8,
            });
            layout
                .section_by_name
                .insert(".got.plt".into(), layout.sections.len() - 1);
            let got_plt_size = 24 + (undefined.len() as u64) * 8;
            vaddr = align_up(got_plt_vaddr + got_plt_size, 8);

            let (dynsym_data, dynstr_data, rela_plt_data, hash_data) =
                build_dynamic_sections(&undefined, got_plt_vaddr)?;
            let dynsym_vaddr = vaddr;
            let dynsym_size = dynsym_data.len() as u64;
            layout.sections.push(MergedSection {
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
                got_plt_vaddr,
                dynsym_vaddr,
                dynstr_vaddr,
                dynstr_size,
                rela_plt_vaddr,
                rela_plt_size,
                hash_vaddr,
            )?;
            let dynamic_vaddr = vaddr;
            layout.sections.push(MergedSection {
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

            let interpreter = "/lib64/ld-linux-x86-64.so.2".to_string();
            // Build DT_NEEDED entries from the requested libraries, resolving
            // each name to its real soname via LibraryResolver.
            let needed: Vec<String> = libs
                .unwrap_or(&[])
                .iter()
                .filter_map(|name| {
                    if name == "System" {
                        // macOS compatibility alias — not meaningful for ELF.
                        return None;
                    }
                    Some(
                        resolver
                            .resolve(name)
                            .map(|r| r.soname)
                            .unwrap_or_else(|| resolver.expected_soname(name)),
                    )
                })
                .collect();
            dynamic_info = Some(DynamicLinkInfo {
                needed,
                plt_symbols: undefined,
                weak_plt_symbols: Vec::new(),
                interpreter: Some(interpreter),
                macho_rebase_addrs: Vec::new(),
                macho_direct_binds: Vec::new(),
            });
        }
    }

    // Build .got section for R_X86_64_GOTPCREL relocations.
    // Pre-scan all objects to find referenced symbol names, assign a GOT slot per
    // unique name, then fill each slot once global_symbols is final (PLT entries
    // included). For external symbols without a definition, the slot stays 0.
    let mut got_symbol_map: HashMap<String, u64> = HashMap::new();
    if arch == TargetArch::X86_64 {
        let mut unique_syms: Vec<String> = Vec::new();
        for obj in parsed.iter() {
            collect_gotpcrel_symbol_names(&obj.data, &obj.sections, &mut unique_syms);
        }
        if !unique_syms.is_empty() {
            let got_base = {
                let last = layout.sections.last().ok_or("no sections")?;
                align_up(last.vaddr + last.data.len() as u64, 8)
            };
            let got_data = vec![0u8; unique_syms.len() * 8];
            layout.sections.push(MergedSection {
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

    // Fill .got entries with resolved addresses (local symbols + PLT stubs for
    // external functions).
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

    for (obj_idx, obj) in parsed.iter().enumerate() {
        let obj_contribs = &section_contribs[obj_idx];
        let obj_by_index = &resolved_by_index_per_object[obj_idx];
        let symbol_names = symbol_names_by_index(&obj.data, &obj.sections)?;

        let mut by_index: Vec<Option<u64>> = Vec::with_capacity(obj_by_index.len());
        for (i, addr) in obj_by_index.iter().enumerate() {
            let resolved_addr = match addr {
                Some(a) => Some(*a),
                None => symbol_names
                    .get(i)
                    .and_then(|name| global_symbols.get(name).copied()),
            };
            by_index.push(resolved_addr);
        }

        let got_by_index: Vec<Option<u64>> = symbol_names
            .iter()
            .map(|name| got_symbol_map.get(name).copied())
            .collect();

        let section_off: HashMap<String, u64> = obj_contribs
            .iter()
            .map(|(k, v)| (k.clone(), v.offset_in_merged))
            .collect();

        apply_relocations(
            arch,
            &mut layout,
            &obj.data,
            &obj.sections,
            &obj.names,
            &by_index,
            &got_by_index,
            Some(&section_off),
        )?;
    }

    Ok(LinkResult {
        layout,
        e_machine,
        symbol_addrs: global_symbols,
        dynamic: dynamic_info,
    })
}

/// Build the raw bytes for `.dynsym`, `.dynstr`, `.rela.plt`, and `.hash`
/// (SysV `DT_HASH`) from the list of symbols that require PLT entries.
///
/// `got_plt_vaddr` is the virtual address of `.got.plt`; it is used to compute
/// each `R_X86_64_JUMP_SLOT` relocation's `r_offset` (GOT slot address).
fn build_dynamic_sections(
    plt_symbols: &[String],
    got_plt_vaddr: u64,
) -> Result<DynSectionQuad, String> {
    let mut dynstr = vec![0u8];
    dynstr.extend_from_slice(b"libc.so.6\0");

    let mut str_offsets: Vec<u32> = Vec::with_capacity(plt_symbols.len());
    for sym in plt_symbols {
        let off = dynstr.len() as u32;
        str_offsets.push(off);
        dynstr.extend_from_slice(sym.as_bytes());
        dynstr.push(0);
    }

    // dynsym[0] MUST be the reserved STN_UNDEF null entry. Real symbols start
    // at index 1, so rela.plt r_sym below is (i + 1).
    let mut dynsym = vec![0u8; 24];
    for &off in &str_offsets {
        dynsym.extend_from_slice(&off.to_le_bytes());
        dynsym.push((1 << 4) | 2); // STB_GLOBAL | STT_FUNC
        dynsym.push(0);
        dynsym.extend_from_slice(&0u16.to_le_bytes()); // st_shndx = SHN_UNDEF
        dynsym.extend_from_slice(&0u64.to_le_bytes());
        dynsym.extend_from_slice(&0u64.to_le_bytes());
    }

    let mut rela_plt = Vec::with_capacity(plt_symbols.len() * 24);
    for (i, _) in plt_symbols.iter().enumerate() {
        let r_offset = got_plt_vaddr + 24 + (i as u64) * 8;
        // r_sym = i + 1 because dynsym index 0 is the reserved null entry.
        let r_info = (((i + 1) as u64) << 32) | 7u64; // r_sym, R_X86_64_JUMP_SLOT
        rela_plt.extend_from_slice(&r_offset.to_le_bytes());
        rela_plt.extend_from_slice(&r_info.to_le_bytes());
        rela_plt.extend_from_slice(&0i64.to_le_bytes());
    }

    let name_refs: Vec<&str> = plt_symbols.iter().map(|s| s.as_str()).collect();
    let hash = build_sysv_hash(&name_refs);

    Ok((dynsym, dynstr, rela_plt, hash))
}

/// Build the raw bytes for the `.dynamic` section (`Elf64_Dyn` array).
///
/// Emits `DT_HASH`, `DT_NEEDED` (offset 1 in dynstr = "libc.so.6"), `DT_STRTAB`,
/// `DT_SYMTAB`, `DT_STRSZ`, `DT_SYMENT`, `DT_PLTGOT`, `DT_PLTRELSZ`,
/// `DT_PLTREL`, `DT_JMPREL`, `DT_BIND_NOW`, `DT_FLAGS` (`DF_BIND_NOW`),
/// `DT_FLAGS_1` (`DF_1_NOW`), and a `DT_NULL` terminator.
fn build_dynamic_section_content(
    got_plt_vaddr: u64,
    dynsym_vaddr: u64,
    dynstr_vaddr: u64,
    dynstr_size: u64,
    rela_plt_vaddr: u64,
    rela_plt_size: u64,
    hash_vaddr: u64,
) -> Result<Vec<u8>, String> {
    let mut content = Vec::new();
    fn push_dyn(content: &mut Vec<u8>, tag: u64, val: u64) {
        content.extend_from_slice(&tag.to_le_bytes());
        content.extend_from_slice(&val.to_le_bytes());
    }
    push_dyn(&mut content, 4, hash_vaddr); // DT_HASH
    push_dyn(&mut content, 1, 1); // DT_NEEDED, "libc.so.6" at offset 1 in dynstr
    push_dyn(&mut content, 5, dynstr_vaddr);
    push_dyn(&mut content, 6, dynsym_vaddr);
    push_dyn(&mut content, 10, dynstr_size);
    push_dyn(&mut content, 11, 24);
    push_dyn(&mut content, 3, got_plt_vaddr);
    push_dyn(&mut content, 2, rela_plt_size);
    push_dyn(&mut content, 20, 7);
    push_dyn(&mut content, 23, rela_plt_vaddr);
    // Force eager binding: loader resolves all JUMP_SLOT relocs at startup and
    // writes the final symbol address into each GOT slot. Avoids needing lazy
    // PLT trampoline state (GOT[0]=_DYNAMIC, GOT slot back-pointers).
    push_dyn(&mut content, 24, 0); // DT_BIND_NOW
    push_dyn(&mut content, 30, 0x8); // DT_FLAGS = DF_BIND_NOW
    push_dyn(&mut content, 0x6ffffffb, 0x1); // DT_FLAGS_1 = DF_1_NOW
    push_dyn(&mut content, 0, 0);
    Ok(content)
}

/// Build the `.plt` and `.got.plt` byte vectors for x86_64 dynamic linking.
///
/// Returns `(plt_bytes, got_plt_bytes)`. The GOT is initialised to all-zeros;
/// the dynamic linker fills in the final symbol addresses at load time.
fn build_plt_got_x86_64(
    plt_symbols: &[String],
    layout: &MergedLayout,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let last = layout.sections.last().ok_or("no sections")?;
    let vaddr = align_up(last.vaddr + last.data.len() as u64, 16);
    let plt0_vaddr = vaddr;
    let plt_size = 16 + (plt_symbols.len() as u64) * 16;
    let got_plt_vaddr = align_up(vaddr + plt_size, 8);

    let mut plt = Vec::new();
    plt.extend_from_slice(&[0xff, 0x35]); // pushq rel32
    let disp_push = (got_plt_vaddr as i64 + 8 - (plt0_vaddr as i64 + 6)) as i32;
    plt.extend_from_slice(&disp_push.to_le_bytes());
    plt.extend_from_slice(&[0xff, 0x25]); // jmpq *rel32
    let disp_jmp = (got_plt_vaddr as i64 + 16 - (plt0_vaddr as i64 + 12)) as i32;
    plt.extend_from_slice(&disp_jmp.to_le_bytes());
    // Pad PLT0 to the full 16-byte stride. PLT[i] entries are addressed at
    // plt0 + 16 + i*16, so PLT0 must occupy exactly 16 bytes (12 used + 4 pad).
    plt.extend_from_slice(&[0x90, 0x90, 0x90, 0x90]);

    for (i, _) in plt_symbols.iter().enumerate() {
        let plt_n_vaddr = plt0_vaddr + 16 + (i as u64) * 16;
        let got_slot_vaddr = got_plt_vaddr + 24 + (i as u64) * 8;
        plt.extend_from_slice(&[0xff, 0x25]);
        let disp = (got_slot_vaddr as i64 - (plt_n_vaddr as i64 + 6)) as i32;
        plt.extend_from_slice(&disp.to_le_bytes());
        plt.push(0x68);
        plt.extend_from_slice(&(i as u32).to_le_bytes());
        plt.extend_from_slice(&[0xe9]);
        let jmp_disp = (plt0_vaddr as i64 - (plt_n_vaddr as i64 + 11)) as i32;
        plt.extend_from_slice(&jmp_disp.to_le_bytes());
    }

    let got_size = 24 + plt_symbols.len() * 8;
    let got = vec![0u8; got_size];

    Ok((plt, got))
}

/// Dispatch relocation application to the appropriate architecture handler.
pub fn apply_relocations(
    arch: TargetArch,
    layout: &mut MergedLayout,
    data: &[u8],
    sections: &[SectionHeader],
    names: &[String],
    symbol_addrs: &[Option<u64>],
    got_entries: &[Option<u64>],
    section_offset: Option<&HashMap<String, u64>>,
) -> Result<(), String> {
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

#[cfg(test)]
mod nobits_tests {
    use super::*;

    fn header(sh_type: u32, size: u64) -> SectionHeader {
        SectionHeader {
            name_offset: 0,
            sh_type,
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: 0,
            sh_size: size,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 1,
            sh_entsize: 0,
        }
    }

    #[test]
    fn nobits_contributes_its_size_so_bss_stays_mapped() {
        // Layout advances vaddr by sh_size while the segment's file size comes from
        // data.len(). An empty vector here left .bss outside the LOAD segment.
        let bss = read_section_data(&[], &header(SHT_NOBITS, 8));
        assert_eq!(bss, vec![0u8; 8]);
    }

    #[test]
    fn empty_and_unknown_sections_contribute_nothing() {
        assert!(read_section_data(&[], &header(SHT_NOBITS, 0)).is_empty());
        assert!(read_section_data(&[], &header(0, 8)).is_empty());
    }
}
