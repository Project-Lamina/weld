//! Section merging and layout for single-object linking.
//!
//! Architecture-specific relocation logic lives in parallel modules:
//! - x86_64: x86_64.rs
//! - aarch64: aarch64.rs
//! - riscv: riscv.rs

#![allow(dead_code)]

mod aarch64;
pub mod macho;
mod riscv;
mod x86_64;

use crate::arch::TargetArch;
use crate::elf::{Elf64Header, SectionHeader, Symbol, parse_elf64_slice, parse_symtab};
use std::collections::HashMap;
use std::path::Path;
use std::thread;

/// Pre-parsed object for reuse in multi-object linking.
pub struct ParsedObject {
    pub data: Vec<u8>,
    pub header: Elf64Header,
    pub sections: Vec<SectionHeader>,
    pub names: Vec<String>,
}

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

#[derive(Debug)]
pub struct LinkResult {
    pub layout: MergedLayout,
    pub e_machine: u16,
    pub symbol_addrs: HashMap<String, u64>,
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
    if sh.sh_type == SHT_PROGBITS && sh.sh_size > 0 {
        let start = sh.sh_offset as usize;
        let end = start + sh.sh_size as usize;
        data.get(start..end).unwrap_or(&[]).to_vec()
    } else {
        Vec::new()
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
            let offset_in_merged = *section_cumul.get(&name).unwrap_or(&0);
            section_cumul.insert(name.clone(), offset_in_merged + size);

            let align = sh.sh_addralign.max(1);
            section_aligns
                .entry(name.clone())
                .and_modify(|a| *a = (*a).max(align))
                .or_insert(align);

            section_flags
                .entry(name.clone())
                .and_modify(|f| *f |= sh.sh_flags)
                .or_insert(sh.sh_flags);

            let entry = merged_data.entry(name.clone()).or_default();
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
) -> Result<Option<(Vec<Symbol>, &'a [u8])>, String> {
    let Some(symtab_sh) = sections.iter().find(|sh| sh.sh_type == SHT_SYMTAB) else {
        return Ok(None);
    };

    let strtab_idx = symtab_sh.sh_link as usize;
    let strtab_sh = sections.get(strtab_idx).ok_or("symtab sh_link invalid")?;
    let strtab = crate::elf::get_strtab_from_section(data, strtab_sh);
    let symbols = parse_symtab(data, symtab_sh)?;

    Ok(Some((symbols, strtab)))
}

fn resolve_symbols_with_offsets<F>(
    data: &[u8],
    layout: &MergedLayout,
    sections: &[SectionHeader],
    names: &[String],
    mut section_offset: F,
) -> Result<(HashMap<String, ResolvedSymbol>, Vec<Option<u64>>), String>
where
    F: FnMut(&str) -> Option<u64>,
{
    let Some((symbols, strtab)) = parse_symtab_view(data, sections)? else {
        return Ok((HashMap::new(), Vec::new()));
    };

    let mut resolved = HashMap::new();
    let mut by_index: Vec<Option<u64>> = Vec::with_capacity(symbols.len());

    for sym in &symbols {
        let name = crate::elf::get_strtab_string(strtab, sym.name_offset)
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
        if !name.is_empty() {
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

fn symbol_names_by_index(data: &[u8], sections: &[SectionHeader]) -> Result<Vec<String>, String> {
    let Some((symbols, strtab)) = parse_symtab_view(data, sections)? else {
        return Ok(Vec::new());
    };

    Ok(symbols
        .iter()
        .map(|sym| {
            crate::elf::get_strtab_string(strtab, sym.name_offset)
                .unwrap_or_else(|| format!("<sym_{}>", sym.name_offset))
        })
        .collect())
}

pub fn resolve_symbols(
    data: &[u8],
    layout: &MergedLayout,
    sections: &[SectionHeader],
    names: &[String],
) -> Result<(HashMap<String, ResolvedSymbol>, Vec<Option<u64>>), String> {
    resolve_symbols_with_offsets(data, layout, sections, names, |_| Some(0))
}

fn resolve_symbols_for_object(
    data: &[u8],
    layout: &MergedLayout,
    sections: &[SectionHeader],
    names: &[String],
    obj_contribs: &HashMap<String, ObjectSectionContrib>,
) -> Result<(HashMap<String, ResolvedSymbol>, Vec<Option<u64>>), String> {
    resolve_symbols_with_offsets(data, layout, sections, names, |section_name| {
        obj_contribs
            .get(section_name)
            .map(|contrib| contrib.offset_in_merged)
    })
}

pub fn merge_and_resolve(
    data: &[u8],
) -> Result<(MergedLayout, HashMap<String, ResolvedSymbol>), String> {
    let (_header, sections, names) = parse_elf64_slice(data)?;
    let layout = merge_sections_single_object(data)?;
    let (symbols, _by_index) = resolve_symbols(data, &layout, &sections, &names)?;
    Ok((layout, symbols))
}

pub fn link_single_object(data: &[u8]) -> Result<LinkResult, String> {
    let (header, sections, names) = parse_elf64_slice(data)?;
    let mut layout = merge_sections_single_object(data)?;
    let (resolved, by_index) = resolve_symbols(data, &layout, &sections, &names)?;
    let arch = TargetArch::from_elf_machine(header.e_machine)
        .ok_or_else(|| format!("unsupported machine {}", header.e_machine))?;
    apply_relocations(arch, &mut layout, data, &sections, &names, &by_index, None)?;
    let symbol_addrs: HashMap<String, u64> = resolved
        .into_iter()
        .filter_map(|(name, r)| r.address.map(|a| (name, a)))
        .collect();
    Ok(LinkResult {
        layout,
        e_machine: header.e_machine,
        symbol_addrs,
    })
}

/// Link multiple object files. Same e_machine required. No -l libraries.
pub fn link_multi_object(objects: &[&[u8]]) -> Result<LinkResult, String> {
    if objects.is_empty() {
        return Err("no objects to link".to_string());
    }
    if objects.len() == 1 {
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

    link_multi_object_parsed(&parsed)
}

fn link_multi_object_parsed(parsed: &[ParsedObject]) -> Result<LinkResult, String> {
    if parsed.is_empty() {
        return Err("no objects to link".to_string());
    }
    if parsed.len() == 1 {
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
            Some(&section_off),
        )?;
    }

    Ok(LinkResult {
        layout,
        e_machine,
        symbol_addrs: global_symbols,
    })
}

pub fn apply_relocations(
    arch: TargetArch,
    layout: &mut MergedLayout,
    data: &[u8],
    sections: &[SectionHeader],
    names: &[String],
    symbol_addrs: &[Option<u64>],
    section_offset: Option<&HashMap<String, u64>>,
) -> Result<(), String> {
    match arch {
        TargetArch::X86_64 => {
            x86_64::apply_relocations(layout, data, sections, names, symbol_addrs, section_offset)
        }
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
        use lamina_platform::{TargetArchitecture, TargetOperatingSystem};

        let asm = ".text\n.globl main\nmain:\n  movq $42, %rax\n  ret\n";
        let tmp = std::env::temp_dir().join("weld_merge_test.o");

        let mut ras =
            ras::Ras::new(TargetArchitecture::X86_64, TargetOperatingSystem::Linux).expect("ras");
        ras.assemble(asm, &tmp).expect("assemble");

        let layout = merge_object_file(&tmp).expect("merge");
        let _ = std::fs::remove_file(&tmp);

        assert!(!layout.sections.is_empty());
        assert!(layout.section_by_name.get(".text").is_some());
    }

    #[test]
    fn test_merge_and_resolve() {
        use lamina_platform::{TargetArchitecture, TargetOperatingSystem};

        let asm = ".text\n.globl main\nmain:\n  movq $42, %rax\n  ret\n";
        let tmp = std::env::temp_dir().join("weld_resolve_test.o");

        let mut ras =
            ras::Ras::new(TargetArchitecture::X86_64, TargetOperatingSystem::Linux).expect("ras");
        ras.assemble(asm, &tmp).expect("assemble");

        let data = std::fs::read(&tmp).expect("read");
        let _ = std::fs::remove_file(&tmp);

        let (layout, symbols) = merge_and_resolve(&data).expect("merge_and_resolve");
        assert!(!layout.sections.is_empty());
        assert!(layout.section_by_name.get(".text").is_some());
        assert!(symbols.is_empty() || symbols.contains_key("main"));
    }

    #[test]
    fn test_link_single_object() {
        use lamina_platform::{TargetArchitecture, TargetOperatingSystem};

        let asm = ".text\n.globl main\nmain:\n  movq $42, %rax\n  ret\n";
        let tmp = std::env::temp_dir().join("weld_link_test.o");

        let mut ras =
            ras::Ras::new(TargetArchitecture::X86_64, TargetOperatingSystem::Linux).expect("ras");
        ras.assemble(asm, &tmp).expect("assemble");

        let data = std::fs::read(&tmp).expect("read");
        let _ = std::fs::remove_file(&tmp);

        let result = link_single_object(&data).expect("link_single_object");
        assert!(!result.layout.sections.is_empty());
        assert!(result.layout.section_by_name.get(".text").is_some());
    }

    #[test]
    fn test_link_multi_object() {
        use lamina_platform::{TargetArchitecture, TargetOperatingSystem};

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
        let result = link_multi_object(&objects).expect("link_multi_object");
        assert!(!result.layout.sections.is_empty());
        assert!(result.layout.section_by_name.get(".text").is_some());
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
        use lamina_platform::{TargetArchitecture, TargetOperatingSystem};

        let asm = ".text\n.globl main\nmain:\n  mov x0, #42\n  ret\n";
        let tmp = std::env::temp_dir().join("weld_link_aarch64_test.o");

        let mut ras =
            ras::Ras::new(TargetArchitecture::Aarch64, TargetOperatingSystem::Linux).expect("ras");
        ras.assemble(asm, &tmp).expect("assemble");

        let data = std::fs::read(&tmp).expect("read");
        let _ = std::fs::remove_file(&tmp);

        let result = link_single_object(&data).expect("link_single_object");
        assert!(!result.layout.sections.is_empty());
        assert!(result.layout.section_by_name.get(".text").is_some());
        assert_eq!(result.e_machine, 183);
    }
}
