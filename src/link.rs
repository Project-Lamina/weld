//! Section merging and layout for single-object linking.

#![allow(dead_code)]

use crate::elf::{
    get_strtab_from_section, parse_elf64_slice, parse_symtab, SectionHeader,
};
use std::collections::HashMap;
use std::path::Path;

const SHN_UNDEF: u16 = 0;
const SHN_ABS: u16 = 0xfff1;

const SHF_ALLOC: u64 = 2;
const SHF_EXECINSTR: u64 = 4;
const SHF_WRITE: u64 = 1;
const SHT_PROGBITS: u32 = 1;
const SHT_NOBITS: u32 = 8;

const TEXT_ALIGN: u64 = 16;
const RODATA_ALIGN: u64 = 16;
const DATA_ALIGN: u64 = 8;

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

pub fn merge_sections_single_object(data: &[u8]) -> Result<MergedLayout, String> {
    let (_header, sections, names) = parse_elf64_slice(data)?;

    let mut to_merge: Vec<(String, &SectionHeader)> = Vec::new();
    for (i, sh) in sections.iter().enumerate() {
        if sh.sh_type != SHT_PROGBITS && sh.sh_type != SHT_NOBITS {
            continue;
        }
        if !is_allocatable(sh.sh_flags) {
            continue;
        }
        let name = names.get(i).cloned().unwrap_or_default();
        to_merge.push((name, sh));
    }

    to_merge.sort_by_key(|(name, _)| section_merge_order(name));

    let mut layout = MergedLayout {
        sections: Vec::new(),
        section_by_name: HashMap::new(),
    };

    let mut vaddr: u64 = 0x400000;

    for (name, sh) in &to_merge {
        let align = sh.sh_addralign.max(1);
        vaddr = align_up(vaddr, align);

        let data_slice = if sh.sh_type == SHT_PROGBITS && sh.sh_size > 0 {
            let start = sh.sh_offset as usize;
            let end = start + sh.sh_size as usize;
            data.get(start..end).unwrap_or(&[]).to_vec()
        } else {
            Vec::new()
        };

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

pub fn resolve_symbols(
    data: &[u8],
    layout: &MergedLayout,
    sections: &[SectionHeader],
    names: &[String],
) -> Result<HashMap<String, ResolvedSymbol>, String> {
    const SHT_SYMTAB: u32 = 2;

    let symtab_idx = sections
        .iter()
        .enumerate()
        .find(|(_, sh)| sh.sh_type == SHT_SYMTAB)
        .map(|(i, _)| i);

    let Some(symtab_idx) = symtab_idx else {
        return Ok(HashMap::new());
    };

    let symtab_sh = &sections[symtab_idx];
    let strtab_idx = symtab_sh.sh_link as usize;
    let strtab_sh = sections.get(strtab_idx).ok_or("symtab sh_link invalid")?;
    let strtab = get_strtab_from_section(data, strtab_sh);

    let symbols = parse_symtab(data, symtab_sh)?;
    let mut resolved = HashMap::new();

    for sym in &symbols {
        let name = crate::elf::get_strtab_string(strtab, sym.name_offset)
            .unwrap_or_else(|| format!("<sym_{}>", sym.name_offset));
        if name.is_empty() {
            continue;
        }

        let (address, is_defined) = match sym.st_shndx {
            SHN_UNDEF => (None, false),
            SHN_ABS => (Some(sym.st_value), true),
            shndx => {
                let section_name = names.get(shndx as usize).cloned().unwrap_or_default();
                let Some(&merged_idx) = layout.section_by_name.get(&section_name) else {
                    resolved.insert(
                        name.clone(),
                        ResolvedSymbol {
                            address: None,
                            size: sym.st_size,
                            is_defined: false,
                        },
                    );
                    continue;
                };
                let merged = &layout.sections[merged_idx];
                let addr = merged.vaddr + sym.st_value;
                (Some(addr), true)
            }
        };

        resolved.insert(
            name,
            ResolvedSymbol {
                address,
                size: sym.st_size,
                is_defined,
            },
        );
    }

    Ok(resolved)
}

pub fn merge_and_resolve(data: &[u8]) -> Result<(MergedLayout, HashMap<String, ResolvedSymbol>), String> {
    let (_header, sections, names) = parse_elf64_slice(data)?;
    let layout = merge_sections_single_object(data)?;
    let symbols = resolve_symbols(data, &layout, &sections, &names)?;
    Ok((layout, symbols))
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

        let mut ras = ras::Ras::new(TargetArchitecture::X86_64, TargetOperatingSystem::Linux)
            .expect("ras");
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

        let mut ras = ras::Ras::new(TargetArchitecture::X86_64, TargetOperatingSystem::Linux)
            .expect("ras");
        ras.assemble(asm, &tmp).expect("assemble");

        let data = std::fs::read(&tmp).expect("read");
        let _ = std::fs::remove_file(&tmp);

        let (layout, symbols) = merge_and_resolve(&data).expect("merge_and_resolve");
        assert!(!layout.sections.is_empty());
        assert!(layout.section_by_name.get(".text").is_some());
        assert!(symbols.is_empty() || symbols.contains_key("main"));
    }
}
