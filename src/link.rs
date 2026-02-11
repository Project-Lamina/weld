//! Section merging and layout for single-object linking.

#![allow(dead_code)]

use crate::arch::TargetArch;
use crate::elf::{
    get_strtab_from_section, parse_elf64_slice, parse_rela_section, parse_symtab, SectionHeader,
};
use crate::elf::reloc_type;
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
) -> Result<(HashMap<String, ResolvedSymbol>, Vec<Option<u64>>), String> {
    const SHT_SYMTAB: u32 = 2;

    let symtab_idx = sections
        .iter()
        .enumerate()
        .find(|(_, sh)| sh.sh_type == SHT_SYMTAB)
        .map(|(i, _)| i);

    let Some(symtab_idx) = symtab_idx else {
        return Ok((HashMap::new(), Vec::new()));
    };

    let symtab_sh = &sections[symtab_idx];
    let strtab_idx = symtab_sh.sh_link as usize;
    let strtab_sh = sections.get(strtab_idx).ok_or("symtab sh_link invalid")?;
    let strtab = get_strtab_from_section(data, strtab_sh);

    let symbols = parse_symtab(data, symtab_sh)?;
    let mut resolved = HashMap::new();
    let mut by_index: Vec<Option<u64>> = Vec::with_capacity(symbols.len());

    for sym in &symbols {
        let name = crate::elf::get_strtab_string(strtab, sym.name_offset)
            .unwrap_or_else(|| format!("<sym_{}>", sym.name_offset));

        let (address, is_defined) = match sym.st_shndx {
            SHN_UNDEF => (None, false),
            SHN_ABS => (Some(sym.st_value), true),
            shndx => {
                let section_name = names.get(shndx as usize).cloned().unwrap_or_default();
                let Some(&merged_idx) = layout.section_by_name.get(&section_name) else {
                    by_index.push(None);
                    if !name.is_empty() {
                        resolved.insert(
                            name,
                            ResolvedSymbol {
                                address: None,
                                size: sym.st_size,
                                is_defined: false,
                            },
                        );
                    }
                    continue;
                };
                let merged = &layout.sections[merged_idx];
                let addr = merged.vaddr + sym.st_value;
                (Some(addr), true)
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

pub fn merge_and_resolve(data: &[u8]) -> Result<(MergedLayout, HashMap<String, ResolvedSymbol>), String> {
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
    apply_relocations(arch, &mut layout, data, &sections, &names, &by_index)?;
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

fn write_u32_le(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn write_u64_le(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
}

pub fn apply_relocations(
    arch: TargetArch,
    layout: &mut MergedLayout,
    data: &[u8],
    sections: &[SectionHeader],
    names: &[String],
    symbol_addrs: &[Option<u64>],
) -> Result<(), String> {
    match arch {
        TargetArch::X86_64 => apply_relocations_x86_64(layout, data, sections, names, symbol_addrs),
        TargetArch::AArch64 | TargetArch::RiscV => {
            Err(format!("relocations for {:?} not yet implemented", arch))
        }
    }
}

fn apply_relocations_x86_64(
    layout: &mut MergedLayout,
    data: &[u8],
    sections: &[SectionHeader],
    names: &[String],
    symbol_addrs: &[Option<u64>],
) -> Result<(), String> {
    const SHT_RELA: u32 = 4;

    for (_rela_idx, rela_sh) in sections.iter().enumerate() {
        if rela_sh.sh_type != SHT_RELA {
            continue;
        }
        let target_section_idx = rela_sh.sh_info as usize;
        let target_name = names.get(target_section_idx).cloned().unwrap_or_default();
        let Some(&merged_idx) = layout.section_by_name.get(&target_name) else {
            continue;
        };
        let merged = &mut layout.sections[merged_idx];
        let relas = parse_rela_section(data, rela_sh)?;

        for rel in &relas {
            let place = merged.vaddr + rel.r_offset;
            let a = rel.r_addend;
            let p = place as i64;

            match rel.r_type {
                reloc_type::R_X86_64_NONE => {}
                reloc_type::R_X86_64_RELATIVE => {
                    let base = merged.vaddr as i64;
                    let val = base.wrapping_add(a) as u64;
                    let off = rel.r_offset as usize;
                    if merged.data.len() < off + 8 {
                        return Err(format!("relocation offset {} out of bounds", rel.r_offset));
                    }
                    write_u64_le(&mut merged.data, off, val);
                }
                reloc_type::R_X86_64_64 => {
                    let Some(Some(s_addr)) = symbol_addrs.get(rel.r_sym as usize) else {
                        return Err(format!("undefined symbol index {}", rel.r_sym));
                    };
                    let val = s_addr.wrapping_add_signed(a);
                    let off = rel.r_offset as usize;
                    if merged.data.len() < off + 8 {
                        return Err(format!("relocation offset {} out of bounds", rel.r_offset));
                    }
                    write_u64_le(&mut merged.data, off, val);
                }
                reloc_type::R_X86_64_32 => {
                    let Some(Some(s_addr)) = symbol_addrs.get(rel.r_sym as usize) else {
                        return Err(format!("undefined symbol index {}", rel.r_sym));
                    };
                    let val = s_addr.wrapping_add_signed(a) as u32;
                    let off = rel.r_offset as usize;
                    if merged.data.len() < off + 4 {
                        return Err(format!("relocation offset {} out of bounds", rel.r_offset));
                    }
                    write_u32_le(&mut merged.data, off, val);
                }
                reloc_type::R_X86_64_PC32 => {
                    let Some(Some(s_addr)) = symbol_addrs.get(rel.r_sym as usize) else {
                        return Err(format!("undefined symbol index {}", rel.r_sym));
                    };
                    let val = (*s_addr as i64).wrapping_add(a).wrapping_sub(p) as u32;
                    let off = rel.r_offset as usize;
                    if merged.data.len() < off + 4 {
                        return Err(format!("relocation offset {} out of bounds", rel.r_offset));
                    }
                    write_u32_le(&mut merged.data, off, val);
                }
                _ => {
                    return Err(format!("unsupported relocation type {}", rel.r_type));
                }
            }
        }
    }

    Ok(())
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

    #[test]
    fn test_link_single_object() {
        use lamina_platform::{TargetArchitecture, TargetOperatingSystem};

        let asm = ".text\n.globl main\nmain:\n  movq $42, %rax\n  ret\n";
        let tmp = std::env::temp_dir().join("weld_link_test.o");

        let mut ras = ras::Ras::new(TargetArchitecture::X86_64, TargetOperatingSystem::Linux)
            .expect("ras");
        ras.assemble(asm, &tmp).expect("assemble");

        let data = std::fs::read(&tmp).expect("read");
        let _ = std::fs::remove_file(&tmp);

        let result = link_single_object(&data).expect("link_single_object");
        assert!(!result.layout.sections.is_empty());
        assert!(result.layout.section_by_name.get(".text").is_some());
    }
}
