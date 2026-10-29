//! `-shared` support for x86_64: exported symbols, imported symbols, and the
//! dynamic relocations a shared object needs beyond the PIE ones.

use super::symbols::parse_symtab_view;
use super::{ParsedObject, SHN_UNDEF};
use crate::collections::{HashMap, HashSet};
use crate::elf::{get_strtab_string, parse_rela_section, reloc_type};
use crate::link::merge::MergedLayout;

const STB_LOCAL: u8 = 0;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;
const STV_DEFAULT: u8 = 0;
const SHT_SYMTAB: u32 = 2;
const SHF_ALLOC: u64 = 2;
const SHF_EXECINSTR: u64 = 4;
const SHN_ABS: u16 = 0xfff1;

/// Global default-visibility names defined by the inputs, in first-seen order.
pub(super) fn collect_exports(parsed: &[ParsedObject]) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    let mut seen = HashSet::default();
    for obj in parsed {
        let Some((symbols, strings)) = parse_symtab_view(&obj.data, &obj.sections)? else {
            continue;
        };
        let Some(table) = obj.sections.iter().find(|s| s.sh_type == SHT_SYMTAB) else {
            continue;
        };
        for (index, symbol) in symbols.iter().enumerate() {
            let record = table.sh_offset as usize + index * 24;
            let other = obj.data.get(record + 5).copied().unwrap_or(0);
            if symbol.bind == STB_LOCAL || symbol.st_shndx == SHN_UNDEF || other & 3 != STV_DEFAULT
            {
                continue;
            }
            if let Some(name) = get_strtab_string(strings, symbol.name_offset)
                && !name.is_empty()
                && seen.insert(name.clone())
            {
                names.push(name);
            }
        }
    }
    Ok(names)
}

/// Rejects absolute or PC-relative data references to symbols the inputs
/// do not define. Those need copy or text relocations, which `-shared` does
/// not produce. Calls through the PLT and GOT loads are allowed.
pub(super) fn reject_data_imports(parsed: &[ParsedObject]) -> Result<(), String> {
    let mut defined = HashSet::default();
    for obj in parsed {
        if let Some((symbols, strings)) = parse_symtab_view(&obj.data, &obj.sections)? {
            for symbol in symbols.iter().filter(|s| s.st_shndx != SHN_UNDEF) {
                if let Some(name) = get_strtab_string(strings, symbol.name_offset) {
                    defined.insert(name);
                }
            }
        }
    }
    for obj in parsed {
        let Some((symbols, strings)) = parse_symtab_view(&obj.data, &obj.sections)? else {
            continue;
        };
        for section in obj.sections.iter().filter(|s| s.sh_type == 4) {
            let target_alloc = obj
                .sections
                .get(section.sh_info as usize)
                .is_some_and(|s| s.sh_flags & SHF_ALLOC != 0);
            if !target_alloc {
                continue;
            }
            for rel in parse_rela_section(&obj.data, section)? {
                let symbol = symbols
                    .get(rel.r_sym as usize)
                    .ok_or("invalid relocation symbol index")?;
                if symbol.st_shndx != SHN_UNDEF {
                    continue;
                }
                let name = get_strtab_string(strings, symbol.name_offset).unwrap_or_default();
                if defined.contains(&name) {
                    continue;
                }
                let data_reference = matches!(
                    rel.r_type,
                    reloc_type::R_X86_64_64
                        | reloc_type::R_X86_64_32
                        | reloc_type::R_X86_64_32S
                        | reloc_type::R_X86_64_PC32
                );
                if data_reference {
                    return Err(format!(
                        "-shared: data reference to undefined symbol {name} needs a copy or text relocation, which is not supported"
                    ));
                }
            }
        }
    }
    Ok(())
}

/// GOT slots that hold the address of an imported symbol. Each gets a
/// `GLOB_DAT` record against that import's dynsym index (imports come first).
pub(super) fn glob_slots(got: &HashMap<String, u64>, imports: &[String]) -> Vec<(String, u32)> {
    imports
        .iter()
        .enumerate()
        .filter(|(_, name)| got.contains_key(name.as_str()))
        .map(|(index, name)| (name.clone(), index as u32 + 1))
        .collect()
}

/// Imports that are only ever referenced weakly. They bind as STB_WEAK so an
/// unresolved one stays 0 at load time instead of failing the dlopen.
pub(super) fn weak_imports(parsed: &[ParsedObject]) -> Result<HashSet<String>, String> {
    let mut weak = HashSet::default();
    let mut strong = HashSet::default();
    for obj in parsed {
        let Some((symbols, strings)) = parse_symtab_view(&obj.data, &obj.sections)? else {
            continue;
        };
        for symbol in symbols.iter().filter(|s| s.st_shndx == SHN_UNDEF) {
            let Some(name) = get_strtab_string(strings, symbol.name_offset) else {
                continue;
            };
            if symbol.bind == STB_WEAK {
                weak.insert(name);
            } else if symbol.bind == STB_GLOBAL {
                strong.insert(name);
            }
        }
    }
    weak.retain(|name| !strong.contains(name));
    Ok(weak)
}

/// Fills the final symbol fields of `.dynsym`. Imports keep their undefined
/// shndx, but weak ones are bound STB_WEAK. Exports take their final address
/// and section, and follow the imports in `.dynsym`.
pub(super) fn fill_dynsym(
    layout: &mut MergedLayout,
    globals: &HashMap<String, u64>,
    imports: &[String],
    weak: &HashSet<String>,
    exports: &[String],
) -> Result<(), String> {
    let dynsym_index = layout.section_by_name[".dynsym"];
    let mut data = std::mem::take(&mut layout.sections[dynsym_index].data);
    for (position, name) in imports.iter().enumerate() {
        if weak.contains(name) {
            let record = (position + 1) * 24;
            if let Some(entry) = data.get_mut(record + 4) {
                *entry = (STB_WEAK << 4) | 2;
            }
        }
    }
    let import_count = imports.len();
    for (position, name) in exports.iter().enumerate() {
        let Some(&address) = globals.get(name) else {
            continue;
        };
        let record = (import_count + position + 1) * 24;
        let section = layout.sections.iter().enumerate().find(|(_, s)| {
            s.flags & SHF_ALLOC != 0
                && address >= s.vaddr
                && address < s.vaddr + (s.data.len() as u64).max(1)
        });
        let (shndx, info_type) = match section {
            Some((index, s)) => (
                (index + 1) as u16,
                if s.flags & SHF_EXECINSTR != 0 { 2 } else { 1 },
            ),
            None => (SHN_ABS, 0),
        };
        let Some(entry) = data.get_mut(record..record + 24) else {
            return Err("shared export index out of range".into());
        };
        entry[4] = (1 << 4) | info_type;
        entry[6..8].copy_from_slice(&shndx.to_le_bytes());
        entry[8..16].copy_from_slice(&address.to_le_bytes());
    }
    layout.sections[dynsym_index].data = data;
    Ok(())
}
