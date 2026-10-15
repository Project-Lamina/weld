//! Symbol resolution across merged objects, and the output symbol table.

use super::{
    MergedLayout, ObjectSectionContrib, SHN_ABS, SHN_UNDEF, SHT_SYMTAB, STB_LOCAL, STB_WEAK,
    merge_sections_single_object,
};
use crate::{
    collections::{HashMap, HashSet},
    elf::{
        SectionHeader, Symbol, get_strtab_from_section, get_strtab_string, parse_elf64_slice,
        parse_rela_section, parse_symtab,
        reloc_type::{R_X86_64_GOTPCREL, R_X86_64_GOTPCRELX, R_X86_64_REX_GOTPCRELX},
    },
};

/// Return type for symbol-table parsing: a list of symbols and the raw string table.
pub(super) type SymtabView<'a> = Option<(Vec<Symbol>, &'a [u8])>;

/// Resolved symbol table paired with per-section virtual-address overrides.
pub(super) type ResolvedSymbols = (HashMap<String, ResolvedSymbol>, Vec<Option<u64>>);
#[derive(Debug, Clone)]
pub struct ResolvedSymbol {
    pub address: Option<u64>,
    pub size: u64,
    pub is_defined: bool,
}
#[derive(Debug, Clone)]
pub struct OutputSymbol {
    pub name: String,
    pub info: u8,
    pub shndx: u16,
    pub value: u64,
    pub size: u64,
}
pub(super) fn collect_output_symbols(
    data: &[u8],
    sections: &[SectionHeader],
    names: &[String],
    layout: &MergedLayout,
    section_offset: impl Fn(&str) -> Option<u64>,
    globals: &HashMap<String, u64>,
) -> Result<Vec<OutputSymbol>, String> {
    let Some((symbols, strtab)) = parse_symtab_view(data, sections)? else {
        return Ok(Vec::new());
    };
    let mut output = Vec::new();
    for sym in symbols {
        if sym.st_shndx == SHN_UNDEF {
            continue;
        }
        let name = get_strtab_string(strtab, sym.name_offset).ok_or("invalid symbol name")?;
        if sym.bind == STB_LOCAL
            && (sym.sym_type == 3
                || (name.starts_with(".L")
                    && sections
                        .get(sym.st_shndx as usize)
                        .is_some_and(|s| s.sh_flags & 0x10 != 0)))
        {
            continue;
        }
        let (shndx, value) = if sym.st_shndx == SHN_ABS {
            (SHN_ABS, sym.st_value)
        } else {
            let Some(section_name) = names.get(sym.st_shndx as usize) else {
                continue;
            };
            let Some(&index) = layout.section_by_name.get(section_name) else {
                continue;
            };
            let Some(offset) = section_offset(section_name) else {
                continue;
            };
            (
                (index + 1) as u16,
                layout.sections[index].vaddr + offset + sym.st_value,
            )
        };
        if sym.bind != STB_LOCAL && globals.get(&name).is_some_and(|&addr| addr != value) {
            continue;
        }
        output.push(OutputSymbol {
            name,
            info: (sym.bind << 4) | sym.sym_type,
            shndx,
            value,
            size: sym.st_size,
        });
    }
    Ok(output)
}
pub(super) fn parse_symtab_view<'a>(
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

pub(super) fn resolve_symbols_with_offsets<F>(
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
        return Ok((HashMap::default(), Vec::new()));
    };

    let mut resolved = HashMap::default();
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

        let index_address = if sym.st_shndx == SHN_UNDEF && sym.bind == STB_WEAK {
            Some(0)
        } else {
            address
        };
        by_index.push(index_address);
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
/// skipped. `seen` carries membership across objects, because `out` holds GOT
/// slot order and scanning it per relocation is quadratic under -fPIC.
pub(super) fn collect_gotpcrel_symbol_names(
    data: &[u8],
    sections: &[SectionHeader],
    out: &mut Vec<String>,
    seen: &mut HashSet<String>,
) {
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
            if !matches!(
                rel.r_type,
                R_X86_64_GOTPCREL | R_X86_64_GOTPCRELX | R_X86_64_REX_GOTPCRELX
            ) {
                continue;
            }
            if let Some(name) = sym_names.get(rel.r_sym as usize)
                && !name.is_empty()
                && seen.insert(name.clone())
            {
                out.push(name.clone());
            }
        }
    }
}

/// Like `symbol_names_by_index` but returns `None` on parse failure instead
/// of `Err`, for use in best-effort pre-scans.
pub(super) fn symbol_names_by_index_raw(data: &[u8], sections: &[SectionHeader]) -> Option<Vec<String>> {
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

pub(super) fn symbol_names_by_index(data: &[u8], sections: &[SectionHeader]) -> Result<Vec<String>, String> {
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

pub(super) fn resolve_symbols_for_object(
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
