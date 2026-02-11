//! Mach-O object linking for macOS.
//!
//! Merges sections, resolves symbols, applies relocations.
//! Supports single-object no-libc (ret42-style) initially.

use crate::arch::TargetArch;
use crate::link::{LinkResult, MergedLayout, MergedSection};
use crate::macho::{Macho64Object, MachoSection, parse_macho64_object};
use std::collections::HashMap;

const PAGE_SIZE: u64 = 4096;
const SEG_BASE: u64 = 0x100000000;

fn macho_section_merge_order(sectname: &str) -> usize {
    match sectname {
        "__text" => 0,
        "__cstring" | "__rodata" => 1,
        "__data" => 2,
        "__bss" => 3,
        _ => 4,
    }
}

fn is_mergeable_section(sec: &MachoSection) -> bool {
    if sec.size == 0 {
        return false;
    }
    if sec.sectname == "__compact_unwind"
        || sec.sectname.starts_with("__") && sec.sectname.contains("unwind")
    {
        return false;
    }
    sec.segname == "__TEXT" || sec.segname == "__DATA" || sec.segname == "__LD"
}

fn read_section_data(obj: &Macho64Object, sec: &MachoSection) -> Vec<u8> {
    let start = sec.offset as usize;
    let end = start + sec.size as usize;
    obj.data.get(start..end).unwrap_or(&[]).to_vec()
}

fn align_up(value: u64, align: u64) -> u64 {
    if align == 0 {
        return value;
    }
    let a = 1u64 << align;
    (value + a - 1) & !(a - 1)
}

fn merge_macho_sections(obj: &Macho64Object) -> MergedLayout {
    let mut to_merge: Vec<&MachoSection> = obj
        .sections
        .iter()
        .filter(|s| is_mergeable_section(s))
        .collect();
    to_merge.sort_by_key(|s| macho_section_merge_order(&s.sectname));

    let mut layout = MergedLayout {
        sections: Vec::new(),
        section_by_name: HashMap::new(),
    };

    let mut vaddr = SEG_BASE;
    for sec in to_merge {
        let align = if sec.align > 0 { sec.align as u64 } else { 4 };
        vaddr = align_up(vaddr, align);

        let name = if sec.sectname == "__text" {
            ".text".to_string()
        } else {
            sec.sectname.clone()
        };

        let data = read_section_data(obj, sec);
        let flags = if sec.sectname == "__text" { 6 } else { 2 };
        let idx = layout.sections.len();
        layout.section_by_name.insert(name.clone(), idx);
        layout.sections.push(MergedSection {
            name,
            data,
            vaddr,
            flags,
            align,
        });
        vaddr += sec.size;
    }

    layout
}

fn resolve_macho_symbols(obj: &Macho64Object, layout: &MergedLayout) -> HashMap<String, u64> {
    let mut addrs = HashMap::new();
    let mut vaddr_by_sect: HashMap<u8, u64> = HashMap::new();

    for (i, sec) in obj.sections.iter().enumerate() {
        let sect_idx = (i + 1) as u8;
        let name = if sec.sectname == "__text" {
            ".text"
        } else {
            &sec.sectname
        };
        if let Some(&idx) = layout.section_by_name.get(name) {
            vaddr_by_sect.insert(sect_idx, layout.sections[idx].vaddr);
        }
    }

    for sym in &obj.symbols {
        if !sym.is_defined || sym.name.is_empty() {
            continue;
        }
        if let Some(&base) = vaddr_by_sect.get(&sym.sect) {
            addrs.insert(sym.name.clone(), base + sym.value);
        }
    }

    addrs
}

pub fn link_macho_single_object(data: &[u8]) -> Result<LinkResult, String> {
    let obj = parse_macho64_object(data)?;
    let arch = TargetArch::from_macho_cputype(obj.header.cputype)
        .ok_or_else(|| format!("unsupported Mach-O cputype {}", obj.header.cputype))?;

    let layout = merge_macho_sections(&obj);
    let symbol_addrs = resolve_macho_symbols(&obj, &layout);

    let e_machine = arch.to_elf_machine();

    Ok(LinkResult {
        layout,
        e_machine,
        symbol_addrs,
    })
}
