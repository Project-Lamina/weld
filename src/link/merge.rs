//! Merge input object sections into one output layout.

use super::{
    SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHN_UNDEF, SHT_NOBITS, SHT_PROGBITS, parse_symtab_view,
    runtime,
};
use crate::{
    collections::HashMap,
    elf::{SectionHeader, get_strtab_string, parse_elf64_slice},
};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct MergedSection {
    pub entsize: u64,
    pub sh_type: u32,
    pub name: String,
    pub data: Vec<u8>,
    pub vaddr: u64,
    pub flags: u64,
    pub align: u64,
}

impl MergedSection {
    pub fn is_relro(&self) -> bool {
        runtime::relro(&self.name)
    }
}

#[derive(Debug, Clone)]
pub struct MergedLayout {
    pub sections: Vec<MergedSection>,
    pub section_by_name: HashMap<String, usize>,
}
pub(super) fn reserve_start(
    layout: &mut MergedLayout,
    sections: &[SectionHeader],
    data: &[u8],
) -> Result<(), String> {
    let Some((symbols, strings)) = parse_symtab_view(data, sections)? else {
        return Ok(());
    };
    if symbols.iter().any(|s| {
        s.st_shndx != SHN_UNDEF
            && get_strtab_string(strings, s.name_offset).as_deref() == Some("_start")
    }) {
        return Ok(());
    }
    reserve_start_section(layout);
    Ok(())
}

pub(super) fn reserve_start_section(layout: &mut MergedLayout) {
    let end = layout
        .sections
        .iter()
        .map(|s| s.vaddr + s.data.len() as u64)
        .max()
        .unwrap_or(0x400000);
    layout
        .section_by_name
        .insert(".text.__weld_start".into(), layout.sections.len());
    layout.sections.push(MergedSection {
        name: ".text.__weld_start".into(),
        entsize: 0,
        sh_type: 1,
        data: vec![0; 64],
        vaddr: align_up(end, 16),
        flags: 6,
        align: 16,
    });
}

pub(super) fn layout_segments(layout: &mut MergedLayout, page: u64) -> Vec<(u64, u64, u64)> {
    let base = layout
        .sections
        .iter()
        .map(|s| s.vaddr)
        .min()
        .unwrap_or(page);
    let old: Vec<_> = layout
        .sections
        .iter()
        .map(|s| (s.vaddr, s.data.len() as u64))
        .collect();
    let mut order: Vec<_> = (0..layout.sections.len()).collect();
    order.sort_by_key(|&i| {
        let s = &layout.sections[i];
        (
            segment_class(s),
            s.sh_type == SHT_NOBITS,
            runtime::array_order(&s.name),
            i,
        )
    });
    let mut end = base;
    let mut previous = None;
    for i in order {
        let section = &mut layout.sections[i];
        let class = segment_class(section);
        if previous != Some(class) {
            end = align_up(end, page);
        }
        section.vaddr = align_up(end, section.align);
        if section.name == ".relro_padding" {
            section
                .data
                .resize((align_up(section.vaddr, page) - section.vaddr) as usize, 0);
        }
        end = section.vaddr + section.data.len() as u64;
        previous = Some(class);
    }
    old.into_iter()
        .zip(&layout.sections)
        .map(|((start, size), s)| (start, size, s.vaddr))
        .collect()
}

pub(crate) fn segment_class(section: &MergedSection) -> u8 {
    if section.is_relro() {
        3
    } else if section.flags & SHF_EXECINSTR != 0 {
        1
    } else if section.flags & SHF_WRITE != 0 {
        4
    } else if section.name.starts_with(".rodata")
        || matches!(
            section.name.as_str(),
            ".eh_frame" | ".eh_frame_hdr" | ".gcc_except_table"
        )
    {
        2
    } else {
        0
    }
}

pub(super) fn move_nobits(layout: &mut MergedLayout) {
    let mut end = layout
        .sections
        .iter()
        .filter(|s| s.sh_type != SHT_NOBITS)
        .map(|s| s.vaddr + s.data.len() as u64)
        .max()
        .unwrap_or(0x400000);
    for section in &mut layout.sections {
        if section.sh_type == SHT_NOBITS {
            end = align_up(end, section.align);
            section.vaddr = end;
            end += section.data.len() as u64;
        }
    }
}
pub(super) fn align_up(value: u64, align: u64) -> u64 {
    if align == 0 {
        return value;
    }
    (value + align - 1) & !(align - 1)
}

pub(super) fn is_allocatable(flags: u64) -> bool {
    (flags & SHF_ALLOC) != 0
}

pub(super) fn output_section_name(name: &str) -> &str {
    for base in [
        ".data.rel.ro",
        ".text",
        ".rodata",
        ".data",
        ".bss",
        ".sdata",
        ".sbss",
        ".tdata",
        ".tbss",
        ".gcc_except_table",
        ".init",
        ".fini",
    ] {
        if name == base
            || name
                .strip_prefix(base)
                .is_some_and(|tail| tail.starts_with('.'))
        {
            return base;
        }
    }
    name
}

pub(super) fn section_merge_order(name: &str) -> usize {
    match name {
        ".text" => 0,
        ".rodata" => 1,
        ".data" => 2,
        ".bss" => 3,
        _ => 4,
    }
}

pub(super) fn collect_mergeable_sections<'a>(
    sections: &'a [SectionHeader],
    names: &[String],
) -> Vec<(String, &'a SectionHeader)> {
    let mut to_merge: Vec<(String, &SectionHeader)> = sections
        .iter()
        .enumerate()
        .filter(|(_, sh)| {
            (matches!(sh.sh_type, SHT_PROGBITS | SHT_NOBITS | 14..=16))
                && is_allocatable(sh.sh_flags)
        })
        .map(|(i, sh)| (names.get(i).cloned().unwrap_or_default(), sh))
        .collect();

    to_merge.sort_by_key(|(name, _)| section_merge_order(name));
    to_merge
}

pub(super) fn read_section_data(data: &[u8], sh: &SectionHeader) -> Vec<u8> {
    if sh.sh_size == 0 {
        return Vec::new();
    }
    match sh.sh_type {
        SHT_PROGBITS | 14..=16 => {
            let start = sh.sh_offset as usize;
            let end = start + sh.sh_size as usize;
            data.get(start..end).unwrap_or(&[]).to_vec()
        }
        SHT_NOBITS => vec![0u8; sh.sh_size as usize],
        _ => Vec::new(),
    }
}

pub(super) fn default_flags_for_section(name: &str) -> u64 {
    match name {
        ".text" => SHF_ALLOC | SHF_EXECINSTR,
        ".rodata" => SHF_ALLOC,
        ".data" | ".bss" => SHF_ALLOC | SHF_WRITE,
        _ => SHF_ALLOC,
    }
}

pub(super) fn append_merged_section(
    layout: &mut MergedLayout,
    name: &str,
    contribs: &[(Vec<u8>, u64)],
    align: u64,
    flags: u64,
    vaddr: &mut u64,
) {
    let total_size: u64 = contribs.iter().map(|(_, size)| *size).sum();

    let mut merged_bytes = Vec::new();
    for (data, _) in contribs {
        merged_bytes.extend_from_slice(data);
    }

    let align = align.max(1);
    *vaddr = align_up(*vaddr, align);

    let idx = layout.sections.len();
    layout.section_by_name.insert(name.to_string(), idx);
    layout.sections.push(MergedSection {
        entsize: 0,
        sh_type: 1,
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
        section_by_name: HashMap::default(),
    };

    let mut vaddr: u64 = 0x400000;

    for (name, sh) in &to_merge {
        let align = sh.sh_addralign.max(1);
        vaddr = align_up(vaddr, align);

        let data_slice = read_section_data(data, sh);

        let merged = MergedSection {
            entsize: sh.sh_entsize,
            sh_type: sh.sh_type,
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
    let mut merged_data: HashMap<String, Vec<(Vec<u8>, u64)>> = HashMap::default();
    let mut section_cumul: HashMap<String, u64> = HashMap::default();
    let mut section_aligns: HashMap<String, u64> = HashMap::default();
    let mut section_types = HashMap::default();
    let mut section_flags: HashMap<String, u64> = HashMap::default();

    for obj_data in objects {
        let (header, sections, names) = parse_elf64_slice(obj_data)?;
        if header.e_machine != e_machine {
            return Err(format!(
                "e_machine mismatch: {} vs {}",
                header.e_machine, e_machine
            ));
        }

        let mut obj_contribs = HashMap::default();

        for (name, sh) in collect_mergeable_sections(&sections, &names) {
            let input_name = name;
            let name = output_section_name(&input_name).to_string();
            section_types.insert(name.clone(), (sh.sh_type, sh.sh_entsize));
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
                input_name,
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
        section_by_name: HashMap::default(),
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

    for section in &mut layout.sections {
        (section.sh_type, section.entsize) = section_types[&section.name];
        section.flags &= !0x30;
        section.entsize = 0;
    }
    for contributions in &section_contribs {
        for name in contributions.keys() {
            let index = layout.section_by_name[output_section_name(name)];
            layout.section_by_name.insert(name.clone(), index);
        }
    }
    Ok((layout, section_contribs))
}

#[cfg(test)]
mod nobits_tests {
    use super::*;
    use crate::elf::SectionHeader;

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
