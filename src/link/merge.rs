//! Merge input object sections into one output layout.

use super::{
    SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHN_COMMON, SHN_UNDEF, SHT_NOBITS, SHT_PROGBITS,
    parse_symtab_view, runtime,
};
use crate::{
    collections::HashMap,
    elf::{MAX_NOBITS_SIZE, MAX_SECTION_ALIGN, SectionHeader, get_strtab_string, parse_elf64_slice},
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
        .filter(|s| is_allocatable(s.flags))
        .map(|s| s.vaddr)
        .min()
        .unwrap_or(page);
    let old: Vec<_> = layout
        .sections
        .iter()
        .map(|s| (s.vaddr, s.data.len() as u64))
        .collect();
    let mut order: Vec<_> = (0..layout.sections.len())
        .filter(|&i| is_allocatable(layout.sections[i].flags))
        .collect();
    order.sort_by_key(|&i| {
        let s = &layout.sections[i];
        (
            segment_class(s),
            s.sh_type == SHT_NOBITS,
            section_rank(&s.name),
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

fn section_rank(name: &str) -> u8 {
    match name {
        n if n.starts_with(".note") => 0,
        ".gnu.hash" | ".hash" => 1,
        ".dynsym" => 2,
        ".dynstr" => 3,
        n if n.starts_with(".gnu.version") => 4,
        n if n.starts_with(".rela") => 5,
        ".init" => 0,
        ".plt" => 1,
        n if n.starts_with(".text") => 2,
        ".fini" => 3,
        n if n.starts_with(".rodata") => 0,
        ".gcc_except_table" => 1,
        ".eh_frame_hdr" => 2,
        ".eh_frame" => 3,
        n if n.starts_with(".preinit_array") => 0,
        n if n.starts_with(".init_array") => 1,
        n if n.starts_with(".fini_array") => 2,
        n if n.starts_with(".data.rel.ro") => 3,
        ".dynamic" => 4,
        ".got" => 5,
        ".got.plt" => 6,
        ".relro_padding" => u8::MAX,
        _ => 7,
    }
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
        .filter(|(i, sh)| {
            (matches!(sh.sh_type, SHT_PROGBITS | SHT_NOBITS | 7 | 14..=16)
                && is_allocatable(sh.sh_flags))
                || (sh.sh_type == SHT_PROGBITS && names.get(*i).is_some_and(|n| n == ".comment"))
        })
        .map(|(i, sh)| (names.get(i).cloned().unwrap_or_default(), sh))
        .collect();

    to_merge.sort_by_key(|(name, _)| section_merge_order(name));
    to_merge
}

type ContentIndex<'a> = HashMap<&'a [u8], Vec<u64>>;

fn progbits_bytes<'a>(data: &'a [u8], sh: &SectionHeader) -> &'a [u8] {
    let start = sh.sh_offset as usize;
    let end = start + sh.sh_size as usize;
    data.get(start..end).unwrap_or(&[])
}

pub(super) fn read_section_data(data: &[u8], sh: &SectionHeader) -> Vec<u8> {
    if sh.sh_size == 0 {
        return Vec::new();
    }
    match sh.sh_type {
        SHT_PROGBITS | 7 | 14..=16 => {
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

    let mut merged_bytes = Vec::with_capacity(contribs.iter().map(|(data, _)| data.len()).sum());
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
    pub elements: Vec<(u64, u64)>,
}

impl ObjectSectionContrib {
    fn mapped_offset(&self, offset: u64) -> u64 {
        let index = self.elements.partition_point(|&(old, _)| old <= offset);
        if index == 0 {
            return self.offset_in_merged + offset;
        }
        let (old, new) = self.elements[index - 1];
        new + offset - old
    }
}

fn merge_elements(
    data: &[u8],
    entsize: usize,
    strings: bool,
) -> Result<Vec<(usize, &[u8])>, String> {
    if entsize == 0 || !data.len().is_multiple_of(entsize) {
        return Err("invalid SHF_MERGE entry size".into());
    }
    let mut result = Vec::new();
    let mut start = 0;
    while start < data.len() {
        let size = if strings {
            data[start..]
                .chunks_exact(entsize)
                .position(|c| c.iter().all(|&b| b == 0))
                .map(|n| (n + 1) * entsize)
                .ok_or("unterminated SHF_STRINGS element")?
        } else {
            entsize
        };
        result.push((start, &data[start..start + size]));
        start += size;
    }
    Ok(result)
}

pub(super) fn remap_merge_offsets(
    objects: &mut [super::ParsedObject],
    contributions: &[HashMap<String, ObjectSectionContrib>],
) -> Result<(), String> {
    for (obj, contributions) in objects.iter_mut().zip(contributions) {
        let Some(table) = obj.sections.iter().find(|s| s.sh_type == 2) else {
            continue;
        };
        let symbols = crate::elf::parse_symtab(&obj.data, table)?;
        let contribution = |section: usize| {
            obj.names
                .get(section)
                .and_then(|name| contributions.get(name))
                .filter(|c| !c.elements.is_empty())
        };
        for relocation_section in obj.sections.iter().filter(|s| s.sh_type == 4) {
            let target = contribution(relocation_section.sh_info as usize);
            for off in (relocation_section.sh_offset as usize
                ..(relocation_section.sh_offset + relocation_section.sh_size) as usize)
                .step_by(24)
            {
                let relocation = crate::elf::parse_rela_entry(&obj.data[off..off + 24], 0)?;
                if let Some(target) = target {
                    let mapped = target.mapped_offset(relocation.r_offset);
                    obj.data[off..off + 8].copy_from_slice(&mapped.to_le_bytes());
                }
                let Some(symbol) = symbols.get(relocation.r_sym as usize) else {
                    return Err("invalid merge relocation symbol".into());
                };
                if let Some(source) = contribution(symbol.st_shndx as usize) {
                    let bias = if obj.header.e_machine == 62
                        && matches!(relocation.r_type, 2 | 4 | 9 | 41 | 42)
                    {
                        4
                    } else {
                        0
                    };
                    let old = symbol
                        .st_value
                        .wrapping_add_signed(relocation.r_addend.wrapping_add(bias));
                    if old <= source.size {
                        let addend = source.mapped_offset(old) as i64
                            - source.mapped_offset(symbol.st_value) as i64
                            - bias;
                        obj.data[off + 16..off + 24].copy_from_slice(&addend.to_le_bytes());
                    }
                }
            }
        }
        for (index, symbol) in symbols.iter().enumerate() {
            if let Some(source) = contribution(symbol.st_shndx as usize) {
                let off = table.sh_offset as usize + index * 24 + 8;
                obj.data[off..off + 8]
                    .copy_from_slice(&source.mapped_offset(symbol.st_value).to_le_bytes());
            }
        }
    }
    Ok(())
}

/// Every common symbol name with the largest size and alignment any object gives it,
/// sorted by name so the layout does not depend on hash order.
fn common_symbol_requirements(objects: &[&[u8]]) -> Result<Vec<(String, u64, u64)>, String> {
    let mut requirements: HashMap<String, (u64, u64)> = HashMap::default();
    for &obj_data in objects {
        let (_, sections, _) = parse_elf64_slice(obj_data)?;
        let Some((symbols, strings)) = parse_symtab_view(obj_data, &sections)? else {
            continue;
        };
        for sym in symbols.iter().filter(|sym| sym.st_shndx == SHN_COMMON) {
            let Some(name) = get_strtab_string(strings, sym.name_offset) else {
                continue;
            };
            let entry = requirements.entry(name).or_insert((0, 1));
            entry.0 = entry.0.max(sym.st_size);
            entry.1 = entry.1.max(sym.st_value);
        }
    }
    let mut sorted: Vec<(String, u64, u64)> = requirements
        .into_iter()
        .map(|(name, (size, align))| (name, size, align))
        .collect();
    sorted.sort_unstable();
    Ok(sorted)
}

/// Places common symbols at the end of `.bss` and returns each name's offset there.
fn place_common_symbols(
    objects: &[&[u8]],
    merged_data: &mut HashMap<String, Vec<(Vec<u8>, u64)>>,
    section_aligns: &mut HashMap<String, u64>,
    section_flags: &mut HashMap<String, u64>,
    section_types: &mut HashMap<String, (u32, u64)>,
) -> Result<HashMap<String, u64>, String> {
    let mut offsets = HashMap::default();
    let requirements = common_symbol_requirements(objects)?;
    if requirements.is_empty() {
        return Ok(offsets);
    }
    section_types.entry(".bss".into()).or_insert((SHT_NOBITS, 0));
    section_flags
        .entry(".bss".into())
        .or_insert(SHF_ALLOC | SHF_WRITE);
    let bss_align = section_aligns.entry(".bss".into()).or_insert(1);
    let bss = merged_data.entry(".bss".into()).or_default();
    let mut end: u64 = bss.iter().map(|(_, size)| *size).sum();
    for (name, size, align) in requirements {
        if !align.is_power_of_two() || align > MAX_SECTION_ALIGN {
            return Err(format!("common symbol {name} has unsupported alignment {align}"));
        }
        let offset = align_up(end, align);
        if offset.checked_add(size).is_none_or(|stop| stop > MAX_NOBITS_SIZE) {
            return Err("common symbols are too large".into());
        }
        if offset > end {
            bss.push((vec![0; (offset - end) as usize], offset - end));
        }
        bss.push((vec![0; size as usize], size));
        offsets.insert(name, offset);
        end = offset + size;
        *bss_align = (*bss_align).max(align);
    }
    Ok(offsets)
}

/// Merge sections from multiple objects. Same e_machine required.
pub fn merge_sections_multi_object(
    objects: &[&[u8]],
) -> Result<
    (
        MergedLayout,
        Vec<HashMap<String, ObjectSectionContrib>>,
        HashMap<String, u64>,
    ),
    String,
> {
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

    let mut elements: HashMap<(String, u64, bool), ContentIndex<'_>> = HashMap::default();
    for &obj_data in objects {
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

            let size = sh.sh_size;
            let align = sh.sh_addralign.max(1);
            let mergeable = sh.sh_flags & 0x10 != 0
                && sh.sh_type == SHT_PROGBITS
                && !sections.iter().any(|r| {
                    r.sh_type == 4
                        && names.get(r.sh_info as usize) == Some(&input_name)
                        && r.sh_size != 0
                });
            let mut element_offsets = Vec::new();
            let raw = *section_cumul.get(&name).unwrap_or(&0);
            let offset_in_merged;
            let entry = merged_data.entry(name.clone()).or_default();
            if mergeable {
                offset_in_merged = 0;
                let mut end = raw;
                let strings = sh.sh_flags & 0x20 != 0;
                let data_slice = progbits_bytes(obj_data, sh);
                let by_content = elements
                    .entry((name.clone(), sh.sh_entsize, strings))
                    .or_default();
                for (old, bytes) in merge_elements(data_slice, sh.sh_entsize as usize, strings)? {
                    let required = if old == 0 {
                        align
                    } else {
                        align.min(1u64 << old.trailing_zeros())
                    };
                    let candidates = by_content.entry(bytes).or_default();
                    let new = if let Some(&offset) = candidates
                        .iter()
                        .find(|&&offset| offset.is_multiple_of(required))
                    {
                        offset
                    } else {
                        let offset = align_up(end, required);
                        if offset > end {
                            entry.push((vec![0; (offset - end) as usize], offset - end));
                        }
                        entry.push((bytes.to_vec(), bytes.len() as u64));
                        end = offset + bytes.len() as u64;
                        candidates.push(offset);
                        offset
                    };
                    element_offsets.push((old as u64, new));
                }
                section_cumul.insert(name.clone(), end);
            } else {
                offset_in_merged = align_up(raw, align);
                let pad = offset_in_merged - raw;
                if pad > 0 {
                    entry.push((vec![0u8; pad as usize], pad));
                }
                entry.push((read_section_data(obj_data, sh), size));
                section_cumul.insert(name.clone(), offset_in_merged + size);
            }

            section_aligns
                .entry(name.clone())
                .and_modify(|a| *a = (*a).max(align))
                .or_insert(align);

            section_flags
                .entry(name.clone())
                .and_modify(|f| *f |= sh.sh_flags)
                .or_insert(sh.sh_flags);

            obj_contribs.insert(
                input_name,
                ObjectSectionContrib {
                    offset_in_merged,
                    size,
                    elements: element_offsets,
                },
            );
        }

        section_contribs.push(obj_contribs);
    }

    let common_offsets = place_common_symbols(
        objects,
        &mut merged_data,
        &mut section_aligns,
        &mut section_flags,
        &mut section_types,
    )?;

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
    Ok((layout, section_contribs, common_offsets))
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
        let bss = read_section_data(&[], &header(SHT_NOBITS, 8));
        assert_eq!(bss, vec![0u8; 8]);
    }

    #[test]
    fn empty_and_unknown_sections_contribute_nothing() {
        assert!(read_section_data(&[], &header(SHT_NOBITS, 0)).is_empty());
        assert!(read_section_data(&[], &header(0, 8)).is_empty());
    }
}
