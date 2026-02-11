//! Mach-O object linking for macOS.
//!
//! Merges sections, resolves symbols, applies relocations.
//! Supports single-object no-libc (ret42-style) initially.

use crate::arch::TargetArch;
use crate::link::{LinkResult, MergedLayout, MergedSection, ObjectSectionContrib};
use crate::macho::{
    parse_macho64_object, parse_macho_relocs, Macho64Object, MachoSection,
    ARM64_RELOC_BRANCH26, ARM64_RELOC_GOT_LOAD_PAGE21, ARM64_RELOC_GOT_LOAD_PAGEOFF12,
    ARM64_RELOC_PAGE21, ARM64_RELOC_PAGEOFF12, GENERIC_RELOC_VANILLA,
};
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

fn align_up_bytes(value: u64, align_bytes: u64) -> u64 {
    if align_bytes == 0 {
        return value;
    }
    (value + align_bytes - 1) & !(align_bytes - 1)
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

        let name = merged_section_name_for_lookup(&sec.segname, &sec.sectname);

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
        let name = merged_section_name_for_lookup(&sec.segname, &sec.sectname);
        if let Some(&idx) = layout.section_by_name.get(&name) {
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

fn symbol_addr_by_index(
    obj: &Macho64Object,
    layout: &MergedLayout,
    symbol_addrs: &HashMap<String, u64>,
) -> Vec<Option<u64>> {
    let mut vaddr_by_sect: HashMap<u8, u64> = HashMap::new();
    for (i, sec) in obj.sections.iter().enumerate() {
        let sect_idx = (i + 1) as u8;
        let name = merged_section_name_for_lookup(&sec.segname, &sec.sectname);
        if let Some(&idx) = layout.section_by_name.get(&name) {
            vaddr_by_sect.insert(sect_idx, layout.sections[idx].vaddr);
        }
    }

    obj.symbols
        .iter()
        .map(|sym| {
            if sym.is_defined {
                vaddr_by_sect
                    .get(&sym.sect)
                    .map(|&base| base + sym.value)
            } else {
                symbol_addrs.get(sym.name.as_str()).copied()
            }
        })
        .collect()
}

fn read_addend(data: &[u8], off: usize, length: u32) -> u64 {
    match length {
        0 => data.get(off).copied().unwrap_or(0) as u64,
        1 => read_u16_le(data, off).unwrap_or(0) as u64,
        2 => read_u32_le(data, off).unwrap_or(0) as u64,
        3 => read_u64_le(data, off).unwrap_or(0),
        _ => 0,
    }
}

fn read_u16_le(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64_le(data: &[u8], off: usize) -> Option<u64> {
    data.get(off..off + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

fn write_u32_le(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn write_u64_le(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
}

fn reloc_size(r_length: u32) -> usize {
    match r_length {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => 4,
    }
}

fn section_offset_from_contrib(
    contrib: &HashMap<String, ObjectSectionContrib>,
) -> HashMap<String, u64> {
    contrib
        .iter()
        .map(|(k, v)| (k.clone(), v.offset_in_merged))
        .collect()
}

fn apply_macho_relocations(
    obj: &Macho64Object,
    layout: &mut MergedLayout,
    _symbol_addrs: &HashMap<String, u64>,
    symbol_addr_by_idx: &[Option<u64>],
    section_offset: Option<&HashMap<String, u64>>,
    got_slot_by_symbol: Option<&HashMap<String, u64>>,
) -> Result<(), String> {
    let mut vaddr_by_sect: HashMap<u8, u64> = HashMap::new();
    for (i, sec) in obj.sections.iter().enumerate() {
        let sect_idx = (i + 1) as u8;
        let merged_name = merged_section_name_for_lookup(&sec.segname, &sec.sectname);
        if let Some(&idx) = layout.section_by_name.get(&merged_name) {
            let off = section_offset
                .and_then(|m| m.get(&merged_name).copied())
                .unwrap_or(0);
            vaddr_by_sect.insert(sect_idx, layout.sections[idx].vaddr + off);
        }
    }

    for (_i, sec) in obj.sections.iter().enumerate() {
        if sec.nreloc == 0 {
            continue;
        }
        let merged_name = merged_section_name_for_lookup(&sec.segname, &sec.sectname);
        let Some(&merged_idx) = layout.section_by_name.get(&merged_name) else {
            continue;
        };
        let merged = &mut layout.sections[merged_idx];
        let relocs = parse_macho_relocs(&obj.data, sec.reloff, sec.nreloc);
        let offset_in_merged = section_offset
            .and_then(|m| m.get(&merged_name).copied())
            .unwrap_or(0) as usize;

        for r in &relocs {
            let off = offset_in_merged + r.r_address as usize;
            let size = reloc_size(r.r_length);
            if merged.data.len() < off + size {
                return Err(format!(
                    "relocation offset {} + {} out of bounds (len {})",
                    off,
                    size,
                    merged.data.len()
                ));
            }
            let addend = read_addend(&merged.data, off, r.r_length);
            let place_addr = merged.vaddr + off as u64;

            let base = if r.r_extern {
                let idx = r.r_symbolnum as usize;
                let addr_opt = if (r.r_type == ARM64_RELOC_GOT_LOAD_PAGE21
                    || r.r_type == ARM64_RELOC_GOT_LOAD_PAGEOFF12)
                    && got_slot_by_symbol.is_some()
                {
                    obj.symbols
                        .get(idx)
                        .and_then(|s| got_slot_by_symbol.and_then(|m| m.get(&s.name).copied()))
                } else {
                    None
                };
                let addr_opt = addr_opt
                    .or_else(|| symbol_addr_by_idx.get(idx).and_then(|o| o.as_ref().copied()));
                let Some(addr) = addr_opt else {
                    let sym_name = obj.symbols.get(idx).map(|s| s.name.as_str()).unwrap_or("?");
                    return Err(format!(
                        "undefined symbol index {} ({}) for relocation",
                        idx, sym_name
                    ));
                };
                addr
            } else {
                let sect_idx = r.r_symbolnum as u8;
                let addr = vaddr_by_sect
                    .get(&sect_idx)
                    .copied()
                    .ok_or_else(|| format!("unknown section index {} for relocation", sect_idx))?;
                addr
            };

            let mut value = base.wrapping_add(addend);
            if r.r_pcrel {
                value = value.wrapping_sub(place_addr);
            }

            match r.r_type {
                GENERIC_RELOC_VANILLA => {
                    match r.r_length {
                        0 => merged.data[off] = value as u8,
                        1 => {
                            let v = (value as u16).to_le_bytes();
                            merged.data[off..off + 2].copy_from_slice(&v);
                        }
                        2 => write_u32_le(&mut merged.data, off, value as u32),
                        3 => write_u64_le(&mut merged.data, off, value),
                        _ => {}
                    }
                }
                ARM64_RELOC_BRANCH26 => {
                    let delta = value.wrapping_sub(place_addr);
                    let imm26 = (delta >> 2) & 0x3FFFFFF;
                    if merged.data.len() < off + 4 {
                        return Err("branch reloc: buffer too short".to_string());
                    }
                    let insn = read_u32_le(&merged.data, off).unwrap_or(0);
                    let patched = (insn & 0xFC000000) | (imm26 as u32);
                    write_u32_le(&mut merged.data, off, patched);
                }
                ARM64_RELOC_PAGE21 => {
                    let page = (value >> 12) << 12;
                    let place_page = (place_addr >> 12) << 12;
                    let imm = ((page as i64 - place_page as i64) >> 12) as i32;
                    let imm_lo = (imm & 3) as u32;
                    let imm_hi = ((imm >> 2) & 0x7FFFF) as u32;
                    if merged.data.len() < off + 4 {
                        return Err("page21 reloc: buffer too short".to_string());
                    }
                    let insn = read_u32_le(&merged.data, off).unwrap_or(0);
                    let patched = (insn & 0x9F00001F) | (imm_lo << 29) | (imm_hi << 5);
                    write_u32_le(&mut merged.data, off, patched);
                }
                ARM64_RELOC_PAGEOFF12 => {
                    let pageoff = (value & 0xFFF) as u32;
                    if merged.data.len() < off + 4 {
                        return Err("pageoff12 reloc: buffer too short".to_string());
                    }
                    let insn = read_u32_le(&merged.data, off).unwrap_or(0);
                    let patched = (insn & 0xFFC003FF) | (pageoff << 10);
                    write_u32_le(&mut merged.data, off, patched);
                }
                ARM64_RELOC_GOT_LOAD_PAGE21 => {
                    let page = (value >> 12) << 12;
                    let place_page = (place_addr >> 12) << 12;
                    let imm = ((page as i64 - place_page as i64) >> 12) as i32;
                    let imm_lo = (imm & 3) as u32;
                    let imm_hi = ((imm >> 2) & 0x7FFFF) as u32;
                    if merged.data.len() < off + 4 {
                        return Err("got_page21 reloc: buffer too short".to_string());
                    }
                    let insn = read_u32_le(&merged.data, off).unwrap_or(0);
                    let patched = (insn & 0x9F00001F) | (imm_lo << 29) | (imm_hi << 5);
                    write_u32_le(&mut merged.data, off, patched);
                }
                ARM64_RELOC_GOT_LOAD_PAGEOFF12 => {
                    let pageoff = (value & 0xFFF) as u32;
                    if merged.data.len() < off + 4 {
                        return Err("got_pageoff12 reloc: buffer too short".to_string());
                    }
                    let insn = read_u32_le(&merged.data, off).unwrap_or(0);
                    let patched = (insn & 0xFFC003FF) | (pageoff << 10);
                    write_u32_le(&mut merged.data, off, patched);
                }
                _ => {
                    return Err(format!(
                        "unsupported Mach-O relocation type {}",
                        r.r_type
                    ));
                }
            }
        }
    }

    Ok(())
}

pub fn link_macho_single_object(data: &[u8]) -> Result<LinkResult, String> {
    let obj = parse_macho64_object(data)?;
    let arch = TargetArch::from_macho_cputype(obj.header.cputype)
        .ok_or_else(|| format!("unsupported Mach-O cputype {}", obj.header.cputype))?;

    let mut layout = merge_macho_sections(&obj);
    let symbol_addrs = resolve_macho_symbols(&obj, &layout);
    let symbol_addr_by_idx = symbol_addr_by_index(&obj, &layout, &symbol_addrs);
    apply_macho_relocations(&obj, &mut layout, &symbol_addrs, &symbol_addr_by_idx, None, None)?;

    let e_machine = arch.to_elf_machine();

    Ok(LinkResult {
        layout,
        e_machine,
        symbol_addrs,
        dynamic: None,
    })
}

fn resolve_rust_std_dylib_from_paths(
    _dylib_paths: &[std::path::PathBuf],
) -> Option<String> {
    let sysroot = std::env::var("RUST_SYSROOT").ok().or_else(|| {
        std::process::Command::new("rustc")
            .args(["--print", "sysroot"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
    })?;
    let host = std::process::Command::new("rustc")
        .args(["-vV"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("host:"))
                .map(|l| l.trim_start_matches("host:").trim().to_string())
        })
        .unwrap_or_else(|| format!("{}-apple-darwin", std::env::consts::ARCH));
    let lib_dir = std::path::Path::new(&sysroot)
        .join("lib/rustlib")
        .join(&host)
        .join("lib");
    for e in std::fs::read_dir(&lib_dir).ok()?.flatten() {
        let fname = e.file_name();
        let name = fname.to_string_lossy();
        if name.starts_with("libstd-") && name.ends_with(".dylib") {
            return Some(e.path().to_string_lossy().to_string());
        }
    }
    None
}

pub fn link_macho_multi_object(
    datas: &[&[u8]],
    libs: Option<&[String]>,
    dylib_paths: &[std::path::PathBuf],
    _input_paths: &[std::path::PathBuf],
) -> Result<LinkResult, String> {
    if datas.is_empty() {
        return Err("no objects to link".to_string());
    }
    if datas.len() == 1 && libs.is_none() {
        return link_macho_single_object(datas[0]);
    }

    let objects: Vec<Macho64Object> = datas
        .iter()
        .map(|d| parse_macho64_object(d))
        .collect::<Result<Vec<_>, _>>()?;

    let (mut layout, section_contribs) = merge_macho_sections_multi(&objects)?;
    let arch = TargetArch::from_macho_cputype(objects[0].header.cputype)
        .ok_or_else(|| format!("unsupported Mach-O cputype {}", objects[0].header.cputype))?;
    let e_machine = arch.to_elf_machine();

    let mut global_symbols: HashMap<String, u64> = HashMap::new();
    for (obj_idx, obj) in objects.iter().enumerate() {
        let contrib = &section_contribs[obj_idx];
        let mut vaddr_by_sect: HashMap<u8, u64> = HashMap::new();
        for (i, sec) in obj.sections.iter().enumerate() {
            let sect_idx = (i + 1) as u8;
            let merged_name = merged_section_name_for_lookup(&sec.segname, &sec.sectname);
            if let (Some(&idx), Some(off)) = (
                layout.section_by_name.get(&merged_name),
                contrib.get(&merged_name),
            ) {
                vaddr_by_sect.insert(sect_idx, layout.sections[idx].vaddr + off.offset_in_merged);
            }
        }
        for sym in &obj.symbols {
            if !sym.is_defined || sym.name.is_empty() {
                continue;
            }
            if let Some(&base) = vaddr_by_sect.get(&sym.sect) {
                let addr = base + sym.value;
                global_symbols.entry(sym.name.clone()).or_insert(addr);
            }
        }
    }

    let has_system = libs
        .map(|l| l.iter().any(|x| x == "System" || x == "c" || x == "m"))
        .unwrap_or(false);

    let mut undefined: Vec<String> = Vec::new();
    if has_system && arch == TargetArch::AArch64 {
        for obj in &objects {
            for sym in &obj.symbols {
                if !sym.is_defined && !sym.name.is_empty() {
                    if !global_symbols.contains_key(&sym.name)
                        && !undefined.contains(&sym.name)
                    {
                        undefined.push(sym.name.clone());
                    }
                }
            }
        }

        if !undefined.is_empty() {
            let last = layout.sections.last().ok_or("no sections")?;
            let mut vaddr = align_up_bytes(last.vaddr + last.data.len() as u64, 16);

            let (stubs_data, stub_helper_data, got_data) =
                build_macho_stubs_arm64(&undefined, vaddr)?;

            let stubs_vaddr = vaddr;
            layout.sections.push(MergedSection {
                name: "__stubs".into(),
                data: stubs_data,
                vaddr: stubs_vaddr,
                flags: 6,
                align: 4,
            });
            layout.section_by_name.insert("__stubs".into(), layout.sections.len() - 1);
            vaddr += layout.sections.last().unwrap().data.len() as u64;

            let stub_helper_vaddr = vaddr;
            layout.sections.push(MergedSection {
                name: "__stub_helper".into(),
                data: stub_helper_data,
                vaddr: stub_helper_vaddr,
                flags: 6,
                align: 4,
            });
            layout.section_by_name.insert("__stub_helper".into(), layout.sections.len() - 1);
            vaddr += layout.sections.last().unwrap().data.len() as u64;

            vaddr = align_up_bytes(vaddr, 0x8000);
            let got_vaddr = vaddr;
            layout.sections.push(MergedSection {
                name: "__got".into(),
                data: got_data,
                vaddr: got_vaddr,
                flags: 2,
                align: 8,
            });
            layout.section_by_name.insert("__got".into(), layout.sections.len() - 1);

            for (i, sym) in undefined.iter().enumerate() {
                let stub_addr = stubs_vaddr + (i as u64) * 12;
                global_symbols.insert(sym.clone(), stub_addr);
            }
        }
    }

    let got_slot_by_symbol: HashMap<String, u64> = if layout.section_by_name.contains_key("__got") {
        let got_idx = layout.section_by_name["__got"];
        let got_vaddr = layout.sections[got_idx].vaddr;
        undefined
            .iter()
            .enumerate()
            .map(|(i, s)| (s.clone(), got_vaddr + (i as u64) * 8))
            .collect()
    } else {
        HashMap::new()
    };

    for (obj_idx, obj) in objects.iter().enumerate() {
        let contrib = &section_contribs[obj_idx];
        let symbol_addrs = symbol_addr_by_index_multi(obj, &layout, &global_symbols, contrib);
        let offset_map = section_offset_from_contrib(contrib);
        apply_macho_relocations(
            obj,
            &mut layout,
            &global_symbols,
            &symbol_addrs,
            Some(&offset_map),
            Some(&got_slot_by_symbol),
        )?;
    }

    let dynamic = if layout.section_by_name.contains_key("__got") {
        let has_undefined = !undefined.is_empty();
        let plt_symbols = undefined;
        let mut needed = vec!["libSystem.B.dylib".into()];
        for p in dylib_paths {
            if let Some(s) = p.to_str() {
                needed.push(s.to_string());
            }
        }
        if needed.len() == 1 && has_undefined {
            if let Some(std_path) = resolve_rust_std_dylib_from_paths(dylib_paths) {
                needed.push(std_path);
            }
        }
        Some(crate::link::DynamicLinkInfo {
            needed,
            plt_symbols,
            interpreter: None,
        })
    } else {
        None
    };

    Ok(LinkResult {
        layout,
        e_machine,
        symbol_addrs: global_symbols,
        dynamic,
    })
}

fn build_macho_stubs_arm64(
    symbols: &[String],
    stubs_start_vaddr: u64,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    const STUB_SIZE: u64 = 12;
    let stub_helper_len = 36;
    let got_vaddr = align_up_bytes(
        stubs_start_vaddr + (symbols.len() as u64) * STUB_SIZE + stub_helper_len as u64,
        0x8000,
    );

    let mut stubs = Vec::with_capacity(symbols.len() * 12);
    for (i, _) in symbols.iter().enumerate() {
        let stub_addr = stubs_start_vaddr + (i as u64) * STUB_SIZE;
        let got_slot = got_vaddr + (i as u64) * 8;
        let page = got_slot & !0xFFF;
        let pageoff = (got_slot & 0xFFF) as u32;
        let stub_page = stub_addr & !0xFFF;
        let imm = ((page - stub_page) >> 12) as i32;
        let imm_lo = (imm & 3) as u32;
        let imm_hi = ((imm >> 2) & 0x7FFFF) as u32;
        let adrp = 0x90000010u32 | (imm_lo << 29) | (imm_hi << 5);
        let ldr = 0xF9400210u32 | (pageoff << 10);
        let br = 0xD61F0200u32;
        stubs.extend_from_slice(&adrp.to_le_bytes());
        stubs.extend_from_slice(&ldr.to_le_bytes());
        stubs.extend_from_slice(&br.to_le_bytes());
    }

    let _stub_helper_vaddr = stubs_start_vaddr + (symbols.len() as u64) * STUB_SIZE;
    let _dyld_private_approx = got_vaddr + 0x8000;
    let mut stub_helper = Vec::with_capacity(stub_helper_len);
    let h0 = 0x90000011u32;
    let h1 = 0x91002231u32;
    let h2 = 0xA9BF46F0u32;
    let h3 = 0x90000010u32;
    let h4 = 0xF9400210u32;
    let h5 = 0xD61F0200u32;
    stub_helper.extend_from_slice(&h0.to_le_bytes());
    stub_helper.extend_from_slice(&h1.to_le_bytes());
    stub_helper.extend_from_slice(&h2.to_le_bytes());
    stub_helper.extend_from_slice(&h3.to_le_bytes());
    stub_helper.extend_from_slice(&h4.to_le_bytes());
    stub_helper.extend_from_slice(&h5.to_le_bytes());

    let got = vec![0u8; symbols.len() * 8];

    Ok((stubs, stub_helper, got))
}

fn merged_section_name_for_lookup(segname: &str, sectname: &str) -> String {
    if sectname == "__text" {
        ".text".into()
    } else if segname == "__TEXT" || segname == "__DATA" {
        format!("{}.{}", segname, sectname)
    } else {
        sectname.to_string()
    }
}

fn symbol_addr_by_index_multi(
    obj: &Macho64Object,
    layout: &MergedLayout,
    global_symbols: &HashMap<String, u64>,
    contrib: &HashMap<String, ObjectSectionContrib>,
) -> Vec<Option<u64>> {
    let mut vaddr_by_sect: HashMap<u8, u64> = HashMap::new();
    for (i, sec) in obj.sections.iter().enumerate() {
        let sect_idx = (i + 1) as u8;
        let merged_name = merged_section_name_for_lookup(&sec.segname, &sec.sectname);
        if let (Some(&idx), Some(off)) = (
            layout.section_by_name.get(&merged_name),
            contrib.get(&merged_name),
        ) {
            vaddr_by_sect.insert(sect_idx, layout.sections[idx].vaddr + off.offset_in_merged);
        }
    }

    obj.symbols
        .iter()
        .map(|sym| {
            if sym.is_defined {
                vaddr_by_sect
                    .get(&sym.sect)
                    .map(|&base| base + sym.value)
            } else {
                global_symbols
                    .get(sym.name.as_str())
                    .copied()
                    .or_else(|| {
                        let stripped = sym.name.strip_prefix('_').unwrap_or(sym.name.as_str());
                        global_symbols.get(stripped).copied()
                    })
                    .or_else(|| {
                        let with_underscore = format!("_{}", sym.name);
                        global_symbols.get(&with_underscore).copied()
                    })
            }
        })
        .collect()
}

fn merge_macho_sections_multi(
    objects: &[Macho64Object],
) -> Result<(MergedLayout, Vec<HashMap<String, ObjectSectionContrib>>), String> {
    if objects.is_empty() {
        return Err("no objects to merge".to_string());
    }
    let cputype = objects[0].header.cputype;
    for obj in objects.iter().skip(1) {
        if obj.header.cputype != cputype {
            return Err("Mach-O objects must have same cputype".to_string());
        }
    }

    let section_merge_order: &[(&str, &str)] = &[
        ("__TEXT", "__text"),
        ("__TEXT", "__cstring"),
        ("__TEXT", "__const"),
        ("__TEXT", "__rodata"),
        ("__TEXT", "__literal4"),
        ("__TEXT", "__literal8"),
        ("__TEXT", "__literal16"),
        ("__TEXT", "__literals"),
        ("__TEXT", "__gcc_except_tab"),
        ("__DATA", "__const"),
        ("__DATA", "__data"),
        ("__DATA", "__bss"),
    ];

    let mut section_contribs: Vec<HashMap<String, ObjectSectionContrib>> =
        (0..objects.len()).map(|_| HashMap::new()).collect();
    let mut merged_data: HashMap<String, Vec<(Vec<u8>, u64)>> = HashMap::new();
    let mut section_cumul: HashMap<String, u64> = HashMap::new();
    let mut section_aligns: HashMap<String, u64> = HashMap::new();
    let mut section_flags: HashMap<String, u64> = HashMap::new();

    for (obj_idx, obj) in objects.iter().enumerate() {
        for sec in &obj.sections {
            if !is_mergeable_section(sec) {
                continue;
            }
            let merged_name = merged_section_name_for_lookup(&sec.segname, &sec.sectname);
            let data = read_section_data(obj, sec);
            let size = data.len() as u64;
            let offset_in_merged = *section_cumul.get(&merged_name).unwrap_or(&0);
            section_cumul.insert(merged_name.clone(), offset_in_merged + size);

            let a = if sec.align > 0 { sec.align as u64 } else { 4 };
            section_aligns
                .entry(merged_name.clone())
                .and_modify(|x| *x = (*x).max(a))
                .or_insert(a);

            let flags = if sec.sectname == "__text" { 6 } else { 2 };
            section_flags
                .entry(merged_name.clone())
                .and_modify(|f| *f |= flags)
                .or_insert(flags);

            merged_data.entry(merged_name.clone()).or_default().push((data, size));

            section_contribs[obj_idx].insert(
                merged_name.clone(),
                ObjectSectionContrib {
                    offset_in_merged,
                    size,
                },
            );
        }
    }

    let mut layout = MergedLayout {
        sections: Vec::new(),
        section_by_name: HashMap::new(),
    };
    let mut vaddr = SEG_BASE;

    for (segname, sectname) in section_merge_order {
        let merged_name = merged_section_name_for_lookup(segname, sectname);
        let Some(contribs) = merged_data.get(&merged_name) else {
            continue;
        };
        let mut merged_bytes = Vec::new();
        for (data, _size) in contribs {
            merged_bytes.extend_from_slice(data);
        }
        if merged_bytes.is_empty() {
            continue;
        }

        let align = *section_aligns.get(&merged_name).unwrap_or(&4);
        let flags = *section_flags.get(&merged_name).unwrap_or(&2);
        vaddr = align_up(vaddr, align);

        let idx = layout.sections.len();
        layout.section_by_name.insert(merged_name.clone(), idx);
        layout.sections.push(MergedSection {
            name: merged_name.clone(),
            data: merged_bytes,
            vaddr,
            flags,
            align,
        });
        vaddr += layout.sections[idx].data.len() as u64;
    }

    Ok((layout, section_contribs))
}
