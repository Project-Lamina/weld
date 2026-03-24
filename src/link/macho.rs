//! Mach-O object linking for macOS.
//!
//! Merges sections, resolves symbols, applies relocations.
//! Supports single-object no-libc (ret42-style) initially.

use crate::arch::TargetArch;
use crate::link::{LinkResult, MergedLayout, MergedSection, ObjectSectionContrib};
use crate::macho::{
    ARM64_RELOC_ADDEND, ARM64_RELOC_BRANCH26, ARM64_RELOC_GOT_LOAD_PAGE21,
    ARM64_RELOC_GOT_LOAD_PAGEOFF12, ARM64_RELOC_PAGE21, ARM64_RELOC_PAGEOFF12,
    ARM64_RELOC_TLVP_LOAD_PAGE21, ARM64_RELOC_TLVP_LOAD_PAGEOFF12, GENERIC_RELOC_VANILLA,
    Macho64Object, MachoSection, MachoSymbol, parse_macho_relocs, parse_macho64_object,
};
use std::collections::{HashMap, HashSet};

const PAGE_SIZE: u64 = 4096;
const SEG_BASE: u64 = 0x100000000;
const VM_ADDR_BIAS: u64 = 0x4000;
const SECTION_TYPE_MASK: u32 = 0x0000_00ff;
const S_ZEROFILL: u32 = 0x1;
const S_GB_ZEROFILL: u32 = 0xc;
const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
const N_WEAK_DEF: u16 = 0x0080;
const N_EXT: u8 = 0x01;

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
        || sec.sectname == "__eh_frame"
        || sec.sectname.contains("eh_frame")
        || sec.sectname.starts_with("__") && sec.sectname.contains("unwind")
    {
        return false;
    }
    true
}

fn is_zerofill_section(sec: &MachoSection) -> bool {
    matches!(
        sec.flags & SECTION_TYPE_MASK,
        S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
    )
}

fn read_section_data(obj: &Macho64Object, sec: &MachoSection) -> Vec<u8> {
    let size = sec.size as usize;
    if size == 0 {
        return Vec::new();
    }
    if is_zerofill_section(sec) {
        return vec![0u8; size];
    }
    let start = sec.offset as usize;
    if start >= obj.data.len() {
        return vec![0u8; size];
    }
    let available = obj.data.len() - start;
    let take = size.min(available);
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&obj.data[start..start + take]);
    if take < size {
        out.resize(size, 0);
    }
    out
}

fn is_data_layout_section(name: &str) -> bool {
    if name == "__got"
        || name == "__data"
        || name == "__bss"
        || name == "__common"
        || name == "__thread_bss"
        || name == "__thread_data"
        || name == "__thread_vars"
    {
        return true;
    }
    if let Some((seg, _)) = name.split_once('.') {
        return seg.starts_with("__DATA") || seg.starts_with("__AUTH");
    }
    false
}

fn is_thread_vars_section(name: &str) -> bool {
    name == "__DATA.__thread_vars" || name == "__DATA_DIRTY.__thread_vars"
}

fn compute_runtime_shifts(layout: &MergedLayout) -> (u64, u64) {
    let text_shift = VM_ADDR_BIAS;
    let mut text_base = SEG_BASE;
    let mut text_end = SEG_BASE;
    let mut data_base = 0u64;
    let mut saw_text = false;
    let mut saw_data = false;

    for sec in &layout.sections {
        if is_data_layout_section(&sec.name) {
            if !saw_data {
                data_base = sec.vaddr;
                saw_data = true;
            }
            continue;
        }
        if !saw_text {
            text_base = sec.vaddr;
            saw_text = true;
        }
        text_end = text_end.max(sec.vaddr + sec.data.len() as u64);
    }

    if !saw_data {
        return (text_shift, text_shift);
    }

    let text_size_aligned = align_up_bytes(text_end.saturating_sub(text_base), VM_ADDR_BIAS);
    let min_after_text = align_up_bytes(text_base + text_shift + text_size_aligned, VM_ADDR_BIAS);
    let data_vmaddr = (data_base + text_shift).max(min_after_text);
    let data_shift = data_vmaddr.saturating_sub(data_base);
    (text_shift, data_shift)
}

fn runtime_addr_for_layout_addr(
    section_ranges: &[(u64, u64, u64)],
    default_shift: u64,
    addr: u64,
) -> u64 {
    for (start, end, shift) in section_ranges {
        if addr >= *start && addr < *end {
            return addr.wrapping_add(*shift);
        }
    }
    addr.wrapping_add(default_shift)
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
        let name = merged_section_name_for_lookup(&sec.segname, &sec.sectname);

        let mut align = if sec.align > 0 { sec.align as u64 } else { 4 };
        if is_data_layout_section(&name) && align < 3 {
            align = 3;
        }
        vaddr = align_up(vaddr, align);

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
            addrs.insert(sym.name.clone(), base + symbol_offset_in_section(obj, sym));
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
                    .map(|&base| base + symbol_offset_in_section(obj, sym))
            } else {
                symbol_addrs.get(sym.name.as_str()).copied()
            }
        })
        .collect()
}

fn symbol_offset_in_section(obj: &Macho64Object, sym: &MachoSymbol) -> u64 {
    if sym.sect == 0 {
        return sym.value;
    }
    let sec_addr = obj
        .sections
        .get((sym.sect - 1) as usize)
        .map(|s| s.addr)
        .unwrap_or(0);
    sym.value.saturating_sub(sec_addr)
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

fn sign_extend_to_i64(value: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

fn add_signed_u64(base: u64, addend: i64) -> u64 {
    if addend >= 0 {
        base.wrapping_add(addend as u64)
    } else {
        base.wrapping_sub((-addend) as u64)
    }
}

fn decode_arm64_reloc_addend(r_symbolnum: u32) -> i64 {
    sign_extend_to_i64((r_symbolnum & 0x00ff_ffff) as u64, 24)
}

fn decode_arm64_branch_addend(insn: u32) -> i64 {
    let imm26 = (insn & 0x03ff_ffff) as u64;
    sign_extend_to_i64(imm26, 26) << 2
}

fn decode_arm64_adrp_addend(insn: u32) -> i64 {
    let immlo = ((insn >> 29) & 0x3) as u64;
    let immhi = ((insn >> 5) & 0x7ffff) as u64;
    let imm21 = (immhi << 2) | immlo;
    sign_extend_to_i64(imm21, 21) << 12
}

fn is_arm64_add_immediate(insn: u32) -> bool {
    let masked = insn & 0x1f00_0000;
    masked == 0x1100_0000 || masked == 0x9100_0000
}

fn is_arm64_load_store_uimm(insn: u32) -> bool {
    (insn & 0x3b00_0000) == 0x3900_0000
}

fn decode_arm64_pageoff_addend(insn: u32) -> u64 {
    let imm12 = ((insn >> 10) & 0x0fff) as u64;
    if is_arm64_add_immediate(insn) {
        let shift = ((insn >> 22) & 1) as u64;
        if shift == 0 { imm12 } else { imm12 << 12 }
    } else if is_arm64_load_store_uimm(insn) {
        let scale = ((insn >> 30) & 0x3) as u64;
        imm12 << scale
    } else {
        imm12
    }
}

fn encode_arm64_pageoff_immediate(insn: u32, pageoff: u32) -> Result<u32, String> {
    let (unit, imm12_max) = if is_arm64_add_immediate(insn) {
        let shift = (insn >> 22) & 1;
        let unit = if shift == 0 { 1u32 } else { 1u32 << 12 };
        (unit, 0x0fff)
    } else if is_arm64_load_store_uimm(insn) {
        let scale = (insn >> 30) & 0x3;
        let unit = 1u32 << scale;
        (unit, 0x0fff)
    } else {
        (1u32, 0x0fff)
    };

    if pageoff % unit != 0 {
        return Err(format!(
            "pageoff {} not aligned for instruction unit {}",
            pageoff, unit
        ));
    }
    let imm12 = pageoff / unit;
    if imm12 > imm12_max {
        return Err(format!("pageoff immediate {} out of range", imm12));
    }
    Ok((insn & 0xffc0_03ff) | (imm12 << 10))
}

fn encode_arm64_tlvp_local_add(insn: u32, pageoff: u32) -> Result<u32, String> {
    if pageoff > 0x0fff {
        return Err(format!("tlvp local pageoff {} out of range", pageoff));
    }
    let rd = insn & 0x1f;
    let rn = (insn >> 5) & 0x1f;
    Ok(0x9100_0000 | (pageoff << 10) | (rn << 5) | rd)
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

fn section_offset_from_contrib(contrib: &HashMap<u8, ObjectSectionContrib>) -> HashMap<u8, u64> {
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
    section_offset: Option<&HashMap<u8, u64>>,
    got_slot_by_symbol: Option<&HashMap<String, u64>>,
    _undefined: &[String],
    text_shift: u64,
    data_shift: u64,
    mut rebase_addrs: Option<&mut HashSet<u64>>,
    mut direct_binds: Option<&mut Vec<(u64, String, bool, i64)>>,
) -> Result<(), String> {
    let trace_relocs = std::env::var("WELD_TRACE_RELOCS").ok().as_deref() == Some("1");
    let trace_tls = std::env::var("WELD_TRACE_TLS").ok().as_deref() == Some("1");
    let mut vaddr_by_sect: HashMap<u8, u64> = HashMap::new();
    for (i, sec) in obj.sections.iter().enumerate() {
        let sect_idx = (i + 1) as u8;
        let merged_name = merged_section_name_for_lookup(&sec.segname, &sec.sectname);
        if let Some(&idx) = layout.section_by_name.get(&merged_name) {
            let off = section_offset
                .and_then(|m| m.get(&sect_idx).copied())
                .unwrap_or(0);
            vaddr_by_sect.insert(sect_idx, layout.sections[idx].vaddr + off);
        }
    }

    let section_ranges: Vec<(u64, u64, u64)> = layout
        .sections
        .iter()
        .map(|sec| {
            let shift = if is_data_layout_section(&sec.name) {
                data_shift
            } else {
                text_shift
            };
            (sec.vaddr, sec.vaddr + sec.data.len() as u64, shift)
        })
        .collect();

    let tls_ranges: Vec<(u64, u64)> = layout
        .sections
        .iter()
        .filter(|sec| sec.name == "__DATA.__thread_data" || sec.name == "__DATA.__thread_bss")
        .map(|sec| (sec.vaddr, sec.vaddr + sec.data.len() as u64))
        .collect();
    let tls_base = tls_ranges.iter().map(|(start, _)| *start).min();
    let tls_end = tls_ranges.iter().map(|(_, end)| *end).max();
    let tls_size = match (tls_base, tls_end) {
        (Some(base), Some(end)) if end >= base => end - base,
        _ => 0,
    };
    if trace_tls {
        eprintln!(
            "tls-ranges={:?} tls_base={:?} tls_end={:?} tls_size=0x{:x}",
            tls_ranges, tls_base, tls_end, tls_size
        );
    }
    for (i, sec) in obj.sections.iter().enumerate() {
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
            .and_then(|m| m.get(&((i + 1) as u8)).copied())
            .unwrap_or(0) as usize;

        let mut addend_by_address: HashMap<u32, i64> = HashMap::new();

        for r in &relocs {
            if r.r_type == ARM64_RELOC_ADDEND {
                addend_by_address.insert(r.r_address, decode_arm64_reloc_addend(r.r_symbolnum));
                continue;
            }

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
            let place_addr = merged.vaddr + off as u64;
            let place_shift = section_ranges
                .get(merged_idx)
                .map(|(_, _, shift)| *shift)
                .unwrap_or(text_shift);
            let mut should_record_rebase =
                !r.r_pcrel && r.r_length == 3 && is_data_layout_section(&merged.name);

            let mut direct_bind_symbol: Option<(String, bool, i64)> = None;
            let base = if r.r_extern {
                let idx = r.r_symbolnum as usize;
                let sym = obj.symbols.get(idx);
                let resolved_sym_addr = symbol_addr_by_idx
                    .get(idx)
                    .and_then(|o| o.as_ref().copied());
                let wants_direct_bind = sym
                    .map(|s| {
                        !s.is_defined
                            && is_thread_vars_section(&merged.name)
                            && r.r_type == GENERIC_RELOC_VANILLA
                            && r.r_length == 3
                            && !r.r_pcrel
                    })
                    .unwrap_or(false);

                if wants_direct_bind {
                    if let Some(s) = sym {
                        let mut bind_addend = read_addend(&merged.data, off, r.r_length) as i64;
                        if bind_addend == 0 && s.name == "__tlv_bootstrap" {
                            bind_addend = 8;
                        }
                        direct_bind_symbol = Some((s.name.clone(), s.is_weak_ref, bind_addend));
                    }
                    0
                } else {
                    let is_got_reloc = r.r_type == ARM64_RELOC_GOT_LOAD_PAGE21
                        || r.r_type == ARM64_RELOC_GOT_LOAD_PAGEOFF12;
                    let is_tlvp_reloc = r.r_type == ARM64_RELOC_TLVP_LOAD_PAGE21
                        || r.r_type == ARM64_RELOC_TLVP_LOAD_PAGEOFF12;
                    let use_got_slot = sym
                        .map(|s| {
                            if is_tlvp_reloc {
                                resolved_sym_addr.is_none()
                            } else {
                                !s.is_defined && is_got_reloc
                            }
                        })
                        .unwrap_or(false);
                    let addr_opt = if use_got_slot && got_slot_by_symbol.is_some() {
                        obj.symbols
                            .get(idx)
                            .and_then(|s| got_slot_by_symbol.and_then(|m| m.get(&s.name).copied()))
                    } else {
                        None
                    };
                    let addr_opt = addr_opt.or_else(|| resolved_sym_addr);
                    let Some(addr) = addr_opt else {
                        let sym_name = obj.symbols.get(idx).map(|s| s.name.as_str()).unwrap_or("?");
                        return Err(format!(
                            "undefined symbol index {} ({}) for relocation",
                            idx, sym_name
                        ));
                    };
                    addr
                }
            } else {
                let sect_idx = r.r_symbolnum as u8;
                let addr = vaddr_by_sect.get(&sect_idx).copied().unwrap_or(0);
                addr
            };
            let base_runtime = if direct_bind_symbol.is_some() {
                0
            } else {
                runtime_addr_for_layout_addr(&section_ranges, text_shift, base)
            };
            let place_runtime = place_addr.wrapping_add(place_shift);
            let extra_addend = addend_by_address.remove(&r.r_address).unwrap_or(0);
            if direct_bind_symbol.is_some() {
                should_record_rebase = false;
            }
            if let Some((sym_name, weak, bind_addend)) = direct_bind_symbol {
                if let Some(binds) = direct_binds.as_deref_mut() {
                    binds.push((place_addr, sym_name, weak, bind_addend));
                }
            }

            if trace_tls && is_thread_vars_section(&merged.name) && r.r_length == 3 {
                let sym_name = if r.r_extern {
                    obj.symbols
                        .get(r.r_symbolnum as usize)
                        .map(|s| s.name.as_str())
                        .unwrap_or("?")
                } else {
                    "<local-sect>"
                };
                let sym_defined = if r.r_extern {
                    obj.symbols
                        .get(r.r_symbolnum as usize)
                        .map(|s| s.is_defined)
                        .unwrap_or(false)
                } else {
                    false
                };
                eprintln!(
                    "tls-reloc off=0x{:x} mod24={} type={} ext={} def={} pcrel={} sym={} base=0x{:x} addend={} sect={}",
                    off,
                    off % 24,
                    r.r_type,
                    r.r_extern,
                    sym_defined,
                    r.r_pcrel,
                    sym_name,
                    base,
                    extra_addend,
                    merged.name
                );
            }

            if trace_relocs && (0x100010000..0x100012000).contains(&place_runtime) {
                let sym_name = if r.r_extern {
                    obj.symbols
                        .get(r.r_symbolnum as usize)
                        .map(|s| s.name.as_str())
                        .unwrap_or("?")
                } else {
                    "<local-sect>"
                };
                eprintln!(
                    "reloc place=0x{:x} type={} extern={} sym={} base=0x{:x} base_rt=0x{:x} extra_addend={} sect={}",
                    place_runtime,
                    r.r_type,
                    r.r_extern,
                    sym_name,
                    base,
                    base_runtime,
                    extra_addend,
                    merged.name
                );

                if r.r_extern {
                    if let Some(sym) = obj.symbols.get(r.r_symbolnum as usize) {
                        if r.r_type == ARM64_RELOC_TLVP_LOAD_PAGE21
                            || r.r_type == ARM64_RELOC_TLVP_LOAD_PAGEOFF12
                        {
                            let sec_info = if sym.sect != 0 {
                                obj.sections
                                    .get((sym.sect - 1) as usize)
                                    .map(|s| {
                                        format!(
                                            "{}:{} merged={} sec_addr=0x{:x}",
                                            s.segname,
                                            s.sectname,
                                            merged_section_name_for_lookup(&s.segname, &s.sectname),
                                            s.addr
                                        )
                                    })
                                    .unwrap_or_else(|| "<bad-sect-idx>".to_string())
                            } else {
                                "<undef-sect>".to_string()
                            };
                            eprintln!(
                                "  tlvp detail: sym={} sym_n_type=0x{:02x} sym_sect={} sym_value=0x{:x} sec_info={}",
                                sym.name, sym.n_type, sym.sect, sym.value, sec_info
                            );
                        }
                        if sym.name.starts_with("__MergedGlobals") {
                            let sec_info = if sym.sect != 0 {
                                obj.sections
                                    .get((sym.sect - 1) as usize)
                                    .map(|s| {
                                        format!(
                                            "{}:{} merged={} sec_addr=0x{:x}",
                                            s.segname,
                                            s.sectname,
                                            merged_section_name_for_lookup(&s.segname, &s.sectname),
                                            s.addr
                                        )
                                    })
                                    .unwrap_or_else(|| "<bad-sect-idx>".to_string())
                            } else {
                                "<undef-sect>".to_string()
                            };
                            eprintln!(
                                "  mergedglobals detail: sym_n_type=0x{:02x} sym_sect={} sym_value=0x{:x} sec_info={}",
                                sym.n_type, sym.sect, sym.value, sec_info
                            );
                        }
                    }
                }
            }

            match r.r_type {
                GENERIC_RELOC_VANILLA => match r.r_length {
                    0 => {
                        let addend = read_addend(&merged.data, off, r.r_length);
                        let mut value = base_runtime.wrapping_add(addend);
                        if r.r_pcrel {
                            value = value.wrapping_sub(place_runtime);
                        }
                        merged.data[off] = value as u8;
                    }
                    1 => {
                        let addend = read_addend(&merged.data, off, r.r_length);
                        let mut value = base_runtime.wrapping_add(addend);
                        if r.r_pcrel {
                            value = value.wrapping_sub(place_runtime);
                        }
                        let v = (value as u16).to_le_bytes();
                        merged.data[off..off + 2].copy_from_slice(&v);
                    }
                    2 => {
                        let addend = read_addend(&merged.data, off, r.r_length);
                        let mut value = base_runtime.wrapping_add(addend);
                        if r.r_pcrel {
                            value = value.wrapping_sub(place_runtime);
                        }
                        write_u32_le(&mut merged.data, off, value as u32);
                    }
                    3 => {
                        let addend = read_addend(&merged.data, off, r.r_length);
                        let is_tls_target = is_thread_vars_section(&merged.name)
                            && !r.r_pcrel
                            && tls_ranges
                                .iter()
                                .any(|(start, end)| base >= *start && base < *end);
                        if is_tls_target {
                            if let Some(tls_start) = tls_base {
                                let target = base.wrapping_add(addend);
                                let tls_offset = target.wrapping_sub(tls_start) as u32;
                                if (off % 24) == 16 && off >= 16 && off + 8 <= merged.data.len() {
                                    let desc_base = off - 16;
                                    write_u64_le(
                                        &mut merged.data,
                                        desc_base + 16,
                                        tls_offset as u64,
                                    );
                                    continue;
                                }
                            }
                        }
                        let mut value = base_runtime.wrapping_add(addend);
                        if r.r_pcrel {
                            value = value.wrapping_sub(place_runtime);
                        }
                        write_u64_le(&mut merged.data, off, value);
                        if should_record_rebase {
                            if let Some(rebases) = rebase_addrs.as_deref_mut() {
                                rebases.insert(place_addr);
                            }
                        }
                    }
                    _ => {}
                },
                ARM64_RELOC_BRANCH26 => {
                    if merged.data.len() < off + 4 {
                        return Err("branch reloc: buffer too short".to_string());
                    }
                    let insn = read_u32_le(&merged.data, off).unwrap_or(0);
                    let addend = decode_arm64_branch_addend(insn) + extra_addend;
                    let target = add_signed_u64(base_runtime, addend);
                    let delta = (target as i128) - (place_runtime as i128);
                    if (delta & 0x3) != 0 {
                        return Err(format!(
                            "branch reloc not 4-byte aligned: target=0x{:x} place=0x{:x}",
                            target, place_runtime
                        ));
                    }
                    let imm26 = delta >> 2;
                    if imm26 < -(1i128 << 25) || imm26 >= (1i128 << 25) {
                        return Err(format!(
                            "branch reloc out of range: target=0x{:x} place=0x{:x}",
                            target, place_runtime
                        ));
                    }
                    let imm26_bits = (imm26 as i64 as u32) & 0x03ff_ffff;
                    let patched = (insn & 0xfc00_0000) | imm26_bits;
                    write_u32_le(&mut merged.data, off, patched);
                }
                ARM64_RELOC_PAGE21 | ARM64_RELOC_GOT_LOAD_PAGE21 | ARM64_RELOC_TLVP_LOAD_PAGE21 => {
                    if merged.data.len() < off + 4 {
                        return Err("page21 reloc: buffer too short".to_string());
                    }
                    let insn = read_u32_le(&merged.data, off).unwrap_or(0);
                    let addend = decode_arm64_adrp_addend(insn) + extra_addend;
                    let target = add_signed_u64(base_runtime, addend);
                    let target_page = (target & !0xfff) as i128;
                    let place_page = (place_runtime & !0xfff) as i128;
                    let delta_pages = (target_page - place_page) >> 12;
                    if delta_pages < -(1i128 << 20) || delta_pages >= (1i128 << 20) {
                        return Err(format!(
                            "adrp reloc out of range: target=0x{:x} place=0x{:x}",
                            target, place_runtime
                        ));
                    }
                    let imm21 = (delta_pages as i64 as u32) & 0x1f_ffff;
                    let imm_lo = imm21 & 0x3;
                    let imm_hi = (imm21 >> 2) & 0x7ffff;
                    let patched = (insn & 0x9F00001F) | (imm_lo << 29) | (imm_hi << 5);
                    write_u32_le(&mut merged.data, off, patched);
                }
                ARM64_RELOC_PAGEOFF12
                | ARM64_RELOC_TLVP_LOAD_PAGEOFF12
                | ARM64_RELOC_GOT_LOAD_PAGEOFF12 => {
                    if merged.data.len() < off + 4 {
                        return Err("pageoff12 reloc: buffer too short".to_string());
                    }
                    let insn = read_u32_le(&merged.data, off).unwrap_or(0);
                    let insn_addend = decode_arm64_pageoff_addend(insn) as i64;
                    let addend = insn_addend + extra_addend;
                    let target = add_signed_u64(base_runtime, addend);
                    let pageoff = (target & 0x0fff) as u32;
                    let patched = if r.r_type == ARM64_RELOC_TLVP_LOAD_PAGEOFF12
                        && r.r_extern
                        && obj
                            .symbols
                            .get(r.r_symbolnum as usize)
                            .map(|s| s.is_defined)
                            .unwrap_or(false)
                    {
                        encode_arm64_tlvp_local_add(insn, pageoff)
                    } else {
                        encode_arm64_pageoff_immediate(insn, pageoff)
                    }
                    .map_err(|e| {
                        format!(
                            "{} (reloc_type={} insn=0x{:08x} base=0x{:x} addend=0x{:x} place=0x{:x})",
                            e, r.r_type, insn, base_runtime, addend, place_runtime
                        )
                    })?;
                    write_u32_le(&mut merged.data, off, patched);
                }
                ARM64_RELOC_ADDEND => {}
                _ => {
                    return Err(format!("unsupported Mach-O relocation type {}", r.r_type));
                }
            }
        }

        if is_thread_vars_section(&merged.name) {
            let tv_size = merged.data.len() as u64;
            let mut i = 0usize;
            while i + 24 <= merged.data.len() {
                let init_off = read_u64_le(&merged.data, i + 16).unwrap_or(0) & 0xffff_ffff;
                let desc_off = i as u64;
                let q2_low = tv_size.saturating_sub(16).saturating_sub(desc_off);
                write_u64_le(&mut merged.data, i + 8, (init_off << 32) | 0x102);
                write_u64_le(&mut merged.data, i + 16, ((0x58u64) << 32) | q2_low);
                i += 24;
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
    apply_macho_relocations(
        &obj,
        &mut layout,
        &symbol_addrs,
        &symbol_addr_by_idx,
        None,
        None,
        &[],
        VM_ADDR_BIAS,
        VM_ADDR_BIAS,
        None,
        None,
    )?;

    let e_machine = arch.to_elf_machine();

    Ok(LinkResult {
        layout,
        e_machine,
        symbol_addrs,
        dynamic: None,
    })
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
    let mut global_symbol_weak: HashMap<String, bool> = HashMap::new();
    for (obj_idx, obj) in objects.iter().enumerate() {
        let contrib = &section_contribs[obj_idx];
        let mut vaddr_by_sect: HashMap<u8, u64> = HashMap::new();
        for (i, sec) in obj.sections.iter().enumerate() {
            let sect_idx = (i + 1) as u8;
            let merged_name = merged_section_name_for_lookup(&sec.segname, &sec.sectname);
            if let (Some(&idx), Some(off)) = (
                layout.section_by_name.get(&merged_name),
                contrib.get(&sect_idx),
            ) {
                vaddr_by_sect.insert(sect_idx, layout.sections[idx].vaddr + off.offset_in_merged);
            }
        }
        for sym in &obj.symbols {
            if !sym.is_defined || sym.name.is_empty() || (sym.n_type & N_EXT) == 0 {
                continue;
            }
            if let Some(&base) = vaddr_by_sect.get(&sym.sect) {
                let addr = base + symbol_offset_in_section(obj, sym);
                let weak_def = (sym.n_desc & N_WEAK_DEF) != 0;
                match global_symbols.get_mut(&sym.name) {
                    Some(existing_addr) => {
                        let existing_weak = *global_symbol_weak.get(&sym.name).unwrap_or(&false);
                        if existing_weak && !weak_def {
                            *existing_addr = addr;
                            global_symbol_weak.insert(sym.name.clone(), false);
                        }
                    }
                    None => {
                        global_symbols.insert(sym.name.clone(), addr);
                        global_symbol_weak.insert(sym.name.clone(), weak_def);
                    }
                }
            }
        }
    }

    let _has_system = libs
        .map(|l| l.iter().any(|x| x == "System" || x == "c" || x == "m"))
        .unwrap_or(false);

    let mut undefined: Vec<String> = Vec::new();
    let mut undefined_set: HashSet<String> = HashSet::new();
    let mut weak_undefined: HashSet<String> = HashSet::new();
    let mut got_symbols: Vec<String> = Vec::new();
    let mut got_symbol_set: HashSet<String> = HashSet::new();
    let mut rebase_addrs: HashSet<u64> = HashSet::new();
    let mut direct_binds: Vec<(u64, String, bool, i64)> = Vec::new();
    if arch == TargetArch::AArch64 {
        for obj in &objects {
            for sym in &obj.symbols {
                if !sym.is_defined && !sym.name.is_empty() {
                    if (sym.n_type & N_EXT) == 0 {
                        continue;
                    }
                    if !global_symbols.contains_key(&sym.name)
                        && undefined_set.insert(sym.name.clone())
                    {
                        undefined.push(sym.name.clone());
                    }
                    if sym.is_weak_ref {
                        weak_undefined.insert(sym.name.clone());
                    }
                }
            }
        }

        for obj in &objects {
            for sec in &obj.sections {
                if sec.nreloc == 0 {
                    continue;
                }
                let relocs = parse_macho_relocs(&obj.data, sec.reloff, sec.nreloc);
                for r in &relocs {
                    if !r.r_extern {
                        continue;
                    }
                    let idx = r.r_symbolnum as usize;
                    let Some(sym) = obj.symbols.get(idx) else {
                        continue;
                    };
                    if sym.name.is_empty() {
                        continue;
                    }
                    if (sym.n_type & N_EXT) == 0 {
                        continue;
                    }
                    let is_got_reloc = r.r_type == ARM64_RELOC_GOT_LOAD_PAGE21
                        || r.r_type == ARM64_RELOC_GOT_LOAD_PAGEOFF12;
                    let is_tlvp_reloc = r.r_type == ARM64_RELOC_TLVP_LOAD_PAGE21
                        || r.r_type == ARM64_RELOC_TLVP_LOAD_PAGEOFF12;
                    let is_locally_resolved = global_symbols.contains_key(&sym.name);
                    let needs_got = if is_tlvp_reloc {
                        !is_locally_resolved
                    } else {
                        !sym.is_defined && is_got_reloc
                    };
                    if needs_got && got_symbol_set.insert(sym.name.clone()) {
                        got_symbols.push(sym.name.clone());
                    }
                    if sym.is_defined {
                        continue;
                    }
                    if !global_symbols.contains_key(&sym.name)
                        && undefined_set.insert(sym.name.clone())
                    {
                        undefined.push(sym.name.clone());
                    }
                    if sym.is_weak_ref {
                        weak_undefined.insert(sym.name.clone());
                    }
                }
            }
        }

        let mut ordered_got = undefined.clone();
        let mut ordered_set: HashSet<String> = undefined.iter().cloned().collect();
        for sym in got_symbols {
            if ordered_set.insert(sym.clone()) {
                ordered_got.push(sym);
            }
        }
        got_symbols = ordered_got;

        if !undefined.is_empty() || !got_symbols.is_empty() {
            let last = layout.sections.last().ok_or("no sections")?;
            let mut vaddr = align_up_bytes(last.vaddr + last.data.len() as u64, 16);

            let (stubs_data, stub_helper_data, got_data) = build_macho_stubs_arm64(
                &undefined,
                got_symbols.len(),
                vaddr,
                VM_ADDR_BIAS,
                VM_ADDR_BIAS,
            )?;

            let stubs_vaddr = vaddr;
            layout.sections.push(MergedSection {
                name: "__stubs".into(),
                data: stubs_data,
                vaddr: stubs_vaddr,
                flags: 6,
                align: 4,
            });
            layout
                .section_by_name
                .insert("__stubs".into(), layout.sections.len() - 1);
            vaddr += layout.sections.last().unwrap().data.len() as u64;

            let stub_helper_vaddr = vaddr;
            layout.sections.push(MergedSection {
                name: "__stub_helper".into(),
                data: stub_helper_data,
                vaddr: stub_helper_vaddr,
                flags: 6,
                align: 4,
            });
            layout
                .section_by_name
                .insert("__stub_helper".into(), layout.sections.len() - 1);
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
            layout
                .section_by_name
                .insert("__got".into(), layout.sections.len() - 1);

            for (i, sym) in undefined.iter().enumerate() {
                let stub_addr = stubs_vaddr + (i as u64) * 12;
                global_symbols.insert(sym.clone(), stub_addr);
            }
        }
    }

    let (text_shift, data_shift) = compute_runtime_shifts(&layout);

    if let Some(stubs_idx) = layout.section_by_name.get("__stubs").copied() {
        let stubs_vaddr = layout.sections[stubs_idx].vaddr;
        let (patched_stubs, _stub_helper, _got) = build_macho_stubs_arm64(
            &undefined,
            got_symbols.len(),
            stubs_vaddr,
            text_shift,
            data_shift,
        )?;
        layout.sections[stubs_idx].data = patched_stubs;
    }

    let section_ranges: Vec<(u64, u64, u64)> = layout
        .sections
        .iter()
        .map(|sec| {
            let shift = if is_data_layout_section(&sec.name) {
                data_shift
            } else {
                text_shift
            };
            (sec.vaddr, sec.vaddr + sec.data.len() as u64, shift)
        })
        .collect();

    if let Some(got_idx) = layout.section_by_name.get("__got").copied() {
        let trace_relocs = std::env::var("WELD_TRACE_RELOCS").ok().as_deref() == Some("1");
        let undefined_set: HashSet<&str> = undefined.iter().map(|s| s.as_str()).collect();
        let got_base = layout.sections[got_idx].vaddr;
        for i in 0..got_symbols.len() {
            rebase_addrs.insert(got_base + (i as u64) * 8);
        }
        let got_data = &mut layout.sections[got_idx].data;
        for (i, sym) in got_symbols.iter().enumerate() {
            if undefined_set.contains(sym.as_str()) {
                continue;
            }
            if let Some(&addr) = global_symbols.get(sym) {
                let runtime_addr = runtime_addr_for_layout_addr(&section_ranges, text_shift, addr);
                let slot_off = i * 8;
                if slot_off + 8 <= got_data.len() {
                    got_data[slot_off..slot_off + 8].copy_from_slice(&runtime_addr.to_le_bytes());
                    if trace_relocs && sym.contains("thread7current2id2ID") {
                        eprintln!(
                            "got prefill: sym={} layout_addr=0x{:x} runtime_addr=0x{:x} slot=0x{:x}",
                            sym,
                            addr,
                            runtime_addr,
                            got_base + slot_off as u64
                        );
                    }
                }
            }
        }
    }

    let got_slot_by_symbol: HashMap<String, u64> = if layout.section_by_name.contains_key("__got") {
        let got_idx = layout.section_by_name["__got"];
        let got_vaddr = layout.sections[got_idx].vaddr;
        got_symbols
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
            &undefined,
            text_shift,
            data_shift,
            Some(&mut rebase_addrs),
            Some(&mut direct_binds),
        )?;
    }

    let dynamic = if layout.section_by_name.contains_key("__got") {
        let plt_symbols = undefined;
        if std::env::var("WELD_TRACE_UNDEF").ok().as_deref() == Some("1") {
            let tlv_bootstrap_count = plt_symbols
                .iter()
                .filter(|s| s.as_str() == "__tlv_bootstrap")
                .count();
            eprintln!(
                "weld undefined count={} tlv_bootstrap_count={}",
                plt_symbols.len(),
                tlv_bootstrap_count
            );
        }
        let weak_plt_symbols: Vec<String> = plt_symbols
            .iter()
            .filter(|s| weak_undefined.contains(*s))
            .cloned()
            .collect();
        let mut macho_rebase_addrs: Vec<u64> = rebase_addrs.into_iter().collect();
        macho_rebase_addrs.sort_unstable();
        direct_binds.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        direct_binds.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1 && a.2 == b.2 && a.3 == b.3);
        if std::env::var("WELD_TRACE_BINDS").ok().as_deref() == Some("1") {
            eprintln!("weld direct_binds: {}", direct_binds.len());
            for (addr, sym, weak, addend) in direct_binds.iter().take(32) {
                eprintln!(
                    "  bind addr=0x{:x} sym={} weak={} addend={}",
                    addr, sym, weak, addend
                );
            }
        }
        let mut needed = vec!["libSystem.B.dylib".into()];
        for p in dylib_paths {
            if let Some(s) = p.to_str() {
                needed.push(s.to_string());
            }
        }
        Some(crate::link::DynamicLinkInfo {
            needed,
            plt_symbols,
            weak_plt_symbols,
            interpreter: None,
            macho_rebase_addrs,
            macho_direct_binds: direct_binds,
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
    got_slot_count: usize,
    stubs_start_vaddr: u64,
    text_shift: u64,
    data_shift: u64,
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
        let stub_runtime = stub_addr.wrapping_add(text_shift);
        let got_runtime = got_slot.wrapping_add(data_shift);
        let page = got_runtime & !0xFFF;
        let pageoff = (got_runtime & 0xFFF) as u32;
        let stub_page = stub_runtime & !0xFFF;
        let imm = ((page as i64 - stub_page as i64) >> 12) as i32;
        let imm_lo = (imm & 3) as u32;
        let imm_hi = ((imm >> 2) & 0x7FFFF) as u32;
        let adrp = 0x90000010u32 | (imm_lo << 29) | (imm_hi << 5);
        let ldr_imm12 = (pageoff >> 3) & 0x0fff;
        let ldr = 0xF9400210u32 | (ldr_imm12 << 10);
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

    let got = vec![0u8; got_slot_count * 8];

    Ok((stubs, stub_helper, got))
}

fn merged_section_name_for_lookup(segname: &str, sectname: &str) -> String {
    if sectname == "__text" {
        ".text".into()
    } else if segname.starts_with("__TEXT")
        || segname.starts_with("__DATA")
        || segname.starts_with("__AUTH")
    {
        format!("{}.{}", segname, sectname)
    } else {
        sectname.to_string()
    }
}

fn symbol_addr_by_index_multi(
    obj: &Macho64Object,
    layout: &MergedLayout,
    global_symbols: &HashMap<String, u64>,
    contrib: &HashMap<u8, ObjectSectionContrib>,
) -> Vec<Option<u64>> {
    let mut vaddr_by_sect: HashMap<u8, u64> = HashMap::new();
    for (i, sec) in obj.sections.iter().enumerate() {
        let sect_idx = (i + 1) as u8;
        let merged_name = merged_section_name_for_lookup(&sec.segname, &sec.sectname);
        if let (Some(&idx), Some(off)) = (
            layout.section_by_name.get(&merged_name),
            contrib.get(&sect_idx),
        ) {
            vaddr_by_sect.insert(sect_idx, layout.sections[idx].vaddr + off.offset_in_merged);
        }
    }

    obj.symbols
        .iter()
        .map(|sym| {
            let defined_addr = sym
                .is_defined
                .then(|| {
                    vaddr_by_sect
                        .get(&sym.sect)
                        .map(|&base| base + symbol_offset_in_section(obj, sym))
                })
                .flatten();
            let undef_addr = if (sym.n_type & N_EXT) != 0 {
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
            } else {
                None
            };
            defined_addr.or(undef_addr)
        })
        .collect()
}

fn merge_macho_sections_multi(
    objects: &[Macho64Object],
) -> Result<(MergedLayout, Vec<HashMap<u8, ObjectSectionContrib>>), String> {
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
        ("__DATA_DIRTY", "__const"),
        ("__DATA", "__data"),
        ("__DATA_DIRTY", "__data"),
        ("__DATA", "__thread_vars"),
        ("__DATA_DIRTY", "__thread_vars"),
        ("__DATA", "__thread_data"),
        ("__DATA_DIRTY", "__thread_data"),
        ("__DATA", "__thread_bss"),
        ("__DATA_DIRTY", "__thread_bss"),
        ("__DATA", "__bss"),
        ("__DATA_DIRTY", "__bss"),
    ];

    let mut section_contribs: Vec<HashMap<u8, ObjectSectionContrib>> =
        (0..objects.len()).map(|_| HashMap::new()).collect();
    let mut merged_data: HashMap<String, Vec<(Vec<u8>, u64)>> = HashMap::new();
    let mut section_cumul: HashMap<String, u64> = HashMap::new();
    let mut section_aligns: HashMap<String, u64> = HashMap::new();
    let mut section_flags: HashMap<String, u64> = HashMap::new();

    for (obj_idx, obj) in objects.iter().enumerate() {
        for (sec_i, sec) in obj.sections.iter().enumerate() {
            if !is_mergeable_section(sec) {
                continue;
            }
            let sect_idx = (sec_i + 1) as u8;
            let merged_name = merged_section_name_for_lookup(&sec.segname, &sec.sectname);
            let data = read_section_data(obj, sec);
            let mut a = if sec.align > 0 { sec.align as u64 } else { 4 };
            if is_data_layout_section(&merged_name) && a < 3 {
                a = 3;
            }
            let size = sec.size;
            let current = *section_cumul.get(&merged_name).unwrap_or(&0);
            let offset_in_merged = align_up(current, a);
            section_cumul.insert(merged_name.clone(), offset_in_merged + size);

            section_aligns
                .entry(merged_name.clone())
                .and_modify(|x| *x = (*x).max(a))
                .or_insert(a);

            let flags = if sec.sectname == "__text" { 6 } else { 2 };
            section_flags
                .entry(merged_name.clone())
                .and_modify(|f| *f |= flags)
                .or_insert(flags);

            let entry = merged_data.entry(merged_name.clone()).or_default();
            if offset_in_merged > current {
                let pad = (offset_in_merged - current) as usize;
                entry.push((vec![0u8; pad], pad as u64));
            }
            entry.push((data, size));

            section_contribs[obj_idx].insert(
                sect_idx,
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

    let mut extra_sections: Vec<String> = merged_data
        .keys()
        .filter(|name| !layout.section_by_name.contains_key(*name))
        .cloned()
        .collect();
    extra_sections.sort();

    for merged_name in extra_sections {
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
            name: merged_name,
            data: merged_bytes,
            vaddr,
            flags,
            align,
        });
        vaddr += layout.sections[idx].data.len() as u64;
    }

    Ok((layout, section_contribs))
}
