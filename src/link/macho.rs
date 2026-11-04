//! Mach-O object linking for macOS.
//!
//! Merges sections, resolves symbols, applies relocations.

use crate::collections::{HashMap, HashSet};
use crate::{
    arch::TargetArch,
    link::{DynamicLinkInfo, LinkResult, MergedLayout, MergedSection, ObjectSectionContrib},
    macho::{
        ARM64_RELOC_ADDEND, ARM64_RELOC_BRANCH26, ARM64_RELOC_GOT_LOAD_PAGE21,
        ARM64_RELOC_GOT_LOAD_PAGEOFF12, ARM64_RELOC_PAGE21, ARM64_RELOC_PAGEOFF12,
        ARM64_RELOC_TLVP_LOAD_PAGE21, ARM64_RELOC_TLVP_LOAD_PAGEOFF12, GENERIC_RELOC_VANILLA,
        Macho64Object, MachoReloc, MachoSection, MachoSymbol, parse_macho_relocs,
        parse_macho64_object,
    },
};
use std::path::PathBuf;

/// Three binary sections emitted when building stub trampolines:
/// stubs, stub helper, and GOT slots.
type StubTriple = (Vec<u8>, Vec<u8>, Vec<u8>);

const SEG_BASE: u64 = 0x100000000;
const VM_ADDR_BIAS: u64 = 0x4000;
const SECTION_TYPE_MASK: u32 = 0x0000_00ff;
/// Mach-O `loader.h`: `S_ATTR_DEBUG`. The linker drops such a section rather than
/// carrying it into the image; `dsymutil` reads the DWARF from the objects instead.
const S_ATTR_DEBUG: u32 = 0x0200_0000;
const S_ZEROFILL: u32 = 0x1;
const S_GB_ZEROFILL: u32 = 0xc;
const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
const N_WEAK_DEF: u16 = 0x0080;
const N_EXT: u8 = 0x01;
const X86_64_RELOC_SIGNED: u32 = 1;
const X86_64_RELOC_BRANCH: u32 = 2;
const X86_64_RELOC_GOT_LOAD: u32 = 3;
const X86_64_RELOC_GOT: u32 = 4;
const X86_64_RELOC_SUBTRACTOR: u32 = 5;
const X86_64_RELOC_SIGNED_1: u32 = 6;
const X86_64_RELOC_SIGNED_2: u32 = 7;
const X86_64_RELOC_SIGNED_4: u32 = 8;
const X86_64_RELOC_TLV: u32 = 9;

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
    if sec.flags & S_ATTR_DEBUG != 0 {
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

/// A TLV descriptor is thunk, key, offset. dyld fills the key at load time, so
/// the image must carry zero there. The thunk is bound and the offset is written
/// by the relocation, so both are left alone.
fn clear_tlv_descriptor_keys(data: &mut [u8]) {
    let mut i = 0usize;
    while i + 24 <= data.len() {
        write_u64_le(data, i + 8, 0);
        i += 24;
    }
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
        section_by_name: HashMap::default(),
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
            entsize: 0,
            sh_type: 1,
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
    let mut addrs = HashMap::default();
    let mut vaddr_by_sect: HashMap<u8, u64> = HashMap::default();

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
    let mut vaddr_by_sect: HashMap<u8, u64> = HashMap::default();
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

    if !pageoff.is_multiple_of(unit) {
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
        .map(|(k, v)| (*k, v.offset_in_merged))
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelocKind {
    Generic,
    Addend,
    Arm64Branch26,
    Arm64Page21,
    Arm64PageOff12,
    Arm64GotLoadPage21,
    Arm64GotLoadPageOff12,
    Arm64TlvpPage21,
    Arm64TlvpPageOff12,
    /// A 32-bit pc-relative field. `adjust` is the number of instruction bytes
    /// that follow the field. `through_got` marks references that must resolve
    /// to a GOT slot instead of the symbol itself.
    X86Pcrel {
        adjust: u64,
        through_got: bool,
    },
}

fn decode_arm64_reloc_kind(r_type: u32) -> Result<RelocKind, String> {
    Ok(match r_type {
        GENERIC_RELOC_VANILLA => RelocKind::Generic,
        ARM64_RELOC_ADDEND => RelocKind::Addend,
        ARM64_RELOC_BRANCH26 => RelocKind::Arm64Branch26,
        ARM64_RELOC_PAGE21 => RelocKind::Arm64Page21,
        ARM64_RELOC_PAGEOFF12 => RelocKind::Arm64PageOff12,
        ARM64_RELOC_GOT_LOAD_PAGE21 => RelocKind::Arm64GotLoadPage21,
        ARM64_RELOC_GOT_LOAD_PAGEOFF12 => RelocKind::Arm64GotLoadPageOff12,
        ARM64_RELOC_TLVP_LOAD_PAGE21 => RelocKind::Arm64TlvpPage21,
        ARM64_RELOC_TLVP_LOAD_PAGEOFF12 => RelocKind::Arm64TlvpPageOff12,
        other => return Err(format!("unsupported Mach-O relocation type {}", other)),
    })
}

fn decode_x86_64_reloc_kind(r: &MachoReloc) -> Result<RelocKind, String> {
    let pcrel32 = |adjust: u64, through_got: bool| {
        if r.r_pcrel && r.r_length == 2 {
            Ok(RelocKind::X86Pcrel {
                adjust,
                through_got,
            })
        } else {
            Err(format!(
                "x86_64 relocation type {} must be a 32-bit pc-relative field (pcrel={}, length={})",
                r.r_type, r.r_pcrel, r.r_length
            ))
        }
    };
    match r.r_type {
        GENERIC_RELOC_VANILLA => {
            if r.r_pcrel || r.r_length != 3 {
                Err(format!(
                    "x86_64 UNSIGNED relocation must be a 64-bit absolute field (pcrel={}, length={})",
                    r.r_pcrel, r.r_length
                ))
            } else {
                Ok(RelocKind::Generic)
            }
        }
        X86_64_RELOC_SIGNED | X86_64_RELOC_BRANCH => pcrel32(0, false),
        X86_64_RELOC_GOT_LOAD | X86_64_RELOC_GOT => pcrel32(0, true),
        X86_64_RELOC_SIGNED_1 => pcrel32(1, false),
        X86_64_RELOC_SIGNED_2 => pcrel32(2, false),
        X86_64_RELOC_SIGNED_4 => pcrel32(4, false),
        X86_64_RELOC_SUBTRACTOR => Err("x86_64 SUBTRACTOR relocations are not supported".into()),
        X86_64_RELOC_TLV => Err("x86_64 TLV relocations are not supported".into()),
        other => Err(format!(
            "unsupported x86_64 Mach-O relocation type {}",
            other
        )),
    }
}

fn decode_reloc_kind(arch: TargetArch, r: &MachoReloc) -> Result<RelocKind, String> {
    match arch {
        TargetArch::X86_64 => decode_x86_64_reloc_kind(r),
        TargetArch::AArch64 => decode_arm64_reloc_kind(r.r_type),
        _ => Err(format!(
            "Mach-O relocations are not supported for {:?}",
            arch
        )),
    }
}

// Relocation application requires the full object context and all output-layout
// references simultaneously. A builder struct would not reduce real complexity here.
#[allow(clippy::too_many_arguments)]
fn apply_macho_relocations(
    obj: &Macho64Object,
    arch: TargetArch,
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
    let mut vaddr_by_sect: HashMap<u8, u64> = HashMap::default();
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
        log::debug!(
            "tls-ranges={:?} tls_base={:?} tls_end={:?} tls_size=0x{:x}",
            tls_ranges,
            tls_base,
            tls_end,
            tls_size
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

        let mut addend_by_address: HashMap<u32, i64> = HashMap::default();

        for r in &relocs {
            let kind = decode_reloc_kind(arch, r)?;
            if kind == RelocKind::Addend {
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
                            && kind == RelocKind::Generic
                            && r.r_length == 3
                            && !r.r_pcrel
                    })
                    .unwrap_or(false);

                if wants_direct_bind {
                    if let Some(s) = sym {
                        let bind_addend = read_addend(&merged.data, off, r.r_length) as i64;
                        direct_bind_symbol = Some((s.name.clone(), s.is_weak_ref, bind_addend));
                    }
                    0
                } else if let RelocKind::X86Pcrel {
                    through_got: true, ..
                } = kind
                {
                    let name = sym.map(|s| s.name.as_str()).unwrap_or("?");
                    got_slot_by_symbol
                        .and_then(|m| m.get(name).copied())
                        .ok_or_else(|| format!("x86_64 GOT reference to {name} has no GOT slot"))?
                } else {
                    let is_got_reloc = matches!(
                        kind,
                        RelocKind::Arm64GotLoadPage21 | RelocKind::Arm64GotLoadPageOff12
                    );
                    let is_tlvp_reloc = matches!(
                        kind,
                        RelocKind::Arm64TlvpPage21 | RelocKind::Arm64TlvpPageOff12
                    );
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
                    let addr_opt = addr_opt.or(resolved_sym_addr);
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
                if matches!(
                    kind,
                    RelocKind::X86Pcrel {
                        through_got: true,
                        ..
                    }
                ) {
                    return Err(format!(
                        "x86_64 GOT reference at offset 0x{:x} has no external symbol",
                        off
                    ));
                }
                let sect_idx = r.r_symbolnum as u8;

                vaddr_by_sect.get(&sect_idx).copied().unwrap_or(0)
            };
            let base_runtime = if direct_bind_symbol.is_some() {
                0
            } else {
                runtime_addr_for_layout_addr(&section_ranges, text_shift, base)
            };
            let place_runtime = place_addr.wrapping_add(place_shift);
            let extra_addend = addend_by_address.remove(&r.r_address).unwrap_or(0);
            let is_direct_bind = direct_bind_symbol.is_some();
            if is_direct_bind {
                should_record_rebase = false;
            }
            if let Some((sym_name, weak, bind_addend)) = direct_bind_symbol
                && let Some(binds) = direct_binds.as_deref_mut()
            {
                binds.push((place_addr, sym_name, weak, bind_addend));
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
                log::debug!(
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
                log::debug!(
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

                if r.r_extern
                    && let Some(sym) = obj.symbols.get(r.r_symbolnum as usize)
                {
                    if matches!(
                        kind,
                        RelocKind::Arm64TlvpPage21 | RelocKind::Arm64TlvpPageOff12
                    ) {
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
                        log::debug!(
                            "  tlvp detail: sym={} sym_n_type=0x{:02x} sym_sect={} sym_value=0x{:x} sec_info={}",
                            sym.name,
                            sym.n_type,
                            sym.sect,
                            sym.value,
                            sec_info
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
                        log::debug!(
                            "  mergedglobals detail: sym_n_type=0x{:02x} sym_sect={} sym_value=0x{:x} sec_info={}",
                            sym.n_type,
                            sym.sect,
                            sym.value,
                            sec_info
                        );
                    }
                }
            }

            match kind {
                RelocKind::Generic => match r.r_length {
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
                        if !r.r_pcrel
                            && !is_direct_bind
                            && !is_data_layout_section(&merged.name)
                            && !merged.name.starts_with("__DWARF.")
                        {
                            let target = if r.r_extern {
                                obj.symbols
                                    .get(r.r_symbolnum as usize)
                                    .map(|s| s.name.as_str())
                                    .unwrap_or("?")
                            } else {
                                "<section>"
                            };
                            return Err(format!(
                                "absolute pointer to {target} at 0x{:x} in {} cannot be rebased: section is not writable data",
                                place_addr, merged.name
                            ));
                        }
                        let is_tls_target = is_thread_vars_section(&merged.name)
                            && !r.r_pcrel
                            && tls_ranges
                                .iter()
                                .any(|(start, end)| base >= *start && base < *end);
                        if is_tls_target && let Some(tls_start) = tls_base {
                            let target = base.wrapping_add(addend);
                            let tls_offset = target.wrapping_sub(tls_start) as u32;
                            if (off % 24) == 16 && off >= 16 && off + 8 <= merged.data.len() {
                                let desc_base = off - 16;
                                write_u64_le(&mut merged.data, desc_base + 16, tls_offset as u64);
                                continue;
                            }
                        }
                        let mut value = base_runtime.wrapping_add(addend);
                        if r.r_pcrel {
                            value = value.wrapping_sub(place_runtime);
                        }
                        write_u64_le(&mut merged.data, off, value);
                        if should_record_rebase && let Some(rebases) = rebase_addrs.as_deref_mut() {
                            rebases.insert(place_addr);
                        }
                    }
                    _ => {}
                },
                RelocKind::Arm64Branch26 => {
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
                    if !(-(1i128 << 25)..(1i128 << 25)).contains(&imm26) {
                        return Err(format!(
                            "branch reloc out of range: target=0x{:x} place=0x{:x}",
                            target, place_runtime
                        ));
                    }
                    let imm26_bits = (imm26 as i64 as u32) & 0x03ff_ffff;
                    let patched = (insn & 0xfc00_0000) | imm26_bits;
                    write_u32_le(&mut merged.data, off, patched);
                }
                RelocKind::Arm64Page21
                | RelocKind::Arm64GotLoadPage21
                | RelocKind::Arm64TlvpPage21 => {
                    if merged.data.len() < off + 4 {
                        return Err("page21 reloc: buffer too short".to_string());
                    }
                    let insn = read_u32_le(&merged.data, off).unwrap_or(0);
                    let addend = decode_arm64_adrp_addend(insn) + extra_addend;
                    let target = add_signed_u64(base_runtime, addend);
                    let target_page = (target & !0xfff) as i128;
                    let place_page = (place_runtime & !0xfff) as i128;
                    let delta_pages = (target_page - place_page) >> 12;
                    if !(-(1i128 << 20)..(1i128 << 20)).contains(&delta_pages) {
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
                RelocKind::Arm64PageOff12
                | RelocKind::Arm64TlvpPageOff12
                | RelocKind::Arm64GotLoadPageOff12 => {
                    if merged.data.len() < off + 4 {
                        return Err("pageoff12 reloc: buffer too short".to_string());
                    }
                    let insn = read_u32_le(&merged.data, off).unwrap_or(0);
                    let insn_addend = decode_arm64_pageoff_addend(insn) as i64;
                    let addend = insn_addend + extra_addend;
                    let target = add_signed_u64(base_runtime, addend);
                    let pageoff = (target & 0x0fff) as u32;
                    let patched = if kind == RelocKind::Arm64TlvpPageOff12
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
                RelocKind::Addend => {}
                RelocKind::X86Pcrel { adjust, .. } => {
                    if merged.data.len() < off + 4 {
                        return Err("x86_64 pc-relative reloc: buffer too short".to_string());
                    }
                    let addend = read_u32_le(&merged.data, off).unwrap_or(0) as i32 as i128;
                    let target = base_runtime as i128 + addend;
                    let disp = target - (place_runtime as i128 + 4 + adjust as i128);
                    let disp = i32::try_from(disp).map_err(|_| {
                        format!(
                            "x86_64 pc-relative reloc out of range: target=0x{:x} place=0x{:x}",
                            target, place_runtime
                        )
                    })?;
                    write_u32_le(&mut merged.data, off, disp as u32);
                }
            }
        }

        if is_thread_vars_section(&merged.name) {
            clear_tlv_descriptor_keys(&mut merged.data);
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
    let mut rebase_addrs: HashSet<u64> = HashSet::default();
    apply_macho_relocations(
        &obj,
        arch,
        &mut layout,
        &symbol_addrs,
        &symbol_addr_by_idx,
        None,
        None,
        &[],
        VM_ADDR_BIAS,
        VM_ADDR_BIAS,
        Some(&mut rebase_addrs),
        None,
    )?;

    let e_machine = arch.to_elf_machine();
    let dynamic = (!rebase_addrs.is_empty()).then(|| {
        let mut macho_rebase_addrs: Vec<u64> = rebase_addrs.into_iter().collect();
        macho_rebase_addrs.sort_unstable();
        DynamicLinkInfo {
            pie: false,
            shared: false,
            needed: vec!["libSystem.B.dylib".into()],
            plt_symbols: Vec::new(),
            weak_plt_symbols: Vec::new(),
            interpreter: None,
            macho_rebase_addrs,
            macho_direct_binds: Vec::new(),
        }
    });

    Ok(LinkResult {
        symbols: Vec::new(),
        layout,
        e_machine,
        symbol_addrs,
        dynamic,
    })
}

pub fn link_macho_multi_object(
    datas: &[&[u8]],
    libs: Option<&[String]>,
    dylib_paths: &[PathBuf],
    _input_paths: &[PathBuf],
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

    let mut global_symbols: HashMap<String, u64> = HashMap::default();
    let mut global_symbol_weak: HashMap<String, bool> = HashMap::default();
    for (obj_idx, obj) in objects.iter().enumerate() {
        let contrib = &section_contribs[obj_idx];
        let mut vaddr_by_sect: HashMap<u8, u64> = HashMap::default();
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
    let mut undefined_set: HashSet<String> = HashSet::default();
    let mut weak_undefined: HashSet<String> = HashSet::default();
    let mut got_symbols: Vec<String> = Vec::new();
    let mut got_symbol_set: HashSet<String> = HashSet::default();
    let mut got_import_weak: HashMap<String, bool> = HashMap::default();
    let mut rebase_addrs: HashSet<u64> = HashSet::default();
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
                entsize: 0,
                sh_type: 1,
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
                entsize: 0,
                sh_type: 1,
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
                entsize: 0,
                sh_type: 1,
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

    if arch == TargetArch::X86_64 {
        for obj in &objects {
            for sec in &obj.sections {
                if sec.nreloc == 0 {
                    continue;
                }
                let merged_name = merged_section_name_for_lookup(&sec.segname, &sec.sectname);
                if !layout.section_by_name.contains_key(&merged_name) {
                    continue;
                }
                for r in parse_macho_relocs(&obj.data, sec.reloff, sec.nreloc) {
                    let kind = decode_reloc_kind(arch, &r)?;
                    if !matches!(
                        kind,
                        RelocKind::X86Pcrel {
                            through_got: true,
                            ..
                        }
                    ) {
                        continue;
                    }
                    let sym = obj
                        .symbols
                        .get(r.r_symbolnum as usize)
                        .filter(|_| r.r_extern)
                        .ok_or_else(|| {
                            format!(
                                "x86_64 GOT reference at offset 0x{:x} has no external symbol",
                                r.r_address
                            )
                        })?;
                    let name = sym.name.clone();
                    if !global_symbols.contains_key(&name) {
                        if sym.is_defined {
                            return Err(format!(
                                "x86_64 GOT reference to {} is defined in an object but not exported, which is not supported",
                                name
                            ));
                        }
                        got_import_weak.insert(name.clone(), sym.is_weak_ref);
                    }
                    if got_symbol_set.insert(name.clone()) {
                        got_symbols.push(name);
                    }
                }
            }
        }
        if !got_symbols.is_empty() {
            let last = layout.sections.last().ok_or("no sections")?;
            let got_vaddr = align_up_bytes(last.vaddr + last.data.len() as u64, 0x8000);
            layout.sections.push(MergedSection {
                entsize: 0,
                sh_type: 1,
                name: "__got".into(),
                data: vec![0u8; got_symbols.len() * 8],
                vaddr: got_vaddr,
                flags: 2,
                align: 8,
            });
            layout
                .section_by_name
                .insert("__got".into(), layout.sections.len() - 1);
            for (i, name) in got_symbols.iter().enumerate() {
                if let Some(&weak) = got_import_weak.get(name) {
                    direct_binds.push((got_vaddr + (i as u64) * 8, name.clone(), weak, 0));
                }
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
                    rebase_addrs.insert(got_base + slot_off as u64);
                    if trace_relocs && sym.contains("thread7current2id2ID") {
                        log::debug!(
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
        HashMap::default()
    };

    for (obj_idx, obj) in objects.iter().enumerate() {
        let contrib = &section_contribs[obj_idx];
        let symbol_addrs = symbol_addr_by_index_multi(obj, &layout, &global_symbols, contrib);
        let offset_map = section_offset_from_contrib(contrib);
        apply_macho_relocations(
            obj,
            arch,
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

    let dynamic = if layout.section_by_name.contains_key("__got")
        || !direct_binds.is_empty()
        || !rebase_addrs.is_empty()
    {
        let plt_symbols = undefined;
        if std::env::var("WELD_TRACE_UNDEF").ok().as_deref() == Some("1") {
            let tlv_bootstrap_count = plt_symbols
                .iter()
                .filter(|s| s.as_str() == "__tlv_bootstrap")
                .count();
            log::debug!(
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
            log::debug!("direct_binds: {}", direct_binds.len());
            for (addr, sym, weak, addend) in direct_binds.iter().take(32) {
                log::debug!(
                    "  bind addr=0x{:x} sym={} weak={} addend={}",
                    addr,
                    sym,
                    weak,
                    addend
                );
            }
        }
        let mut needed = vec!["libSystem.B.dylib".into()];
        for p in dylib_paths {
            if let Some(s) = p.to_str() {
                needed.push(s.to_string());
            }
        }
        Some(DynamicLinkInfo {
            pie: false,
            shared: false,
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
        symbols: Vec::new(),
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
) -> Result<StubTriple, String> {
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
    let mut vaddr_by_sect: HashMap<u8, u64> = HashMap::default();
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
        (0..objects.len()).map(|_| HashMap::default()).collect();
    let mut merged_data: HashMap<String, Vec<(Vec<u8>, u64)>> = HashMap::default();
    let mut section_cumul: HashMap<String, u64> = HashMap::default();
    let mut section_aligns: HashMap<String, u64> = HashMap::default();
    let mut section_flags: HashMap<String, u64> = HashMap::default();

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
                    elements: Vec::new(),
                    offset_in_merged,
                    size,
                },
            );
        }
    }

    if section_cumul
        .keys()
        .any(|name| name.starts_with("__DATA_DIRTY.__thread_"))
    {
        return Err("thread-local sections in __DATA_DIRTY are not supported".to_string());
    }
    let thread_data = "__DATA.__thread_data".to_string();
    let bss_align = section_aligns.get("__DATA.__thread_bss").copied();
    let data_len = section_cumul.get(&thread_data).copied();
    if let (Some(bss_align), Some(data_len)) = (bss_align, data_len) {
        let padded = align_up(data_len, bss_align);
        if padded > data_len {
            let pad = (padded - data_len) as usize;
            merged_data
                .entry(thread_data.clone())
                .or_default()
                .push((vec![0u8; pad], pad as u64));
            section_cumul.insert(thread_data.clone(), padded);
        }
        let data_align = section_aligns.entry(thread_data).or_insert(0);
        *data_align = (*data_align).max(bss_align);
    }

    let mut layout = MergedLayout {
        sections: Vec::new(),
        section_by_name: HashMap::default(),
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
            entsize: 0,
            sh_type: 1,
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
            entsize: 0,
            sh_type: 1,
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::macho::Macho64Header;

    fn thread_section(
        segname: &str,
        sectname: &str,
        size: u64,
        align: u32,
        flags: u32,
    ) -> MachoSection {
        MachoSection {
            sectname: sectname.into(),
            segname: segname.into(),
            addr: 0,
            size,
            offset: 0,
            align,
            reloff: 0,
            nreloc: 0,
            flags,
        }
    }

    fn object_with(sections: Vec<MachoSection>, data: Vec<u8>) -> Macho64Object {
        Macho64Object {
            header: Macho64Header {
                cputype: 0x0100_000C,
                filetype: 1,
                ncmds: 0,
                sizeofcmds: 0,
                segments: Vec::new(),
            },
            sections,
            symbols: Vec::new(),
            data,
        }
    }

    #[test]
    fn tlv_descriptor_keeps_its_thunk_and_offset_and_zeroes_its_key() {
        let mut data = vec![0u8; 48];
        for (i, slot) in [(0usize, 0x1111u64), (8, 0x2222), (16, 0x30)]
            .into_iter()
            .chain([(24usize, 0x4444u64), (32, 0x5555), (40, 0x60)])
        {
            data[i..i + 8].copy_from_slice(&slot.to_le_bytes());
        }
        clear_tlv_descriptor_keys(&mut data);
        let at = |o: usize| u64::from_le_bytes(data[o..o + 8].try_into().unwrap());
        assert_eq!(at(0), 0x1111, "thunk must survive for the bind");
        assert_eq!(at(8), 0, "dyld fills the key, so the image carries zero");
        assert_eq!(at(16), 0x30, "offset is what the relocation wrote");
        assert_eq!(at(24), 0x4444);
        assert_eq!(at(32), 0);
        assert_eq!(at(40), 0x60);
    }

    #[test]
    fn thread_bss_starts_where_thread_data_ends() {
        let obj = object_with(
            vec![
                thread_section("__DATA", "__thread_data", 5, 3, 0x11),
                thread_section("__DATA", "__thread_bss", 4, 4, 0x12),
            ],
            vec![0xAB; 5],
        );
        let (layout, _) = merge_macho_sections_multi(&[obj]).expect("merges");
        let data = &layout.sections[layout.section_by_name["__DATA.__thread_data"]];
        let bss = &layout.sections[layout.section_by_name["__DATA.__thread_bss"]];
        assert_eq!(&data.data[..5], &[0xAB; 5]);
        assert_eq!(data.data.len(), 16);
        assert_eq!(bss.vaddr, data.vaddr + 16);
        assert_eq!(bss.vaddr % 16, 0);
        assert_eq!(data.vaddr % 16, 0);
        assert_eq!(bss.data.len(), 4);
    }

    #[test]
    fn thread_data_in_dirty_segment_is_error() {
        let obj = object_with(
            vec![thread_section("__DATA_DIRTY", "__thread_data", 4, 3, 0x11)],
            vec![0; 4],
        );
        assert!(merge_macho_sections_multi(&[obj]).is_err());
    }

    pub(crate) const X86_64_CPU: u32 = 0x0100_0007;
    const RELOC_SIGNED_4: u32 = 8;

    pub(crate) struct TestReloc {
        address: u32,
        symbolnum: u32,
        pcrel: bool,
        length: u32,
        external: bool,
        rtype: u32,
    }

    pub(crate) struct TestSection {
        segname: &'static str,
        sectname: &'static str,
        data: Vec<u8>,
        relocs: Vec<TestReloc>,
    }

    pub(crate) struct TestSymbol {
        name: &'static str,
        sect: u8,
        value: u64,
        external: bool,
    }

    pub(crate) fn reloc(
        address: u32,
        symbolnum: u32,
        pcrel: bool,
        length: u32,
        external: bool,
        rtype: u32,
    ) -> TestReloc {
        TestReloc {
            address,
            symbolnum,
            pcrel,
            length,
            external,
            rtype,
        }
    }

    pub(crate) fn macho_object(
        cputype: u32,
        sections: &[TestSection],
        symbols: &[TestSymbol],
    ) -> Vec<u8> {
        let seg_cmd_size = 72 + 80 * sections.len();
        let mut out = vec![0u8; 32 + seg_cmd_size + 24];
        let mut data_offsets = Vec::new();
        for sec in sections {
            data_offsets.push(out.len());
            out.extend_from_slice(&sec.data);
        }
        let mut reloc_offsets = Vec::new();
        for sec in sections {
            reloc_offsets.push(out.len());
            for r in &sec.relocs {
                let info = (r.symbolnum & 0x00ff_ffff)
                    | ((r.pcrel as u32) << 24)
                    | (r.length << 25)
                    | ((r.external as u32) << 27)
                    | (r.rtype << 28);
                out.extend_from_slice(&r.address.to_le_bytes());
                out.extend_from_slice(&info.to_le_bytes());
            }
        }
        let symoff = out.len();
        let mut strtab = vec![0u8];
        for s in symbols {
            let strx = strtab.len() as u32;
            strtab.extend_from_slice(s.name.as_bytes());
            strtab.push(0);
            let n_type = (if s.sect == 0 { 0 } else { 0x0e }) | s.external as u8;
            out.extend_from_slice(&strx.to_le_bytes());
            out.push(n_type);
            out.push(s.sect);
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&s.value.to_le_bytes());
        }
        let stroff = out.len();
        out.extend_from_slice(&strtab);

        let mut hdr = Vec::new();
        hdr.extend_from_slice(&0xFEEDFACFu32.to_le_bytes());
        hdr.extend_from_slice(&cputype.to_le_bytes());
        hdr.extend_from_slice(&3u32.to_le_bytes());
        hdr.extend_from_slice(&1u32.to_le_bytes());
        hdr.extend_from_slice(&2u32.to_le_bytes());
        hdr.extend_from_slice(&((seg_cmd_size + 24) as u32).to_le_bytes());
        hdr.extend_from_slice(&0u32.to_le_bytes());
        hdr.extend_from_slice(&0u32.to_le_bytes());
        out[..32].copy_from_slice(&hdr);

        let mut seg = Vec::new();
        seg.extend_from_slice(&0x19u32.to_le_bytes());
        seg.extend_from_slice(&(seg_cmd_size as u32).to_le_bytes());
        seg.extend_from_slice(&[0u8; 16]);
        seg.extend_from_slice(&[0u8; 32]);
        seg.extend_from_slice(&7u32.to_le_bytes());
        seg.extend_from_slice(&7u32.to_le_bytes());
        seg.extend_from_slice(&(sections.len() as u32).to_le_bytes());
        seg.extend_from_slice(&0u32.to_le_bytes());
        for (i, sec) in sections.iter().enumerate() {
            let mut sh = Vec::new();
            let mut sectname = [0u8; 16];
            sectname[..sec.sectname.len()].copy_from_slice(sec.sectname.as_bytes());
            let mut segname = [0u8; 16];
            segname[..sec.segname.len()].copy_from_slice(sec.segname.as_bytes());
            sh.extend_from_slice(&sectname);
            sh.extend_from_slice(&segname);
            sh.extend_from_slice(&0u64.to_le_bytes());
            sh.extend_from_slice(&(sec.data.len() as u64).to_le_bytes());
            sh.extend_from_slice(&(data_offsets[i] as u32).to_le_bytes());
            sh.extend_from_slice(&4u32.to_le_bytes());
            sh.extend_from_slice(&(reloc_offsets[i] as u32).to_le_bytes());
            sh.extend_from_slice(&(sec.relocs.len() as u32).to_le_bytes());
            sh.extend_from_slice(&0u32.to_le_bytes());
            sh.extend_from_slice(&[0u8; 12]);
            seg.extend_from_slice(&sh);
        }
        out[32..32 + seg_cmd_size].copy_from_slice(&seg);

        let mut symtab = Vec::new();
        symtab.extend_from_slice(&2u32.to_le_bytes());
        symtab.extend_from_slice(&24u32.to_le_bytes());
        symtab.extend_from_slice(&(symoff as u32).to_le_bytes());
        symtab.extend_from_slice(&(symbols.len() as u32).to_le_bytes());
        symtab.extend_from_slice(&(stroff as u32).to_le_bytes());
        symtab.extend_from_slice(&(strtab.len() as u32).to_le_bytes());
        let at = 32 + seg_cmd_size;
        out[at..at + 24].copy_from_slice(&symtab);
        out
    }

    pub(crate) fn text(data: Vec<u8>, relocs: Vec<TestReloc>) -> TestSection {
        TestSection {
            segname: "__TEXT",
            sectname: "__text",
            data,
            relocs,
        }
    }

    pub(crate) fn data_sect(data: Vec<u8>) -> TestSection {
        TestSection {
            segname: "__DATA",
            sectname: "__data",
            data,
            relocs: Vec::new(),
        }
    }

    pub(crate) fn defined(name: &'static str, sect: u8, value: u64) -> TestSymbol {
        TestSymbol {
            name,
            sect,
            value,
            external: true,
        }
    }

    pub(crate) fn undefined(name: &'static str) -> TestSymbol {
        TestSymbol {
            name,
            sect: 0,
            value: 0,
            external: true,
        }
    }

    fn i32_at(data: &[u8], off: usize) -> i64 {
        i32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as i64
    }

    fn text_bytes(layout: &MergedLayout) -> (&[u8], u64) {
        let sec = &layout.sections[layout.section_by_name[".text"]];
        (&sec.data, sec.vaddr)
    }

    pub(crate) fn link_pair(a: Vec<u8>, b: Vec<u8>) -> Result<LinkResult, String> {
        link_macho_multi_object(&[a.as_slice(), b.as_slice()], None, &[], &[])
    }

    #[test]
    fn x86_branch_to_symbol_in_other_object_patches_rel32() {
        let caller = macho_object(
            X86_64_CPU,
            &[text(
                vec![0x90, 0x90, 0x90, 0x90, 0xE8, 0, 0, 0, 0, 0xC3],
                vec![reloc(5, 0, true, 2, true, X86_64_RELOC_BRANCH)],
            )],
            &[undefined("_callee")],
        );
        let callee = macho_object(
            X86_64_CPU,
            &[text(vec![0xC3], Vec::new())],
            &[defined("_callee", 1, 0)],
        );
        let result = link_pair(caller, callee).expect("links");
        let (bytes, text_vaddr) = text_bytes(&result.layout);
        assert_eq!(bytes[4], 0xE8);
        let target = result.symbol_addrs["_callee"];
        let place = text_vaddr + 5;
        assert_eq!(i32_at(bytes, 5), target as i64 - (place as i64 + 4));
    }

    #[test]
    fn x86_branch_in_single_object_patches_rel32() {
        let obj = macho_object(
            X86_64_CPU,
            &[text(
                vec![0xE8, 0, 0, 0, 0, 0xC3, 0xC3, 0xC3],
                vec![reloc(1, 0, true, 2, true, X86_64_RELOC_BRANCH)],
            )],
            &[defined("_self", 1, 6)],
        );
        let result = link_macho_single_object(&obj).expect("links");
        let (bytes, text_vaddr) = text_bytes(&result.layout);
        assert_eq!(
            i32_at(bytes, 1),
            (text_vaddr as i64 + 6) - (text_vaddr as i64 + 1 + 4)
        );
    }

    #[test]
    fn x86_signed_4_skips_the_trailing_immediate() {
        let user = macho_object(
            X86_64_CPU,
            &[text(
                vec![0xC7, 0x05, 0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44],
                vec![reloc(2, 0, true, 2, true, RELOC_SIGNED_4)],
            )],
            &[undefined("_var")],
        );
        let home = macho_object(
            X86_64_CPU,
            &[data_sect(vec![0; 8])],
            &[defined("_var", 1, 0)],
        );
        let result = link_pair(user, home).expect("links");
        let (bytes, text_vaddr) = text_bytes(&result.layout);
        let (text_shift, data_shift) = compute_runtime_shifts(&result.layout);
        let target = result.symbol_addrs["_var"] + data_shift;
        let place = text_vaddr + text_shift + 2;
        assert_eq!(i32_at(bytes, 2), target as i64 - (place as i64 + 4 + 4));
        assert_eq!(
            &bytes[6..10],
            &[0x11, 0x22, 0x33, 0x44],
            "immediate is untouched"
        );
    }

    #[test]
    fn x86_signed_non_extern_resolves_against_section_base() {
        let obj = macho_object(
            X86_64_CPU,
            &[text(
                vec![8, 0, 0, 0, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3],
                vec![reloc(0, 1, true, 2, false, X86_64_RELOC_SIGNED)],
            )],
            &[],
        );
        let result = link_macho_single_object(&obj).expect("links");
        let (bytes, text_vaddr) = text_bytes(&result.layout);
        assert_eq!(
            i32_at(bytes, 0),
            (text_vaddr as i64 + 8) - (text_vaddr as i64 + 4)
        );
    }

    #[test]
    fn x86_got_load_points_at_a_prefilled_slot() {
        let user = macho_object(
            X86_64_CPU,
            &[text(
                vec![0x48, 0x8B, 0x05, 0, 0, 0, 0, 0xC3],
                vec![reloc(3, 0, true, 2, true, X86_64_RELOC_GOT_LOAD)],
            )],
            &[undefined("_var")],
        );
        let home = macho_object(
            X86_64_CPU,
            &[data_sect(vec![0x2A; 8])],
            &[defined("_var", 1, 0)],
        );
        let result = link_pair(user, home).expect("links");
        let (bytes, text_vaddr) = text_bytes(&result.layout);
        let got = &result.layout.sections[result.layout.section_by_name["__got"]];
        let slot = got.vaddr;
        let (text_shift, data_shift) = compute_runtime_shifts(&result.layout);
        let var = result.symbol_addrs["_var"];
        assert_eq!(
            u64::from_le_bytes(got.data[..8].try_into().unwrap()),
            var + data_shift
        );
        let slot_runtime = slot + data_shift;
        let place = text_vaddr + text_shift + 3;
        assert_eq!(i32_at(bytes, 3), slot_runtime as i64 - (place as i64 + 4));
        let dynamic = result.dynamic.expect("got needs dynamic info");
        assert!(dynamic.macho_rebase_addrs.contains(&slot));
    }

    #[test]
    fn absolute_data_pointer_is_recorded_for_rebase() {
        let obj = macho_object(
            X86_64_CPU,
            &[
                text(vec![0xC3], Vec::new()),
                TestSection {
                    segname: "__DATA",
                    sectname: "__data",
                    data: vec![0; 16],
                    relocs: vec![reloc(8, 0, false, 3, true, 0)],
                },
            ],
            &[defined("_target", 1, 0)],
        );
        let result = link_macho_single_object(&obj).expect("links");
        let data = result
            .layout
            .sections
            .iter()
            .find(|s| s.data.len() == 16)
            .expect("data section");
        let dynamic = result.dynamic.expect("a pointer needs rebase info");
        assert_eq!(dynamic.macho_rebase_addrs, vec![data.vaddr + 8]);
    }

    #[test]
    fn absolute_pointer_in_text_is_refused_naming_symbol() {
        let obj = macho_object(
            X86_64_CPU,
            &[text(vec![0; 16], vec![reloc(8, 0, false, 3, true, 0)])],
            &[defined("_here", 1, 0)],
        );
        let err = link_macho_single_object(&obj).expect_err("text cannot be rebased");
        assert!(err.contains("_here"), "{err}");
        assert!(err.contains("cannot be rebased"), "{err}");
    }

    #[test]
    fn x86_got_to_undefined_symbol_gets_a_bound_slot() {
        let user = macho_object(
            X86_64_CPU,
            &[text(
                vec![0x48, 0x8B, 0x05, 0, 0, 0, 0, 0xC3],
                vec![reloc(3, 0, true, 2, true, X86_64_RELOC_GOT_LOAD)],
            )],
            &[undefined("_ext")],
        );
        let home = macho_object(
            X86_64_CPU,
            &[text(vec![0xC3], Vec::new())],
            &[defined("_home", 1, 0)],
        );
        let result = link_pair(user, home).expect("links");
        let (bytes, text_vaddr) = text_bytes(&result.layout);
        let got = &result.layout.sections[result.layout.section_by_name["__got"]];
        assert_eq!(got.data, vec![0u8; 8]);
        let (text_shift, data_shift) = compute_runtime_shifts(&result.layout);
        let place = text_vaddr + text_shift + 3;
        let slot_runtime = got.vaddr + data_shift;
        assert_eq!(i32_at(bytes, 3), slot_runtime as i64 - (place as i64 + 4));
        let dynamic = result.dynamic.expect("an import needs bind info");
        assert_eq!(
            dynamic.macho_direct_binds,
            vec![(got.vaddr, "_ext".to_string(), false, 0)]
        );
        assert!(!dynamic.macho_rebase_addrs.contains(&got.vaddr));
    }

    #[test]
    fn x86_got_to_defined_unexported_symbol_is_error_naming_symbol() {
        let user = macho_object(
            X86_64_CPU,
            &[text(
                vec![0x48, 0x8B, 0x05, 0, 0, 0, 0, 0xC3],
                vec![reloc(3, 0, true, 2, true, X86_64_RELOC_GOT_LOAD)],
            )],
            &[TestSymbol {
                name: "_local",
                sect: 1,
                value: 0,
                external: false,
            }],
        );
        let home = macho_object(
            X86_64_CPU,
            &[text(vec![0xC3], Vec::new())],
            &[defined("_home", 1, 0)],
        );
        let Err(err) = link_pair(user, home) else {
            panic!("must fail")
        };
        assert!(err.contains("_local"), "{err}");
    }

    #[test]
    fn x86_branch_to_undefined_symbol_is_error() {
        let obj = macho_object(
            X86_64_CPU,
            &[text(
                vec![0xE8, 0, 0, 0, 0, 0xC3],
                vec![reloc(1, 0, true, 2, true, X86_64_RELOC_BRANCH)],
            )],
            &[undefined("_printf")],
        );
        let Err(err) = link_macho_single_object(&obj) else {
            panic!("must fail")
        };
        assert!(err.contains("undefined symbol"), "{err}");
    }

    #[test]
    fn x86_relocation_types_without_support_are_errors() {
        let cases = [
            (X86_64_RELOC_SUBTRACTOR, 2, false, "SUBTRACTOR"),
            (X86_64_RELOC_TLV, 2, true, "TLV"),
            (12, 2, true, "unsupported x86_64"),
            (X86_64_RELOC_SIGNED, 2, false, "32-bit pc-relative"),
            (0, 2, false, "64-bit absolute"),
        ];
        for (rtype, length, pcrel, want) in cases {
            let obj = macho_object(
                X86_64_CPU,
                &[text(
                    vec![0; 8],
                    vec![reloc(0, 0, pcrel, length, true, rtype)],
                )],
                &[defined("_s", 1, 0)],
            );
            let err = link_macho_single_object(&obj)
                .err()
                .unwrap_or_else(|| panic!("type {rtype} must be refused"));
            assert!(err.contains(want), "type {rtype}: {err}");
        }
    }

    #[test]
    fn arm64_subtractor_is_still_refused_by_its_own_type() {
        let Err(err) = decode_reloc_kind(
            TargetArch::AArch64,
            &MachoReloc {
                r_address: 0,
                r_symbolnum: 0,
                r_pcrel: false,
                r_length: 3,
                r_extern: true,
                r_type: 1,
            },
        ) else {
            panic!("arm64 type 1 is unsupported")
        };
        assert_eq!(err, "unsupported Mach-O relocation type 1");
    }

    #[test]
    fn x86_relocation_types_decode_to_their_own_kinds() {
        let rel = |rtype: u32, pcrel: bool, length: u32| MachoReloc {
            r_address: 0,
            r_symbolnum: 0,
            r_pcrel: pcrel,
            r_length: length,
            r_extern: true,
            r_type: rtype,
        };
        let decode = |r: MachoReloc| decode_reloc_kind(TargetArch::X86_64, &r);
        assert_eq!(decode(rel(0, false, 3)), Ok(RelocKind::Generic));
        assert_eq!(
            decode(rel(2, true, 2)),
            Ok(RelocKind::X86Pcrel {
                adjust: 0,
                through_got: false
            })
        );
        assert_eq!(
            decode(rel(1, true, 2)),
            Ok(RelocKind::X86Pcrel {
                adjust: 0,
                through_got: false
            })
        );
        assert_eq!(
            decode(rel(3, true, 2)),
            Ok(RelocKind::X86Pcrel {
                adjust: 0,
                through_got: true
            })
        );
        assert_eq!(
            decode(rel(4, true, 2)),
            Ok(RelocKind::X86Pcrel {
                adjust: 0,
                through_got: true
            })
        );
        assert_eq!(
            decode(rel(6, true, 2)),
            Ok(RelocKind::X86Pcrel {
                adjust: 1,
                through_got: false
            })
        );
        assert_eq!(
            decode(rel(7, true, 2)),
            Ok(RelocKind::X86Pcrel {
                adjust: 2,
                through_got: false
            })
        );
        assert_eq!(
            decode(rel(8, true, 2)),
            Ok(RelocKind::X86Pcrel {
                adjust: 4,
                through_got: false
            })
        );
        assert!(decode(rel(5, false, 3)).is_err());
        assert!(decode(rel(9, true, 2)).is_err());
        assert!(decode(rel(12, true, 2)).is_err());
        assert!(decode(rel(0, true, 3)).is_err());
        assert!(decode(rel(2, false, 2)).is_err());
    }
}
