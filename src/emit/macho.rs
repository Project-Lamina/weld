//! Mach-O 64 executable emission for macOS.
//!
//! Emits MH_EXECUTABLE with __TEXT, LC_MAIN, LC_LOAD_DYLINKER, LC_LOAD_DYLIB.

#![allow(dead_code)]

use crate::arch::TargetArch;
use crate::link::{DynamicLinkInfo, MergedLayout, MergedSection};
use crate::segment::{align_up_usize, build_segment_buffer};
use std::collections::HashMap;
use std::io::Write;

const MH_MAGIC_64: u32 = 0xFEEDFACF;
const MH_EXECUTABLE: u32 = 2;
const CPU_TYPE_X86_64: u32 = 0x01000007;
const CPU_TYPE_ARM64: u32 = 0x0100000C;
const LC_SEGMENT_64: u32 = 0x19;
const LC_MAIN: u32 = 0x80000028;
const LC_LOAD_DYLINKER: u32 = 0x0E;
const LC_LOAD_DYLIB: u32 = 0x0C;
const LC_DYLD_INFO_ONLY: u32 = 0x22;
const VM_PROT_READ: u32 = 1;
const VM_PROT_WRITE: u32 = 2;
const VM_PROT_EXECUTE: u32 = 4;

const PAGE_SIZE: usize = 4096;
const SEG_BASE: u64 = 0x100000000;

fn write_u32(w: &mut impl Write, val: u32) -> std::io::Result<()> {
    w.write_all(&val.to_le_bytes())
}

fn write_u64(w: &mut impl Write, val: u64) -> std::io::Result<()> {
    w.write_all(&val.to_le_bytes())
}

fn pad_segname(name: &str) -> [u8; 16] {
    let mut buf = [0u8; 16];
    let len = name.len().min(16);
    buf[..len].copy_from_slice(&name.as_bytes()[..len]);
    buf
}

pub fn emit_macho_executable(
    layout: &MergedLayout,
    arch: TargetArch,
    entry: u64,
    out: &mut impl Write,
) -> std::io::Result<()> {
    let (base, seg_buffer) = build_segment_buffer(layout, 0x100000000);
    let text_size = seg_buffer.len();
    let text_size_aligned = align_up_usize(text_size, PAGE_SIZE);

    let cputype = arch.to_macho_cputype();
    if cputype == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "RISC-V not supported for Mach-O",
        ));
    }

    let mut total_cmds = 0u32;
    let mut sizeofcmds = 0u32;

    let mut lc_buf = Vec::new();

    let mut lc_pagezero = [0u8; 72];
    lc_pagezero[0..4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
    lc_pagezero[4..8].copy_from_slice(&72u32.to_le_bytes());
    lc_pagezero[8..24].copy_from_slice(&pad_segname("__PAGEZERO"));
    lc_pagezero[24..32].copy_from_slice(&0u64.to_le_bytes());
    lc_pagezero[32..40].copy_from_slice(&0x100000000u64.to_le_bytes());
    lc_buf.extend_from_slice(&lc_pagezero);
    total_cmds += 1;
    sizeofcmds += 72;

    let data_file_off = PAGE_SIZE as u64;
    const SECT64_SIZE: usize = 80;
    let seg_total_size = 72 + SECT64_SIZE;
    let mut seg_cmd = vec![0u8; seg_total_size];
    seg_cmd[0..4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
    seg_cmd[4..8].copy_from_slice(&(seg_total_size as u32).to_le_bytes());
    const SEG_VMADDR: u64 = 0x100000000;
    seg_cmd[8..24].copy_from_slice(&pad_segname("__TEXT"));
    seg_cmd[24..32].copy_from_slice(&SEG_VMADDR.to_le_bytes());
    seg_cmd[32..40].copy_from_slice(&(text_size_aligned as u64).to_le_bytes());
    seg_cmd[40..48].copy_from_slice(&data_file_off.to_le_bytes());
    seg_cmd[48..56].copy_from_slice(&(text_size as u64).to_le_bytes());
    seg_cmd[56..60].copy_from_slice(&(VM_PROT_READ | VM_PROT_EXECUTE).to_le_bytes());
    seg_cmd[60..64].copy_from_slice(&(VM_PROT_READ | VM_PROT_EXECUTE).to_le_bytes());
    seg_cmd[64..68].copy_from_slice(&1u32.to_le_bytes());
    seg_cmd[68..72].copy_from_slice(&0u32.to_le_bytes());

    seg_cmd[72..88].copy_from_slice(&pad_segname("__text"));
    seg_cmd[88..104].copy_from_slice(&pad_segname("__TEXT"));
    seg_cmd[104..112].copy_from_slice(&SEG_VMADDR.to_le_bytes());
    seg_cmd[112..120].copy_from_slice(&(text_size as u64).to_le_bytes());
    seg_cmd[120..124].copy_from_slice(&(PAGE_SIZE as u32).to_le_bytes());
    seg_cmd[124..128].copy_from_slice(&4u32.to_le_bytes());
    seg_cmd[128..132].copy_from_slice(&0u32.to_le_bytes());
    seg_cmd[132..136].copy_from_slice(&0u32.to_le_bytes());
    seg_cmd[136..140].copy_from_slice(&0x80000400u32.to_le_bytes());
    seg_cmd[140..144].copy_from_slice(&0u32.to_le_bytes());
    seg_cmd[144..148].copy_from_slice(&0u32.to_le_bytes());

    lc_buf.extend_from_slice(&seg_cmd);
    total_cmds += 1;
    sizeofcmds += seg_total_size as u32;

    let entry_offset = entry.saturating_sub(base);
    let mut lc_main = vec![0u8; 24];
    lc_main[0..4].copy_from_slice(&LC_MAIN.to_le_bytes());
    lc_main[4..8].copy_from_slice(&24u32.to_le_bytes());
    lc_main[8..16].copy_from_slice(&entry_offset.to_le_bytes());
    lc_main[16..24].copy_from_slice(&0u64.to_le_bytes());
    lc_buf.extend_from_slice(&lc_main);
    total_cmds += 1;
    sizeofcmds += 24;

    let dyld_path = "/usr/lib/dyld\0";
    let dyld_len = dyld_path.len();
    let dyld_cmd_size = align_up_usize(24 + dyld_len, 8);
    let mut lc_dyld = vec![0u8; dyld_cmd_size];
    lc_dyld[0..4].copy_from_slice(&LC_LOAD_DYLINKER.to_le_bytes());
    lc_dyld[4..8].copy_from_slice(&(dyld_cmd_size as u32).to_le_bytes());
    lc_dyld[8..12].copy_from_slice(&24u32.to_le_bytes());
    lc_dyld[12..16].copy_from_slice(&0u32.to_le_bytes());
    lc_dyld[16..20].copy_from_slice(&0u32.to_le_bytes());
    lc_dyld[20..24].copy_from_slice(&0u32.to_le_bytes());
    lc_dyld[24..24 + dyld_len - 1].copy_from_slice(&dyld_path.as_bytes()[..dyld_len - 1]);
    lc_buf.extend_from_slice(&lc_dyld);
    total_cmds += 1;
    sizeofcmds += dyld_cmd_size as u32;

    let lib_path = "/usr/lib/libSystem.B.dylib\0";
    let lib_len = lib_path.len();
    let lib_cmd_size = align_up_usize(24 + lib_len, 8);
    let mut lc_lib = vec![0u8; lib_cmd_size];
    lc_lib[0..4].copy_from_slice(&LC_LOAD_DYLIB.to_le_bytes());
    lc_lib[4..8].copy_from_slice(&(lib_cmd_size as u32).to_le_bytes());
    lc_lib[8..12].copy_from_slice(&24u32.to_le_bytes());
    lc_lib[12..16].copy_from_slice(&0u32.to_le_bytes());
    lc_lib[16..20].copy_from_slice(&0x10000u32.to_le_bytes());
    lc_lib[20..24].copy_from_slice(&0x10000u32.to_le_bytes());
    lc_lib[24..24 + lib_len - 1].copy_from_slice(&lib_path.as_bytes()[..lib_len - 1]);
    lc_buf.extend_from_slice(&lc_lib);
    total_cmds += 1;
    sizeofcmds += lib_cmd_size as u32;

    let mut hdr = [0u8; 32];
    hdr[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
    hdr[4..8].copy_from_slice(&cputype.to_le_bytes());
    hdr[8..12].copy_from_slice(&0u32.to_le_bytes());
    hdr[12..16].copy_from_slice(&MH_EXECUTABLE.to_le_bytes());
    hdr[16..20].copy_from_slice(&total_cmds.to_le_bytes());
    hdr[20..24].copy_from_slice(&sizeofcmds.to_le_bytes());
    hdr[24..28].copy_from_slice(&0u32.to_le_bytes());
    out.write_all(&hdr)?;

    out.write_all(&lc_buf)?;

    let data_start = align_up_usize(32 + sizeofcmds as usize, PAGE_SIZE);
    let pad = data_start - 32 - sizeofcmds as usize;
    if pad > 0 {
        out.write_all(&vec![0u8; pad])?;
    }

    out.write_all(&seg_buffer)?;

    let trailing = text_size_aligned - text_size;
    if trailing > 0 {
        out.write_all(&vec![0u8; trailing])?;
    }

    Ok(())
}

fn push_uleb128(buf: &mut Vec<u8>, mut val: u64) {
    loop {
        let mut b = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            b |= 0x80;
        }
        buf.push(b);
        if val == 0 {
            break;
        }
    }
}

fn build_rebase_opcodes(
    data_segment_index: u32,
    got_offset: u64,
    got_slot_count: u64,
) -> Vec<u8> {
    const REBASE_TYPE_POINTER: u8 = 1;
    const REBASE_OPCODE_SET_TYPE_IMM: u8 = 0x40;
    const REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x50;
    const REBASE_OPCODE_DO_REBASE_ULEB_TIMES: u8 = 0x20;
    const REBASE_OPCODE_DONE: u8 = 0x80;

    let mut buf = Vec::new();
    buf.push(REBASE_OPCODE_SET_TYPE_IMM | REBASE_TYPE_POINTER);
    buf.push(REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB);
    push_uleb128(&mut buf, data_segment_index as u64);
    push_uleb128(&mut buf, got_offset);
    buf.push(REBASE_OPCODE_DO_REBASE_ULEB_TIMES);
    push_uleb128(&mut buf, got_slot_count);
    buf.push(REBASE_OPCODE_DONE);
    buf
}

fn build_bind_opcodes(
    plt_symbols: &[String],
    data_segment_index: u32,
    got_offset_in_segment: u64,
) -> Vec<u8> {
    const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u8 = 0x00;
    const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x30;
    const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x50;
    const BIND_TYPE_POINTER: u8 = 1;
    const BIND_OPCODE_SET_TYPE_IMM: u8 = 0x40;
    const BIND_OPCODE_DO_BIND: u8 = 0x70;
    const BIND_OPCODE_DONE: u8 = 0x80;

    let mut buf = Vec::new();
    buf.push(BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1);
    for (i, sym) in plt_symbols.iter().enumerate() {
        buf.push(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM);
        buf.extend_from_slice(sym.as_bytes());
        buf.push(0);
        buf.push(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB);
        push_uleb128(&mut buf, data_segment_index as u64);
        push_uleb128(&mut buf, got_offset_in_segment + (i as u64) * 8);
        buf.push(BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER);
        buf.push(BIND_OPCODE_DO_BIND);
    }
    buf.push(BIND_OPCODE_DONE);
    buf
}

pub fn emit_macho_executable_dynamic(
    layout: &MergedLayout,
    arch: TargetArch,
    entry: u64,
    dyn_info: &DynamicLinkInfo,
    out: &mut impl Write,
) -> std::io::Result<()> {
    let text_sections: Vec<&MergedSection> = layout
        .sections
        .iter()
        .filter(|s| s.name != "__got" && s.name != "__data" && s.name != "__bss")
        .collect();
    let data_sections: Vec<&MergedSection> = layout
        .sections
        .iter()
        .filter(|s| s.name == "__got" || s.name == "__data" || s.name == "__bss")
        .collect();

    let text_layout = MergedLayout {
        sections: text_sections.iter().map(|s| (*s).clone()).collect(),
        section_by_name: HashMap::new(),
    };
    let data_layout = MergedLayout {
        sections: data_sections.iter().map(|s| (*s).clone()).collect(),
        section_by_name: HashMap::new(),
    };

    let (text_base, text_buffer) = build_segment_buffer(&text_layout, SEG_BASE);
    let text_size = text_buffer.len();
    let text_size_aligned = align_up_usize(text_size, PAGE_SIZE);

    let (data_base, data_buffer) = build_segment_buffer(&data_layout, SEG_BASE + 0x8000);
    let data_size = data_buffer.len();
    let data_size_aligned = align_up_usize(data_size, PAGE_SIZE);

    let got_section = data_sections.iter().find(|s| s.name == "__got");
    let got_offset_in_segment = got_section
        .map(|s| (s.vaddr - data_base) as u64)
        .unwrap_or(0);
    let got_slot_count = got_section
        .map(|s| s.data.len() / 8)
        .unwrap_or(0) as u64;

    const DATA_SEGMENT_INDEX: u32 = 2;
    let rebase_opcodes =
        build_rebase_opcodes(DATA_SEGMENT_INDEX, got_offset_in_segment, got_slot_count);
    let bind_opcodes = build_bind_opcodes(
        &dyn_info.plt_symbols,
        DATA_SEGMENT_INDEX,
        got_offset_in_segment,
    );

    let cputype = arch.to_macho_cputype();
    if cputype == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "RISC-V not supported for Mach-O",
        ));
    }

    let mut total_cmds = 0u32;
    let mut sizeofcmds = 0u32;
    let mut lc_buf = Vec::new();

    let mut lc_pagezero = [0u8; 72];
    lc_pagezero[0..4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
    lc_pagezero[4..8].copy_from_slice(&72u32.to_le_bytes());
    lc_pagezero[8..24].copy_from_slice(&pad_segname("__PAGEZERO"));
    lc_pagezero[24..32].copy_from_slice(&0u64.to_le_bytes());
    lc_pagezero[32..40].copy_from_slice(&0x100000000u64.to_le_bytes());
    lc_buf.extend_from_slice(&lc_pagezero);
    total_cmds += 1;
    sizeofcmds += 72;

    const SECT64_SIZE: usize = 80;
    let text_seg_size = 72 + SECT64_SIZE * text_sections.len();
    let mut text_seg = vec![0u8; text_seg_size];
    text_seg[0..4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
    text_seg[4..8].copy_from_slice(&(text_seg_size as u32).to_le_bytes());
    text_seg[8..24].copy_from_slice(&pad_segname("__TEXT"));
    text_seg[24..32].copy_from_slice(&text_base.to_le_bytes());
    text_seg[32..40].copy_from_slice(&(text_size_aligned as u64).to_le_bytes());
    text_seg[40..48].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
    text_seg[48..56].copy_from_slice(&(text_size as u64).to_le_bytes());
    text_seg[56..60].copy_from_slice(&(VM_PROT_READ | VM_PROT_EXECUTE).to_le_bytes());
    text_seg[60..64].copy_from_slice(&(VM_PROT_READ | VM_PROT_EXECUTE).to_le_bytes());
    text_seg[64..68].copy_from_slice(&(text_sections.len() as u32).to_le_bytes());
    for (i, sec) in text_sections.iter().enumerate() {
        let sectname = if sec.name == ".text" { "__text" } else { &sec.name };
        let base = 72 + i * SECT64_SIZE;
        let sec_offset_in_segment = (sec.vaddr - text_base) as u64;
        let sec_file_offset = PAGE_SIZE as u64 + sec_offset_in_segment;
        text_seg[base..base + 16].copy_from_slice(&pad_segname(sectname));
        text_seg[base + 16..base + 32].copy_from_slice(&pad_segname("__TEXT"));
        text_seg[base + 32..base + 40].copy_from_slice(&sec.vaddr.to_le_bytes());
        text_seg[base + 40..base + 48].copy_from_slice(&(sec.data.len() as u64).to_le_bytes());
        text_seg[base + 48..base + 56].copy_from_slice(&sec_file_offset.to_le_bytes());
        text_seg[base + 56..base + 60].copy_from_slice(&4u32.to_le_bytes());
        text_seg[base + 60..base + 64].copy_from_slice(&4u32.to_le_bytes());
        text_seg[base + 64..base + 68].copy_from_slice(&0u32.to_le_bytes());
        text_seg[base + 68..base + 72].copy_from_slice(&0u32.to_le_bytes());
        text_seg[base + 72..base + 76].copy_from_slice(&0x80000400u32.to_le_bytes());
    }
    lc_buf.extend_from_slice(&text_seg);
    total_cmds += 1;
    sizeofcmds += text_seg_size as u32;

    let data_file_off = PAGE_SIZE as u64 + text_size_aligned as u64;
    let data_seg_size = 72 + SECT64_SIZE * data_sections.len();
    let mut data_seg = vec![0u8; data_seg_size];
    data_seg[0..4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
    data_seg[4..8].copy_from_slice(&(data_seg_size as u32).to_le_bytes());
    data_seg[8..24].copy_from_slice(&pad_segname("__DATA"));
    data_seg[24..32].copy_from_slice(&data_base.to_le_bytes());
    data_seg[32..40].copy_from_slice(&(data_size_aligned as u64).to_le_bytes());
    data_seg[40..48].copy_from_slice(&data_file_off.to_le_bytes());
    data_seg[48..56].copy_from_slice(&(data_size as u64).to_le_bytes());
    data_seg[56..60].copy_from_slice(&(VM_PROT_READ | VM_PROT_WRITE).to_le_bytes());
    data_seg[60..64].copy_from_slice(&(VM_PROT_READ | VM_PROT_WRITE).to_le_bytes());
    data_seg[64..68].copy_from_slice(&(data_sections.len() as u32).to_le_bytes());
    for (i, sec) in data_sections.iter().enumerate() {
        let sectname = if sec.name == "__got" {
            "__la_symbol_ptr"
        } else {
            &sec.name
        };
        let base = 72 + i * SECT64_SIZE;
        let sec_offset_in_segment = (sec.vaddr - data_base) as u64;
        let sec_file_offset = data_file_off + sec_offset_in_segment;
        data_seg[base..base + 16].copy_from_slice(&pad_segname(sectname));
        data_seg[base + 16..base + 32].copy_from_slice(&pad_segname("__DATA"));
        data_seg[base + 32..base + 40].copy_from_slice(&sec.vaddr.to_le_bytes());
        data_seg[base + 40..base + 48].copy_from_slice(&(sec.data.len() as u64).to_le_bytes());
        data_seg[base + 48..base + 56].copy_from_slice(&sec_file_offset.to_le_bytes());
        data_seg[base + 56..base + 60].copy_from_slice(&8u32.to_le_bytes());
        data_seg[base + 60..base + 64].copy_from_slice(&3u32.to_le_bytes());
        data_seg[base + 64..base + 68].copy_from_slice(&0u32.to_le_bytes());
        data_seg[base + 68..base + 72].copy_from_slice(&0u32.to_le_bytes());
        data_seg[base + 72..base + 76].copy_from_slice(&0x00000100u32.to_le_bytes());
    }
    lc_buf.extend_from_slice(&data_seg);
    total_cmds += 1;
    sizeofcmds += data_seg_size as u32;

    let entry_offset = entry.saturating_sub(text_base);
    let mut lc_main = vec![0u8; 24];
    lc_main[0..4].copy_from_slice(&LC_MAIN.to_le_bytes());
    lc_main[4..8].copy_from_slice(&24u32.to_le_bytes());
    lc_main[8..16].copy_from_slice(&entry_offset.to_le_bytes());
    lc_main[16..24].copy_from_slice(&0u64.to_le_bytes());
    lc_buf.extend_from_slice(&lc_main);
    total_cmds += 1;
    sizeofcmds += 24;

    let dyld_path = "/usr/lib/dyld\0";
    let dyld_len = dyld_path.len();
    let dyld_cmd_size = align_up_usize(24 + dyld_len, 8);
    let mut lc_dyld = vec![0u8; dyld_cmd_size];
    lc_dyld[0..4].copy_from_slice(&LC_LOAD_DYLINKER.to_le_bytes());
    lc_dyld[4..8].copy_from_slice(&(dyld_cmd_size as u32).to_le_bytes());
    lc_dyld[8..12].copy_from_slice(&24u32.to_le_bytes());
    lc_dyld[24..24 + dyld_len - 1].copy_from_slice(&dyld_path.as_bytes()[..dyld_len - 1]);
    lc_buf.extend_from_slice(&lc_dyld);
    total_cmds += 1;
    sizeofcmds += dyld_cmd_size as u32;

    let lib_path = "/usr/lib/libSystem.B.dylib\0";
    let lib_len = lib_path.len();
    let lib_cmd_size = align_up_usize(24 + lib_len, 8);
    let mut lc_lib = vec![0u8; lib_cmd_size];
    lc_lib[0..4].copy_from_slice(&LC_LOAD_DYLIB.to_le_bytes());
    lc_lib[4..8].copy_from_slice(&(lib_cmd_size as u32).to_le_bytes());
    lc_lib[8..12].copy_from_slice(&24u32.to_le_bytes());
    lc_lib[16..20].copy_from_slice(&0x10000u32.to_le_bytes());
    lc_lib[20..24].copy_from_slice(&0x10000u32.to_le_bytes());
    lc_lib[24..24 + lib_len - 1].copy_from_slice(&lib_path.as_bytes()[..lib_len - 1]);
    lc_buf.extend_from_slice(&lc_lib);
    total_cmds += 1;
    sizeofcmds += lib_cmd_size as u32;

    let dyld_info_off = align_up_usize(32 + sizeofcmds as usize, 8);
    let bind_off = dyld_info_off + rebase_opcodes.len();
    let mut lc_dyld_info = vec![0u8; 48];
    lc_dyld_info[0..4].copy_from_slice(&LC_DYLD_INFO_ONLY.to_le_bytes());
    lc_dyld_info[4..8].copy_from_slice(&48u32.to_le_bytes());
    lc_dyld_info[8..12].copy_from_slice(&(dyld_info_off as u32).to_le_bytes());
    lc_dyld_info[12..16].copy_from_slice(&(rebase_opcodes.len() as u32).to_le_bytes());
    lc_dyld_info[16..20].copy_from_slice(&0u32.to_le_bytes());
    lc_dyld_info[20..24].copy_from_slice(&0u32.to_le_bytes());
    lc_dyld_info[24..28].copy_from_slice(&(bind_off as u32).to_le_bytes());
    lc_dyld_info[28..32].copy_from_slice(&(bind_opcodes.len() as u32).to_le_bytes());
    lc_dyld_info[32..36].copy_from_slice(&0u32.to_le_bytes());
    lc_dyld_info[36..40].copy_from_slice(&0u32.to_le_bytes());
    lc_dyld_info[40..44].copy_from_slice(&0u32.to_le_bytes());
    lc_dyld_info[44..48].copy_from_slice(&0u32.to_le_bytes());
    lc_buf.extend_from_slice(&lc_dyld_info);
    total_cmds += 1;
    sizeofcmds += 48;

    let mut hdr = [0u8; 32];
    hdr[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
    hdr[4..8].copy_from_slice(&cputype.to_le_bytes());
    hdr[8..12].copy_from_slice(&0u32.to_le_bytes());
    hdr[12..16].copy_from_slice(&MH_EXECUTABLE.to_le_bytes());
    hdr[16..20].copy_from_slice(&total_cmds.to_le_bytes());
    hdr[20..24].copy_from_slice(&sizeofcmds.to_le_bytes());
    hdr[24..28].copy_from_slice(&0u32.to_le_bytes());
    out.write_all(&hdr)?;
    out.write_all(&lc_buf)?;

    let segment_start = align_up_usize(32 + sizeofcmds as usize, PAGE_SIZE);
    let cmds_end = 32 + sizeofcmds as usize;
    let dyld_pad = dyld_info_off.saturating_sub(cmds_end);
    if dyld_pad > 0 {
        out.write_all(&vec![0u8; dyld_pad])?;
    }
    out.write_all(&rebase_opcodes)?;
    out.write_all(&bind_opcodes)?;
    let after_dyld = dyld_info_off + rebase_opcodes.len() + bind_opcodes.len();
    let seg_pad = segment_start.saturating_sub(after_dyld);
    if seg_pad > 0 {
        out.write_all(&vec![0u8; seg_pad])?;
    }

    out.write_all(&text_buffer)?;
    let text_trailing = text_size_aligned - text_size;
    if text_trailing > 0 {
        out.write_all(&vec![0u8; text_trailing])?;
    }

    out.write_all(&data_buffer)?;
    let data_trailing = data_size_aligned - data_size;
    if data_trailing > 0 {
        out.write_all(&vec![0u8; data_trailing])?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::MergedSection;
    use std::collections::HashMap;

    #[test]
    fn test_emit_macho_header() {
        let layout = MergedLayout {
            sections: vec![MergedSection {
                name: ".text".into(),
                data: vec![0xc3],
                vaddr: 0x100000000,
                flags: 4,
                align: 16,
            }],
            section_by_name: {
                let mut m = HashMap::new();
                m.insert(".text".into(), 0);
                m
            },
        };

        let mut out = Vec::new();
        emit_macho_executable(&layout, TargetArch::X86_64, 0x100000000, &mut out).expect("emit");

        assert!(out.len() >= 32);
        assert_eq!(&out[0..4], &0xFEEDFACFu32.to_le_bytes());
        assert_eq!(&out[4..8], &0x01000007u32.to_le_bytes());
    }
}
