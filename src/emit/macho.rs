//! Mach-O 64 executable emission for macOS.
//!
//! Emits MH_EXECUTABLE with __TEXT, LC_MAIN, LC_LOAD_DYLINKER, LC_LOAD_DYLIB.

#![allow(dead_code)]

use crate::arch::TargetArch;
use crate::link::MergedLayout;
use crate::segment::{align_up_usize, build_segment_buffer};
use std::io::Write;

const MH_MAGIC_64: u32 = 0xFEEDFACF;
const MH_EXECUTABLE: u32 = 2;
const CPU_TYPE_X86_64: u32 = 0x01000007;
const CPU_TYPE_ARM64: u32 = 0x0100000C;
const LC_SEGMENT_64: u32 = 0x19;
const LC_MAIN: u32 = 0x80000028;
const LC_LOAD_DYLINKER: u32 = 0x0E;
const LC_LOAD_DYLIB: u32 = 0x0C;
const VM_PROT_READ: u32 = 1;
const VM_PROT_EXECUTE: u32 = 4;

const PAGE_SIZE: usize = 4096;

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
