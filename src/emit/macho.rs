//! Mach-O 64 executable emission for macOS.
//!
//! Emits MH_EXECUTABLE with __TEXT, LC_MAIN, LC_LOAD_DYLINKER, LC_LOAD_DYLIB.

#![allow(dead_code)]

use crate::arch::TargetArch;
use crate::link::{DynamicLinkInfo, MergedLayout, MergedSection};
use crate::segment::{align_up_u64, align_up_usize, build_segment_buffer};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Error, ErrorKind, Result, Write};

const MH_MAGIC_64: u32 = 0xFEEDFACF;
const MH_EXECUTABLE: u32 = 2;
const MH_NOUNDEFS: u32 = 0x1;
const MH_DYLDLINK: u32 = 0x4;
const MH_TWOLEVEL: u32 = 0x80;
const MH_PIE: u32 = 0x200000;
const CPU_TYPE_X86_64: u32 = 0x01000007;
const CPU_TYPE_ARM64: u32 = 0x0100000C;
const LC_SEGMENT_64: u32 = 0x19;
const LC_MAIN: u32 = 0x80000028;
const LC_LOAD_DYLINKER: u32 = 0x0E;
const LC_LOAD_DYLIB: u32 = 0x0C;
const LC_UUID: u32 = 0x1B;
const LC_DYLD_INFO_ONLY: u32 = 0x80000022;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x80000033;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x80000034;
const LC_BUILD_VERSION: u32 = 0x32;
const LC_SYMTAB: u32 = 0x2;
const LC_DYSYMTAB: u32 = 0xb;
const N_SECT_EXT: u8 = 0x0f;
const VM_PROT_READ: u32 = 1;
const VM_PROT_WRITE: u32 = 2;
const VM_PROT_EXECUTE: u32 = 4;

const PAGE_SIZE: usize = 16384;
const SEG_BASE: u64 = 0x100000000;

fn write_u32(w: &mut impl Write, val: u32) -> Result<()> {
    w.write_all(&val.to_le_bytes())
}

fn write_u64(w: &mut impl Write, val: u64) -> Result<()> {
    w.write_all(&val.to_le_bytes())
}

fn pad_segname(name: &str) -> [u8; 16] {
    let mut buf = [0u8; 16];
    let len = name.len().min(16);
    buf[..len].copy_from_slice(&name.as_bytes()[..len]);
    buf
}

fn section_name_fields(name: &str) -> (&str, &str) {
    if name == ".text" {
        return ("__TEXT", "__text");
    }
    if name == "__got" {
        return ("__DATA", "__got");
    }
    if name == "__data"
        || name == "__bss"
        || name == "__common"
        || name == "__thread_bss"
        || name == "__thread_data"
        || name == "__thread_vars"
    {
        return ("__DATA", name);
    }
    if name == "__stubs" || name == "__stub_helper" {
        return ("__TEXT", name);
    }
    if let Some((seg, sect)) = name.split_once('.') {
        if (seg.starts_with("__DATA") || seg.starts_with("__AUTH")) && sect.starts_with("__") {
            return ("__DATA", sect);
        }
        if seg.starts_with("__") && sect.starts_with("__") {
            return (seg, sect);
        }
    }
    ("__TEXT", name)
}

fn is_data_section(name: &str) -> bool {
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

fn default_uuid() -> [u8; 16] {
    [
        0x57, 0x45, 0x4c, 0x44, 0x2d, 0x4c, 0x49, 0x4e, 0x4b, 0x45, 0x52, 0x2d, 0x30, 0x30, 0x30,
        0x31,
    ]
}

fn section_meta(name: &str) -> (u32, u32, u32) {
    match name {
        "__text" => (0x80000400, 0, 0),
        "__stubs" => (0x80000400, 0, 0),
        "__stub_helper" => (0x80000400, 0, 0),
        "__cstring" => (0x00000002, 0, 0),
        "__literal4" => (0x00000000, 0, 0),
        "__literal8" => (0x00000000, 0, 0),
        "__literal16" => (0x00000000, 0, 0),
        "__bss" => (0x00000001, 0, 0),
        "__common" => (0x00000001, 0, 0),
        "__thread_data" => (0x00000011, 0, 0),
        "__thread_bss" => (0x00000012, 0, 0),
        "__thread_vars" => (0x00000013, 0, 0),
        "__got" => (0x00000000, 0, 0),
        _ => (0x00000000, 0, 0),
    }
}

pub fn emit_macho_executable(
    layout: &MergedLayout,
    arch: TargetArch,
    entry: u64,
    out: &mut impl Write,
) -> Result<()> {
    let (_base, seg_buffer) = build_segment_buffer(layout, 0x100000000);
    let text_size = seg_buffer.len();
    let text_size_aligned = align_up_usize(text_size, PAGE_SIZE);

    let cputype = arch.to_macho_cputype();
    if cputype == 0 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
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

    let data_file_off = 0u64;
    const SECT64_SIZE: usize = 80;
    let seg_total_size = 72 + SECT64_SIZE;
    let mut seg_cmd = vec![0u8; seg_total_size];
    seg_cmd[0..4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
    seg_cmd[4..8].copy_from_slice(&(seg_total_size as u32).to_le_bytes());
    const SEG_VMADDR: u64 = 0x100000000;
    seg_cmd[8..24].copy_from_slice(&pad_segname("__TEXT"));
    seg_cmd[24..32].copy_from_slice(&SEG_VMADDR.to_le_bytes());
    seg_cmd[32..40].copy_from_slice(&((PAGE_SIZE + text_size_aligned) as u64).to_le_bytes());
    seg_cmd[40..48].copy_from_slice(&data_file_off.to_le_bytes());
    seg_cmd[48..56].copy_from_slice(&((PAGE_SIZE + text_size_aligned) as u64).to_le_bytes());
    seg_cmd[56..60].copy_from_slice(&(VM_PROT_READ | VM_PROT_EXECUTE).to_le_bytes());
    seg_cmd[60..64].copy_from_slice(&(VM_PROT_READ | VM_PROT_EXECUTE).to_le_bytes());
    seg_cmd[64..68].copy_from_slice(&1u32.to_le_bytes());
    seg_cmd[68..72].copy_from_slice(&0u32.to_le_bytes());

    seg_cmd[72..88].copy_from_slice(&pad_segname("__text"));
    seg_cmd[88..104].copy_from_slice(&pad_segname("__TEXT"));
    seg_cmd[104..112].copy_from_slice(&(SEG_VMADDR + PAGE_SIZE as u64).to_le_bytes());
    seg_cmd[112..120].copy_from_slice(&(text_size as u64).to_le_bytes());
    seg_cmd[120..124].copy_from_slice(&(PAGE_SIZE as u32).to_le_bytes());
    seg_cmd[124..128].copy_from_slice(&4u32.to_le_bytes());
    seg_cmd[128..132].copy_from_slice(&0u32.to_le_bytes());
    seg_cmd[132..136].copy_from_slice(&0u32.to_le_bytes());
    seg_cmd[136..140].copy_from_slice(&0x80000400u32.to_le_bytes());
    seg_cmd[140..144].copy_from_slice(&0u32.to_le_bytes());
    seg_cmd[144..148].copy_from_slice(&0u32.to_le_bytes());
    seg_cmd[148..152].copy_from_slice(&0u32.to_le_bytes());

    lc_buf.extend_from_slice(&seg_cmd);
    total_cmds += 1;
    sizeofcmds += seg_total_size as u32;

    let entry_offset = (entry + PAGE_SIZE as u64).saturating_sub(SEG_VMADDR);
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
    let dyld_cmd_size = align_up_usize(12 + dyld_len, 8);
    let mut lc_dyld = vec![0u8; dyld_cmd_size];
    lc_dyld[0..4].copy_from_slice(&LC_LOAD_DYLINKER.to_le_bytes());
    lc_dyld[4..8].copy_from_slice(&(dyld_cmd_size as u32).to_le_bytes());
    lc_dyld[8..12].copy_from_slice(&12u32.to_le_bytes());
    lc_dyld[12..12 + dyld_len - 1].copy_from_slice(&dyld_path.as_bytes()[..dyld_len - 1]);
    lc_buf.extend_from_slice(&lc_dyld);
    total_cmds += 1;
    sizeofcmds += dyld_cmd_size as u32;

    let mut lc_uuid = [0u8; 24];
    lc_uuid[0..4].copy_from_slice(&LC_UUID.to_le_bytes());
    lc_uuid[4..8].copy_from_slice(&24u32.to_le_bytes());
    lc_uuid[8..24].copy_from_slice(&default_uuid());
    lc_buf.extend_from_slice(&lc_uuid);
    total_cmds += 1;
    sizeofcmds += 24;

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

    let mut lc_build = [0u8; 32];
    lc_build[0..4].copy_from_slice(&LC_BUILD_VERSION.to_le_bytes());
    lc_build[4..8].copy_from_slice(&32u32.to_le_bytes());
    lc_build[8..12].copy_from_slice(&1u32.to_le_bytes());
    lc_build[12..16].copy_from_slice(&0x001A0000u32.to_le_bytes());
    lc_build[16..20].copy_from_slice(&0x001A0200u32.to_le_bytes());
    lc_build[20..24].copy_from_slice(&1u32.to_le_bytes());
    lc_build[24..28].copy_from_slice(&3u32.to_le_bytes());
    lc_build[28..32].copy_from_slice(&0x04CE0100u32.to_le_bytes());
    lc_buf.extend_from_slice(&lc_build);
    total_cmds += 1;
    sizeofcmds += 32;

    let mut hdr = [0u8; 32];
    hdr[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
    hdr[4..8].copy_from_slice(&cputype.to_le_bytes());
    hdr[8..12].copy_from_slice(&0u32.to_le_bytes());
    hdr[12..16].copy_from_slice(&MH_EXECUTABLE.to_le_bytes());
    hdr[16..20].copy_from_slice(&total_cmds.to_le_bytes());
    hdr[20..24].copy_from_slice(&sizeofcmds.to_le_bytes());
    let flags = MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE;
    hdr[24..28].copy_from_slice(&flags.to_le_bytes());
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

fn push_sleb128(buf: &mut Vec<u8>, mut val: i64) {
    loop {
        let byte = (val & 0x7f) as u8;
        let sign = (byte & 0x40) != 0;
        val >>= 7;
        let done = (val == 0 && !sign) || (val == -1 && sign);
        if done {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
}

fn build_rebase_opcodes(data_segment_index: u32, pointer_offsets: &[u64]) -> Vec<u8> {
    if pointer_offsets.is_empty() {
        return Vec::new();
    }
    const REBASE_TYPE_POINTER: u8 = 1;
    const REBASE_OPCODE_SET_TYPE_IMM: u8 = 0x10;
    const REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x20;
    const REBASE_OPCODE_DO_REBASE_IMM_TIMES: u8 = 0x50;
    const REBASE_OPCODE_DO_REBASE_ULEB_TIMES: u8 = 0x60;
    const REBASE_OPCODE_DONE: u8 = 0x00;

    let mut offsets = pointer_offsets.to_vec();
    offsets.sort_unstable();
    offsets.dedup();

    let mut buf = Vec::new();
    buf.push(REBASE_OPCODE_SET_TYPE_IMM | REBASE_TYPE_POINTER);

    let mut i = 0usize;
    while i < offsets.len() {
        let start = offsets[i];
        let mut count = 1usize;
        while i + count < offsets.len() && offsets[i + count] == offsets[i + count - 1] + 8 {
            count += 1;
        }

        buf.push(REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | ((data_segment_index as u8) & 0x0F));
        push_uleb128(&mut buf, start);
        if count <= 15 {
            buf.push(REBASE_OPCODE_DO_REBASE_IMM_TIMES | (count as u8));
        } else {
            buf.push(REBASE_OPCODE_DO_REBASE_ULEB_TIMES);
            push_uleb128(&mut buf, count as u64);
        }
        i += count;
    }

    buf.push(REBASE_OPCODE_DONE);
    buf
}

fn build_bind_opcodes(
    plt_symbols: &[String],
    weak_symbols: &[String],
    data_segment_index: u32,
    got_offset_in_segment: u64,
    direct_binds: &[(u64, String, bool, i64)],
) -> Vec<u8> {
    if plt_symbols.is_empty() && direct_binds.is_empty() {
        return Vec::new();
    }
    const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
    const BIND_SPECIAL_DYLIB_FLAT_LOOKUP_IMM: u8 = 0x0E;
    const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
    const BIND_SYMBOL_FLAGS_WEAK_IMPORT: u8 = 0x01;
    const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
    const BIND_OPCODE_SET_ADDEND_SLEB: u8 = 0x60;
    const BIND_TYPE_POINTER: u8 = 1;
    const BIND_OPCODE_SET_TYPE_IMM: u8 = 0x50;
    const BIND_OPCODE_DO_BIND: u8 = 0x90;
    const BIND_OPCODE_DONE: u8 = 0x00;

    let weak: HashSet<&str> = weak_symbols.iter().map(|s| s.as_str()).collect();

    let mut buf = Vec::new();
    buf.push(BIND_OPCODE_SET_DYLIB_SPECIAL_IMM | BIND_SPECIAL_DYLIB_FLAT_LOOKUP_IMM);
    for (i, sym) in plt_symbols.iter().enumerate() {
        let sym_flags = if weak.contains(sym.as_str()) {
            BIND_SYMBOL_FLAGS_WEAK_IMPORT
        } else {
            0
        };
        buf.push(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | sym_flags);
        buf.extend_from_slice(sym.as_bytes());
        buf.push(0);
        buf.push(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | ((data_segment_index as u8) & 0x0F));
        push_uleb128(&mut buf, got_offset_in_segment + (i as u64) * 8);
        buf.push(BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER);
        buf.push(BIND_OPCODE_DO_BIND);
    }
    for (off, sym, is_weak, addend) in direct_binds {
        let sym_flags = if *is_weak {
            BIND_SYMBOL_FLAGS_WEAK_IMPORT
        } else {
            0
        };
        buf.push(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | sym_flags);
        buf.extend_from_slice(sym.as_bytes());
        buf.push(0);
        buf.push(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | ((data_segment_index as u8) & 0x0F));
        push_uleb128(&mut buf, *off);
        buf.push(BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER);
        if *addend != 0 {
            buf.push(BIND_OPCODE_SET_ADDEND_SLEB);
            push_sleb128(&mut buf, *addend);
        }
        buf.push(BIND_OPCODE_DO_BIND);
    }
    buf.push(BIND_OPCODE_DONE);
    buf
}

fn uleb128_size(mut v: u64) -> usize {
    let mut n = 1usize;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

#[derive(Default, Clone)]
struct ExportRawNode {
    terminal: Option<(u64, u64)>,
    children: BTreeMap<u8, usize>,
}

#[derive(Default, Clone)]
struct ExportTrieNode {
    terminal: Option<(u64, u64)>,
    edges: Vec<(Vec<u8>, usize)>,
    offset: usize,
}

fn insert_export_symbol(nodes: &mut Vec<ExportRawNode>, name: &str, address: u64) {
    let mut idx = 0usize;
    for &ch in name.as_bytes() {
        let next = if let Some(&n) = nodes[idx].children.get(&ch) {
            n
        } else {
            nodes.push(ExportRawNode::default());
            let n = nodes.len() - 1;
            nodes[idx].children.insert(ch, n);
            n
        };
        idx = next;
    }
    nodes[idx].terminal = Some((0, address));
}

fn compress_export_node(
    raw_nodes: &[ExportRawNode],
    raw_idx: usize,
    out_nodes: &mut Vec<ExportTrieNode>,
) -> usize {
    let out_idx = out_nodes.len();
    out_nodes.push(ExportTrieNode {
        terminal: raw_nodes[raw_idx].terminal,
        edges: Vec::new(),
        offset: 0,
    });

    let children: Vec<(u8, usize)> = raw_nodes[raw_idx]
        .children
        .iter()
        .map(|(k, v)| (*k, *v))
        .collect();

    for (ch, mut child_idx) in children {
        let mut label = vec![ch];
        while raw_nodes[child_idx].terminal.is_none() && raw_nodes[child_idx].children.len() == 1 {
            let (&next_ch, &next_idx) = raw_nodes[child_idx].children.iter().next().unwrap();
            label.push(next_ch);
            child_idx = next_idx;
        }
        let child_out_idx = compress_export_node(raw_nodes, child_idx, out_nodes);
        out_nodes[out_idx].edges.push((label, child_out_idx));
    }

    out_idx
}

fn export_node_size(nodes: &[ExportTrieNode], idx: usize) -> usize {
    let node = &nodes[idx];
    let terminal_size = if let Some((flags, address)) = node.terminal {
        uleb128_size(flags) + uleb128_size(address)
    } else {
        0
    };

    let mut size = uleb128_size(terminal_size as u64) + terminal_size + 1;
    for (label, child_idx) in &node.edges {
        size += label.len() + 1 + uleb128_size(nodes[*child_idx].offset as u64);
    }
    size
}

fn build_export_trie(exports: &[(String, u64)]) -> Vec<u8> {
    if exports.is_empty() {
        return vec![0, 0];
    }

    let mut raw_nodes = vec![ExportRawNode::default()];
    for (name, address) in exports {
        insert_export_symbol(&mut raw_nodes, name, *address);
    }

    let mut nodes = Vec::new();
    let _root = compress_export_node(&raw_nodes, 0, &mut nodes);

    loop {
        let mut next_off = 0usize;
        let mut changed = false;
        for i in 0..nodes.len() {
            if nodes[i].offset != next_off {
                nodes[i].offset = next_off;
                changed = true;
            }
            next_off += export_node_size(&nodes, i);
        }
        if !changed {
            break;
        }
    }

    let total_size = if let Some(last) = nodes.last() {
        last.offset + export_node_size(&nodes, nodes.len() - 1)
    } else {
        0
    };
    let mut out = vec![0u8; total_size];

    for node in &nodes {
        let mut encoded = Vec::new();
        let terminal_size = if let Some((flags, address)) = node.terminal {
            let sz = uleb128_size(flags) + uleb128_size(address);
            push_uleb128(&mut encoded, sz as u64);
            push_uleb128(&mut encoded, flags);
            push_uleb128(&mut encoded, address);
            sz
        } else {
            push_uleb128(&mut encoded, 0);
            0
        };
        let _ = terminal_size;
        encoded.push(node.edges.len() as u8);
        for (label, child_idx) in &node.edges {
            encoded.extend_from_slice(label);
            encoded.push(0);
            push_uleb128(&mut encoded, nodes[*child_idx].offset as u64);
        }
        let start = node.offset;
        let end = start + encoded.len();
        out[start..end].copy_from_slice(&encoded);
    }

    out
}

// Parameters mirror the dyld chained-fixups payload layout, which requires all
// segment/import details simultaneously. Splitting further would hurt readability.
#[allow(clippy::too_many_arguments)]
fn build_chained_fixups_payload(
    seg_count: u32,
    data_seg_index: Option<u32>,
    data_seg_vmoff: u64,
    data_seg_size: u64,
    got_offset: u64,
    got_slot_count: u64,
    import_symbols: &[String],
    data_buffer: &mut [u8],
) -> Vec<u8> {
    const DYLD_CHAINED_IMPORT: u32 = 1;
    const DYLD_CHAINED_PTR_64: u16 = 2;
    const DYLD_CHAINED_PTR_START_NONE: u16 = 0xFFFF;
    const BIND_SPECIAL_DYLIB_FLAT_LOOKUP: u8 = 0xFE;

    let import_count = std::cmp::min(got_slot_count as usize, import_symbols.len());
    let mut page_first_starts: BTreeMap<u32, u16> = BTreeMap::new();

    for i in 0..import_count {
        let off = got_offset + (i as u64) * 8;
        if (off as usize) + 8 > data_buffer.len() {
            break;
        }
        let page_idx = (off / PAGE_SIZE as u64) as u32;
        let page_off = (off % PAGE_SIZE as u64) as u16;
        page_first_starts.entry(page_idx).or_insert(page_off);

        let next = if i + 1 < import_count {
            let next_off = got_offset + ((i + 1) as u64) * 8;
            if next_off / PAGE_SIZE as u64 == off / PAGE_SIZE as u64 {
                (next_off - off) / 4
            } else {
                0
            }
        } else {
            0
        };

        let mut bind_ptr = (i as u64) & 0x00FF_FFFF;
        bind_ptr |= (next & 0x0FFF) << 51;
        bind_ptr |= 1u64 << 63;
        data_buffer[off as usize..off as usize + 8].copy_from_slice(&bind_ptr.to_le_bytes());
    }

    let header_size = align_up_usize(28, 8);
    let starts_in_image_size = align_up_usize(4 + seg_count as usize * 4, 8);
    let starts_offset = header_size as u32;

    let mut payload = vec![0u8; header_size + starts_in_image_size];

    payload[4..8].copy_from_slice(&starts_offset.to_le_bytes());
    payload[16..20].copy_from_slice(&(import_count as u32).to_le_bytes());
    payload[20..24].copy_from_slice(&DYLD_CHAINED_IMPORT.to_le_bytes());
    payload[24..28].copy_from_slice(&0u32.to_le_bytes());

    let starts_base = starts_offset as usize;
    payload[starts_base..starts_base + 4].copy_from_slice(&seg_count.to_le_bytes());

    if import_count > 0
        && let Some(seg_idx) = data_seg_index
    {
        let page_count = data_seg_size
            .div_ceil(PAGE_SIZE as u64)
            .max(page_first_starts.keys().last().copied().unwrap_or(0) as u64 + 1)
            as usize;
        let seg_info_size_unaligned = 24 + page_count.saturating_sub(1) * 2;
        let seg_info_size = align_up_usize(seg_info_size_unaligned, 8);

        let seg_info_rel = (payload.len() - starts_base) as u32;
        let seg_off_entry = starts_base + 4 + seg_idx as usize * 4;
        if seg_off_entry + 4 <= payload.len() {
            payload[seg_off_entry..seg_off_entry + 4].copy_from_slice(&seg_info_rel.to_le_bytes());
        }

        let seg_start = payload.len();
        payload.resize(seg_start + seg_info_size, 0);
        payload[seg_start..seg_start + 4].copy_from_slice(&(seg_info_size as u32).to_le_bytes());
        payload[seg_start + 4..seg_start + 6].copy_from_slice(&(PAGE_SIZE as u16).to_le_bytes());
        payload[seg_start + 6..seg_start + 8].copy_from_slice(&DYLD_CHAINED_PTR_64.to_le_bytes());
        payload[seg_start + 8..seg_start + 16].copy_from_slice(&data_seg_vmoff.to_le_bytes());
        payload[seg_start + 16..seg_start + 20].copy_from_slice(&0u32.to_le_bytes());
        payload[seg_start + 20..seg_start + 22].copy_from_slice(&(page_count as u16).to_le_bytes());

        let mut page_starts = vec![DYLD_CHAINED_PTR_START_NONE; page_count];
        for (page_idx, start_off) in &page_first_starts {
            let idx = *page_idx as usize;
            if idx < page_starts.len() {
                page_starts[idx] = *start_off;
            }
        }
        let starts_off = seg_start + 22;
        for (i, v) in page_starts.iter().enumerate() {
            let o = starts_off + i * 2;
            if o + 2 <= payload.len() {
                payload[o..o + 2].copy_from_slice(&v.to_le_bytes());
            }
        }
    }

    let imports_offset = payload.len() as u32;
    let mut name_off = 0u32;
    for _ in 0..import_count {
        let entry = (BIND_SPECIAL_DYLIB_FLAT_LOOKUP as u32) | (name_off << 9);
        payload.extend_from_slice(&entry.to_le_bytes());
        let name = &import_symbols[name_off as usize];
        name_off += (name.len() + 1) as u32;
    }

    let symbols_offset = payload.len() as u32;
    for sym in import_symbols.iter().take(import_count) {
        payload.extend_from_slice(sym.as_bytes());
        payload.push(0);
    }

    let aligned = align_up_usize(payload.len(), 8);
    if aligned > payload.len() {
        payload.resize(aligned, 0);
    }

    payload[8..12].copy_from_slice(&imports_offset.to_le_bytes());
    payload[12..16].copy_from_slice(&symbols_offset.to_le_bytes());

    payload
}

pub fn emit_macho_executable_dynamic(
    layout: &MergedLayout,
    arch: TargetArch,
    entry: u64,
    dyn_info: &DynamicLinkInfo,
    out: &mut impl Write,
) -> Result<()> {
    let text_sections_owned: Vec<MergedSection> = layout
        .sections
        .iter()
        .filter(|s| !is_data_section(&s.name))
        .cloned()
        .collect();
    let mut data_sections_owned: Vec<MergedSection> = layout
        .sections
        .iter()
        .filter(|s| is_data_section(&s.name))
        .cloned()
        .collect();
    if data_sections_owned.is_empty() {
        data_sections_owned.push(MergedSection {
            name: "__data".to_string(),
            data: vec![0u8; 8],
            vaddr: 0,
            flags: 0,
            align: 3,
        });
    }
    let text_sections: Vec<&MergedSection> = text_sections_owned.iter().collect();
    let data_sections: Vec<&MergedSection> = data_sections_owned.iter().collect();

    let text_layout = MergedLayout {
        sections: text_sections_owned.clone(),
        section_by_name: HashMap::new(),
    };
    let data_layout = MergedLayout {
        sections: data_sections_owned.clone(),
        section_by_name: HashMap::new(),
    };

    let (text_base, text_buffer) = build_segment_buffer(&text_layout, SEG_BASE);
    let text_vmaddr = text_base;
    let text_size = text_buffer.len();
    let text_size_aligned = align_up_usize(text_size, PAGE_SIZE);

    let (data_base, data_buffer) = build_segment_buffer(&data_layout, SEG_BASE + 0x8000);
    let data_size = data_buffer.len();
    let data_size_aligned = align_up_usize(data_size, PAGE_SIZE);
    let has_data = !data_layout.sections.is_empty();
    let data_vmaddr = if has_data {
        let derived = data_base + PAGE_SIZE as u64;
        let min_after_text = align_up_u64(
            text_vmaddr + PAGE_SIZE as u64 + text_size_aligned as u64,
            PAGE_SIZE as u64,
        );
        derived.max(min_after_text)
    } else {
        0
    };

    let got_section = data_sections.iter().find(|s| s.name == "__got");
    let got_offset_in_segment = got_section.map(|s| s.vaddr - data_base).unwrap_or(0);

    const DATA_SEGMENT_INDEX: u32 = 2;
    let mut rebase_offsets: Vec<u64> = dyn_info
        .macho_rebase_addrs
        .iter()
        .filter_map(|&addr| {
            if addr < data_base {
                return None;
            }
            let off = addr - data_base;
            if off + 8 <= data_size as u64 {
                Some(off)
            } else {
                None
            }
        })
        .collect();
    rebase_offsets.sort_unstable();
    rebase_offsets.dedup();

    let mut direct_bind_offsets: Vec<(u64, String, bool, i64)> = dyn_info
        .macho_direct_binds
        .iter()
        .filter_map(|(addr, sym, weak, addend)| {
            if *addr < data_base {
                return None;
            }
            let off = *addr - data_base;
            if off + 8 <= data_size as u64 {
                Some((off, sym.clone(), *weak, *addend))
            } else {
                None
            }
        })
        .collect();
    direct_bind_offsets.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    direct_bind_offsets.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1 && a.2 == b.2 && a.3 == b.3);

    let rebase_opcodes = build_rebase_opcodes(DATA_SEGMENT_INDEX, &rebase_offsets);
    let bind_opcodes = build_bind_opcodes(
        &dyn_info.plt_symbols,
        &dyn_info.weak_plt_symbols,
        DATA_SEGMENT_INDEX,
        got_offset_in_segment,
        &direct_bind_offsets,
    );

    let cputype = arch.to_macho_cputype();
    if cputype == 0 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
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
    lc_pagezero[32..40].copy_from_slice(&text_vmaddr.to_le_bytes());
    lc_buf.extend_from_slice(&lc_pagezero);
    total_cmds += 1;
    sizeofcmds += 72;

    const SECT64_SIZE: usize = 80;
    let text_seg_size = 72 + SECT64_SIZE * text_sections.len();
    let mut text_seg = vec![0u8; text_seg_size];
    text_seg[0..4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
    text_seg[4..8].copy_from_slice(&(text_seg_size as u32).to_le_bytes());
    text_seg[8..24].copy_from_slice(&pad_segname("__TEXT"));
    text_seg[24..32].copy_from_slice(&text_vmaddr.to_le_bytes());
    text_seg[32..40].copy_from_slice(&((PAGE_SIZE + text_size_aligned) as u64).to_le_bytes());
    text_seg[40..48].copy_from_slice(&0u64.to_le_bytes());
    text_seg[48..56].copy_from_slice(&((PAGE_SIZE + text_size_aligned) as u64).to_le_bytes());
    text_seg[56..60].copy_from_slice(&(VM_PROT_READ | VM_PROT_EXECUTE).to_le_bytes());
    text_seg[60..64].copy_from_slice(&(VM_PROT_READ | VM_PROT_EXECUTE).to_le_bytes());
    text_seg[64..68].copy_from_slice(&(text_sections.len() as u32).to_le_bytes());
    for (i, sec) in text_sections.iter().enumerate() {
        let (segname, sectname) = section_name_fields(&sec.name);
        let (flags, reserved1, reserved2) = section_meta(sectname);
        let base = 72 + i * SECT64_SIZE;
        let sec_offset_in_segment = sec.vaddr - text_base;
        let sec_file_offset = PAGE_SIZE as u64 + sec_offset_in_segment;
        text_seg[base..base + 16].copy_from_slice(&pad_segname(sectname));
        text_seg[base + 16..base + 32].copy_from_slice(&pad_segname(segname));
        text_seg[base + 32..base + 40]
            .copy_from_slice(&(sec.vaddr + PAGE_SIZE as u64).to_le_bytes());
        text_seg[base + 40..base + 48].copy_from_slice(&(sec.data.len() as u64).to_le_bytes());
        text_seg[base + 48..base + 52].copy_from_slice(&(sec_file_offset as u32).to_le_bytes());
        text_seg[base + 52..base + 56].copy_from_slice(&(sec.align as u32).to_le_bytes());
        text_seg[base + 56..base + 60].copy_from_slice(&0u32.to_le_bytes());
        text_seg[base + 60..base + 64].copy_from_slice(&0u32.to_le_bytes());
        text_seg[base + 64..base + 68].copy_from_slice(&flags.to_le_bytes());
        text_seg[base + 68..base + 72].copy_from_slice(&reserved1.to_le_bytes());
        text_seg[base + 72..base + 76].copy_from_slice(&reserved2.to_le_bytes());
        text_seg[base + 76..base + 80].copy_from_slice(&0u32.to_le_bytes());
    }
    lc_buf.extend_from_slice(&text_seg);
    total_cmds += 1;
    sizeofcmds += text_seg_size as u32;

    let data_file_off = PAGE_SIZE as u64 + text_size_aligned as u64;
    let linkedit_file_off = if has_data {
        data_file_off + data_size_aligned as u64
    } else {
        data_file_off
    };
    let linkedit_vaddr = if has_data {
        align_up_u64(data_vmaddr + data_size_aligned as u64, PAGE_SIZE as u64)
    } else {
        align_up_u64(
            text_vmaddr + PAGE_SIZE as u64 + text_size_aligned as u64,
            PAGE_SIZE as u64,
        )
    };
    let dyld_info_off = linkedit_file_off as usize;
    let bind_off = align_up_usize(dyld_info_off + rebase_opcodes.len(), 8);
    let bind_pad_len = bind_off.saturating_sub(dyld_info_off + rebase_opcodes.len());
    let dyld_info_size = rebase_opcodes.len() + bind_pad_len + bind_opcodes.len();

    let mut symtab_bytes = Vec::with_capacity(32);
    let write_nlist = |buf: &mut Vec<u8>, strx: u32, value: u64| {
        buf.extend_from_slice(&strx.to_le_bytes());
        buf.push(N_SECT_EXT);
        buf.push(1u8);
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&value.to_le_bytes());
    };
    write_nlist(&mut symtab_bytes, 1, text_vmaddr);
    write_nlist(&mut symtab_bytes, 21, entry + PAGE_SIZE as u64);
    let strtab_bytes = b"\0__mh_execute_header\0_main\0".to_vec();

    let symoff_unaligned = linkedit_file_off as usize + dyld_info_size;
    let symoff = align_up_usize(symoff_unaligned, 8) as u32;
    let symtab_pad_len = (symoff as usize).saturating_sub(symoff_unaligned);
    let stroff = symoff + symtab_bytes.len() as u32;
    let strsize = strtab_bytes.len() as u32;

    let linkedit_size =
        (dyld_info_size + symtab_pad_len + symtab_bytes.len() + strtab_bytes.len()) as u64;
    if has_data {
        let data_seg_size = 72 + SECT64_SIZE * data_sections.len();
        let mut data_seg = vec![0u8; data_seg_size];
        data_seg[0..4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
        data_seg[4..8].copy_from_slice(&(data_seg_size as u32).to_le_bytes());
        data_seg[8..24].copy_from_slice(&pad_segname("__DATA"));
        data_seg[24..32].copy_from_slice(&data_vmaddr.to_le_bytes());
        data_seg[32..40].copy_from_slice(&(data_size_aligned as u64).to_le_bytes());
        data_seg[40..48].copy_from_slice(&data_file_off.to_le_bytes());
        data_seg[48..56].copy_from_slice(&(data_size_aligned as u64).to_le_bytes());
        data_seg[56..60].copy_from_slice(&(VM_PROT_READ | VM_PROT_WRITE).to_le_bytes());
        data_seg[60..64].copy_from_slice(&(VM_PROT_READ | VM_PROT_WRITE).to_le_bytes());
        data_seg[64..68].copy_from_slice(&(data_sections.len() as u32).to_le_bytes());
        for (i, sec) in data_sections.iter().enumerate() {
            let (segname, sectname) = section_name_fields(&sec.name);
            let (flags, reserved1, reserved2) = section_meta(sectname);
            let base = 72 + i * SECT64_SIZE;
            let sec_offset_in_segment = sec.vaddr - data_base;
            let sec_file_offset = data_file_off + sec_offset_in_segment;
            data_seg[base..base + 16].copy_from_slice(&pad_segname(sectname));
            data_seg[base + 16..base + 32].copy_from_slice(&pad_segname(segname));
            data_seg[base + 32..base + 40]
                .copy_from_slice(&(data_vmaddr + sec_offset_in_segment).to_le_bytes());
            data_seg[base + 40..base + 48].copy_from_slice(&(sec.data.len() as u64).to_le_bytes());
            data_seg[base + 48..base + 52].copy_from_slice(&(sec_file_offset as u32).to_le_bytes());
            data_seg[base + 52..base + 56].copy_from_slice(&(sec.align as u32).to_le_bytes());
            data_seg[base + 56..base + 60].copy_from_slice(&0u32.to_le_bytes());
            data_seg[base + 60..base + 64].copy_from_slice(&0u32.to_le_bytes());
            data_seg[base + 64..base + 68].copy_from_slice(&flags.to_le_bytes());
            data_seg[base + 68..base + 72].copy_from_slice(&reserved1.to_le_bytes());
            data_seg[base + 72..base + 76].copy_from_slice(&reserved2.to_le_bytes());
            data_seg[base + 76..base + 80].copy_from_slice(&0u32.to_le_bytes());
        }
        lc_buf.extend_from_slice(&data_seg);
        total_cmds += 1;
        sizeofcmds += data_seg_size as u32;
    }

    {
        let mut linkedit_seg = [0u8; 72];
        linkedit_seg[0..4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
        linkedit_seg[4..8].copy_from_slice(&72u32.to_le_bytes());
        linkedit_seg[8..24].copy_from_slice(&pad_segname("__LINKEDIT"));
        linkedit_seg[24..32].copy_from_slice(&linkedit_vaddr.to_le_bytes());
        let linkedit_vm = if linkedit_size == 0 {
            PAGE_SIZE as u64
        } else {
            align_up_u64(linkedit_size, PAGE_SIZE as u64)
        };
        linkedit_seg[32..40].copy_from_slice(&linkedit_vm.to_le_bytes());
        linkedit_seg[40..48].copy_from_slice(&linkedit_file_off.to_le_bytes());
        linkedit_seg[48..56].copy_from_slice(&linkedit_size.to_le_bytes());
        linkedit_seg[56..60].copy_from_slice(&VM_PROT_READ.to_le_bytes());
        linkedit_seg[60..64].copy_from_slice(&VM_PROT_READ.to_le_bytes());
        linkedit_seg[64..68].copy_from_slice(&0u32.to_le_bytes());
        linkedit_seg[68..72].copy_from_slice(&0u32.to_le_bytes());
        lc_buf.extend_from_slice(&linkedit_seg);
        total_cmds += 1;
        sizeofcmds += 72;
    }

    let mut lc_symtab = [0u8; 24];
    lc_symtab[0..4].copy_from_slice(&LC_SYMTAB.to_le_bytes());
    lc_symtab[4..8].copy_from_slice(&24u32.to_le_bytes());
    lc_symtab[8..12].copy_from_slice(&symoff.to_le_bytes());
    lc_symtab[12..16].copy_from_slice(&2u32.to_le_bytes());
    lc_symtab[16..20].copy_from_slice(&stroff.to_le_bytes());
    lc_symtab[20..24].copy_from_slice(&strsize.to_le_bytes());
    lc_buf.extend_from_slice(&lc_symtab);
    total_cmds += 1;
    sizeofcmds += 24;

    let mut lc_dysymtab = [0u8; 80];
    lc_dysymtab[0..4].copy_from_slice(&LC_DYSYMTAB.to_le_bytes());
    lc_dysymtab[4..8].copy_from_slice(&80u32.to_le_bytes());
    lc_dysymtab[8..12].copy_from_slice(&0u32.to_le_bytes());
    lc_dysymtab[12..16].copy_from_slice(&0u32.to_le_bytes());
    lc_dysymtab[16..20].copy_from_slice(&0u32.to_le_bytes());
    lc_dysymtab[20..24].copy_from_slice(&2u32.to_le_bytes());
    lc_dysymtab[24..28].copy_from_slice(&2u32.to_le_bytes());
    lc_dysymtab[28..32].copy_from_slice(&0u32.to_le_bytes());
    lc_buf.extend_from_slice(&lc_dysymtab);
    total_cmds += 1;
    sizeofcmds += 80;

    let dyld_path = "/usr/lib/dyld\0";
    let dyld_len = dyld_path.len();
    let dyld_cmd_size = align_up_usize(12 + dyld_len, 8);
    let mut lc_dyld = vec![0u8; dyld_cmd_size];
    lc_dyld[0..4].copy_from_slice(&LC_LOAD_DYLINKER.to_le_bytes());
    lc_dyld[4..8].copy_from_slice(&(dyld_cmd_size as u32).to_le_bytes());
    lc_dyld[8..12].copy_from_slice(&12u32.to_le_bytes());
    lc_dyld[12..12 + dyld_len - 1].copy_from_slice(&dyld_path.as_bytes()[..dyld_len - 1]);
    lc_buf.extend_from_slice(&lc_dyld);
    total_cmds += 1;
    sizeofcmds += dyld_cmd_size as u32;

    let mut lc_uuid = [0u8; 24];
    lc_uuid[0..4].copy_from_slice(&LC_UUID.to_le_bytes());
    lc_uuid[4..8].copy_from_slice(&24u32.to_le_bytes());
    lc_uuid[8..24].copy_from_slice(&default_uuid());
    lc_buf.extend_from_slice(&lc_uuid);
    total_cmds += 1;
    sizeofcmds += 24;

    let mut lc_build = [0u8; 32];
    lc_build[0..4].copy_from_slice(&LC_BUILD_VERSION.to_le_bytes());
    lc_build[4..8].copy_from_slice(&32u32.to_le_bytes());
    lc_build[8..12].copy_from_slice(&1u32.to_le_bytes());
    lc_build[12..16].copy_from_slice(&0x001A0000u32.to_le_bytes());
    lc_build[16..20].copy_from_slice(&0x001A0200u32.to_le_bytes());
    lc_build[20..24].copy_from_slice(&1u32.to_le_bytes());
    lc_build[24..28].copy_from_slice(&3u32.to_le_bytes());
    lc_build[28..32].copy_from_slice(&0x04CE0100u32.to_le_bytes());
    lc_buf.extend_from_slice(&lc_build);
    total_cmds += 1;
    sizeofcmds += 32;

    let entry_offset = (entry + PAGE_SIZE as u64).saturating_sub(text_vmaddr);
    let mut lc_main = vec![0u8; 24];
    lc_main[0..4].copy_from_slice(&LC_MAIN.to_le_bytes());
    lc_main[4..8].copy_from_slice(&24u32.to_le_bytes());
    lc_main[8..16].copy_from_slice(&entry_offset.to_le_bytes());
    lc_main[16..24].copy_from_slice(&0u64.to_le_bytes());
    lc_buf.extend_from_slice(&lc_main);
    total_cmds += 1;
    sizeofcmds += 24;

    if dyn_info.needed.is_empty() {
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
    } else {
        for needed in &dyn_info.needed {
            let normalized = if needed == "libSystem.B.dylib" {
                "/usr/lib/libSystem.B.dylib"
            } else {
                needed.as_str()
            };
            let mut path_bytes = normalized.as_bytes().to_vec();
            path_bytes.push(0);
            let lib_cmd_size = align_up_usize(24 + path_bytes.len(), 8);
            let mut lc_lib = vec![0u8; lib_cmd_size];
            lc_lib[0..4].copy_from_slice(&LC_LOAD_DYLIB.to_le_bytes());
            lc_lib[4..8].copy_from_slice(&(lib_cmd_size as u32).to_le_bytes());
            lc_lib[8..12].copy_from_slice(&24u32.to_le_bytes());
            lc_lib[16..20].copy_from_slice(&0x10000u32.to_le_bytes());
            lc_lib[20..24].copy_from_slice(&0x10000u32.to_le_bytes());
            lc_lib[24..24 + path_bytes.len() - 1]
                .copy_from_slice(&path_bytes[..path_bytes.len() - 1]);
            lc_buf.extend_from_slice(&lc_lib);
            total_cmds += 1;
            sizeofcmds += lib_cmd_size as u32;
        }
    }

    {
        let mut lc_dyld_info = vec![0u8; 48];
        lc_dyld_info[0..4].copy_from_slice(&LC_DYLD_INFO_ONLY.to_le_bytes());
        lc_dyld_info[4..8].copy_from_slice(&48u32.to_le_bytes());
        lc_dyld_info[8..12].copy_from_slice(&(dyld_info_off as u32).to_le_bytes());
        lc_dyld_info[12..16].copy_from_slice(&(rebase_opcodes.len() as u32).to_le_bytes());
        lc_dyld_info[16..20].copy_from_slice(&(bind_off as u32).to_le_bytes());
        lc_dyld_info[20..24].copy_from_slice(&(bind_opcodes.len() as u32).to_le_bytes());
        lc_dyld_info[24..28].copy_from_slice(&0u32.to_le_bytes());
        lc_dyld_info[28..32].copy_from_slice(&0u32.to_le_bytes());
        lc_dyld_info[32..36].copy_from_slice(&0u32.to_le_bytes());
        lc_dyld_info[36..40].copy_from_slice(&0u32.to_le_bytes());
        lc_dyld_info[40..44].copy_from_slice(&0u32.to_le_bytes());
        lc_dyld_info[44..48].copy_from_slice(&0u32.to_le_bytes());
        lc_buf.extend_from_slice(&lc_dyld_info);
        total_cmds += 1;
        sizeofcmds += 48;
    }

    let mut hdr = [0u8; 32];
    hdr[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
    hdr[4..8].copy_from_slice(&cputype.to_le_bytes());
    hdr[8..12].copy_from_slice(&0u32.to_le_bytes());
    hdr[12..16].copy_from_slice(&MH_EXECUTABLE.to_le_bytes());
    hdr[16..20].copy_from_slice(&total_cmds.to_le_bytes());
    hdr[20..24].copy_from_slice(&sizeofcmds.to_le_bytes());
    let flags = MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE;
    hdr[24..28].copy_from_slice(&flags.to_le_bytes());
    out.write_all(&hdr)?;
    out.write_all(&lc_buf)?;

    let segment_start = align_up_usize(32 + sizeofcmds as usize, PAGE_SIZE);
    let cmds_end = 32 + sizeofcmds as usize;
    let seg_pad = segment_start.saturating_sub(cmds_end);
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

    {
        out.write_all(&rebase_opcodes)?;
        if bind_pad_len > 0 {
            out.write_all(&vec![0u8; bind_pad_len])?;
        }
        out.write_all(&bind_opcodes)?;
    }
    if symtab_pad_len > 0 {
        out.write_all(&vec![0u8; symtab_pad_len])?;
    }
    out.write_all(&symtab_bytes)?;
    out.write_all(&strtab_bytes)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
