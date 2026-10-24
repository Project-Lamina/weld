//! PE32+ (64-bit Windows) executable emission.

use crate::collections::{HashMap, HashSet};
use crate::link::{DynamicLinkInfo, MergedLayout};
use crate::object::coff_reloc_span;
use std::io::{Result, Write};

const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
const IMAGE_OPTIONAL_HDR64_MAGIC: u16 = 0x020B;
const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;
const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
const IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: u16 = 0x8000;

/// Default image base for 64-bit PE executables (conventional Windows default).
const IMAGE_BASE: u64 = 0x0000_0001_4000_0000;
const SECTION_ALIGN: u64 = 0x1000;
const FILE_ALIGN: u64 = 0x0200;
const SIZEOF_OPTIONAL_HEADER: u16 = 240;
const SIZEOF_SECTION_HEADER: usize = 40;
const SIZEOF_DOS_STUB: usize = 64;
const SIZEOF_PE_SIGNATURE: usize = 4;
const SIZEOF_COFF_HEADER: usize = 20;

/// Number of data directory entries we always write.
const NUM_DATA_DIRS: u32 = 16;
const _DATA_DIR_IMPORT: usize = 1;
const _DATA_DIR_IAT: usize = 12;

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

fn align_up(v: u64, align: u64) -> u64 {
    if align == 0 {
        return v;
    }
    (v + align - 1) & !(align - 1)
}

fn align_up_usize(v: usize, align: usize) -> usize {
    if align == 0 {
        return v;
    }
    (v + align - 1) & !(align - 1)
}

/// Names of symbols that will be imported from the given DLL.
struct ImportEntry<'a> {
    dll_name: &'a str,
    /// (hint, symbol_name) pairs.  hint=0 is fine for ExitProcess etc.
    symbols: Vec<(u16, &'a str)>,
}

/// Build the raw bytes for a minimal .rdata import section and return
/// `(bytes, import_dir_rva_relative, iat_rva_relative, size_of_import_dir, size_of_iat)`
/// where the RVAs are *relative to the start of the .rdata section*.
///
/// `rdata_rva` is the RVA (relative to image base) of the .rdata section.
fn build_import_section(
    rdata_rva: u64,
    entries: &[ImportEntry<'_>],
) -> (Vec<u8>, u32, u32, u32, u32) {
    // Import Directory Table (IDT): (entries.len() + 1) * 20 bytes (null-terminated)
    // Import Lookup Table (ILT) for each DLL: (symbols.len() + 1) * 8 bytes
    // Import Address Table (IAT): same layout as ILT

    let num_dlls = entries.len();
    let idt_size = (num_dlls + 1) * 20;

    // Compute per-DLL ILT offsets (each ILT immediately follows the IDT).
    let mut ilt_offsets: Vec<usize> = Vec::with_capacity(num_dlls);
    let mut ilt_total_size = 0usize;
    for e in entries {
        ilt_offsets.push(idt_size + ilt_total_size);
        ilt_total_size += (e.symbols.len() + 1) * 8;
    }

    let iat_base_off = idt_size + ilt_total_size;
    let mut iat_offsets: Vec<usize> = Vec::with_capacity(num_dlls);
    let mut iat_total_size = 0usize;
    for e in entries {
        iat_offsets.push(iat_base_off + iat_total_size);
        iat_total_size += (e.symbols.len() + 1) * 8;
    }

    let hint_names_base = iat_base_off + iat_total_size;
    let mut hint_name_offsets: Vec<Vec<usize>> = Vec::with_capacity(num_dlls);
    let mut hint_name_cursor = hint_names_base;
    for e in entries {
        let mut sym_offs = Vec::with_capacity(e.symbols.len());
        for (_, name) in &e.symbols {
            sym_offs.push(hint_name_cursor);
            hint_name_cursor += 2 + name.len() + 1; // hint(u16) + name + NUL
            // DWORD-align each IMAGE_IMPORT_BY_NAME
            hint_name_cursor = align_up_usize(hint_name_cursor, 2);
        }
        hint_name_offsets.push(sym_offs);
    }

    let dll_name_base = hint_name_cursor;
    let mut dll_name_offsets: Vec<usize> = Vec::with_capacity(num_dlls);
    let mut dll_name_cursor = dll_name_base;
    for e in entries {
        dll_name_offsets.push(dll_name_cursor);
        dll_name_cursor += e.dll_name.len() + 1;
    }

    let total_size = align_up_usize(dll_name_cursor, FILE_ALIGN as usize);
    let mut buf = vec![0u8; total_size];

    let section_rva = rdata_rva as u32;

    for (di, _e) in entries.iter().enumerate() {
        let base = di * 20;
        let ilt_rva = section_rva + ilt_offsets[di] as u32;
        let iat_rva = section_rva + iat_offsets[di] as u32;
        let name_rva = section_rva + dll_name_offsets[di] as u32;

        buf[base..base + 4].copy_from_slice(&ilt_rva.to_le_bytes()); // OriginalFirstThunk
        buf[base + 12..base + 16].copy_from_slice(&name_rva.to_le_bytes()); // Name
        buf[base + 16..base + 20].copy_from_slice(&iat_rva.to_le_bytes()); // FirstThunk
    }

    for (di, e) in entries.iter().enumerate() {
        for (si, _) in e.symbols.iter().enumerate() {
            let hint_name_rva = section_rva + hint_name_offsets[di][si] as u32;
            let thunk: u64 = hint_name_rva as u64; // bit 63 = 0 → by name
            let ilt_off = ilt_offsets[di] + si * 8;
            let iat_off = iat_offsets[di] + si * 8;
            buf[ilt_off..ilt_off + 8].copy_from_slice(&thunk.to_le_bytes());
            buf[iat_off..iat_off + 8].copy_from_slice(&thunk.to_le_bytes());
        }
    }

    for (di, e) in entries.iter().enumerate() {
        for (si, (hint, name)) in e.symbols.iter().enumerate() {
            let off = hint_name_offsets[di][si];
            buf[off..off + 2].copy_from_slice(&hint.to_le_bytes());
            let name_bytes = name.as_bytes();
            buf[off + 2..off + 2 + name_bytes.len()].copy_from_slice(name_bytes);
        }
    }

    for (di, e) in entries.iter().enumerate() {
        let off = dll_name_offsets[di];
        buf[off..off + e.dll_name.len()].copy_from_slice(e.dll_name.as_bytes());
    }

    let idt_rva = 0u32;
    let iat_rva = iat_base_off as u32;
    let iat_size_u32 = iat_total_size as u32;

    (buf, idt_rva, iat_rva, idt_size as u32, iat_size_u32)
}

struct PeSection {
    name: [u8; 8],
    data: Vec<u8>,
    characteristics: u32,
}

impl PeSection {
    fn new(name: &str, data: Vec<u8>, characteristics: u32) -> Self {
        let mut n = [0u8; 8];
        let b = name.as_bytes();
        n[..b.len().min(8)].copy_from_slice(&b[..b.len().min(8)]);
        Self {
            name: n,
            data,
            characteristics,
        }
    }

    fn virtual_size(&self) -> u32 {
        self.data.len() as u32
    }

    fn raw_size(&self) -> u32 {
        align_up(self.data.len() as u64, FILE_ALIGN) as u32
    }
}

/// Emit a PE32+ (AMD64) console executable.
///
/// `layout`     — merged section layout from the linker.
/// `entry`      — virtual address of the entry point.
/// `dyn_info`   — optional dynamic link info; if provided the `plt_symbols`
///               are added as imports from `kernel32.dll` / stdlib.
pub fn emit_pe_executable(
    layout: &MergedLayout,
    entry: u64,
    dyn_info: Option<&DynamicLinkInfo>,
    out: &mut impl Write,
) -> Result<()> {
    let text_data = layout
        .sections
        .iter()
        .find(|s| s.name == ".text")
        .map(|s| s.data.clone())
        .unwrap_or_default();

    let data_data = layout
        .sections
        .iter()
        .find(|s| s.name == ".data")
        .map(|s| s.data.clone())
        .unwrap_or_default();

    let mut import_symbols: Vec<(u16, String)> = vec![(0, "ExitProcess".to_string())];
    if let Some(dyn_info) = dyn_info {
        for sym in &dyn_info.plt_symbols {
            if sym != "ExitProcess" {
                import_symbols.push((0, sym.clone()));
            }
        }
    }

    let has_data = !data_data.is_empty();
    let num_sections: u16 = if has_data { 3 } else { 2 };

    let headers_raw_size = SIZEOF_DOS_STUB
        + SIZEOF_PE_SIGNATURE
        + SIZEOF_COFF_HEADER
        + SIZEOF_OPTIONAL_HEADER as usize
        + (num_sections as usize) * SIZEOF_SECTION_HEADER;
    let size_of_headers = align_up(headers_raw_size as u64, FILE_ALIGN) as u32;

    // RVAs are relative to IMAGE_BASE.
    let text_rva = align_up(size_of_headers as u64, SECTION_ALIGN) as u32;
    let text_vsize = text_data.len() as u32;
    let text_raw_size = align_up(text_vsize as u64, FILE_ALIGN) as u32;

    let data_rva = if has_data {
        align_up(
            text_rva as u64 + align_up(text_vsize as u64, SECTION_ALIGN),
            SECTION_ALIGN,
        ) as u32
    } else {
        0
    };
    let data_vsize = data_data.len() as u32;
    let data_raw_size = if has_data {
        align_up(data_vsize as u64, FILE_ALIGN) as u32
    } else {
        0
    };

    let rdata_rva = if has_data {
        align_up(
            data_rva as u64 + align_up(data_vsize as u64, SECTION_ALIGN),
            SECTION_ALIGN,
        ) as u32
    } else {
        align_up(
            text_rva as u64 + align_up(text_vsize as u64, SECTION_ALIGN),
            SECTION_ALIGN,
        ) as u32
    };

    let sym_refs: Vec<(u16, &str)> = import_symbols
        .iter()
        .map(|(h, n)| (*h, n.as_str()))
        .collect();
    let entries = [ImportEntry {
        dll_name: "KERNEL32.DLL",
        symbols: sym_refs,
    }];
    let (rdata_bytes, idt_rel_off, iat_rel_off, idt_size_bytes, iat_size_bytes) =
        build_import_section(rdata_rva as u64, &entries);

    let import_dir_rva = rdata_rva + idt_rel_off;
    let iat_rva = rdata_rva + iat_rel_off;
    let rdata_vsize = rdata_bytes.len() as u32;
    let rdata_raw_size = align_up(rdata_vsize as u64, FILE_ALIGN) as u32;

    let last_section_end = rdata_rva as u64 + align_up(rdata_vsize as u64, SECTION_ALIGN);
    let size_of_image = align_up(last_section_end, SECTION_ALIGN) as u32;

    let text_file_off = size_of_headers;
    let data_file_off = text_file_off + text_raw_size;
    let rdata_file_off = if has_data {
        data_file_off + data_raw_size
    } else {
        text_file_off + text_raw_size
    };

    let entry_rva = entry.saturating_sub(IMAGE_BASE) as u32;

    let mut dos = [0u8; SIZEOF_DOS_STUB];
    dos[0] = 0x4D;
    dos[1] = 0x5A;
    // Minimum DOS stub: set e_lfanew at offset 0x3C
    let e_lfanew = SIZEOF_DOS_STUB as u32;
    dos[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
    out.write_all(&dos)?;

    out.write_all(b"PE\0\0")?;

    let mut coff = [0u8; SIZEOF_COFF_HEADER];
    write_u16(&mut coff, 0, IMAGE_FILE_MACHINE_AMD64);
    write_u16(&mut coff, 2, num_sections);
    write_u16(&mut coff, 16, SIZEOF_OPTIONAL_HEADER);
    write_u16(
        &mut coff,
        18,
        IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE,
    );
    out.write_all(&coff)?;

    let mut opt = [0u8; SIZEOF_OPTIONAL_HEADER as usize];
    let mut o = 0usize;

    write_u16_at(&mut opt, &mut o, IMAGE_OPTIONAL_HDR64_MAGIC);
    opt[o] = 14;
    o += 1;
    opt[o] = 0;
    o += 1;
    write_u32_at(&mut opt, &mut o, text_raw_size);
    write_u32_at(&mut opt, &mut o, rdata_raw_size + data_raw_size);
    write_u32_at(&mut opt, &mut o, 0);
    write_u32_at(&mut opt, &mut o, entry_rva);
    write_u32_at(&mut opt, &mut o, text_rva);

    write_u64_at(&mut opt, &mut o, IMAGE_BASE);
    write_u32_at(&mut opt, &mut o, SECTION_ALIGN as u32);
    write_u32_at(&mut opt, &mut o, FILE_ALIGN as u32);
    write_u16_at(&mut opt, &mut o, 6);
    write_u16_at(&mut opt, &mut o, 0);
    write_u16_at(&mut opt, &mut o, 0);
    write_u16_at(&mut opt, &mut o, 0);
    write_u16_at(&mut opt, &mut o, 6);
    write_u16_at(&mut opt, &mut o, 0);
    write_u32_at(&mut opt, &mut o, 0);
    write_u32_at(&mut opt, &mut o, size_of_image);
    write_u32_at(&mut opt, &mut o, size_of_headers);
    write_u32_at(&mut opt, &mut o, 0);
    write_u16_at(&mut opt, &mut o, IMAGE_SUBSYSTEM_WINDOWS_CUI);
    write_u16_at(
        &mut opt,
        &mut o,
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT
            | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            | IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE,
    );
    write_u64_at(&mut opt, &mut o, 0x10_0000);
    write_u64_at(&mut opt, &mut o, 0x1000);
    write_u64_at(&mut opt, &mut o, 0x10_0000);
    write_u64_at(&mut opt, &mut o, 0x1000);
    write_u32_at(&mut opt, &mut o, 0);
    write_u32_at(&mut opt, &mut o, NUM_DATA_DIRS);

    // Index 0: Export table — unused
    write_u32_at(&mut opt, &mut o, 0);
    write_u32_at(&mut opt, &mut o, 0);
    // Index 1: Import table
    write_u32_at(&mut opt, &mut o, import_dir_rva);
    write_u32_at(&mut opt, &mut o, idt_size_bytes);
    // Index 2–11: unused
    for _ in 2..12 {
        write_u32_at(&mut opt, &mut o, 0);
        write_u32_at(&mut opt, &mut o, 0);
    }
    // Index 12: IAT
    write_u32_at(&mut opt, &mut o, iat_rva);
    write_u32_at(&mut opt, &mut o, iat_size_bytes);
    // Index 13–15: unused
    for _ in 13..16 {
        write_u32_at(&mut opt, &mut o, 0);
        write_u32_at(&mut opt, &mut o, 0);
    }

    assert_eq!(
        o, SIZEOF_OPTIONAL_HEADER as usize,
        "optional header size mismatch"
    );
    out.write_all(&opt)?;

    let sections: Vec<PeSection> = {
        let mut v = vec![PeSection::new(
            ".text",
            text_data.clone(),
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        )];
        if has_data {
            v.push(PeSection::new(
                ".data",
                data_data.clone(),
                IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
            ));
        }
        v.push(PeSection::new(
            ".rdata",
            rdata_bytes.clone(),
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        ));
        v
    };

    let sec_rvas = {
        let mut rvas = vec![text_rva];
        if has_data {
            rvas.push(data_rva);
        }
        rvas.push(rdata_rva);
        rvas
    };
    let sec_file_offs = {
        let mut offs = vec![text_file_off];
        if has_data {
            offs.push(data_file_off);
        }
        offs.push(rdata_file_off);
        offs
    };

    for (i, sec) in sections.iter().enumerate() {
        let mut sh = [0u8; SIZEOF_SECTION_HEADER];
        sh[0..8].copy_from_slice(&sec.name);
        sh[8..12].copy_from_slice(&sec.virtual_size().to_le_bytes());
        sh[12..16].copy_from_slice(&sec_rvas[i].to_le_bytes());
        sh[16..20].copy_from_slice(&sec.raw_size().to_le_bytes());
        sh[20..24].copy_from_slice(&sec_file_offs[i].to_le_bytes());
        sh[36..40].copy_from_slice(&sec.characteristics.to_le_bytes());
        out.write_all(&sh)?;
    }

    let header_written = headers_raw_size;
    let padding = size_of_headers as usize - header_written;
    out.write_all(&vec![0u8; padding])?;

    for sec in &sections {
        out.write_all(&sec.data)?;
        let pad = sec.raw_size() as usize - sec.data.len();
        out.write_all(&vec![0u8; pad])?;
    }

    Ok(())
}

const IMAGE_REL_AMD64_ABSOLUTE: u16 = 0x0000;
const IMAGE_REL_AMD64_ADDR32NB: u16 = 0x0003;
const IMAGE_REL_AMD64_ADDR64: u16 = 0x0001;
const IMAGE_REL_AMD64_ADDR32: u16 = 0x0002;
const IMAGE_REL_AMD64_REL32: u16 = 0x0004;
const OPCODE_CALL_REL32: u8 = 0xE8;
const OPCODE_JMP_REL32: u8 = 0xE9;
const IMAGE_REL_BASED_DIR64: u16 = 10;
const BASE_RELOC_PAGE: u32 = 0x1000;
const DATA_DIR_BASE_RELOC: usize = 5;
const DATA_DIR_EXCEPTION: usize = 3;
const PDATA_RECORD_SIZE: usize = 12;
const IMAGE_REL_AMD64_REL32_5: u16 = 0x0009;
const IMAGE_SYM_UNDEFINED_SECTION: i16 = 0;
const IMAGE_SYM_ABSOLUTE_SECTION: i16 = -1;
const IMAGE_SYM_CLASS_EXTERNAL: u8 = 2;
/// Auxiliary record TagIndex names the default symbol used when the weak name
/// has no strong definition anywhere in the link.
const IMAGE_SYM_CLASS_WEAK_EXTERNAL: u8 = 105;
const IMAGE_SYM_DTYPE_FUNCTION: u16 = 0x20;
const IMPORT_SYMBOL_PREFIX: &str = "__imp_";
const IMAGE_SYM_CLASS_STATIC: u8 = 3;
const IMAGE_SCN_LNK_COMDAT: u32 = 0x0000_1000;
const IMAGE_COMDAT_SELECT_NODUPLICATES: u8 = 1;
const IMAGE_COMDAT_SELECT_ANY: u8 = 2;
const IMAGE_COMDAT_SELECT_SAME_SIZE: u8 = 3;
const IMAGE_COMDAT_SELECT_EXACT_MATCH: u8 = 4;
const IMAGE_COMDAT_SELECT_ASSOCIATIVE: u8 = 5;
const IMAGE_COMDAT_SELECT_LARGEST: u8 = 6;
const IMAGE_SCN_LNK_INFO: u32 = 0x0000_0200;
const IMAGE_SCN_LNK_REMOVE: u32 = 0x0000_0800;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
const SIZEOF_COFF_SYMBOL: usize = 18;
const SIZEOF_COFF_SECTION_HEADER: usize = 40;
const SIZEOF_COFF_RELOC: usize = 10;
const CRT_MAIN_SYMBOL: &str = "__main";
const COFF_RET: u8 = 0xC3;

#[derive(Clone)]
struct CoffSymbol {
    name: String,
    section: i16,
    value: u32,
    class: u8,
    typ: u16,
    /// Symbol index of the default symbol, for weak externals.
    tag: usize,
}

#[derive(Clone, Copy)]
enum CoffRegion {
    Text = 0,
    ReadOnly = 1,
    Writable = 2,
    Pdata = 3,
}

#[derive(Clone, Copy)]
struct CoffComdat {
    selection: u8,
    assoc: usize,
}

struct CoffSection<'a> {
    object: usize,
    name: String,
    region: CoffRegion,
    align: usize,
    size: usize,
    raw: &'a [u8],
    relocs: Vec<(u32, u32, u16)>,
    offset: usize,
    comdat: Option<CoffComdat>,
    keep: bool,
}

#[derive(Clone, Copy)]
enum CoffDef {
    Section { index: usize, value: u32 },
    Absolute(u32),
}

fn coff_error(message: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

fn coff_section_align(flags: u32) -> usize {
    match (flags >> 20) & 0xF {
        0 => 1,
        n => 1 << (n - 1),
    }
}

fn rel32(target: u64, end: u64) -> Result<i32> {
    i32::try_from(target as i64 - end as i64)
        .map_err(|_| coff_error("branch target out of 32-bit range".to_string()))
}

/// Windows kernel32.dll API functions. Everything else goes to msvcrt.dll.
fn is_kernel32_symbol(name: &str) -> bool {
    matches!(
        name,
        "ExitProcess"
            | "GetStdHandle"
            | "WriteFile"
            | "WriteConsoleA"
            | "WriteConsoleW"
            | "ReadFile"
            | "CloseHandle"
            | "CreateFileA"
            | "CreateFileW"
            | "VirtualAlloc"
            | "VirtualFree"
            | "GetLastError"
            | "SetLastError"
            | "LoadLibraryA"
            | "GetProcAddress"
            | "FreeLibrary"
            | "HeapAlloc"
            | "HeapFree"
            | "GetProcessHeap"
    )
}

fn coff_read_u16(data: &[u8], off: usize) -> Option<u16> {
    let b = data.get(off..off + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}
fn coff_read_u32(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn coff_symbol_name(name_bytes: &[u8; 8], strtab: &[u8]) -> String {
    if name_bytes[..4] == [0, 0, 0, 0] {
        let off = u32::from_le_bytes([name_bytes[4], name_bytes[5], name_bytes[6], name_bytes[7]])
            as usize;
        if off >= 4 && off < strtab.len() {
            let s = &strtab[off..];
            let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
            return String::from_utf8_lossy(&s[..end]).into_owned();
        }
        return String::new();
    }
    let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
    String::from_utf8_lossy(&name_bytes[..end]).into_owned()
}

/// Section names longer than 8 bytes are stored as `/` followed by the decimal
/// offset of the name in the string table.
fn coff_section_name(raw: &[u8], strtab: &[u8]) -> String {
    if raw[0] == b'/' {
        let digits = raw[1..].split(|&b| b == 0).next().unwrap_or(&[]);
        let offset = std::str::from_utf8(digits)
            .ok()
            .and_then(|d| d.parse::<usize>().ok());
        if let Some(off) = offset.filter(|&off| off >= 4) {
            let s = strtab.get(off..).unwrap_or(&[]);
            let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
            return String::from_utf8_lossy(&s[..end]).into_owned();
        }
    }
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

fn coff_duplicate_symbol(name: &str, first: usize, second: usize) -> std::io::Error {
    coff_error(format!(
        "duplicate symbol {name} defined in object {first} and object {second}"
    ))
}

/// Base relocation blocks: one per 4 KiB page, each with `(type << 12) | offset` entries.
fn build_base_relocs(sites: &[(u32, u16)]) -> Vec<u8> {
    let mut sites = sites.to_vec();
    sites.sort_unstable();
    let mut out = Vec::new();
    let mut i = 0;
    while i < sites.len() {
        let page = sites[i].0 & !(BASE_RELOC_PAGE - 1);
        let mut j = i;
        while j < sites.len() && sites[j].0 & !(BASE_RELOC_PAGE - 1) == page {
            j += 1;
        }
        let mut entries: Vec<u16> = sites[i..j]
            .iter()
            .map(|&(rva, ty)| (ty << 12) | ((rva & (BASE_RELOC_PAGE - 1)) as u16))
            .collect();
        if entries.len() % 2 == 1 {
            entries.push(0);
        }
        out.extend_from_slice(&page.to_le_bytes());
        out.extend_from_slice(&((8 + 2 * entries.len()) as u32).to_le_bytes());
        for entry in entries {
            out.extend_from_slice(&entry.to_le_bytes());
        }
        i = j;
    }
    out
}

/// Parse one COFF object. Sections that are not linked are `None`, so the
/// index of an entry is its section number minus one.
fn parse_coff_object(
    object: usize,
    coff: &[u8],
) -> Result<(Vec<CoffSymbol>, Vec<Option<CoffSection<'_>>>)> {
    let truncated = || coff_error(format!("truncated COFF object {object}"));
    let n_sections = coff_read_u16(coff, 2).ok_or_else(truncated)? as usize;
    let opt_size = coff_read_u16(coff, 16).ok_or_else(truncated)? as usize;
    let sym_table_off = coff_read_u32(coff, 8).ok_or_else(truncated)? as usize;
    let n_syms = coff_read_u32(coff, 12).ok_or_else(truncated)? as usize;

    let strtab_off = sym_table_off + n_syms * SIZEOF_COFF_SYMBOL;
    let strtab: &[u8] = if n_syms == 0 {
        &[]
    } else {
        let strtab_size = coff_read_u32(coff, strtab_off).unwrap_or(4) as usize;
        &coff[strtab_off.min(coff.len())..(strtab_off + strtab_size).min(coff.len())]
    };

    // Indexed by raw table index; auxiliary records get empty names.
    let mut syms: Vec<CoffSymbol> = Vec::with_capacity(n_syms);
    let mut section_aux: HashMap<usize, (u8, usize)> = HashMap::default();
    let mut i = 0;
    while i < n_syms {
        let rec = sym_table_off + i * SIZEOF_COFF_SYMBOL;
        let Some(r) = coff.get(rec..rec + SIZEOF_COFF_SYMBOL) else {
            break;
        };
        let name_bytes: &[u8; 8] = r[..8].try_into().unwrap_or(&[0u8; 8]);
        let num_aux = r[17] as usize;
        let section = i16::from_le_bytes([r[12], r[13]]);
        if r[16] == IMAGE_SYM_CLASS_STATIC && section > 0 && num_aux > 0 {
            let aux_at = rec + SIZEOF_COFF_SYMBOL;
            if let (Some(&selection), Some(number)) =
                (coff.get(aux_at + 14), coff_read_u16(coff, aux_at + 12))
            {
                section_aux.insert(section as usize, (selection, number as usize));
            }
        }
        syms.push(CoffSymbol {
            name: coff_symbol_name(name_bytes, strtab),
            section,
            value: u32::from_le_bytes([r[8], r[9], r[10], r[11]]),
            class: r[16],
            typ: u16::from_le_bytes([r[14], r[15]]),
            tag: if r[16] == IMAGE_SYM_CLASS_WEAK_EXTERNAL {
                coff_read_u32(coff, rec + SIZEOF_COFF_SYMBOL).unwrap_or(0) as usize
            } else {
                0
            },
        });
        for _ in 0..num_aux {
            syms.push(CoffSymbol {
                name: String::new(),
                section: IMAGE_SYM_UNDEFINED_SECTION,
                value: 0,
                class: 0,
                typ: 0,
                tag: 0,
            });
        }
        i += 1 + num_aux;
    }

    let mut sections: Vec<Option<CoffSection>> = Vec::with_capacity(n_sections);
    for s in 0..n_sections {
        let sh = 20 + opt_size + s * SIZEOF_COFF_SECTION_HEADER;
        let flags = coff_read_u32(coff, sh + 36).ok_or_else(truncated)?;
        if flags & (IMAGE_SCN_LNK_INFO | IMAGE_SCN_LNK_REMOVE | IMAGE_SCN_MEM_DISCARDABLE) != 0 {
            sections.push(None);
            continue;
        }
        let raw_size = coff_read_u32(coff, sh + 16).ok_or_else(truncated)? as usize;
        let raw_ptr = coff_read_u32(coff, sh + 20).ok_or_else(truncated)? as usize;
        let relocs_ptr = coff_read_u32(coff, sh + 24).ok_or_else(truncated)? as usize;
        let n_relocs = coff_read_u16(coff, sh + 32).ok_or_else(truncated)?;
        let name = coff_section_name(&coff[sh..sh + 8], strtab);

        let uninitialized = flags & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0;
        let region = if name == ".pdata" || name.starts_with(".pdata$") {
            CoffRegion::Pdata
        } else if flags & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) != 0 {
            CoffRegion::Text
        } else if uninitialized || flags & IMAGE_SCN_MEM_WRITE != 0 {
            CoffRegion::Writable
        } else {
            CoffRegion::ReadOnly
        };
        let raw: &[u8] = if uninitialized {
            &[]
        } else {
            coff.get(raw_ptr..raw_ptr + raw_size)
                .ok_or_else(|| coff_error(format!("section {name} data lies outside the object")))?
        };

        let (relocs_at, n_relocs) =
            coff_reloc_span(coff, relocs_ptr, n_relocs, flags).ok_or_else(truncated)?;
        let mut relocs = Vec::with_capacity(n_relocs);
        for r in 0..n_relocs {
            let o = relocs_at + r * SIZEOF_COFF_RELOC;
            let rec = coff.get(o..o + SIZEOF_COFF_RELOC).ok_or_else(|| {
                coff_error(format!(
                    "relocations of section {name} lie outside the object"
                ))
            })?;
            relocs.push((
                u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]),
                u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]),
                u16::from_le_bytes([rec[8], rec[9]]),
            ));
        }

        let comdat = (flags & IMAGE_SCN_LNK_COMDAT != 0).then(|| {
            let (selection, assoc) = section_aux
                .get(&(s + 1))
                .copied()
                .unwrap_or((IMAGE_COMDAT_SELECT_ANY, 0));
            CoffComdat { selection, assoc }
        });
        sections.push(Some(CoffSection {
            object,
            name,
            region,
            align: coff_section_align(flags),
            size: raw_size,
            raw,
            relocs,
            offset: 0,
            comdat,
            keep: true,
        }));
    }
    Ok((syms, sections))
}

/// Link COFF objects and emit a PE32+ executable directly.
///
/// Code sections go to `.text`, read-only data to `.rdata`, writable and
/// uninitialized data to `.data`. Undefined externals get `jmp [iat]` thunks.
pub fn link_and_emit_pe_from_coffs(objects: &[&[u8]], out: &mut impl Write) -> Result<()> {
    let mut syms_of: Vec<Vec<CoffSymbol>> = Vec::with_capacity(objects.len());
    let mut slot_of: Vec<Vec<Option<usize>>> = Vec::with_capacity(objects.len());
    let mut sections: Vec<CoffSection> = Vec::new();
    for (oi, coff) in objects.iter().enumerate() {
        let (syms, parsed) = parse_coff_object(oi, coff)?;
        let mut slots = Vec::with_capacity(parsed.len());
        for sec in parsed {
            slots.push(sec.map(|s| {
                sections.push(s);
                sections.len() - 1
            }));
        }
        syms_of.push(syms);
        slot_of.push(slots);
    }

    let mut comdat_key: Vec<Option<&str>> = vec![None; sections.len()];
    for (oi, syms) in syms_of.iter().enumerate() {
        for s in syms {
            if s.class != IMAGE_SYM_CLASS_EXTERNAL || s.section <= 0 {
                continue;
            }
            let Some(Some(k)) = slot_of[oi].get(s.section as usize - 1) else {
                continue;
            };
            if sections[*k].comdat.is_some() && comdat_key[*k].is_none() {
                comdat_key[*k] = Some(s.name.as_str());
            }
        }
    }
    let mut comdat_owner: HashMap<&str, usize> = HashMap::default();
    for k in 0..sections.len() {
        let (Some(comdat), Some(key)) = (sections[k].comdat, comdat_key[k]) else {
            continue;
        };
        if comdat.selection == IMAGE_COMDAT_SELECT_ASSOCIATIVE {
            continue;
        }
        match comdat_owner.get(key).copied() {
            None => {
                comdat_owner.insert(key, k);
            }
            Some(first) => {
                let mismatch = |what: &str| {
                    coff_error(format!(
                        "comdat {key} differs in {what} between objects {} and {}",
                        sections[first].object, sections[k].object
                    ))
                };
                match comdat.selection {
                    IMAGE_COMDAT_SELECT_NODUPLICATES => {
                        return Err(coff_duplicate_symbol(
                            key,
                            sections[first].object,
                            sections[k].object,
                        ));
                    }
                    IMAGE_COMDAT_SELECT_SAME_SIZE if sections[first].size != sections[k].size => {
                        return Err(mismatch("size"));
                    }
                    IMAGE_COMDAT_SELECT_EXACT_MATCH if sections[first].raw != sections[k].raw => {
                        return Err(mismatch("contents"));
                    }
                    IMAGE_COMDAT_SELECT_LARGEST if sections[k].size > sections[first].size => {
                        sections[first].keep = false;
                        comdat_owner.insert(key, k);
                        continue;
                    }
                    _ => {}
                }
                sections[k].keep = false;
            }
        }
    }
    loop {
        let mut changed = false;
        for k in 0..sections.len() {
            let Some(CoffComdat {
                selection: IMAGE_COMDAT_SELECT_ASSOCIATIVE,
                assoc,
            }) = sections[k].comdat
            else {
                continue;
            };
            let target_kept = slot_of[sections[k].object]
                .get(assoc.wrapping_sub(1))
                .copied()
                .flatten()
                .is_some_and(|t| sections[t].keep);
            if sections[k].keep && !target_kept {
                sections[k].keep = false;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let mut defs: HashMap<&str, (CoffDef, usize)> = HashMap::default();
    for (oi, syms) in syms_of.iter().enumerate() {
        for s in syms {
            if s.class != IMAGE_SYM_CLASS_EXTERNAL || s.name.is_empty() {
                continue;
            }
            let def = if s.section > 0 {
                match slot_of[oi].get(s.section as usize - 1).copied().flatten() {
                    Some(k) if sections[k].keep => CoffDef::Section {
                        index: k,
                        value: s.value,
                    },
                    _ => continue,
                }
            } else if s.section == IMAGE_SYM_ABSOLUTE_SECTION {
                CoffDef::Absolute(s.value)
            } else {
                continue;
            };
            if let Some(&(_, first)) = defs.get(s.name.as_str()) {
                return Err(coff_duplicate_symbol(&s.name, first, oi));
            }
            defs.insert(s.name.as_str(), (def, oi));
        }
    }

    let mut undefined: Vec<&str> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::default();
    for syms in &syms_of {
        for rec in syms {
            let s = if rec.class == IMAGE_SYM_CLASS_WEAK_EXTERNAL {
                if defs.contains_key(rec.name.as_str()) {
                    continue;
                }
                match syms.get(rec.tag) {
                    Some(default) => default,
                    None => continue,
                }
            } else {
                rec
            };
            if s.section != IMAGE_SYM_UNDEFINED_SECTION
                || s.class != IMAGE_SYM_CLASS_EXTERNAL
                || s.name.is_empty()
                || defs.contains_key(s.name.as_str())
            {
                continue;
            }
            if s.value != 0 {
                return Err(coff_error(format!(
                    "common symbol {} is not supported",
                    s.name
                )));
            }
            let import = match s.name.strip_prefix(IMPORT_SYMBOL_PREFIX) {
                Some(base) => {
                    if defs.contains_key(base) {
                        return Err(coff_error(format!(
                            "{IMPORT_SYMBOL_PREFIX}{base} refers to a symbol defined in this link; \
                             pointer slots for local symbols are not supported"
                        )));
                    }
                    base
                }
                None => {
                    if s.name == CRT_MAIN_SYMBOL {
                        return Err(coff_error(format!(
                            "undefined {CRT_MAIN_SYMBOL}: it runs global constructors from libgcc and weld \
                             cannot supply it; link a runtime that defines it"
                        )));
                    }
                    s.name.as_str()
                }
            };
            if seen.insert(import) {
                undefined.push(import);
            }
        }
    }
    let thunk_index: HashMap<&str, usize> =
        undefined.iter().enumerate().map(|(i, n)| (*n, i)).collect();

    let mut region_len = [0usize; 4];
    for sec in sections.iter_mut().filter(|sec| sec.keep) {
        let r = sec.region as usize;
        let align = match sec.region {
            CoffRegion::Pdata => {
                if sec.size % PDATA_RECORD_SIZE != 0 {
                    return Err(coff_error(format!(
                        "{} in object {} is not a whole number of exception records",
                        sec.name, sec.object
                    )));
                }
                1
            }
            _ => sec.align,
        };
        region_len[r] = align_up_usize(region_len[r], align);
        sec.offset = region_len[r];
        region_len[r] += sec.size;
    }

    let needs_main_stub = false;
    let thunks_off = region_len[CoffRegion::Text as usize];
    let stub_off = thunks_off + undefined.len() * 6;
    let text_size = stub_off + usize::from(needs_main_stub);

    let has_data = region_len[CoffRegion::Writable as usize] > 0;
    let has_pdata = region_len[CoffRegion::Pdata as usize] > 0;
    let has_base_relocs = sections.iter().any(|sec| {
        sec.keep
            && sec
                .relocs
                .iter()
                .any(|&(_, _, t)| t == IMAGE_REL_AMD64_ADDR64 || t == IMAGE_REL_AMD64_ADDR32)
    });
    let n_regions = 2 + usize::from(has_data) + usize::from(has_pdata);
    let n_out_sections = n_regions + usize::from(has_base_relocs);
    let headers_raw: usize = SIZEOF_DOS_STUB
        + SIZEOF_PE_SIGNATURE
        + SIZEOF_COFF_HEADER
        + SIZEOF_OPTIONAL_HEADER as usize
        + n_out_sections * SIZEOF_SECTION_HEADER;
    let size_of_headers = align_up(headers_raw as u64, FILE_ALIGN) as u32;
    let text_rva = align_up(size_of_headers as u64, SECTION_ALIGN) as u32;
    let rdata_rva = text_rva + align_up(text_size as u64, SECTION_ALIGN) as u32;

    let kernel32_syms: Vec<&str> = undefined
        .iter()
        .copied()
        .filter(|n| is_kernel32_symbol(n))
        .collect();
    let has_exit_process = kernel32_syms.contains(&"ExitProcess");
    let mut k32_syms: Vec<&str> = if has_exit_process {
        kernel32_syms.clone()
    } else {
        let mut v = vec!["ExitProcess"];
        v.extend(kernel32_syms.iter().copied());
        v
    };
    k32_syms.dedup();

    let ucrt_syms: Vec<&str> = undefined
        .iter()
        .copied()
        .filter(|n| !is_kernel32_symbol(n))
        .collect();

    // msvcrt.dll exports plain `printf`; ucrtbase.dll does not.
    let crt_dll_name = "msvcrt.dll";
    let entries = if ucrt_syms.is_empty() {
        vec![ImportEntry {
            dll_name: "KERNEL32.DLL",
            symbols: k32_syms.iter().map(|&n| (0u16, n)).collect(),
        }]
    } else {
        vec![
            ImportEntry {
                dll_name: "KERNEL32.DLL",
                symbols: k32_syms.iter().map(|&n| (0u16, n)).collect(),
            },
            ImportEntry {
                dll_name: crt_dll_name,
                symbols: ucrt_syms.iter().map(|&n| (0u16, n)).collect(),
            },
        ]
    };

    let rdata_import_off = align_up_usize(region_len[CoffRegion::ReadOnly as usize], 16);
    let (import_bytes, idt_off, iat_rel_off, idt_sz, iat_sz) =
        build_import_section(rdata_rva as u64 + rdata_import_off as u64, &entries);
    let import_base_rva = rdata_rva + rdata_import_off as u32;
    let import_dir_rva = import_base_rva + idt_off;
    let iat_rva = import_base_rva + iat_rel_off;

    // IAT structure: all entries for all DLLs, each 8 bytes, null-terminated per DLL.
    // Within the IAT region, entries are ordered: k32_syms (with null), then ucrt_syms (with null).
    fn iat_entry_va(
        rdata_vaddr: u64,
        iat_rel_off: u32,
        dll_idx: usize,
        sym_idx_in_dll: usize,
        dll_sym_counts: &[usize],
    ) -> u64 {
        let mut base_entry = 0usize;
        for count in dll_sym_counts.iter().take(dll_idx) {
            base_entry += count + 1;
        }
        base_entry += sym_idx_in_dll;
        rdata_vaddr + iat_rel_off as u64 + base_entry as u64 * 8
    }

    let dll_sym_counts = vec![k32_syms.len(), ucrt_syms.len()];
    let import_va = IMAGE_BASE + import_base_rva as u64;
    let mut sym_iat_va: HashMap<&str, u64> = HashMap::default();
    for (i, name) in k32_syms.iter().enumerate() {
        sym_iat_va.insert(
            *name,
            iat_entry_va(import_va, iat_rel_off, 0, i, &dll_sym_counts),
        );
    }
    for (i, name) in ucrt_syms.iter().enumerate() {
        sym_iat_va.insert(
            *name,
            iat_entry_va(import_va, iat_rel_off, 1, i, &dll_sym_counts),
        );
    }

    let rdata_len = rdata_import_off + import_bytes.len();
    let data_rva = rdata_rva + align_up(rdata_len as u64, SECTION_ALIGN) as u32;
    let pdata_rva = data_rva
        + align_up(
            region_len[CoffRegion::Writable as usize] as u64,
            SECTION_ALIGN,
        ) as u32;
    let region_rva = [text_rva, rdata_rva, data_rva, pdata_rva];
    let region_size = [
        text_size,
        rdata_len,
        region_len[CoffRegion::Writable as usize],
        region_len[CoffRegion::Pdata as usize],
    ];
    let region_base = [
        0usize,
        (rdata_rva - text_rva) as usize,
        (data_rva - text_rva) as usize,
        (pdata_rva - text_rva) as usize,
    ];
    let mut blob = vec![0u8; region_base[3] + region_size[3]];

    for sec in sections
        .iter()
        .filter(|sec| sec.keep && !sec.raw.is_empty())
    {
        let at = region_base[sec.region as usize] + sec.offset;
        blob[at..at + sec.raw.len()].copy_from_slice(sec.raw);
    }
    let import_at = region_base[1] + rdata_import_off;
    blob[import_at..import_at + import_bytes.len()].copy_from_slice(&import_bytes);

    let thunk_va = |i: usize| IMAGE_BASE + text_rva as u64 + (thunks_off + i * 6) as u64;
    for (i, name) in undefined.iter().enumerate() {
        let at = thunks_off + i * 6;
        let end_va = thunk_va(i) + 6;
        let iat_va = *sym_iat_va
            .get(name)
            .ok_or_else(|| coff_error(format!("no import slot for {name}")))?;
        blob[at..at + 2].copy_from_slice(&[0xFF, 0x25]);
        blob[at + 2..at + 6].copy_from_slice(&rel32(iat_va, end_va)?.to_le_bytes());
    }
    if needs_main_stub {
        blob[stub_off] = COFF_RET;
    }

    let sec_rva = |sec: &CoffSection| region_rva[sec.region as usize] + sec.offset as u32;
    let def_va = |def: CoffDef| -> i64 {
        match def {
            CoffDef::Section { index, value } => {
                IMAGE_BASE as i64 + i64::from(sec_rva(&sections[index])) + i64::from(value)
            }
            CoffDef::Absolute(v) => i64::from(v),
        }
    };
    let is_undefined_external = |sym: &CoffSymbol| {
        sym.section == IMAGE_SYM_UNDEFINED_SECTION
            && sym.class == IMAGE_SYM_CLASS_EXTERNAL
            && !sym.name.is_empty()
    };
    // The flag is true when the value is an image address, which needs a base
    // relocation if it is stored in memory. Absolute symbols are not relocated.
    let resolve =
        |oi: usize, sym_idx: usize, allow_thunk: bool, owner: &str| -> Result<(i64, bool)> {
            let missing =
                |idx: usize| coff_error(format!("{owner} names missing symbol index {idx}"));
            let mut sym_idx = sym_idx;
            let mut sym = syms_of[oi].get(sym_idx).ok_or_else(|| missing(sym_idx))?;
            let mut hops = 0usize;
            while sym.class == IMAGE_SYM_CLASS_WEAK_EXTERNAL {
                if let Some(&(def, _)) = defs.get(sym.name.as_str()) {
                    return Ok(match def {
                        CoffDef::Section { .. } => (def_va(def), true),
                        CoffDef::Absolute(_) => (def_va(def), false),
                    });
                }
                hops += 1;
                if hops > syms_of[oi].len() {
                    return Err(coff_error(format!(
                        "weak external {} forms a cycle",
                        sym.name
                    )));
                }
                sym_idx = sym.tag;
                sym = syms_of[oi].get(sym_idx).ok_or_else(|| missing(sym_idx))?;
            }
            if sym.section > 0 {
                if let Some(k) = slot_of[oi]
                    .get(sym.section as usize - 1)
                    .copied()
                    .flatten()
                    .filter(|&k| sections[k].keep)
                {
                    let va =
                        IMAGE_BASE as i64 + i64::from(sec_rva(&sections[k])) + i64::from(sym.value);
                    return Ok((va, true));
                }
            } else if sym.section == IMAGE_SYM_ABSOLUTE_SECTION {
                return Ok((i64::from(sym.value), false));
            }
            if sym.class == IMAGE_SYM_CLASS_EXTERNAL
                && let Some(&(def, _)) = defs.get(sym.name.as_str())
            {
                return Ok(match def {
                    CoffDef::Section { .. } => (def_va(def), true),
                    CoffDef::Absolute(_) => (def_va(def), false),
                });
            }
            if is_undefined_external(sym) {
                if let Some(base) = sym.name.strip_prefix(IMPORT_SYMBOL_PREFIX) {
                    return sym_iat_va
                        .get(base)
                        .map(|&va| (va as i64, true))
                        .ok_or_else(|| coff_error(format!("no import slot for {base}")));
                }
                if allow_thunk && let Some(&i) = thunk_index.get(sym.name.as_str()) {
                    return Ok((thunk_va(i) as i64, true));
                }
                return Err(coff_error(format!(
                    "undefined symbol {} referenced from {owner} as data or a function address; \
                 import it through {IMPORT_SYMBOL_PREFIX}{}",
                    sym.name, sym.name
                )));
            }
            Err(coff_error(format!(
                "unresolved symbol {} referenced from {owner}",
                sym.name
            )))
        };

    let mut base_relocs: Vec<(u32, u16)> = Vec::new();
    for sec in sections.iter().filter(|sec| sec.keep) {
        let base = region_base[sec.region as usize] + sec.offset;
        for &(vaddr, sym_idx, rel_type) in &sec.relocs {
            if rel_type == IMAGE_REL_AMD64_ABSOLUTE {
                continue;
            }
            let width = if rel_type == IMAGE_REL_AMD64_ADDR64 {
                8
            } else {
                4
            };
            let field = vaddr as usize;
            if field + width > sec.size {
                return Err(coff_error(format!(
                    "relocation at {field:#x} lies outside section {}",
                    sec.name
                )));
            }
            let at = base + field;
            let p_va = IMAGE_BASE as i64 + i64::from(text_rva) + at as i64;
            let site_rva = text_rva + at as u32;
            let addend = if width == 8 {
                i64::from_le_bytes(blob[at..at + 8].try_into().unwrap())
            } else {
                i64::from(i32::from_le_bytes(blob[at..at + 4].try_into().unwrap()))
            };
            let object = sec.object;
            let call_site = matches!(rel_type, IMAGE_REL_AMD64_REL32..=IMAGE_REL_AMD64_REL32_5)
                && matches!(
                    field.checked_sub(1).and_then(|p| sec.raw.get(p)),
                    Some(&(OPCODE_CALL_REL32 | OPCODE_JMP_REL32))
                );
            let function_sym = syms_of[object]
                .get(sym_idx as usize)
                .is_some_and(|s| s.typ & 0xF0 == IMAGE_SYM_DTYPE_FUNCTION);
            let allow_thunk = call_site || function_sym;
            match rel_type {
                IMAGE_REL_AMD64_REL32..=IMAGE_REL_AMD64_REL32_5 => {
                    let (target, _) = resolve(object, sym_idx as usize, allow_thunk, &sec.name)?;
                    let trailing = i64::from(rel_type - IMAGE_REL_AMD64_REL32);
                    let v = target + addend - (p_va + 4 + trailing);
                    let v = i32::try_from(v)
                        .map_err(|_| coff_error(format!("REL32 out of range in {}", sec.name)))?;
                    blob[at..at + 4].copy_from_slice(&v.to_le_bytes());
                }
                IMAGE_REL_AMD64_ADDR64 => {
                    let (target, image_addr) =
                        resolve(object, sym_idx as usize, allow_thunk, &sec.name)?;
                    let v = (target + addend) as u64;
                    blob[at..at + 8].copy_from_slice(&v.to_le_bytes());
                    if image_addr {
                        base_relocs.push((site_rva, IMAGE_REL_BASED_DIR64));
                    }
                }
                IMAGE_REL_AMD64_ADDR32 => {
                    // The loader adds its base delta to these 32 bits only, so the stored
                    // value is a usable pointer only while the image stays below 4 GiB.
                    // ASLR does not guarantee that, and MSVC does not emit ADDR32 for x64.
                    return Err(coff_error(format!(
                        "ADDR32 relocation in {}: use ADDR32NB or ADDR64",
                        sec.name
                    )));
                }
                IMAGE_REL_AMD64_ADDR32NB => {
                    let (target, _) = resolve(object, sym_idx as usize, false, &sec.name)?;
                    let v = target - IMAGE_BASE as i64 + addend;
                    let v = u32::try_from(v).map_err(|_| {
                        coff_error(format!("ADDR32NB out of range in {}", sec.name))
                    })?;
                    blob[at..at + 4].copy_from_slice(&v.to_le_bytes());
                }
                other => {
                    return Err(coff_error(format!(
                        "unsupported relocation type {other:#06x} in section {}",
                        sec.name
                    )));
                }
            }
        }
    }

    if has_pdata {
        let at = region_base[3];
        let (chunks, _) = blob[at..at + region_size[3]].as_chunks::<PDATA_RECORD_SIZE>();
        let mut records: Vec<[u8; PDATA_RECORD_SIZE]> = chunks.to_vec();
        records.sort_by_key(|rec| u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]));
        for (i, rec) in records.iter().enumerate() {
            let off = at + i * PDATA_RECORD_SIZE;
            blob[off..off + PDATA_RECORD_SIZE].copy_from_slice(rec);
        }
    }

    let entry_sym = syms_of.iter().enumerate().find_map(|(oi, syms)| {
        syms.iter()
            .position(|s| s.section > 0 && (s.name == "main" || s.name == "_main"))
            .map(|i| (oi, i))
    });
    let entry_va = match entry_sym {
        Some((oi, i)) => resolve(oi, i, false, "entry point")?.0 as u64,
        None => IMAGE_BASE + text_rva as u64,
    };

    let mut pe_sections = vec![
        PeSection::new(
            ".text",
            blob[..text_size].to_vec(),
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        ),
        PeSection::new(
            ".rdata",
            blob[region_base[1]..region_base[1] + rdata_len].to_vec(),
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        ),
    ];
    let mut sec_rvas: Vec<u32> = vec![text_rva, rdata_rva];
    if has_data {
        let at = region_base[2];
        pe_sections.push(PeSection::new(
            ".data",
            blob[at..at + region_size[2]].to_vec(),
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        ));
        sec_rvas.push(data_rva);
    }
    if has_pdata {
        let at = region_base[3];
        pe_sections.push(PeSection::new(
            ".pdata",
            blob[at..at + region_size[3]].to_vec(),
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        ));
        sec_rvas.push(pdata_rva);
    }
    let pdata_dir = if has_pdata {
        (pdata_rva, region_size[3] as u32)
    } else {
        (0, 0)
    };
    let regions_end = pdata_rva as u64 + align_up(region_size[3] as u64, SECTION_ALIGN);
    let mut image_end = regions_end;
    let mut base_reloc_dir = (0u32, 0u32);
    if !base_relocs.is_empty() {
        let bytes = build_base_relocs(&base_relocs);
        base_reloc_dir = (regions_end as u32, bytes.len() as u32);
        sec_rvas.push(regions_end as u32);
        image_end += align_up(bytes.len() as u64, SECTION_ALIGN);
        pe_sections.push(PeSection::new(
            ".reloc",
            bytes,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE,
        ));
    }
    let mut sec_file_offs = Vec::with_capacity(pe_sections.len());
    let mut file_off = size_of_headers;
    for sec in &pe_sections {
        sec_file_offs.push(file_off);
        file_off += sec.raw_size();
    }
    let size_of_image = align_up(image_end, SECTION_ALIGN) as u32;

    emit_pe_raw(
        out,
        &pe_sections,
        &sec_rvas,
        &sec_file_offs,
        size_of_headers,
        size_of_image,
        entry_va,
        import_dir_rva,
        iat_rva,
        idt_sz,
        iat_sz,
        base_reloc_dir,
        pdata_dir,
    )
}

#[allow(clippy::too_many_arguments)]
fn emit_pe_raw(
    out: &mut impl Write,
    sections: &[PeSection],
    sec_rvas: &[u32],
    sec_file_offs: &[u32],
    size_of_headers: u32,
    size_of_image: u32,
    entry_va: u64,
    import_dir_rva: u32,
    iat_rva: u32,
    idt_size: u32,
    iat_size: u32,
    base_reloc_dir: (u32, u32),
    pdata_dir: (u32, u32),
) -> Result<()> {
    let mut dos = [0u8; SIZEOF_DOS_STUB];
    dos[0] = b'M';
    dos[1] = b'Z';
    let e_lfanew = SIZEOF_DOS_STUB as u32;
    dos[60..64].copy_from_slice(&e_lfanew.to_le_bytes());
    out.write_all(&dos)?;

    out.write_all(b"PE\0\0")?;

    let n_sec = sections.len() as u16;
    let mut coff_hdr = [0u8; SIZEOF_COFF_HEADER];
    coff_hdr[0..2].copy_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
    coff_hdr[2..4].copy_from_slice(&n_sec.to_le_bytes());
    coff_hdr[16..18].copy_from_slice(&SIZEOF_OPTIONAL_HEADER.to_le_bytes());
    let characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    coff_hdr[18..20].copy_from_slice(&characteristics.to_le_bytes());
    out.write_all(&coff_hdr)?;

    let mut opt = [0u8; SIZEOF_OPTIONAL_HEADER as usize];
    let entry_rva = (entry_va - IMAGE_BASE) as u32;
    let text_rva = sec_rvas[0];
    write_u16(&mut opt, 0, IMAGE_OPTIONAL_HDR64_MAGIC);
    let raw_sum = |flag: u32| -> u32 {
        sections
            .iter()
            .filter(|sec| sec.characteristics & flag != 0)
            .map(|sec| sec.raw_size())
            .sum()
    };
    write_u32_at_off(&mut opt, 4, raw_sum(IMAGE_SCN_CNT_CODE));
    write_u32_at_off(&mut opt, 8, raw_sum(IMAGE_SCN_CNT_INITIALIZED_DATA));
    write_u32_at_off(&mut opt, 16, entry_rva);
    write_u32_at_off(&mut opt, 20, text_rva);
    write_u64_at_off(&mut opt, 24, IMAGE_BASE);
    write_u32_at_off(&mut opt, 32, SECTION_ALIGN as u32);
    write_u32_at_off(&mut opt, 36, FILE_ALIGN as u32);
    write_u16_at_off(&mut opt, 40, 6);
    write_u16_at_off(&mut opt, 44, 0);
    write_u16_at_off(&mut opt, 48, 6);
    write_u32_at_off(&mut opt, 56, size_of_image);
    write_u32_at_off(&mut opt, 60, size_of_headers);
    write_u16_at_off(&mut opt, 68, IMAGE_SUBSYSTEM_WINDOWS_CUI);
    let dll_chars = IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        | IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE;
    write_u16_at_off(&mut opt, 70, dll_chars);
    write_u64_at_off(&mut opt, 72, 0x100000);
    write_u64_at_off(&mut opt, 80, 0x1000);
    write_u64_at_off(&mut opt, 88, 0x100000);
    write_u64_at_off(&mut opt, 96, 0x1000);
    write_u32_at_off(&mut opt, 108, NUM_DATA_DIRS);
    // Data directories start at offset 112. Each entry is 8 bytes (RVA + Size).
    // Index 1 = Import Directory Table, index 12 = Import Address Table.
    write_u32_at_off(&mut opt, 112 + 8, import_dir_rva);
    write_u32_at_off(&mut opt, 112 + 8 + 4, idt_size);
    write_u32_at_off(&mut opt, 112 + 12 * 8, iat_rva);
    write_u32_at_off(&mut opt, 112 + 12 * 8 + 4, iat_size);
    write_u32_at_off(&mut opt, 112 + DATA_DIR_BASE_RELOC * 8, base_reloc_dir.0);
    write_u32_at_off(
        &mut opt,
        112 + DATA_DIR_BASE_RELOC * 8 + 4,
        base_reloc_dir.1,
    );
    write_u32_at_off(&mut opt, 112 + DATA_DIR_EXCEPTION * 8, pdata_dir.0);
    write_u32_at_off(&mut opt, 112 + DATA_DIR_EXCEPTION * 8 + 4, pdata_dir.1);
    out.write_all(&opt)?;

    for (i, sec) in sections.iter().enumerate() {
        let mut sh = [0u8; SIZEOF_SECTION_HEADER];
        sh[0..8].copy_from_slice(&sec.name);
        let vsize = sec.data.len() as u32;
        let raw_size = align_up(vsize as u64, FILE_ALIGN) as u32;
        sh[8..12].copy_from_slice(&vsize.to_le_bytes());
        sh[12..16].copy_from_slice(&sec_rvas[i].to_le_bytes());
        sh[16..20].copy_from_slice(&raw_size.to_le_bytes());
        sh[20..24].copy_from_slice(&sec_file_offs[i].to_le_bytes());
        sh[36..40].copy_from_slice(&sec.characteristics.to_le_bytes());
        out.write_all(&sh)?;
    }

    let headers_written = SIZEOF_DOS_STUB
        + SIZEOF_PE_SIGNATURE
        + SIZEOF_COFF_HEADER
        + SIZEOF_OPTIONAL_HEADER as usize
        + sections.len() * SIZEOF_SECTION_HEADER;
    let pad = size_of_headers as usize - headers_written;
    out.write_all(&vec![0u8; pad])?;

    for sec in sections {
        let raw_size = align_up(sec.data.len() as u64, FILE_ALIGN) as usize;
        out.write_all(&sec.data)?;
        out.write_all(&vec![0u8; raw_size - sec.data.len()])?;
    }

    Ok(())
}

fn write_u32_at_off(buf: &mut [u8], off: usize, v: u32) {
    if off + 4 <= buf.len() {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
}
fn write_u16_at_off(buf: &mut [u8], off: usize, v: u16) {
    if off + 2 <= buf.len() {
        buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
}
fn write_u64_at_off(buf: &mut [u8], off: usize, v: u64) {
    if off + 8 <= buf.len() {
        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
}

fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn write_u16_at(buf: &mut [u8], cursor: &mut usize, v: u16) {
    buf[*cursor..*cursor + 2].copy_from_slice(&v.to_le_bytes());
    *cursor += 2;
}

fn write_u32_at(buf: &mut [u8], cursor: &mut usize, v: u32) {
    buf[*cursor..*cursor + 4].copy_from_slice(&v.to_le_bytes());
    *cursor += 4;
}

fn write_u64_at(buf: &mut [u8], cursor: &mut usize, v: u64) {
    buf[*cursor..*cursor + 8].copy_from_slice(&v.to_le_bytes());
    *cursor += 8;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::MergedSection;

    fn minimal_layout() -> (MergedLayout, u64) {
        let text_rva = align_up(512, SECTION_ALIGN) as u32;
        let entry = IMAGE_BASE + text_rva as u64;

        let layout = MergedLayout {
            sections: vec![MergedSection {
                entsize: 0,
                sh_type: 1,
                name: ".text".to_string(),
                data: vec![0xC3],
                vaddr: entry,
                flags: 0,
                align: 16,
            }],
            section_by_name: {
                let mut m = HashMap::default();
                m.insert(".text".to_string(), 0);
                m
            },
        };
        (layout, entry)
    }

    #[test]
    fn test_emit_pe_produces_mz_magic() {
        let (layout, entry) = minimal_layout();
        let mut buf = Vec::new();
        emit_pe_executable(&layout, entry, None, &mut buf).unwrap();
        assert_eq!(&buf[0..2], b"MZ", "DOS MZ magic missing");
    }

    #[test]
    fn test_emit_pe_has_pe_signature() {
        let (layout, entry) = minimal_layout();
        let mut buf = Vec::new();
        emit_pe_executable(&layout, entry, None, &mut buf).unwrap();
        let e_lfanew = u32::from_le_bytes(buf[0x3C..0x40].try_into().unwrap()) as usize;
        assert_eq!(
            &buf[e_lfanew..e_lfanew + 4],
            b"PE\0\0",
            "PE signature missing"
        );
    }

    #[test]
    fn test_emit_pe_machine_type() {
        let (layout, entry) = minimal_layout();
        let mut buf = Vec::new();
        emit_pe_executable(&layout, entry, None, &mut buf).unwrap();
        let e_lfanew = u32::from_le_bytes(buf[0x3C..0x40].try_into().unwrap()) as usize;
        let machine = u16::from_le_bytes(buf[e_lfanew + 4..e_lfanew + 6].try_into().unwrap());
        assert_eq!(
            machine, IMAGE_FILE_MACHINE_AMD64,
            "machine type should be AMD64"
        );
    }

    #[test]
    fn test_emit_pe_optional_magic() {
        let (layout, entry) = minimal_layout();
        let mut buf = Vec::new();
        emit_pe_executable(&layout, entry, None, &mut buf).unwrap();
        let e_lfanew = u32::from_le_bytes(buf[0x3C..0x40].try_into().unwrap()) as usize;
        // Optional header starts at e_lfanew + 4 (PE sig) + 20 (COFF)
        let opt_off = e_lfanew + 4 + 20;
        let magic = u16::from_le_bytes(buf[opt_off..opt_off + 2].try_into().unwrap());
        assert_eq!(
            magic, IMAGE_OPTIONAL_HDR64_MAGIC,
            "optional header magic should be PE32+"
        );
    }

    #[test]
    fn test_emit_pe_file_is_not_empty() {
        let (layout, entry) = minimal_layout();
        let mut buf = Vec::new();
        emit_pe_executable(&layout, entry, None, &mut buf).unwrap();
        assert!(
            buf.len() >= 512,
            "PE file unexpectedly small: {} bytes",
            buf.len()
        );
    }

    struct TestSection<'a> {
        name: &'a str,
        flags: u32,
        data: &'a [u8],
        relocs: &'a [(u32, u32, u16)],
        selection: u8,
        assoc: u16,
    }

    fn push_test_name(o: &mut Vec<u8>, name: &str) {
        let mut bytes = [0u8; 8];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        o.extend_from_slice(&bytes);
    }

    /// Builds a COFF object. Each section gets a section symbol with one
    /// auxiliary record; `symbols` follow them, so the first of them has
    /// index `2 * sections.len()`.
    fn coff_object(sections: &[TestSection], symbols: &[(&str, i16, u8, u32)]) -> Vec<u8> {
        coff_object_with_strtab(sections, symbols, &[])
    }

    /// `strtab_tail` is appended after the 4-byte string table size.
    fn coff_object_with_strtab(
        sections: &[TestSection],
        symbols: &[(&str, i16, u8, u32)],
        strtab_tail: &[u8],
    ) -> Vec<u8> {
        let n = sections.len();
        let mut at = 20 + n * SIZEOF_COFF_SECTION_HEADER;
        let mut raw_ptrs = Vec::new();
        for s in sections {
            raw_ptrs.push(at);
            at += s.data.len();
        }
        let mut reloc_ptrs = Vec::new();
        for s in sections {
            reloc_ptrs.push(at);
            at += s.relocs.len() * SIZEOF_COFF_RELOC;
        }
        let mut o = Vec::new();
        o.extend_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
        o.extend_from_slice(&(n as u16).to_le_bytes());
        o.extend_from_slice(&0u32.to_le_bytes());
        o.extend_from_slice(&(at as u32).to_le_bytes());
        let n_records: usize = symbols
            .iter()
            .map(|&(_, _, class, _)| {
                if class == IMAGE_SYM_CLASS_WEAK_EXTERNAL {
                    2
                } else {
                    1
                }
            })
            .sum();
        o.extend_from_slice(&((2 * n + n_records) as u32).to_le_bytes());
        o.extend_from_slice(&0u16.to_le_bytes());
        o.extend_from_slice(&0u16.to_le_bytes());
        for (i, s) in sections.iter().enumerate() {
            push_test_name(&mut o, s.name);
            o.extend_from_slice(&0u32.to_le_bytes());
            o.extend_from_slice(&0u32.to_le_bytes());
            o.extend_from_slice(&(s.data.len() as u32).to_le_bytes());
            o.extend_from_slice(&(raw_ptrs[i] as u32).to_le_bytes());
            o.extend_from_slice(&(reloc_ptrs[i] as u32).to_le_bytes());
            o.extend_from_slice(&0u32.to_le_bytes());
            o.extend_from_slice(&(s.relocs.len() as u16).to_le_bytes());
            o.extend_from_slice(&0u16.to_le_bytes());
            o.extend_from_slice(&s.flags.to_le_bytes());
        }
        for s in sections {
            o.extend_from_slice(s.data);
        }
        for s in sections {
            for &(vaddr, sym, rel_type) in s.relocs {
                o.extend_from_slice(&vaddr.to_le_bytes());
                o.extend_from_slice(&sym.to_le_bytes());
                o.extend_from_slice(&rel_type.to_le_bytes());
            }
        }
        for (i, s) in sections.iter().enumerate() {
            push_test_name(&mut o, s.name);
            o.extend_from_slice(&0u32.to_le_bytes());
            o.extend_from_slice(&((i + 1) as i16).to_le_bytes());
            o.extend_from_slice(&0u16.to_le_bytes());
            o.push(IMAGE_SYM_CLASS_STATIC);
            o.push(1);
            o.extend_from_slice(&(s.data.len() as u32).to_le_bytes());
            o.extend_from_slice(&(s.relocs.len() as u16).to_le_bytes());
            o.extend_from_slice(&0u16.to_le_bytes());
            o.extend_from_slice(&0u32.to_le_bytes());
            o.extend_from_slice(&s.assoc.to_le_bytes());
            o.push(s.selection);
            o.extend_from_slice(&[0u8; 3]);
        }
        for &(name, section, class, value) in symbols {
            // For a weak external the value is the TagIndex of its default symbol,
            // which is stored in the auxiliary record.
            let weak = class == IMAGE_SYM_CLASS_WEAK_EXTERNAL;
            push_test_name(&mut o, name);
            o.extend_from_slice(&(if weak { 0 } else { value }).to_le_bytes());
            o.extend_from_slice(&section.to_le_bytes());
            o.extend_from_slice(&0u16.to_le_bytes());
            o.push(class);
            o.push(u8::from(weak));
            if weak {
                o.extend_from_slice(&value.to_le_bytes());
                o.extend_from_slice(&3u32.to_le_bytes());
                o.extend_from_slice(&[0u8; 10]);
            }
        }
        o.extend_from_slice(&((4 + strtab_tail.len()) as u32).to_le_bytes());
        o.extend_from_slice(strtab_tail);
        o
    }

    fn pe_section_vsize(out: &[u8], index: usize) -> u32 {
        let e_lfanew = u32::from_le_bytes(out[0x3C..0x40].try_into().unwrap()) as usize;
        let at = e_lfanew
            + 4
            + SIZEOF_COFF_HEADER
            + SIZEOF_OPTIONAL_HEADER as usize
            + index * SIZEOF_SECTION_HEADER;
        u32::from_le_bytes(out[at + 8..at + 12].try_into().unwrap())
    }

    const TEXT_FLAGS: u32 = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    const COMDAT_TEXT_FLAGS: u32 = TEXT_FLAGS | IMAGE_SCN_LNK_COMDAT;

    fn text_section<'a>(data: &'a [u8], relocs: &'a [(u32, u32, u16)]) -> TestSection<'a> {
        TestSection {
            name: ".text",
            flags: TEXT_FLAGS,
            data,
            relocs,
            selection: 0,
            assoc: 0,
        }
    }

    #[test]
    fn test_coff_relocation_into_rdata_resolves() {
        let text = [0x48, 0x8D, 0x0D, 0, 0, 0, 0, 0xC3];
        let relocs = [(3, 2, IMAGE_REL_AMD64_REL32)];
        let coff = coff_object(
            &[
                text_section(&text, &relocs),
                TestSection {
                    name: ".rdata",
                    flags: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
                    data: b"hi\0\0",
                    relocs: &[],
                    selection: 0,
                    assoc: 0,
                },
            ],
            &[("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );

        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[coff.as_slice()], &mut out).expect("links");
        let disp_at = 512 + 3;
        let disp = i32::from_le_bytes(out[disp_at..disp_at + 4].try_into().unwrap());
        assert_eq!(disp, 0x2000 - 0x1007);
        assert_eq!(&out[1024..1027], b"hi\0");
    }

    #[test]
    fn test_coff_objects_link_across_each_other() {
        let call = [0xE8, 0, 0, 0, 0, 0xC3];
        let call_relocs = [(1, 3, IMAGE_REL_AMD64_REL32)];
        let caller = coff_object(
            &[text_section(&call, &call_relocs)],
            &[
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                (
                    "helper",
                    IMAGE_SYM_UNDEFINED_SECTION,
                    IMAGE_SYM_CLASS_EXTERNAL,
                    0,
                ),
            ],
        );
        let body = [0xC3, 0xC3, 0x90, 0xC3];
        let callee = coff_object(
            &[text_section(&body, &[])],
            &[("helper", 1, IMAGE_SYM_CLASS_EXTERNAL, 2)],
        );

        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[caller.as_slice(), callee.as_slice()], &mut out)
            .expect("links");
        let disp = i32::from_le_bytes(out[512 + 1..512 + 5].try_into().unwrap());
        assert_eq!(disp, 3);
    }

    #[test]
    fn test_coff_duplicate_strong_definition_is_error() {
        let body = [0xC3];
        let obj = coff_object(
            &[text_section(&body, &[])],
            &[("dup", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        let mut out = Vec::new();
        let result = link_and_emit_pe_from_coffs(&[obj.as_slice(), obj.as_slice()], &mut out);
        assert!(result.is_err());
    }

    fn comdat_object(body: &[u8], selection: u8) -> Vec<u8> {
        coff_object(
            &[TestSection {
                name: ".text",
                flags: COMDAT_TEXT_FLAGS,
                data: body,
                relocs: &[],
                selection,
                assoc: 0,
            }],
            &[("inl", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        )
    }

    #[test]
    fn test_coff_comdat_largest_keeps_largest_copy() {
        let small = comdat_object(&[0xC3; 4], IMAGE_COMDAT_SELECT_LARGEST);
        let large = comdat_object(&[0x90; 8], IMAGE_COMDAT_SELECT_LARGEST);
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[small.as_slice(), large.as_slice()], &mut out)
            .expect("links");
        assert_eq!(pe_section_vsize(&out, 0), 8);
        assert_eq!(&out[512..520], &[0x90; 8]);

        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[large.as_slice(), small.as_slice()], &mut out)
            .expect("links");
        assert_eq!(pe_section_vsize(&out, 0), 8);
    }

    #[test]
    fn test_coff_comdat_same_size_rejects_different_sizes() {
        let a = comdat_object(&[0xC3; 4], IMAGE_COMDAT_SELECT_SAME_SIZE);
        let b = comdat_object(&[0xC3; 8], IMAGE_COMDAT_SELECT_SAME_SIZE);
        let mut out = Vec::new();
        assert!(link_and_emit_pe_from_coffs(&[a.as_slice(), b.as_slice()], &mut out).is_err());
    }

    #[test]
    fn test_coff_comdat_exact_match_rejects_different_contents() {
        let a = comdat_object(&[0xC3; 4], IMAGE_COMDAT_SELECT_EXACT_MATCH);
        let b = comdat_object(&[0x90; 4], IMAGE_COMDAT_SELECT_EXACT_MATCH);
        let mut out = Vec::new();
        assert!(link_and_emit_pe_from_coffs(&[a.as_slice(), b.as_slice()], &mut out).is_err());
        let same = comdat_object(&[0xC3; 4], IMAGE_COMDAT_SELECT_EXACT_MATCH);
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[a.as_slice(), same.as_slice()], &mut out).expect("links");
    }

    #[test]
    fn test_coff_comdat_is_linked_once() {
        let body = [0xC3; 4];
        let obj = coff_object(
            &[TestSection {
                name: ".text",
                flags: COMDAT_TEXT_FLAGS,
                data: &body,
                relocs: &[],
                selection: IMAGE_COMDAT_SELECT_ANY,
                assoc: 0,
            }],
            &[("inl", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice(), obj.as_slice()], &mut out).expect("links");
        assert_eq!(pe_section_vsize(&out, 0), 4);
    }

    fn pe_section_header(out: &[u8], index: usize) -> &[u8] {
        let e_lfanew = u32::from_le_bytes(out[0x3C..0x40].try_into().unwrap()) as usize;
        let at = e_lfanew
            + 4
            + SIZEOF_COFF_HEADER
            + SIZEOF_OPTIONAL_HEADER as usize
            + index * SIZEOF_SECTION_HEADER;
        &out[at..at + SIZEOF_SECTION_HEADER]
    }

    fn le_u32(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }

    fn pe_data_dir(out: &[u8], index: usize) -> (u32, u32) {
        let e_lfanew = u32::from_le_bytes(out[0x3C..0x40].try_into().unwrap()) as usize;
        let dir = e_lfanew + 24 + 112 + index * 8;
        (le_u32(out, dir), le_u32(out, dir + 4))
    }

    fn pe_base_reloc_dir(out: &[u8]) -> (u32, u32) {
        pe_data_dir(out, DATA_DIR_BASE_RELOC)
    }

    const DATA_FLAGS: u32 =
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    fn absolute_pointer_object(rel_type: u16) -> Vec<u8> {
        let text = [0xC3];
        let data = [0u8; 8];
        let relocs = [(0, 4, rel_type)];
        coff_object(
            &[
                text_section(&text, &[]),
                TestSection {
                    name: ".data",
                    flags: DATA_FLAGS,
                    data: &data,
                    relocs: &relocs,
                    selection: 0,
                    assoc: 0,
                },
            ],
            &[
                ("f", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
            ],
        )
    }

    fn weak_call_caller(default_index: u32) -> Vec<u8> {
        let call = [0xE8, 0, 0, 0, 0, 0xC3];
        coff_object(
            &[text_section(&call, &[(1, 4, IMAGE_REL_AMD64_REL32)])],
            &[
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                (
                    "dflt",
                    IMAGE_SYM_UNDEFINED_SECTION,
                    IMAGE_SYM_CLASS_EXTERNAL,
                    0,
                ),
                (
                    "foo",
                    IMAGE_SYM_UNDEFINED_SECTION,
                    IMAGE_SYM_CLASS_WEAK_EXTERNAL,
                    default_index,
                ),
            ],
        )
    }

    #[test]
    fn test_coff_weak_external_prefers_strong_definition() {
        let caller = weak_call_caller(3);
        let body = [0xC3, 0xC3, 0x90, 0xC3];
        let callee = coff_object(
            &[text_section(&body, &[])],
            &[("foo", 1, IMAGE_SYM_CLASS_EXTERNAL, 2)],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[caller.as_slice(), callee.as_slice()], &mut out)
            .expect("links");
        let disp = i32::from_le_bytes(out[512 + 1..512 + 5].try_into().unwrap());
        assert_eq!(disp, 3);
    }

    #[test]
    fn test_coff_weak_external_falls_back_to_default() {
        let caller = weak_call_caller(3);
        let body = [0xC3, 0xC3, 0x90, 0xC3];
        let callee = coff_object(
            &[text_section(&body, &[])],
            &[("dflt", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[caller.as_slice(), callee.as_slice()], &mut out)
            .expect("links");
        let disp = i32::from_le_bytes(out[512 + 1..512 + 5].try_into().unwrap());
        assert_eq!(disp, 1);
    }

    #[test]
    fn test_coff_weak_external_with_absolute_default_stores_null() {
        let text = [0xC3];
        let data = [0u8; 8];
        let relocs = [(0, 6, IMAGE_REL_AMD64_ADDR64)];
        let obj = coff_object(
            &[
                text_section(&text, &[]),
                TestSection {
                    name: ".data",
                    flags: DATA_FLAGS,
                    data: &data,
                    relocs: &relocs,
                    selection: 0,
                    assoc: 0,
                },
            ],
            &[
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                (
                    "zero",
                    IMAGE_SYM_ABSOLUTE_SECTION,
                    IMAGE_SYM_CLASS_EXTERNAL,
                    0,
                ),
                (
                    "foo",
                    IMAGE_SYM_UNDEFINED_SECTION,
                    IMAGE_SYM_CLASS_WEAK_EXTERNAL,
                    5,
                ),
            ],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], &mut out).expect("links");
        let data = pe_section_header(&out, 2);
        let data_ptr = le_u32(data, 20) as usize;
        let stored = u64::from_le_bytes(out[data_ptr..data_ptr + 8].try_into().unwrap());
        assert_eq!(stored, 0);
        assert_eq!(pe_base_reloc_dir(&out), (0, 0));
    }

    #[test]
    fn test_coff_addr64_to_absolute_symbol_has_no_base_reloc() {
        let text = [0xC3];
        let data = [0u8; 8];
        let relocs = [(0, 5, IMAGE_REL_AMD64_ADDR64)];
        let obj = coff_object(
            &[
                text_section(&text, &[]),
                TestSection {
                    name: ".data",
                    flags: DATA_FLAGS,
                    data: &data,
                    relocs: &relocs,
                    selection: 0,
                    assoc: 0,
                },
            ],
            &[
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                (
                    "konst",
                    IMAGE_SYM_ABSOLUTE_SECTION,
                    IMAGE_SYM_CLASS_EXTERNAL,
                    0x42,
                ),
            ],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], &mut out).expect("links");
        let data = pe_section_header(&out, 2);
        let data_ptr = le_u32(data, 20) as usize;
        let stored = u64::from_le_bytes(out[data_ptr..data_ptr + 8].try_into().unwrap());
        assert_eq!(stored, 0x42);
        assert_eq!(pe_base_reloc_dir(&out), (0, 0));
    }

    #[test]
    fn test_coff_addr64_emits_base_reloc() {
        let obj = absolute_pointer_object(IMAGE_REL_AMD64_ADDR64);
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], &mut out).expect("links");

        let data = pe_section_header(&out, 2);
        let data_rva = le_u32(data, 12);
        let data_ptr = le_u32(data, 20) as usize;
        let stored = u64::from_le_bytes(out[data_ptr..data_ptr + 8].try_into().unwrap());
        assert_eq!(stored, IMAGE_BASE + 0x1000);

        let (reloc_rva, reloc_size) = pe_base_reloc_dir(&out);
        let reloc = pe_section_header(&out, 3);
        assert_eq!(le_u32(reloc, 12), reloc_rva);
        assert_eq!(reloc_size, 12);
        let ptr = le_u32(reloc, 20) as usize;
        assert_eq!(le_u32(&out, ptr), data_rva & !0xFFF);
        assert_eq!(le_u32(&out, ptr + 4), 12);
        let entry = u16::from_le_bytes(out[ptr + 8..ptr + 10].try_into().unwrap());
        assert_eq!(
            entry,
            (IMAGE_REL_BASED_DIR64 << 12) | (data_rva & 0xFFF) as u16
        );
    }

    #[test]
    fn test_coff_addr32_is_rejected() {
        let obj = absolute_pointer_object(IMAGE_REL_AMD64_ADDR32);
        let mut out = Vec::new();
        let err = link_and_emit_pe_from_coffs(&[obj.as_slice()], &mut out)
            .expect_err("ADDR32 must be rejected");
        assert!(err.to_string().contains("ADDR32"), "{err}");
    }

    #[test]
    fn test_coff_without_absolute_relocs_has_no_base_reloc() {
        let text = [0xC3];
        let obj = coff_object(
            &[text_section(&text, &[])],
            &[("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], &mut out).expect("links");
        assert_eq!(pe_base_reloc_dir(&out), (0, 0));
    }

    fn undefined_import_object(text: &[u8], relocs: &[(u32, u32, u16)], symbol: &str) -> Vec<u8> {
        coff_object(
            &[text_section(text, relocs)],
            &[
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                (
                    symbol,
                    IMAGE_SYM_UNDEFINED_SECTION,
                    IMAGE_SYM_CLASS_EXTERNAL,
                    0,
                ),
            ],
        )
    }

    #[test]
    fn test_coff_import_prefix_resolves_to_iat_slot() {
        let call = [0xFF, 0x15, 0, 0, 0, 0, 0xC3];
        let relocs = [(2, 3, IMAGE_REL_AMD64_REL32)];
        let obj = undefined_import_object(&call, &relocs, "__imp_f");
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], &mut out).expect("links");

        let disp = i32::from_le_bytes(out[512 + 2..512 + 6].try_into().unwrap());
        let slot_rva = (0x1000 + 2 + 4 + disp) as u32;
        let rdata = pe_section_header(&out, 1);
        let rdata_rva = le_u32(rdata, 12);
        let rdata_size = le_u32(rdata, 8);
        assert!(slot_rva >= rdata_rva && slot_rva + 8 <= rdata_rva + rdata_size);
        let slot_at = le_u32(rdata, 20) as usize + (slot_rva - rdata_rva) as usize;
        assert_ne!(
            u64::from_le_bytes(out[slot_at..slot_at + 8].try_into().unwrap()),
            0
        );
        assert!(!out.windows(7).any(|w| w == b"__imp_f"));
    }

    #[test]
    fn test_coff_call_to_undefined_function_uses_thunk() {
        let call = [0xE8, 0, 0, 0, 0, 0xC3];
        let relocs = [(1, 3, IMAGE_REL_AMD64_REL32)];
        let obj = undefined_import_object(&call, &relocs, "f");
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], &mut out).expect("links");

        let disp = i32::from_le_bytes(out[512 + 1..512 + 5].try_into().unwrap());
        let target = (0x1000 + 1 + 4 + disp) as u32;
        let thunk_at = 512 + (target - 0x1000) as usize;
        assert_eq!(&out[thunk_at..thunk_at + 2], &[0xFF, 0x25]);
    }

    #[test]
    fn test_coff_data_reference_to_undefined_symbol_is_error() {
        let lea = [0x48, 0x8D, 0x0D, 0, 0, 0, 0, 0xC3];
        let relocs = [(3, 3, IMAGE_REL_AMD64_REL32)];
        let obj = undefined_import_object(&lea, &relocs, "plain");
        let mut out = Vec::new();
        assert!(link_and_emit_pe_from_coffs(&[obj.as_slice()], &mut out).is_err());
    }

    #[test]
    fn test_coff_absolute_reference_to_undefined_symbol_is_error() {
        let text = [0xC3];
        let data = [0u8; 8];
        let relocs = [(0, 3, IMAGE_REL_AMD64_ADDR64)];
        let obj = coff_object(
            &[
                text_section(&text, &[]),
                TestSection {
                    name: ".data",
                    flags: DATA_FLAGS,
                    data: &data,
                    relocs: &relocs,
                    selection: 0,
                    assoc: 0,
                },
            ],
            &[
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                (
                    "plain",
                    IMAGE_SYM_UNDEFINED_SECTION,
                    IMAGE_SYM_CLASS_EXTERNAL,
                    0,
                ),
            ],
        );
        let mut out = Vec::new();
        assert!(link_and_emit_pe_from_coffs(&[obj.as_slice()], &mut out).is_err());
    }

    fn pdata_object(
        text: &[u8],
        pdata: &[u8],
        pdata_relocs: &[(u32, u32, u16)],
        symbols: &[(&str, i16, u8, u32)],
    ) -> Vec<u8> {
        coff_object(
            &[
                text_section(text, &[]),
                TestSection {
                    name: ".pdata",
                    flags: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
                    data: pdata,
                    relocs: pdata_relocs,
                    selection: 0,
                    assoc: 0,
                },
            ],
            symbols,
        )
    }

    #[test]
    fn test_coff_long_section_name_is_read_from_string_table() {
        let record = [0u8; 12];
        let obj = coff_object_with_strtab(
            &[
                text_section(&[0x90; 8], &[]),
                TestSection {
                    name: "/4",
                    flags: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
                    data: &record,
                    relocs: &[],
                    selection: 0,
                    assoc: 0,
                },
            ],
            &[("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
            b".pdata$longname\0",
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], &mut out).expect("links");
        assert_eq!(pe_data_dir(&out, DATA_DIR_EXCEPTION), (0x3000, 12));
    }

    #[test]
    fn test_coff_pdata_is_contiguous_and_sorted() {
        let record = [0u8; 12];
        let obj0 = pdata_object(
            &[0x90; 8],
            &record,
            &[(0, 5, IMAGE_REL_AMD64_ADDR32NB)],
            &[
                ("f0", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                ("f1", 0, IMAGE_SYM_CLASS_EXTERNAL, 0),
            ],
        );
        let obj1 = pdata_object(
            &[0xC3; 8],
            &record,
            &[(0, 5, IMAGE_REL_AMD64_ADDR32NB)],
            &[
                ("f1", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                ("f0", 0, IMAGE_SYM_CLASS_EXTERNAL, 0),
            ],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj0.as_slice(), obj1.as_slice()], &mut out).expect("links");

        let pdata = pe_section_header(&out, 2);
        let pdata_rva = le_u32(pdata, 12);
        let pdata_ptr = le_u32(pdata, 20) as usize;
        assert_eq!(le_u32(&out, pdata_ptr), 0x1000);
        assert_eq!(le_u32(&out, pdata_ptr + 12), 0x1008);
        assert_eq!(pe_data_dir(&out, DATA_DIR_EXCEPTION), (pdata_rva, 24));
    }

    #[test]
    fn test_coff_without_pdata_has_no_exception_dir() {
        let text = [0xC3];
        let obj = coff_object(
            &[text_section(&text, &[])],
            &[("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], &mut out).expect("links");
        assert_eq!(pe_data_dir(&out, DATA_DIR_EXCEPTION), (0, 0));
    }

    #[test]
    fn test_coff_pdata_size_not_multiple_of_record_is_error() {
        let obj = pdata_object(
            &[0xC3],
            &[0u8; 4],
            &[],
            &[("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        let mut out = Vec::new();
        assert!(link_and_emit_pe_from_coffs(&[obj.as_slice()], &mut out).is_err());
    }
}
