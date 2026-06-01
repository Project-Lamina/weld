//! PE32+ (64-bit Windows) executable emission.
//!
//! Emits a minimal IMAGE_FILE_MACHINE_AMD64 console executable with:
//! - A standard DOS stub and PE signature
//! - COFF + Optional (PE32+) headers
//! - .text, .rdata, and optionally .data sections
//! - An import directory for kernel32.dll (ExitProcess + any runtime symbols)
//! - Proper section/file alignment and correct RVA fixups

use crate::link::{DynamicLinkInfo, MergedLayout};
use std::io::Write;

// ---------------------------------------------------------------------------
// PE constants
// ---------------------------------------------------------------------------

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
const SECTION_ALIGN: u64 = 0x1000; // virtual address granularity
const FILE_ALIGN: u64 = 0x0200; // file offset granularity
const SIZEOF_OPTIONAL_HEADER: u16 = 240;
const SIZEOF_SECTION_HEADER: usize = 40;
const SIZEOF_DOS_STUB: usize = 64;
const SIZEOF_PE_SIGNATURE: usize = 4;
const SIZEOF_COFF_HEADER: usize = 20;

/// Number of data directory entries we always write.
const NUM_DATA_DIRS: u32 = 16;
const _DATA_DIR_IMPORT: usize = 1;
const _DATA_DIR_IAT: usize = 12;

// IMAGE_SECTION_CHARACTERISTICS
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

// ---------------------------------------------------------------------------
// Helper: align an integer up to a multiple of `align`
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Import table builder
// ---------------------------------------------------------------------------

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
    // --- Layout planning ---
    // Import Directory Table (IDT): (entries.len() + 1) * 20 bytes (null-terminated)
    // Import Lookup Table (ILT) for each DLL: (symbols.len() + 1) * 8 bytes
    // Import Address Table (IAT): same layout as ILT (we write identical bytes)
    // IMAGE_IMPORT_BY_NAME records: u16 hint + name\0
    // DLL name strings

    let num_dlls = entries.len();
    let idt_size = (num_dlls + 1) * 20; // +1 for null terminator

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
            hint_name_cursor += 2 + name.len() + 1; // hint(u16) + name + \0
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

    // rdata_rva is already relative to image base; cast is safe (u32 fits all normal RVAs).
    let section_rva = rdata_rva as u32;

    // Write IDT
    for (di, _e) in entries.iter().enumerate() {
        let base = di * 20;
        let ilt_rva = section_rva + ilt_offsets[di] as u32;
        let iat_rva = section_rva + iat_offsets[di] as u32;
        let name_rva = section_rva + dll_name_offsets[di] as u32;

        buf[base..base + 4].copy_from_slice(&ilt_rva.to_le_bytes()); // OriginalFirstThunk
        // TimeDateStamp (4 bytes) = 0
        // ForwarderChain (4 bytes) = 0
        buf[base + 12..base + 16].copy_from_slice(&name_rva.to_le_bytes()); // Name
        buf[base + 16..base + 20].copy_from_slice(&iat_rva.to_le_bytes()); // FirstThunk
    }
    // Null terminator entry already zero.

    // Write ILT and IAT entries
    for (di, e) in entries.iter().enumerate() {
        for (si, _) in e.symbols.iter().enumerate() {
            let hint_name_rva = section_rva + hint_name_offsets[di][si] as u32;
            let thunk: u64 = hint_name_rva as u64; // bit 63 = 0 → by name
            let ilt_off = ilt_offsets[di] + si * 8;
            let iat_off = iat_offsets[di] + si * 8;
            buf[ilt_off..ilt_off + 8].copy_from_slice(&thunk.to_le_bytes());
            buf[iat_off..iat_off + 8].copy_from_slice(&thunk.to_le_bytes());
        }
        // Null terminator entries already zero.
    }

    // Write IMAGE_IMPORT_BY_NAME records
    for (di, e) in entries.iter().enumerate() {
        for (si, (hint, name)) in e.symbols.iter().enumerate() {
            let off = hint_name_offsets[di][si];
            buf[off..off + 2].copy_from_slice(&hint.to_le_bytes());
            let name_bytes = name.as_bytes();
            buf[off + 2..off + 2 + name_bytes.len()].copy_from_slice(name_bytes);
            // null byte already present (buf is zero-initialised)
        }
    }

    // Write DLL name strings
    for (di, e) in entries.iter().enumerate() {
        let off = dll_name_offsets[di];
        buf[off..off + e.dll_name.len()].copy_from_slice(e.dll_name.as_bytes());
    }

    let idt_rva = 0u32; // relative to section start
    let iat_rva = iat_base_off as u32;
    let idt_size_u32 = (num_dlls * 20) as u32; // not including null entry — convention varies; use actual
    let iat_size_u32 = iat_total_size as u32;

    (buf, idt_rva, iat_rva, idt_size_u32, iat_size_u32)
}

// ---------------------------------------------------------------------------
// Section descriptor (used for layout)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

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
) -> std::io::Result<()> {
    // --- Collect .text and .data bytes from merged layout ---
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

    // --- Determine which symbols to import ---
    let mut import_symbols: Vec<(u16, String)> = vec![(0, "ExitProcess".to_string())];
    if let Some(dyn_info) = dyn_info {
        for sym in &dyn_info.plt_symbols {
            if sym != "ExitProcess" {
                import_symbols.push((0, sym.clone()));
            }
        }
    }

    // --- Compute header sizes ---
    // Sections: .text, optionally .data, .rdata (imports)
    let has_data = !data_data.is_empty();
    let num_sections: u16 = if has_data { 3 } else { 2 };

    let headers_raw_size = SIZEOF_DOS_STUB
        + SIZEOF_PE_SIGNATURE
        + SIZEOF_COFF_HEADER
        + SIZEOF_OPTIONAL_HEADER as usize
        + (num_sections as usize) * SIZEOF_SECTION_HEADER;
    let size_of_headers = align_up(headers_raw_size as u64, FILE_ALIGN) as u32;

    // --- Lay out sections in virtual address space ---
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

    // --- SizeOfImage ---
    let last_section_end = rdata_rva as u64 + align_up(rdata_vsize as u64, SECTION_ALIGN);
    let size_of_image = align_up(last_section_end, SECTION_ALIGN) as u32;

    // --- File offsets for section data ---
    let text_file_off = size_of_headers;
    let data_file_off = text_file_off + text_raw_size;
    let rdata_file_off = if has_data {
        data_file_off + data_raw_size
    } else {
        text_file_off + text_raw_size
    };

    // --- Entry point RVA (relative to image base) ---
    let entry_rva = entry.saturating_sub(IMAGE_BASE) as u32;

    // =========================================================================
    // Assemble the file
    // =========================================================================

    // --- DOS stub (minimal 64-byte version) ---
    let mut dos = [0u8; SIZEOF_DOS_STUB];
    dos[0] = 0x4D; // M
    dos[1] = 0x5A; // Z
    // Minimum DOS stub: set e_lfanew at offset 0x3C
    let e_lfanew = SIZEOF_DOS_STUB as u32;
    dos[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
    out.write_all(&dos)?;

    // --- PE signature ---
    out.write_all(b"PE\0\0")?;

    // --- COFF header ---
    let mut coff = [0u8; SIZEOF_COFF_HEADER];
    write_u16(&mut coff, 0, IMAGE_FILE_MACHINE_AMD64);
    write_u16(&mut coff, 2, num_sections);
    // TimeDateStamp at 4: leave 0
    // PointerToSymbolTable at 8: 0
    // NumberOfSymbols at 12: 0
    write_u16(&mut coff, 16, SIZEOF_OPTIONAL_HEADER);
    write_u16(
        &mut coff,
        18,
        IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE,
    );
    out.write_all(&coff)?;

    // --- Optional header (PE32+, 240 bytes total) ---
    let mut opt = [0u8; SIZEOF_OPTIONAL_HEADER as usize];
    let mut o = 0usize;

    // Standard fields
    write_u16_at(&mut opt, &mut o, IMAGE_OPTIONAL_HDR64_MAGIC); // Magic
    opt[o] = 14;
    o += 1; // MajorLinkerVersion
    opt[o] = 0;
    o += 1; // MinorLinkerVersion
    write_u32_at(&mut opt, &mut o, text_raw_size); // SizeOfCode
    write_u32_at(&mut opt, &mut o, rdata_raw_size + data_raw_size); // SizeOfInitializedData
    write_u32_at(&mut opt, &mut o, 0); // SizeOfUninitializedData
    write_u32_at(&mut opt, &mut o, entry_rva); // AddressOfEntryPoint
    write_u32_at(&mut opt, &mut o, text_rva); // BaseOfCode

    // Windows-specific fields
    write_u64_at(&mut opt, &mut o, IMAGE_BASE);
    write_u32_at(&mut opt, &mut o, SECTION_ALIGN as u32);
    write_u32_at(&mut opt, &mut o, FILE_ALIGN as u32);
    write_u16_at(&mut opt, &mut o, 6); // MajorOSVersion
    write_u16_at(&mut opt, &mut o, 0); // MinorOSVersion
    write_u16_at(&mut opt, &mut o, 0); // MajorImageVersion
    write_u16_at(&mut opt, &mut o, 0); // MinorImageVersion
    write_u16_at(&mut opt, &mut o, 6); // MajorSubsystemVersion
    write_u16_at(&mut opt, &mut o, 0); // MinorSubsystemVersion
    write_u32_at(&mut opt, &mut o, 0); // Win32VersionValue (must be 0)
    write_u32_at(&mut opt, &mut o, size_of_image);
    write_u32_at(&mut opt, &mut o, size_of_headers);
    write_u32_at(&mut opt, &mut o, 0); // CheckSum (optional; 0 works for most cases)
    write_u16_at(&mut opt, &mut o, IMAGE_SUBSYSTEM_WINDOWS_CUI);
    write_u16_at(
        &mut opt,
        &mut o,
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT
            | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            | IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE,
    );
    write_u64_at(&mut opt, &mut o, 0x10_0000); // SizeOfStackReserve (1 MB)
    write_u64_at(&mut opt, &mut o, 0x1000); // SizeOfStackCommit (4 KB)
    write_u64_at(&mut opt, &mut o, 0x10_0000); // SizeOfHeapReserve (1 MB)
    write_u64_at(&mut opt, &mut o, 0x1000); // SizeOfHeapCommit (4 KB)
    write_u32_at(&mut opt, &mut o, 0); // LoaderFlags (must be 0)
    write_u32_at(&mut opt, &mut o, NUM_DATA_DIRS); // NumberOfRvaAndSizes

    // Data directories (16 entries × 8 bytes = 128 bytes)

    // Index 0: Export table — unused
    write_u32_at(&mut opt, &mut o, 0);
    write_u32_at(&mut opt, &mut o, 0);
    // Index 1: Import table
    write_u32_at(&mut opt, &mut o, import_dir_rva);
    write_u32_at(&mut opt, &mut o, idt_size_bytes + 20); // include null entry
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

    // --- Section headers ---
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
        sh[8..12].copy_from_slice(&sec.virtual_size().to_le_bytes()); // VirtualSize
        sh[12..16].copy_from_slice(&sec_rvas[i].to_le_bytes()); // VirtualAddress
        sh[16..20].copy_from_slice(&sec.raw_size().to_le_bytes()); // SizeOfRawData
        sh[20..24].copy_from_slice(&sec_file_offs[i].to_le_bytes()); // PointerToRawData
        // PointerToRelocations (24), PointerToLinenumbers (28): 0
        // NumberOfRelocations (32), NumberOfLinenumbers (34): 0
        sh[36..40].copy_from_slice(&sec.characteristics.to_le_bytes());
        out.write_all(&sh)?;
    }

    // Pad headers to file alignment
    let header_written = headers_raw_size;
    let padding = size_of_headers as usize - header_written;
    out.write_all(&vec![0u8; padding])?;

    // --- Section data ---
    for sec in &sections {
        out.write_all(&sec.data)?;
        let pad = sec.raw_size() as usize - sec.data.len();
        out.write_all(&vec![0u8; pad])?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// COFF→PE direct linker
// ---------------------------------------------------------------------------

const IMAGE_REL_AMD64_REL32: u16 = 4;
const IMAGE_SYM_UNDEFINED_SECTION: i16 = 0;
const IMAGE_SYM_CLASS_EXTERNAL: u8 = 2;

/// Windows kernel32.dll API functions. Everything else goes to ucrt.dll.
fn is_kernel32_symbol(name: &str) -> bool {
    matches!(
        name,
        "ExitProcess" | "GetStdHandle" | "WriteFile" | "WriteConsoleA" | "WriteConsoleW"
            | "ReadFile" | "CloseHandle" | "CreateFileA" | "CreateFileW"
            | "VirtualAlloc" | "VirtualFree" | "GetLastError" | "SetLastError"
            | "LoadLibraryA" | "GetProcAddress" | "FreeLibrary"
            | "HeapAlloc" | "HeapFree" | "GetProcessHeap"
    )
}

fn coff_read_u16(data: &[u8], off: usize) -> Option<u16> {
    let b = data.get(off..off + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}
fn coff_read_i16(data: &[u8], off: usize) -> Option<i16> {
    let b = data.get(off..off + 2)?;
    Some(i16::from_le_bytes([b[0], b[1]]))
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

/// Link a single COFF object file and emit a PE32+ executable directly.
///
/// Handles `IMAGE_REL_AMD64_REL32` relocations for external symbols by inserting
/// 6-byte JMP thunks. CRT functions (printf, etc.) are imported from `ucrt.dll`;
/// Windows API functions are imported from `KERNEL32.DLL`.
pub fn link_and_emit_pe_from_coff(
    coff: &[u8],
    out: &mut impl Write,
) -> std::io::Result<()> {
    // --- Parse COFF file header ---
    let n_sections = coff_read_u16(coff, 2).unwrap_or(0) as usize;
    let sym_table_off = coff_read_u32(coff, 8).unwrap_or(0) as usize;
    let n_syms = coff_read_u32(coff, 12).unwrap_or(0) as usize;

    // String table immediately follows the symbol table.
    let strtab_off = sym_table_off + n_syms * 18;
    let strtab_size = if strtab_off + 4 <= coff.len() {
        coff_read_u32(coff, strtab_off).unwrap_or(4) as usize
    } else {
        4
    };
    let strtab_end = (strtab_off + strtab_size).min(coff.len());
    let strtab = &coff[strtab_off.min(coff.len())..strtab_end];

    // --- Parse symbol table: collect names of undefined external symbols ---
    let mut sym_names: Vec<String> = Vec::with_capacity(n_syms);
    {
        let mut i = 0;
        while i < n_syms {
            let rec = sym_table_off + i * 18;
            if rec + 18 > coff.len() {
                break;
            }
            let name_bytes: &[u8; 8] = coff[rec..rec + 8].try_into().unwrap_or(&[0u8; 8]);
            sym_names.push(coff_symbol_name(name_bytes, strtab));
            let num_aux = coff[rec + 17] as usize;
            i += 1 + num_aux;
            // Push placeholder names for aux records so indices stay aligned
            for _ in 0..num_aux {
                sym_names.push(String::new());
            }
        }
    }

    // Build map: symbol_name → index for undefined external symbols
    let undefined_syms: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        let mut out_v = Vec::new();
        for (i, name) in sym_names.iter().enumerate() {
            if name.is_empty() {
                continue;
            }
            let rec = sym_table_off + i * 18;
            if rec + 18 > coff.len() {
                continue;
            }
            let section_num = coff_read_i16(coff, rec + 12).unwrap_or(0);
            let storage_class = coff[rec + 17]; // byte 17: StorageClass (byte 16 is NumberOfAuxSymbols)
            if section_num == IMAGE_SYM_UNDEFINED_SECTION
                && storage_class == IMAGE_SYM_CLASS_EXTERNAL
                && seen.insert(name.clone())
            {
                out_v.push(name.clone());
            }
        }
        out_v
    };

    // Map each undefined symbol name to its thunk index
    let sym_to_thunk: std::collections::HashMap<String, usize> = undefined_syms
        .iter()
        .enumerate()
        .map(|(i, n)| (n.clone(), i))
        .collect();

    // --- Parse section headers, find .text ---
    let mut text_data: Vec<u8> = Vec::new();
    let mut text_relocs: Vec<(u32, u32, u16)> = Vec::new(); // (vaddr_in_section, sym_idx, type)

    for s in 0..n_sections {
        let sh_off = 20 + s * 40;
        if sh_off + 40 > coff.len() {
            break;
        }
        let raw_off = coff_read_u32(coff, sh_off + 20).unwrap_or(0) as usize;
        let raw_size = coff_read_u32(coff, sh_off + 16).unwrap_or(0) as usize;
        let reloc_off = coff_read_u32(coff, sh_off + 24).unwrap_or(0) as usize;
        let n_relocs = coff_read_u16(coff, sh_off + 32).unwrap_or(0) as usize;
        let flags = coff_read_u32(coff, sh_off + 36).unwrap_or(0);

        let is_code = (flags & 0x20) != 0; // IMAGE_SCN_CNT_CODE
        if is_code && raw_size > 0 && raw_off + raw_size <= coff.len() {
            text_data = coff[raw_off..raw_off + raw_size].to_vec();
            for r in 0..n_relocs {
                let r_off = reloc_off + r * 10;
                if r_off + 10 > coff.len() {
                    break;
                }
                let vaddr = coff_read_u32(coff, r_off).unwrap_or(0);
                let sym_idx = coff_read_u32(coff, r_off + 4).unwrap_or(0);
                let rel_type = coff_read_u16(coff, r_off + 8).unwrap_or(0);
                text_relocs.push((vaddr, sym_idx, rel_type));
            }
            break; // Only first code section
        }
    }

    // --- Find `main` entry point offset within .text ---
    let main_offset: u32 = {
        let mut found = 0u32;
        for (i, name) in sym_names.iter().enumerate() {
            if name == "main" || name == "_main" {
                let rec = sym_table_off + i * 18;
                if rec + 18 <= coff.len() {
                    found = coff_read_u32(coff, rec + 8).unwrap_or(0);
                }
                break;
            }
        }
        found
    };

    // --- Determine layout ---
    // .text = original code + thunks (6 bytes each)
    let n_thunks = undefined_syms.len();
    let thunks_offset = text_data.len(); // byte offset of thunk block within .text

    // Pre-compute section VAs so we can fill in thunk displacements.
    // header_size rounds up to FILE_ALIGN (512).
    let num_sections_pe: u16 = 2; // .text, .rdata
    let headers_raw: usize = SIZEOF_DOS_STUB
        + SIZEOF_PE_SIGNATURE
        + SIZEOF_COFF_HEADER
        + SIZEOF_OPTIONAL_HEADER as usize
        + (num_sections_pe as usize) * SIZEOF_SECTION_HEADER;
    let size_of_headers_pe = align_up(headers_raw as u64, FILE_ALIGN) as u32;
    let text_rva = align_up(size_of_headers_pe as u64, SECTION_ALIGN) as u32;
    let text_va = IMAGE_BASE + text_rva as u64;

    // Compute rdata_rva (after .text, section-aligned)
    let total_text_bytes = thunks_offset + n_thunks * 6;
    let rdata_rva = align_up(
        text_rva as u64 + align_up(total_text_bytes as u64, SECTION_ALIGN),
        SECTION_ALIGN,
    ) as u32;

    // Compute IAT offset within rdata.
    // Import section layout: IDT + ILT + IAT + hint/name + dll_names
    // For 1 or 2 DLLs (kernel32 + ucrt), we need to know the counts.
    let kernel32_syms: Vec<&str> = undefined_syms.iter()
        .filter(|n| is_kernel32_symbol(n))
        .map(|n| n.as_str())
        .collect();
    // Always include ExitProcess in kernel32
    let has_exit_process = kernel32_syms.contains(&"ExitProcess");
    let mut k32_syms: Vec<&str> = if has_exit_process {
        kernel32_syms.clone()
    } else {
        let mut v = vec!["ExitProcess"];
        v.extend(kernel32_syms.iter().copied());
        v
    };
    k32_syms.dedup();

    let ucrt_syms: Vec<&str> = undefined_syms.iter()
        .filter(|n| !is_kernel32_symbol(n))
        .map(|n| n.as_str())
        .collect();

    // Build two import entries
    // msvcrt.dll is the system CRT DLL present on all Windows versions.
    // ucrtbase.dll does NOT export plain `printf`/`fflush` by name (they are
    // compiler-intrinsic wrappers in the MSVC CRT headers).
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
    let (rdata_bytes, idt_off, iat_rel_off, idt_sz, iat_sz) =
        build_import_section(rdata_rva as u64, &entries);

    // IAT layout within rdata: for each DLL, IAT entries are at sequential positions.
    // We need the VA of each symbol's IAT entry.
    // IAT structure: all entries for all DLLs, each 8 bytes, null-terminated per DLL.
    // Within build_import_section, ILT comes before IAT.
    // For simplicity, recompute using the iat_rel_off we have.
    // Within the IAT region, entries are ordered: k32_syms (with null), then ucrt_syms (with null).
    fn iat_entry_va(
        rdata_vaddr: u64, iat_rel_off: u32,
        dll_idx: usize,
        sym_idx_in_dll: usize,
        dll_sym_counts: &[usize],
    ) -> u64 {
        let mut base_entry = 0usize;
        for i in 0..dll_idx {
            base_entry += dll_sym_counts[i] + 1; // +1 for null terminator
        }
        base_entry += sym_idx_in_dll;
        rdata_vaddr + iat_rel_off as u64 + base_entry as u64 * 8
    }

    let dll_sym_counts = vec![k32_syms.len(), ucrt_syms.len()];

    // Build a lookup: undefined_sym_name → IAT entry VA (IMAGE_BASE + rdata_rva + offset)
    let mut sym_iat_va: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for (i, name) in k32_syms.iter().enumerate() {
        sym_iat_va.insert(
            name.to_string(),
            iat_entry_va(IMAGE_BASE + rdata_rva as u64, iat_rel_off, 0, i, &dll_sym_counts),
        );
    }
    for (i, name) in ucrt_syms.iter().enumerate() {
        sym_iat_va.insert(
            name.to_string(),
            iat_entry_va(IMAGE_BASE + rdata_rva as u64, iat_rel_off, 1, i, &dll_sym_counts),
        );
    }

    // --- Build thunks ---
    // Thunk i is at: text_va + thunks_offset + i * 6
    let mut thunk_bytes: Vec<u8> = Vec::with_capacity(n_thunks * 6);
    for (i, sym_name) in undefined_syms.iter().enumerate() {
        let thunk_va = text_va + thunks_offset as u64 + i as u64 * 6;
        let thunk_end_va = thunk_va + 6;
        let iat_va = sym_iat_va.get(sym_name).copied().unwrap_or(thunk_end_va);
        let rel = (iat_va as i64 - thunk_end_va as i64) as i32;
        thunk_bytes.extend_from_slice(&[0xFF, 0x25]); // JMP QWORD PTR [rip+rel32]
        thunk_bytes.extend_from_slice(&rel.to_le_bytes());
    }

    // --- Patch call sites in code ---
    let mut patched_text = text_data.clone();
    for (vaddr_in_sec, sym_idx, rel_type) in &text_relocs {
        if *rel_type != IMAGE_REL_AMD64_REL32 {
            continue;
        }
        let sym_name = sym_names.get(*sym_idx as usize).map(|s| s.as_str()).unwrap_or("");
        if sym_name.is_empty() {
            continue;
        }
        let thunk_idx = match sym_to_thunk.get(sym_name) {
            Some(&idx) => idx,
            None => continue,
        };
        let thunk_va = text_va + thunks_offset as u64 + thunk_idx as u64 * 6;
        // The relocation patches a 4-byte field at vaddr_in_sec within the section.
        // For REL32: field = target_va - (section_va + vaddr_in_sec + 4)
        let field_va = text_va + *vaddr_in_sec as u64;
        let rel32 = (thunk_va as i64) - (field_va as i64 + 4);
        let off = *vaddr_in_sec as usize;
        if off + 4 <= patched_text.len() {
            patched_text[off..off + 4].copy_from_slice(&(rel32 as i32).to_le_bytes());
        }
    }

    // Final .text = patched code + thunks
    patched_text.extend_from_slice(&thunk_bytes);

    // --- Build MergedLayout and emit ---
    let entry_va = text_va + main_offset as u64;

    // Build dynamic info (plt_symbols tells the emitter what to import).
    // We handle routing ourselves via entry_refs; pass empty plt_symbols to avoid
    // the emitter adding a duplicate KERNEL32.DLL entry.
    // Instead, we rebuild the rdata manually below and call a lower-level emit.

    // Bypass emit_pe_executable's import building (it only does KERNEL32.DLL).
    // Write PE manually using the pre-built rdata_bytes from build_import_section above.
    let import_dir_rva = rdata_rva + idt_off;
    let iat_rva = rdata_rva + iat_rel_off;

    let text_vsize = patched_text.len() as u32;
    let text_raw_size = align_up(text_vsize as u64, FILE_ALIGN) as u32;
    let rdata_vsize = rdata_bytes.len() as u32;
    let last_section_end = rdata_rva as u64 + align_up(rdata_vsize as u64, SECTION_ALIGN);
    let size_of_image = align_up(last_section_end, SECTION_ALIGN) as u32;

    let text_file_off = size_of_headers_pe;
    let rdata_file_off = text_file_off + text_raw_size;

    let sections = vec![
        PeSection::new(
            ".text",
            patched_text,
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        ),
        PeSection::new(
            ".rdata",
            rdata_bytes,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        ),
    ];

    emit_pe_raw(
        out,
        &sections,
        &[text_rva, rdata_rva],
        &[text_file_off, rdata_file_off],
        size_of_headers_pe,
        size_of_image,
        entry_va,
        import_dir_rva,
        iat_rva,
        idt_sz,
        iat_sz,
    )
}

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
) -> std::io::Result<()> {
    // DOS stub
    let mut dos = [0u8; SIZEOF_DOS_STUB];
    dos[0] = b'M';
    dos[1] = b'Z';
    let e_lfanew = SIZEOF_DOS_STUB as u32;
    dos[60..64].copy_from_slice(&e_lfanew.to_le_bytes());
    out.write_all(&dos)?;

    // PE signature
    out.write_all(b"PE\0\0")?;

    // COFF header
    let n_sec = sections.len() as u16;
    let mut coff_hdr = [0u8; SIZEOF_COFF_HEADER];
    coff_hdr[0..2].copy_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
    coff_hdr[2..4].copy_from_slice(&n_sec.to_le_bytes());
    coff_hdr[16..18].copy_from_slice(&SIZEOF_OPTIONAL_HEADER.to_le_bytes());
    let characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    coff_hdr[18..20].copy_from_slice(&characteristics.to_le_bytes());
    out.write_all(&coff_hdr)?;

    // Optional header
    let mut opt = [0u8; SIZEOF_OPTIONAL_HEADER as usize];
    let entry_rva = (entry_va - IMAGE_BASE) as u32;
    let text_rva = sec_rvas[0];
    write_u16(&mut opt, 0, IMAGE_OPTIONAL_HDR64_MAGIC);
    write_u32_at_off(&mut opt, 16, entry_rva); // AddressOfEntryPoint
    write_u32_at_off(&mut opt, 20, text_rva);  // BaseOfCode
    write_u64_at_off(&mut opt, 24, IMAGE_BASE);
    write_u32_at_off(&mut opt, 32, SECTION_ALIGN as u32);
    write_u32_at_off(&mut opt, 36, FILE_ALIGN as u32);
    write_u16_at_off(&mut opt, 40, 6); // MajorOSVersion
    write_u16_at_off(&mut opt, 44, 0); // MajorImageVersion
    write_u16_at_off(&mut opt, 48, 6); // MajorSubsystemVersion
    write_u32_at_off(&mut opt, 56, size_of_image);
    write_u32_at_off(&mut opt, 60, size_of_headers);
    write_u16_at_off(&mut opt, 68, IMAGE_SUBSYSTEM_WINDOWS_CUI);
    let dll_chars = IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        | IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE;
    write_u16_at_off(&mut opt, 70, dll_chars);
    write_u64_at_off(&mut opt, 72, 0x100000); // SizeOfStackReserve
    write_u64_at_off(&mut opt, 80, 0x1000);   // SizeOfStackCommit
    write_u64_at_off(&mut opt, 88, 0x100000); // SizeOfHeapReserve
    write_u64_at_off(&mut opt, 96, 0x1000);   // SizeOfHeapCommit
    write_u32_at_off(&mut opt, 108, NUM_DATA_DIRS); // NumberOfRvaAndSizes
    // Data directories start at offset 112. Each entry is 8 bytes (RVA + Size).
    // Index 1 = Import Directory Table, index 12 = Import Address Table.
    write_u32_at_off(&mut opt, 112 + 1 * 8,     import_dir_rva); // [1].VirtualAddress
    write_u32_at_off(&mut opt, 112 + 1 * 8 + 4, idt_size);       // [1].Size
    write_u32_at_off(&mut opt, 112 + 12 * 8,    iat_rva);         // [12].VirtualAddress
    write_u32_at_off(&mut opt, 112 + 12 * 8 + 4, iat_size);      // [12].Size
    out.write_all(&opt)?;

    // Section headers
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

    // Padding to size_of_headers
    let headers_written = SIZEOF_DOS_STUB
        + SIZEOF_PE_SIGNATURE
        + SIZEOF_COFF_HEADER
        + SIZEOF_OPTIONAL_HEADER as usize
        + sections.len() * SIZEOF_SECTION_HEADER;
    let pad = size_of_headers as usize - headers_written;
    out.write_all(&vec![0u8; pad])?;

    // Section data
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

// ---------------------------------------------------------------------------
// Write helpers (cursor-based writes into a fixed-size buffer)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::{MergedLayout, MergedSection};
    use std::collections::HashMap;

    fn minimal_layout() -> (MergedLayout, u64) {
        // Emit a one-byte .text section.  The entry is the image base + .text RVA.
        let text_rva = align_up(512, SECTION_ALIGN) as u32; // SizeOfHeaders rounded → 4096
        let entry = IMAGE_BASE + text_rva as u64;

        let layout = MergedLayout {
            sections: vec![MergedSection {
                name: ".text".to_string(),
                data: vec![0xC3], // single RET instruction
                vaddr: entry,
                flags: 0,
                align: 16,
            }],
            section_by_name: {
                let mut m = HashMap::new();
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
        // Should be at least headers + one padded section.
        assert!(
            buf.len() >= 512,
            "PE file unexpectedly small: {} bytes",
            buf.len()
        );
    }
}
