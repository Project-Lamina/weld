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
fn build_import_section(
    rdata_vaddr: u64,
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

    let section_rva = rdata_vaddr as u32;

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

    let rdata_vaddr = IMAGE_BASE + rdata_rva as u64;

    let sym_refs: Vec<(u16, &str)> = import_symbols
        .iter()
        .map(|(h, n)| (*h, n.as_str()))
        .collect();
    let entries = [ImportEntry {
        dll_name: "KERNEL32.DLL",
        symbols: sym_refs,
    }];
    let (rdata_bytes, idt_rel_off, iat_rel_off, idt_size_bytes, iat_size_bytes) =
        build_import_section(rdata_vaddr, &entries);

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
    let entry_rva = (entry.saturating_sub(IMAGE_BASE)) as u32;

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
    let data_dir_start = o;
    let _ = data_dir_start;

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
