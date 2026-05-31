//! Minimal Mach-O 64-bit reader skeleton.
//!
//! Parses header, LC_SEGMENT_64 with sections, LC_SYMTAB for object files.
//! Used for native Mach-O linking (Phase 6.2).

#![allow(dead_code)]

use std::path::Path;

const MH_MAGIC_64: u32 = 0xFEEDFACF;
const MH_CIGAM_64: u32 = 0xCFFAEDFE;
const MH_OBJECT: u32 = 1;
const MH_DYLIB: u32 = 6;
const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x0b;
const LC_SYMSEG: u32 = 0x02;

const CPU_TYPE_X86_64: u32 = 0x01000007;
const CPU_TYPE_ARM64: u32 = 0x0100000C;

const N_TYPE: u8 = 0x0e;
const N_SECT: u8 = 0x0e;
const N_EXT: u8 = 0x01;
const N_WEAK_REF: u16 = 0x0040;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachoCpuType {
    X86_64,
    Arm64,
}

impl MachoCpuType {
    pub fn from_raw(v: u32) -> Option<Self> {
        match v {
            CPU_TYPE_X86_64 => Some(Self::X86_64),
            CPU_TYPE_ARM64 => Some(Self::Arm64),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MachoSegment {
    pub name: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
}

#[derive(Debug, Clone)]
pub struct MachoSection {
    pub sectname: String,
    pub segname: String,
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
}

/// Mach-O relocation_info: r_address (4) + r_info (4).
/// r_info: r_symbolnum:24, r_pcrel:1, r_length:2, r_extern:1, r_type:4
pub const GENERIC_RELOC_VANILLA: u32 = 0;
pub const ARM64_RELOC_BRANCH26: u32 = 2;
pub const ARM64_RELOC_PAGE21: u32 = 3;
pub const ARM64_RELOC_PAGEOFF12: u32 = 4;
pub const ARM64_RELOC_GOT_LOAD_PAGE21: u32 = 5;
pub const ARM64_RELOC_GOT_LOAD_PAGEOFF12: u32 = 6;
pub const ARM64_RELOC_TLVP_LOAD_PAGE21: u32 = 8;
pub const ARM64_RELOC_TLVP_LOAD_PAGEOFF12: u32 = 9;
pub const ARM64_RELOC_ADDEND: u32 = 10;
pub const X86_64_RELOC_BRANCH: u32 = 2;

#[derive(Debug, Clone, Copy)]
pub struct MachoReloc {
    pub r_address: u32,
    pub r_symbolnum: u32,
    pub r_pcrel: bool,
    pub r_length: u32,
    pub r_extern: bool,
    pub r_type: u32,
}

#[derive(Debug, Clone)]
pub struct MachoSymbol {
    pub name: String,
    pub value: u64,
    pub sect: u8,
    pub n_type: u8,
    pub n_desc: u16,
    pub is_defined: bool,
    pub is_weak_ref: bool,
}

#[derive(Debug, Clone)]
pub struct Macho64Header {
    pub cputype: u32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub segments: Vec<MachoSegment>,
}

#[derive(Debug, Clone)]
pub struct Macho64Object {
    pub header: Macho64Header,
    pub sections: Vec<MachoSection>,
    pub symbols: Vec<MachoSymbol>,
    pub data: Vec<u8>,
}

fn read_u32_be(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u16_le(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u64_le(data: &[u8], off: usize) -> Option<u64> {
    data.get(off..off + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

fn trim_cstr(b: &[u8]) -> &[u8] {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    &b[..end]
}

pub fn is_macho64(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let magic = read_u32_le(data, 0).or_else(|| read_u32_be(data, 0));
    magic == Some(MH_MAGIC_64) || magic == Some(MH_CIGAM_64)
}

pub fn is_macho_dylib(data: &[u8]) -> bool {
    is_macho64(data)
        && data.len() >= 16
        && read_u32_le(data, 12)
            .map(|ft| ft == MH_DYLIB)
            .unwrap_or(false)
}

pub fn parse_macho64_header(data: &[u8]) -> Result<Macho64Header, String> {
    if data.len() < 32 {
        return Err("file too short for Mach-O 64 header".to_string());
    }

    let magic = read_u32_le(data, 0)
        .or_else(|| read_u32_be(data, 0))
        .ok_or("bad magic")?;
    if magic != MH_MAGIC_64 && magic != MH_CIGAM_64 {
        return Err("not Mach-O 64".to_string());
    }
    if magic == MH_CIGAM_64 {
        return Err("big-endian Mach-O not supported".to_string());
    }

    let cputype = read_u32_le(data, 4).ok_or("bad cputype")?;
    let _cpusubtype = read_u32_le(data, 8);
    let filetype = read_u32_le(data, 12).ok_or("bad filetype")?;
    let ncmds = read_u32_le(data, 16).ok_or("bad ncmds")?;
    let sizeofcmds = read_u32_le(data, 20).ok_or("bad sizeofcmds")?;

    let mut segments = Vec::new();
    let mut off = 32usize;

    for _ in 0..ncmds {
        if data.len() < off + 8 {
            break;
        }
        let cmd = read_u32_le(data, off).ok_or("bad cmd")?;
        let cmdsize = read_u32_le(data, off + 4).ok_or("bad cmdsize")? as usize;

        if cmd == LC_SEGMENT_64 && cmdsize >= 72 {
            let segname = data.get(off + 8..off + 24).unwrap_or(&[]);
            let name = String::from_utf8_lossy(trim_cstr(segname))
                .trim_end_matches('\0')
                .to_string();
            let vmaddr = read_u64_le(data, off + 24).ok_or("bad vmaddr")?;
            let vmsize = read_u64_le(data, off + 32).ok_or("bad vmsize")?;
            let fileoff = read_u64_le(data, off + 40).ok_or("bad fileoff")?;
            let filesize = read_u64_le(data, off + 48).ok_or("bad filesize")?;

            segments.push(MachoSegment {
                name,
                vmaddr,
                vmsize,
                fileoff,
                filesize,
            });
        }

        off += cmdsize;
    }

    Ok(Macho64Header {
        cputype,
        filetype,
        ncmds,
        sizeofcmds,
        segments,
    })
}

fn parse_sections_from_segment(data: &[u8], off: usize, _cmdsize: usize) -> Vec<MachoSection> {
    let mut sections = Vec::new();
    let nsects = read_u32_le(data, off + 64).unwrap_or(0) as usize;
    let mut sec_off = off + 72;
    for _ in 0..nsects {
        if data.len() < sec_off + 80 {
            break;
        }
        let sectname = String::from_utf8_lossy(trim_cstr(&data[sec_off..sec_off + 16]))
            .trim_end_matches('\0')
            .to_string();
        let segname = String::from_utf8_lossy(trim_cstr(&data[sec_off + 16..sec_off + 32]))
            .trim_end_matches('\0')
            .to_string();
        let addr = read_u64_le(data, sec_off + 32).unwrap_or(0);
        let size = read_u64_le(data, sec_off + 40).unwrap_or(0);
        let offset = read_u32_le(data, sec_off + 48).unwrap_or(0);
        let align = read_u32_le(data, sec_off + 52).unwrap_or(0);
        let reloff = read_u32_le(data, sec_off + 56).unwrap_or(0);
        let nreloc = read_u32_le(data, sec_off + 60).unwrap_or(0);
        let flags = read_u32_le(data, sec_off + 64).unwrap_or(0);
        sections.push(MachoSection {
            sectname,
            segname,
            addr,
            size,
            offset,
            align,
            reloff,
            nreloc,
            flags,
        });
        sec_off += 80;
    }
    sections
}

fn parse_symtab(
    data: &[u8],
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
) -> Vec<MachoSymbol> {
    let mut symbols = Vec::new();
    let soff = symoff as usize;
    let st_end = (stroff + strsize) as usize;
    for i in 0..nsyms {
        let off = soff + i as usize * 16;
        if data.len() < off + 16 {
            break;
        }
        let n_strx = read_u32_le(data, off).unwrap_or(0) as usize;
        let n_type = data.get(off + 4).copied().unwrap_or(0);
        let n_sect = data.get(off + 5).copied().unwrap_or(0);
        let n_desc = read_u16_le(data, off + 6).unwrap_or(0);
        let n_value = read_u64_le(data, off + 8).unwrap_or(0);

        let name = if n_strx > 0 && st_end > stroff as usize + n_strx {
            let sstart = stroff as usize + n_strx;
            let s = &data[sstart..];
            String::from_utf8_lossy(trim_cstr(s)).to_string()
        } else {
            String::new()
        };

        let sect_type = n_type & N_TYPE;
        let is_defined = sect_type == N_SECT && n_sect != 0;
        let is_weak_ref = !is_defined && (n_desc & N_WEAK_REF) != 0;

        symbols.push(MachoSymbol {
            name,
            value: n_value,
            sect: n_sect,
            n_type,
            n_desc,
            is_defined,
            is_weak_ref,
        });
    }
    symbols
}

pub fn parse_macho_relocs(data: &[u8], reloff: u32, nreloc: u32) -> Vec<MachoReloc> {
    let mut out = Vec::with_capacity(nreloc as usize);
    let base = reloff as usize;
    for i in 0..nreloc {
        let off = base + i as usize * 8;
        if data.len() < off + 8 {
            break;
        }
        let r_address = read_u32_le(data, off).unwrap_or(0);
        let r_info = read_u32_le(data, off + 4).unwrap_or(0);
        let r_symbolnum = r_info & 0xFFFFFF;
        let r_pcrel = (r_info >> 24) & 1 != 0;
        let r_length = (r_info >> 25) & 3;
        let r_extern = (r_info >> 27) & 1 != 0;
        let r_type = (r_info >> 28) & 0xF;
        out.push(MachoReloc {
            r_address,
            r_symbolnum,
            r_pcrel,
            r_length,
            r_extern,
            r_type,
        });
    }
    out
}

pub fn parse_macho64_object(data: &[u8]) -> Result<Macho64Object, String> {
    let header = parse_macho64_header(data)?;
    if header.filetype != MH_OBJECT {
        return Err("expected MH_OBJECT".to_string());
    }

    let mut all_sections = Vec::new();
    let mut symoff = 0u32;
    let mut nsyms = 0u32;
    let mut stroff = 0u32;
    let mut strsize = 0u32;

    let mut off = 32usize;
    for _ in 0..header.ncmds {
        if data.len() < off + 8 {
            break;
        }
        let cmd = read_u32_le(data, off).ok_or("bad cmd")?;
        let cmdsize = read_u32_le(data, off + 4).ok_or("bad cmdsize")? as usize;

        if cmd == LC_SEGMENT_64 && cmdsize >= 72 {
            let mut secs = parse_sections_from_segment(data, off, cmdsize);
            all_sections.append(&mut secs);
        } else if (cmd == LC_SYMTAB || cmd == LC_SYMSEG) && cmdsize >= 24 {
            let read_symoff = read_u32_le(data, off + 8).ok_or("bad symoff")?;
            let read_nsyms = read_u32_le(data, off + 12).ok_or("bad nsyms")?;
            let read_stroff = read_u32_le(data, off + 16).ok_or("bad stroff")?;
            let read_strsize = read_u32_le(data, off + 20).ok_or("bad strsize")?;
            if read_nsyms > nsyms {
                symoff = read_symoff;
                nsyms = read_nsyms;
                stroff = read_stroff;
                strsize = read_strsize;
            }
        }

        off += cmdsize;
    }

    let symbols = parse_symtab(data, symoff, nsyms, stroff, strsize);

    Ok(Macho64Object {
        header,
        sections: all_sections,
        symbols,
        data: data.to_vec(),
    })
}

pub fn parse_macho64_file(path: &Path) -> Result<Macho64Header, String> {
    let data = std::fs::read(path).map_err(|e| format!("read failed: {}", e))?;
    parse_macho64_header(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_macho64_elf() {
        let elf = [0x7f, b'E', b'L', b'F'];
        assert!(!is_macho64(&elf));
    }

    #[test]
    fn test_is_macho64_magic() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&0xFEEDFACFu32.to_le_bytes());
        assert!(is_macho64(&data));
    }

    #[test]
    fn test_parse_macho64_minimal() {
        let mut data = vec![0u8; 200];
        data[0..4].copy_from_slice(&0xFEEDFACFu32.to_le_bytes());
        data[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
        data[12..16].copy_from_slice(&1u32.to_le_bytes());
        data[16..20].copy_from_slice(&1u32.to_le_bytes());
        data[20..24].copy_from_slice(&72u32.to_le_bytes());
        data[32..36].copy_from_slice(&0x19u32.to_le_bytes());
        data[36..40].copy_from_slice(&72u32.to_le_bytes());
        data[40..56].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");

        let h = parse_macho64_header(&data).expect("parse");
        assert_eq!(h.cputype, 0x01000007);
        assert_eq!(h.ncmds, 1);
        assert_eq!(h.segments.len(), 1);
        assert_eq!(h.segments[0].name, "__TEXT");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_parse_real_object_symbol_count() {
        use std::process::Command;
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let main_add_c = manifest_dir.join("tests/c/main_add.c");
        if !main_add_c.exists() {
            return;
        }
        let tmp = std::env::temp_dir();
        let obj = tmp.join("weld_parse_symbol_test.o");
        let cc = Command::new("clang")
            .args(["-c", "-o"])
            .arg(&obj)
            .arg(&main_add_c)
            .output();
        let Ok(out) = cc else { return };
        if !out.status.success() {
            return;
        }
        let data = std::fs::read(&obj).unwrap_or_default();
        let _ = std::fs::remove_file(&obj);
        if data.len() < 100 {
            return;
        }
        let parsed = parse_macho64_object(&data).expect("parse");
        assert!(
            parsed.symbols.len() >= 4,
            "main_add.o should have at least 4 symbols, got {}",
            parsed.symbols.len()
        );
    }

    #[test]
    fn test_parse_macho_relocs() {
        let mut data = vec![0u8; 24];
        data[0..4].copy_from_slice(&4u32.to_le_bytes());
        data[4..8].copy_from_slice(&(1u32 << 27).to_le_bytes());
        data[8..12].copy_from_slice(&8u32.to_le_bytes());
        data[12..16].copy_from_slice(&0u32.to_le_bytes());
        let relocs = parse_macho_relocs(&data, 0, 2);
        assert_eq!(relocs.len(), 2);
        assert_eq!(relocs[0].r_address, 4);
        assert!(!relocs[0].r_pcrel);
        assert!(relocs[0].r_extern);
        assert_eq!(relocs[1].r_address, 8);
        assert!(!relocs[1].r_extern);
    }
}
