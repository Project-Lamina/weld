//! Minimal Mach-O 64-bit reader skeleton.
//!
//! Parses header and LC_SEGMENT_64 for __TEXT and __DATA.
//! Used for future Mach-O linking (Phase 6.2).

#![allow(dead_code)]

use std::path::Path;

const MH_MAGIC_64: u32 = 0xFEEDFACF;
const MH_CIGAM_64: u32 = 0xCFFAEDFE;
const LC_SEGMENT_64: u32 = 0x19;

const CPU_TYPE_X86_64: u32 = 0x01000007;
const CPU_TYPE_ARM64: u32 = 0x0100000C;

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
pub struct Macho64Header {
    pub cputype: u32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub segments: Vec<MachoSegment>,
}

fn read_u32_be(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
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
}
