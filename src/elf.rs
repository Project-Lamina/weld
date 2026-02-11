//! Minimal ELF64 parser for relocatable object files.
//! No external crate; manual byte parsing.

#![allow(dead_code)]

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ElfType {
    Relocatable = 1,
    Executable = 2,
    Dynamic = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SectionType {
    Null = 0,
    Progbits = 1,
    Symtab = 2,
    Strtab = 3,
    Rela = 4,
}

#[derive(Debug, Clone)]
pub struct SectionHeader {
    pub name_offset: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

#[derive(Debug, Clone)]
pub struct Elf64Header {
    pub e_type: u16,
    pub e_machine: u16,
    pub e_shoff: u64,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

fn read_u16_le(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64_le(data: &[u8], off: usize) -> Option<u64> {
    data.get(off..off + 8).map(|b| {
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    })
}

pub fn parse_elf64_header(data: &[u8]) -> Result<Elf64Header, String> {
    if data.len() < 64 {
        return Err("file too short for ELF64 header".to_string());
    }
    if data[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Err("not an ELF file".to_string());
    }
    if data[4] != 2 {
        return Err("not ELF64".to_string());
    }
    if data[5] != 1 {
        return Err("not little-endian".to_string());
    }

    let e_type = read_u16_le(data, 16).ok_or("bad e_type")?;
    let e_machine = read_u16_le(data, 18).ok_or("bad e_machine")?;
    let e_shoff = read_u64_le(data, 40).ok_or("bad e_shoff")?;
    let e_shnum = read_u16_le(data, 60).ok_or("bad e_shnum")?;
    let e_shstrndx = read_u16_le(data, 62).ok_or("bad e_shstrndx")?;

    Ok(Elf64Header {
        e_type,
        e_machine,
        e_shoff,
        e_shnum,
        e_shstrndx,
    })
}

pub fn parse_section_header(data: &[u8], off: u64) -> Result<SectionHeader, String> {
    let off = off as usize;
    if data.len() < off + 64 {
        return Err("file too short for section header".to_string());
    }

    let name_offset = read_u32_le(data, off).ok_or("bad sh_name")?;
    let sh_type = read_u32_le(data, off + 4).ok_or("bad sh_type")?;
    let sh_flags = read_u64_le(data, off + 8).ok_or("bad sh_flags")?;
    let sh_addr = read_u64_le(data, off + 16).ok_or("bad sh_addr")?;
    let sh_offset = read_u64_le(data, off + 24).ok_or("bad sh_offset")?;
    let sh_size = read_u64_le(data, off + 32).ok_or("bad sh_size")?;
    let sh_link = read_u32_le(data, off + 40).ok_or("bad sh_link")?;
    let sh_info = read_u32_le(data, off + 44).ok_or("bad sh_info")?;
    let sh_addralign = read_u64_le(data, off + 48).ok_or("bad sh_addralign")?;
    let sh_entsize = read_u64_le(data, off + 56).ok_or("bad sh_entsize")?;

    Ok(SectionHeader {
        name_offset,
        sh_type,
        sh_flags,
        sh_addr,
        sh_offset,
        sh_size,
        sh_link,
        sh_info,
        sh_addralign,
        sh_entsize,
    })
}

pub fn get_section_name(_data: &[u8], shstrtab: &[u8], name_offset: u32) -> Option<String> {
    let mut i = name_offset as usize;
    while i < shstrtab.len() && shstrtab[i] != 0 {
        i += 1;
    }
    let slice = shstrtab.get(name_offset as usize..i)?;
    std::str::from_utf8(slice).ok().map(String::from)
}

pub fn parse_elf64_file(path: &Path) -> Result<(Elf64Header, Vec<SectionHeader>, Vec<String>), String> {
    let data = std::fs::read(path).map_err(|e| format!("read failed: {}", e))?;
    parse_elf64_slice(&data)
}

pub fn parse_elf64_slice(data: &[u8]) -> Result<(Elf64Header, Vec<SectionHeader>, Vec<String>), String> {
    let header = parse_elf64_header(data)?;

    let shoff = header.e_shoff as usize;
    let shnum = header.e_shnum as usize;
    let shstrndx = header.e_shstrndx as usize;

    if shnum == 0 {
        return Ok((header, Vec::new(), Vec::new()));
    }

    let mut sections = Vec::with_capacity(shnum);
    for i in 0..shnum {
        let off = shoff + i * 64;
        let sh = parse_section_header(data, off as u64)?;
        sections.push(sh);
    }

    let shstrtab_data = if shstrndx < sections.len() {
        let sh = &sections[shstrndx];
        let start = sh.sh_offset as usize;
        let end = start + sh.sh_size as usize;
        data.get(start..end).unwrap_or(&[])
    } else {
        &[]
    };

    let mut names = Vec::with_capacity(shnum);
    for sh in &sections {
        let name = get_section_name(data, shstrtab_data, sh.name_offset)
            .unwrap_or_else(|| format!("<{}>", sh.name_offset));
        names.push(name);
    }

    Ok((header, sections, names))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_elf_header() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        data[4] = 2;
        data[5] = 1;
        data[16..18].copy_from_slice(&1u16.to_le_bytes());
        data[18..20].copy_from_slice(&62u16.to_le_bytes());
        data[40..48].copy_from_slice(&64u64.to_le_bytes());
        data[60..62].copy_from_slice(&3u16.to_le_bytes());
        data[62..64].copy_from_slice(&1u16.to_le_bytes());

        let header = parse_elf64_header(&data).expect("parse");
        assert_eq!(header.e_type, 1);
        assert_eq!(header.e_machine, 62);
        assert_eq!(header.e_shoff, 64);
        assert_eq!(header.e_shnum, 3);
    }
}
