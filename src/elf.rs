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

const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const ELF64_SYM_SIZE: usize = 24;
const ELF64_RELA_SIZE: usize = 24;

pub mod reloc_type {
    pub const R_X86_64_NONE: u32 = 0;
    pub const R_X86_64_64: u32 = 1;
    pub const R_X86_64_PC32: u32 = 2;
    pub const R_X86_64_32: u32 = 10;
    pub const R_X86_64_RELATIVE: u32 = 8;
    pub const R_X86_64_PLT32: u32 = 4;
    pub const R_X86_64_GOTPCREL: u32 = 9;

    pub const R_AARCH64_NONE: u32 = 0;
    pub const R_AARCH64_ABS64: u32 = 257;
    pub const R_AARCH64_ABS32: u32 = 258;
    pub const R_AARCH64_ADD_ABS_LO12_NC: u32 = 277;
    pub const R_AARCH64_ADR_PREL_LO21: u32 = 274;
    pub const R_AARCH64_ADR_PREL_PG_HI21: u32 = 275;
    pub const R_AARCH64_JUMP26: u32 = 282;
    pub const R_AARCH64_CALL26: u32 = 283;
    pub const R_AARCH64_RELATIVE: u32 = 1027;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SymBind {
    Local = 0,
    Global = 1,
    Weak = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SymType {
    Notype = 0,
    Object = 1,
    Func = 2,
    Section = 3,
    File = 4,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name_offset: u32,
    pub bind: u8,
    pub sym_type: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
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

pub fn parse_symbol_entry(data: &[u8], off: usize) -> Result<Symbol, String> {
    if data.len() < off + ELF64_SYM_SIZE {
        return Err("file too short for symbol entry".to_string());
    }
    let st_name = read_u32_le(data, off).ok_or("bad st_name")?;
    let st_info = data.get(off + 4).copied().ok_or("bad st_info")?;
    let _st_other = data.get(off + 5).copied();
    let st_shndx = read_u16_le(data, off + 6).ok_or("bad st_shndx")?;
    let st_value = read_u64_le(data, off + 8).ok_or("bad st_value")?;
    let st_size = read_u64_le(data, off + 16).ok_or("bad st_size")?;

    let bind = st_info >> 4;
    let sym_type = st_info & 0xf;

    Ok(Symbol {
        name_offset: st_name,
        bind,
        sym_type,
        st_shndx,
        st_value,
        st_size,
    })
}

pub fn get_strtab_string(strtab: &[u8], offset: u32) -> Option<String> {
    if offset == 0 {
        return Some(String::new());
    }
    let mut i = offset as usize;
    while i < strtab.len() && strtab[i] != 0 {
        i += 1;
    }
    let slice = strtab.get(offset as usize..i)?;
    std::str::from_utf8(slice).ok().map(String::from)
}

pub fn parse_symtab(data: &[u8], symtab_sh: &SectionHeader) -> Result<Vec<Symbol>, String> {
    let sym_start = symtab_sh.sh_offset as usize;
    let entsize = symtab_sh.sh_entsize as usize;
    let count = if entsize > 0 {
        (symtab_sh.sh_size as usize) / entsize
    } else {
        (symtab_sh.sh_size as usize) / ELF64_SYM_SIZE
    };

    let mut symbols = Vec::with_capacity(count);
    for i in 0..count {
        let off = sym_start + i * ELF64_SYM_SIZE;
        let sym = parse_symbol_entry(data, off)?;
        symbols.push(sym);
    }
    Ok(symbols)
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

#[derive(Debug, Clone)]
pub struct RelaEntry {
    pub r_offset: u64,
    pub r_sym: u32,
    pub r_type: u32,
    pub r_addend: i64,
}

pub fn parse_rela_entry(data: &[u8], off: usize) -> Result<RelaEntry, String> {
    if data.len() < off + ELF64_RELA_SIZE {
        return Err("file too short for RELA entry".to_string());
    }
    let r_offset = read_u64_le(data, off).ok_or("bad r_offset")?;
    let r_info = read_u64_le(data, off + 8).ok_or("bad r_info")?;
    let r_addend = read_u64_le(data, off + 16).ok_or("bad r_addend")? as i64;

    let r_sym = (r_info >> 32) as u32;
    let r_type = (r_info & 0xffff_ffff) as u32;

    Ok(RelaEntry {
        r_offset,
        r_sym,
        r_type,
        r_addend,
    })
}

pub fn parse_rela_section(data: &[u8], rela_sh: &SectionHeader) -> Result<Vec<RelaEntry>, String> {
    let start = rela_sh.sh_offset as usize;
    let entsize = rela_sh.sh_entsize as usize;
    let size = entsize.max(ELF64_RELA_SIZE);
    let count = (rela_sh.sh_size as usize) / size;

    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let off = start + i * size;
        let entry = parse_rela_entry(data, off)?;
        entries.push(entry);
    }
    Ok(entries)
}

pub fn get_strtab_from_section<'a>(data: &'a [u8], sh: &SectionHeader) -> &'a [u8] {
    let start = sh.sh_offset as usize;
    let end = start + sh.sh_size as usize;
    data.get(start..end).unwrap_or(&[])
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

    #[test]
    fn test_parse_symbol_entry() {
        let mut data = vec![0u8; 24];
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        data[4] = 0x12;
        data[6..8].copy_from_slice(&1u16.to_le_bytes());
        data[8..16].copy_from_slice(&0x100u64.to_le_bytes());

        let sym = parse_symbol_entry(&data, 0).expect("parse");
        assert_eq!(sym.name_offset, 1);
        assert_eq!(sym.bind, 1);
        assert_eq!(sym.sym_type, 2);
        assert_eq!(sym.st_shndx, 1);
        assert_eq!(sym.st_value, 0x100);
    }

    #[test]
    fn test_get_strtab_string() {
        let strtab = b"\0main\0foo\0";
        assert_eq!(get_strtab_string(strtab, 0).as_deref(), Some(""));
        assert_eq!(get_strtab_string(strtab, 1).as_deref(), Some("main"));
        assert_eq!(get_strtab_string(strtab, 6).as_deref(), Some("foo"));
    }

    #[test]
    fn test_parse_rela_entry() {
        let mut data = vec![0u8; 24];
        data[0..8].copy_from_slice(&0x10u64.to_le_bytes());
        data[8..16].copy_from_slice(&(1u64 | (5u64 << 32)).to_le_bytes());
        data[16..24].copy_from_slice(&(-4i64 as u64).to_le_bytes());

        let rel = parse_rela_entry(&data, 0).expect("parse");
        assert_eq!(rel.r_offset, 0x10);
        assert_eq!(rel.r_sym, 5);
        assert_eq!(rel.r_type, 1);
        assert_eq!(rel.r_addend, -4);
    }
}
