//! COFF object reader shared by the archive symbol scan and the PE linker.
//!
//! `parse` does not fail. It keeps what it can read and records the first
//! malformation in `Object::problem`, so each caller applies its own policy to
//! the same reading.

use crate::collections::HashMap;

pub(crate) const HEADER_SIZE: usize = 20;
pub(crate) const SECTION_HEADER_SIZE: usize = 40;
pub(crate) const SYMBOL_SIZE: usize = 18;
pub(crate) const RELOC_SIZE: usize = 10;

// Machine types present in bare object files (.obj).
// PE executables start with the DOS MZ header (0x4D5A), not one of these.
pub(crate) const MACHINE_I386: u16 = 0x014C;
pub(crate) const MACHINE_AMD64: u16 = 0x8664;
pub(crate) const MACHINE_ARM64: u16 = 0xAA64;
pub(crate) const MACHINE_ARM: u16 = 0x01C0;
pub(crate) const MACHINE_RISCV32: u16 = 0x5032;
pub(crate) const MACHINE_RISCV64: u16 = 0x5064;

pub(crate) const IMAGE_SYM_UNDEFINED_SECTION: i16 = 0;
pub(crate) const IMAGE_SYM_ABSOLUTE_SECTION: i16 = -1;
pub(crate) const IMAGE_SYM_CLASS_EXTERNAL: u8 = 2;
pub(crate) const IMAGE_SYM_CLASS_STATIC: u8 = 3;
/// Auxiliary record TagIndex names the default symbol used when the weak name
/// has no strong definition anywhere in the link.
pub(crate) const IMAGE_SYM_CLASS_WEAK_EXTERNAL: u8 = 105;

pub(crate) const IMAGE_SCN_LNK_COMDAT: u32 = 0x0000_1000;
pub(crate) const IMAGE_SCN_LNK_INFO: u32 = 0x0000_0200;
pub(crate) const IMAGE_SCN_LNK_REMOVE: u32 = 0x0000_0800;
pub(crate) const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub(crate) const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
/// Set with a count of 0xFFFF when the real relocation count does not fit in 16 bits.
pub(crate) const IMAGE_SCN_LNK_NRELOC_OVFL: u32 = 0x0100_0000;

#[derive(Clone)]
pub(crate) struct Symbol {
    pub name: String,
    pub section: i16,
    pub value: u32,
    pub class: u8,
    pub typ: u16,
    pub num_aux: usize,
    /// Symbol index of the default symbol, for weak externals.
    pub tag: usize,
    /// Name in the record at `tag`, when that index is inside the symbol table.
    pub tag_name: String,
}

impl Symbol {
    fn auxiliary() -> Self {
        Symbol {
            name: String::new(),
            section: IMAGE_SYM_UNDEFINED_SECTION,
            value: 0,
            class: 0,
            typ: 0,
            num_aux: 0,
            tag: 0,
            tag_name: String::new(),
        }
    }
}

pub(crate) struct Section<'a> {
    pub name: String,
    pub flags: u32,
    /// Linker-only or discardable sections contribute nothing to the link.
    pub skipped: bool,
    pub size: usize,
    /// Empty for uninitialized sections and for data outside the object.
    pub raw: &'a [u8],
    /// (virtual address, symbol index, type), up to the first unreadable record.
    pub relocs: Vec<(u32, u32, u16)>,
}

pub(crate) enum Problem {
    Truncated,
    SymbolTable,
    SectionData(String),
    Relocs(String),
}

pub(crate) struct Object<'a> {
    pub symbol_table_offset: usize,
    pub symbol_count: usize,
    /// Indexed by raw symbol table index; auxiliary records are placeholders.
    pub symbols: Vec<Symbol>,
    /// The symbol table ends inside the object; `symbols` holds the readable prefix.
    pub symbols_truncated: bool,
    pub sections: Vec<Section<'a>>,
    /// Auxiliary section definitions keyed by 1-based section number: (selection, associated section).
    pub comdat_aux: HashMap<usize, (u8, usize)>,
    pub problem: Option<Problem>,
}

pub(crate) fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

pub(crate) fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

pub(crate) fn parse(coff: &[u8]) -> Object<'_> {
    let mut object = Object {
        symbol_table_offset: 0,
        symbol_count: 0,
        symbols: Vec::new(),
        symbols_truncated: false,
        sections: Vec::new(),
        comdat_aux: HashMap::default(),
        problem: None,
    };
    let header = (|| {
        Some((
            read_u16(coff, 2)? as usize,
            read_u16(coff, 16)? as usize,
            read_u32(coff, 8)? as usize,
            read_u32(coff, 12)? as usize,
        ))
    })();
    let Some((n_sections, opt_size, sym_off, n_syms)) = header else {
        object.problem = Some(Problem::Truncated);
        return object;
    };
    object.symbol_table_offset = sym_off;
    object.symbol_count = n_syms;
    let strtab = string_table(coff, sym_off, n_syms).unwrap_or_else(|| {
        object.symbols_truncated = true;
        &[]
    });
    read_symbols(coff, sym_off, n_syms, strtab, &mut object);
    read_sections(coff, n_sections, opt_size, strtab, &mut object);
    if object.symbols_truncated {
        note(&mut object, Problem::SymbolTable);
    }
    object
}

fn note(object: &mut Object<'_>, problem: Problem) {
    if object.problem.is_none() {
        object.problem = Some(problem);
    }
}

fn string_table(coff: &[u8], sym_off: usize, n_syms: usize) -> Option<&[u8]> {
    if n_syms == 0 {
        return Some(&[]);
    }
    let off = sym_off.checked_add(n_syms.checked_mul(SYMBOL_SIZE)?)?;
    let size = read_u32(coff, off)? as usize;
    let end = off.saturating_add(size).min(coff.len());
    Some(&coff[off..end])
}

fn read_symbols(
    coff: &[u8],
    sym_off: usize,
    n_syms: usize,
    strtab: &[u8],
    object: &mut Object<'_>,
) {
    if n_syms > 0 && (sym_off == 0 || sym_off + n_syms * SYMBOL_SIZE > coff.len()) {
        object.symbols_truncated = true;
        if sym_off == 0 {
            return;
        }
    }
    let mut i = 0;
    while i < n_syms {
        let rec = sym_off + i * SYMBOL_SIZE;
        let Some(r) = coff.get(rec..rec + SYMBOL_SIZE) else {
            return;
        };
        let class = r[16];
        let section = i16::from_le_bytes([r[12], r[13]]);
        let num_aux = r[17] as usize;
        if class == IMAGE_SYM_CLASS_STATIC && section > 0 && num_aux > 0 {
            let aux_at = rec + SYMBOL_SIZE;
            if let (Some(&selection), Some(number)) =
                (coff.get(aux_at + 14), read_u16(coff, aux_at + 12))
            {
                object
                    .comdat_aux
                    .insert(section as usize, (selection, number as usize));
            }
        }
        let tag = if class == IMAGE_SYM_CLASS_WEAK_EXTERNAL {
            read_u32(coff, rec + SYMBOL_SIZE).unwrap_or(0) as usize
        } else {
            0
        };
        let tag_name = if class == IMAGE_SYM_CLASS_WEAK_EXTERNAL && tag < n_syms {
            let at = sym_off + tag * SYMBOL_SIZE;
            coff.get(at..at + 8)
                .map(|b| symbol_name(b, strtab))
                .unwrap_or_default()
        } else {
            String::new()
        };
        object.symbols.push(Symbol {
            name: symbol_name(&r[..8], strtab),
            section,
            value: u32::from_le_bytes([r[8], r[9], r[10], r[11]]),
            class,
            typ: u16::from_le_bytes([r[14], r[15]]),
            num_aux,
            tag,
            tag_name,
        });
        object
            .symbols
            .extend((0..num_aux).map(|_| Symbol::auxiliary()));
        i += 1 + num_aux;
    }
}

fn read_sections<'a>(
    coff: &'a [u8],
    n_sections: usize,
    opt_size: usize,
    strtab: &[u8],
    object: &mut Object<'a>,
) {
    for s in 0..n_sections {
        let sh = HEADER_SIZE + opt_size + s * SECTION_HEADER_SIZE;
        let Some(flags) = read_u32(coff, sh + 36) else {
            note(object, Problem::Truncated);
            return;
        };
        let skipped =
            flags & (IMAGE_SCN_LNK_INFO | IMAGE_SCN_LNK_REMOVE | IMAGE_SCN_MEM_DISCARDABLE) != 0;
        let name = section_name(&coff[sh..sh + 8], strtab);
        let (Some(raw_size), Some(raw_ptr), Some(relocs_ptr), Some(n_relocs)) = (
            read_u32(coff, sh + 16),
            read_u32(coff, sh + 20),
            read_u32(coff, sh + 24),
            read_u16(coff, sh + 32),
        ) else {
            note(object, Problem::Truncated);
            return;
        };
        let raw: &[u8] = if flags & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
            &[]
        } else {
            match coff.get(raw_ptr as usize..raw_ptr as usize + raw_size as usize) {
                Some(raw) => raw,
                None => {
                    if !skipped {
                        note(object, Problem::SectionData(name.clone()));
                    }
                    &[]
                }
            }
        };
        let (relocs_at, count) = match coff_reloc_span(coff, relocs_ptr as usize, n_relocs, flags) {
            Some(span) => span,
            None if skipped => (0, 0),
            None => {
                note(object, Problem::Truncated);
                return;
            }
        };
        let readable = coff.len().saturating_sub(relocs_at) / RELOC_SIZE;
        let mut relocs = Vec::with_capacity(count.min(readable));
        for r in 0..count {
            let o = relocs_at + r * RELOC_SIZE;
            let Some(rec) = coff.get(o..o + RELOC_SIZE) else {
                if !skipped {
                    note(object, Problem::Relocs(name.clone()));
                }
                break;
            };
            relocs.push((
                u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]),
                u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]),
                u16::from_le_bytes([rec[8], rec[9]]),
            ));
        }
        object.sections.push(Section {
            name,
            flags,
            skipped,
            size: raw_size as usize,
            raw,
            relocs,
        });
    }
}

/// Byte offset and count of a section's relocation records. A section with more than
/// 0xFFFF relocations sets `count` to 0xFFFF and IMAGE_SCN_LNK_NRELOC_OVFL; the real
/// count, including the record that holds it, is then the first record's VirtualAddress.
pub(crate) fn coff_reloc_span(
    data: &[u8],
    relocs_ptr: usize,
    count: u16,
    flags: u32,
) -> Option<(usize, usize)> {
    if count == u16::MAX && flags & IMAGE_SCN_LNK_NRELOC_OVFL != 0 {
        let total = read_u32(data, relocs_ptr)? as usize;
        return Some((relocs_ptr + RELOC_SIZE, total.checked_sub(1)?));
    }
    Some((relocs_ptr, count as usize))
}

/// Decode a COFF symbol name: either inline (≤8 bytes, NUL-padded) or a
/// string-table reference stored as 0x00000000 + 4-byte offset.
fn symbol_name(name_bytes: &[u8], strtab: &[u8]) -> String {
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
fn section_name(raw: &[u8], strtab: &[u8]) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflowed_relocation_count_comes_from_first_record() {
        let mut data = vec![0u8; 64];
        data[20..24].copy_from_slice(&5u32.to_le_bytes());
        assert_eq!(
            coff_reloc_span(&data, 20, u16::MAX, IMAGE_SCN_LNK_NRELOC_OVFL),
            Some((30, 4))
        );
        assert_eq!(coff_reloc_span(&data, 20, 3, 0), Some((20, 3)));
        assert_eq!(coff_reloc_span(&data, 20, u16::MAX, 0), Some((20, 65535)));
    }

    #[test]
    fn truncated_string_table_header_is_reported_not_guessed() {
        let mut data = vec![0u8; 36 + SYMBOL_SIZE + 2];
        data[8..12].copy_from_slice(&36u32.to_le_bytes());
        data[12..16].copy_from_slice(&1u32.to_le_bytes());
        data[36 + 4..36 + 8].copy_from_slice(&4u32.to_le_bytes());
        let object = parse(&data);
        assert!(matches!(object.problem, Some(Problem::SymbolTable)));
    }

    #[test]
    fn unreadable_relocation_records_reserve_nothing() {
        let mut data = vec![0u8; 64];
        data[2..4].copy_from_slice(&1u16.to_le_bytes());
        data[56..60].copy_from_slice(&IMAGE_SCN_LNK_NRELOC_OVFL.to_le_bytes());
        data[44..48].copy_from_slice(&60u32.to_le_bytes());
        data[52..54].copy_from_slice(&u16::MAX.to_le_bytes());
        data[60..64].copy_from_slice(&u32::MAX.to_le_bytes());
        let object = parse(&data);
        assert!(object.sections[0].relocs.is_empty());
        assert!(object.sections[0].relocs.capacity() < 1024);
    }
}
