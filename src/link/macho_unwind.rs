//! Mach-O `__TEXT,__unwind_info` from the `__LD,__compact_unwind` entries of the inputs.
//!
//! Each input entry is 32 bytes: the function address, its length, a 32-bit encoding,
//! the personality routine and the LSDA. The unwinder reads the output table: a version 1
//! header, the personality offsets, a first-level index, the LSDA entries, and regular
//! second-level pages. Offsets are from the Mach-O header, except the section offsets
//! in the header and the index, which are from the start of the section.

use crate::collections::HashMap;
use crate::macho::{GENERIC_RELOC_VANILLA, Macho64Object, MachoReloc, parse_macho_relocs};

const ENTRY_SIZE: usize = 32;
const HEADER_SIZE: usize = 28;
const INDEX_SIZE: usize = 12;
const LSDA_SIZE: usize = 8;
const PAGE_HEADER_SIZE: usize = 8;
const PAGE_ENTRY_SIZE: usize = 8;
const REGULAR_PAGE_KIND: u32 = 2;
/// A regular page holds `(4096 - 8) / 8` entries, which keeps every page under 4 KiB.
const PAGE_ENTRY_LIMIT: usize = 511;
/// The personality index lives in two bits of the encoding, with 0 meaning none.
const PERSONALITY_LIMIT: usize = 3;
const UNWIND_HAS_LSDA: u32 = 0x4000_0000;
const UNWIND_PERSONALITY_MASK: u32 = 0x3000_0000;
const UNWIND_MODE_MASK: u32 = 0x0f00_0000;
const UNWIND_MODE_DWARF: u32 = 0x0300_0000;

/// One function's compact unwind entry, with its pointers resolved to layout addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompactEntry {
    pub function: u64,
    pub length: u32,
    pub encoding: u32,
    /// The imported personality routine, by symbol name.
    pub personality: Option<String>,
    pub lsda: Option<u64>,
}

/// A pointer field of a compact unwind entry, after its relocation is applied.
enum Pointer {
    Null,
    Address(u64),
    Import(String),
}

/// Reads the compact unwind entries of one object. `vaddr_by_sect` maps each object
/// section (1-based) to its layout address. `symbol_addrs` maps each symbol index to its
/// layout address, or `None` when the symbol is not defined anywhere in the link.
pub(crate) fn collect_entries(
    obj: &Macho64Object,
    vaddr_by_sect: &HashMap<u8, u64>,
    symbol_addrs: &[Option<u64>],
) -> Result<Vec<CompactEntry>, String> {
    let Some(sec) = obj
        .sections
        .iter()
        .find(|s| s.segname == "__LD" && s.sectname == "__compact_unwind")
    else {
        return Ok(Vec::new());
    };
    let size = sec.size as usize;
    if !size.is_multiple_of(ENTRY_SIZE) {
        return Err(format!(
            "__LD,__compact_unwind is {size} bytes, not a multiple of {ENTRY_SIZE}"
        ));
    }
    let start = sec.offset as usize;
    let data = obj
        .data
        .get(start..start + size)
        .ok_or("__LD,__compact_unwind extends past the end of the object")?;
    let mut relocs_by_offset: HashMap<u32, MachoReloc> = HashMap::default();
    for r in parse_macho_relocs(&obj.data, sec.reloff, sec.nreloc) {
        relocs_by_offset.insert(r.r_address, r);
    }

    let pointer = |field: usize| -> Result<Pointer, String> {
        let value = read_u64(data, field);
        let Some(r) = relocs_by_offset.get(&(field as u32)) else {
            if value == 0 {
                return Ok(Pointer::Null);
            }
            return Err(format!(
                "compact unwind pointer at offset 0x{field:x} has no relocation"
            ));
        };
        if r.r_type != GENERIC_RELOC_VANILLA || r.r_pcrel || r.r_length != 3 {
            return Err(format!(
                "compact unwind pointer at offset 0x{field:x} is not an absolute 64-bit UNSIGNED relocation"
            ));
        }
        if r.r_extern {
            let idx = r.r_symbolnum as usize;
            let sym = obj
                .symbols
                .get(idx)
                .ok_or("compact unwind relocation names no symbol")?;
            return match symbol_addrs.get(idx).copied().flatten() {
                Some(addr) => Ok(Pointer::Address(addr.wrapping_add(value))),
                None => Ok(Pointer::Import(sym.name.clone())),
            };
        }
        let sect = r.r_symbolnum as usize;
        let sec_addr = obj
            .sections
            .get(sect.wrapping_sub(1))
            .ok_or("compact unwind relocation names no section")?
            .addr;
        let offset_in_sect = value
            .checked_sub(sec_addr)
            .ok_or("compact unwind pointer lies before its section")?;
        let base = vaddr_by_sect
            .get(&(sect as u8))
            .copied()
            .ok_or("compact unwind pointer targets a section that is not in the output")?;
        Ok(Pointer::Address(base + offset_in_sect))
    };

    let mut entries = Vec::with_capacity(size / ENTRY_SIZE);
    for n in 0..size / ENTRY_SIZE {
        let at = n * ENTRY_SIZE;
        let function = match pointer(at)? {
            Pointer::Address(addr) => addr,
            _ => return Err("compact unwind entry does not name a defined function".into()),
        };
        let length = read_u32(data, at + 8);
        let encoding = read_u32(data, at + 12);
        if encoding & UNWIND_MODE_MASK == UNWIND_MODE_DWARF {
            return Err(format!(
                "compact unwind entry for the function at 0x{function:x} uses DWARF mode (encoding 0x{encoding:08x}), which needs __eh_frame and is not supported on Mach-O yet"
            ));
        }
        let personality = match pointer(at + 16)? {
            Pointer::Null => None,
            Pointer::Import(name) => Some(name),
            Pointer::Address(_) => {
                return Err(
                    "a compact unwind personality routine defined in the link is not supported"
                        .into(),
                );
            }
        };
        let lsda = match pointer(at + 24)? {
            Pointer::Null => None,
            Pointer::Address(addr) => Some(addr),
            Pointer::Import(name) => {
                return Err(format!(
                    "LSDA for the function at 0x{function:x} names undefined {name}"
                ));
            }
        };
        entries.push(CompactEntry {
            function,
            length,
            encoding: encoding & !UNWIND_PERSONALITY_MASK,
            personality,
            lsda,
        });
    }
    Ok(entries)
}

/// One first-level row of the table, once addresses are offsets from the Mach-O header.
struct Row {
    function: u32,
    end: u32,
    encoding: u32,
    lsda: Option<u32>,
}

/// Builds the `__unwind_info` bytes. `offset_of` maps a layout address to its offset
/// from the Mach-O header, and `personality_offset` maps a personality symbol to the
/// offset of its GOT slot from the Mach-O header. The size depends only on the counts,
/// so a caller may build with placeholder mappings to reserve the section first.
pub(crate) fn build_unwind_info(
    entries: &[CompactEntry],
    offset_of: impl Fn(u64) -> Result<u32, String>,
    personality_offset: impl Fn(&str) -> Result<u32, String>,
) -> Result<Vec<u8>, String> {
    let mut personalities: Vec<&str> = Vec::new();
    let mut rows: Vec<Row> = Vec::with_capacity(entries.len());
    for entry in entries {
        let function = offset_of(entry.function)?;
        let length = entry.length;
        let end = function
            .checked_add(length)
            .ok_or("compact unwind function extends past the 32-bit offset range")?;
        let personality_index = match entry.personality.as_deref() {
            None => 0,
            Some(name) => {
                let idx = match personalities.iter().position(|p| *p == name) {
                    Some(idx) => idx,
                    None => {
                        personalities.push(name);
                        personalities.len() - 1
                    }
                };
                if personalities.len() > PERSONALITY_LIMIT {
                    return Err(format!(
                        "more than {PERSONALITY_LIMIT} personality routines are not supported"
                    ));
                }
                idx as u32 + 1
            }
        };
        let lsda = entry.lsda.map(&offset_of).transpose()?;
        let mut encoding = entry.encoding & !UNWIND_PERSONALITY_MASK;
        encoding |= personality_index << 28;
        if lsda.is_some() {
            encoding |= UNWIND_HAS_LSDA;
        } else {
            encoding &= !UNWIND_HAS_LSDA;
        }
        rows.push(Row {
            function,
            end,
            encoding,
            lsda,
        });
    }
    rows.sort_by_key(|row| row.function);
    if rows.windows(2).any(|w| w[0].function == w[1].function) {
        return Err("two compact unwind entries name the same function".into());
    }

    let personality_count = personalities.len();
    let lsda_rows: Vec<(u32, u32)> = rows
        .iter()
        .filter_map(|row| row.lsda.map(|lsda| (row.function, lsda)))
        .collect();
    let page_count = rows.len().div_ceil(PAGE_ENTRY_LIMIT);
    let index_count = page_count + 1;

    let personality_start = HEADER_SIZE;
    let index_start = personality_start + 4 * personality_count;
    let lsda_start = index_start + INDEX_SIZE * index_count;
    let pages_start = lsda_start + LSDA_SIZE * lsda_rows.len();
    let total = pages_start
        + rows
            .chunks(PAGE_ENTRY_LIMIT)
            .map(|page| PAGE_HEADER_SIZE + PAGE_ENTRY_SIZE * page.len())
            .sum::<usize>();

    let mut out: Vec<u8> = Vec::with_capacity(total);
    let as_u32 = |value: usize| -> Result<u32, String> {
        u32::try_from(value).map_err(|_| "__unwind_info exceeds 4 GiB".to_string())
    };
    for word in [
        1,
        HEADER_SIZE,
        0,
        personality_start,
        personality_count,
        index_start,
        index_count,
    ] {
        out.extend_from_slice(&as_u32(word)?.to_le_bytes());
    }
    for name in &personalities {
        let offset = personality_offset(name)?;
        out.extend_from_slice(&offset.to_le_bytes());
    }

    let mut page_start = pages_start;
    for page in rows.chunks(PAGE_ENTRY_LIMIT) {
        let first = page[0].function;
        let lsdas_before = lsda_rows.partition_point(|(function, _)| *function < first);
        out.extend_from_slice(&first.to_le_bytes());
        out.extend_from_slice(&as_u32(page_start)?.to_le_bytes());
        out.extend_from_slice(&as_u32(lsda_start + LSDA_SIZE * lsdas_before)?.to_le_bytes());
        page_start += PAGE_HEADER_SIZE + PAGE_ENTRY_SIZE * page.len();
    }
    let sentinel = rows.iter().map(|row| row.end).max().unwrap_or(0);
    out.extend_from_slice(&sentinel.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&as_u32(lsda_start + LSDA_SIZE * lsda_rows.len())?.to_le_bytes());
    debug_assert_eq!(out.len(), lsda_start);

    for (function, lsda) in &lsda_rows {
        out.extend_from_slice(&function.to_le_bytes());
        out.extend_from_slice(&lsda.to_le_bytes());
    }
    for page in rows.chunks(PAGE_ENTRY_LIMIT) {
        out.extend_from_slice(&REGULAR_PAGE_KIND.to_le_bytes());
        out.extend_from_slice(&(PAGE_HEADER_SIZE as u16).to_le_bytes());
        out.extend_from_slice(&(page.len() as u16).to_le_bytes());
        for row in page {
            out.extend_from_slice(&row.function.to_le_bytes());
            out.extend_from_slice(&row.encoding.to_le_bytes());
        }
    }
    debug_assert_eq!(out.len(), total);
    Ok(out)
}

/// An upper bound on the size of the table for `count` entries. The personality and LSDA
/// arrays are sized for their largest possible contents, so the bound holds whatever the
/// entries turn out to name.
pub(crate) fn reserved_size(count: usize) -> usize {
    let pages = count.div_ceil(PAGE_ENTRY_LIMIT);
    HEADER_SIZE
        + PERSONALITY_LIMIT * 4
        + INDEX_SIZE * (pages + 1)
        + (LSDA_SIZE + PAGE_ENTRY_SIZE) * count
        + PAGE_HEADER_SIZE * pages
}

/// The number of compact unwind entries in one object.
pub(crate) fn entry_count(obj: &Macho64Object) -> usize {
    obj.sections
        .iter()
        .filter(|s| s.segname == "__LD" && s.sectname == "__compact_unwind")
        .map(|s| s.size as usize / ENTRY_SIZE)
        .sum()
}

fn read_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}

fn read_u64(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}
