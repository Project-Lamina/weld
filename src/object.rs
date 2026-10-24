use crate::{
    archive,
    elf::{get_strtab_from_section, get_strtab_string, parse_elf64_slice, parse_symtab},
    macho::{is_macho_dylib, is_macho64, parse_macho64_object},
};

use crate::collections::{HashMap, HashSet};
use std::{
    io::{Read, Seek},
    path::{Path, PathBuf},
};

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const FAT_MAGIC: u32 = 0xCAFEBABE;
const FAT_MAGIC_64: u32 = 0xCAFEBABF;
const CPU_TYPE_X86_64: u32 = 0x01000007;
const CPU_TYPE_ARM64: u32 = 0x0100000C;
const SHN_UNDEF: u16 = 0;
const SHT_SYMTAB: u32 = 2;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;
const N_EXT: u8 = 0x01;

// COFF machine types present in bare object files (.obj).
// PE executables start with the DOS MZ header (0x4D5A), not one of these.
const COFF_MACHINE_I386: u16 = 0x014C;
const COFF_MACHINE_AMD64: u16 = 0x8664;
const COFF_MACHINE_ARM64: u16 = 0xAA64;
const COFF_MACHINE_ARM: u16 = 0x01C0;
const COFF_MACHINE_RISCV32: u16 = 0x5032;
const COFF_MACHINE_RISCV64: u16 = 0x5064;

const IMAGE_SYM_UNDEFINED: i16 = 0;
const IMAGE_SYM_CLASS_EXTERNAL: u8 = 2;
const IMAGE_SYM_CLASS_WEAK_EXTERNAL: u8 = 105;

#[derive(Default, Clone)]
struct ObjectSymbolSummary {
    defined: HashSet<String>,
    undefined: HashSet<String>,
    /// (weak name, default name) pairs from COFF weak externals.
    weak_defaults: Vec<(String, String)>,
}

#[derive(Clone)]
struct ArchiveEntry {
    position: usize,
    start: usize,
    len: usize,
    symbols: Option<ObjectSymbolSummary>,
    selected: bool,
}

struct ArchiveEntries {
    buffer: Vec<u8>,
    file: Option<std::fs::File>,
    members: Vec<ArchiveEntry>,
    index: Option<HashMap<String, Vec<usize>>>,
}

impl ArchiveEntries {
    fn body(&mut self, i: usize) -> Vec<u8> {
        let (start, len) = (self.members[i].start, self.members[i].len);
        match &mut self.file {
            Some(file) => {
                let mut body = vec![0u8; len];
                let read = file
                    .seek(std::io::SeekFrom::Start(start as u64))
                    .and_then(|_| file.read_exact(&mut body));
                if read.is_err() {
                    body.clear();
                }
                body
            }
            None => self.buffer.get(start..start + len).unwrap_or(&[]).to_vec(),
        }
    }
}

fn read_u32_be(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64_be(data: &[u8], off: usize) -> Option<u64> {
    data.get(off..off + 8)
        .map(|b| u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

fn host_macho_cputype() -> Option<u32> {
    match std::env::consts::ARCH {
        "x86_64" => Some(CPU_TYPE_X86_64),
        "aarch64" => Some(CPU_TYPE_ARM64),
        _ => None,
    }
}

fn thin_fat_macho_binary(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 8 {
        return None;
    }

    let magic = read_u32_be(data, 0)?;
    let is_fat64 = match magic {
        FAT_MAGIC => false,
        FAT_MAGIC_64 => true,
        _ => return None,
    };

    let nfat_arch = read_u32_be(data, 4)? as usize;
    let arch_size = if is_fat64 { 32usize } else { 20usize };
    let table_end = 8usize.checked_add(nfat_arch.checked_mul(arch_size)?)?;
    if table_end > data.len() {
        return None;
    }

    let wanted = host_macho_cputype();
    let mut first_slice: Option<(usize, usize)> = None;
    let mut selected: Option<(usize, usize)> = None;

    for idx in 0..nfat_arch {
        let off = 8 + idx * arch_size;
        let cputype = read_u32_be(data, off)?;
        let (slice_off, slice_size) = if is_fat64 {
            (
                read_u64_be(data, off + 8)? as usize,
                read_u64_be(data, off + 16)? as usize,
            )
        } else {
            (
                read_u32_be(data, off + 8)? as usize,
                read_u32_be(data, off + 12)? as usize,
            )
        };

        let slice_end = slice_off.checked_add(slice_size)?;
        if slice_end > data.len() {
            continue;
        }

        first_slice.get_or_insert((slice_off, slice_size));
        if Some(cputype) == wanted {
            selected = Some((slice_off, slice_size));
            break;
        }
    }

    let (slice_off, slice_size) = selected.or(first_slice)?;
    Some(data[slice_off..slice_off + slice_size].to_vec())
}

fn normalize_macho_container(data: Vec<u8>) -> Vec<u8> {
    thin_fat_macho_binary(&data).unwrap_or(data)
}

fn is_elf(data: &[u8]) -> bool {
    data.len() >= ELF_MAGIC.len() && data[..ELF_MAGIC.len()] == ELF_MAGIC
}

fn read_u16_le(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn is_coff(data: &[u8]) -> bool {
    if data.len() < 20 {
        return false;
    }
    let machine = match read_u16_le(data, 0) {
        Some(m) => m,
        None => return false,
    };
    // Reject MZ (PE) headers — those need the PE linker path, not direct COFF parsing.
    if data[0] == b'M' && data[1] == b'Z' {
        return false;
    }
    matches!(
        machine,
        COFF_MACHINE_I386
            | COFF_MACHINE_AMD64
            | COFF_MACHINE_ARM64
            | COFF_MACHINE_ARM
            | COFF_MACHINE_RISCV32
            | COFF_MACHINE_RISCV64
    )
}

/// Extract global/external symbol names from a COFF object file.
fn collect_coff_symbol_summary(data: &[u8]) -> Option<ObjectSymbolSummary> {
    if data.len() < 20 {
        return None;
    }
    let sym_table_off = read_u32_le(data, 8)? as usize;
    let sym_count = read_u32_le(data, 12)? as usize;

    if sym_table_off == 0 || sym_count == 0 {
        return Some(ObjectSymbolSummary::default());
    }

    // Each COFF symbol record is exactly 18 bytes.
    let sym_table_end = sym_table_off.checked_add(sym_count.checked_mul(18)?)?;
    if sym_table_end > data.len() {
        return None;
    }

    // The string table immediately follows the symbol table.
    let strtab_off = sym_table_end;
    let strtab_size = if strtab_off + 4 <= data.len() {
        read_u32_le(data, strtab_off)? as usize
    } else {
        0
    };
    let strtab_end = strtab_off.checked_add(strtab_size)?;
    let strtab = if strtab_end <= data.len() {
        &data[strtab_off..strtab_end]
    } else {
        &data[strtab_off.min(data.len())..]
    };

    let referenced = coff_relocated_symbols(data);
    let mut weak_tags: HashSet<usize> = HashSet::default();
    let mut i = 0usize;
    while i < sym_count {
        let rec_off = sym_table_off + i * 18;
        if data[rec_off + 16] == IMAGE_SYM_CLASS_WEAK_EXTERNAL {
            let tag = read_u32_le(data, rec_off + 18).unwrap_or(0) as usize;
            weak_tags.insert(tag);
        }
        i += 1 + data[rec_off + 17] as usize;
    }

    let mut summary = ObjectSymbolSummary::default();
    let mut i = 0usize;
    while i < sym_count {
        let rec_off = sym_table_off + i * 18;
        let section_number = i16::from_le_bytes([data[rec_off + 12], data[rec_off + 13]]);
        let storage_class = data[rec_off + 16];
        let num_aux = data[rec_off + 17] as usize;
        let name = coff_symbol_name(&data[rec_off..rec_off + 8], strtab);

        if storage_class == IMAGE_SYM_CLASS_EXTERNAL && !name.is_empty() {
            if section_number != IMAGE_SYM_UNDEFINED {
                summary.defined.insert(name);
            } else if referenced.contains(&i) || !weak_tags.contains(&i) {
                summary.undefined.insert(name);
            }
        } else if storage_class == IMAGE_SYM_CLASS_WEAK_EXTERNAL && num_aux > 0 && !name.is_empty()
        {
            let tag = read_u32_le(data, rec_off + 18).unwrap_or(0) as usize;
            if tag < sym_count {
                let tag_off = sym_table_off + tag * 18;
                let default = coff_symbol_name(&data[tag_off..tag_off + 8], strtab);
                if referenced.contains(&i) && !default.is_empty() {
                    summary.undefined.insert(name.clone());
                    summary.weak_defaults.push((name, default));
                }
            }
        }

        i += 1 + num_aux;
    }

    summary
        .undefined
        .retain(|sym| !summary.defined.contains(sym));
    Some(summary)
}

/// Symbol-table indices named by any relocation in the object. Overflowed
/// relocation counts are not followed, so such an object is read as referencing
/// only the relocations it lists directly.
fn coff_relocated_symbols(data: &[u8]) -> HashSet<usize> {
    let mut referenced = HashSet::default();
    let Some(n_sections) = data
        .get(2..4)
        .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
    else {
        return referenced;
    };
    let opt_size = data
        .get(16..18)
        .map_or(0, |b| u16::from_le_bytes([b[0], b[1]]) as usize);
    for s in 0..n_sections {
        let sh = 20 + opt_size + s * 40;
        let (Some(ptr), Some(count)) = (read_u32_le(data, sh + 24), data.get(sh + 32..sh + 34))
        else {
            break;
        };
        let count = u16::from_le_bytes([count[0], count[1]]) as usize;
        for r in 0..count {
            let Some(sym) = read_u32_le(data, ptr as usize + r * 10 + 4) else {
                break;
            };
            referenced.insert(sym as usize);
        }
    }
    referenced
}

/// Decode a COFF symbol name: either inline (≤8 bytes, NUL-padded) or a
/// string-table reference stored as 0x00000000 + 4-byte offset.
fn coff_symbol_name(name_bytes: &[u8], strtab: &[u8]) -> String {
    if name_bytes.len() < 8 {
        return String::new();
    }
    if name_bytes[0..4] == [0, 0, 0, 0] {
        let off = u32::from_le_bytes([name_bytes[4], name_bytes[5], name_bytes[6], name_bytes[7]])
            as usize;
        if off >= 4 && off < strtab.len() {
            let s = &strtab[off..];
            let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
            return String::from_utf8_lossy(&s[..end]).into_owned();
        }
        return String::new();
    }
    let end = name_bytes[..8].iter().position(|&b| b == 0).unwrap_or(8);
    String::from_utf8_lossy(&name_bytes[..end]).into_owned()
}

#[allow(dead_code)]
fn read_macho(path: &PathBuf) -> Option<Vec<u8>> {
    let data = normalize_macho_container(std::fs::read(path).ok()?);
    if is_macho64(&data) { Some(data) } else { None }
}

fn collect_elf_symbol_summary(data: &[u8]) -> Option<ObjectSymbolSummary> {
    let (_header, sections, _names) = parse_elf64_slice(data).ok()?;
    let mut summary = ObjectSymbolSummary::default();

    for symtab_sh in sections.iter().filter(|sh| sh.sh_type == SHT_SYMTAB) {
        let strtab_sh = sections.get(symtab_sh.sh_link as usize)?;
        let strtab = get_strtab_from_section(data, strtab_sh);
        let symbols = parse_symtab(data, symtab_sh).ok()?;
        for sym in symbols {
            if sym.bind != STB_GLOBAL && sym.bind != STB_WEAK {
                continue;
            }
            let name = get_strtab_string(strtab, sym.name_offset)?;
            if name.is_empty() {
                continue;
            }
            if sym.st_shndx == SHN_UNDEF {
                if sym.bind == STB_WEAK {
                    continue;
                }
                summary.undefined.insert(name);
            } else {
                summary.defined.insert(name);
            }
        }
    }

    summary
        .undefined
        .retain(|sym| !summary.defined.contains(sym));
    Some(summary)
}

fn collect_macho_symbol_summary(data: &[u8]) -> Option<ObjectSymbolSummary> {
    let obj = parse_macho64_object(data).ok()?;
    let mut summary = ObjectSymbolSummary::default();

    for sym in obj.symbols {
        if sym.name.is_empty() || (sym.n_type & N_EXT) == 0 {
            continue;
        }
        if sym.is_defined {
            summary.defined.insert(sym.name);
        } else {
            if sym.is_weak_ref {
                continue;
            }
            summary.undefined.insert(sym.name);
        }
    }

    summary
        .undefined
        .retain(|sym| !summary.defined.contains(sym));
    Some(summary)
}

fn collect_object_symbol_summary(data: &[u8]) -> Option<ObjectSymbolSummary> {
    if is_elf(data) {
        collect_elf_symbol_summary(data)
    } else if is_macho64(data) {
        collect_macho_symbol_summary(data)
    } else if is_coff(data) {
        collect_coff_symbol_summary(data)
    } else {
        None
    }
}

fn apply_symbol_summary(
    summary: &ObjectSymbolSummary,
    defined_symbols: &mut HashSet<String>,
    unresolved_symbols: &mut HashSet<String>,
    weak_defaults: &mut Vec<(String, String)>,
) {
    for sym in &summary.defined {
        defined_symbols.insert(sym.clone());
        unresolved_symbols.remove(sym);
    }
    for sym in &summary.undefined {
        if !defined_symbols.contains(sym) {
            unresolved_symbols.insert(sym.clone());
        }
    }
    weak_defaults.extend(summary.weak_defaults.iter().cloned());
}

/// Opens a static library, reading only its member headers and symbol index when
/// every member is an object with an index. Other archives are read in full.
fn open_library_entries(path: &Path, position: usize) -> Option<ArchiveEntries> {
    if let Some(entries) = scan_indexed_library(path, position) {
        return Some(entries);
    }
    let data = normalize_macho_container(std::fs::read(path).ok()?);
    load_archive_entries(data, position)
}

fn scan_indexed_library(path: &Path, position: usize) -> Option<ArchiveEntries> {
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    let scan = archive::scan_headers(&mut file, len).ok()?;
    let index = scan.index?;
    let mut offsets = HashMap::default();
    let mut members = Vec::new();
    for member in scan.members {
        let prefix_len = member.len.min(64);
        let mut prefix = vec![0u8; prefix_len];
        file.seek(std::io::SeekFrom::Start(member.start as u64))
            .and_then(|_| file.read_exact(&mut prefix))
            .ok()?;
        if !is_elf(&prefix) {
            if is_macho64(&prefix) || is_coff(&prefix) {
                return None;
            }
            continue;
        }
        offsets.insert(member.offset, members.len());
        members.push(ArchiveEntry {
            position,
            start: member.start,
            len: member.len,
            symbols: None,
            selected: false,
        });
    }
    let index = index
        .into_iter()
        .map(|(name, offsets_in_index)| {
            let indices = offsets_in_index
                .iter()
                .map(|offset| offsets.get(offset).copied())
                .collect::<Option<Vec<_>>>()?;
            Some((name, indices))
        })
        .collect::<Option<HashMap<_, _>>>()?;
    Some(ArchiveEntries {
        buffer: Vec::new(),
        file: Some(file),
        members,
        index: Some(index),
    })
}

fn load_archive_entries(data: Vec<u8>, position: usize) -> Option<ArchiveEntries> {
    let archive = archive::parse_members(&data).ok()?;
    let mut offsets = HashMap::default();
    let mut members = Vec::new();
    for member in archive.members {
        let body = member.data(&data);
        if !(is_elf(body) || is_macho64(body) || is_coff(body)) {
            continue;
        }
        offsets.insert(member.offset, members.len());
        members.push(ArchiveEntry {
            position,
            start: member.start,
            len: member.len,
            symbols: None,
            selected: false,
        });
    }
    let index = archive.index.and_then(|index| {
        if members.iter().any(|entry| {
            !is_elf(
                data.get(entry.start..entry.start + entry.len)
                    .unwrap_or(&[]),
            )
        }) {
            return None;
        }
        index
            .into_iter()
            .map(|(name, offsets_in_index)| {
                let indices = offsets_in_index
                    .iter()
                    .map(|offset| offsets.get(offset).copied())
                    .collect::<Option<Vec<_>>>()?;
                Some((name, indices))
            })
            .collect::<Option<HashMap<_, _>>>()
    });
    if index.is_none() {
        for entry in &mut members {
            let body = data
                .get(entry.start..entry.start + entry.len)
                .unwrap_or(&[]);
            entry.symbols = Some(collect_object_symbol_summary(body).unwrap_or_default());
        }
    }
    log::trace!(
        "archive members={} indexed={}",
        members.len(),
        index.is_some()
    );
    Some(ArchiveEntries {
        buffer: data,
        file: None,
        members,
        index,
    })
}

/// A weak external's default is only needed if nothing else defines the weak
/// name, so defaults are requested after the ordinary selection has settled.
fn select_with_weak_defaults(
    archives: &mut [ArchiveEntries],
    objects: &mut Vec<Vec<u8>>,
    positions: &mut Vec<usize>,
    defined_symbols: &mut HashSet<String>,
    unresolved_symbols: &mut HashSet<String>,
    weak_defaults: &mut Vec<(String, String)>,
) {
    loop {
        select_archive_members(
            archives,
            objects,
            positions,
            defined_symbols,
            unresolved_symbols,
            weak_defaults,
        );
        let mut requested = false;
        for (weak, default) in weak_defaults.iter() {
            if !defined_symbols.contains(weak)
                && !defined_symbols.contains(default)
                && unresolved_symbols.insert(default.clone())
            {
                requested = true;
            }
        }
        if !requested {
            break;
        }
    }
}

fn select_archive_members(
    archives: &mut [ArchiveEntries],
    objects: &mut Vec<Vec<u8>>,
    positions: &mut Vec<usize>,
    defined_symbols: &mut HashSet<String>,
    unresolved_symbols: &mut HashSet<String>,
    weak_defaults: &mut Vec<(String, String)>,
) {
    loop {
        let mut changed = false;
        for archive in archives.iter_mut() {
            let mut cursor = 0;
            loop {
                let next = if let Some(index) = &archive.index {
                    unresolved_symbols
                        .iter()
                        .filter_map(|name| index.get(name))
                        .flatten()
                        .copied()
                        .filter(|&i| i >= cursor && !archive.members[i].selected)
                        .min()
                } else {
                    (cursor..archive.members.len()).find(|&i| {
                        let entry = &archive.members[i];
                        !entry.selected
                            && !entry
                                .symbols
                                .as_ref()
                                .unwrap()
                                .defined
                                .is_disjoint(unresolved_symbols)
                    })
                };
                let Some(i) = next else { break };
                cursor = i + 1;
                let body_owned = archive.body(i);
                if archive.members[i].symbols.is_none() {
                    let summary = collect_object_symbol_summary(&body_owned).unwrap_or_default();
                    archive.members[i].symbols = Some(summary);
                }
                let entry = &mut archive.members[i];
                let symbols = entry.symbols.as_ref().expect("summary just set");
                if symbols.defined.is_disjoint(unresolved_symbols) {
                    continue;
                }
                entry.selected = true;
                log::trace!("archive select member {i} at position {}", entry.position);
                let position = entry.position;
                let symbols = entry.symbols.clone().expect("summary just set");
                apply_symbol_summary(&symbols, defined_symbols, unresolved_symbols, weak_defaults);
                objects.push(normalize_macho_container(body_owned));
                positions.push(position);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectFormat {
    Elf,
    MachO,
    Coff,
}

fn expand_data_to_objects(data: Vec<u8>) -> Option<Vec<Vec<u8>>> {
    if is_elf(&data) || is_macho64(&data) || is_coff(&data) {
        Some(vec![data])
    } else {
        None
    }
}

/// Refuse GCC LTO objects: their real content lives in `.gnu.lto_*` sections that only
/// the LTO plugin can expand, so linking them would silently drop every definition.
pub fn reject_lto_objects(objects: &[Vec<u8>]) -> Result<(), String> {
    for data in objects {
        if !is_elf(data) {
            continue;
        }
        let (header, _, names) = parse_elf64_slice(data)?;
        if header.e_type == 1 && names.iter().any(|name| name.starts_with(".gnu.lto_")) {
            return Err("GCC LTO is not supported".to_string());
        }
    }
    Ok(())
}

pub fn load_objects(
    paths: &[PathBuf],
    libs: &[PathBuf],
    entries: &[String],
) -> Option<(ObjectFormat, Vec<Vec<u8>>, Vec<PathBuf>)> {
    let loaded = load_objects_with_positions(paths, libs, entries, &[], &[])?;
    Some((loaded.format, loaded.objects, loaded.dylibs))
}

pub struct LoadedObjects {
    pub format: ObjectFormat,
    pub objects: Vec<Vec<u8>>,
    pub dylibs: Vec<PathBuf>,
    pub positions: Vec<usize>,
}

pub fn load_objects_with_positions(
    paths: &[PathBuf],
    libs: &[PathBuf],
    entries: &[String],
    path_positions: &[usize],
    library_positions: &[usize],
) -> Option<LoadedObjects> {
    if paths.is_empty() {
        return None;
    }

    let mut all_objects: Vec<Vec<u8>> = Vec::new();
    let mut positions = Vec::new();
    let mut archives: Vec<ArchiveEntries> = Vec::new();
    let mut dylib_paths: Vec<PathBuf> = Vec::new();
    let mut defined_symbols: HashSet<String> = HashSet::default();
    let mut unresolved_symbols: HashSet<String> = entries.iter().cloned().collect();
    let mut weak_defaults: Vec<(String, String)> = Vec::new();

    let loaded = crate::parallel::map(paths.to_vec(), |path| {
        std::fs::read(path).ok().map(normalize_macho_container)
    });
    let loaded: Vec<_> = loaded.into_iter().collect::<Option<_>>()?;
    let need_summaries = !libs.is_empty() || loaded.iter().any(|data| archive::is_archive(data));
    for (i, (path, data)) in paths.iter().zip(loaded).enumerate() {
        let position = path_positions.get(i).copied().unwrap_or(i + 1);
        if is_macho_dylib(&data) {
            dylib_paths.push(path.clone());
        } else if archive::is_archive(&data) {
            archives.push(load_archive_entries(data, position)?);
        } else {
            for obj in expand_data_to_objects(data)? {
                if need_summaries {
                    let symbols = collect_object_symbol_summary(&obj).unwrap_or_default();
                    apply_symbol_summary(
                        &symbols,
                        &mut defined_symbols,
                        &mut unresolved_symbols,
                        &mut weak_defaults,
                    );
                }
                all_objects.push(obj);
                positions.push(position);
            }
        }
    }
    // gcc passes -lgcc twice; the fixed point below makes a second copy redundant.
    let mut seen_libs: HashSet<PathBuf> = HashSet::default();
    for (i, path) in libs.iter().enumerate() {
        if !seen_libs.insert(path.clone()) {
            continue;
        }
        let position = library_positions
            .get(i)
            .copied()
            .unwrap_or(paths.len() + i + 1);
        archives.push(open_library_entries(path, position)?);
    }

    select_with_weak_defaults(
        &mut archives,
        &mut all_objects,
        &mut positions,
        &mut defined_symbols,
        &mut unresolved_symbols,
        &mut weak_defaults,
    );

    if all_objects.is_empty() {
        return None;
    }
    let first = all_objects.first()?;
    let format = if is_elf(first) {
        ObjectFormat::Elf
    } else if is_macho64(first) {
        ObjectFormat::MachO
    } else if is_coff(first) {
        ObjectFormat::Coff
    } else {
        return None;
    };
    for obj in &all_objects {
        let ok = match format {
            ObjectFormat::Elf => is_elf(obj),
            ObjectFormat::MachO => is_macho64(obj),
            ObjectFormat::Coff => is_coff(obj),
        };
        if !ok {
            return None;
        }
    }
    Some(LoadedObjects {
        format,
        objects: all_objects,
        dylibs: dylib_paths,
        positions,
    })
}

pub fn load_macho_objects(
    paths: &[PathBuf],
    libs: &[PathBuf],
    entries: &[String],
) -> Option<(Vec<Vec<u8>>, Vec<PathBuf>)> {
    load_objects(paths, libs, entries).and_then(|(fmt, data, dylib_paths)| {
        if fmt == ObjectFormat::MachO {
            Some((data, dylib_paths))
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_u32_be(buf: &mut [u8], off: usize, val: u32) {
        buf[off..off + 4].copy_from_slice(&val.to_be_bytes());
    }

    fn write_u16_le_at(buf: &mut [u8], off: usize, val: u16) {
        buf[off..off + 2].copy_from_slice(&val.to_le_bytes());
    }

    fn write_u32_le_at(buf: &mut [u8], off: usize, val: u32) {
        buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
    }

    /// Build a minimal COFF object with one external-defined symbol ("_foo") stored
    /// inline in the 8-byte name field, and one external-undefined symbol ("_bar")
    /// stored via the string table.
    fn make_minimal_coff() -> Vec<u8> {
        let sym_table_off: u32 = 20;
        let sym_count: u32 = 2;
        let strtab_content = b"\x0d\x00\x00\x00_bar\0";
        let strtab_size = strtab_content.len();

        let mut data = vec![0u8; 20 + (sym_count as usize) * 18 + strtab_size];

        write_u16_le_at(&mut data, 0, COFF_MACHINE_AMD64);
        write_u16_le_at(&mut data, 2, 0);
        write_u32_le_at(&mut data, 8, sym_table_off);
        write_u32_le_at(&mut data, 12, sym_count);

        let s0 = 20usize;
        data[s0..s0 + 4].copy_from_slice(b"_foo");
        data[s0 + 12..s0 + 14].copy_from_slice(&1i16.to_le_bytes());
        data[s0 + 16] = IMAGE_SYM_CLASS_EXTERNAL;

        let s1 = 20 + 18;
        data[s1..s1 + 4].copy_from_slice(&[0, 0, 0, 0]);
        data[s1 + 4..s1 + 8].copy_from_slice(&4u32.to_le_bytes());
        data[s1 + 12..s1 + 14].copy_from_slice(&0i16.to_le_bytes());
        data[s1 + 16] = IMAGE_SYM_CLASS_EXTERNAL;

        let st_off = 20 + (sym_count as usize) * 18;
        data[st_off..st_off + strtab_size].copy_from_slice(strtab_content);

        data
    }

    #[test]
    fn coff_detection_rejects_elf_and_pe() {
        assert!(!is_coff(&ELF_MAGIC));
        assert!(!is_coff(b"MZ\x90\x00"));
        assert!(!is_coff(b"\xcf\xfa\xed\xfe"));
    }

    #[test]
    fn coff_detection_accepts_known_machine_types() {
        let mut buf = [0u8; 20];
        write_u16_le_at(&mut buf, 0, COFF_MACHINE_AMD64);
        assert!(is_coff(&buf));
        write_u16_le_at(&mut buf, 0, COFF_MACHINE_ARM64);
        assert!(is_coff(&buf));
        write_u16_le_at(&mut buf, 0, COFF_MACHINE_RISCV64);
        assert!(is_coff(&buf));
    }

    #[test]
    fn coff_symbol_extraction_inline_and_strtab() {
        let coff = make_minimal_coff();
        assert!(is_coff(&coff));
        let summary = collect_coff_symbol_summary(&coff).expect("should parse");
        assert!(summary.defined.contains("_foo"), "expected _foo in defined");
        assert!(
            summary.undefined.contains("_bar"),
            "expected _bar in undefined"
        );
        assert!(
            !summary.undefined.contains("_foo"),
            "_foo should not be in undefined"
        );
    }

    #[test]
    fn thin_fat_binary_picks_host_slice() {
        let header_size = 8usize;
        let arch_entry_size = 20usize;
        let table_size = arch_entry_size * 2;
        let first_slice = b"!<arch>\n";
        let second_slice = b"\xcf\xfa\xed\xfe";
        let first_off = header_size + table_size;
        let second_off = first_off + first_slice.len();

        let mut data = vec![0u8; second_off + second_slice.len()];
        write_u32_be(&mut data, 0, FAT_MAGIC);
        write_u32_be(&mut data, 4, 2);

        write_u32_be(&mut data, 8, CPU_TYPE_X86_64);
        write_u32_be(&mut data, 12, 3);
        write_u32_be(&mut data, 16, first_off as u32);
        write_u32_be(&mut data, 20, first_slice.len() as u32);
        write_u32_be(&mut data, 24, 0);

        write_u32_be(&mut data, 28, CPU_TYPE_ARM64);
        write_u32_be(&mut data, 32, 0);
        write_u32_be(&mut data, 36, second_off as u32);
        write_u32_be(&mut data, 40, second_slice.len() as u32);
        write_u32_be(&mut data, 44, 0);

        data[first_off..first_off + first_slice.len()].copy_from_slice(first_slice);
        data[second_off..second_off + second_slice.len()].copy_from_slice(second_slice);

        let thin = thin_fat_macho_binary(&data).expect("fat should thin");
        match host_macho_cputype() {
            Some(CPU_TYPE_X86_64) => assert_eq!(thin, first_slice),
            Some(CPU_TYPE_ARM64) => assert_eq!(thin, second_slice),
            _ => assert!(thin == first_slice || thin == second_slice),
        }
    }
}

#[cfg(test)]
mod archive_selection_tests {
    use super::*;
    use std::process::Command;

    fn assemble(dir: &std::path::Path, name: &str, src: &str) -> Option<PathBuf> {
        let asm = dir.join(format!("{name}.s"));
        let obj = dir.join(format!("{name}.o"));
        std::fs::write(&asm, src).ok()?;
        let status = Command::new("as")
            .arg("-o")
            .arg(&obj)
            .arg(&asm)
            .status()
            .ok()?;
        status.success().then_some(obj)
    }

    #[test]
    fn indexed_selection_matches_eager_order_and_leaves_unused_members_unparsed() {
        let dir = std::env::temp_dir().join(format!("weld-index-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sources = [
            ("early", ".globl choice\nchoice:\n ret\n"),
            ("unused", ".globl unused\nunused:\n ret\n"),
            ("dep", ".globl dep\ndep:\n call choice\n call leaf\n ret\n"),
            ("late", ".globl choice\nchoice:\n ret\n"),
            ("leaf", ".globl leaf\nleaf:\n ret\n"),
        ];
        let Some(paths) = sources
            .iter()
            .map(|(name, src)| assemble(&dir, name, src))
            .collect::<Option<Vec<_>>>()
        else {
            return;
        };
        let lib = dir.join("libindex.a");
        let _ = std::fs::remove_file(&lib);
        assert!(
            Command::new("ar")
                .arg("rcs")
                .arg(&lib)
                .args(&paths)
                .status()
                .unwrap()
                .success()
        );
        let data = std::fs::read(&lib).unwrap();
        let mut indexed = load_archive_entries(data.clone(), 7).unwrap();
        assert!(indexed.index.is_some());
        assert!(indexed.members.iter().all(|entry| entry.symbols.is_none()));
        let mut eager = load_archive_entries(data, 7).unwrap();
        eager.index = None;
        for i in 0..eager.members.len() {
            let body = {
                let entry = &eager.members[i];
                eager.buffer[entry.start..entry.start + entry.len].to_vec()
            };
            eager.members[i].symbols = Some(collect_object_symbol_summary(&body).unwrap());
        }
        let select = |archive: &mut ArchiveEntries| {
            let mut objects = Vec::new();
            let mut positions = Vec::new();
            let mut defined = HashSet::default();
            let mut unresolved = HashSet::from_iter(["dep".to_string()]);
            select_archive_members(
                std::slice::from_mut(archive),
                &mut objects,
                &mut positions,
                &mut defined,
                &mut unresolved,
                &mut Vec::new(),
            );
            assert!(unresolved.is_empty());
            assert_eq!(positions, [7, 7, 7]);
            objects
        };
        let objects = select(&mut indexed);
        assert_eq!(objects, select(&mut eager));
        assert_eq!(
            objects,
            [2, 3, 4].map(|i| std::fs::read(&paths[i]).unwrap())
        );
        assert!(
            indexed.members[..2]
                .iter()
                .all(|entry| entry.symbols.is_none())
        );

        let unindexed = dir.join("libunindexed.a");
        let _ = std::fs::remove_file(&unindexed);
        assert!(
            Command::new("ar")
                .arg("rcS")
                .arg(&unindexed)
                .args(&paths)
                .status()
                .unwrap()
                .success()
        );
        let mut fallback = load_archive_entries(std::fs::read(unindexed).unwrap(), 7).unwrap();
        assert!(fallback.index.is_none());
        assert!(fallback.members.iter().all(|entry| entry.symbols.is_some()));
        assert_eq!(objects, select(&mut fallback));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn pulls_only_members_reachable_from_undefined_symbols() {
        let dir = std::env::temp_dir().join(format!("weld-archive-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (Some(main), Some(a), Some(b), Some(c)) = (
            assemble(&dir, "main", ".globl _start\n_start:\n call dep_fn\n ret\n"),
            assemble(&dir, "used", ".globl used_fn\nused_fn:\n ret\n"),
            assemble(&dir, "unused", ".globl unused_fn\nunused_fn:\n ret\n"),
            assemble(&dir, "dep", ".globl dep_fn\ndep_fn:\n call used_fn\n ret\n"),
        ) else {
            return;
        };
        let lib = dir.join("libpick.a");
        let _ = std::fs::remove_file(&lib);
        let status = Command::new("ar")
            .arg("rcs")
            .arg(&lib)
            .args([&a, &b, &c])
            .status();
        let Ok(status) = status else { return };
        assert!(status.success());

        let entries = vec!["_start".to_string()];
        let (format, objects, _) =
            load_objects(&[main, lib], &[], &entries).expect("link inputs load");
        assert_eq!(format, ObjectFormat::Elf);
        assert_eq!(objects.len(), 3, "main plus the two needed members");
        let defines = |name: &str| {
            objects.iter().any(|obj| {
                collect_object_symbol_summary(obj).is_some_and(|s| s.defined.contains(name))
            })
        };
        assert!(defines("used_fn"));
        assert!(defines("dep_fn"));
        assert!(!defines("unused_fn"));
    }
}

#[cfg(test)]
mod coff_weak_selection_tests {
    use super::*;

    /// Symbol tuples are (name, section, class, tag); `tag` is only used for weak externals.
    /// `relocs` lists the symbol indices referenced by one relocation each.
    fn coff_object(symbols: &[(&str, i16, u8, u32)], relocs: &[u32]) -> Vec<u8> {
        let mut records = Vec::new();
        let mut count = 0u32;
        for &(name, section, class, tag) in symbols {
            let mut name_field = [0u8; 8];
            name_field[..name.len()].copy_from_slice(name.as_bytes());
            records.extend_from_slice(&name_field);
            records.extend_from_slice(&0u32.to_le_bytes());
            records.extend_from_slice(&section.to_le_bytes());
            records.extend_from_slice(&0u16.to_le_bytes());
            records.push(class);
            if class == IMAGE_SYM_CLASS_WEAK_EXTERNAL {
                records.push(1);
                records.extend_from_slice(&tag.to_le_bytes());
                records.extend_from_slice(&[0u8; 14]);
                count += 2;
            } else {
                records.push(0);
                count += 1;
            }
        }
        let section_count = u16::from(!relocs.is_empty());
        let reloc_off = 20 + 40 * usize::from(section_count);
        let sym_off = reloc_off + 10 * relocs.len();
        let mut data = vec![0u8; 20];
        data[0..2].copy_from_slice(&COFF_MACHINE_AMD64.to_le_bytes());
        data[2..4].copy_from_slice(&section_count.to_le_bytes());
        data[8..12].copy_from_slice(&(sym_off as u32).to_le_bytes());
        data[12..16].copy_from_slice(&count.to_le_bytes());
        if !relocs.is_empty() {
            let mut sh = [0u8; 40];
            sh[..6].copy_from_slice(b".text\0");
            sh[24..28].copy_from_slice(&(reloc_off as u32).to_le_bytes());
            sh[32..34].copy_from_slice(&(relocs.len() as u16).to_le_bytes());
            data.extend_from_slice(&sh);
        }
        for &sym in relocs {
            data.extend_from_slice(&0u32.to_le_bytes());
            data.extend_from_slice(&sym.to_le_bytes());
            data.extend_from_slice(&IMAGE_REL_AMD64_ADDR64_TEST.to_le_bytes());
        }
        data.extend_from_slice(&records);
        data.extend_from_slice(&4u32.to_le_bytes());
        data
    }

    const IMAGE_REL_AMD64_ADDR64_TEST: u16 = 1;

    fn archive(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut out = b"!<arch>\n".to_vec();
        for (name, body) in members {
            let header = format!(
                "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                format!("{name}/"),
                0,
                0,
                0,
                644,
                body.len()
            );
            out.extend_from_slice(header.as_bytes());
            out.extend_from_slice(body);
            if body.len() % 2 == 1 {
                out.push(b'\n');
            }
        }
        out
    }

    fn selected_members(input: &[u8], archive_data: Vec<u8>) -> Vec<usize> {
        let mut archives = vec![load_archive_entries(archive_data, 1).unwrap()];
        let mut objects = vec![input.to_vec()];
        let mut positions = vec![0];
        let mut defined = HashSet::default();
        let mut unresolved = HashSet::default();
        let mut weak_defaults = Vec::new();
        let summary = collect_object_symbol_summary(input).unwrap();
        apply_symbol_summary(&summary, &mut defined, &mut unresolved, &mut weak_defaults);
        select_with_weak_defaults(
            &mut archives,
            &mut objects,
            &mut positions,
            &mut defined,
            &mut unresolved,
            &mut weak_defaults,
        );
        archives[0]
            .members
            .iter()
            .enumerate()
            .filter(|(_, m)| m.selected)
            .map(|(i, _)| i)
            .collect()
    }

    fn caller(relocs: &[u32]) -> Vec<u8> {
        coff_object(
            &[
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                ("dflt", IMAGE_SYM_UNDEFINED, IMAGE_SYM_CLASS_EXTERNAL, 0),
                ("foo", IMAGE_SYM_UNDEFINED, IMAGE_SYM_CLASS_WEAK_EXTERNAL, 1),
            ],
            relocs,
        )
    }

    fn lib_with(names: &[&str]) -> Vec<u8> {
        let mut members = vec![(
            "other.o",
            coff_object(&[("other", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)], &[]),
        )];
        for name in names {
            members.push((
                name,
                coff_object(&[(name, 1, IMAGE_SYM_CLASS_EXTERNAL, 0)], &[]),
            ));
        }
        let members: Vec<(&str, Vec<u8>)> = members.into_iter().map(|(n, b)| (n, b)).collect();
        archive(&members)
    }

    #[test]
    fn weak_external_summary_names_default() {
        let summary = collect_coff_symbol_summary(&caller(&[2])).unwrap();
        assert!(summary.undefined.contains("foo"));
        assert!(!summary.undefined.contains("dflt"));
        assert_eq!(
            summary.weak_defaults,
            [("foo".to_string(), "dflt".to_string())]
        );
    }

    #[test]
    fn strong_definition_of_weak_name_is_selected_over_default() {
        let lib = archive(&[
            (
                "other.o",
                coff_object(&[("other", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)], &[]),
            ),
            (
                "dflt.o",
                coff_object(&[("dflt", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)], &[]),
            ),
            (
                "foo.o",
                coff_object(&[("foo", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)], &[]),
            ),
        ]);
        assert_eq!(selected_members(&caller(&[2]), lib), [2]);
    }

    #[test]
    fn default_is_selected_when_nothing_defines_weak_name() {
        assert_eq!(selected_members(&caller(&[2]), lib_with(&["dflt"])), [1]);
    }

    #[test]
    fn direct_reference_to_default_selects_it() {
        assert_eq!(selected_members(&caller(&[1, 2]), lib_with(&["dflt"])), [1]);
    }
}
