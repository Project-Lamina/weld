use std::collections::HashSet;
use std::path::PathBuf;
use std::thread;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const AR_MAGIC: [u8; 8] = [0x21, 0x3c, 0x61, 0x72, 0x63, 0x68, 0x3e, 0x0a];
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

// COFF symbol table constants
const IMAGE_SYM_UNDEFINED: i16 = 0;
const IMAGE_SYM_CLASS_EXTERNAL: u8 = 2;

#[derive(Default, Clone)]
struct ObjectSymbolSummary {
    defined: HashSet<String>,
    undefined: HashSet<String>,
}

#[derive(Clone)]
struct ArchiveMember {
    data: Vec<u8>,
    symbols: ObjectSymbolSummary,
    selected: bool,
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

/// Returns true for bare COFF object files (.obj). PE executables are excluded
/// because they begin with the MZ DOS stub (0x4D5A), not a COFF machine type.
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

    let mut summary = ObjectSymbolSummary::default();
    let mut i = 0usize;
    while i < sym_count {
        let rec_off = sym_table_off + i * 18;
        let section_number = i16::from_le_bytes([data[rec_off + 12], data[rec_off + 13]]);
        let storage_class = data[rec_off + 17];
        let num_aux = data[rec_off + 16] as usize;

        if storage_class == IMAGE_SYM_CLASS_EXTERNAL {
            let name = coff_symbol_name(&data[rec_off..rec_off + 8], strtab);
            if !name.is_empty() {
                if section_number == IMAGE_SYM_UNDEFINED {
                    summary.undefined.insert(name);
                } else {
                    summary.defined.insert(name);
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

fn is_ar(data: &[u8]) -> bool {
    data.len() >= AR_MAGIC.len() && data[..AR_MAGIC.len()] == AR_MAGIC
}

fn read_elf(path: &PathBuf) -> Option<Vec<u8>> {
    let data = normalize_macho_container(std::fs::read(path).ok()?);
    if is_elf(&data) { Some(data) } else { None }
}

#[allow(dead_code)]
fn read_macho(path: &PathBuf) -> Option<Vec<u8>> {
    let data = normalize_macho_container(std::fs::read(path).ok()?);
    if crate::macho::is_macho64(&data) {
        Some(data)
    } else {
        None
    }
}

fn collect_elf_symbol_summary(data: &[u8]) -> Option<ObjectSymbolSummary> {
    let (_header, sections, _names) = crate::elf::parse_elf64_slice(data).ok()?;
    let mut summary = ObjectSymbolSummary::default();

    for symtab_sh in sections.iter().filter(|sh| sh.sh_type == SHT_SYMTAB) {
        let strtab_sh = sections.get(symtab_sh.sh_link as usize)?;
        let strtab = crate::elf::get_strtab_from_section(data, strtab_sh);
        let symbols = crate::elf::parse_symtab(data, symtab_sh).ok()?;
        for sym in symbols {
            if sym.bind != STB_GLOBAL && sym.bind != STB_WEAK {
                continue;
            }
            let name = crate::elf::get_strtab_string(strtab, sym.name_offset)?;
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
    let obj = crate::macho::parse_macho64_object(data).ok()?;
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
    } else if crate::macho::is_macho64(data) {
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
}

fn extract_ar_members(data: &[u8]) -> Vec<ArchiveMember> {
    let mut out = Vec::new();
    if !is_ar(data) || data.len() < 8 + 60 {
        return out;
    }
    let mut off = 8usize;
    while off + 60 <= data.len() {
        let name = std::str::from_utf8(&data[off..off + 16])
            .unwrap_or("")
            .trim_end_matches(' ')
            .trim_end_matches('/');
        let size_str = std::str::from_utf8(&data[off + 48..off + 58])
            .unwrap_or("0")
            .trim_end_matches(' ');
        let member_size: usize = size_str.parse().unwrap_or(0);
        off += 60;
        if member_size > 0 && off + member_size <= data.len() {
            let member = &data[off..off + member_size];
            let payload = if let Some(suffix) = name.strip_prefix("#1/") {
                let n: usize = suffix.parse().unwrap_or(0);
                if n < member.len() {
                    &member[n..]
                } else {
                    member
                }
            } else {
                member
            };

            let normalized = normalize_macho_container(payload.to_vec());
            if !name.is_empty()
                && name != "/"
                && name != "//"
                && (is_elf(&normalized)
                    || crate::macho::is_macho64(&normalized)
                    || is_coff(&normalized))
            {
                let symbols = collect_object_symbol_summary(&normalized).unwrap_or_default();
                out.push(ArchiveMember {
                    data: normalized,
                    symbols,
                    selected: false,
                });
            }
        }
        off += member_size;
        if !off.is_multiple_of(2) {
            off += 1;
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectFormat {
    Elf,
    MachO,
    Coff,
}

fn expand_data_to_objects(data: Vec<u8>) -> Option<Vec<Vec<u8>>> {
    if is_elf(&data) || crate::macho::is_macho64(&data) || is_coff(&data) {
        Some(vec![data])
    } else {
        None
    }
}

pub fn load_objects(paths: &[PathBuf]) -> Option<(ObjectFormat, Vec<Vec<u8>>, Vec<PathBuf>)> {
    if paths.is_empty() {
        return None;
    }

    let mut all_objects: Vec<Vec<u8>> = Vec::new();
    let mut dylib_paths: Vec<PathBuf> = Vec::new();
    let mut defined_symbols: HashSet<String> = HashSet::new();
    let mut unresolved_symbols: HashSet<String> = HashSet::new();
    let trace_archive = std::env::var("WELD_TRACE_ARCHIVE").ok().as_deref() == Some("1");

    for path in paths {
        let data = normalize_macho_container(std::fs::read(path).ok()?);
        if crate::macho::is_macho_dylib(&data) {
            dylib_paths.push(path.clone());
            continue;
        }

        if is_ar(&data) {
            let mut members = extract_ar_members(&data);
            let mut selected_any = false;
            if trace_archive {
                eprintln!(
                    "[weld] archive {} members={}",
                    path.display(),
                    members.len()
                );
            }

            loop {
                let mut changed = false;
                for member in members.iter_mut() {
                    if member.selected {
                        continue;
                    }
                    if member.symbols.defined.is_disjoint(&unresolved_symbols) {
                        continue;
                    }
                    member.selected = true;
                    selected_any = true;
                    if trace_archive {
                        let mut hits: Vec<&str> = member
                            .symbols
                            .defined
                            .intersection(&unresolved_symbols)
                            .map(|s| s.as_str())
                            .collect();
                        hits.sort_unstable();
                        let sample = hits.into_iter().take(4).collect::<Vec<_>>().join(",");
                        eprintln!(
                            "[weld]   select member defs={} undefs={} hits=[{}]",
                            member.symbols.defined.len(),
                            member.symbols.undefined.len(),
                            sample
                        );
                    }
                    apply_symbol_summary(
                        &member.symbols,
                        &mut defined_symbols,
                        &mut unresolved_symbols,
                    );
                    all_objects.push(member.data.clone());
                    changed = true;
                }
                if !changed {
                    break;
                }
            }

            if !selected_any
                && all_objects.is_empty()
                && let Some(first_member) = members.first()
            {
                apply_symbol_summary(
                    &first_member.symbols,
                    &mut defined_symbols,
                    &mut unresolved_symbols,
                );
                all_objects.push(first_member.data.clone());
            }
            continue;
        }

        let objs = expand_data_to_objects(data)?;
        for obj in objs {
            let symbols = collect_object_symbol_summary(&obj).unwrap_or_default();
            apply_symbol_summary(&symbols, &mut defined_symbols, &mut unresolved_symbols);
            all_objects.push(obj);
        }
    }

    if all_objects.is_empty() {
        return None;
    }
    let first = all_objects.first()?;
    let format = if is_elf(first) {
        ObjectFormat::Elf
    } else if crate::macho::is_macho64(first) {
        ObjectFormat::MachO
    } else if is_coff(first) {
        ObjectFormat::Coff
    } else {
        return None;
    };
    for obj in &all_objects {
        let ok = match format {
            ObjectFormat::Elf => is_elf(obj),
            ObjectFormat::MachO => crate::macho::is_macho64(obj),
            ObjectFormat::Coff => is_coff(obj),
        };
        if !ok {
            return None;
        }
    }
    Some((format, all_objects, dylib_paths))
}

pub fn load_elf_objects(paths: &[PathBuf]) -> Option<Vec<Vec<u8>>> {
    if paths.is_empty() {
        return None;
    }

    if paths.len() == 1 {
        let data = read_elf(paths.first()?)?;
        return Some(vec![data]);
    }

    let handles: Vec<_> = paths
        .iter()
        .map(|path| {
            let path = path.clone();
            thread::spawn(move || read_elf(&path))
        })
        .collect();

    let mut out = Vec::with_capacity(handles.len());
    for handle in handles {
        let data = handle.join().ok()??;
        out.push(data);
    }

    Some(out)
}

pub fn load_macho_objects(paths: &[PathBuf]) -> Option<(Vec<Vec<u8>>, Vec<PathBuf>)> {
    load_objects(paths).and_then(|(fmt, data, dylib_paths)| {
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
        // Two 18-byte symbol records + a string table with "_bar\0".
        // Header: 20 bytes. Symbol table starts right after header (no sections).
        let sym_table_off: u32 = 20;
        let sym_count: u32 = 2;
        let strtab_content = b"\x0d\x00\x00\x00_bar\0"; // 4-byte size + "_bar\0"
        let strtab_size = strtab_content.len();

        let mut data = vec![0u8; 20 + (sym_count as usize) * 18 + strtab_size];

        // COFF header
        write_u16_le_at(&mut data, 0, COFF_MACHINE_AMD64);
        write_u16_le_at(&mut data, 2, 0); // section count
        write_u32_le_at(&mut data, 8, sym_table_off);
        write_u32_le_at(&mut data, 12, sym_count);

        // Symbol 0: "_foo" inline, section 1 (defined), class = external
        let s0 = 20usize;
        data[s0..s0 + 4].copy_from_slice(b"_foo");
        data[s0 + 12..s0 + 14].copy_from_slice(&1i16.to_le_bytes()); // section number
        data[s0 + 17] = IMAGE_SYM_CLASS_EXTERNAL;

        // Symbol 1: "_bar" via strtab at offset 4, section 0 (undefined), class = external
        let s1 = 20 + 18;
        data[s1..s1 + 4].copy_from_slice(&[0, 0, 0, 0]); // zeroes -> use offset
        data[s1 + 4..s1 + 8].copy_from_slice(&4u32.to_le_bytes()); // strtab offset
        data[s1 + 12..s1 + 14].copy_from_slice(&0i16.to_le_bytes()); // undefined
        data[s1 + 17] = IMAGE_SYM_CLASS_EXTERNAL;

        // String table
        let st_off = 20 + (sym_count as usize) * 18;
        data[st_off..st_off + strtab_size].copy_from_slice(strtab_content);

        data
    }

    #[test]
    fn coff_detection_rejects_elf_and_pe() {
        assert!(!is_coff(&ELF_MAGIC));
        assert!(!is_coff(b"MZ\x90\x00"));
        assert!(!is_coff(b"\xcf\xfa\xed\xfe")); // Mach-O LE
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

        // Entry 0: x86_64
        write_u32_be(&mut data, 8, CPU_TYPE_X86_64);
        write_u32_be(&mut data, 12, 3);
        write_u32_be(&mut data, 16, first_off as u32);
        write_u32_be(&mut data, 20, first_slice.len() as u32);
        write_u32_be(&mut data, 24, 0);

        // Entry 1: arm64
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
