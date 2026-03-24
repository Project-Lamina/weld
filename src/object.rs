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
            let payload = if name.starts_with("#1/") {
                let n: usize = name[3..].parse().unwrap_or(0);
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
                && (is_elf(&normalized) || crate::macho::is_macho64(&normalized))
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
        if off % 2 != 0 {
            off += 1;
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectFormat {
    Elf,
    MachO,
}

fn expand_data_to_objects(data: Vec<u8>) -> Option<Vec<Vec<u8>>> {
    if is_elf(&data) {
        Some(vec![data])
    } else if crate::macho::is_macho64(&data) {
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

            if !selected_any && all_objects.is_empty() {
                if let Some(first_member) = members.first() {
                    apply_symbol_summary(
                        &first_member.symbols,
                        &mut defined_symbols,
                        &mut unresolved_symbols,
                    );
                    all_objects.push(first_member.data.clone());
                }
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
    } else {
        return None;
    };
    for obj in &all_objects {
        let ok = match format {
            ObjectFormat::Elf => is_elf(obj),
            ObjectFormat::MachO => crate::macho::is_macho64(obj),
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
        .cloned()
        .map(|path| thread::spawn(move || read_elf(&path)))
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
