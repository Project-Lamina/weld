use std::path::PathBuf;
use std::thread;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const AR_MAGIC: [u8; 8] = [0x21, 0x3c, 0x61, 0x72, 0x63, 0x68, 0x3e, 0x0a];

fn is_elf(data: &[u8]) -> bool {
    data.len() >= ELF_MAGIC.len() && data[..ELF_MAGIC.len()] == ELF_MAGIC
}

fn is_ar(data: &[u8]) -> bool {
    data.len() >= AR_MAGIC.len() && data[..AR_MAGIC.len()] == AR_MAGIC
}

fn read_elf(path: &PathBuf) -> Option<Vec<u8>> {
    let data = std::fs::read(path).ok()?;
    if is_elf(&data) {
        Some(data)
    } else {
        None
    }
}

fn read_macho(path: &PathBuf) -> Option<Vec<u8>> {
    let data = std::fs::read(path).ok()?;
    if crate::macho::is_macho64(&data) {
        Some(data)
    } else {
        None
    }
}

fn extract_ar_objects(data: &[u8]) -> Vec<Vec<u8>> {
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
            if !name.is_empty() && name != "/" && name != "//"
                && (is_elf(payload) || crate::macho::is_macho64(payload))
            {
                out.push(payload.to_vec());
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

fn expand_path_to_objects(path: &PathBuf) -> Option<Vec<Vec<u8>>> {
    let data = std::fs::read(path).ok()?;
    if is_ar(&data) {
        let objs = extract_ar_objects(&data);
        if objs.is_empty() {
            return None;
        }
        Some(objs)
    } else if is_elf(&data) {
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
    for path in paths {
        let data = std::fs::read(path).ok()?;
        if crate::macho::is_macho_dylib(&data) {
            dylib_paths.push(path.clone());
            continue;
        }
        let objs = expand_path_to_objects(path)?;
        all_objects.extend(objs);
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
