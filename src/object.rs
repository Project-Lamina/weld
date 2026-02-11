use std::path::PathBuf;
use std::thread;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

fn is_elf(data: &[u8]) -> bool {
    data.len() >= ELF_MAGIC.len() && data[..ELF_MAGIC.len()] == ELF_MAGIC
}

fn read_elf(path: &PathBuf) -> Option<Vec<u8>> {
    let data = std::fs::read(path).ok()?;
    if is_elf(&data) { Some(data) } else { None }
}

fn read_macho(path: &PathBuf) -> Option<Vec<u8>> {
    let data = std::fs::read(path).ok()?;
    if crate::macho::is_macho64(&data) {
        Some(data)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectFormat {
    Elf,
    MachO,
}

pub fn load_objects(paths: &[PathBuf]) -> Option<(ObjectFormat, Vec<Vec<u8>>)> {
    if paths.is_empty() {
        return None;
    }
    let first = paths.first()?;
    let first_data = std::fs::read(first).ok()?;
    let format = if is_elf(&first_data) {
        ObjectFormat::Elf
    } else if crate::macho::is_macho64(&first_data) {
        ObjectFormat::MachO
    } else {
        return None;
    };

    if paths.len() == 1 {
        return Some((format, vec![first_data]));
    }

    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        let data = match format {
            ObjectFormat::Elf => read_elf(path)?,
            ObjectFormat::MachO => read_macho(path)?,
        };
        out.push(data);
    }
    Some((format, out))
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

pub fn load_macho_objects(paths: &[PathBuf]) -> Option<Vec<Vec<u8>>> {
    load_objects(paths).and_then(|(fmt, data)| {
        if fmt == ObjectFormat::MachO {
            Some(data)
        } else {
            None
        }
    })
}
