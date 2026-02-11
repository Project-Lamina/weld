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
