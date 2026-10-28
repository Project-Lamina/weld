use super::*;
use crate::elf::RelaEntry;

type Node = (usize, usize);

struct Frame {
    start: usize,
    end: usize,
    cie: Option<usize>,
}

fn frames(data: &[u8]) -> Result<Vec<Frame>, String> {
    let mut result = Vec::new();
    let mut start = 0;
    while start + 4 <= data.len() {
        let size = u32::from_le_bytes(data[start..start + 4].try_into().unwrap()) as usize;
        if size == 0 {
            start += 4;
            continue;
        }
        if size == u32::MAX as usize || size < 4 || start + 4 + size > data.len() {
            return Err("unsupported .eh_frame record during section GC".into());
        }
        let id = u32::from_le_bytes(data[start + 4..start + 8].try_into().unwrap()) as usize;
        let cie = if id == 0 {
            None
        } else {
            Some((start + 4).checked_sub(id).ok_or("invalid CIE offset")?)
        };
        result.push(Frame {
            start,
            end: start + 4 + size,
            cie,
        });
        start += 4 + size;
    }
    if start != data.len() {
        return Err("truncated .eh_frame record during section GC".into());
    }
    Ok(result)
}

fn target(
    obj: usize,
    sym: &Symbol,
    strings: &[u8],
    globals: &HashMap<String, Node>,
) -> Option<Node> {
    if sym.st_shndx == SHN_UNDEF {
        globals
            .get(&get_strtab_string(strings, sym.name_offset)?)
            .copied()
    } else if sym.st_shndx < 0xff00 {
        Some((obj, sym.st_shndx as usize))
    } else {
        None
    }
}

fn frame_relocations<'a>(
    frame: &Frame,
    relas: &'a [RelaEntry],
) -> impl Iterator<Item = &'a RelaEntry> {
    relas
        .iter()
        .filter(move |r| (frame.start..frame.end).contains(&(r.r_offset as usize)))
}

pub(super) fn collect(parsed: &mut [ParsedObject], roots: &[String]) -> Result<(), String> {
    let mut globals = HashMap::default();
    let mut tables = Vec::new();
    for (i, obj) in parsed.iter().enumerate() {
        let table = parse_symtab_view(&obj.data, &obj.sections)?.unwrap_or_default();
        for sym in &table.0 {
            if sym.bind != STB_LOCAL
                && sym.st_shndx != SHN_UNDEF
                && sym.st_shndx < 0xff00
                && let Some(name) = get_strtab_string(table.1, sym.name_offset)
            {
                let node = (i, sym.st_shndx as usize);
                if sym.bind == STB_WEAK {
                    globals.entry(name).or_insert(node);
                } else {
                    globals.insert(name, node);
                }
            }
        }
        tables.push(table);
    }
    let mut edges: HashMap<Node, Vec<Node>> = HashMap::default();
    let mut live = HashSet::default();
    for name in roots {
        if let Some(&node) = globals.get(name) {
            live.insert(node);
        }
    }
    for (i, obj) in parsed.iter().enumerate() {
        let (symbols, strings) = &tables[i];
        for (j, section) in obj.sections.iter().enumerate() {
            if section.sh_flags & 0x200000 != 0
                || matches!(section.sh_type, 14..=16)
                || matches!(
                    obj.names[j].as_str(),
                    ".init" | ".fini" | ".ctors" | ".dtors"
                )
            {
                live.insert((i, j));
            }
        }
        for section in obj.sections.iter().filter(|s| s.sh_type == 4) {
            let source = section.sh_info as usize;
            let relas = parse_rela_section(&obj.data, section)?;
            let targets = |r: &RelaEntry| {
                symbols
                    .get(r.r_sym as usize)
                    .and_then(|s| target(i, s, strings, &globals))
            };
            if obj.names.get(source).map(String::as_str) == Some(".eh_frame") {
                let frame_section = &obj.sections[source];
                let data = get_strtab_from_section(&obj.data, frame_section);
                for frame in frames(data)? {
                    let refs: Vec<_> = frame_relocations(&frame, &relas)
                        .filter_map(targets)
                        .collect();
                    if frame.cie.is_none() {
                        live.extend(refs);
                    } else if let Some(&function) = refs.first() {
                        edges.entry(function).or_default().extend(refs);
                        edges.entry(function).or_default().push((i, source));
                    }
                }
            } else {
                edges
                    .entry((i, source))
                    .or_default()
                    .extend(relas.iter().filter_map(targets));
            }
        }
    }
    let mut pending: Vec<_> = live.iter().copied().collect();
    while let Some(node) = pending.pop() {
        if let Some(targets) = edges.get(&node) {
            for &target in targets {
                if live.insert(target) {
                    pending.push(target);
                }
            }
        }
    }
    let mut frame_updates = Vec::new();
    for (i, obj) in parsed.iter().enumerate() {
        let (symbols, strings) = &tables[i];
        for (rindex, section) in obj
            .sections
            .iter()
            .enumerate()
            .filter(|(_, s)| s.sh_type == 4)
        {
            let source = section.sh_info as usize;
            if obj.names.get(source).map(String::as_str) != Some(".eh_frame")
                || !live.contains(&(i, source))
            {
                continue;
            }
            let data = get_strtab_from_section(&obj.data, &obj.sections[source]);
            let relas = parse_rela_section(&obj.data, section)?;
            let mut bytes = Vec::new();
            let mut relocations = Vec::new();
            let mut offsets = HashMap::default();
            for frame in frames(data)? {
                let keep = frame.cie.is_none()
                    || frame_relocations(&frame, &relas)
                        .next()
                        .and_then(|r| symbols.get(r.r_sym as usize))
                        .and_then(|s| target(i, s, strings, &globals))
                        .is_some_and(|n| live.contains(&n));
                if !keep {
                    continue;
                }
                let offset = bytes.len();
                offsets.insert(frame.start, offset);
                bytes.extend_from_slice(&data[frame.start..frame.end]);
                if let Some(cie) = frame.cie {
                    let cie_offset = offsets.get(&cie).ok_or("missing CIE during section GC")?;
                    bytes[offset + 4..offset + 8]
                        .copy_from_slice(&((offset + 4 - cie_offset) as u32).to_le_bytes());
                }
                for rel in frame_relocations(&frame, &relas) {
                    relocations.extend_from_slice(
                        &((offset + rel.r_offset as usize - frame.start) as u64).to_le_bytes(),
                    );
                    relocations.extend_from_slice(
                        &(((rel.r_sym as u64) << 32) | rel.r_type as u64).to_le_bytes(),
                    );
                    relocations.extend_from_slice(&rel.r_addend.to_le_bytes());
                }
            }
            frame_updates.push((i, source, bytes));
            frame_updates.push((i, rindex, relocations));
        }
    }
    drop(tables);
    for (i, index, bytes) in frame_updates {
        let obj = &mut parsed[i];
        obj.sections[index].sh_offset = obj.data.len() as u64;
        obj.sections[index].sh_size = bytes.len() as u64;
        obj.data.extend(bytes);
    }
    for (i, obj) in parsed.iter_mut().enumerate() {
        for (j, section) in obj.sections.iter_mut().enumerate() {
            if is_allocatable(section.sh_flags) && !live.contains(&(i, j)) {
                section.sh_flags &= !SHF_ALLOC;
            }
        }
        for j in 0..obj.sections.len() {
            if obj.sections[j].sh_type == 4
                && !live.contains(&(i, obj.sections[j].sh_info as usize))
            {
                obj.sections[j].sh_size = 0;
            }
        }
    }
    Ok(())
}
