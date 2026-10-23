use super::dynamic::elf_hash;
use super::*;

struct Export {
    symbol: Symbol,
    library: String,
    version: Option<String>,
}

pub(super) struct Runtime {
    copies: Vec<(u64, u32)>,
    got: Vec<(u64, u32)>,
    relocations: Vec<PendingRelocation>,
}

struct PendingRelocation {
    object: usize,
    section: usize,
    input_name: String,
    offset: u64,
    symbol: u32,
    kind: u32,
    addend: i64,
}

fn symbol_name(strings: &[u8], offset: u32) -> Option<&str> {
    let bytes = strings.get(offset as usize..)?;
    std::str::from_utf8(bytes.get(..bytes.iter().position(|&b| b == 0)?)?).ok()
}

fn append(layout: &mut MergedLayout, name: &str, data: Vec<u8>, align: u64, flags: u64) {
    let end = layout
        .sections
        .iter()
        .map(|s| s.vaddr + s.data.len() as u64)
        .max()
        .unwrap_or(0x400000);
    layout
        .section_by_name
        .insert(name.into(), layout.sections.len());
    layout.sections.push(MergedSection {
        name: name.into(),
        data,
        vaddr: align_up(end, align),
        align,
        flags,
        sh_type: 1,
        entsize: 0,
    });
}

fn word(bytes: &[u8], offset: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or("truncated ELF runtime record")?
            .try_into()
            .unwrap(),
    ))
}

fn half(bytes: &[u8], offset: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or("truncated ELF version record")?
            .try_into()
            .unwrap(),
    ))
}

fn exports(
    libs: &[String],
    resolver: &LibraryResolver,
    needed: &[String],
    imports: &HashMap<String, u32>,
) -> Result<HashMap<String, Export>, String> {
    let mut requested_names: HashMap<&str, Vec<&String>> = HashMap::default();
    for name in imports.keys() {
        requested_names
            .entry(name.split('@').next().unwrap())
            .or_default()
            .push(name);
    }
    let mut result = HashMap::default();
    let mut seen = HashSet::default();
    for lib in libs {
        let Some(lib) = resolver.resolve(lib) else {
            continue;
        };
        if !needed.contains(&lib.soname) || !seen.insert(lib.soname.clone()) {
            continue;
        }
        let data = crate::elf::read_dynamic_symbol_bytes(&lib.path)?;
        let (_, sections, _) = parse_elf64_slice(&data)?;
        let mut versions = HashMap::default();
        for section in sections.iter().filter(|s| s.sh_type == 0x6ffffffd) {
            let bytes = get_strtab_from_section(&data, section);
            let strings = get_strtab_from_section(&data, &sections[section.sh_link as usize]);
            let mut off = 0;
            while off < bytes.len() {
                let index = half(bytes, off + 4)?;
                let aux = word(bytes, off + 12)? as usize;
                let name = get_strtab_string(strings, word(bytes, off + aux)?)
                    .ok_or("invalid version name")?;
                versions.insert(index, name);
                let next = word(bytes, off + 16)? as usize;
                if next == 0 {
                    break;
                }
                off += next;
            }
        }
        let versym = sections
            .iter()
            .find(|s| s.sh_type == 0x6fffffff)
            .map(|s| get_strtab_from_section(&data, s));
        for section in sections.iter().filter(|s| s.sh_type == 11) {
            let strings = get_strtab_from_section(&data, &sections[section.sh_link as usize]);
            for (i, record) in get_strtab_from_section(&data, section)
                .chunks_exact(24)
                .enumerate()
            {
                if half(record, 6)? == SHN_UNDEF || record[4] >> 4 == STB_LOCAL {
                    continue;
                }
                let Some(name) = symbol_name(strings, word(record, 0)?) else {
                    continue;
                };
                let Some(candidates) = requested_names.get(name) else {
                    continue;
                };
                let index = versym.map(|v| half(v, i * 2)).transpose()?.unwrap_or(1);
                let version = versions.get(&(index & 0x7fff));
                for &requested in candidates {
                    if result.contains_key(requested) {
                        continue;
                    }
                    if let Some((_, required)) = requested.split_once('@') {
                        if version.map(String::as_str) != Some(required.trim_start_matches('@')) {
                            continue;
                        }
                    } else if index & 0x8000 != 0 {
                        continue;
                    }
                    result.insert(
                        requested.clone(),
                        Export {
                            symbol: crate::elf::parse_symbol_entry(record, 0)?,
                            library: lib.soname.clone(),
                            version: version.cloned(),
                        },
                    );
                }
            }
        }
    }
    Ok(result)
}

fn dyn_entry(bytes: &mut Vec<u8>, tag: u64, value: u64) {
    bytes.extend_from_slice(&tag.to_le_bytes());
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn rela(bytes: &mut Vec<u8>, offset: u64, index: u32, kind: u32, addend: i64) {
    bytes.extend_from_slice(&offset.to_le_bytes());
    bytes.extend_from_slice(&((u64::from(index) << 32) | u64::from(kind)).to_le_bytes());
    bytes.extend_from_slice(&addend.to_le_bytes());
}

pub(super) fn prepare(
    layout: &mut MergedLayout,
    parsed: &[ParsedObject],
    dynamic: &DynamicLinkInfo,
    libs: &[String],
    resolver: &LibraryResolver,
    got: &HashMap<String, u64>,
    globals: &mut HashMap<String, u64>,
) -> Result<Runtime, String> {
    let imports: HashMap<_, _> = dynamic
        .plt_symbols
        .iter()
        .enumerate()
        .map(|(i, name)| (name.clone(), (i + 1) as u32))
        .collect();
    let exports = exports(libs, resolver, &dynamic.needed, &imports)?;
    for name in imports.keys() {
        if name.contains('@') && !exports.contains_key(name) {
            return Err(format!("undefined versioned symbol {name}"));
        }
    }
    let dynsym_idx = layout.section_by_name[".dynsym"];
    let mut weak = HashSet::default();
    let mut strong = HashSet::default();
    let mut relocations = Vec::new();
    for (object, obj) in parsed.iter().enumerate() {
        let Some(table) = obj.sections.iter().find(|s| s.sh_type == SHT_SYMTAB) else {
            continue;
        };
        let strings = get_strtab_from_section(&obj.data, &obj.sections[table.sh_link as usize]);
        let symbols = get_strtab_from_section(&obj.data, table);
        let mut indices = vec![0u32; symbols.len() / 24];
        for (i, record) in symbols.chunks_exact(24).enumerate() {
            if half(record, 6)? != SHN_UNDEF {
                continue;
            }
            if let Some(name) = symbol_name(strings, word(record, 0)?) {
                indices[i] = imports.get(name).copied().unwrap_or(0);
                if record[4] >> 4 == STB_WEAK {
                    weak.insert(name.to_string());
                } else {
                    strong.insert(name.to_string());
                }
            }
        }
        for section in obj.sections.iter().filter(|s| s.sh_type == 4) {
            let Some(&target) = layout
                .section_by_name
                .get(&obj.names[section.sh_info as usize])
            else {
                continue;
            };
            for record in get_strtab_from_section(&obj.data, section).chunks_exact(24) {
                let kind = word(record, 8)?;
                if !matches!(kind, 1 | 6 | 8) {
                    continue;
                }
                let index = word(record, 12)? as usize;
                let symbol = *indices
                    .get(index)
                    .ok_or("invalid dynamic relocation symbol")?;
                if (kind == 8 && dynamic.pie) || (kind != 8 && symbol == 0) {
                    continue;
                }
                let relocation = crate::elf::parse_rela_entry(record, 0)?;
                relocations.push(PendingRelocation {
                    object,
                    section: target,
                    input_name: obj.names[section.sh_info as usize].clone(),
                    offset: relocation.r_offset,
                    symbol,
                    kind,
                    addend: relocation.r_addend,
                });
            }
        }
    }
    for name in &dynamic.plt_symbols {
        if !exports.contains_key(name) && (!weak.contains(name) || strong.contains(name)) {
            return Err(format!("undefined symbol {name}"));
        }
    }
    let mut copies = Vec::new();
    let mut copy_symbols = Vec::new();
    for name in &dynamic.plt_symbols {
        let index = imports[name];
        let record = index as usize * 24;
        let binding = if weak.contains(name) && !strong.contains(name) {
            STB_WEAK
        } else {
            STB_GLOBAL
        };
        let kind = exports.get(name).map_or(2, |e| e.symbol.sym_type);
        layout.sections[dynsym_idx].data[record + 4] = (binding << 4) | kind;
        if kind == 1 {
            let export = &exports[name];
            let size =
                usize::try_from(export.symbol.st_size).map_err(|_| "imported data too large")?;
            let section = layout.section_by_name.get(".dynbss").copied();
            let idx = if let Some(idx) = section {
                idx
            } else {
                append(layout, ".dynbss", Vec::new(), 16, SHF_ALLOC | SHF_WRITE);
                layout.sections.len() - 1
            };
            let section = &mut layout.sections[idx];
            let offset = align_up(section.data.len() as u64, 16) as usize;
            section.data.resize(offset + size, 0);
            let address = section.vaddr + offset as u64;
            globals.insert(name.clone(), address);
            copies.push((address, index));
            copy_symbols.push((record, idx, address, size as u64));
        }
    }
    for (record, idx, address, size) in copy_symbols {
        let bytes = &mut layout.sections[dynsym_idx].data;
        bytes[record + 6..record + 8].copy_from_slice(&((idx + 1) as u16).to_le_bytes());
        bytes[record + 8..record + 16].copy_from_slice(&address.to_le_bytes());
        bytes[record + 16..record + 24].copy_from_slice(&size.to_le_bytes());
    }
    let stridx = layout.section_by_name[".dynstr"];
    let mut strings = layout.sections[stridx].data.clone();
    let mut versym = vec![0u8; (imports.len() + 1) * 2];
    let mut requirements: Vec<(String, Vec<(String, u16)>)> = Vec::new();
    let mut version_count = 2u16;
    for name in &dynamic.plt_symbols {
        let index = imports[name] as usize;
        let version = if let Some(export) = exports.get(name)
            && let Some(version) = &export.version
        {
            let group = if let Some(i) = requirements
                .iter()
                .position(|(lib, _)| lib == &export.library)
            {
                i
            } else {
                requirements.push((export.library.clone(), Vec::new()));
                requirements.len() - 1
            };
            let entries = &mut requirements[group].1;
            if let Some((_, index)) = entries.iter().find(|(v, _)| v == version) {
                *index
            } else {
                let index = version_count;
                version_count = version_count
                    .checked_add(1)
                    .ok_or("too many symbol versions")?;
                entries.push((version.clone(), index));
                index
            }
        } else {
            1
        };
        versym[index * 2..index * 2 + 2].copy_from_slice(&version.to_le_bytes());
    }
    let mut verneed = Vec::new();
    for (group, (library, entries)) in requirements.iter().enumerate() {
        let file = strings.len() as u32;
        strings.extend_from_slice(library.as_bytes());
        strings.push(0);
        verneed.extend_from_slice(&1u16.to_le_bytes());
        verneed.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        verneed.extend_from_slice(&file.to_le_bytes());
        verneed.extend_from_slice(&16u32.to_le_bytes());
        verneed.extend_from_slice(
            &(if group + 1 == requirements.len() {
                0
            } else {
                16 + entries.len() as u32 * 16
            })
            .to_le_bytes(),
        );
        for (i, (name, index)) in entries.iter().enumerate() {
            let offset = strings.len() as u32;
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
            verneed.extend_from_slice(&elf_hash(name.as_bytes()).to_le_bytes());
            verneed.extend_from_slice(&0u16.to_le_bytes());
            verneed.extend_from_slice(&index.to_le_bytes());
            verneed.extend_from_slice(&offset.to_le_bytes());
            verneed
                .extend_from_slice(&(if i + 1 == entries.len() { 0u32 } else { 16 }).to_le_bytes());
        }
    }
    layout.sections[stridx].data.clear();
    let end = layout
        .sections
        .iter()
        .map(|s| s.vaddr + s.data.len() as u64)
        .max()
        .unwrap();
    layout.sections[stridx].vaddr = align_up(end, 8);
    layout.sections[stridx].data = strings;
    append(layout, ".gnu.version", versym, 2, SHF_ALLOC);
    append(layout, ".gnu.version_r", verneed, 8, SHF_ALLOC);
    let mut gnu_hash = Vec::new();
    for v in [1u32, 1, 1, 5] {
        gnu_hash.extend_from_slice(&v.to_le_bytes());
    }
    let hashes: Vec<_> = dynamic
        .plt_symbols
        .iter()
        .map(|name| {
            name.split('@')
                .next()
                .unwrap()
                .bytes()
                .fold(5381u32, |h, b| {
                    h.wrapping_mul(33).wrapping_add(u32::from(b))
                })
        })
        .collect();
    let bloom = hashes.iter().fold(0u64, |bloom, hash| {
        bloom | (1 << (hash % 64)) | (1 << ((hash >> 5) % 64))
    });
    gnu_hash.extend_from_slice(&bloom.to_le_bytes());
    gnu_hash.extend_from_slice(&1u32.to_le_bytes());
    for (i, hash) in hashes.iter().enumerate() {
        gnu_hash
            .extend_from_slice(&((hash & !1) | u32::from(i + 1 == imports.len())).to_le_bytes());
    }
    if imports.is_empty() {
        gnu_hash[24..28].fill(0);
    }
    append(layout, ".gnu.hash", gnu_hash, 8, SHF_ALLOC);
    let count = copies.len()
        + got
            .keys()
            .filter(|name| imports.contains_key(*name))
            .count()
        + relocations.len();
    if let Some(&idx) = layout.section_by_name.get(".rela.dyn") {
        let end = layout
            .sections
            .iter()
            .map(|s| s.vaddr + s.data.len() as u64)
            .max()
            .unwrap();
        layout.sections[idx].vaddr = align_up(end, 8);
        let size = layout.sections[idx].data.len() + count * 24;
        layout.sections[idx].data.resize(size, 0);
    } else {
        append(layout, ".rela.dyn", vec![0; count * 24], 8, SHF_ALLOC);
    }
    if let Some(&idx) = layout.section_by_name.get(".eh_frame") {
        let count = frame_entries(&layout.sections[idx])?.len();
        append(
            layout,
            ".eh_frame_hdr",
            vec![0; 12 + count * 8],
            4,
            SHF_ALLOC,
        );
    }
    let dynidx = layout.section_by_name[".dynamic"];
    let mut entries: Vec<(u64, u64)> = layout.sections[dynidx]
        .data
        .chunks_exact(16)
        .filter_map(|v| {
            let tag = u64::from_le_bytes(v[..8].try_into().unwrap());
            (tag != 0).then(|| (tag, u64::from_le_bytes(v[8..].try_into().unwrap())))
        })
        .collect();
    for (tag, section) in [
        (5, ".dynstr"),
        (0x6ffffff0, ".gnu.version"),
        (0x6ffffffe, ".gnu.version_r"),
        (0x6ffffef5, ".gnu.hash"),
        (7, ".rela.dyn"),
    ] {
        if section == ".gnu.version_r" && requirements.is_empty() {
            continue;
        }
        let value = layout.sections[layout.section_by_name[section]].vaddr;
        if let Some(entry) = entries.iter_mut().find(|e| e.0 == tag) {
            entry.1 = value;
        } else {
            entries.push((tag, value));
        }
    }
    entries.iter_mut().find(|e| e.0 == 10).unwrap().1 = layout.sections[stridx].data.len() as u64;
    if !requirements.is_empty() {
        entries.push((0x6fffffff, requirements.len() as u64));
    }
    entries.extend([(8, (count * 24) as u64), (9, 24)]);
    for (name, tag, size_tag) in [
        (".init_array", 25, 27),
        (".fini_array", 26, 28),
        (".preinit_array", 32, 33),
    ] {
        let size: usize = layout
            .sections
            .iter()
            .filter(|s| array_kind(&s.name).is_some_and(|(base, _)| base == name))
            .map(|s| s.data.len())
            .sum();
        if size != 0 {
            entries.extend([(tag, 0), (size_tag, size as u64)]);
        }
    }
    for (name, tag) in [(".init", 12), (".fini", 13)] {
        if let Some(&idx) = layout.section_by_name.get(name) {
            entries.push((tag, layout.sections[idx].vaddr));
        }
    }
    layout.sections[dynidx]
        .data
        .resize((entries.len() + 1) * 16, 0);
    let mut end = align_up(
        layout
            .sections
            .iter()
            .map(|s| s.vaddr + s.data.len() as u64)
            .max()
            .unwrap(),
        4096,
    );
    let mut protected: Vec<_> = layout
        .sections
        .iter()
        .enumerate()
        .filter(|(_, s)| relro(&s.name))
        .map(|(i, _)| i)
        .collect();
    protected.sort_by_key(|&i| {
        let name = &layout.sections[i].name;
        array_kind(name).map_or((name.as_str(), 0), |(base, priority)| (base, priority))
    });
    for idx in protected {
        let section = &mut layout.sections[idx];
        if array_kind(&section.name).is_some() {
            section.align = 8;
        }
        section.vaddr = align_up(end, section.align);
        end = section.vaddr + section.data.len() as u64;
    }
    let padding = (align_up(end, 4096) - end) as usize;
    append(layout, ".relro_padding", vec![0; padding], 1, SHF_ALLOC);
    for (tag, name) in [
        (3, ".got.plt"),
        (25, ".init_array"),
        (26, ".fini_array"),
        (32, ".preinit_array"),
    ] {
        let address = if name == ".got.plt" {
            Some(layout.sections[layout.section_by_name[name]].vaddr)
        } else {
            layout
                .sections
                .iter()
                .filter(|s| array_kind(&s.name).is_some_and(|(base, _)| base == name))
                .map(|s| s.vaddr)
                .min()
        };
        if let Some(address) = address
            && let Some(entry) = entries.iter_mut().find(|e| e.0 == tag)
        {
            entry.1 = address;
        }
    }
    let mut content = Vec::new();
    for (tag, value) in entries {
        dyn_entry(&mut content, tag, value);
    }
    dyn_entry(&mut content, 0, 0);
    layout.sections[dynidx].data = content;
    let gotplt = layout.sections[layout.section_by_name[".got.plt"]].vaddr;
    globals.insert("_GLOBAL_OFFSET_TABLE_".into(), gotplt);
    let pltidx = layout.section_by_name[".plt"];
    let plt = &mut layout.sections[pltidx];
    for (off, target) in [(2, gotplt + 8), (8, gotplt + 16)] {
        plt.data[off..off + 4].copy_from_slice(
            &((target as i64 - (plt.vaddr + off as u64 + 4) as i64) as i32).to_le_bytes(),
        );
    }
    for i in 0..imports.len() {
        let off = 16 + i * 16 + 2;
        plt.data[off..off + 4].copy_from_slice(
            &((gotplt as i64 + 24 + i as i64 * 8 - (plt.vaddr + off as u64 + 4) as i64) as i32)
                .to_le_bytes(),
        );
    }
    let idx = layout.section_by_name[".rela.plt"];
    for i in 0..imports.len() {
        layout.sections[idx].data[i * 24..i * 24 + 8]
            .copy_from_slice(&(gotplt + 24 + i as u64 * 8).to_le_bytes());
    }
    let gotbase = layout
        .section_by_name
        .get(".got")
        .map(|&i| layout.sections[i].vaddr);
    let oldbase = got.values().min().copied();
    let got = got
        .iter()
        .filter_map(|(name, address)| {
            imports
                .get(name)
                .map(|&index| (gotbase.unwrap() + address - oldbase.unwrap(), index))
        })
        .collect();
    Ok(Runtime {
        copies,
        got,
        relocations,
    })
}

fn array_kind(name: &str) -> Option<(&'static str, u32)> {
    for base in [".init_array", ".fini_array", ".preinit_array"] {
        if name == base {
            return Some((base, 65535));
        }
        if let Some(priority) = name
            .strip_prefix(base)
            .and_then(|s| s.strip_prefix('.'))
            .and_then(|s| s.parse().ok())
        {
            return Some((base, priority));
        }
    }
    None
}

pub(super) fn array_order(name: &str) -> (&str, u32) {
    if name == ".relro_padding" {
        return ("~", 0);
    }
    array_kind(name).unwrap_or((name, 0))
}

impl Runtime {
    pub(super) fn remap(&mut self, address: impl Fn(u64) -> u64) {
        for (value, _) in self.copies.iter_mut().chain(&mut self.got) {
            *value = address(*value);
        }
    }
}

pub(super) fn relro(name: &str) -> bool {
    matches!(
        name,
        ".dynamic"
            | ".got"
            | ".got.plt"
            | ".init_array"
            | ".fini_array"
            | ".preinit_array"
            | ".relro_padding"
    ) || name.starts_with(".data.rel.ro")
        || array_kind(name).is_some()
}

pub(super) fn finish(
    layout: &mut MergedLayout,
    contributions: &[HashMap<String, ObjectSectionContrib>],
    runtime: &Runtime,
) -> Result<(), String> {
    let mut bytes = Vec::new();
    for &(address, index) in &runtime.copies {
        rela(&mut bytes, address, index, 5, 0);
    }
    for &(address, index) in &runtime.got {
        rela(&mut bytes, address, index, 6, 0);
    }
    for relocation in &runtime.relocations {
        let section = &layout.sections[relocation.section];
        let base = section.vaddr
            + contributions[relocation.object][&relocation.input_name].offset_in_merged;
        rela(
            &mut bytes,
            base + relocation.offset,
            relocation.symbol,
            relocation.kind,
            relocation.addend,
        );
    }
    let idx = layout.section_by_name[".rela.dyn"];
    let size = bytes.len() as u64;
    bytes.resize(layout.sections[idx].data.len(), 0);
    layout.sections[idx].data = bytes;
    let idx = layout.section_by_name[".dynamic"];
    for record in layout.sections[idx].data.chunks_exact_mut(16) {
        if u64::from_le_bytes(record[..8].try_into().unwrap()) == 8 {
            record[8..].copy_from_slice(&size.to_le_bytes());
        }
    }
    if let Some(&hdridx) = layout.section_by_name.get(".eh_frame_hdr") {
        let frame = &layout.sections[layout.section_by_name[".eh_frame"]];
        let mut entries = frame_entries(frame)?;
        entries.sort_unstable();
        let address = layout.sections[hdridx].vaddr;
        let mut bytes = vec![1, 0x1b, 0x03, 0x3b];
        bytes.extend_from_slice(&((frame.vaddr as i64 - address as i64 - 4) as i32).to_le_bytes());
        bytes.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (pc, fde) in entries {
            for value in [pc, fde] {
                bytes.extend_from_slice(&((value as i64 - address as i64) as i32).to_le_bytes());
            }
        }
        layout.sections[hdridx].data = bytes;
    }
    Ok(())
}

fn leb(bytes: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut value = 0;
    for shift in (0..64).step_by(7) {
        let byte = *bytes.get(*pos).ok_or("truncated CFI LEB128")?;
        *pos += 1;
        value |= u64::from(byte & 127) << shift;
        if byte & 128 == 0 {
            return Ok(value);
        }
    }
    Err("oversized CFI LEB128".into())
}

fn pointer(bytes: &[u8], pos: &mut usize, encoding: u8, base: u64) -> Result<u64, String> {
    let start = *pos;
    let (value, width) = match encoding & 15 {
        0 | 4 => (
            u64::from_le_bytes(
                bytes
                    .get(start..start + 8)
                    .ok_or("truncated CFI pointer")?
                    .try_into()
                    .unwrap(),
            ),
            8,
        ),
        3 => (u64::from(word(bytes, start)?), 4),
        0xb => (word(bytes, start)? as i32 as i64 as u64, 4),
        0xc => (
            u64::from_le_bytes(
                bytes
                    .get(start..start + 8)
                    .ok_or("truncated CFI pointer")?
                    .try_into()
                    .unwrap(),
            ),
            8,
        ),
        _ => return Err(format!("unsupported CFI pointer encoding {encoding:#x}")),
    };
    *pos += width;
    match encoding & 0x70 {
        0 => Ok(value),
        0x10 => Ok(value.wrapping_add(base + start as u64)),
        _ => Err(format!("unsupported CFI pointer base {encoding:#x}")),
    }
}

fn frame_entries(section: &MergedSection) -> Result<Vec<(u64, u64)>, String> {
    let bytes = &section.data;
    let mut cies = HashMap::default();
    let mut entries = Vec::new();
    let mut off = 0;
    while off + 4 <= bytes.len() {
        let length = word(bytes, off)? as usize;
        if length == 0 {
            off += 4;
            continue;
        }
        if length == u32::MAX as usize {
            return Err("extended CFI record lengths unsupported".into());
        }
        let end = off
            .checked_add(4 + length)
            .filter(|&end| end <= bytes.len())
            .ok_or("truncated CFI record")?;
        let id = word(bytes, off + 4)? as usize;
        if id == 0 {
            let version = bytes[off + 8];
            let mut pos = off + 9;
            let start = pos;
            while pos < end && bytes[pos] != 0 {
                pos += 1;
            }
            let augmentation = bytes.get(start..pos).ok_or("invalid CIE augmentation")?;
            pos += 1;
            leb(bytes, &mut pos)?;
            leb(bytes, &mut pos)?;
            if version == 1 {
                pos += 1;
            } else {
                leb(bytes, &mut pos)?;
            }
            let mut encoding = 0;
            if augmentation.first() == Some(&b'z') {
                leb(bytes, &mut pos)?;
                for &kind in &augmentation[1..] {
                    match kind {
                        b'R' => {
                            encoding = *bytes.get(pos).ok_or("truncated CIE encoding")?;
                            pos += 1;
                        }
                        b'L' => pos += 1,
                        b'P' => {
                            let encoding = *bytes.get(pos).ok_or("truncated CIE personality")?;
                            pos += 1;
                            pointer(bytes, &mut pos, encoding, section.vaddr)?;
                        }
                        b'S' => (),
                        _ => return Err(format!("unsupported CIE augmentation {}", kind as char)),
                    }
                }
            }
            cies.insert(off, encoding);
        } else {
            let cie = (off + 4).checked_sub(id).ok_or("invalid FDE CIE offset")?;
            let encoding = *cies.get(&cie).ok_or("missing FDE CIE")?;
            let pc = pointer(bytes, &mut (off + 8), encoding, section.vaddr)?;
            entries.push((pc, section.vaddr + off as u64));
        }
        off = end;
    }
    Ok(entries)
}

pub(super) fn remap_generated(layout: &mut MergedLayout, remap: impl Fn(u64) -> u64) {
    for section in &mut layout.sections {
        match section.name.as_str() {
            ".dynamic" => {
                for record in section.data.chunks_exact_mut(16) {
                    let tag = u64::from_le_bytes(record[..8].try_into().unwrap());
                    if matches!(
                        tag,
                        3 | 4
                            | 5
                            | 6
                            | 7
                            | 12
                            | 13
                            | 23
                            | 25
                            | 26
                            | 32
                            | 0x6ffffef5
                            | 0x6ffffff0
                            | 0x6ffffffe
                    ) {
                        let value = u64::from_le_bytes(record[8..].try_into().unwrap());
                        record[8..].copy_from_slice(&remap(value).to_le_bytes());
                    }
                }
            }
            ".rela.plt" => {
                for record in section.data.chunks_exact_mut(24) {
                    let value = u64::from_le_bytes(record[..8].try_into().unwrap());
                    record[..8].copy_from_slice(&remap(value).to_le_bytes());
                }
            }
            ".dynsym" => {
                for record in section.data.chunks_exact_mut(24) {
                    let value = u64::from_le_bytes(record[8..16].try_into().unwrap());
                    if value != 0 {
                        record[8..16].copy_from_slice(&remap(value).to_le_bytes());
                    }
                }
            }
            ".got.plt" => {
                for record in section.data.chunks_exact_mut(8) {
                    let value = u64::from_le_bytes(record.try_into().unwrap());
                    if value != 0 {
                        record.copy_from_slice(&remap(value).to_le_bytes());
                    }
                }
            }
            _ => (),
        }
    }
    if let (Some(&plt), Some(&got)) = (
        layout.section_by_name.get(".plt"),
        layout.section_by_name.get(".got.plt"),
    ) {
        let got = layout.sections[got].vaddr;
        let plt = &mut layout.sections[plt];
        for (off, target) in [(2, got + 8), (8, got + 16)]
            .into_iter()
            .chain((0..plt.data.len() / 16 - 1).map(|i| (18 + i * 16, got + 24 + i as u64 * 8)))
        {
            plt.data[off..off + 4].copy_from_slice(
                &((target as i64 - (plt.vaddr + off as u64 + 4) as i64) as i32).to_le_bytes(),
            );
        }
    }
}
