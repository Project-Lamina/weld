use super::{MergedLayout, ParsedObject, align_up};
use crate::{collections::HashMap, elf::get_strtab_from_section};

fn word(bytes: &[u8], offset: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or("truncated GNU property")?
            .try_into()
            .unwrap(),
    ))
}

fn properties(obj: &ParsedObject) -> Result<HashMap<u32, Vec<u8>>, String> {
    let mut result = HashMap::default();
    for (_, section) in obj
        .sections
        .iter()
        .enumerate()
        .filter(|(i, s)| s.sh_type == 7 && obj.names[*i] == ".note.gnu.property")
    {
        let bytes = get_strtab_from_section(&obj.data, section);
        let mut offset = 0;
        while offset < bytes.len() {
            let namesz = word(bytes, offset)? as usize;
            let descsz = word(bytes, offset + 4)? as usize;
            let kind = word(bytes, offset + 8)?;
            let name = offset + 12;
            let desc = align_up((name + namesz) as u64, 4) as usize;
            let end = desc
                .checked_add(descsz)
                .filter(|&end| end <= bytes.len())
                .ok_or("invalid GNU property note size")?;
            if kind != 5 || bytes.get(name..name + namesz) != Some(b"GNU\0") {
                return Err("invalid GNU property note".into());
            }
            let mut property = desc;
            while property < end {
                let kind = word(bytes, property)?;
                let size = word(bytes, property + 4)? as usize;
                let value = bytes
                    .get(property + 8..property + 8 + size)
                    .filter(|_| property + 8 + size <= end)
                    .ok_or("invalid GNU property size")?;
                if result.insert(kind, value.to_vec()).is_some() {
                    return Err("duplicate GNU property".into());
                }
                property = align_up((property + 8 + size) as u64, 8) as usize;
            }
            offset = align_up(end as u64, 4) as usize;
        }
    }
    Ok(result)
}

pub(super) fn merge_properties(
    layout: &mut MergedLayout,
    objects: &[ParsedObject],
) -> Result<(), String> {
    let Some(&index) = layout.section_by_name.get(".note.gnu.property") else {
        return Ok(());
    };
    let inputs: Vec<_> = objects.iter().map(properties).collect::<Result<_, _>>()?;
    let mut kinds: Vec<_> = inputs.iter().flat_map(|p| p.keys().copied()).collect();
    kinds.sort_unstable();
    kinds.dedup();
    let mut desc = Vec::new();
    for kind in kinds {
        let values: Vec<_> = inputs.iter().filter_map(|p| p.get(&kind)).collect();
        let all = values.len() == inputs.len();
        let and = matches!(kind, 0xb0000000..=0xb0007fff)
            || (objects[0].header.e_machine == 62 && kind == 0xc0000002)
            || (objects[0].header.e_machine == 183 && kind == 0xc0000000);
        let or = matches!(kind, 0xb0008000..=0xb000ffff)
            || (objects[0].header.e_machine == 62 && matches!(kind, 0xc0008002 | 0xc0010002));
        let value = if and || or {
            if (and || kind == 0xc0010002) && !all {
                continue;
            }
            let mut merged = if and { u32::MAX } else { 0 };
            for value in values {
                if value.len() != 4 {
                    return Err("invalid integer GNU property size".into());
                }
                let value = word(value, 0)?;
                merged = if and { merged & value } else { merged | value };
            }
            if merged == 0 {
                continue;
            }
            merged.to_le_bytes().to_vec()
        } else if kind == 1 {
            let mut size = 0u64;
            for value in values {
                size = size.max(u64::from_le_bytes(
                    value
                        .as_slice()
                        .try_into()
                        .map_err(|_| "invalid GNU stack size property")?,
                ));
            }
            size.to_le_bytes().to_vec()
        } else if kind == 2 {
            if !all {
                continue;
            }
            Vec::new()
        } else {
            if values.iter().any(|v| *v != values[0]) {
                return Err(format!("conflicting GNU property {kind:#x}"));
            }
            values[0].clone()
        };
        desc.extend_from_slice(&kind.to_le_bytes());
        desc.extend_from_slice(&(value.len() as u32).to_le_bytes());
        desc.extend_from_slice(&value);
        desc.resize(align_up(desc.len() as u64, 8) as usize, 0);
    }
    let section = &mut layout.sections[index];
    section.data.clear();
    section.align = 8;
    if !desc.is_empty() {
        for value in [4u32, desc.len() as u32, 5] {
            section.data.extend_from_slice(&value.to_le_bytes());
        }
        section.data.extend_from_slice(b"GNU\0");
        section.data.extend_from_slice(&desc);
    }
    Ok(())
}
