use super::*;
use crate::elf::reloc_type::*;

pub(super) struct RelativeRelocations {
    slots: Vec<(usize, usize, Option<i64>)>,
    kind: u32,
}

pub(super) fn prepare(
    layout: &mut MergedLayout,
    objects: &[ParsedObject],
    contributions: &[HashMap<String, ObjectSectionContrib>],
    got: &HashMap<String, u64>,
    globals: &HashMap<String, u64>,
) -> Result<RelativeRelocations, String> {
    let arch = TargetArch::from_elf_machine(objects[0].header.e_machine)
        .ok_or("unsupported PIE architecture")?;
    let (absolute, relative_kind, rejected): (u32, u32, &[u32]) = match arch {
        TargetArch::X86_64 => (R_X86_64_64, R_X86_64_RELATIVE, &[R_X86_64_32, R_X86_64_32S]),
        TargetArch::AArch64 => (R_AARCH64_ABS64, R_AARCH64_RELATIVE, &[R_AARCH64_ABS32]),
        TargetArch::RiscV => (
            R_RISCV_64,
            R_RISCV_RELATIVE,
            &[R_RISCV_32, R_RISCV_HI20, R_RISCV_LO12_I, R_RISCV_LO12_S],
        ),
    };
    let mut slots = Vec::new();
    let mut absolute_names = HashSet::default();
    let mut defined_names = HashSet::default();
    for obj in objects {
        if let Some((symbols, strings)) = parse_symtab_view(&obj.data, &obj.sections)? {
            for symbol in symbols.iter().filter(|s| s.bind != STB_LOCAL) {
                if let Some(name) = get_strtab_string(strings, symbol.name_offset) {
                    if symbol.st_shndx == SHN_ABS {
                        absolute_names.insert(name);
                    } else if symbol.st_shndx != SHN_UNDEF {
                        defined_names.insert(name);
                    }
                }
            }
        }
    }
    for (object, obj) in objects.iter().enumerate() {
        let Some((symbols, strings)) = parse_symtab_view(&obj.data, &obj.sections)? else {
            continue;
        };
        for section in obj.sections.iter().filter(|s| s.sh_type == 4) {
            let target = section.sh_info as usize;
            let Some(contribution) = contributions[object].get(&obj.names[target]) else {
                continue;
            };
            let index = layout.section_by_name[&obj.names[target]];
            for rel in parse_rela_section(&obj.data, section)? {
                let relative = rel.r_type == relative_kind;
                let symbol = symbols
                    .get(rel.r_sym as usize)
                    .ok_or("invalid PIE symbol index")?;
                let name = get_strtab_string(strings, symbol.name_offset).unwrap_or_default();
                if !relative
                    && (symbol.st_shndx == SHN_ABS
                        || absolute_names.contains(&name)
                        || (symbol.st_shndx == SHN_UNDEF && !defined_names.contains(&name)))
                {
                    continue;
                }
                match rel.r_type {
                    kind if kind == absolute
                        || relative
                        || (arch == TargetArch::X86_64 && kind == 6) =>
                    {
                        slots.push((
                            index,
                            (contribution.offset_in_merged + rel.r_offset) as usize,
                            relative.then_some(rel.r_addend),
                        ))
                    }
                    kind if rejected.contains(&kind) => {
                        return Err(format!(
                            "relocation type {} requires position independent input for PIE",
                            rel.r_type
                        ));
                    }
                    _ => (),
                }
            }
        }
    }
    if let Some(&index) = layout.section_by_name.get(".got") {
        let base = layout.sections[index].vaddr;
        for (name, address) in got {
            if globals.contains_key(name)
                && defined_names.contains(name)
                && !absolute_names.contains(name)
            {
                slots.push((index, (*address - base) as usize, None));
            }
        }
    }
    slots.sort_unstable();
    let end = layout
        .sections
        .iter()
        .map(|s| s.vaddr + s.data.len() as u64)
        .max()
        .unwrap_or(4096);
    layout
        .section_by_name
        .insert(".rela.dyn".into(), layout.sections.len());
    layout.sections.push(MergedSection {
        name: ".rela.dyn".into(),
        data: vec![0; slots.len() * 24],
        vaddr: align_up(end, 8),
        align: 8,
        flags: SHF_ALLOC,
        sh_type: 4,
        entsize: 24,
    });
    Ok(RelativeRelocations {
        slots,
        kind: relative_kind,
    })
}

pub(super) fn finish(
    layout: &mut MergedLayout,
    pending: RelativeRelocations,
) -> Result<(), String> {
    let mut bytes = Vec::new();
    for (index, offset, addend) in &pending.slots {
        let section = &mut layout.sections[*index];
        let slot = section
            .data
            .get_mut(*offset..*offset + 8)
            .ok_or("PIE relocation out of bounds")?;
        let addend = addend.unwrap_or_else(|| i64::from_le_bytes(slot.try_into().unwrap()));
        slot.copy_from_slice(&addend.to_le_bytes());
        bytes.extend_from_slice(&(section.vaddr + *offset as u64).to_le_bytes());
        bytes.extend_from_slice(&u64::from(pending.kind).to_le_bytes());
        bytes.extend_from_slice(&addend.to_le_bytes());
    }
    let dynidx = layout.section_by_name[".dynamic"];
    let existing_size = layout.sections[dynidx]
        .data
        .chunks_exact(16)
        .find_map(|record| {
            (u64::from_le_bytes(record[..8].try_into().unwrap()) == 8)
                .then(|| u64::from_le_bytes(record[8..].try_into().unwrap()) as usize)
        })
        .unwrap_or(0);
    let relaidx = layout.section_by_name[".rela.dyn"];
    bytes.extend_from_slice(&layout.sections[relaidx].data[..existing_size]);
    layout.sections[relaidx].data = bytes;
    dynamic::set_relative_tags(layout, pending.slots.len() as u64);
    Ok(())
}

pub(super) fn add_dynamic(
    layout: &mut MergedLayout,
    arch: TargetArch,
    interpreter: Option<String>,
) -> DynamicLinkInfo {
    let mut append = |name: &str, data: Vec<u8>, flags: u64| {
        let end = layout
            .sections
            .iter()
            .map(|s| s.vaddr + s.data.len() as u64)
            .max()
            .unwrap_or(arch.page_align());
        let address = align_up(end, 8);
        layout
            .section_by_name
            .insert(name.into(), layout.sections.len());
        layout.sections.push(MergedSection {
            name: name.into(),
            data,
            vaddr: address,
            flags,
            align: 8,
            sh_type: 1,
            entsize: 0,
        });
        address
    };
    let strings = append(".dynstr", vec![0], SHF_ALLOC);
    let symbols = append(".dynsym", vec![0; 24], SHF_ALLOC);
    let hash = append(".hash", dynamic::build_sysv_hash(&[]), SHF_ALLOC);
    let mut content = Vec::new();
    for (tag, value) in [
        (4u64, hash),
        (5, strings),
        (6, symbols),
        (10, 1),
        (11, 24),
        (7, 0),
        (8, 0),
        (9, 24),
        (0x6ffffff9, 0),
        (0x6ffffffb, 0x08000000),
        (0, 0),
    ] {
        content.extend_from_slice(&tag.to_le_bytes());
        content.extend_from_slice(&value.to_le_bytes());
    }
    append(".dynamic", content, SHF_ALLOC | SHF_WRITE);
    DynamicLinkInfo {
        pie: true,
        interpreter: Some(interpreter.unwrap_or_else(|| {
            match arch {
                TargetArch::X86_64 => "/lib64/ld-linux-x86-64.so.2",
                TargetArch::AArch64 => "/lib/ld-linux-aarch64.so.1",
                TargetArch::RiscV => "/lib/ld-linux-riscv64-lp64d.so.1",
            }
            .into()
        })),
        ..DynamicLinkInfo::default()
    }
}
