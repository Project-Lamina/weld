//! x86_64 relocation application.

use crate::elf::reloc_type;
use crate::elf::{SectionHeader, parse_rela_section};
use crate::link::MergedLayout;

fn write_u32_le(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn write_u64_le(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
}

/// Apply all x86_64 `SHT_RELA` relocations from `data` into `layout`.
///
/// `symbol_addrs[i]` is the resolved virtual address of ELF symbol index `i`,
/// or `None` for an undefined symbol. `section_offset` maps each section name
/// to its byte offset within the merged section (used for multi-object links).
pub fn apply_relocations(
    layout: &mut MergedLayout,
    data: &[u8],
    sections: &[SectionHeader],
    names: &[String],
    symbol_addrs: &[Option<u64>],
    section_offset: Option<&std::collections::HashMap<String, u64>>,
) -> Result<(), String> {
    const SHT_RELA: u32 = 4;

    for rela_sh in sections.iter() {
        if rela_sh.sh_type != SHT_RELA {
            continue;
        }
        let target_section_idx = rela_sh.sh_info as usize;
        let target_name = names.get(target_section_idx).cloned().unwrap_or_default();
        let Some(&merged_idx) = layout.section_by_name.get(&target_name) else {
            continue;
        };
        let merged = &mut layout.sections[merged_idx];
        let data_off = section_offset
            .and_then(|m| m.get(&target_name).copied())
            .unwrap_or(0) as usize;
        let relas = parse_rela_section(data, rela_sh)?;

        for rel in &relas {
            let off = data_off + rel.r_offset as usize;
            let place = merged.vaddr + off as u64;
            let a = rel.r_addend;
            let p = place as i64;

            match rel.r_type {
                reloc_type::R_X86_64_NONE => {}
                reloc_type::R_X86_64_RELATIVE => {
                    let base = merged.vaddr as i64;
                    let val = base.wrapping_add(a) as u64;
                    if merged.data.len() < off + 8 {
                        return Err(format!("relocation offset {} out of bounds", rel.r_offset));
                    }
                    write_u64_le(&mut merged.data, off, val);
                }
                reloc_type::R_X86_64_64 => {
                    let Some(Some(s_addr)) = symbol_addrs.get(rel.r_sym as usize) else {
                        return Err(format!("undefined symbol index {}", rel.r_sym));
                    };
                    let val = s_addr.wrapping_add_signed(a);
                    if merged.data.len() < off + 8 {
                        return Err(format!("relocation offset {} out of bounds", rel.r_offset));
                    }
                    write_u64_le(&mut merged.data, off, val);
                }
                reloc_type::R_X86_64_32 => {
                    let Some(Some(s_addr)) = symbol_addrs.get(rel.r_sym as usize) else {
                        return Err(format!("undefined symbol index {}", rel.r_sym));
                    };
                    let val = s_addr.wrapping_add_signed(a) as u32;
                    if merged.data.len() < off + 4 {
                        return Err(format!("relocation offset {} out of bounds", rel.r_offset));
                    }
                    write_u32_le(&mut merged.data, off, val);
                }
                reloc_type::R_X86_64_PC32 | reloc_type::R_X86_64_PLT32 => {
                    let Some(Some(s_addr)) = symbol_addrs.get(rel.r_sym as usize) else {
                        return Err(format!("undefined symbol index {}", rel.r_sym));
                    };
                    let val = (*s_addr as i64).wrapping_add(a).wrapping_sub(p) as u32;
                    if merged.data.len() < off + 4 {
                        return Err(format!("relocation offset {} out of bounds", rel.r_offset));
                    }
                    write_u32_le(&mut merged.data, off, val);
                }
                _ => {
                    return Err(format!("unsupported x86_64 relocation type {}", rel.r_type));
                }
            }
        }
    }

    Ok(())
}
