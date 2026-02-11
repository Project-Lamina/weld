//! AArch64 relocation application.
//!
//! Supports: ABS64, ABS32, RELATIVE, ADD_ABS_LO12_NC, ADR_PREL_LO21,
//! ADR_PREL_PG_HI21, CALL26, JUMP26.

use crate::elf::reloc_type;
use crate::elf::{parse_rela_section, SectionHeader};
use crate::link::MergedLayout;

fn write_u32_le(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn write_u64_le(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
}

fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn page4k(x: u64) -> u64 {
    x & !0xFFF
}

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
        let data_off = section_offset.and_then(|m| m.get(&target_name).copied()).unwrap_or(0) as usize;
        let relas = parse_rela_section(data, rela_sh)?;

        for rel in &relas {
            let off = data_off + rel.r_offset as usize;
            let place = merged.vaddr + off as u64;
            let a = rel.r_addend;
            let p = place as i64;

            match rel.r_type {
                reloc_type::R_AARCH64_NONE => {}
                reloc_type::R_AARCH64_RELATIVE => {
                    let base = merged.vaddr as i64;
                    let val = base.wrapping_add(a) as u64;
                    if merged.data.len() < off + 8 {
                        return Err(format!("relocation offset {} out of bounds", rel.r_offset));
                    }
                    write_u64_le(&mut merged.data, off, val);
                }
                reloc_type::R_AARCH64_ABS64 => {
                    let Some(Some(s_addr)) = symbol_addrs.get(rel.r_sym as usize) else {
                        return Err(format!("undefined symbol index {}", rel.r_sym));
                    };
                    let val = s_addr.wrapping_add_signed(a);
                    if merged.data.len() < off + 8 {
                        return Err(format!("relocation offset {} out of bounds", rel.r_offset));
                    }
                    write_u64_le(&mut merged.data, off, val);
                }
                reloc_type::R_AARCH64_ABS32 => {
                    let Some(Some(s_addr)) = symbol_addrs.get(rel.r_sym as usize) else {
                        return Err(format!("undefined symbol index {}", rel.r_sym));
                    };
                    let val = s_addr.wrapping_add_signed(a) as u32;
                    if merged.data.len() < off + 4 {
                        return Err(format!("relocation offset {} out of bounds", rel.r_offset));
                    }
                    write_u32_le(&mut merged.data, off, val);
                }
                reloc_type::R_AARCH64_ADD_ABS_LO12_NC => {
                    let Some(Some(s_addr)) = symbol_addrs.get(rel.r_sym as usize) else {
                        return Err(format!("undefined symbol index {}", rel.r_sym));
                    };
                    let val = (s_addr.wrapping_add_signed(a) & 0xFFF) as u32;
                    if merged.data.len() < off + 4 {
                        return Err(format!("relocation offset {} out of bounds", rel.r_offset));
                    }
                    let insn = read_u32_le(&merged.data, off);
                    let patched = (insn & !(0xFFF << 10)) | (val << 10);
                    write_u32_le(&mut merged.data, off, patched);
                }
                reloc_type::R_AARCH64_ADR_PREL_LO21 => {
                    let Some(Some(s_addr)) = symbol_addrs.get(rel.r_sym as usize) else {
                        return Err(format!("undefined symbol index {}", rel.r_sym));
                    };
                    let diff = (*s_addr as i64).wrapping_add(a).wrapping_sub(p);
                    let val = (diff & 0x1FFFFF) as u32;
                    if merged.data.len() < off + 4 {
                        return Err(format!("relocation offset {} out of bounds", rel.r_offset));
                    }
                    let insn = read_u32_le(&merged.data, off);
                    let immlo = val & 3;
                    let immhi = (val >> 2) & 0x7FFFF;
                    let patched = (insn & 0x9F00001F) | (immlo << 29) | (immhi << 5);
                    write_u32_le(&mut merged.data, off, patched);
                }
                reloc_type::R_AARCH64_ADR_PREL_PG_HI21 => {
                    let Some(Some(s_addr)) = symbol_addrs.get(rel.r_sym as usize) else {
                        return Err(format!("undefined symbol index {}", rel.r_sym));
                    };
                    let s_plus_a = s_addr.wrapping_add_signed(a);
                    let page_s = page4k(s_plus_a);
                    let page_p = page4k(place);
                    let diff = (page_s as i64).wrapping_sub(page_p as i64);
                    let val = (diff & 0x1FFFFF) as u32;
                    if merged.data.len() < off + 4 {
                        return Err(format!("relocation offset {} out of bounds", rel.r_offset));
                    }
                    let insn = read_u32_le(&merged.data, off);
                    let immlo = val & 3;
                    let immhi = (val >> 2) & 0x7FFFF;
                    let patched = (insn & 0x9F00001F) | (immlo << 29) | (immhi << 5);
                    write_u32_le(&mut merged.data, off, patched);
                }
                reloc_type::R_AARCH64_CALL26 | reloc_type::R_AARCH64_JUMP26 => {
                    let Some(Some(s_addr)) = symbol_addrs.get(rel.r_sym as usize) else {
                        return Err(format!("undefined symbol index {}", rel.r_sym));
                    };
                    let diff = (*s_addr as i64).wrapping_add(a).wrapping_sub(p);
                    let val = (diff / 4) & 0x3FFFFFF;
                    let off = rel.r_offset as usize;
                    if merged.data.len() < off + 4 {
                        return Err(format!("relocation offset {} out of bounds", rel.r_offset));
                    }
                    let insn = read_u32_le(&merged.data, off);
                    let patched = (insn & 0xFC000000) | (val as u32);
                    write_u32_le(&mut merged.data, off, patched);
                }
                _ => {
                    return Err(format!("unsupported AArch64 relocation type {}", rel.r_type));
                }
            }
        }
    }

    Ok(())
}
