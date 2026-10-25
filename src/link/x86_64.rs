//! x86_64 relocation application.

use super::SHF_ALLOC;
use super::merge::tls_segment;
use crate::collections::HashMap;
use crate::elf::reloc_type;
use crate::elf::{SectionHeader, parse_rela_section};
use crate::link::MergedLayout;

/// Rejects relocations of the general-dynamic TLS model, which needs
/// `__tls_get_addr` and dynamic TLS that weld does not provide.
pub(super) fn reject_general_dynamic_tls(
    data: &[u8],
    sections: &[SectionHeader],
    names: &[String],
) -> Result<(), String> {
    const SHT_RELA: u32 = 4;
    for rela_sh in sections.iter().filter(|s| s.sh_type == SHT_RELA) {
        let Some(target) = sections.get(rela_sh.sh_info as usize) else {
            continue;
        };
        if target.sh_flags & SHF_ALLOC == 0 {
            continue;
        }
        for rel in parse_rela_section(data, rela_sh)? {
            let kind = match rel.r_type {
                reloc_type::R_X86_64_TLSGD => "R_X86_64_TLSGD",
                reloc_type::R_X86_64_TLSLD => "R_X86_64_TLSLD",
                reloc_type::R_X86_64_DTPOFF32 => "R_X86_64_DTPOFF32",
                _ => continue,
            };
            let section = names
                .get(rela_sh.sh_info as usize)
                .map_or("?", String::as_str);
            return Err(format!(
                "general dynamic TLS is not supported ({kind} in section {section}); only the initial-exec and local-exec models are planned"
            ));
        }
    }
    Ok(())
}

fn write_u32_le(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn write_u64_le(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
}

fn pc_relative_field(displacement: i64, r_type: u32) -> Result<u32, String> {
    i32::try_from(displacement)
        .map(|value| value as u32)
        .map_err(|_| {
            format!("relocation type {r_type} displacement {displacement} does not fit in i32")
        })
}

/// Thread-pointer offset of a thread-local symbol at `address + addend`. On x86_64
/// the thread pointer sits just past the static TLS block, so offsets are negative.
pub(super) fn local_exec_offset(
    tls: Option<&super::merge::TlsSegment>,
    address: u64,
    addend: i64,
) -> Result<i64, String> {
    let tls = tls.ok_or("thread-local relocation without a thread-local block")?;
    let block = tls.memsz.div_ceil(tls.align) * tls.align;
    let target = i128::from(address) + i128::from(addend) - i128::from(tls.vaddr);
    i64::try_from(target - i128::from(block)).map_err(|_| "thread-local offset overflows".into())
}

/// Apply all x86_64 `SHT_RELA` relocations from `data` into `layout`.
///
/// `symbol_addrs[i]` is the resolved virtual address of ELF symbol index `i`,
/// or `None` for an undefined symbol. `got_entries[i]` is the vaddr of the
/// `.got` slot for symbol `i`, used for `R_X86_64_GOTPCREL`. `section_offset`
/// maps each section name to its byte offset within the merged section.
pub fn apply_relocations(
    layout: &mut MergedLayout,
    data: &[u8],
    sections: &[SectionHeader],
    names: &[String],
    symbol_addrs: &[Option<u64>],
    got_entries: &[Option<u64>],
    section_offset: Option<&HashMap<String, u64>>,
) -> Result<(), String> {
    const SHT_RELA: u32 = 4;
    let tls = tls_segment(layout)?;

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
            let off = usize::try_from(rel.r_offset)
                .ok()
                .and_then(|r| data_off.checked_add(r))
                .filter(|&off| off <= merged.data.len())
                .ok_or_else(|| format!("relocation offset {} out of bounds", rel.r_offset))?;
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
                reloc_type::R_X86_64_64 | 6 => {
                    let Some(Some(s_addr)) = symbol_addrs.get(rel.r_sym as usize) else {
                        return Err(format!("undefined symbol index {}", rel.r_sym));
                    };
                    let val = s_addr.wrapping_add_signed(a);
                    if merged.data.len() < off + 8 {
                        return Err(format!("relocation offset {} out of bounds", rel.r_offset));
                    }
                    write_u64_le(&mut merged.data, off, val);
                }
                reloc_type::R_X86_64_32 | reloc_type::R_X86_64_32S => {
                    let Some(Some(s_addr)) = symbol_addrs.get(rel.r_sym as usize) else {
                        return Err(format!("undefined symbol index {}", rel.r_sym));
                    };
                    let full = s_addr.wrapping_add_signed(a);
                    if rel.r_type == reloc_type::R_X86_64_32S {
                        let signed = full as i64;
                        if signed < i64::from(i32::MIN) || signed > i64::from(i32::MAX) {
                            return Err(format!("R_X86_64_32S value {signed} does not fit in i32"));
                        }
                    } else if full > u64::from(u32::MAX) {
                        return Err(format!("R_X86_64_32 value {full} does not fit in u32"));
                    }
                    if merged.data.len() < off + 4 {
                        return Err(format!("relocation offset {} out of bounds", rel.r_offset));
                    }
                    write_u32_le(&mut merged.data, off, full as u32);
                }
                reloc_type::R_X86_64_PC32 | reloc_type::R_X86_64_PLT32 => {
                    let Some(Some(s_addr)) = symbol_addrs.get(rel.r_sym as usize) else {
                        return Err(format!("undefined symbol index {}", rel.r_sym));
                    };
                    let val = pc_relative_field(
                        (*s_addr as i64).wrapping_add(a).wrapping_sub(p),
                        rel.r_type,
                    )?;
                    if merged.data.len() < off + 4 {
                        return Err(format!("relocation offset {} out of bounds", rel.r_offset));
                    }
                    write_u32_le(&mut merged.data, off, val);
                }
                reloc_type::R_X86_64_GOTPCREL
                | reloc_type::R_X86_64_GOTPCRELX
                | reloc_type::R_X86_64_REX_GOTPCRELX
                | reloc_type::R_X86_64_GOTTPOFF => {
                    let got_entry_vaddr = got_entries
                        .get(rel.r_sym as usize)
                        .copied()
                        .flatten()
                        .ok_or_else(|| {
                            format!("no GOT entry for symbol index {} (GOTPCREL)", rel.r_sym)
                        })?;
                    let val = pc_relative_field(
                        (got_entry_vaddr as i64).wrapping_add(a).wrapping_sub(p),
                        rel.r_type,
                    )?;
                    if merged.data.len() < off + 4 {
                        return Err(format!("relocation offset {} out of bounds", rel.r_offset));
                    }
                    write_u32_le(&mut merged.data, off, val);
                }
                reloc_type::R_X86_64_TPOFF32 | reloc_type::R_X86_64_TPOFF64 => {
                    let Some(Some(s_addr)) = symbol_addrs.get(rel.r_sym as usize) else {
                        return Err(format!("undefined symbol index {}", rel.r_sym));
                    };
                    let tp_offset = local_exec_offset(tls.as_ref(), *s_addr, a)?;
                    if rel.r_type == reloc_type::R_X86_64_TPOFF64 {
                        if merged.data.len() < off + 8 {
                            return Err(format!(
                                "relocation offset {} out of bounds",
                                rel.r_offset
                            ));
                        }
                        write_u64_le(&mut merged.data, off, tp_offset as u64);
                    } else {
                        let value = i32::try_from(tp_offset).map_err(|_| {
                            format!("R_X86_64_TPOFF32 value {tp_offset} does not fit in i32")
                        })?;
                        if merged.data.len() < off + 4 {
                            return Err(format!(
                                "relocation offset {} out of bounds",
                                rel.r_offset
                            ));
                        }
                        write_u32_le(&mut merged.data, off, value as u32);
                    }
                }
                reloc_type::R_X86_64_TLSGD
                | reloc_type::R_X86_64_TLSLD
                | reloc_type::R_X86_64_DTPOFF32 => {
                    return Err(format!(
                        "unsupported x86_64 TLS relocation type {}",
                        rel.r_type
                    ));
                }
                _ => {
                    return Err(format!("unsupported x86_64 relocation type {}", rel.r_type));
                }
            }
        }
    }

    Ok(())
}
