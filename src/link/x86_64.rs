//! x86_64 relocation application.

use super::SHF_ALLOC;
use super::merge::tls_segment;
use super::symbols::symbol_names_by_index;
use crate::collections::{HashMap, HashSet};
use crate::elf::reloc_type;
use crate::elf::{RelaEntry, SectionHeader, parse_rela_section};
use crate::link::MergedLayout;

const TLS_GET_ADDR: &str = "__tls_get_addr";
const GD_LEA: [u8; 4] = [0x66, 0x48, 0x8d, 0x3d];
const GD_CALL: [u8; 4] = [0x66, 0x66, 0x48, 0xe8];
const LE_MOV_FS: [u8; 9] = [0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0];
const LE_LEA_RAX: [u8; 3] = [0x48, 0x8d, 0x80];

/// Rejects local-dynamic TLS, which needs a module-wide `__tls_get_addr` block
/// that relaxation cannot replace.
pub(super) fn reject_local_dynamic_tls(
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
                reloc_type::R_X86_64_TLSLD => "R_X86_64_TLSLD",
                reloc_type::R_X86_64_DTPOFF32 => "R_X86_64_DTPOFF32",
                _ => continue,
            };
            let section = names
                .get(rela_sh.sh_info as usize)
                .map_or("?", String::as_str);
            return Err(format!(
                "local dynamic TLS is not supported ({kind} in section {section}); use -ftls-model=global-dynamic or local-exec"
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
        let Some(target_sh) = sections.get(target_section_idx) else {
            continue;
        };
        let merged = &mut layout.sections[merged_idx];
        let data_off = section_offset
            .and_then(|m| m.get(&target_name).copied())
            .unwrap_or(0) as usize;
        let relas = parse_rela_section(data, rela_sh)?;
        let gd_sites = general_dynamic_sites(data, sections, target_sh, &relas)?;
        let gd_leas: HashSet<usize> = gd_sites.iter().map(|&(lea, _)| lea).collect();
        let gd_calls: HashSet<usize> = gd_sites.iter().map(|&(_, call)| call).collect();

        for (index, rel) in relas.iter().enumerate() {
            if gd_calls.contains(&index) {
                continue;
            }
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
                reloc_type::R_X86_64_TLSGD if gd_leas.contains(&index) => {
                    let Some(Some(s_addr)) = symbol_addrs.get(rel.r_sym as usize) else {
                        return Err(format!("undefined symbol index {}", rel.r_sym));
                    };
                    let tp_offset = i32::try_from(local_exec_offset(tls.as_ref(), *s_addr, 0)?)
                        .map_err(|_| {
                            "R_X86_64_TLSGD local-exec offset does not fit in i32".to_string()
                        })?;
                    let start = off - 4;
                    if merged.data.len() < start + 16 {
                        return Err(format!("relocation offset {} out of bounds", rel.r_offset));
                    }
                    merged.data[start..start + 9].copy_from_slice(&LE_MOV_FS);
                    merged.data[start + 9..start + 12].copy_from_slice(&LE_LEA_RAX);
                    merged.data[start + 12..start + 16].copy_from_slice(&tp_offset.to_le_bytes());
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

/// General-dynamic call sites in one relocation section, as `(tlsgd, call)` indices
/// into `relas`. A site is the 16-byte `lea x@tlsgd(%rip),%rdi` plus
/// `call __tls_get_addr@PLT` pair, which the linker relaxes to local-exec.
fn general_dynamic_sites(
    data: &[u8],
    sections: &[SectionHeader],
    target: &SectionHeader,
    relas: &[RelaEntry],
) -> Result<Vec<(usize, usize)>, String> {
    if !relas
        .iter()
        .any(|rel| rel.r_type == reloc_type::R_X86_64_TLSGD)
    {
        return Ok(Vec::new());
    }
    let names = symbol_names_by_index(data, sections)?;
    let code = data
        .get(target.sh_offset as usize..(target.sh_offset + target.sh_size) as usize)
        .unwrap_or(&[]);
    let mut sites = Vec::new();
    for (lea, rel) in relas
        .iter()
        .enumerate()
        .filter(|(_, rel)| rel.r_type == reloc_type::R_X86_64_TLSGD)
    {
        let start = rel
            .r_offset
            .checked_sub(4)
            .and_then(|start| usize::try_from(start).ok());
        let is_sequence = start
            .and_then(|start| code.get(start..start + 16))
            .is_some_and(|bytes| bytes[..4] == GD_LEA && bytes[8..12] == GD_CALL);
        if !is_sequence {
            return Err(format!(
                "general dynamic TLS at offset {} is not a __tls_get_addr call sequence",
                rel.r_offset
            ));
        }
        let call = relas
            .iter()
            .position(|other| {
                other.r_offset == rel.r_offset + 8
                    && other.r_type == reloc_type::R_X86_64_PLT32
                    && other.r_addend == -4
                    && names.get(other.r_sym as usize).map(|n| n.as_ref()) == Some(TLS_GET_ADDR)
            })
            .ok_or_else(|| {
                format!(
                    "general dynamic TLS at offset {} has no __tls_get_addr call relocation",
                    rel.r_offset
                )
            })?;
        sites.push((lea, call));
    }
    Ok(sites)
}

/// True when every relocation against `__tls_get_addr` in `data` is a general-dynamic
/// call that is relaxed away, so the undefined symbol is never reached.
pub(super) fn tls_get_addr_only_relaxed(
    data: &[u8],
    sections: &[SectionHeader],
) -> Result<bool, String> {
    const SHT_RELA: u32 = 4;
    let names = symbol_names_by_index(data, sections)?;
    let (mut total, mut relaxed) = (0usize, 0usize);
    for rela_sh in sections.iter().filter(|s| s.sh_type == SHT_RELA) {
        let Some(target) = sections.get(rela_sh.sh_info as usize) else {
            continue;
        };
        let relas = parse_rela_section(data, rela_sh)?;
        let calls: HashSet<usize> = general_dynamic_sites(data, sections, target, &relas)?
            .into_iter()
            .map(|(_, call)| call)
            .collect();
        for (index, rel) in relas.iter().enumerate() {
            if names.get(rel.r_sym as usize).map(|n| n.as_ref()) == Some(TLS_GET_ADDR) {
                total += 1;
                relaxed += usize::from(calls.contains(&index));
            }
        }
    }
    Ok(total == relaxed)
}
