//! x86_64 relocation application.

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
/// `leaq x@tlsld(%rip),%rdi`, the three bytes before the displacement.
const LD_LEA: [u8; 3] = [0x48, 0x8d, 0x3d];
/// The whole local-dynamic sequence, `lea` then `call __tls_get_addr`, is twelve bytes.
const LD_SEQUENCE: usize = 12;
/// What those twelve bytes become in local exec: three `data16` prefixes padding out
/// `movq %fs:0,%rax`, which leaves the thread pointer in `%rax` for the `@dtpoff`
/// operands that follow. The x86-64 psABI gives this replacement.
const LE_LD_MOV_FS: [u8; LD_SEQUENCE] =
    [0x66, 0x66, 0x66, 0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0];

/// The local-dynamic TLS sites in `target`, as indices of the `lea` and its
/// `__tls_get_addr` call in `relas`.
///
/// A site is the twelve-byte `leaq x@tlsld(%rip),%rdi` plus `call __tls_get_addr@PLT`
/// pair. An executable has one module, so the call cannot return anything but this
/// module's thread pointer, and the pair relaxes to local exec exactly as the
/// general-dynamic one does.
fn local_dynamic_sites(
    data: &[u8],
    sections: &[SectionHeader],
    target: &SectionHeader,
    relas: &[RelaEntry],
) -> Result<Vec<(usize, usize)>, String> {
    if !relas
        .iter()
        .any(|rel| rel.r_type == reloc_type::R_X86_64_TLSLD)
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
        .filter(|(_, rel)| rel.r_type == reloc_type::R_X86_64_TLSLD)
    {
        let start = rel
            .r_offset
            .checked_sub(LD_LEA.len() as u64)
            .and_then(|start| usize::try_from(start).ok());
        let is_sequence = start
            .and_then(|start| code.get(start..start + LD_SEQUENCE))
            .is_some_and(|bytes| bytes[..LD_LEA.len()] == LD_LEA && bytes[7] == 0xe8);
        if !is_sequence {
            return Err(format!(
                "local dynamic TLS at offset {} is not a __tls_get_addr call sequence",
                rel.r_offset
            ));
        }
        // The call's displacement sits five bytes past the `lea`'s, but rather than
        // pin that, take the one __tls_get_addr call inside this twelve-byte sequence.
        let sequence = rel.r_offset - LD_LEA.len() as u64
            ..rel.r_offset - LD_LEA.len() as u64 + LD_SEQUENCE as u64;
        let call = relas
            .iter()
            .position(|other| {
                sequence.contains(&other.r_offset)
                    && other.r_type == reloc_type::R_X86_64_PLT32
                    && names.get(other.r_sym as usize).map(|n| n.as_ref()) == Some(TLS_GET_ADDR)
            })
            .ok_or_else(|| {
                format!(
                    "local dynamic TLS at offset {} has no __tls_get_addr call relocation",
                    rel.r_offset
                )
            })?;
        sites.push((lea, call));
    }
    Ok(sites)
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
        // Debug sections name code that `--gc-sections` may have taken away. A reader
        // takes address zero for something that is not in the image, so an unresolved
        // symbol becomes zero here rather than failing the link.
        let tombstoned: Option<Vec<Option<u64>>> = super::merge::is_debug_section(&target_name)
            .then(|| {
                symbol_addrs
                    .iter()
                    .map(|addr| Some(addr.unwrap_or(0)))
                    .collect()
            });
        let symbol_addrs = tombstoned.as_deref().unwrap_or(symbol_addrs);
        let merged = &mut layout.sections[merged_idx];
        // A section that contributed nothing to the merge has nothing to relocate.
        // Taking zero for its offset would apply its relocations over whichever object
        // does start the merged section.
        let data_off = match section_offset {
            Some(offsets) => match offsets.get(&target_name) {
                Some(&offset) => offset as usize,
                None => continue,
            },
            None => 0,
        };
        let relas = parse_rela_section(data, rela_sh)?;
        let gd_sites = general_dynamic_sites(data, sections, target_sh, &relas)?;
        let ld_sites = local_dynamic_sites(data, sections, target_sh, &relas)?;
        let gd_leas: HashSet<usize> = gd_sites.iter().map(|&(lea, _)| lea).collect();
        let ld_leas: HashSet<usize> = ld_sites.iter().map(|&(lea, _)| lea).collect();
        let relaxed_calls: HashSet<usize> = gd_sites
            .iter()
            .chain(ld_sites.iter())
            .map(|&(_, call)| call)
            .collect();

        for (index, rel) in relas.iter().enumerate() {
            if relaxed_calls.contains(&index) {
                continue;
            }
            let off = usize::try_from(rel.r_offset)
                .ok()
                .and_then(|r| data_off.checked_add(r))
                .filter(|&off| off <= merged.data.len())
                .ok_or_else(|| {
                    format!(
                        "relocation offset {} out of bounds in section {target_name}",
                        rel.r_offset
                    )
                })?;
            let place = merged.vaddr + off as u64;
            let a = rel.r_addend;
            let p = place as i64;

            match rel.r_type {
                reloc_type::R_X86_64_NONE => {}
                reloc_type::R_X86_64_RELATIVE => {
                    let base = merged.vaddr as i64;
                    let val = base.wrapping_add(a) as u64;
                    if merged.data.len() < off + 8 {
                        return Err(format!(
                            "relocation offset {} out of bounds in section {target_name}",
                            rel.r_offset
                        ));
                    }
                    write_u64_le(&mut merged.data, off, val);
                }
                reloc_type::R_X86_64_64 | 6 => {
                    let Some(Some(s_addr)) = symbol_addrs.get(rel.r_sym as usize) else {
                        return Err(format!("undefined symbol index {}", rel.r_sym));
                    };
                    let val = s_addr.wrapping_add_signed(a);
                    if merged.data.len() < off + 8 {
                        return Err(format!(
                            "relocation offset {} out of bounds in section {target_name}",
                            rel.r_offset
                        ));
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
                        return Err(format!(
                            "relocation offset {} out of bounds in section {target_name}",
                            rel.r_offset
                        ));
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
                        return Err(format!(
                            "relocation offset {} out of bounds in section {target_name}",
                            rel.r_offset
                        ));
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
                        return Err(format!(
                            "relocation offset {} out of bounds in section {target_name}",
                            rel.r_offset
                        ));
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
                        return Err(format!(
                            "relocation offset {} out of bounds in section {target_name}",
                            rel.r_offset
                        ));
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
                reloc_type::R_X86_64_TLSLD if ld_leas.contains(&index) => {
                    // The sequence loads the thread pointer and nothing else; the
                    // `@dtpoff` operands after it carry the offsets.
                    let start = off - LD_LEA.len();
                    if merged.data.len() < start + LD_SEQUENCE {
                        return Err(format!(
                            "relocation offset {} out of bounds in section {target_name}",
                            rel.r_offset
                        ));
                    }
                    merged.data[start..start + LD_SEQUENCE].copy_from_slice(&LE_LD_MOV_FS);
                }
                reloc_type::R_X86_64_DTPOFF32 => {
                    // After the sequence above, the operand is read from the thread
                    // pointer, so an offset within the module's block becomes the same
                    // local-exec offset `@tpoff` would have given.
                    let Some(Some(s_addr)) = symbol_addrs.get(rel.r_sym as usize) else {
                        return Err(format!("undefined symbol index {}", rel.r_sym));
                    };
                    let tp_offset = local_exec_offset(tls.as_ref(), *s_addr, a)?;
                    let value = i32::try_from(tp_offset).map_err(|_| {
                        format!("R_X86_64_DTPOFF32 value {tp_offset} does not fit in i32")
                    })?;
                    if merged.data.len() < off + 4 {
                        return Err(format!(
                            "relocation offset {} out of bounds in section {target_name}",
                            rel.r_offset
                        ));
                    }
                    write_u32_le(&mut merged.data, off, value as u32);
                }
                reloc_type::R_X86_64_TLSGD | reloc_type::R_X86_64_TLSLD => {
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

/// True when every relocation against `__tls_get_addr` in `data` belongs to a dynamic
/// TLS sequence that is relaxed away, so the undefined symbol is never reached.
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
            .chain(local_dynamic_sites(data, sections, target, &relas)?)
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
