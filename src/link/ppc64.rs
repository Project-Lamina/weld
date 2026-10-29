//! PowerPC64 (ELFv2) relocation application.
//!
//! Handles REL24 branches, REL16 HA/LO address pairs and TOC16 HA/LO. Every
//! object shares the one `.TOC.` the linker defines, so a call to a symbol with
//! a local entry point lands past its TOC setup prologue.

use crate::{
    elf::parse_rela_section,
    link::{MergedLayout, RelocInputs},
};

const R_PPC64_NONE: u32 = 0;
const R_PPC64_REL24: u32 = 10;
const R_PPC64_TOC16_LO: u32 = 48;
const R_PPC64_TOC16_HA: u32 = 50;
const R_PPC64_REL16_LO: u32 = 250;
const R_PPC64_REL16_HA: u32 = 252;

const SHT_RELA: u32 = 4;

fn ha16(v: i64) -> u64 {
    ((v + 0x8000) >> 16) as u64 & 0xFFFF
}

fn lo16(v: i64) -> u64 {
    v as u64 & 0xFFFF
}

fn check_32(v: i64, what: &str) -> Result<(), String> {
    if i32::try_from(v).is_ok() {
        Ok(())
    } else {
        Err(format!("{what} out of range: {v}"))
    }
}

fn read_insn(buf: &[u8], off: usize) -> Result<u32, String> {
    let bytes = buf
        .get(off..off + 4)
        .ok_or_else(|| format!("relocation offset {off} out of bounds"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_insn(buf: &mut [u8], off: usize, insn: u32) -> Result<(), String> {
    let bytes = buf
        .get_mut(off..off + 4)
        .ok_or_else(|| format!("relocation offset {off} out of bounds"))?;
    bytes.copy_from_slice(&insn.to_le_bytes());
    Ok(())
}

fn patch_immediate(buf: &mut [u8], off: usize, field: u64) -> Result<(), String> {
    let insn = read_insn(buf, off)?;
    write_insn(buf, off, (insn & 0xFFFF_0000) | field as u32)
}

fn patch_branch(buf: &mut [u8], off: usize, disp: i64) -> Result<(), String> {
    if disp & 3 != 0 || !(-(1 << 25)..(1 << 25)).contains(&disp) {
        return Err(format!("R_PPC64_REL24 out of range or misaligned: {disp}"));
    }
    let insn = read_insn(buf, off)?;
    write_insn(
        buf,
        off,
        (insn & !0x03FF_FFFC) | (disp as u32 & 0x03FF_FFFC),
    )
}

/// Apply all PowerPC64 `SHT_RELA` relocations from `data` into `layout`.
///
/// `inputs.symbol_addrs[i]` is the resolved address of ELF symbol index `i`, or
/// `None` if undefined. `inputs.toc` is the value of `.TOC.`, and
/// `inputs.local_entries` maps the address of each defined symbol with a local
/// entry point to that offset.
pub fn apply_relocations(
    layout: &mut MergedLayout,
    inputs: &RelocInputs<'_>,
) -> Result<(), String> {
    let RelocInputs {
        data,
        sections,
        names,
        symbol_addrs,
        section_offset,
        toc,
        local_entries,
        ..
    } = *inputs;
    let toc = toc as i64;

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
            let p = (merged.vaddr + off as u64) as i64;
            let addend = rel.r_addend;
            let sym = || -> Result<i64, String> {
                match symbol_addrs.get(rel.r_sym as usize) {
                    Some(Some(s)) => Ok(s.wrapping_add_signed(addend) as i64),
                    _ => Err(format!("undefined symbol index {}", rel.r_sym)),
                }
            };
            let buf = &mut merged.data;

            match rel.r_type {
                R_PPC64_NONE => {}
                R_PPC64_REL24 => {
                    let base = match symbol_addrs.get(rel.r_sym as usize) {
                        Some(Some(s)) => *s,
                        _ => return Err(format!("undefined symbol index {}", rel.r_sym)),
                    };
                    let entry = local_entries.get(&base).copied().unwrap_or(0);
                    let target = base.wrapping_add_signed(addend).wrapping_add(entry) as i64;
                    patch_branch(buf, off, target - p)?;
                }
                R_PPC64_REL16_LO => patch_immediate(buf, off, lo16(sym()? - p))?,
                R_PPC64_REL16_HA => {
                    let v = sym()? - p;
                    check_32(v, "R_PPC64_REL16_HA")?;
                    patch_immediate(buf, off, ha16(v))?;
                }
                R_PPC64_TOC16_LO => patch_immediate(buf, off, lo16(sym()? - toc))?,
                R_PPC64_TOC16_HA => {
                    let v = sym()? - toc;
                    check_32(v, "R_PPC64_TOC16_HA")?;
                    patch_immediate(buf, off, ha16(v))?;
                }
                other => return Err(format!("unsupported PowerPC64 relocation type {other}")),
            }
        }
    }
    Ok(())
}
