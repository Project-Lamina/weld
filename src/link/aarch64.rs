//! AArch64 relocation application.
//!
//! Static relocations for ABS, PREL, MOVW absolute, PC-relative branch and
//! address forms, page-offset loads and stores, and CALL/JUMP26. GOT and TLS
//! relocations are not handled.

use crate::collections::HashMap;
use crate::{
    elf::{SectionHeader, parse_rela_section, reloc_type},
    link::MergedLayout,
};

fn read_u32_le(buf: &[u8], off: usize) -> Result<u32, String> {
    let bytes = buf
        .get(off..off + 4)
        .ok_or_else(|| format!("relocation offset {off} out of bounds"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_bytes(buf: &mut [u8], off: usize, len: usize, val: u64) -> Result<(), String> {
    let dst = buf
        .get_mut(off..off + len)
        .ok_or_else(|| format!("relocation offset {off} out of bounds"))?;
    dst.copy_from_slice(&val.to_le_bytes()[..len]);
    Ok(())
}

fn patch_insn(buf: &mut [u8], off: usize, f: impl FnOnce(u32) -> u32) -> Result<(), String> {
    let insn = read_u32_le(buf, off)?;
    write_bytes(buf, off, 4, f(insn) as u64)
}

fn fits_signed(v: i64, bits: u32) -> bool {
    let lim = 1i64 << (bits - 1);
    (-lim..lim).contains(&v)
}

fn check_signed(v: i64, bits: u32, what: &str) -> Result<(), String> {
    if fits_signed(v, bits) {
        Ok(())
    } else {
        Err(format!("{what} out of range: {v}"))
    }
}

fn check_unsigned(v: u64, bits: u32, what: &str) -> Result<(), String> {
    if bits >= 64 || v >> bits == 0 {
        Ok(())
    } else {
        Err(format!("{what} out of range: {v:#x}"))
    }
}

fn page4k(x: u64) -> u64 {
    x & !0xFFF
}

/// Apply all AArch64 `SHT_RELA` relocations from `data` into `layout`.
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
    section_offset: Option<&HashMap<String, u64>>,
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
            let sym = || -> Result<i64, String> {
                match symbol_addrs.get(rel.r_sym as usize) {
                    Some(Some(s)) => Ok(s.wrapping_add_signed(a) as i64),
                    _ => Err(format!("undefined symbol index {}", rel.r_sym)),
                }
            };
            let buf = &mut merged.data;

            match rel.r_type {
                reloc_type::R_AARCH64_NONE => {}
                reloc_type::R_AARCH64_RELATIVE => {
                    let val = (merged.vaddr as i64).wrapping_add(a) as u64;
                    write_bytes(buf, off, 8, val)?;
                }
                reloc_type::R_AARCH64_ABS64 => {
                    write_bytes(buf, off, 8, sym()? as u64)?;
                }
                reloc_type::R_AARCH64_ABS32 => {
                    let v = sym()? as u64;
                    check_unsigned(v, 32, "R_AARCH64_ABS32")?;
                    write_bytes(buf, off, 4, v)?;
                }
                reloc_type::R_AARCH64_ABS16 => {
                    let v = sym()? as u64;
                    check_unsigned(v, 16, "R_AARCH64_ABS16")?;
                    write_bytes(buf, off, 2, v)?;
                }
                reloc_type::R_AARCH64_PREL64 => {
                    write_bytes(buf, off, 8, (sym()? - p) as u64)?;
                }
                reloc_type::R_AARCH64_PREL32 => {
                    let v = sym()? - p;
                    check_signed(v, 32, "R_AARCH64_PREL32")?;
                    write_bytes(buf, off, 4, v as u64)?;
                }
                reloc_type::R_AARCH64_PREL16 => {
                    let v = sym()? - p;
                    check_signed(v, 16, "R_AARCH64_PREL16")?;
                    write_bytes(buf, off, 2, v as u64)?;
                }
                reloc_type::R_AARCH64_MOVW_UABS_G0
                | reloc_type::R_AARCH64_MOVW_UABS_G1
                | reloc_type::R_AARCH64_MOVW_UABS_G2
                | reloc_type::R_AARCH64_MOVW_UABS_G3 => {
                    let shift = movw_shift(rel.r_type);
                    let v = sym()? as u64;
                    check_unsigned(v >> shift, 16, "R_AARCH64_MOVW_UABS")?;
                    patch_insn(buf, off, |i| patch_imm16(i, (v >> shift) as u32))?;
                }
                reloc_type::R_AARCH64_MOVW_UABS_G0_NC
                | reloc_type::R_AARCH64_MOVW_UABS_G1_NC
                | reloc_type::R_AARCH64_MOVW_UABS_G2_NC => {
                    let shift = movw_shift(rel.r_type);
                    let v = sym()? as u64;
                    patch_insn(buf, off, |i| patch_imm16(i, ((v >> shift) & 0xFFFF) as u32))?;
                }
                reloc_type::R_AARCH64_ADD_ABS_LO12_NC => {
                    let v = (sym()? as u64 & 0xFFF) as u32;
                    patch_insn(buf, off, |i| patch_imm12(i, v))?;
                }
                reloc_type::R_AARCH64_LDST8_ABS_LO12_NC => {
                    let v = (sym()? as u64 & 0xFFF) as u32;
                    patch_insn(buf, off, |i| patch_imm12(i, v))?;
                }
                reloc_type::R_AARCH64_LDST16_ABS_LO12_NC => {
                    let v = ((sym()? as u64 & 0xFFF) >> 1) as u32;
                    patch_insn(buf, off, |i| patch_imm12(i, v))?;
                }
                reloc_type::R_AARCH64_LDST32_ABS_LO12_NC => {
                    let v = ((sym()? as u64 & 0xFFF) >> 2) as u32;
                    patch_insn(buf, off, |i| patch_imm12(i, v))?;
                }
                reloc_type::R_AARCH64_LDST64_ABS_LO12_NC => {
                    let v = ((sym()? as u64 & 0xFFF) >> 3) as u32;
                    patch_insn(buf, off, |i| patch_imm12(i, v))?;
                }
                reloc_type::R_AARCH64_LDST128_ABS_LO12_NC => {
                    let v = ((sym()? as u64 & 0xFFF) >> 4) as u32;
                    patch_insn(buf, off, |i| patch_imm12(i, v))?;
                }
                reloc_type::R_AARCH64_ADR_PREL_LO21 => {
                    let diff = sym()? - p;
                    check_signed(diff, 21, "R_AARCH64_ADR_PREL_LO21")?;
                    patch_insn(buf, off, |i| patch_adr_imm21(i, diff))?;
                }
                reloc_type::R_AARCH64_ADR_PREL_PG_HI21 => {
                    let pages = (page4k(sym()? as u64) as i64 - page4k(place) as i64) >> 12;
                    if !fits_signed(pages, 21) {
                        return Err(format!(
                            "R_AARCH64_ADR_PREL_PG_HI21 out of range: {pages} pages"
                        ));
                    }
                    patch_insn(buf, off, |i| patch_adr_imm21(i, pages))?;
                }
                reloc_type::R_AARCH64_ADR_PREL_PG_HI21_NC => {
                    let pages = (page4k(sym()? as u64) as i64 - page4k(place) as i64) >> 12;
                    patch_insn(buf, off, |i| patch_adr_imm21(i, pages))?;
                }
                reloc_type::R_AARCH64_LD_PREL_LO19 | reloc_type::R_AARCH64_CONDBR19 => {
                    let diff = sym()? - p;
                    check_word_branch(diff, 19, "R_AARCH64_CONDBR19")?;
                    patch_insn(buf, off, |i| patch_field(i, 5, 19, (diff >> 2) as u32))?;
                }
                reloc_type::R_AARCH64_TSTBR14 => {
                    let diff = sym()? - p;
                    check_word_branch(diff, 14, "R_AARCH64_TSTBR14")?;
                    patch_insn(buf, off, |i| patch_field(i, 5, 14, (diff >> 2) as u32))?;
                }
                reloc_type::R_AARCH64_CALL26 | reloc_type::R_AARCH64_JUMP26 => {
                    let diff = sym()? - p;
                    check_word_branch(diff, 26, "R_AARCH64_CALL26")?;
                    patch_insn(buf, off, |i| patch_field(i, 0, 26, (diff >> 2) as u32))?;
                }
                _ => {
                    return Err(format!(
                        "unsupported AArch64 relocation type {}",
                        rel.r_type
                    ));
                }
            }
        }
    }

    Ok(())
}

fn movw_shift(r_type: u32) -> u32 {
    match r_type {
        reloc_type::R_AARCH64_MOVW_UABS_G0 | reloc_type::R_AARCH64_MOVW_UABS_G0_NC => 0,
        reloc_type::R_AARCH64_MOVW_UABS_G1 | reloc_type::R_AARCH64_MOVW_UABS_G1_NC => 16,
        reloc_type::R_AARCH64_MOVW_UABS_G2 | reloc_type::R_AARCH64_MOVW_UABS_G2_NC => 32,
        _ => 48,
    }
}

fn check_word_branch(diff: i64, bits: u32, what: &str) -> Result<(), String> {
    if diff & 3 != 0 {
        return Err(format!("{what} target is not 4-byte aligned: {diff}"));
    }
    check_signed(diff, bits + 2, what)
}

/// Write `value` into the `width`-bit field starting at bit `lsb`.
fn patch_field(insn: u32, lsb: u32, width: u32, value: u32) -> u32 {
    let mask = ((1u32 << width) - 1) << lsb;
    (insn & !mask) | ((value << lsb) & mask)
}

fn patch_imm16(insn: u32, value: u32) -> u32 {
    patch_field(insn, 5, 16, value & 0xFFFF)
}

fn patch_imm12(insn: u32, value: u32) -> u32 {
    patch_field(insn, 10, 12, value & 0xFFF)
}

/// ADR takes a byte delta and ADRP a page delta; both are a 21-bit immediate
/// split into immlo at bits 29-30 and immhi at bits 5-23.
fn patch_adr_imm21(insn: u32, imm: i64) -> u32 {
    let val = (imm as u32) & 0x1FFFFF;
    (insn & 0x9F00001F) | ((val & 3) << 29) | (((val >> 2) & 0x7FFFF) << 5)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recover the signed page count an ADRP encodes.
    fn decode_pages(insn: u32) -> i64 {
        let val = ((insn >> 29) & 3) | (((insn >> 5) & 0x7FFFF) << 2);
        ((val << 11) as i32 >> 11) as i64
    }

    #[test]
    fn adrp_encodes_pages_not_bytes() {
        let insn = 0x9000_0000;
        for pages in [0i64, 1, 2, -1, 1023, -1024] {
            let patched = patch_adr_imm21(insn, pages);
            assert_eq!(decode_pages(patched), pages, "for {pages} pages");
        }
        assert_eq!(patch_adr_imm21(insn, 1), 0xB000_0000);
    }

    #[test]
    fn movw_patches_the_16_bit_field() {
        let movz = 0xD280_0000;
        assert_eq!(patch_imm16(movz, 0x1234), 0xD282_4680);
        assert_eq!(patch_imm16(movz, 0x1_1234), 0xD282_4680);
    }

    #[test]
    fn conditional_branch_takes_a_word_offset() {
        let b_eq_back_two_words = 0x5400_0000;
        let patched = patch_field(b_eq_back_two_words, 5, 19, (-8i64 >> 2) as u32);
        assert_eq!(patched, 0x54FF_FFC0);
    }

    #[test]
    fn word_branch_rejects_unaligned_and_far_targets() {
        assert!(check_word_branch(6, 26, "t").is_err());
        assert!(check_word_branch(1 << 28, 26, "t").is_err());
        assert!(check_word_branch(-(1 << 27), 26, "t").is_ok());
    }
}
