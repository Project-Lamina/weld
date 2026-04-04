//! RISC-V relocation application (ELF psABI).
//!
//! Covers the relocations produced by a standard RISC-V toolchain:
//! absolute, PC-relative, AUIPC+JALR call pairs, and branch/JAL.

use crate::elf::reloc_type;
use crate::elf::{SectionHeader, parse_rela_section};
use crate::link::MergedLayout;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Raw read/write helpers
// ---------------------------------------------------------------------------

fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn write_u32_le(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn write_u64_le(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
}

// ---------------------------------------------------------------------------
// Instruction-level field patching
// ---------------------------------------------------------------------------

/// Patch the 20-bit upper immediate in a U-type instruction (LUI / AUIPC).
/// `imm20` is the value to place in bits [31:12].
fn patch_u_imm20(instr: u32, imm20: i32) -> u32 {
    (instr & 0x0000_0FFF) | ((imm20 as u32 & 0xF_FFFF) << 12)
}

/// Patch the 12-bit immediate in an I-type instruction.
/// `imm12` occupies bits [31:20].
fn patch_i_imm12(instr: u32, imm12: i32) -> u32 {
    (instr & 0x000F_FFFF) | ((imm12 as u32 & 0xFFF) << 20)
}

/// Patch the 12-bit immediate in an S-type instruction.
/// Bits [31:25] = imm[11:5], bits [11:7] = imm[4:0].
fn patch_s_imm12(instr: u32, imm12: i32) -> u32 {
    let imm = imm12 as u32 & 0xFFF;
    (instr & 0x01FF_F07F) | ((imm >> 5) << 25) | ((imm & 0x1F) << 7)
}

/// Patch the 13-bit branch offset in a B-type instruction.
/// Bit layout: [31]=imm[12], [30:25]=imm[10:5], [11:8]=imm[4:1], [7]=imm[11].
fn patch_b_type(instr: u32, offset: i32) -> u32 {
    let o = offset as u32;
    let imm12 = (o >> 12) & 1;
    let imm11 = (o >> 11) & 1;
    let imm10_5 = (o >> 5) & 0x3F;
    let imm4_1 = (o >> 1) & 0xF;
    (instr & 0x01FF_F07F) | (imm12 << 31) | (imm10_5 << 25) | (imm4_1 << 8) | (imm11 << 7)
}

/// Patch the 21-bit JAL offset in a J-type instruction.
/// Bit layout: [31]=imm[20], [30:21]=imm[10:1], [20]=imm[11], [19:12]=imm[19:12].
fn patch_j_type(instr: u32, offset: i32) -> u32 {
    let o = offset as u32;
    let imm20 = (o >> 20) & 1;
    let imm19_12 = (o >> 12) & 0xFF;
    let imm11 = (o >> 11) & 1;
    let imm10_1 = (o >> 1) & 0x3FF;
    (instr & 0x0000_0FFF) | (imm20 << 31) | (imm10_1 << 21) | (imm11 << 20) | (imm19_12 << 12)
}

// ---------------------------------------------------------------------------
// Main relocation handler
// ---------------------------------------------------------------------------

pub fn apply_relocations(
    layout: &mut MergedLayout,
    data: &[u8],
    sections: &[SectionHeader],
    names: &[String],
    symbol_addrs: &[Option<u64>],
    section_offset: Option<&HashMap<String, u64>>,
) -> Result<(), String> {
    const SHT_RELA: u32 = 4;

    // Cache for PCREL_HI20 values keyed by the PC of the AUIPC instruction.
    // PCREL_LO12_I/S relocations reference the symbol of the paired AUIPC,
    // so we record the full PC-relative offset there.
    let mut hi20_cache: HashMap<u64, i64> = HashMap::new();

    for rela_sh in sections.iter() {
        if rela_sh.sh_type != SHT_RELA {
            continue;
        }
        let target_section_idx = rela_sh.sh_info as usize;
        let target_name = names.get(target_section_idx).cloned().unwrap_or_default();
        let Some(&merged_idx) = layout.section_by_name.get(&target_name) else {
            continue;
        };
        let data_off = section_offset
            .and_then(|m| m.get(&target_name).copied())
            .unwrap_or(0) as usize;
        let relas = parse_rela_section(data, rela_sh)?;

        for rel in &relas {
            let off = data_off + rel.r_offset as usize;
            let merged = &layout.sections[merged_idx];
            let place = merged.vaddr + off as u64;
            let a = rel.r_addend;
            let p = place as i64;
            let base = layout.sections[merged_idx].vaddr as i64;

            // Resolve symbol address (may be None for undefined externals).
            let sym_addr: Option<i64> = symbol_addrs
                .get(rel.r_sym as usize)
                .and_then(|o| *o)
                .map(|v| v as i64);

            // Helper: require a defined symbol
            let require_sym = |sym_addr: Option<i64>| -> Result<i64, String> {
                sym_addr.ok_or_else(|| {
                    format!("undefined symbol index {} for RISC-V relocation", rel.r_sym)
                })
            };

            match rel.r_type {
                reloc_type::R_RISCV_NONE => {}

                // Absolute 32-bit: *(u32*)P = S + A
                reloc_type::R_RISCV_32 => {
                    let s = require_sym(sym_addr)?;
                    let val = s.wrapping_add(a) as u32;
                    let merged = &mut layout.sections[merged_idx];
                    if merged.data.len() < off + 4 {
                        return Err(format!("R_RISCV_32: offset {} out of bounds", off));
                    }
                    write_u32_le(&mut merged.data, off, val);
                }

                // Absolute 64-bit: *(u64*)P = S + A
                reloc_type::R_RISCV_64 => {
                    let s = require_sym(sym_addr)?;
                    let val = s.wrapping_add(a) as u64;
                    let merged = &mut layout.sections[merged_idx];
                    if merged.data.len() < off + 8 {
                        return Err(format!("R_RISCV_64: offset {} out of bounds", off));
                    }
                    write_u64_le(&mut merged.data, off, val);
                }

                // Dynamic: *(u64*)P = B + A
                reloc_type::R_RISCV_RELATIVE => {
                    let val = base.wrapping_add(a) as u64;
                    let merged = &mut layout.sections[merged_idx];
                    if merged.data.len() < off + 8 {
                        return Err(format!("R_RISCV_RELATIVE: offset {} out of bounds", off));
                    }
                    write_u64_le(&mut merged.data, off, val);
                }

                // B-type branch: patch offset = (S+A-P) into B-type immediate.
                reloc_type::R_RISCV_BRANCH => {
                    let s = require_sym(sym_addr)?;
                    let offset = s.wrapping_add(a).wrapping_sub(p) as i32;
                    let merged = &mut layout.sections[merged_idx];
                    if merged.data.len() < off + 4 {
                        return Err(format!("R_RISCV_BRANCH: offset {} out of bounds", off));
                    }
                    let instr = read_u32_le(&merged.data, off);
                    write_u32_le(&mut merged.data, off, patch_b_type(instr, offset));
                }

                // J-type JAL: patch offset = (S+A-P).
                reloc_type::R_RISCV_JAL => {
                    let s = require_sym(sym_addr)?;
                    let offset = s.wrapping_add(a).wrapping_sub(p) as i32;
                    let merged = &mut layout.sections[merged_idx];
                    if merged.data.len() < off + 4 {
                        return Err(format!("R_RISCV_JAL: offset {} out of bounds", off));
                    }
                    let instr = read_u32_le(&merged.data, off);
                    write_u32_le(&mut merged.data, off, patch_j_type(instr, offset));
                }

                // CALL / CALL_PLT: AUIPC+JALR pair (8 bytes).
                // The AUIPC gets the hi20 of (S+A-P), JALR gets the lo12.
                reloc_type::R_RISCV_CALL | reloc_type::R_RISCV_CALL_PLT => {
                    let s = require_sym(sym_addr)?;
                    let diff = s.wrapping_add(a).wrapping_sub(p);
                    let hi20 = ((diff + 0x800) >> 12) as i32;
                    let lo12 = (diff - ((hi20 as i64) << 12)) as i32;
                    let merged = &mut layout.sections[merged_idx];
                    if merged.data.len() < off + 8 {
                        return Err(format!("R_RISCV_CALL: offset {} out of bounds", off));
                    }
                    let auipc = read_u32_le(&merged.data, off);
                    let jalr = read_u32_le(&merged.data, off + 4);
                    write_u32_le(&mut merged.data, off, patch_u_imm20(auipc, hi20));
                    write_u32_le(&mut merged.data, off + 4, patch_i_imm12(jalr, lo12));
                }

                // PCREL_HI20: AUIPC — store hi20 in cache keyed by PC for the LO12 below.
                reloc_type::R_RISCV_PCREL_HI20 => {
                    let s = require_sym(sym_addr)?;
                    let diff = s.wrapping_add(a).wrapping_sub(p);
                    let hi20 = ((diff + 0x800) >> 12) as i32;
                    hi20_cache.insert(place, diff); // store full diff; LO12 recomputes
                    let merged = &mut layout.sections[merged_idx];
                    if merged.data.len() < off + 4 {
                        return Err(format!("R_RISCV_PCREL_HI20: offset {} out of bounds", off));
                    }
                    let instr = read_u32_le(&merged.data, off);
                    write_u32_le(&mut merged.data, off, patch_u_imm20(instr, hi20));
                }

                // PCREL_LO12_I: I-type load/JALR — lo12 of the paired AUIPC.
                // The symbol for this reloc points to the AUIPC instruction itself.
                reloc_type::R_RISCV_PCREL_LO12_I => {
                    let auipc_pc = require_sym(sym_addr)? as u64;
                    let diff = hi20_cache.get(&auipc_pc).copied().ok_or_else(|| {
                        format!(
                            "R_RISCV_PCREL_LO12_I: no matching PCREL_HI20 at 0x{:x}",
                            auipc_pc
                        )
                    })?;
                    let hi20 = (diff + 0x800) >> 12;
                    let lo12 = (diff - (hi20 << 12)) as i32;
                    let merged = &mut layout.sections[merged_idx];
                    if merged.data.len() < off + 4 {
                        return Err(format!(
                            "R_RISCV_PCREL_LO12_I: offset {} out of bounds",
                            off
                        ));
                    }
                    let instr = read_u32_le(&merged.data, off);
                    write_u32_le(&mut merged.data, off, patch_i_imm12(instr, lo12));
                }

                // PCREL_LO12_S: S-type store — lo12 of the paired AUIPC.
                reloc_type::R_RISCV_PCREL_LO12_S => {
                    let auipc_pc = require_sym(sym_addr)? as u64;
                    let diff = hi20_cache.get(&auipc_pc).copied().ok_or_else(|| {
                        format!(
                            "R_RISCV_PCREL_LO12_S: no matching PCREL_HI20 at 0x{:x}",
                            auipc_pc
                        )
                    })?;
                    let hi20 = (diff + 0x800) >> 12;
                    let lo12 = (diff - (hi20 << 12)) as i32;
                    let merged = &mut layout.sections[merged_idx];
                    if merged.data.len() < off + 4 {
                        return Err(format!(
                            "R_RISCV_PCREL_LO12_S: offset {} out of bounds",
                            off
                        ));
                    }
                    let instr = read_u32_le(&merged.data, off);
                    write_u32_le(&mut merged.data, off, patch_s_imm12(instr, lo12));
                }

                // Absolute HI20: LUI — upper 20 bits of (S+A).
                reloc_type::R_RISCV_HI20 => {
                    let s = require_sym(sym_addr)?;
                    let val = s.wrapping_add(a);
                    let hi20 = ((val + 0x800) >> 12) as i32;
                    let merged = &mut layout.sections[merged_idx];
                    if merged.data.len() < off + 4 {
                        return Err(format!("R_RISCV_HI20: offset {} out of bounds", off));
                    }
                    let instr = read_u32_le(&merged.data, off);
                    write_u32_le(&mut merged.data, off, patch_u_imm20(instr, hi20));
                }

                // Absolute LO12_I: I-type — lower 12 bits of (S+A).
                reloc_type::R_RISCV_LO12_I => {
                    let s = require_sym(sym_addr)?;
                    let val = s.wrapping_add(a);
                    let hi20 = (val + 0x800) >> 12;
                    let lo12 = (val - (hi20 << 12)) as i32;
                    let merged = &mut layout.sections[merged_idx];
                    if merged.data.len() < off + 4 {
                        return Err(format!("R_RISCV_LO12_I: offset {} out of bounds", off));
                    }
                    let instr = read_u32_le(&merged.data, off);
                    write_u32_le(&mut merged.data, off, patch_i_imm12(instr, lo12));
                }

                // Absolute LO12_S: S-type — lower 12 bits of (S+A).
                reloc_type::R_RISCV_LO12_S => {
                    let s = require_sym(sym_addr)?;
                    let val = s.wrapping_add(a);
                    let hi20 = (val + 0x800) >> 12;
                    let lo12 = (val - (hi20 << 12)) as i32;
                    let merged = &mut layout.sections[merged_idx];
                    if merged.data.len() < off + 4 {
                        return Err(format!("R_RISCV_LO12_S: offset {} out of bounds", off));
                    }
                    let instr = read_u32_le(&merged.data, off);
                    write_u32_le(&mut merged.data, off, patch_s_imm12(instr, lo12));
                }

                _ => {
                    return Err(format!("unsupported RISC-V relocation type {}", rel.r_type));
                }
            }
        }
    }

    Ok(())
}
