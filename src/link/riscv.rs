//! RISC-V relocation application.
//!
//! Stub: relocations not yet implemented.

use crate::elf::SectionHeader;
use crate::link::MergedLayout;

pub fn apply_relocations(
    _layout: &mut MergedLayout,
    _data: &[u8],
    _sections: &[SectionHeader],
    _names: &[String],
    _symbol_addrs: &[Option<u64>],
) -> Result<(), String> {
    Err("RISC-V relocations not yet implemented".to_string())
}
