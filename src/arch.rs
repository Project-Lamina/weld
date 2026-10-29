//! Target architecture abstraction.
//! Each architecture has its own relocation handling. Link and emit dispatch by `TargetArch`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetArch {
    X86_64,
    AArch64,
    RiscV,
    PowerPc64,
}

impl TargetArch {
    /// Convert an ELF `e_machine` value to a `TargetArch`, or `None` if unrecognised.
    pub fn from_elf_machine(machine: u16) -> Option<Self> {
        match machine {
            62 => Some(Self::X86_64),
            183 => Some(Self::AArch64),
            243 => Some(Self::RiscV),
            21 => Some(Self::PowerPc64),
            _ => None,
        }
    }

    /// Map a GNU ld `-m` emulation name to an architecture.
    pub fn from_emulation(name: &str) -> Option<Self> {
        match name {
            "elf_x86_64" | "elf_x86_64_fbsd" => Some(Self::X86_64),
            "aarch64linux" | "aarch64elf" | "aarch64_elf" => Some(Self::AArch64),
            "elf64lriscv" | "elf32lriscv" => Some(Self::RiscV),
            "elf64lppc" => Some(Self::PowerPc64),
            _ => None,
        }
    }

    /// Return the ELF `e_machine` value for this architecture.
    pub fn to_elf_machine(self) -> u16 {
        match self {
            Self::X86_64 => 62,
            Self::AArch64 => 183,
            Self::RiscV => 243,
            Self::PowerPc64 => 21,
        }
    }

    /// Default virtual load address for static ELF executables.
    pub fn default_load_base(self) -> u64 {
        match self {
            Self::X86_64 => 0x400000,
            Self::AArch64 => 0x400000,
            Self::RiscV => 0x10000,
            Self::PowerPc64 => 0x10000000,
        }
    }

    /// ELF `e_flags`: ELFv2 for PowerPC64, zero elsewhere.
    pub fn elf_flags(self) -> u32 {
        match self {
            Self::PowerPc64 => 2,
            _ => 0,
        }
    }

    /// Page alignment used for ELF PT_LOAD segments (always 4 KiB).
    pub fn page_align(self) -> u64 {
        0x1000
    }

    /// Return the Mach-O `cpu_type_t` value, or 0 for unsupported architectures.
    pub fn to_macho_cputype(self) -> u32 {
        match self {
            Self::X86_64 => 0x01000007,
            Self::AArch64 => 0x0100000C,
            Self::RiscV | Self::PowerPc64 => 0,
        }
    }

    /// Convert a Mach-O `cpu_type_t` to a `TargetArch`, or `None` if unrecognised.
    pub fn from_macho_cputype(cputype: u32) -> Option<Self> {
        match cputype {
            0x01000007 => Some(Self::X86_64),
            0x0100000C => Some(Self::AArch64),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arch_from_elf_machine() {
        assert_eq!(TargetArch::from_elf_machine(62), Some(TargetArch::X86_64));
        assert_eq!(TargetArch::from_elf_machine(183), Some(TargetArch::AArch64));
        assert_eq!(TargetArch::from_elf_machine(243), Some(TargetArch::RiscV));
        assert_eq!(
            TargetArch::from_elf_machine(21),
            Some(TargetArch::PowerPc64)
        );
        assert_eq!(TargetArch::from_elf_machine(0), None);
    }

    #[test]
    fn test_arch_to_elf_machine() {
        assert_eq!(TargetArch::X86_64.to_elf_machine(), 62);
        assert_eq!(TargetArch::AArch64.to_elf_machine(), 183);
        assert_eq!(TargetArch::PowerPc64.to_elf_machine(), 21);
    }
}
