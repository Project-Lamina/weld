//! Target architecture abstraction for parallel multi-arch support.
//!
//! Each architecture has its own relocation handling; link and emit
//! dispatch by TargetArch. New arches (AArch64, RISC-V) can be added here.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetArch {
    X86_64,
    AArch64,
    RiscV,
}

impl TargetArch {
    pub fn from_elf_machine(machine: u16) -> Option<Self> {
        match machine {
            62 => Some(Self::X86_64),
            183 => Some(Self::AArch64),
            243 => Some(Self::RiscV),
            _ => None,
        }
    }

    pub fn to_elf_machine(self) -> u16 {
        match self {
            Self::X86_64 => 62,
            Self::AArch64 => 183,
            Self::RiscV => 243,
        }
    }

    pub fn default_load_base(self) -> u64 {
        match self {
            Self::X86_64 => 0x400000,
            Self::AArch64 => 0x400000,
            Self::RiscV => 0x10000,
        }
    }

    pub fn page_align(self) -> u64 {
        0x1000
    }

    pub fn to_macho_cputype(self) -> u32 {
        match self {
            Self::X86_64 => 0x01000007,
            Self::AArch64 => 0x0100000C,
            Self::RiscV => 0,
        }
    }

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
        assert_eq!(TargetArch::from_elf_machine(0), None);
    }

    #[test]
    fn test_arch_to_elf_machine() {
        assert_eq!(TargetArch::X86_64.to_elf_machine(), 62);
        assert_eq!(TargetArch::AArch64.to_elf_machine(), 183);
    }
}
