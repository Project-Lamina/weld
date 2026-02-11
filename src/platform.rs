//! Target platform support ordering.
//!
//! Priority: Linux and macOS first, Windows later.
//! - Linux: ELF executable emission (native weld linking)
//! - macOS: delegate to ld64; Mach-O emission planned
//! - Windows: delegate to link.exe; PE support planned

#![allow(dead_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetPlatform {
    Linux,
    MacOS,
    Windows,
}

impl TargetPlatform {
    pub fn current() -> Self {
        #[cfg(target_os = "linux")]
        {
            Self::Linux
        }
        #[cfg(target_os = "macos")]
        {
            Self::MacOS
        }
        #[cfg(target_os = "windows")]
        {
            Self::Windows
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Self::Linux
        }
    }

    pub fn supports_native_linking(self) -> bool {
        matches!(self, Self::Linux)
    }

    pub fn output_format(self) -> &'static str {
        match self {
            Self::Linux => "ELF",
            Self::MacOS => "Mach-O",
            Self::Windows => "PE",
        }
    }
}
