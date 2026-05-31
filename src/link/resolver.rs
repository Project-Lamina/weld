//! Library path resolver for `-l` flag handling.
//!
//! Searches standard platform directories for shared and static libraries,
//! returning the actual file path and soname so the linker can emit correct
//! `DT_NEEDED` entries and, in the future, extract archive members.

use crate::arch::TargetArch;
use crate::platform::TargetPlatform;
use std::path::{Path, PathBuf};

/// A library found on disk.
#[derive(Debug, Clone)]
pub struct ResolvedLibrary {
    /// Absolute path to the library file.
    pub path: PathBuf,
    /// Soname or library name used in `DT_NEEDED` / `LC_LOAD_DYLIB`.
    /// For shared libraries this is the real soname (e.g. `libc.so.6`).
    /// For static archives it is `libNAME.a`.
    pub soname: String,
    /// True when the file is a static archive (`.a`).
    pub is_static: bool,
}

/// Searches a set of directories for a library matching `-lNAME`.
///
/// Uses the same precedence as the GNU linker: shared library over static
/// archive, versioned soname over unversioned.
pub struct LibraryResolver {
    search_paths: Vec<PathBuf>,
    _arch: TargetArch,
    platform: TargetPlatform,
}

impl LibraryResolver {
    /// Build a resolver with the platform-default library search paths for
    /// the given architecture.  Extra paths can be added with `add_path`.
    pub fn new(arch: TargetArch, platform: TargetPlatform) -> Self {
        let search_paths = default_search_paths(arch, platform);
        Self {
            search_paths,
            _arch: arch,
            platform,
        }
    }

    /// Prepend an extra directory to the search path (mirrors `-L dir`).
    pub fn add_path(&mut self, path: PathBuf) {
        self.search_paths.insert(0, path);
    }

    /// Try to resolve `-lNAME` to a concrete file.
    ///
    /// On Linux: tries `libNAME.so.N` (N=6,5,2,1,0), then `libNAME.so`,
    ///           then `libNAME.a`, in each search directory.
    /// On macOS: tries `libNAME.dylib`, then `libNAME.tbd`, then `libNAME.a`.
    /// On Windows: tries `NAME.lib`, `libNAME.lib`, then `NAME.dll`.
    ///
    /// Returns `None` if the library cannot be found in any search path.
    pub fn resolve(&self, lib_name: &str) -> Option<ResolvedLibrary> {
        let candidates = self.candidates(lib_name);

        for dir in &self.search_paths {
            for (filename, soname, is_static) in &candidates {
                let path = dir.join(filename);
                if path.exists() {
                    return Some(ResolvedLibrary {
                        path,
                        soname: soname.clone(),
                        is_static: *is_static,
                    });
                }
            }
        }

        None
    }

    /// Return all known resolved names without file-system access.
    /// Useful for producing `DT_NEEDED` sonames when the library is
    /// expected to be present at runtime but not at link time.
    pub fn expected_soname(&self, lib_name: &str) -> String {
        match self.platform {
            TargetPlatform::Linux => format!("lib{}.so.6", lib_name),
            TargetPlatform::MacOS => format!("lib{}.dylib", lib_name),
            TargetPlatform::Windows => format!("{}.dll", lib_name),
        }
    }

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    fn candidates(&self, lib_name: &str) -> Vec<(String, String, bool)> {
        // (filename_to_probe, soname_for_DT_NEEDED, is_static)
        match self.platform {
            TargetPlatform::Linux => {
                let mut v: Vec<(String, String, bool)> = Vec::new();
                // Versioned shared objects (most common first).
                for version in [6, 5, 2, 1, 0u8] {
                    let name = format!("lib{}.so.{}", lib_name, version);
                    v.push((name.clone(), name, false));
                }
                // Unversioned symlink (linker stubs / sysroot).
                v.push((
                    format!("lib{}.so", lib_name),
                    format!("lib{}.so", lib_name),
                    false,
                ));
                // Static fallback.
                v.push((
                    format!("lib{}.a", lib_name),
                    format!("lib{}.a", lib_name),
                    true,
                ));
                v
            }
            TargetPlatform::MacOS => {
                vec![
                    (
                        format!("lib{}.dylib", lib_name),
                        format!("lib{}.dylib", lib_name),
                        false,
                    ),
                    (
                        format!("lib{}.tbd", lib_name),
                        format!("lib{}.dylib", lib_name),
                        false,
                    ),
                    (
                        format!("lib{}.a", lib_name),
                        format!("lib{}.a", lib_name),
                        true,
                    ),
                ]
            }
            TargetPlatform::Windows => {
                vec![
                    (
                        format!("{}.lib", lib_name),
                        format!("{}.dll", lib_name),
                        false,
                    ),
                    (
                        format!("lib{}.lib", lib_name),
                        format!("{}.dll", lib_name),
                        false,
                    ),
                    (
                        format!("{}.dll", lib_name),
                        format!("{}.dll", lib_name),
                        false,
                    ),
                ]
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Platform-default search paths
// ---------------------------------------------------------------------------

fn default_search_paths(arch: TargetArch, platform: TargetPlatform) -> Vec<PathBuf> {
    match platform {
        TargetPlatform::Linux => linux_search_paths(arch),
        TargetPlatform::MacOS => macos_search_paths(),
        TargetPlatform::Windows => windows_search_paths(),
    }
}

fn linux_search_paths(arch: TargetArch) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();

    // Architecture-specific multilib paths (checked first).
    let multilib = match arch {
        TargetArch::X86_64 => vec![
            "/lib/x86_64-linux-gnu",
            "/usr/lib/x86_64-linux-gnu",
            "/lib64",
            "/usr/lib64",
        ],
        TargetArch::AArch64 => vec!["/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu"],
        TargetArch::RiscV => vec!["/lib/riscv64-linux-gnu", "/usr/lib/riscv64-linux-gnu"],
    };

    for p in multilib {
        paths.push(PathBuf::from(p));
    }

    // Generic paths present on all Linux systems.
    for p in ["/lib", "/usr/lib", "/usr/local/lib"] {
        paths.push(PathBuf::from(p));
    }

    paths
}

fn macos_search_paths() -> Vec<PathBuf> {
    let mut paths = vec![
        PathBuf::from("/usr/lib"),
        PathBuf::from("/usr/local/lib"),
        PathBuf::from("/opt/homebrew/lib"),
    ];

    // Include Homebrew opt sub-directories if present.
    if let Ok(entries) = std::fs::read_dir("/opt/homebrew/opt") {
        let mut opt_paths: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path().join("lib"))
            .filter(|p| p.is_dir())
            .collect();
        opt_paths.sort_unstable();
        paths.extend(opt_paths);
    }

    if let Ok(entries) = std::fs::read_dir("/usr/local/opt") {
        let mut opt_paths: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path().join("lib"))
            .filter(|p| p.is_dir())
            .collect();
        opt_paths.sort_unstable();
        paths.extend(opt_paths);
    }

    paths
}

fn windows_search_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // Windows SDK and MSVC search paths from common environment variables.
    if let Ok(sdk_root) = std::env::var("WindowsSdkDir") {
        let sdk_lib = Path::new(&sdk_root).join("Lib");
        if sdk_lib.is_dir() {
            paths.push(sdk_lib);
        }
    }
    if let Ok(vctools) = std::env::var("VCToolsInstallDir") {
        let vc_lib = Path::new(&vctools).join("lib").join("x64");
        if vc_lib.is_dir() {
            paths.push(vc_lib);
        }
    }

    // System32 is always available.
    if let Ok(sysroot) = std::env::var("SystemRoot") {
        paths.push(Path::new(&sysroot).join("System32"));
    } else {
        paths.push(PathBuf::from(r"C:\Windows\System32"));
    }

    paths
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_candidates_linux() {
        let r = LibraryResolver::new(TargetArch::X86_64, TargetPlatform::Linux);
        let cands = r.candidates("c");
        // Should have versioned entries and a static fallback.
        assert!(cands.iter().any(|(f, _, s)| f == "libc.so.6" && !s));
        assert!(cands.iter().any(|(f, _, s)| f == "libc.a" && *s));
    }

    #[test]
    fn test_candidates_macos() {
        let r = LibraryResolver::new(TargetArch::AArch64, TargetPlatform::MacOS);
        let cands = r.candidates("System");
        assert!(cands.iter().any(|(f, _, s)| f == "libSystem.dylib" && !s));
        assert!(cands.iter().any(|(f, _, s)| f == "libSystem.a" && *s));
    }

    #[test]
    fn test_expected_soname() {
        let r = LibraryResolver::new(TargetArch::X86_64, TargetPlatform::Linux);
        assert_eq!(r.expected_soname("c"), "libc.so.6");

        let r = LibraryResolver::new(TargetArch::AArch64, TargetPlatform::MacOS);
        assert_eq!(r.expected_soname("c"), "libc.dylib");
    }

    #[test]
    fn test_add_path_prepended() {
        let mut r = LibraryResolver::new(TargetArch::X86_64, TargetPlatform::Linux);
        let extra = PathBuf::from("/custom/lib");
        r.add_path(extra.clone());
        assert_eq!(r.search_paths[0], extra);
    }

    #[test]
    fn test_candidates_windows() {
        let r = LibraryResolver::new(TargetArch::X86_64, TargetPlatform::Windows);
        let cands = r.candidates("kernel32");
        // Primary candidate: kernel32.lib (import library)
        assert!(
            cands
                .iter()
                .any(|(f, soname, _)| f == "kernel32.lib" && soname == "kernel32.dll"),
            "expected kernel32.lib -> kernel32.dll"
        );
        // libkernel32.lib alternative form
        assert!(
            cands.iter().any(|(f, _, _)| f == "libkernel32.lib"),
            "expected libkernel32.lib candidate"
        );
        // Bare DLL fallback
        assert!(
            cands.iter().any(|(f, _, _)| f == "kernel32.dll"),
            "expected kernel32.dll candidate"
        );
    }

    #[test]
    fn test_expected_soname_windows() {
        let r = LibraryResolver::new(TargetArch::X86_64, TargetPlatform::Windows);
        assert_eq!(r.expected_soname("kernel32"), "kernel32.dll");
    }

    #[test]
    fn test_linux_search_paths_contain_standard_dirs() {
        let r = LibraryResolver::new(TargetArch::X86_64, TargetPlatform::Linux);
        let paths: Vec<String> = r
            .search_paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert!(paths.contains(&"/usr/lib".to_string()));
        assert!(paths.contains(&"/usr/lib/x86_64-linux-gnu".to_string()));
    }

    #[test]
    fn test_linux_aarch64_search_paths() {
        let r = LibraryResolver::new(TargetArch::AArch64, TargetPlatform::Linux);
        let paths: Vec<String> = r
            .search_paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert!(paths.contains(&"/lib/aarch64-linux-gnu".to_string()));
    }
}
