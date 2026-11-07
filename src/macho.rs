//! Mach-O 64-bit object reader.
//! Parses header, LC_SEGMENT_64 with sections, LC_SYMTAB for object files.

const MH_MAGIC_64: u32 = 0xFEEDFACF;
const MH_CIGAM_64: u32 = 0xCFFAEDFE;
const MH_OBJECT: u32 = 1;
const MH_DYLIB: u32 = 6;
const LC_SEGMENT_64: u32 = 0x19;
/// Mach-O `loader.h`: `LC_SYMTAB` is 2. 0x0b is `LC_DYSYMTAB`, whose first two
/// words are `ilocalsym`/`nlocalsym`, not `symoff`/`nsyms`.
const LC_SYMTAB: u32 = 0x2;

const N_TYPE: u8 = 0x0e;
const N_SECT: u8 = 0x0e;
const N_WEAK_REF: u16 = 0x0040;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MachoSegment {
    pub name: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
}

#[derive(Debug, Clone)]
pub struct MachoSection {
    pub sectname: String,
    pub segname: String,
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
}

/// Mach-O relocation_info: r_address (4) + r_info (4).
/// r_info: r_symbolnum:24, r_pcrel:1, r_length:2, r_extern:1, r_type:4
pub const GENERIC_RELOC_VANILLA: u32 = 0;
pub const ARM64_RELOC_BRANCH26: u32 = 2;
pub const ARM64_RELOC_PAGE21: u32 = 3;
pub const ARM64_RELOC_PAGEOFF12: u32 = 4;
pub const ARM64_RELOC_GOT_LOAD_PAGE21: u32 = 5;
pub const ARM64_RELOC_GOT_LOAD_PAGEOFF12: u32 = 6;
pub const ARM64_RELOC_TLVP_LOAD_PAGE21: u32 = 8;
pub const ARM64_RELOC_TLVP_LOAD_PAGEOFF12: u32 = 9;
pub const ARM64_RELOC_ADDEND: u32 = 10;

#[derive(Debug, Clone, Copy)]
pub struct MachoReloc {
    pub r_address: u32,
    pub r_symbolnum: u32,
    pub r_pcrel: bool,
    pub r_length: u32,
    pub r_extern: bool,
    pub r_type: u32,
}

#[derive(Debug, Clone)]
pub struct MachoSymbol {
    pub name: String,
    pub value: u64,
    pub sect: u8,
    pub n_type: u8,
    pub n_desc: u16,
    pub is_defined: bool,
    pub is_weak_ref: bool,
}

#[derive(Debug, Clone)]
pub struct Macho64Header {
    pub cputype: u32,
    pub filetype: u32,
    pub ncmds: u32,
    #[allow(dead_code)]
    pub sizeofcmds: u32,
    #[allow(dead_code)]
    pub segments: Vec<MachoSegment>,
}

#[derive(Debug, Clone)]
pub struct Macho64Object {
    pub header: Macho64Header,
    pub sections: Vec<MachoSection>,
    pub symbols: Vec<MachoSymbol>,
    pub data: Vec<u8>,
}

fn read_u32_be(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u16_le(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u64_le(data: &[u8], off: usize) -> Option<u64> {
    data.get(off..off + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

fn trim_cstr(b: &[u8]) -> &[u8] {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    &b[..end]
}

pub fn is_macho64(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let magic = read_u32_le(data, 0).or_else(|| read_u32_be(data, 0));
    magic == Some(MH_MAGIC_64) || magic == Some(MH_CIGAM_64)
}

pub fn is_macho_dylib(data: &[u8]) -> bool {
    is_macho64(data)
        && data.len() >= 16
        && read_u32_le(data, 12)
            .map(|ft| ft == MH_DYLIB)
            .unwrap_or(false)
}

/// The name a dylib answers to (`LC_ID_DYLIB`), which is what a program must load it by.
pub fn dylib_install_name(data: &[u8]) -> Option<String> {
    const LC_ID_DYLIB: u32 = 0xd;
    let ncmds = read_u32_le(data, 16)?;
    let mut at = 32usize;
    for _ in 0..ncmds {
        let cmd = read_u32_le(data, at)?;
        let size = read_u32_le(data, at + 4)? as usize;
        if cmd == LC_ID_DYLIB {
            let name_at = at + read_u32_le(data, at + 8)? as usize;
            let bytes = data.get(name_at..at + size)?;
            let end = bytes.iter().position(|b| *b == 0)?;
            return String::from_utf8(bytes[..end].to_vec()).ok();
        }
        at = at.checked_add(size).filter(|_| size >= 8)?;
    }
    None
}

pub fn parse_macho64_header(data: &[u8]) -> Result<Macho64Header, String> {
    if data.len() < 32 {
        return Err("file too short for Mach-O 64 header".to_string());
    }

    let magic = read_u32_le(data, 0)
        .or_else(|| read_u32_be(data, 0))
        .ok_or("bad magic")?;
    if magic != MH_MAGIC_64 && magic != MH_CIGAM_64 {
        return Err("not Mach-O 64".to_string());
    }
    if magic == MH_CIGAM_64 {
        return Err("big-endian Mach-O not supported".to_string());
    }

    let cputype = read_u32_le(data, 4).ok_or("bad cputype")?;
    let _cpusubtype = read_u32_le(data, 8);
    let filetype = read_u32_le(data, 12).ok_or("bad filetype")?;
    let ncmds = read_u32_le(data, 16).ok_or("bad ncmds")?;
    let sizeofcmds = read_u32_le(data, 20).ok_or("bad sizeofcmds")?;

    let mut segments = Vec::new();
    let mut off = 32usize;

    for _ in 0..ncmds {
        if data.len() < off + 8 {
            break;
        }
        let cmd = read_u32_le(data, off).ok_or("bad cmd")?;
        let cmdsize = read_u32_le(data, off + 4).ok_or("bad cmdsize")? as usize;

        if cmd == LC_SEGMENT_64 && cmdsize >= 72 {
            let segname = data.get(off + 8..off + 24).unwrap_or(&[]);
            let name = String::from_utf8_lossy(trim_cstr(segname))
                .trim_end_matches('\0')
                .to_string();
            let vmaddr = read_u64_le(data, off + 24).ok_or("bad vmaddr")?;
            let vmsize = read_u64_le(data, off + 32).ok_or("bad vmsize")?;
            let fileoff = read_u64_le(data, off + 40).ok_or("bad fileoff")?;
            let filesize = read_u64_le(data, off + 48).ok_or("bad filesize")?;

            segments.push(MachoSegment {
                name,
                vmaddr,
                vmsize,
                fileoff,
                filesize,
            });
        }

        off += cmdsize;
    }

    Ok(Macho64Header {
        cputype,
        filetype,
        ncmds,
        sizeofcmds,
        segments,
    })
}

fn parse_sections_from_segment(data: &[u8], off: usize, _cmdsize: usize) -> Vec<MachoSection> {
    let mut sections = Vec::new();
    let nsects = read_u32_le(data, off + 64).unwrap_or(0) as usize;
    let mut sec_off = off + 72;
    for _ in 0..nsects {
        if data.len() < sec_off + 80 {
            break;
        }
        let sectname = String::from_utf8_lossy(trim_cstr(&data[sec_off..sec_off + 16]))
            .trim_end_matches('\0')
            .to_string();
        let segname = String::from_utf8_lossy(trim_cstr(&data[sec_off + 16..sec_off + 32]))
            .trim_end_matches('\0')
            .to_string();
        let addr = read_u64_le(data, sec_off + 32).unwrap_or(0);
        let size = read_u64_le(data, sec_off + 40).unwrap_or(0);
        let offset = read_u32_le(data, sec_off + 48).unwrap_or(0);
        let align = read_u32_le(data, sec_off + 52).unwrap_or(0);
        let reloff = read_u32_le(data, sec_off + 56).unwrap_or(0);
        let nreloc = read_u32_le(data, sec_off + 60).unwrap_or(0);
        let flags = read_u32_le(data, sec_off + 64).unwrap_or(0);
        sections.push(MachoSection {
            sectname,
            segname,
            addr,
            size,
            offset,
            align,
            reloff,
            nreloc,
            flags,
        });
        sec_off += 80;
    }
    sections
}

fn parse_symtab(
    data: &[u8],
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
) -> Vec<MachoSymbol> {
    let mut symbols = Vec::new();
    let soff = symoff as usize;
    let st_end = (stroff as usize)
        .saturating_add(strsize as usize)
        .min(data.len());
    for i in 0..nsyms {
        let off = soff + i as usize * 16;
        if data.len() < off + 16 {
            break;
        }
        let n_strx = read_u32_le(data, off).unwrap_or(0) as usize;
        let n_type = data.get(off + 4).copied().unwrap_or(0);
        let n_sect = data.get(off + 5).copied().unwrap_or(0);
        let n_desc = read_u16_le(data, off + 6).unwrap_or(0);
        let n_value = read_u64_le(data, off + 8).unwrap_or(0);

        let sstart = (stroff as usize).saturating_add(n_strx);
        let name = if n_strx > 0 && sstart < st_end {
            String::from_utf8_lossy(trim_cstr(&data[sstart..st_end])).to_string()
        } else {
            String::new()
        };

        let sect_type = n_type & N_TYPE;
        let is_defined = sect_type == N_SECT && n_sect != 0;
        let is_weak_ref = !is_defined && (n_desc & N_WEAK_REF) != 0;

        symbols.push(MachoSymbol {
            name,
            value: n_value,
            sect: n_sect,
            n_type,
            n_desc,
            is_defined,
            is_weak_ref,
        });
    }
    symbols
}

pub fn parse_macho_relocs(data: &[u8], reloff: u32, nreloc: u32) -> Vec<MachoReloc> {
    let base = reloff as usize;
    let readable = data.len().saturating_sub(base) / 8;
    let mut out = Vec::with_capacity((nreloc as usize).min(readable));
    for i in 0..nreloc {
        let off = base + i as usize * 8;
        if data.len() < off + 8 {
            break;
        }
        let r_address = read_u32_le(data, off).unwrap_or(0);
        let r_info = read_u32_le(data, off + 4).unwrap_or(0);
        let r_symbolnum = r_info & 0xFFFFFF;
        let r_pcrel = (r_info >> 24) & 1 != 0;
        let r_length = (r_info >> 25) & 3;
        let r_extern = (r_info >> 27) & 1 != 0;
        let r_type = (r_info >> 28) & 0xF;
        out.push(MachoReloc {
            r_address,
            r_symbolnum,
            r_pcrel,
            r_length,
            r_extern,
            r_type,
        });
    }
    out
}

pub fn parse_macho64_object(data: &[u8]) -> Result<Macho64Object, String> {
    let header = parse_macho64_header(data)?;
    if header.filetype != MH_OBJECT {
        return Err("expected MH_OBJECT".to_string());
    }

    let mut all_sections = Vec::new();
    let mut symoff = 0u32;
    let mut nsyms = 0u32;
    let mut stroff = 0u32;
    let mut strsize = 0u32;

    let mut off = 32usize;
    for _ in 0..header.ncmds {
        if data.len() < off + 8 {
            break;
        }
        let cmd = read_u32_le(data, off).ok_or("bad cmd")?;
        let cmdsize = read_u32_le(data, off + 4).ok_or("bad cmdsize")? as usize;

        if cmd == LC_SEGMENT_64 && cmdsize >= 72 {
            let mut secs = parse_sections_from_segment(data, off, cmdsize);
            all_sections.append(&mut secs);
        } else if cmd == LC_SYMTAB && cmdsize >= 24 {
            let read_symoff = read_u32_le(data, off + 8).ok_or("bad symoff")?;
            let read_nsyms = read_u32_le(data, off + 12).ok_or("bad nsyms")?;
            let read_stroff = read_u32_le(data, off + 16).ok_or("bad stroff")?;
            let read_strsize = read_u32_le(data, off + 20).ok_or("bad strsize")?;
            if read_nsyms > nsyms {
                symoff = read_symoff;
                nsyms = read_nsyms;
                stroff = read_stroff;
                strsize = read_strsize;
            }
        }

        off += cmdsize;
    }

    let symbols = parse_symtab(data, symoff, nsyms, stroff, strsize);

    Ok(Macho64Object {
        header,
        sections: all_sections,
        symbols,
        data: data.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_commands_are_the_values_loader_h_gives_them() {
        assert_eq!(LC_SEGMENT_64, 0x19);
        assert_eq!(LC_SYMTAB, 0x2);
    }

    #[test]
    fn test_is_macho64_elf() {
        let elf = [0x7f, b'E', b'L', b'F'];
        assert!(!is_macho64(&elf));
    }

    #[test]
    fn test_is_macho64_magic() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&0xFEEDFACFu32.to_le_bytes());
        assert!(is_macho64(&data));
    }

    #[test]
    fn test_parse_macho64_minimal() {
        let mut data = vec![0u8; 200];
        data[0..4].copy_from_slice(&0xFEEDFACFu32.to_le_bytes());
        data[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
        data[12..16].copy_from_slice(&1u32.to_le_bytes());
        data[16..20].copy_from_slice(&1u32.to_le_bytes());
        data[20..24].copy_from_slice(&72u32.to_le_bytes());
        data[32..36].copy_from_slice(&0x19u32.to_le_bytes());
        data[36..40].copy_from_slice(&72u32.to_le_bytes());
        data[40..56].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");

        let h = parse_macho64_header(&data).expect("parse");
        assert_eq!(h.cputype, 0x01000007);
        assert_eq!(h.ncmds, 1);
        assert_eq!(h.segments.len(), 1);
        assert_eq!(h.segments[0].name, "__TEXT");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_parse_real_object_symbol_count() {
        use std::process::Command;
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let main_add_c = manifest_dir.join("tests/c/main_add.c");
        if !main_add_c.exists() {
            return;
        }
        use crate::test_support::TempDir;
        let tmp = TempDir::new("weld_parse_symbol_test");
        let obj = tmp.path().join("weld_parse_symbol_test.o");
        let cc = Command::new("clang")
            .args(["-c", "-o"])
            .arg(&obj)
            .arg(&main_add_c)
            .output();
        let Ok(out) = cc else { return };
        if !out.status.success() {
            return;
        }
        let data = std::fs::read(&obj).unwrap_or_default();
        let _ = std::fs::remove_file(&obj);
        if data.len() < 100 {
            return;
        }
        let parsed = parse_macho64_object(&data).expect("parse");
        assert!(
            parsed.symbols.len() >= 4,
            "main_add.o should have at least 4 symbols, got {}",
            parsed.symbols.len()
        );
    }

    #[test]
    fn symtab_string_offset_past_end_of_file_yields_no_name() {
        let mut data = vec![0u8; 72];
        data[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        data[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
        data[12..16].copy_from_slice(&MH_OBJECT.to_le_bytes());
        data[16..20].copy_from_slice(&1u32.to_le_bytes());
        data[20..24].copy_from_slice(&24u32.to_le_bytes());
        data[32..36].copy_from_slice(&LC_SYMTAB.to_le_bytes());
        data[36..40].copy_from_slice(&24u32.to_le_bytes());
        data[40..44].copy_from_slice(&56u32.to_le_bytes());
        data[44..48].copy_from_slice(&1u32.to_le_bytes());
        data[48..52].copy_from_slice(&72u32.to_le_bytes());
        data[52..56].copy_from_slice(&0x1000u32.to_le_bytes());
        data[56..60].copy_from_slice(&1u32.to_le_bytes());
        data[60] = N_SECT;
        data[61] = 1;

        let parsed = parse_macho64_object(&data).expect("parse");
        assert_eq!(parsed.symbols.len(), 1);
        assert_eq!(parsed.symbols[0].name, "");
    }

    #[test]
    fn symtab_string_table_bounds_that_overflow_yield_no_name() {
        let mut data = vec![0u8; 72];
        data[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        data[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
        data[12..16].copy_from_slice(&MH_OBJECT.to_le_bytes());
        data[16..20].copy_from_slice(&1u32.to_le_bytes());
        data[20..24].copy_from_slice(&24u32.to_le_bytes());
        data[32..36].copy_from_slice(&LC_SYMTAB.to_le_bytes());
        data[36..40].copy_from_slice(&24u32.to_le_bytes());
        data[40..44].copy_from_slice(&56u32.to_le_bytes());
        data[44..48].copy_from_slice(&1u32.to_le_bytes());
        data[48..52].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        data[52..56].copy_from_slice(&0x20u32.to_le_bytes());
        data[56..60].copy_from_slice(&1u32.to_le_bytes());
        data[60] = N_SECT;
        data[61] = 1;

        let parsed = parse_macho64_object(&data).expect("parse");
        assert_eq!(parsed.symbols.len(), 1);
        assert_eq!(parsed.symbols[0].name, "");
    }

    #[test]
    fn reloc_count_beyond_the_file_does_not_reserve_for_every_claimed_entry() {
        let data = vec![0u8; 16];
        let relocs = parse_macho_relocs(&data, 0, 0xFFFF_FFFF);
        assert_eq!(relocs.len(), 2);
        assert!(relocs.capacity() < 1024);
    }

    #[test]
    fn test_parse_macho_relocs() {
        let mut data = vec![0u8; 24];
        data[0..4].copy_from_slice(&4u32.to_le_bytes());
        data[4..8].copy_from_slice(&(1u32 << 27).to_le_bytes());
        data[8..12].copy_from_slice(&8u32.to_le_bytes());
        data[12..16].copy_from_slice(&0u32.to_le_bytes());
        let relocs = parse_macho_relocs(&data, 0, 2);
        assert_eq!(relocs.len(), 2);
        assert_eq!(relocs[0].r_address, 4);
        assert!(!relocs[0].r_pcrel);
        assert!(relocs[0].r_extern);
        assert_eq!(relocs[1].r_address, 8);
        assert!(!relocs[1].r_extern);
    }

    /// Link what clang compiles on this Mac, then run it.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    mod host {
        use crate::test_support::TempDir;
        use crate::test_support::weld_binary;
        use std::path::Path;
        use std::{fs, process::Command};

        fn compile(dir: &Path, name: &str, source: &str) {
            fs::write(dir.join(format!("{name}.c")), source).unwrap();
            let status = Command::new("clang")
                .current_dir(dir)
                .args(["-c", &format!("{name}.c"), "-o", &format!("{name}.o")])
                .status()
                .unwrap();
            assert!(status.success());
        }

        fn weld(dir: &Path, args: &[&str]) {
            let output = Command::new(&weld_binary())
                .current_dir(dir)
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        fn run(dir: &Path, name: &str) -> String {
            let output = Command::new(dir.join(name)).output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8_lossy(&output.stdout).into_owned()
        }

        const CALLS_HELPER: &str = "#include <stdio.h>\nint helper(void);\nint main(void){printf(\"%d\\n\",helper());return 0;}\n";

        fn helper_dylib(dir: &Path) {
            fs::write(dir.join("helper.c"), "int helper(void){return 7;}\n").unwrap();
            let status = Command::new("clang")
                .current_dir(dir)
                .args([
                    "-dynamiclib",
                    "helper.c",
                    "-install_name",
                    "@rpath/libhelper.dylib",
                    "-o",
                    "libhelper.dylib",
                ])
                .status()
                .unwrap();
            assert!(status.success());
        }

        #[test]
        fn rpath_finds_dylib_beside_the_program() {
            let guard = TempDir::new("weld-macho-rpath");
            let dir = guard.path();
            helper_dylib(dir);
            compile(dir, "main", CALLS_HELPER);
            weld(
                dir,
                &[
                    "main.o",
                    "-L.",
                    "-lhelper",
                    "-lSystem",
                    "-rpath",
                    "@executable_path",
                    "-o",
                    "main",
                ],
            );
            assert_eq!(run(dir, "main"), "7\n");
        }

        #[test]
        fn framework_flag_loads_the_framework() {
            let guard = TempDir::new("weld-macho-framework");
            let dir = guard.path();
            compile(
                dir,
                "main",
                "#include <CoreFoundation/CoreFoundation.h>\n#include <stdio.h>\n\
                 int main(void){CFStringRef s=CFStringCreateWithCString(0,\"hi\",kCFStringEncodingUTF8);\
                 printf(\"%ld\\n\",(long)CFStringGetLength(s));CFRelease(s);return 0;}\n",
            );
            weld(
                dir,
                &[
                    "main.o",
                    "-framework",
                    "CoreFoundation",
                    "-lSystem",
                    "-o",
                    "main",
                ],
            );
            assert_eq!(run(dir, "main"), "2\n");
        }

        #[test]
        fn strip_accepts_the_output_and_it_still_runs() {
            let guard = TempDir::new("weld-macho-strip");
            let dir = guard.path();
            compile(
                dir,
                "main",
                "#include <stdio.h>\nint main(void){puts(\"ok\");return 0;}\n",
            );
            weld(dir, &["main.o", "-lSystem", "-o", "main"]);
            let strip = Command::new("strip")
                .current_dir(dir)
                .arg("main")
                .output()
                .unwrap();
            assert!(
                strip.status.success(),
                "{}",
                String::from_utf8_lossy(&strip.stderr)
            );
            let sign = Command::new("codesign")
                .current_dir(dir)
                .args(["-f", "-s", "-", "main"])
                .status()
                .unwrap();
            assert!(sign.success());
            assert_eq!(run(dir, "main"), "ok\n");
        }

        /// Frame-based and frameless functions both need their compact unwind entries to walk.
        /// The reference is the same objects linked by clang, so the count must match Apple's.
        #[test]
        fn unwind_info_lets_backtrace_walk_frames() {
            let guard = TempDir::new("weld-macho-unwind-info");
            let dir = guard.path();
            fs::write(
                dir.join("bt_main.c"),
                "#include <stdio.h>\nint leaf(int x);\nint middle(int x){return leaf(x)+1;}\n\
                 int main(void){printf(\"frames=%d\\n\",leaf(0)+middle(0)*0);return 0;}\n",
            )
            .unwrap();
            fs::write(
                dir.join("bt_leaf.c"),
                "#include <execinfo.h>\nstatic int depth(void){void *b[32];return backtrace(b,32);}\n\
                 int leaf(int x){return depth()+x;}\n",
            )
            .unwrap();
            for opt in ["-O0", "-O2"] {
                for name in ["bt_main", "bt_leaf"] {
                    let status = Command::new("clang")
                        .current_dir(dir)
                        .args([opt, "-c", &format!("{name}.c"), "-o", &format!("{name}.o")])
                        .status()
                        .unwrap();
                    assert!(status.success());
                }
                let reference = Command::new("clang")
                    .current_dir(dir)
                    .args(["bt_main.o", "bt_leaf.o", "-o", "bt_reference"])
                    .status()
                    .unwrap();
                assert!(reference.success());
                weld(
                    dir,
                    &["bt_main.o", "bt_leaf.o", "-lSystem", "-o", "bt_weld"],
                );
                let expected = run(dir, "bt_reference");
                assert_eq!(run(dir, "bt_weld"), expected, "{opt}");
                let frames: usize = expected
                    .trim()
                    .strip_prefix("frames=")
                    .and_then(|n| n.parse().ok())
                    .unwrap();
                assert!(frames >= 3, "{opt}: {expected}");
            }
        }

        const CXX_LIB: &str = r#"#include <stdio.h>
        #include <stdexcept>
        #include <string>
        #include <vector>
        struct Guard {
            std::string name;
            explicit Guard(const char *n) : name(n) { printf("enter %s\n", name.c_str()); }
            ~Guard() { printf("leave %s\n", name.c_str()); }
        };
        int deepest(int n) {
            Guard g("deepest");
            std::vector<int> v(n, 1);
            if (n > 2) throw std::runtime_error("too deep");
            return static_cast<int>(v.size());
        }
        int middle(int n) {
            Guard g("middle");
            std::string msg = "middle work";
            return deepest(n) + static_cast<int>(msg.size());
        }
        "#;

        const CXX_MAIN: &str = r#"#include <stdio.h>
        #include <stdexcept>
        int middle(int n);
        int rethrow_once(int n) {
            try { return middle(n); }
            catch (const std::logic_error &) { printf("logic\n"); return -1; }
            catch (...) { printf("rethrowing\n"); throw; }
        }
        int main() {
            try { printf("ok %d\n", middle(1)); } catch (const std::exception &e) { printf("caught1 %s\n", e.what()); }
            try { printf("ok %d\n", rethrow_once(5)); } catch (const std::runtime_error &e) { printf("caught2 %s\n", e.what()); }
            try { throw 42; } catch (int v) { printf("int %d\n", v); }
            return 0;
        }
        "#;

        /// Exceptions thrown two frames down, with destructors running in the frames they unwind
        /// through, rethrown by `catch (...)`, and caught by type and by `int`. The expected output
        /// is what the same objects print when Apple's linker builds them.
        #[test]
        fn cpp_exceptions_unwind_across_frames() {
            let guard = TempDir::new("weld-macho-eh-unwind");
            let dir = guard.path();
            fs::write(dir.join("lib.cpp"), CXX_LIB).unwrap();
            fs::write(dir.join("main.cpp"), CXX_MAIN).unwrap();
            let expected = "enter middle\nenter deepest\nleave deepest\nleave middle\nok 12\n\
                            enter middle\nenter deepest\nleave deepest\nleave middle\nrethrowing\n\
                            caught2 too deep\nint 42\n";
            for opt in ["-O0", "-O2"] {
                for name in ["lib", "main"] {
                    let status = Command::new("clang++")
                        .current_dir(dir)
                        .args([
                            opt,
                            "-c",
                            &format!("{name}.cpp"),
                            "-o",
                            &format!("{name}.o"),
                        ])
                        .status()
                        .unwrap();
                    assert!(status.success());
                }
                weld(dir, &["main.o", "lib.o", "-lc++", "-lSystem", "-o", "main"]);
                assert_eq!(run(dir, "main"), expected, "{opt}");
            }
        }

        /// A throw that leaves a dylib built by weld, through its unwind table, into the program.
        #[test]
        fn cpp_exceptions_cross_a_dylib_from_weld() {
            let guard = TempDir::new("weld-macho-eh-dylib");
            let dir = guard.path();
            fs::write(
                dir.join("lib.cpp"),
                "#include <stdio.h>\n#include <stdexcept>\n\
                 struct G { int id; explicit G(int i) : id(i) {} ~G() { printf(\"dtor %d\\n\", id); } };\n\
                 __attribute__((noinline)) void thrower() { G g(1); throw std::runtime_error(\"from dylib\"); }\n\
                 extern \"C\" void throw_through_dylib() { G g(2); thrower(); }\n",
            )
            .unwrap();
            fs::write(
                dir.join("main.cpp"),
                "#include <stdio.h>\n#include <stdexcept>\nextern \"C\" void throw_through_dylib();\n\
                 int main() { try { throw_through_dylib(); } catch (const std::exception &e) { printf(\"caught %s\\n\", e.what()); } return 0; }\n",
            )
            .unwrap();
            for name in ["lib", "main"] {
                let status = Command::new("clang++")
                    .current_dir(dir)
                    .args(["-c", &format!("{name}.cpp"), "-o", &format!("{name}.o")])
                    .status()
                    .unwrap();
                assert!(status.success());
            }
            weld(
                dir,
                &[
                    "lib.o",
                    "-dylib",
                    "-install_name",
                    "@rpath/libeh.dylib",
                    "-lc++",
                    "-lSystem",
                    "-o",
                    "libeh.dylib",
                ],
            );
            weld(
                dir,
                &[
                    "main.o",
                    "-L.",
                    "-leh",
                    "-lc++",
                    "-lSystem",
                    "-rpath",
                    "@executable_path",
                    "-o",
                    "main",
                ],
            );
            assert_eq!(run(dir, "main"), "dtor 1\ndtor 2\ncaught from dylib\n");
        }

        #[test]
        fn cpp_exceptions_without_a_library_are_refused_by_name() {
            let guard = TempDir::new("weld-macho-eh");
            let dir = guard.path();
            fs::write(
                dir.join("main.cpp"),
                "#include <stdexcept>\nint main(){try{throw std::runtime_error(\"x\");}catch(const std::exception&){return 0;}}\n",
            )
            .unwrap();
            let status = Command::new("clang++")
                .current_dir(dir)
                .args(["-c", "main.cpp", "-o", "main.o"])
                .status()
                .unwrap();
            assert!(status.success());
            let output = Command::new(&weld_binary())
                .current_dir(dir)
                .args(["main.o", "-o", "main"])
                .output()
                .unwrap();
            assert!(!output.status.success());
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains("C++ exception tables"), "{stderr}");
        }

        #[test]
        fn filelist_names_the_inputs() {
            let guard = TempDir::new("weld-macho-filelist");
            let dir = guard.path();
            compile(
                dir,
                "main",
                "#include <stdio.h>\nint main(void){puts(\"listed\");return 0;}\n",
            );
            fs::write(dir.join("inputs"), "main.o\n").unwrap();
            weld(dir, &["-filelist", "inputs", "-lSystem", "-o", "main"]);
            assert_eq!(run(dir, "main"), "listed\n");
        }

        #[test]
        fn strong_definition_overrides_weak() {
            let guard = TempDir::new("weld-macho-weak");
            let dir = guard.path();
            compile(
                dir,
                "weak",
                "#include <stdio.h>\n__attribute__((weak)) long w = 7;\n\
                 int main(void){printf(\"%ld\\n\",w);return 0;}\n",
            );
            compile(dir, "strong", "long w = 99;\n");
            weld(dir, &["weak.o", "strong.o", "-lSystem", "-o", "both"]);
            assert_eq!(run(dir, "both"), "99\n");
            weld(dir, &["weak.o", "-lSystem", "-o", "alone"]);
            assert_eq!(run(dir, "alone"), "7\n");
        }

        #[test]
        fn thread_local_from_another_object() {
            let guard = TempDir::new("weld-macho-tlv");
            let dir = guard.path();
            compile(
                dir,
                "main",
                "#include <stdio.h>\n__thread long tv = 5;\nlong get(void);\n\
                 int main(void){printf(\"%ld\\n\",get());return 0;}\n",
            );
            compile(
                dir,
                "get",
                "extern __thread long tv;\nlong get(void){return tv;}\n",
            );
            weld(dir, &["main.o", "get.o", "-lSystem", "-o", "main"]);
            assert_eq!(run(dir, "main"), "5\n");
        }

        const HELPER_DYLIB_SOURCE: &str = "int helper(void){return 7;}\nint other = 5;\n";

        fn weld_dylib(dir: &Path) {
            compile(dir, "helper", HELPER_DYLIB_SOURCE);
            weld(
                dir,
                &[
                    "helper.o",
                    "-dylib",
                    "-install_name",
                    "@rpath/libhelper.dylib",
                    "-o",
                    "libhelper.dylib",
                ],
            );
        }

        #[test]
        fn dylib_from_weld_is_named_signed_and_linked_against() {
            let guard = TempDir::new("weld-macho-dylib");
            let dir = guard.path();
            weld_dylib(dir);

            let load = Command::new("otool")
                .current_dir(dir)
                .args(["-l", "libhelper.dylib"])
                .output()
                .unwrap();
            let load = String::from_utf8_lossy(&load.stdout);
            assert!(load.contains("cmd LC_ID_DYLIB"), "{load}");
            assert!(load.contains("name @rpath/libhelper.dylib"), "{load}");
            assert!(!load.contains("LC_MAIN"), "{load}");
            let header = Command::new("otool")
                .current_dir(dir)
                .args(["-hv", "libhelper.dylib"])
                .output()
                .unwrap();
            assert!(
                String::from_utf8_lossy(&header.stdout).contains("DYLIB"),
                "{}",
                String::from_utf8_lossy(&header.stdout)
            );
            let sign = Command::new("codesign")
                .current_dir(dir)
                .args(["-v", "libhelper.dylib"])
                .status()
                .unwrap();
            assert!(sign.success());

            compile(
                dir,
                "main",
                "#include <stdio.h>\nint helper(void);\nextern int other;\n\
                 int main(void){printf(\"%d %d\\n\",helper(),other);return 0;}\n",
            );
            weld(
                dir,
                &[
                    "main.o",
                    "-L.",
                    "-lhelper",
                    "-lSystem",
                    "-rpath",
                    "@executable_path",
                    "-o",
                    "main",
                ],
            );
            assert_eq!(run(dir, "main"), "7 5\n");
        }

        #[test]
        fn dylib_from_weld_opens_with_dlopen() {
            let guard = TempDir::new("weld-macho-dlopen");
            let dir = guard.path();
            weld_dylib(dir);
            fs::write(
                dir.join("open.c"),
                r#"#include <dlfcn.h>
        #include <stdio.h>
        int main(void) {
            void *h = dlopen("./libhelper.dylib", RTLD_NOW);
            if (!h) { printf("%s\n", dlerror()); return 1; }
            int (*helper)(void) = (int (*)(void))dlsym(h, "helper");
            int *other = (int *)dlsym(h, "other");
            if (!helper || !other) { printf("missing symbol\n"); return 1; }
            printf("%d %d\n", helper(), *other);
            return 0;
        }
        "#,
            )
            .unwrap();
            let status = Command::new("clang")
                .current_dir(dir)
                .args(["open.c", "-o", "open"])
                .status()
                .unwrap();
            assert!(status.success());
            let output = Command::new(dir.join("open"))
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert_eq!(String::from_utf8_lossy(&output.stdout), "7 5\n");
        }

        #[test]
        fn links_in_process_through_the_library() {
            let guard = TempDir::new("weld-macho-lib");
            let dir = guard.path();
            compile(
                dir,
                "main",
                "#include <stdio.h>\nint main(void){puts(\"in process\");return 0;}\n",
            );
            let path = |name: &str| dir.join(name).to_string_lossy().into_owned();
            let args = [path("main.o"), "-lSystem".into(), "-o".into(), path("main")];
            crate::link(&args).unwrap();
            assert_eq!(run(dir, "main"), "in process\n");
            let missing = [
                path("main.o"),
                "-lSystem".into(),
                "-e".into(),
                "nope".into(),
                "-o".into(),
                path("bad"),
            ];
            assert_eq!(
                crate::link(&missing),
                Err("entry symbol nope is not defined".to_string())
            );
        }

        #[test]
        fn archive_written_by_weld_links_with_ld64_and_weld() {
            let guard = TempDir::new("weld-macho-archive");
            let dir = guard.path();
            compile(dir, "alpha", "int alpha(void){return 1;}\n");
            compile(
                dir,
                "a_member_with_a_long_name",
                "__attribute__((visibility(\"hidden\"))) int hidden(void){return 40;}\n\
                 int gamma(void){return hidden();}\n",
            );
            compile(
                dir,
                "main",
                "#include <stdio.h>\nint alpha(void);int gamma(void);\n\
                 int main(void){printf(\"%d %d\\n\",alpha(),gamma());return 0;}\n",
            );
            weld(
                dir,
                &[
                    "--archive",
                    "alpha.o",
                    "a_member_with_a_long_name.o",
                    "-o",
                    "libparts.a",
                ],
            );
            let map = Command::new("nm")
                .current_dir(dir)
                .args(["--print-armap", "libparts.a"])
                .output()
                .unwrap();
            let map = String::from_utf8_lossy(&map.stdout);
            for line in [
                "_alpha in alpha.o",
                "_gamma in a_member_with_a_long_name.o",
                "_hidden in a_member_with_a_long_name.o",
            ] {
                assert!(map.contains(line), "{map}");
            }
            let status = Command::new("clang")
                .current_dir(dir)
                .args(["main.o", "-L.", "-lparts", "-o", "by_ld64"])
                .status()
                .unwrap();
            assert!(status.success());
            assert_eq!(run(dir, "by_ld64"), "1 40\n");
            weld(dir, &["main.o", "libparts.a", "-lSystem", "-o", "by_weld"]);
            assert_eq!(run(dir, "by_weld"), "1 40\n");
        }
    }
}
