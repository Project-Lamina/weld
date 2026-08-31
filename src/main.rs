//! weld - Cross-platform linker for Lamina
//!
//! Native linking only. Supports object files and dynamic libs (-lc, -lSystem).
//! No delegation to system linker.

mod arch;
mod cli;
mod elf;
mod emit;
mod link;
mod macho;
mod object;
mod platform;
mod segment;

use crate::{
    arch::TargetArch,
    cli::{ParseAction, ParsedArgs, parse_args, print_usage},
    link::{
        DynamicLinkInfo, LinkResult, MergedSection, link_multi_object_with_interp,
        macho::link_macho_multi_object,
    },
    object::{ObjectFormat, load_objects},
};
use std::{
    env,
    io::{Result, Write},
    path::Path,
};

const ELFOSABI_NONE: u8 = 0;
const ELFOSABI_FREEBSD: u8 = 9;

fn os_abi_for_target(target_os: Option<&str>) -> u8 {
    match target_os {
        Some("orbis") | Some("ps4") | Some("prospero") | Some("ps5") | Some("freebsd") => {
            ELFOSABI_FREEBSD
        }
        _ => ELFOSABI_NONE,
    }
}

#[cfg(unix)]
fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(mut perms) = std::fs::metadata(path).map(|m| m.permissions()) {
        perms.set_mode(0o755);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) {}

#[cfg(target_os = "macos")]
fn ad_hoc_codesign(path: &Path) -> std::io::Result<()> {
    let status = std::process::Command::new("codesign")
        .arg("-s")
        .arg("-")
        .arg("-f")
        .arg(path)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other("codesign failed"))
    }
}

#[cfg(not(target_os = "macos"))]
fn ad_hoc_codesign(_path: &Path) -> Result<()> {
    Ok(())
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn select_entry(args: &ParsedArgs, result: &LinkResult) -> Option<u64> {
    if let Some(s) = args.entry.as_ref()
        && let Some(&addr) = result.symbol_addrs.get(s)
    {
        return Some(addr);
    }
    result
        .symbol_addrs
        .get("main")
        .copied()
        .or_else(|| result.symbol_addrs.get("_main").copied())
        .or_else(|| result.symbol_addrs.get("_start").copied())
        .or_else(|| {
            result
                .layout
                .sections
                .first()
                .filter(|s| s.name == ".text")
                .map(|s| s.vaddr)
        })
}

/// True when no real `_start` is defined, so weld must provide program startup
/// itself. This applies to both static and dynamic links: when we don't link a
/// C runtime (crt1.o), nothing defines `_start`, and entering directly at `main`
/// would `ret` into `argc` on the initial stack. The synthetic stub calls `main`
/// and then issues the `exit` syscall. For dynamic links the PLT/GOT are already
/// resolved by the interpreter (BIND_NOW) before `_start` runs.
fn needs_synthetic_start(result: &LinkResult) -> bool {
    !result.symbol_addrs.contains_key("_start")
}

/// Append a freestanding `_start` to a static x86_64 ELF layout and return its
/// entry address. The stub calls `main`, then issues the `exit` syscall with
/// `main`'s return value. `freebsd_abi` selects SYS_exit=1 (FreeBSD/Orbis/Prospero)
/// vs SYS_exit=60 (Linux).
fn synthesize_elf_start_x86_64(result: &mut LinkResult, freebsd_abi: bool) -> Option<u64> {
    if TargetArch::from_elf_machine(result.e_machine) != Some(TargetArch::X86_64) {
        return None;
    }

    let main_addr = result
        .symbol_addrs
        .get("main")
        .or_else(|| result.symbol_addrs.get("_main"))
        .copied()?;

    let last = result.layout.sections.last()?;
    let start_vaddr = (last.vaddr + last.data.len() as u64 + 15) & !15;

    let sys_exit: u32 = if freebsd_abi { 1 } else { 60 };

    let mut code = Vec::new();
    code.push(0xe8); // call rel32 -> main
    let call_next = start_vaddr + 5;
    let rel = i32::try_from(main_addr as i64 - call_next as i64).ok()?;
    code.extend_from_slice(&rel.to_le_bytes());
    code.extend_from_slice(&[0x48, 0x89, 0xc7]); // movq %rax, %rdi
    code.push(0xb8); // movl $SYS_exit, %eax
    code.extend_from_slice(&sys_exit.to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05]); // syscall

    let idx = result.layout.sections.len();
    result
        .layout
        .section_by_name
        .insert(".text.__weld_start".to_string(), idx);
    result.layout.sections.push(MergedSection {
        name: ".text.__weld_start".to_string(),
        data: code,
        vaddr: start_vaddr,
        flags: 2 | 4, // SHF_ALLOC | SHF_EXECINSTR
        align: 16,
    });

    Some(start_vaddr)
}

fn try_weld_link_elf(args: &ParsedArgs) -> Option<i32> {
    let obj_data_list = object::load_elf_objects(&args.input_files)?;
    let obj_refs: Vec<&[u8]> = obj_data_list.iter().map(|d| d.as_slice()).collect();
    let libs = if args.libraries.is_empty() {
        None
    } else {
        Some(args.libraries.as_slice())
    };
    let target_os = args.target_os.as_deref();
    let os_abi = os_abi_for_target(target_os);
    let freebsd_abi = os_abi == ELFOSABI_FREEBSD;
    let mut result =
        link_multi_object_with_interp(&obj_refs, libs, args.dynamic_linker.as_deref()).ok()?;
    let arch = TargetArch::from_elf_machine(result.e_machine)?;
    let entry = if needs_synthetic_start(&result) {
        synthesize_elf_start_x86_64(&mut result, freebsd_abi)
            .or_else(|| select_entry(args, &result))?
    } else {
        select_entry(args, &result)?
    };
    let out_path = args.output_file.as_deref().unwrap_or(Path::new("a.out"));
    let out_file = std::fs::File::create(out_path).ok()?;
    let mut out = std::io::BufWriter::new(out_file);
    if let Some(ref dyn_info) = result.dynamic {
        emit::elf::emit_elf_executable_dynamic(
            &result.layout,
            arch,
            entry,
            os_abi,
            dyn_info,
            &mut out,
        )
        .ok()?;
    } else {
        emit::elf::emit_elf_executable(&result.layout, arch, entry, os_abi, &mut out).ok()?;
    }
    out.flush().ok()?;
    drop(out);
    set_executable(out_path);
    Some(0)
}

fn try_weld_link_macho(args: &ParsedArgs) -> Option<i32> {
    let (obj_data_list, dylib_paths) = object::load_macho_objects(&args.input_files)?;
    let obj_refs: Vec<&[u8]> = obj_data_list.iter().map(|d| d.as_slice()).collect();
    let libs = if args.libraries.is_empty() {
        None
    } else {
        Some(args.libraries.as_slice())
    };
    let result = link_macho_multi_object(&obj_refs, libs, &dylib_paths, &args.input_files).ok()?;
    let arch = TargetArch::from_elf_machine(result.e_machine)?;
    let entry = select_entry(args, &result)?;
    let out_path = args.output_file.as_deref().unwrap_or(Path::new("a.out"));
    let out_file = std::fs::File::create(out_path).ok()?;
    let mut out = std::io::BufWriter::new(out_file);
    let fallback_dyn = DynamicLinkInfo {
        needed: vec!["/usr/lib/libSystem.B.dylib".to_string()],
        plt_symbols: Vec::new(),
        weak_plt_symbols: Vec::new(),
        interpreter: None,
        macho_rebase_addrs: Vec::new(),
        macho_direct_binds: Vec::new(),
    };
    let dyn_info = result.dynamic.as_ref().unwrap_or(&fallback_dyn);
    emit::macho::emit_macho_executable_dynamic(&result.layout, arch, entry, dyn_info, &mut out)
        .ok()?;
    out.flush().ok()?;
    drop(out);
    set_executable(out_path);
    ad_hoc_codesign(out_path).ok()?;
    Some(0)
}

fn try_weld_link_pe(args: &ParsedArgs) -> Option<i32> {
    // Accept both COFF object files and (legacy) ELF objects. For COFF, use the
    // direct COFF→PE linker. For ELF (rare on Windows), fall through to the
    // original path.
    if let Some(first) = args.input_files.first() {
        let data = std::fs::read(first).ok()?;
        let is_coff = object::is_coff_object(&data);
        if is_coff {
            let out_path = args.output_file.as_deref().unwrap_or(Path::new("a.exe"));
            let out_file = std::fs::File::create(out_path).ok()?;
            let mut out = std::io::BufWriter::new(out_file);
            emit::pe::link_and_emit_pe_from_coff(&data, &mut out).ok()?;
            out.flush().ok()?;
            return Some(0);
        }
    }

    // Legacy ELF-based path (kept for compatibility).
    let obj_data_list = object::load_elf_objects(&args.input_files)?;
    let obj_refs: Vec<&[u8]> = obj_data_list.iter().map(|d| d.as_slice()).collect();
    let libs = if args.libraries.is_empty() {
        None
    } else {
        Some(args.libraries.as_slice())
    };
    let result =
        link_multi_object_with_interp(&obj_refs, libs, args.dynamic_linker.as_deref()).ok()?;
    let entry = select_entry(args, &result)?;
    let out_path = args.output_file.as_deref().unwrap_or(Path::new("a.exe"));
    let out_file = std::fs::File::create(out_path).ok()?;
    let mut out = std::io::BufWriter::new(out_file);
    emit::pe::emit_pe_executable(&result.layout, entry, result.dynamic.as_ref(), &mut out).ok()?;
    out.flush().ok()?;
    Some(0)
}

fn try_weld_link(args: &ParsedArgs) -> Option<i32> {
    if args.input_files.is_empty() {
        return None;
    }

    // Windows PE: triggered by explicit --target=windows or .exe output suffix.
    let wants_pe = args
        .output_file
        .as_ref()
        .map(|p| {
            p.extension()
                .map(|e| e.eq_ignore_ascii_case("exe"))
                .unwrap_or(false)
        })
        .unwrap_or(false);

    if wants_pe {
        return try_weld_link_pe(args);
    }

    let (format, _, _) = load_objects(&args.input_files)?;

    match format {
        ObjectFormat::Elf => try_weld_link_elf(args),
        ObjectFormat::MachO => try_weld_link_macho(args),
        ObjectFormat::Coff => try_weld_link_pe(args),
    }
}

fn main() {
    let argv: Vec<String> = env::args().collect();
    let link_args: Vec<String> = argv.get(1..).unwrap_or(&[]).to_vec();

    match parse_args(&link_args) {
        Ok(ParseAction::Run(args)) => {
            // Output format is chosen from the input objects, not the host OS, so
            // ELF/Mach-O linking works even when cross-linking from another host.
            // Unsupported output formats are reported per-format in `try_weld_link`.
            match try_weld_link(&args) {
                Some(0) => {
                    if args.verbose {
                        eprintln!("[weld] linked");
                    }
                    std::process::exit(0);
                }
                None => {
                    {
                        if let Some((format, data, dylib_paths)) = load_objects(&args.input_files) {
                            let refs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
                            let err = match format {
                                ObjectFormat::Elf => link_multi_object_with_interp(
                                    &refs,
                                    Some(&args.libraries),
                                    args.dynamic_linker.as_deref(),
                                )
                                .err(),
                                ObjectFormat::MachO => link_macho_multi_object(
                                    &refs,
                                    Some(&args.libraries),
                                    &dylib_paths,
                                    &args.input_files,
                                )
                                .err(),
                                ObjectFormat::Coff => {
                                    Some("COFF/PE linking not yet implemented".to_string())
                                }
                            };
                            if let Some(e) = err {
                                eprintln!("weld: {e}");
                            }
                        } else {
                            eprintln!("weld: could not read the input objects");
                        }
                    }
                    eprintln!("weld: link failed");
                    std::process::exit(1);
                }
                Some(code) => std::process::exit(code),
            }
        }
        Ok(ParseAction::Help) => {
            print_usage();
        }
        Ok(ParseAction::Version) => {
            println!("weld {}", VERSION);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            print_usage();
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::MergedLayout;
    use std::collections::HashMap;

    fn static_main_result() -> LinkResult {
        let mut section_by_name = HashMap::new();
        section_by_name.insert(".text".to_string(), 0);
        let mut symbol_addrs = HashMap::new();
        symbol_addrs.insert("main".to_string(), 0x400000u64);
        LinkResult {
            layout: MergedLayout {
                sections: vec![MergedSection {
                    name: ".text".to_string(),
                    data: vec![0xc3],
                    vaddr: 0x400000,
                    flags: 2 | 4,
                    align: 16,
                }],
                section_by_name,
            },
            e_machine: 62,
            symbol_addrs,
            dynamic: None,
        }
    }

    #[test]
    fn synthesizes_start_for_static_main() {
        let mut result = static_main_result();
        assert!(needs_synthetic_start(&result));

        let entry = synthesize_elf_start_x86_64(&mut result, false).expect("start synthesized");
        assert!(entry >= 0x400000);
        assert!(
            result
                .layout
                .section_by_name
                .contains_key(".text.__weld_start")
        );

        let start = &result.layout.sections[result.layout.sections.len() - 1];
        // call rel32 (5) + mov %rax,%rdi (3) + mov $60,%eax (5) + syscall (2).
        assert_eq!(start.data.len(), 15);
        assert_eq!(start.data[0], 0xe8);
        assert_eq!(&start.data[13..15], &[0x0f, 0x05]);
    }

    #[test]
    fn no_synthetic_start_when_start_is_defined() {
        let mut result = static_main_result();
        result.symbol_addrs.insert("_start".to_string(), 0x401000);
        assert!(!needs_synthetic_start(&result));
    }

    #[test]
    fn synthesizes_start_for_dynamic_link_without_start() {
        // A dynamic link (libc) with no crt-provided `_start` still needs the
        // synthetic stub, otherwise entering at `main` returns into `argc`.
        let mut result = static_main_result();
        result.dynamic = Some(DynamicLinkInfo::default());
        assert!(needs_synthetic_start(&result));
    }

    #[test]
    fn no_synthetic_start_for_dynamic_link_with_start() {
        let mut result = static_main_result();
        result.dynamic = Some(DynamicLinkInfo::default());
        result.symbol_addrs.insert("_start".to_string(), 0x401000);
        assert!(!needs_synthetic_start(&result));
    }
}
