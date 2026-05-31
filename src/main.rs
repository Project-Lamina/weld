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

use crate::cli::{ParseAction, ParsedArgs, parse_args, print_usage};
use crate::object::{ObjectFormat, load_objects};
use crate::platform::TargetPlatform;
use std::env;
use std::io::Write;
use std::path::Path;

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
fn ad_hoc_codesign(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn select_entry(args: &ParsedArgs, result: &link::LinkResult) -> Option<u64> {
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

fn try_weld_link_elf(args: &ParsedArgs) -> Option<i32> {
    let obj_data_list = crate::object::load_elf_objects(&args.input_files)?;
    let obj_refs: Vec<&[u8]> = obj_data_list.iter().map(|d| d.as_slice()).collect();
    let libs = if args.libraries.is_empty() {
        None
    } else {
        Some(args.libraries.as_slice())
    };
    let result = link::link_multi_object(&obj_refs, libs).ok()?;
    let arch = arch::TargetArch::from_elf_machine(result.e_machine)?;
    let entry = select_entry(args, &result)?;
    let out_path = args.output_file.as_deref().unwrap_or(Path::new("a.out"));
    let out_file = std::fs::File::create(out_path).ok()?;
    let mut out = std::io::BufWriter::new(out_file);
    if let Some(ref dyn_info) = result.dynamic {
        emit::elf::emit_elf_executable_dynamic(&result.layout, arch, entry, dyn_info, &mut out)
            .ok()?;
    } else {
        emit::elf::emit_elf_executable(&result.layout, arch, entry, &mut out).ok()?;
    }
    out.flush().ok()?;
    drop(out);
    set_executable(out_path);
    Some(0)
}

fn try_weld_link_macho(args: &ParsedArgs) -> Option<i32> {
    let (obj_data_list, dylib_paths) = crate::object::load_macho_objects(&args.input_files)?;
    let obj_refs: Vec<&[u8]> = obj_data_list.iter().map(|d| d.as_slice()).collect();
    let libs = if args.libraries.is_empty() {
        None
    } else {
        Some(args.libraries.as_slice())
    };
    let result =
        link::macho::link_macho_multi_object(&obj_refs, libs, &dylib_paths, &args.input_files)
            .ok()?;
    let arch = arch::TargetArch::from_elf_machine(result.e_machine)?;
    let entry = select_entry(args, &result)?;
    let out_path = args.output_file.as_deref().unwrap_or(Path::new("a.out"));
    let out_file = std::fs::File::create(out_path).ok()?;
    let mut out = std::io::BufWriter::new(out_file);
    let fallback_dyn = crate::link::DynamicLinkInfo {
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
    let obj_data_list = crate::object::load_elf_objects(&args.input_files)?;
    let obj_refs: Vec<&[u8]> = obj_data_list.iter().map(|d| d.as_slice()).collect();
    let libs = if args.libraries.is_empty() {
        None
    } else {
        Some(args.libraries.as_slice())
    };
    let result = link::link_multi_object(&obj_refs, libs).ok()?;
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
        ObjectFormat::Coff => {
            eprintln!("weld: COFF/PE linking not yet implemented");
            None
        }
    }
}

fn main() {
    let argv: Vec<String> = env::args().collect();
    let link_args: Vec<String> = argv.get(1..).unwrap_or(&[]).to_vec();

    match parse_args(&link_args) {
        Ok(ParseAction::Run(args)) => {
            let platform = TargetPlatform::current();

            if !platform.supports_native_linking() {
                eprintln!("weld: native linking not supported on this platform");
                std::process::exit(1);
            }

            match try_weld_link(&args) {
                Some(0) => {
                    if args.verbose {
                        eprintln!("[weld] linked");
                    }
                    std::process::exit(0);
                }
                None => {
                    if args.verbose {
                        if let Some((format, data, dylib_paths)) =
                            crate::object::load_objects(&args.input_files)
                        {
                            let refs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
                            let err = match format {
                                crate::object::ObjectFormat::Elf => {
                                    crate::link::link_multi_object(&refs, Some(&args.libraries))
                                        .err()
                                }
                                crate::object::ObjectFormat::MachO => {
                                    crate::link::macho::link_macho_multi_object(
                                        &refs,
                                        Some(&args.libraries),
                                        &dylib_paths,
                                        &args.input_files,
                                    )
                                    .err()
                                }
                                crate::object::ObjectFormat::Coff => {
                                    Some("COFF/PE linking not yet implemented".to_string())
                                }
                            };
                            if let Some(e) = err {
                                eprintln!("[weld] native link failed: {}", e);
                            }
                        } else {
                            eprintln!(
                                "[weld] load_objects returned None (check input paths/format)"
                            );
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
