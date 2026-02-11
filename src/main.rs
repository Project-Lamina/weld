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
use crate::delegate::{detect_linker, run_linker};
use crate::object::{ObjectFormat, load_objects};
use crate::platform::TargetPlatform;
use std::env;
use std::io::Write;
use std::path::Path;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn select_entry(args: &ParsedArgs, result: &link::LinkResult) -> Option<u64> {
    if let Some(s) = args.entry.as_ref() {
        if let Some(&addr) = result.symbol_addrs.get(s) {
            return Some(addr);
        }
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
    let result = link::link_multi_object(&obj_refs).ok()?;
    let arch = arch::TargetArch::from_elf_machine(result.e_machine)?;
    let entry = select_entry(args, &result)?;
    let out_path = args
        .output_file
        .as_ref()
        .map(|p| p.as_path())
        .unwrap_or(Path::new("a.out"));
    let out_file = std::fs::File::create(out_path).ok()?;
    let mut out = std::io::BufWriter::new(out_file);
    emit::elf::emit_elf_executable(&result.layout, arch, entry, &mut out).ok()?;
    out.flush().ok()?;
    Some(0)
}

fn try_weld_link_macho(args: &ParsedArgs) -> Option<i32> {
    let obj_data_list = crate::object::load_macho_objects(&args.input_files)?;
    let data = obj_data_list.first()?;
    let result = link::macho::link_macho_single_object(data).ok()?;
    let arch = arch::TargetArch::from_elf_machine(result.e_machine)?;
    let entry = select_entry(args, &result)?;
    let out_path = args
        .output_file
        .as_ref()
        .map(|p| p.as_path())
        .unwrap_or(Path::new("a.out"));
    let out_file = std::fs::File::create(out_path).ok()?;
    let mut out = std::io::BufWriter::new(out_file);
    emit::macho::emit_macho_executable(&result.layout, arch, entry, &mut out).ok()?;
    out.flush().ok()?;
    Some(0)
}

fn try_weld_link(args: &ParsedArgs) -> Option<i32> {
    if args.input_files.is_empty() || !args.libraries.is_empty() {
        return None;
    }

    let (format, _) = load_objects(&args.input_files)?;

    match format {
        ObjectFormat::Elf => try_weld_link_elf(args),
        ObjectFormat::MachO => try_weld_link_macho(args),
    }
}

fn main() {
    let argv: Vec<String> = env::args().collect();
    let link_args: Vec<String> = argv.get(1..).unwrap_or(&[]).to_vec();

    match parse_args(&link_args) {
        Ok(ParseAction::Run(args)) => {
            let platform = TargetPlatform::current();

            if platform.supports_native_linking() {
                if let Some(0) = try_weld_link(&args) {
                    if args.verbose {
                        eprintln!("[weld] linked with native backend");
                    }
                    std::process::exit(0);
                }
            }

            let linker = detect_linker(platform);
            let status = run_linker(linker, &link_args, args.verbose);
            std::process::exit(status);
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
