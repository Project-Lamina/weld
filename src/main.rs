//! weld - Cross-platform linker for Lamina
//!
//! Drop-in replacement for ld/lld/mold. ld-style arguments.
//! Platform priority: Linux and macOS first, Windows later.

mod arch;
mod cli;
mod delegate;
mod elf;
mod emit;
mod link;
mod macho;
mod object;
mod platform;
mod segment;

use crate::cli::{ParseAction, ParsedArgs, parse_args, print_usage};
use crate::delegate::{detect_linker, run_linker};
use crate::object::load_elf_objects;
use crate::platform::TargetPlatform;
use std::env;
use std::io::Write;
use std::path::Path;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn select_entry(args: &ParsedArgs, result: &link::LinkResult) -> Option<u64> {
    args.entry
        .as_ref()
        .and_then(|s| result.symbol_addrs.get(s).copied())
        .or_else(|| result.symbol_addrs.get("main").copied())
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

fn try_weld_link(args: &ParsedArgs) -> Option<i32> {
    if args.input_files.is_empty() || !args.libraries.is_empty() {
        return None;
    }
    let out_path = args
        .output_file
        .as_ref()
        .map(|p| p.as_path())
        .unwrap_or(Path::new("a.out"));

    let obj_data_list: Vec<Vec<u8>> = if args.input_files.len() > 1 {
        let paths: Vec<PathBuf> = args.input_files.clone();
        let handles: Vec<_> = paths
            .into_iter()
            .map(|p| thread::spawn(move || std::fs::read(&p)))
            .collect();
        let mut out = Vec::with_capacity(handles.len());
        for h in handles {
            let data = match h.join() {
                Ok(Ok(d)) => d,
                _ => return None,
            };
            if data.len() < 4 || &data[0..4] != [0x7f, b'E', b'L', b'F'] {
                return None;
            }
            out.push(data);
        }
        out
    } else {
        let path = args.input_files.first()?;
        let data = std::fs::read(path).ok()?;
        if data.len() < 4 || &data[0..4] != [0x7f, b'E', b'L', b'F'] {
            return None;
        }
        vec![data]
    };

    let obj_refs: Vec<&[u8]> = obj_data_list.iter().map(|d| d.as_slice()).collect();
    let result = match link::link_multi_object(&obj_refs) {
        Ok(r) => r,
        Err(_) => return None,
    };

    let arch = arch::TargetArch::from_elf_machine(result.e_machine)?;
    let entry = args
        .entry
        .as_ref()
        .and_then(|s| result.symbol_addrs.get(s).copied())
        .or_else(|| result.symbol_addrs.get("main").copied())
        .or_else(|| result.symbol_addrs.get("_start").copied())
        .or_else(|| {
            result
                .layout
                .sections
                .first()
                .filter(|s| s.name == ".text")
                .map(|s| s.vaddr)
        });

    let entry = entry?;
    let out_file = std::fs::File::create(out_path).ok()?;
    let mut out = std::io::BufWriter::new(out_file);
    emit::emit_elf_executable(&result.layout, arch, entry, &mut out).ok()?;
    out.flush().ok()?;
    Some(0)
}

fn main() {
    let argv: Vec<String> = env::args().collect();
    let link_args: Vec<String> = argv.get(1..).unwrap_or(&[]).to_vec();

    match parse_args() {
        Ok(args) => {
            if let Some(0) = try_weld_link(&args) {
                if args.verbose {
                    eprintln!("[weld] linked with native backend");
                }
                std::process::exit(0);
            }
            let linker = detect_linker();
            let status = run_linker(linker, &link_args, args.verbose);
            std::process::exit(status);
        }
        Err(e) => {
            if e == "help" {
                print_usage();
                return;
            }
            if e == "version" {
                println!("weld {}", VERSION);
                return;
            }
            eprintln!("Error: {}", e);
            print_usage();
            std::process::exit(1);
        }
    }
}
