//! weld - Cross-platform linker for Lamina
//!
//! Drop-in replacement for ld/lld/mold. ld-style arguments.

mod elf;
mod link;

use std::env;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_usage() {
    eprintln!("weld - Cross-platform linker for Lamina");
    eprintln!();
    eprintln!("Usage: weld [options] [input files...]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -o <file>, --output <file>   Output file (default: a.out)");
    eprintln!("  -e <symbol>, --entry <symbol>  Entry point symbol");
    eprintln!("  -l <lib>                    Link library (e.g. -lc)");
    eprintln!("  -m <emulation>               Target emulation (e.g. elf_x86_64)");
    eprintln!("  --dynamic-linker <path>     Dynamic linker path");
    eprintln!("  -v, --verbose               Verbose output");
    eprintln!("  -h, --help                  This help");
    eprintln!("  --version                   Print version");
}

#[derive(Debug, Default)]
struct ParsedArgs {
    output_file: Option<PathBuf>,
    entry: Option<String>,
    libraries: Vec<String>,
    emulation: Option<String>,
    dynamic_linker: Option<String>,
    verbose: bool,
    input_files: Vec<PathBuf>,
}

fn parse_args() -> Result<ParsedArgs, String> {
    let mut args = ParsedArgs::default();
    let argv: Vec<String> = env::args().collect();
    let mut i = 1;

    while i < argv.len() {
        let a = &argv[i];
        i += 1;

        match a.as_str() {
            "-o" | "--output" => {
                let next = argv.get(i).ok_or("Missing argument for -o")?.clone();
                i += 1;
                args.output_file = Some(PathBuf::from(next));
            }
            "-e" | "--entry" => {
                let next = argv.get(i).ok_or("Missing argument for -e")?.clone();
                i += 1;
                args.entry = Some(next);
            }
            s if s == "-l" || s.starts_with("-l") && s.len() > 2 => {
                let lib = if s == "-l" {
                    let next = argv.get(i).ok_or("Missing argument for -l")?.clone();
                    i += 1;
                    next
                } else {
                    s[2..].to_string()
                };
                args.libraries.push(lib);
            }
            "-m" => {
                let next = argv.get(i).ok_or("Missing argument for -m")?.clone();
                i += 1;
                args.emulation = Some(next);
            }
            "--dynamic-linker" => {
                let next = argv.get(i).ok_or("Missing argument for --dynamic-linker")?.clone();
                i += 1;
                args.dynamic_linker = Some(next);
            }
            "-v" | "--verbose" => args.verbose = true,
            "-h" | "--help" => return Err("help".to_string()),
            "--version" => return Err("version".to_string()),
            "-arch" | "-syslibroot" | "-platform_version" | "-L" | "-B" => {
                if argv.get(i).map(|s| !s.starts_with('-')).unwrap_or(false) {
                    i += 1;
                }
            }
            _ => {
                if !a.starts_with('-') {
                    args.input_files.push(PathBuf::from(a.clone()));
                }
            }
        }
    }

    Ok(args)
}

fn detect_linker() -> &'static str {
    #[cfg(windows)]
    {
        if Command::new("link").arg("/?").output().is_ok() {
            return "link";
        }
    }

    #[cfg(unix)]
    {
        if Command::new("mold").arg("--version").output().is_ok() {
            return "mold";
        }
        if Command::new("lld").arg("-v").output().is_ok()
            || Command::new("ld.lld").arg("-v").output().is_ok()
        {
            return "lld";
        }
        if Command::new("ld").arg("--version").output().is_ok()
            || Command::new("ld").arg("-v").output().is_ok()
        {
            return "ld";
        }
    }

    #[cfg(target_os = "macos")]
    {
        if Command::new("ld64").arg("-version").output().is_ok() {
            return "ld64";
        }
    }

    "ld"
}

fn run_linker(linker: &str, args: &[String], verbose: bool) -> i32 {
    if verbose {
        eprintln!("[weld] Using linker: {}", linker);
        eprintln!("[weld] Args: {:?}", args);
    }

    let output = Command::new(linker).args(args).output();

    match output {
        Ok(out) => {
            let _ = std::io::stdout().lock().write_all(&out.stdout);
            let _ = std::io::stderr().lock().write_all(&out.stderr);
            out.status.code().unwrap_or(1)
        }
        Err(e) => {
            eprintln!("weld: failed to run {}: {}", linker, e);
            1
        }
    }
}

fn main() {
    let argv: Vec<String> = env::args().collect();
    let link_args: Vec<String> = argv.get(1..).unwrap_or(&[]).to_vec();

    match parse_args() {
        Ok(args) => {
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
