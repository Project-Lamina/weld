use std::path::PathBuf;

#[derive(Debug, Default)]
pub struct ParsedArgs {
    pub output_file: Option<PathBuf>,
    pub entry: Option<String>,
    pub libraries: Vec<String>,
    pub emulation: Option<String>,
    pub dynamic_linker: Option<String>,
    pub target_os: Option<String>,
    pub search_paths: Vec<PathBuf>,
    pub verbose: bool,
    pub input_files: Vec<PathBuf>,
}

pub enum ParseAction {
    Run(ParsedArgs),
    Help,
    Version,
}

pub fn print_usage() {
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
    eprintln!("  --target <os>               Target OS (e.g. linux, orbis, prospero, freebsd)");
    eprintln!("  -v, --verbose               Verbose output");
    eprintln!("  -h, --help                  This help");
    eprintln!("  --version                   Print version");
    eprintln!();
    eprintln!(
        "GCC: link with weld using -fuse-ld=weld; assemble .s with ras by symlinking as -> ras and passing gcc -B<prefix> (see ras --help)."
    );
}

/// Consume the next element of `argv` as the required argument for `flag`.
/// Returns `Err` if there is no next element.
fn take_required_arg(argv: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    let next = argv
        .get(*i)
        .ok_or_else(|| format!("Missing argument for {}", flag))?
        .clone();
    *i += 1;
    Ok(next)
}

/// Advance `i` by up to `count` positions, clamped to the end of `argv`.
fn skip_args(argv: &[String], i: &mut usize, count: usize) {
    let remaining = argv.len().saturating_sub(*i);
    *i += remaining.min(count);
}

/// Parse a weld command-line argument vector into a `ParseAction`.
///
/// Handles the GCC/Clang linker driver flags that weld may receive when invoked
/// via `-fuse-ld=weld`. Unknown flags starting with `-` are silently ignored;
/// non-flag arguments are collected as input files.
pub fn parse_args(argv: &[String]) -> Result<ParseAction, String> {
    let mut args = ParsedArgs::default();
    let mut i = 0;

    while i < argv.len() {
        let a = &argv[i];
        i += 1;

        match a.as_str() {
            "-o" | "--output" => {
                let next = take_required_arg(argv, &mut i, "-o")?;
                args.output_file = Some(PathBuf::from(next));
            }
            "-e" | "--entry" => {
                let next = take_required_arg(argv, &mut i, "-e")?;
                args.entry = Some(next);
            }
            "-lto_library"
            | "-framework"
            | "-weak_framework"
            | "-syslibroot"
            | "-mllvm"
            | "-exported_symbols_list"
            | "-install_name"
            | "-B"
            | "-F"
            | "-arch"
            | "-filelist"
            | "-object_path_lto" => {
                skip_args(argv, &mut i, 1);
            }
            "-platform_version" => {
                skip_args(argv, &mut i, 3);
            }
            "-demangle" | "-no_deduplicate" | "-dynamic" | "-dead_strip" => {}
            s if s == "-l" || s.starts_with("-l") && s.len() > 2 => {
                let lib = if s == "-l" {
                    take_required_arg(argv, &mut i, "-l")?
                } else {
                    s[2..].to_string()
                };
                args.libraries.push(lib);
            }
            "-m" => {
                let next = take_required_arg(argv, &mut i, "-m")?;
                args.emulation = Some(next);
            }
            "--dynamic-linker" => {
                let next = take_required_arg(argv, &mut i, "--dynamic-linker")?;
                args.dynamic_linker = Some(next);
            }
            "--target" => {
                let next = take_required_arg(argv, &mut i, "--target")?;
                args.target_os = Some(next);
            }
            "-v" | "--verbose" => args.verbose = true,
            "-h" | "--help" => return Ok(ParseAction::Help),
            "--version" => return Ok(ParseAction::Version),
            s if s.starts_with("-mmacosx-version-min") || s.starts_with("-mios") => {}
            "-nodefaultlibs" | "-nostdlib" => {}
            s if s.starts_with("-L") && s.len() > 2 => {
                args.search_paths.push(PathBuf::from(&s[2..]));
            }
            "-L" => {
                let next = take_required_arg(argv, &mut i, "-L")?;
                args.search_paths.push(PathBuf::from(next));
            }
            s if s.starts_with("-B") && s.len() > 2 => {}
            s if s.starts_with("-F") && s.len() > 2 => {}
            s if s.starts_with("-Wl,") => {}
            _ => {
                if !a.starts_with('-') {
                    args.input_files.push(PathBuf::from(a.clone()));
                }
            }
        }
    }

    Ok(ParseAction::Run(args))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clang_macos_linker_flags_without_treating_versions_as_inputs() {
        let argv = vec![
            "-demangle",
            "-lto_library",
            "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/libLTO.dylib",
            "-no_deduplicate",
            "-dynamic",
            "-arch",
            "arm64",
            "-platform_version",
            "macos",
            "26.0.0",
            "26.2",
            "-syslibroot",
            "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk",
            "-mllvm",
            "-enable-linkonceodr-outlining",
            "-o",
            "/tmp/weld_bench_main",
            "-L/usr/local/lib",
            "/tmp/main-e06c85.o",
            "-lSystem",
            "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/17/lib/darwin/libclang_rt.osx.a",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();

        let ParseAction::Run(parsed) = parse_args(&argv).expect("parse args") else {
            panic!("expected ParseAction::Run");
        };

        assert!(
            parsed
                .input_files
                .iter()
                .any(|p| p.to_string_lossy() == "/tmp/main-e06c85.o")
        );
        assert!(
            parsed
                .input_files
                .iter()
                .any(|p| p.to_string_lossy().ends_with("libclang_rt.osx.a"))
        );
        assert!(
            !parsed
                .input_files
                .iter()
                .any(|p| p.to_string_lossy() == "26.0.0")
        );
        assert!(
            !parsed
                .input_files
                .iter()
                .any(|p| p.to_string_lossy() == "26.2")
        );
        assert!(parsed.libraries.iter().any(|l| l == "System"));
    }
}
