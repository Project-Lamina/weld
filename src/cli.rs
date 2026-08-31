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
    pub rpaths: Vec<String>,
    pub verbose: bool,
    pub input_files: Vec<PathBuf>,
}

pub enum ParseAction {
    Run(Box<ParsedArgs>),
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
/// Expand `@file` response files and split `-Wl,a,b` into separate arguments.
///
/// Compiler drivers pass both forms, and response files are how Windows gets
/// around the command-line length limit. Nested `@file` is followed to
/// `MAX_RESPONSE_DEPTH` so a self-referencing file cannot loop forever.
fn expand_argv(argv: &[String], depth: usize) -> Result<Vec<String>, String> {
    const MAX_RESPONSE_DEPTH: usize = 8;
    let mut out = Vec::with_capacity(argv.len());
    for a in argv {
        if let Some(rest) = a.strip_prefix("-Wl,") {
            out.extend(rest.split(',').filter(|s| !s.is_empty()).map(String::from));
        } else if let Some(path) = a.strip_prefix('@') {
            if depth >= MAX_RESPONSE_DEPTH {
                return Err(format!("response file nesting too deep at @{path}"));
            }
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read response file {path}: {e}"))?;
            let inner: Vec<String> = split_response_file(&text);
            out.extend(expand_argv(&inner, depth + 1)?);
        } else {
            out.push(a.clone());
        }
    }
    Ok(out)
}

/// Split response-file text on whitespace, honouring single and double quotes
/// and backslash escapes, as GNU ld does.
fn split_response_file(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut has = false;
    let mut quote: Option<char> = None;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else if c == '\\' && q == '"' {
                    if let Some(n) = chars.next() {
                        cur.push(n);
                    }
                } else {
                    cur.push(c);
                }
            }
            None if c == '\'' || c == '"' => {
                quote = Some(c);
                has = true;
            }
            None if c == '\\' => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                    has = true;
                }
            }
            None if c.is_whitespace() => {
                if has || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            None => {
                cur.push(c);
                has = true;
            }
        }
    }
    if has || !cur.is_empty() {
        out.push(cur);
    }
    out
}

pub fn parse_args(argv: &[String]) -> Result<ParseAction, String> {
    let argv = &expand_argv(argv, 0)?;
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
            "-rpath" | "--rpath" => {
                let next = take_required_arg(argv, &mut i, "-rpath")?;
                args.rpaths.push(next);
            }
            s if s.starts_with("-rpath=") => {
                args.rpaths.push(s["-rpath=".len()..].to_string());
            }
            s if s.starts_with("--rpath=") => {
                args.rpaths.push(s["--rpath=".len()..].to_string());
            }
            "-L" => {
                let next = take_required_arg(argv, &mut i, "-L")?;
                args.search_paths.push(PathBuf::from(next));
            }
            s if s.starts_with("-B") && s.len() > 2 => {}
            s if s.starts_with("-F") && s.len() > 2 => {}
            // Output kinds weld cannot produce yet. Silently ignoring these
            // would emit a plain executable and report success.
            "-shared" | "--shared" | "-dylib" | "-static" | "-r" | "--relocatable" => {
                return Err(format!("{a} is not supported yet"));
            }
            _ => {
                if a.starts_with('-') {
                    return Err(format!("unrecognized option {a}"));
                }
                args.input_files.push(PathBuf::from(a.clone()));
            }
        }
    }

    Ok(ParseAction::Run(Box::new(args)))
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

    #[test]
    fn wl_prefix_splits_into_separate_args() {
        let out = expand_argv(&["-Wl,-L,libdir".into(), "a.o".into()], 0).unwrap();
        assert_eq!(out, vec!["-L", "libdir", "a.o"]);
    }

    #[test]
    fn dash_l_collects_both_joined_and_separated_forms() {
        let argv: Vec<String> = ["-Ljoined", "-L", "sep", "a.o"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let ParseAction::Run(parsed) = parse_args(&argv).unwrap() else {
            panic!("expected a link action");
        };
        let paths: Vec<String> = parsed
            .search_paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(paths, vec!["joined", "sep"]);
    }

    #[test]
    fn response_file_splitting_honours_quotes_and_escapes() {
        assert_eq!(
            split_response_file("-La b\n\"two words\" 'sq' a\\ b"),
            vec!["-La", "b", "two words", "sq", "a b"]
        );
    }

    #[test]
    fn empty_quoted_argument_survives_splitting() {
        assert_eq!(split_response_file("a \"\" b"), vec!["a", "", "b"]);
    }
}
