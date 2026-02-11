use std::path::PathBuf;

#[derive(Debug, Default)]
pub struct ParsedArgs {
    pub output_file: Option<PathBuf>,
    pub entry: Option<String>,
    pub libraries: Vec<String>,
    pub emulation: Option<String>,
    pub dynamic_linker: Option<String>,
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
    eprintln!("  -v, --verbose               Verbose output");
    eprintln!("  -h, --help                  This help");
    eprintln!("  --version                   Print version");
}

pub fn parse_args(argv: &[String]) -> Result<ParseAction, String> {
    let mut args = ParsedArgs::default();
    let mut i = 0;

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
                let next = argv
                    .get(i)
                    .ok_or("Missing argument for --dynamic-linker")?
                    .clone();
                i += 1;
                args.dynamic_linker = Some(next);
            }
            "-v" | "--verbose" => args.verbose = true,
            "-h" | "--help" => return Ok(ParseAction::Help),
            "--version" => return Ok(ParseAction::Version),
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

    Ok(ParseAction::Run(args))
}
