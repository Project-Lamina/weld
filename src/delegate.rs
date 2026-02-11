use crate::platform::TargetPlatform;
use std::io::Write;
use std::process::Command;

fn command_available(cmd: &str, probe_arg: &str) -> bool {
    Command::new(cmd).arg(probe_arg).output().is_ok()
}

pub fn detect_linker(platform: TargetPlatform) -> &'static str {
    match platform {
        TargetPlatform::Linux => {
            if command_available("mold", "--version") {
                return "mold";
            }
            if command_available("ld.lld", "-v") {
                return "ld.lld";
            }
            if command_available("lld", "-v") {
                return "lld";
            }
            if command_available("ld", "--version") || command_available("ld", "-v") {
                return "ld";
            }
            "ld"
        }
        TargetPlatform::MacOS => {
            if command_available("ld64", "-version") {
                return "ld64";
            }
            if command_available("ld", "-v") || command_available("ld", "-version") {
                return "ld";
            }
            "ld"
        }
        TargetPlatform::Windows => {
            if command_available("link", "/?") {
                return "link";
            }
            "link"
        }
    }
}

pub fn run_linker(linker: &str, args: &[String], verbose: bool) -> i32 {
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
