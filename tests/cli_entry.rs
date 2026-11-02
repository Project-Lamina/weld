#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

mod common;
use common::TempDir;
use std::{fs, process::Command};

fn compile(dir: &std::path::Path, source: &str) {
    fs::write(dir.join("input.c"), source).unwrap();
    let status = Command::new("cc")
        .current_dir(dir)
        .args([
            "-c",
            "-fno-pic",
            "-fno-stack-protector",
            "input.c",
            "-o",
            "input.o",
        ])
        .status()
        .unwrap();
    assert!(status.success());
}

fn weld(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_weld"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn pe_output_from_elf_inputs_is_refused() {
    let guard = TempDir::new("weld-pe-elf");
    let dir = guard.path();
    compile(dir, "int main(void) { return 0; }");
    let output = weld(dir, &["-o", "out.exe", "input.o"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("PE output cannot be built from ELF inputs"),
        "{stderr}"
    );
    assert!(!dir.join("out.exe").exists());
}

#[test]
fn dash_e_names_the_entry_when_no_start_is_defined() {
    let guard = TempDir::new("weld-entry-e");
    let dir = guard.path();
    compile(
        dir,
        "int alt(void) { return 7; } int main(void) { return 1; }",
    );
    let output = weld(dir, &["-e", "alt", "-o", "out", "input.o"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let status = Command::new(dir.join("out")).status().unwrap();
    assert_eq!(status.code(), Some(7));

    let output = weld(dir, &["-e", "nope", "-o", "out2", "input.o"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("entry symbol nope is not defined"),
        "{stderr}"
    );
    assert!(!dir.join("out2").exists());
}

#[test]
fn dynamic_link_refuses_target_os_without_known_linker() {
    let guard = TempDir::new("weld-target-os");
    let dir = guard.path();
    compile(dir, "int main(void) { return 0; }");
    let output = weld(dir, &["--target", "orbis", "-lc", "-o", "out", "input.o"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("--target orbis"), "{stderr}");
    assert!(!dir.join("out").exists());
}

#[test]
fn freebsd_target_gets_freebsd_interpreter() {
    let guard = TempDir::new("weld-target-freebsd");
    let dir = guard.path();
    compile(dir, "int main(void) { return 0; }");
    let output = weld(dir, &["--target", "freebsd", "-lc", "-o", "out", "input.o"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let image = fs::read(dir.join("out")).unwrap();
    let freebsd = b"/libexec/ld-elf.so.1";
    assert!(image.windows(freebsd.len()).any(|w| w == freebsd));
    let glibc = b"/lib64/ld-linux-x86-64.so.2";
    assert!(!image.windows(glibc.len()).any(|w| w == glibc));
}
