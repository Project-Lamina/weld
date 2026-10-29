#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::{fs, path::Path, process::Command};

fn run(program: &str, args: &[&str], dir: &Path) -> (i32, String) {
    let result = Command::new(program)
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        result.stderr.is_empty(),
        "{program}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    (
        result.status.code().unwrap_or(-1),
        String::from_utf8(result.stdout).unwrap(),
    )
}

#[test]
fn relocatable_output_relinks_and_runs() {
    let dir = std::env::temp_dir().join(format!("weld-relocatable-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("main.s"),
        ".text\n.globl main\nmain:\n push %rbx\n call foo\n mov gv(%rip),%ecx\n add %ecx,%eax\n pop %rbx\n ret\n.data\n.globl gv\ngv: .long 7\n",
    )
    .unwrap();
    fs::write(
        dir.join("foo.s"),
        ".text\n.globl foo\nfoo:\n movl $35,%eax\n lea msg(%rip),%rdx\n movzbl (%rdx),%edx\n ret\n.section .rodata\nmsg: .byte 0\n",
    )
    .unwrap();
    run("as", &["main.s", "-o", "main.o"], &dir);
    run("as", &["foo.s", "-o", "foo.o"], &dir);
    let weld = env!("CARGO_BIN_EXE_weld");
    run(weld, &["-r", "main.o", "foo.o", "-o", "combined.o"], &dir);

    let (_, header) = run("readelf", &["-hW", "combined.o"], &dir);
    assert!(header.contains("REL (Relocatable file)"));
    let (_, relocs) = run("readelf", &["-rW", "combined.o"], &dir);
    assert!(relocs.contains("R_X86_64_PLT32") && relocs.contains("R_X86_64_PC32"));

    run(weld, &["combined.o", "-o", "combined"], &dir);
    let (code, _) = run("./combined", &[], &dir);
    assert_eq!(code, 42);
}
