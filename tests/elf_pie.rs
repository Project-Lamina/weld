#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

mod common;
use common::TempDir;
use std::{fs, os::unix::fs::symlink, path::Path, process::Command};

fn run(program: &str, args: &[&str], dir: &Path) -> String {
    let output = Command::new(program)
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn default_gcc_pie_rebases_data_functions_and_got() {
    let guard = TempDir::new("weld-pie-runtime");
    let dir = guard.path();
    fs::create_dir_all(dir.join("prefix")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("prefix/ld")).unwrap();
    fs::write(
        dir.join("data.c"),
        "int value = 42; int buffer[2048]; int get(void) { return value; }\n",
    )
    .unwrap();
    fs::write(dir.join("main.c"), r#"
#include <stdio.h>
extern int value, buffer[], get(void);
static int local = 7;
int *pointers[] = { &value, &local, buffer + 2047 };
int (*function)(void) = get;
int main(void) {
    if (pointers[0] != &value || pointers[1] != &local || pointers[2] != buffer + 2047 || function != get) return 1;
    *pointers[2] = 3;
    printf("%d %d %d\n", *pointers[0], *pointers[1], function() + buffer[2047]);
}
"#).unwrap();
    for flags in ["-fPIE", "-fPIC"] {
        run(
            "gcc",
            &["-Bprefix", flags, "main.c", "data.c", "-o", "output"],
            dir,
        );
        for _ in 0..3 {
            assert_eq!(run("./output", &[], dir), "42 7 45\n");
        }
        let header = run("readelf", &["-hW", "output"], dir);
        assert!(header.contains("DYN (Position-Independent Executable file)"));
        let tags = run("readelf", &["-dW", "output"], dir);
        for tag in ["(RELA)", "(RELASZ)", "(RELAENT)", "(RELACOUNT)", "NOW PIE"] {
            assert!(tags.contains(tag), "missing {tag}: {tags}");
        }
        let headers = run("readelf", &["-lW", "output"], dir);
        assert!(
            headers
                .lines()
                .any(|line| line.contains("LOAD") && line.contains("0x0000000000000000"))
        );
        assert!(run("readelf", &["-rW", "output"], dir).contains("R_X86_64_RELATIVE"));
    }
}

#[test]
fn freestanding_pie_preserves_absolute_symbols() {
    let guard = TempDir::new("weld-pie-absolute");
    let dir = guard.path();
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("input.s"),
        r#"
.text
.globl _start
_start:
    lea value(%rip), %rax
    cmp pointer(%rip), %rax
    jne fail
    lea _start(%rip), %rax
    cmp relative(%rip), %rax
    jne fail
    cmpq $123, constant(%rip)
    jne fail
    xor %edi, %edi
    jmp exit
fail:
    mov $1, %edi
exit:
    mov $60, %eax
    syscall
.data
value: .quad 42
pointer: .quad value
relative: .quad 0
.reloc relative, R_X86_64_RELATIVE, 0x1000
constant: .quad absolute
.globl absolute
.set absolute, 123
"#,
    )
    .unwrap();
    run("as", &["input.s", "-o", "input.o"], dir);
    run(
        env!("CARGO_BIN_EXE_weld"),
        &["-pie", "input.o", "-o", "output"],
        dir,
    );
    run("./output", &[], dir);
    let relocs = run("readelf", &["-rW", "output"], dir);
    assert_eq!(relocs.matches("R_X86_64_RELATIVE").count(), 2);
    fs::write(
        dir.join("bad.s"),
        ".text\n.globl _start\n_start: mov $value, %eax\n.data\nvalue: .quad 0\n",
    )
    .unwrap();
    run("as", &["bad.s", "-o", "bad.o"], dir);
    let rejected = Command::new(env!("CARGO_BIN_EXE_weld"))
        .args(["-pie", "bad.o", "-o", "bad"])
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("requires position independent input")
    );
}

#[test]
fn cross_architecture_pie_emits_relative_relocations() {
    let guard = TempDir::new("weld-pie-cross");
    let dir = guard.path();
    fs::create_dir_all(dir).unwrap();
    for (target, instruction, relocation, interpreter) in [
        (
            "aarch64-linux-gnu",
            "ret",
            "R_AARCH64_RELATIVE",
            "/lib/ld-linux-aarch64.so.1",
        ),
        (
            "riscv64-linux-gnu",
            "ret",
            "R_RISCV_RELATIVE",
            "/lib/ld-linux-riscv64-lp64d.so.1",
        ),
    ] {
        fs::write(dir.join("input.s"), format!(".text\n.globl _start\n_start: {instruction}\n.data\n.globl value\nvalue: .quad 42\npointer: .quad value+8\n")).unwrap();
        run(
            "clang",
            &["-target", target, "-c", "input.s", "-o", "input.o"],
            dir,
        );
        run(
            env!("CARGO_BIN_EXE_weld"),
            &["--pie", "input.o", "-o", "output"],
            dir,
        );
        let relocs = run("readelf", &["-rW", "output"], dir);
        assert_eq!(relocs.matches(relocation).count(), 1, "{relocs}");
        let symbols = run("nm", &["output"], dir);
        let value = symbols
            .lines()
            .find_map(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                (fields.last() == Some(&"value"))
                    .then(|| u64::from_str_radix(fields[0], 16).unwrap())
            })
            .unwrap();
        let addend = relocs
            .lines()
            .find(|line| line.contains(relocation))
            .unwrap()
            .split_whitespace()
            .last()
            .unwrap();
        assert_eq!(u64::from_str_radix(addend, 16).unwrap(), value + 8);
        assert!(run("readelf", &["-dW", "output"], dir).contains("PIE"));
        assert!(run("readelf", &["-lW", "output"], dir).contains(interpreter));
        assert!(
            run("readelf", &["-hW", "output"], dir)
                .contains("DYN (Position-Independent Executable file)")
        );
    }
}
