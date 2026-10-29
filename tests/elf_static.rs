#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

mod common;
use common::TempDir;
use std::{fs, os::unix::fs::symlink, path::Path, process::Command};

fn run(dir: &Path, program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn static_archives_rescan_cycles_and_preserve_runtime_arrays() {
    let guard = TempDir::new("weld-static");
    let dir = guard.path();
    fs::create_dir_all(dir.join("drv")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("drv/ld")).unwrap();
    fs::write(
        dir.join("start.s"),
        r#"
.globl _start
.text
_start:
    call *init(%rip)
    call first
    cmp $42, %eax
    jne fail
    call *fini(%rip)
    xor %edi, %edi
    jmp exit
fail:
    mov $1, %edi
exit:
    mov $60, %eax
    syscall
.section .init_array,"aw",@init_array
init: .quad initialize
.section .fini_array,"aw",@fini_array
fini: .quad finalize
.section .note.GNU-stack,"",@progbits
"#,
    )
    .unwrap();
    for (name, source) in [
        (
            "first",
            "int value; void initialize(void) { value = 42; } void finalize(void) { value = 0; } extern int second(void); int first(void) { return second(); }",
        ),
        ("last", "extern int value; int last(void) { return value; }"),
        (
            "second",
            "extern int last(void); int second(void) { return last(); }",
        ),
    ] {
        fs::write(dir.join(format!("{name}.c")), source).unwrap();
        run(
            dir,
            "gcc",
            &[
                "-c",
                "-fno-pie",
                "-fno-stack-protector",
                &format!("{name}.c"),
                "-o",
                &format!("{name}.o"),
            ],
        );
    }
    run(dir, "gcc", &["-c", "start.s", "-o", "start.o"]);
    run(dir, "ar", &["rcs", "libfirst.a", "first.o", "last.o"]);
    run(dir, "ar", &["rcs", "libsecond.a", "second.o"]);
    run(
        dir,
        "gcc",
        &["-shared", "-nostdlib", "second.o", "-o", "libfirst.so"],
    );
    run(
        dir,
        "gcc",
        &[
            "-Bdrv",
            "-static",
            "-nostdlib",
            "start.o",
            "-L.",
            "-Wl,--start-group",
            "-lfirst",
            "-lsecond",
            "-Wl,--end-group",
            "-o",
            "output",
        ],
    );
    run(dir, "./output", &[]);
    let headers = run(dir, "readelf", &["-hlSW", "output"]);
    assert!(
        headers.contains("EXEC")
            && headers.contains(".init_array")
            && headers.contains(".fini_array")
    );
    for forbidden in [
        "INTERP", "DYNAMIC", ".dynamic", ".dynsym", ".dynstr", ".plt", ".got",
    ] {
        assert!(!headers.contains(forbidden), "{forbidden}: {headers}");
    }
}

#[test]
fn static_glibc_and_unsupported_runtime_features_fail_before_emission() {
    let guard = TempDir::new("weld-static-errors");
    let dir = guard.path();
    fs::create_dir_all(dir.join("drv")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("drv/ld")).unwrap();
    for (source, flags, diagnostic) in [
        (
            "int main(void) { return 0; }",
            vec![],
            "static GNU IFUNC is not supported",
        ),
        (
            "int impl(void) { return 0; } void *resolve(void) { return impl; } int func(void) __attribute__((ifunc(\"resolve\"))); int main(void) { return func(); }",
            vec!["-nostdlib"],
            "static GNU IFUNC is not supported",
        ),
        (
            "int main(void) { return 0; }",
            vec!["-nostdlib", "-lmissing_weld_library"],
            "cannot find static library",
        ),
    ] {
        fs::write(dir.join("input.c"), source).unwrap();
        let output = Command::new("gcc")
            .current_dir(dir)
            .args(["-Bdrv", "-static", "input.c", "-o", "output"])
            .args(flags)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{stderr}");
        assert!(stderr.contains(diagnostic), "{stderr}");
        assert!(!dir.join("output").exists());
    }
}

#[test]
fn archive_listed_before_its_user_is_not_searched() {
    let guard = TempDir::new("weld-archive-order");
    let dir = guard.path();
    fs::create_dir_all(dir.join("drv")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("drv/ld")).unwrap();
    for (name, source) in [
        ("r", "int r(void) { return 20; }"),
        ("q", "int r(void); int q(void) { return r() * 2; }"),
        ("p", "int q(void); int p(void) { return q() + 1; }"),
        (
            "main",
            "#include <stdio.h>\nint p(void); int main(void) { printf(\"p=%d\\n\", p()); return 0; }",
        ),
    ] {
        fs::write(dir.join(format!("{name}.c")), source).unwrap();
        run(
            dir,
            "gcc",
            &["-c", &format!("{name}.c"), "-o", &format!("{name}.o")],
        );
    }
    run(dir, "ar", &["rcs", "libchain.a", "r.o", "q.o", "p.o"]);
    let output = Command::new("gcc")
        .current_dir(dir)
        .args(["-Bdrv", "-o", "before", "libchain.a", "main.o"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("undefined"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    run(
        dir,
        "gcc",
        &["-Bdrv", "-o", "after", "main.o", "libchain.a"],
    );
    assert_eq!(run(dir, "./after", &[]), "p=41\n");
}

#[test]
fn archive_member_pulled_after_earlier_definition_is_duplicate() {
    let guard = TempDir::new("weld-archive-dup");
    let dir = guard.path();
    fs::create_dir_all(dir.join("drv")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("drv/ld")).unwrap();
    for (name, source) in [
        ("member", "int strongf(void) { return 7; }"),
        ("object", "int strongf(void) { return 5; }"),
        (
            "main",
            "int strongf(void); int main(void) { return strongf(); }",
        ),
    ] {
        fs::write(dir.join(format!("{name}.c")), source).unwrap();
        run(
            dir,
            "gcc",
            &["-c", &format!("{name}.c"), "-o", &format!("{name}.o")],
        );
    }
    run(dir, "ar", &["rcs", "libmember.a", "member.o"]);
    let output = Command::new("gcc")
        .current_dir(dir)
        .args(["-Bdrv", "-o", "dup", "main.o", "libmember.a", "object.o"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("multiple definition of strongf"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn archive_without_symbol_index_is_rejected_like_ld() {
    let guard = TempDir::new("weld-archive-noidx");
    let dir = guard.path();
    fs::create_dir_all(dir.join("drv")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("drv/ld")).unwrap();
    fs::write(dir.join("empty.c"), "int main(void) { return 0; }").unwrap();
    fs::write(dir.join("helper.c"), "int helper(void) { return 1; }").unwrap();
    run(dir, "gcc", &["-c", "empty.c", "-o", "empty.o"]);
    run(dir, "gcc", &["-c", "helper.c", "-o", "helper.o"]);
    run(dir, "ar", &["rcS", "libnoidx.a", "helper.o"]);
    let output = Command::new("gcc")
        .current_dir(dir)
        .args(["-Bdrv", "-o", "noidx", "empty.o", "libnoidx.a"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("archive has no index"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn static_link_emits_eh_frame_hdr_for_unwinders() {
    let guard = TempDir::new("weld-static-eh-hdr");
    let dir = guard.path();
    fs::create_dir_all(dir.join("drv")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("drv/ld")).unwrap();
    fs::write(
        dir.join("start.s"),
        ".globl _start\n.text\n_start:\n call main\n mov %eax, %edi\n mov $60, %eax\n syscall\n.section .note.GNU-stack,\"\",@progbits\n",
    )
    .unwrap();
    fs::write(
        dir.join("prog.c"),
        "__attribute__((noinline)) int a(int x) { return x + 1; }\n__attribute__((noinline)) int b(int x) { return a(x) * 2; }\nint main(void) { return b(3) == 8 ? 0 : 1; }\n",
    )
    .unwrap();
    run(
        dir,
        "gcc",
        &["-c", "-O0", "-fno-pie", "prog.c", "-o", "prog.o"],
    );
    run(dir, "gcc", &["-c", "start.s", "-o", "start.o"]);
    run(
        dir,
        "gcc",
        &[
            "-Bdrv",
            "-static",
            "-nostdlib",
            "start.o",
            "prog.o",
            "-o",
            "output",
        ],
    );
    assert!(Command::new(dir.join("output")).status().unwrap().success());
    let headers = run(dir, "readelf", &["-SlW", "output"]);
    assert!(headers.contains(".eh_frame_hdr") && headers.contains("GNU_EH_FRAME"));
    let frames = run(dir, "readelf", &["--debug-dump=frames", "output"]);
    let fdes = frames.matches(" FDE cie").count();
    assert_eq!(fdes, 3);
    let dump = run(dir, "readelf", &["-x", ".eh_frame_hdr", "output"]);
    let hex: String = dump
        .lines()
        .filter(|line| line.trim_start().starts_with("0x"))
        .flat_map(|line| {
            line.split_whitespace()
                .skip(1)
                .take_while(|group| group.len() == 8)
        })
        .collect();
    assert!(hex.starts_with("011b033b"), "{hex}");
    let word = |at: usize| {
        let le = [
            &hex[at + 6..at + 8],
            &hex[at + 4..at + 6],
            &hex[at + 2..at + 4],
            &hex[at..at + 2],
        ];
        u32::from_str_radix(&le.concat(), 16).unwrap()
    };
    assert_eq!(word(16) as usize, fdes);
    assert_eq!(hex.len(), (12 + fdes * 8) * 2);
}
