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
fn archive_written_by_weld_links_and_runs() {
    let guard = TempDir::new("weld-archive-write");
    let dir = guard.path();
    fs::create_dir_all(dir.join("drv")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("drv/ld")).unwrap();
    fs::write(dir.join("alpha.c"), "int alpha(void) { return 1; }\n").unwrap();
    fs::write(
        dir.join("beta.c"),
        "int alpha(void);\nint beta(void) { return alpha() + 2; }\n",
    )
    .unwrap();
    fs::write(
        dir.join("a_member_with_a_long_name.c"),
        "int gamma(void) { return 40; }\n",
    )
    .unwrap();
    fs::write(
        dir.join("main.c"),
        "#include <stdio.h>\nint beta(void);\nint gamma(void);\nint main(void) { printf(\"%d %d\\n\", beta(), gamma()); return 0; }\n",
    )
    .unwrap();
    for name in ["alpha", "beta", "a_member_with_a_long_name"] {
        run(
            dir,
            "gcc",
            &[
                "-c",
                "-fno-pie",
                &format!("{name}.c"),
                "-o",
                &format!("{name}.o"),
            ],
        );
    }

    run(
        dir,
        env!("CARGO_BIN_EXE_weld"),
        &[
            "--archive",
            "-o",
            "libparts.a",
            "alpha.o",
            "beta.o",
            "a_member_with_a_long_name.o",
        ],
    );
    let listing = run(dir, "ar", &["t", "libparts.a"]);
    assert_eq!(
        listing.lines().collect::<Vec<_>>(),
        ["alpha.o", "beta.o", "a_member_with_a_long_name.o"]
    );
    let index = run(dir, "nm", &["-s", "libparts.a"]);
    for symbol in [
        "alpha in alpha.o",
        "beta in beta.o",
        "gamma in a_member_with_a_long_name.o",
    ] {
        assert!(index.contains(symbol), "{index}");
    }

    run(
        dir,
        "gcc",
        &[
            "-Bdrv",
            "-fno-pie",
            "-no-pie",
            "main.c",
            "libparts.a",
            "-o",
            "prog",
        ],
    );
    assert_eq!(run(dir, "./prog", &[]), "3 40\n");
}

#[test]
fn archive_mode_refuses_bad_invocations() {
    let guard = TempDir::new("weld-archive-refuse");
    let dir = guard.path();
    fs::write(dir.join("junk.a"), b"not an archive").unwrap();

    let no_output = Command::new(env!("CARGO_BIN_EXE_weld"))
        .current_dir(dir)
        .args(["--archive", "junk.a"])
        .output()
        .unwrap();
    assert!(!no_output.status.success());
    assert!(String::from_utf8_lossy(&no_output.stderr).contains("requires -o"));

    let with_lib = Command::new(env!("CARGO_BIN_EXE_weld"))
        .current_dir(dir)
        .args(["--archive", "-lc", "-o", "out.a", "junk.a"])
        .output()
        .unwrap();
    assert!(!with_lib.status.success());
    assert!(!dir.join("out.a").exists());

    let not_object = Command::new(env!("CARGO_BIN_EXE_weld"))
        .current_dir(dir)
        .args(["--archive", "-o", "out.a", "junk.a"])
        .output()
        .unwrap();
    assert!(!not_object.status.success());
    let stderr = String::from_utf8_lossy(&not_object.stderr);
    assert!(
        stderr.contains("junk.a: not an ELF64 or COFF object"),
        "{stderr}"
    );
    assert!(!dir.join("out.a").exists());
}
