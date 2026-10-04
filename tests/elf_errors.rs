#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::{fs, os::unix::fs::symlink, process::Command};

#[test]
fn rejects_lto_and_unresolved_symbols_before_emission() {
    let dir = std::env::temp_dir().join(format!("weld-errors-{}", std::process::id()));
    fs::create_dir_all(dir.join("drv")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("drv/ld")).unwrap();
    for (source, flags, diagnostic) in [
        (
            "int main(void) { return 0; }",
            vec!["-flto"],
            "LTO is not supported",
        ),
        (
            "extern int missing(void); int main(void) { return missing(); }",
            vec![],
            "undefined symbol missing",
        ),
        (
            "int other(void) { return 0; }",
            vec![],
            "undefined symbol main",
        ),
        (
            "extern int missing; int main(void) { return missing; }",
            vec!["-no-pie"],
            "undefined symbol missing",
        ),
        (
            "extern int missing(void); int main(void) { return missing(); }",
            vec!["-nostdlib", "-no-pie"],
            "undefined symbol missing",
        ),
    ] {
        fs::write(dir.join("input.c"), source).unwrap();
        let output = Command::new("gcc")
            .current_dir(&dir)
            .args(["-Bdrv", "input.c", "-o", "output"])
            .args(flags)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{stderr}");
        assert!(stderr.contains(diagnostic), "{stderr}");
        assert!(!dir.join("output").exists());
    }
    fs::write(dir.join("input.c"), "extern int optional(void) __attribute__((weak)); int main(void) { return optional ? optional() : 0; }").unwrap();
    let status = Command::new("gcc")
        .current_dir(&dir)
        .args(["-Bdrv", "input.c", "-o", "output"])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(Command::new(dir.join("output")).status().unwrap().success());
    fs::remove_dir_all(dir).unwrap();
}
