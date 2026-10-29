#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

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
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn gcc_shared_object_loads_with_dlopen() {
    let dir = std::env::temp_dir().join(format!("weld-shared-{}", std::process::id()));
    fs::create_dir_all(dir.join("prefix")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("prefix/ld")).unwrap();
    fs::write(
        dir.join("lib.c"),
        "#include <stdio.h>\nint shared_value = 42;\nstatic int hidden = 3;\nint shared_add(int a, int b) { return a + b + hidden; }\nconst char *shared_name(void) { return \"weld\"; }\nvoid shared_print(const char *s) { printf(\"print:%s\\n\", s); }\n",
    )
    .unwrap();
    fs::write(
        dir.join("main.c"),
        r#"
#include <dlfcn.h>
#include <stdio.h>
int main(void) {
    void *h = dlopen("./libweldshared.so", RTLD_NOW);
    if (!h) return 1;
    int (*add)(int, int) = (int (*)(int, int))dlsym(h, "shared_add");
    int *value = (int *)dlsym(h, "shared_value");
    const char *(*name)(void) = (const char *(*)(void))dlsym(h, "shared_name");
    void (*print)(const char *) = (void (*)(const char *))dlsym(h, "shared_print");
    if (!add || !value || !name || !print) return 1;
    printf("%d %d %s\n", add(1, 2), *value, name());
    print("x");
    return 0;
}
"#,
    )
    .unwrap();
    run(
        "gcc",
        &[
            "-Bprefix",
            "-shared",
            "-fPIC",
            "-Wl,-soname,libweldshared.so",
            "lib.c",
            "-o",
            "libweldshared.so",
        ],
        &dir,
    );
    let header = run("readelf", &["-hW", "libweldshared.so"], &dir);
    assert!(header.contains("DYN (Shared object file)"), "{header}");
    let tags = run("readelf", &["-dW", "libweldshared.so"], &dir);
    assert!(
        tags.contains("(SONAME)") && tags.contains("libweldshared.so"),
        "{tags}"
    );
    let symbols = run("readelf", &["--dyn-syms", "-W", "libweldshared.so"], &dir);
    assert!(symbols.contains("shared_add"), "{symbols}");
    run("gcc", &["main.c", "-o", "main", "-ldl"], &dir);
    assert_eq!(run("./main", &[], &dir), "6 42 weld\nprint:x\n");
}

#[test]
fn shared_rejects_non_x86_64_targets() {
    let dir = std::env::temp_dir().join(format!("weld-shared-arch-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("f.s"), "    .text\n    .globl f\nf:\n    ret\n").unwrap();
    let assembled = Command::new("ras")
        .args(["--target", "aarch64_linux", "-o", "f.o", "f.s"])
        .current_dir(&dir)
        .status();
    if !matches!(assembled, Ok(status) if status.success()) {
        return;
    }
    let output = Command::new(env!("CARGO_BIN_EXE_weld"))
        .args(["-shared", "-o", "libf.so", "f.o"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("-shared is not supported for AArch64")
    );
}
