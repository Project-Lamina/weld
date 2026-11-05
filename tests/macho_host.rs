//! Link what clang compiles on this Mac, then run it.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

mod common;
use common::TempDir;
use std::path::Path;
use std::{fs, process::Command};

fn compile(dir: &Path, name: &str, source: &str) {
    fs::write(dir.join(format!("{name}.c")), source).unwrap();
    let status = Command::new("clang")
        .current_dir(dir)
        .args(["-c", &format!("{name}.c"), "-o", &format!("{name}.o")])
        .status()
        .unwrap();
    assert!(status.success());
}

fn weld(dir: &Path, args: &[&str]) {
    let output = Command::new(env!("CARGO_BIN_EXE_weld"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run(dir: &Path, name: &str) -> String {
    let output = Command::new(dir.join(name)).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

const CALLS_HELPER: &str =
    "#include <stdio.h>\nint helper(void);\nint main(void){printf(\"%d\\n\",helper());return 0;}\n";

fn helper_dylib(dir: &Path) {
    fs::write(dir.join("helper.c"), "int helper(void){return 7;}\n").unwrap();
    let status = Command::new("clang")
        .current_dir(dir)
        .args([
            "-dynamiclib",
            "helper.c",
            "-install_name",
            "@rpath/libhelper.dylib",
            "-o",
            "libhelper.dylib",
        ])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn rpath_finds_dylib_beside_the_program() {
    let guard = TempDir::new("weld-macho-rpath");
    let dir = guard.path();
    helper_dylib(dir);
    compile(dir, "main", CALLS_HELPER);
    weld(
        dir,
        &[
            "main.o",
            "-L.",
            "-lhelper",
            "-lSystem",
            "-rpath",
            "@executable_path",
            "-o",
            "main",
        ],
    );
    assert_eq!(run(dir, "main"), "7\n");
}

#[test]
fn framework_flag_loads_the_framework() {
    let guard = TempDir::new("weld-macho-framework");
    let dir = guard.path();
    compile(
        dir,
        "main",
        "#include <CoreFoundation/CoreFoundation.h>\n#include <stdio.h>\n\
         int main(void){CFStringRef s=CFStringCreateWithCString(0,\"hi\",kCFStringEncodingUTF8);\
         printf(\"%ld\\n\",(long)CFStringGetLength(s));CFRelease(s);return 0;}\n",
    );
    weld(
        dir,
        &[
            "main.o",
            "-framework",
            "CoreFoundation",
            "-lSystem",
            "-o",
            "main",
        ],
    );
    assert_eq!(run(dir, "main"), "2\n");
}

#[test]
fn strip_accepts_the_output_and_it_still_runs() {
    let guard = TempDir::new("weld-macho-strip");
    let dir = guard.path();
    compile(
        dir,
        "main",
        "#include <stdio.h>\nint main(void){puts(\"ok\");return 0;}\n",
    );
    weld(dir, &["main.o", "-lSystem", "-o", "main"]);
    let strip = Command::new("strip")
        .current_dir(dir)
        .arg("main")
        .output()
        .unwrap();
    assert!(
        strip.status.success(),
        "{}",
        String::from_utf8_lossy(&strip.stderr)
    );
    let sign = Command::new("codesign")
        .current_dir(dir)
        .args(["-f", "-s", "-", "main"])
        .status()
        .unwrap();
    assert!(sign.success());
    assert_eq!(run(dir, "main"), "ok\n");
}

#[test]
fn cpp_exceptions_are_refused_by_name() {
    let guard = TempDir::new("weld-macho-eh");
    let dir = guard.path();
    fs::write(
        dir.join("main.cpp"),
        "#include <stdexcept>\nint main(){try{throw std::runtime_error(\"x\");}catch(const std::exception&){return 0;}}\n",
    )
    .unwrap();
    let status = Command::new("clang++")
        .current_dir(dir)
        .args(["-c", "main.cpp", "-o", "main.o"])
        .status()
        .unwrap();
    assert!(status.success());
    let output = Command::new(env!("CARGO_BIN_EXE_weld"))
        .current_dir(dir)
        .args(["main.o", "-lc++", "-lSystem", "-o", "main"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("C++ exception tables"), "{stderr}");
}

#[test]
fn filelist_names_the_inputs() {
    let guard = TempDir::new("weld-macho-filelist");
    let dir = guard.path();
    compile(
        dir,
        "main",
        "#include <stdio.h>\nint main(void){puts(\"listed\");return 0;}\n",
    );
    fs::write(dir.join("inputs"), "main.o\n").unwrap();
    weld(dir, &["-filelist", "inputs", "-lSystem", "-o", "main"]);
    assert_eq!(run(dir, "main"), "listed\n");
}

const HELPER_DYLIB_SOURCE: &str = "int helper(void){return 7;}\nint other = 5;\n";

fn weld_dylib(dir: &Path) {
    compile(dir, "helper", HELPER_DYLIB_SOURCE);
    weld(
        dir,
        &[
            "helper.o",
            "-dylib",
            "-install_name",
            "@rpath/libhelper.dylib",
            "-o",
            "libhelper.dylib",
        ],
    );
}

#[test]
fn dylib_from_weld_is_named_signed_and_linked_against() {
    let guard = TempDir::new("weld-macho-dylib");
    let dir = guard.path();
    weld_dylib(dir);

    let load = Command::new("otool")
        .current_dir(dir)
        .args(["-l", "libhelper.dylib"])
        .output()
        .unwrap();
    let load = String::from_utf8_lossy(&load.stdout);
    assert!(load.contains("cmd LC_ID_DYLIB"), "{load}");
    assert!(load.contains("name @rpath/libhelper.dylib"), "{load}");
    assert!(!load.contains("LC_MAIN"), "{load}");
    let header = Command::new("otool")
        .current_dir(dir)
        .args(["-hv", "libhelper.dylib"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&header.stdout).contains("DYLIB"),
        "{}",
        String::from_utf8_lossy(&header.stdout)
    );
    let sign = Command::new("codesign")
        .current_dir(dir)
        .args(["-v", "libhelper.dylib"])
        .status()
        .unwrap();
    assert!(sign.success());

    compile(
        dir,
        "main",
        "#include <stdio.h>\nint helper(void);\nextern int other;\n\
         int main(void){printf(\"%d %d\\n\",helper(),other);return 0;}\n",
    );
    weld(
        dir,
        &[
            "main.o",
            "-L.",
            "-lhelper",
            "-lSystem",
            "-rpath",
            "@executable_path",
            "-o",
            "main",
        ],
    );
    assert_eq!(run(dir, "main"), "7 5\n");
}

#[test]
fn dylib_from_weld_opens_with_dlopen() {
    let guard = TempDir::new("weld-macho-dlopen");
    let dir = guard.path();
    weld_dylib(dir);
    fs::write(
        dir.join("open.c"),
        r#"#include <dlfcn.h>
#include <stdio.h>
int main(void) {
    void *h = dlopen("./libhelper.dylib", RTLD_NOW);
    if (!h) { printf("%s\n", dlerror()); return 1; }
    int (*helper)(void) = (int (*)(void))dlsym(h, "helper");
    int *other = (int *)dlsym(h, "other");
    if (!helper || !other) { printf("missing symbol\n"); return 1; }
    printf("%d %d\n", helper(), *other);
    return 0;
}
"#,
    )
    .unwrap();
    let status = Command::new("clang")
        .current_dir(dir)
        .args(["open.c", "-o", "open"])
        .status()
        .unwrap();
    assert!(status.success());
    let output = Command::new(dir.join("open"))
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "7 5\n");
}
