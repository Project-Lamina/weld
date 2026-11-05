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

/// Frame-based and frameless functions both need their compact unwind entries to walk.
/// The reference is the same objects linked by clang, so the count must match Apple's.
#[test]
fn unwind_info_lets_backtrace_walk_frames() {
    let guard = TempDir::new("weld-macho-unwind-info");
    let dir = guard.path();
    fs::write(
        dir.join("bt_main.c"),
        "#include <stdio.h>\nint leaf(int x);\nint middle(int x){return leaf(x)+1;}\n\
         int main(void){printf(\"frames=%d\\n\",leaf(0)+middle(0)*0);return 0;}\n",
    )
    .unwrap();
    fs::write(
        dir.join("bt_leaf.c"),
        "#include <execinfo.h>\nstatic int depth(void){void *b[32];return backtrace(b,32);}\n\
         int leaf(int x){return depth()+x;}\n",
    )
    .unwrap();
    for opt in ["-O0", "-O2"] {
        for name in ["bt_main", "bt_leaf"] {
            let status = Command::new("clang")
                .current_dir(dir)
                .args([opt, "-c", &format!("{name}.c"), "-o", &format!("{name}.o")])
                .status()
                .unwrap();
            assert!(status.success());
        }
        let reference = Command::new("clang")
            .current_dir(dir)
            .args(["bt_main.o", "bt_leaf.o", "-o", "bt_reference"])
            .status()
            .unwrap();
        assert!(reference.success());
        weld(
            dir,
            &["bt_main.o", "bt_leaf.o", "-lSystem", "-o", "bt_weld"],
        );
        let expected = run(dir, "bt_reference");
        assert_eq!(run(dir, "bt_weld"), expected, "{opt}");
        let frames: usize = expected
            .trim()
            .strip_prefix("frames=")
            .and_then(|n| n.parse().ok())
            .unwrap();
        assert!(frames >= 3, "{opt}: {expected}");
    }
}

const CXX_LIB: &str = r#"#include <stdio.h>
#include <stdexcept>
#include <string>
#include <vector>
struct Guard {
    std::string name;
    explicit Guard(const char *n) : name(n) { printf("enter %s\n", name.c_str()); }
    ~Guard() { printf("leave %s\n", name.c_str()); }
};
int deepest(int n) {
    Guard g("deepest");
    std::vector<int> v(n, 1);
    if (n > 2) throw std::runtime_error("too deep");
    return static_cast<int>(v.size());
}
int middle(int n) {
    Guard g("middle");
    std::string msg = "middle work";
    return deepest(n) + static_cast<int>(msg.size());
}
"#;

const CXX_MAIN: &str = r#"#include <stdio.h>
#include <stdexcept>
int middle(int n);
int rethrow_once(int n) {
    try { return middle(n); }
    catch (const std::logic_error &) { printf("logic\n"); return -1; }
    catch (...) { printf("rethrowing\n"); throw; }
}
int main() {
    try { printf("ok %d\n", middle(1)); } catch (const std::exception &e) { printf("caught1 %s\n", e.what()); }
    try { printf("ok %d\n", rethrow_once(5)); } catch (const std::runtime_error &e) { printf("caught2 %s\n", e.what()); }
    try { throw 42; } catch (int v) { printf("int %d\n", v); }
    return 0;
}
"#;

/// Exceptions thrown two frames down, with destructors running in the frames they unwind
/// through, rethrown by `catch (...)`, and caught by type and by `int`. The expected output
/// is what the same objects print when Apple's linker builds them.
#[test]
fn cpp_exceptions_unwind_across_frames() {
    let guard = TempDir::new("weld-macho-eh-unwind");
    let dir = guard.path();
    fs::write(dir.join("lib.cpp"), CXX_LIB).unwrap();
    fs::write(dir.join("main.cpp"), CXX_MAIN).unwrap();
    let expected = "enter middle\nenter deepest\nleave deepest\nleave middle\nok 12\n\
                    enter middle\nenter deepest\nleave deepest\nleave middle\nrethrowing\n\
                    caught2 too deep\nint 42\n";
    for opt in ["-O0", "-O2"] {
        for name in ["lib", "main"] {
            let status = Command::new("clang++")
                .current_dir(dir)
                .args([
                    opt,
                    "-c",
                    &format!("{name}.cpp"),
                    "-o",
                    &format!("{name}.o"),
                ])
                .status()
                .unwrap();
            assert!(status.success());
        }
        weld(dir, &["main.o", "lib.o", "-lc++", "-lSystem", "-o", "main"]);
        assert_eq!(run(dir, "main"), expected, "{opt}");
    }
}

#[test]
fn cpp_exceptions_without_a_library_are_refused_by_name() {
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
        .args(["main.o", "-o", "main"])
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
