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
        "{program} {args:?}: status={} stderr={}",
        output.status,
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
fn cpp_constructors_exceptions_and_destructors() {
    let dir = std::env::temp_dir().join(format!("weld-cpp-runtime-{}", std::process::id()));
    fs::create_dir_all(dir.join("prefix")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("prefix/ld")).unwrap();
    fs::write(
        dir.join("input.cpp"),
        r#"
#include <cstdio>
#include <string>
#include <vector>
#include <stdexcept>
struct G { G(){ std::puts("ctor"); } ~G(){ std::puts("dtor"); } };
static G g;
int main() {
    std::vector<int> v;
    for (int i = 0; i < 10; ++i) v.push_back(i * i);
    int t = 0;
    for (int x : v) t += x;
    std::string s = "sum=" + std::to_string(t);
    try { if (t > 0) throw std::runtime_error("boom"); }
    catch (const std::exception& e) { s += " caught:"; s += e.what(); }
    std::puts(s.c_str());
    return t % 5;
}
"#,
    )
    .unwrap();
    let expected = "ctor\nsum=285 caught:boom\ndtor\n";
    for (mode, flags) in [
        ("-no-pie", "-fno-pic"),
        ("-no-pie", "-fPIC"),
        ("-pie", "-fPIE"),
        ("-pie", "-fPIC"),
    ] {
        run(
            "g++",
            &[mode, flags, "-c", "input.cpp", "-o", "input.o"],
            &dir,
        );
        run("g++", &[mode, "input.o", "-o", "reference"], &dir);
        run("g++", &[mode, "-Bprefix", "input.o", "-o", "output"], &dir);
        assert_eq!(run("./reference", &[], &dir), expected);
        assert_eq!(run("./output", &[], &dir), expected);
        let tags = run("readelf", &["-dW", "output"], &dir);
        for tag in [
            "(RELA)",
            "(RELASZ)",
            "(RELAENT)",
            "(INIT_ARRAY)",
            "(FINI_ARRAY)",
            "(INIT)",
            "(FINI)",
            "(VERSYM)",
            "(VERNEED)",
            "(VERNEEDNUM)",
            "(GNU_HASH)",
        ] {
            assert!(tags.contains(tag), "missing {tag}");
        }
        let headers = run("readelf", &["-lW", "output"], &dir);
        assert!(headers.contains("GNU_EH_FRAME") && headers.contains("GNU_RELRO"));
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn imported_data_pointers_and_version_requirements() {
    let dir = std::env::temp_dir().join(format!("weld-data-runtime-{}", std::process::id()));
    fs::create_dir_all(dir.join("prefix")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("prefix/ld")).unwrap();
    fs::write(
        dir.join("library.c"),
        "int value = 42; int get(void) { return value; }\n",
    )
    .unwrap();
    fs::write(
        dir.join("version.map"),
        "CHECK_1 { global: value; get; local: *; };\n",
    )
    .unwrap();
    fs::write(
        dir.join("input.c"),
        r#"
#include <stdio.h>
extern int value, get(void);
int *pointer = &value;
int main(void) {
    if (value != 42 || pointer != &value || *pointer != 42 || get() != 42) return 1;
    value = 73;
    printf("%d %d\n", *pointer, get());
    return *pointer != 73 || get() != 73;
}
"#,
    )
    .unwrap();
    run(
        "gcc",
        &[
            "-shared",
            "-fPIC",
            "library.c",
            "-Wl,--version-script=version.map",
            "-o",
            "libinput.so",
        ],
        &dir,
    );
    for (mode, flags) in [
        ("-no-pie", "-fno-pic"),
        ("-no-pie", "-fPIC"),
        ("-pie", "-fPIE"),
        ("-pie", "-fPIC"),
    ] {
        run(
            "gcc",
            &[
                mode,
                flags,
                "-Bprefix",
                "input.c",
                "-L.",
                "-linput",
                "-Wl,-rpath,$ORIGIN",
                "-o",
                "output",
            ],
            &dir,
        );
        assert_eq!(run("./output", &[], &dir), "73 73\n");
        let versions = run("readelf", &["-VW", "output"], &dir);
        assert!(versions.contains("CHECK_1"));
        let relocs = run("readelf", &["-rW", "output"], &dir);
        assert!(relocs.contains("R_X86_64_COPY") && relocs.contains("R_X86_64_64"));
        if flags == "-fPIC" {
            assert!(relocs.contains("R_X86_64_GLOB_DAT"));
        }
    }
    fs::write(
        dir.join("version.map"),
        "CHECK_2 { global: value; get; local: *; };\n",
    )
    .unwrap();
    run(
        "gcc",
        &[
            "-shared",
            "-fPIC",
            "library.c",
            "-Wl,--version-script=version.map",
            "-o",
            "libinput.so",
        ],
        &dir,
    );
    let output = Command::new(dir.join("output")).output().unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("CHECK_1") && error.contains("not found"),
        "{error}"
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn init_array_priorities_and_weak_got_entries() {
    let dir = std::env::temp_dir().join(format!("weld-init-runtime-{}", std::process::id()));
    fs::create_dir_all(dir.join("prefix")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("prefix/ld")).unwrap();
    fs::write(
        dir.join("input.c"),
        r#"
#include <stdio.h>
extern void absent(void) __attribute__((weak));
int state;
__attribute__((constructor(200))) static void later(void) { state = state * 10 + 2; }
__attribute__((constructor(101))) static void earlier(void) { state = state * 10 + 1; }
__attribute__((constructor)) static void last(void) { state = state * 10 + 3; }
__attribute__((destructor(200))) static void first_dtor(void) { puts("first dtor"); }
__attribute__((destructor(101))) static void last_dtor(void) { puts("last dtor"); }
int main(void) { if (absent || state != 123) return 1; printf("%d\n", state); return 0; }
"#,
    )
    .unwrap();
    for mode in ["-no-pie", "-pie"] {
        run("gcc", &[mode, "-Bprefix", "input.c", "-o", "output"], &dir);
        assert_eq!(run("./output", &[], &dir), "123\nfirst dtor\nlast dtor\n");
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn explicit_symbol_versions_select_nondefault_exports() {
    let dir = std::env::temp_dir().join(format!("weld-version-runtime-{}", std::process::id()));
    fs::create_dir_all(dir.join("prefix")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("prefix/ld")).unwrap();
    fs::write(
        dir.join("library.c"),
        r#"
int old(void) { return 12; }
int current(void) { return 34; }
__asm__(".symver old,number@CHECK_1");
__asm__(".symver current,number@@CHECK_2");
"#,
    )
    .unwrap();
    fs::write(dir.join("version.map"), "CHECK_1 {}; CHECK_2 {} CHECK_1;\n").unwrap();
    fs::write(
        dir.join("input.c"),
        r#"
#include <stdio.h>
extern int old(void), number(void);
__asm__(".symver old,number@CHECK_1");
int main(void) { printf("%d %d\n", old(), number()); return old() != 12 || number() != 34; }
"#,
    )
    .unwrap();
    run(
        "gcc",
        &[
            "-shared",
            "-fPIC",
            "library.c",
            "-Wl,--version-script=version.map",
            "-o",
            "libinput.so",
        ],
        &dir,
    );
    run(
        "gcc",
        &[
            "-no-pie",
            "-Bprefix",
            "input.c",
            "-L.",
            "-linput",
            "-Wl,-rpath,$ORIGIN",
            "-o",
            "output",
        ],
        &dir,
    );
    assert_eq!(run("./output", &[], &dir), "12 34\n");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn read_only_table_of_imported_function_pointers_is_relocated_in_place() {
    let dir = std::env::temp_dir().join(format!("weld-rodata-runtime-{}", std::process::id()));
    fs::create_dir_all(dir.join("prefix")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("prefix/ld")).unwrap();
    fs::write(
        dir.join("input.c"),
        r#"
#include <stdio.h>
typedef int (*printer)(const char *);
int wrapped(const char *s) { return printf("[%s]\n", s); }
static const printer table[] = { puts, wrapped, 0 };
const char *const names[] = { "alpha", "beta" };
int main(int argc, char **argv) {
    table[argc - 1]("from table");
    printf("%s\n", names[argc - 1]);
    return 0;
}
"#,
    )
    .unwrap();
    run(
        "gcc",
        &["-no-pie", "-fno-pic", "-c", "input.c", "-o", "input.o"],
        &dir,
    );
    run("gcc", &["-no-pie", "input.o", "-o", "reference"], &dir);
    run(
        "gcc",
        &["-no-pie", "-Bprefix", "input.o", "-o", "output"],
        &dir,
    );
    assert_eq!(run("./reference", &[], &dir), "from table\nalpha\n");
    assert_eq!(run("./output", &[], &dir), "from table\nalpha\n");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn imported_data_alias_shares_copy_relocation() {
    let dir = std::env::temp_dir().join(format!("weld-alias-runtime-{}", std::process::id()));
    fs::create_dir_all(dir.join("prefix")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("prefix/ld")).unwrap();
    fs::write(
        dir.join("input.c"),
        r#"
#include <stdio.h>
extern char **environ;
extern char **__environ;
int main(void) {
    printf("%d %d\n", environ != 0, environ == __environ);
    return 0;
}
"#,
    )
    .unwrap();
    run(
        "gcc",
        &["-no-pie", "-fno-pic", "-c", "input.c", "-o", "input.o"],
        &dir,
    );
    run("gcc", &["-no-pie", "input.o", "-o", "reference"], &dir);
    run(
        "gcc",
        &["-no-pie", "-Bprefix", "input.o", "-o", "output"],
        &dir,
    );
    assert_eq!(run("./reference", &[], &dir), "1 1\n");
    assert_eq!(run("./output", &[], &dir), "1 1\n");
    fs::remove_dir_all(dir).unwrap();
}
