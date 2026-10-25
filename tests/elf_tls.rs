#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::{fs, path::Path, process::Command};

fn run(program: &str, args: &[&str], dir: &Path) -> String {
    let result = Command::new(program)
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}

/// `(p_vaddr, p_filesz, p_memsz, p_align)` of the PT_TLS header.
fn pt_tls(dir: &Path, output: &str) -> Vec<u64> {
    let text = run("readelf", &["-lW", output], dir);
    let line = text
        .lines()
        .find(|line| line.trim_start().starts_with("TLS "))
        .unwrap_or_else(|| panic!("{output} has no PT_TLS:\n{text}"));
    let fields: Vec<&str> = line.split_whitespace().collect();
    [2, 4, 5, 7]
        .iter()
        .map(|&i| {
            let digits = fields[i].trim_start_matches("0x");
            u64::from_str_radix(digits, 16).unwrap()
        })
        .collect()
}

fn link_both(name: &str, sources: &[&str], cflags: &[&str]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("weld-tls-{name}-{}", std::process::id()));
    fs::create_dir_all(dir.join("drv")).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_weld"), dir.join("drv/ld")).unwrap();
    let mut objects = Vec::new();
    for (i, source) in sources.iter().enumerate() {
        let file = format!("unit{i}.c");
        fs::write(dir.join(&file), source).unwrap();
        let object = format!("unit{i}.o");
        let mut args = cflags.to_vec();
        args.extend(["-c", &file, "-o", &object]);
        run("gcc", &args, &dir);
        objects.push(object);
    }
    let mut ld_args = vec!["-no-pie"];
    ld_args.extend(objects.iter().map(String::as_str));
    ld_args.extend(["-o", "reference"]);
    run("gcc", &ld_args, &dir);
    let mut weld_args = vec!["-no-pie", "-B", "drv/"];
    weld_args.extend(objects.iter().map(String::as_str));
    weld_args.extend(["-o", "weld"]);
    run("gcc", &weld_args, &dir);
    dir
}

fn link_and_compare(name: &str, sources: &[&str]) {
    let dir = link_both(name, sources, &["-fno-pic"]);
    let weld = pt_tls(&dir, "weld");
    let reference = pt_tls(&dir, "reference");
    assert_eq!(
        weld[0] % weld[3],
        0,
        "PT_TLS vaddr is not aligned for {name}"
    );
    assert_eq!(
        weld[1..],
        reference[1..],
        "PT_TLS (filesz, memsz, align) for {name}"
    );
    fs::remove_dir_all(dir).unwrap();
}

fn compare_program_output(name: &str, sources: &[&str], cflags: &[&str]) -> String {
    let dir = link_both(name, sources, cflags);
    let expected = run("./reference", &[], &dir);
    assert_eq!(run("./weld", &[], &dir), expected, "{name} output");
    fs::remove_dir_all(dir).unwrap();
    expected
}

const DEFINITIONS: &str = "__thread int a = 1; __thread char b[3]; __thread long c __attribute__((aligned(32))); __thread short d = 4;";

const DECLARATIONS: &str = "extern __thread int a; extern __thread char b[3]; extern __thread long c; extern __thread short d;";

const PROBE_MAIN: &str = r#"
#include <stdio.h>
int main(void) {
    unsigned long tp;
    __asm__("movq %%fs:0, %0" : "=r"(tp));
    a += 1; c = 9; d += 2; b[2] = 'x';
    printf("%ld %ld %ld %ld %d %ld %d %d\n",
        (long)((char *)&a - (char *)tp), (long)((char *)b - (char *)tp),
        (long)((char *)&c - (char *)tp), (long)((char *)&d - (char *)tp),
        a, c, d, b[2]);
    return 0;
}
"#;

#[test]
fn pt_tls_sizes_and_alignment_match_ld_with_tdata_and_tbss() {
    link_and_compare(
        "mixed",
        &[
            "__thread int a = 1; __thread char b[3]; __thread long c __attribute__((aligned(32))); int main(void) { return 0; }",
        ],
    );
}

#[test]
fn pt_tls_matches_ld_for_bss_only_thread_locals() {
    link_and_compare(
        "tbss",
        &["__thread int z; __thread double w[5]; int main(void) { return 0; }"],
    );
}

#[test]
fn pt_tls_matches_ld_for_initialised_thread_locals_only() {
    link_and_compare(
        "tdata",
        &["__thread int init = 3; int main(void) { return 0; }"],
    );
}

#[test]
fn pt_tls_matches_ld_across_two_objects() {
    link_and_compare(
        "two-units",
        &[
            "__thread int x = 5; __thread char pad[7]; int main(void) { return 0; }",
            "__thread long y __attribute__((aligned(16))); __thread short s = 9;",
        ],
    );
}

#[test]
fn local_exec_offsets_from_thread_pointer_match_ld() {
    let source = format!("{DEFINITIONS}\n{PROBE_MAIN}");
    let output = compare_program_output("local-exec-one-unit", &[&source], &["-fno-pic"]);
    assert_eq!(output, "-96 -64 -32 -92 2 9 6 120\n");
}

#[test]
fn local_exec_offsets_hold_across_object_files_with_ld() {
    let probe = format!("{DECLARATIONS}\n{PROBE_MAIN}");
    let output = compare_program_output(
        "local-exec-two-units",
        &[DEFINITIONS, &probe],
        &["-fno-pic", "-ftls-model=local-exec"],
    );
    assert_eq!(output, "-96 -64 -32 -92 2 9 6 120\n");
}
