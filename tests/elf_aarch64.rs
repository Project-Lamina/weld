#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

mod common;
use common::TempDir;
use std::{fs, path::Path, process::Command, process::Output};

const GCC: &str = "aarch64-linux-gnu-gcc";
const SYSROOT: &str = "/usr/aarch64-linux-gnu";

fn output_of(program: &str, args: &[&str], dir: &Path) -> Output {
    Command::new(program)
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap()
}

fn run(program: &str, args: &[&str], dir: &Path) -> String {
    let result = output_of(program, args, dir);
    assert!(
        result.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8_lossy(&result.stdout).into_owned()
}

fn toolchain_file(name: &str) -> String {
    run(GCC, &[&format!("--print-file-name={name}")], Path::new("/"))
        .trim()
        .to_string()
}

/// The command line lamina hands a linker for an aarch64 Linux executable.
fn link_args<'a>(object: &'a str, out: &'a str, crt: &'a [String]) -> Vec<String> {
    let mut args: Vec<String> = ["-m", "aarch64linux", "--dynamic-linker"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    args.push("/lib/ld-linux-aarch64.so.1".into());
    args.push(crt[0].clone());
    args.push(crt[1].clone());
    args.push(object.into());
    args.push(crt[2].clone());
    for flag in ["-e", "_start", "-lc"] {
        args.push(flag.into());
    }
    args.push(crt[3].clone());
    args.push("-o".into());
    args.push(out.into());
    args
}

fn crt_objects() -> Vec<String> {
    ["crt1.o", "crti.o", "crtn.o", "libgcc.a"]
        .iter()
        .map(|name| toolchain_file(name))
        .collect()
}

fn compile(dir: &Path, name: &str, source: &str, flags: &[&str]) -> String {
    fs::write(dir.join(format!("{name}.c")), source).unwrap();
    let object = format!("{name}.o");
    let mut args: Vec<&str> = flags.to_vec();
    let c = format!("{name}.c");
    args.extend(["-c", &c, "-o", &object]);
    run(GCC, &args, dir);
    object
}

fn link_with(linker: &str, dir: &Path, object: &str, out: &str) -> Output {
    let crt = crt_objects();
    let args = link_args(object, out, &crt);
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    output_of(linker, &borrowed, dir)
}

fn weld_link(dir: &Path, object: &str, out: &str) {
    let result = link_with(env!("CARGO_BIN_EXE_weld"), dir, object, out);
    assert!(
        result.status.success(),
        "weld refused {object}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn emulate(dir: &Path, binary: &str) -> String {
    run(
        "qemu-aarch64-static",
        &["-L", SYSROOT, &format!("./{binary}")],
        dir,
    )
}

const PRINTS_SUM: &str = r#"
#include <stdio.h>
int table[4] = {1, 2, 3, 4};
int sum(void) { int s = 0; for (int i = 0; i < 4; i++) s += table[i]; return s; }
int main(void) { printf("%d %d\n", sum(), table[2]); return 0; }
"#;

const THREAD_LOCAL: &str = r#"
#include <stdio.h>
__thread int counter = 7;
int main(void) { counter += 5; printf("%d\n", counter); return 0; }
"#;

#[test]
fn calls_into_libc_run_through_a_bind_now_plt() {
    let guard = TempDir::new("weld-aarch64-plt");
    let dir = guard.path();
    let object = compile(dir, "plt", PRINTS_SUM, &["-O1"]);
    weld_link(dir, &object, "output");
    assert_eq!(emulate(dir, "output"), "10 3\n");

    let relocations = run("aarch64-linux-gnu-readelf", &["-rW", "output"], dir);
    assert!(relocations.contains("R_AARCH64_JUMP_SLOT"), "{relocations}");
    for name in ["printf", "__libc_start_main"] {
        assert!(
            relocations
                .lines()
                .any(|line| line.contains("R_AARCH64_JUMP_SLOT") && line.contains(name)),
            "no JUMP_SLOT for {name}: {relocations}"
        );
    }
    let dynamic = run("aarch64-linux-gnu-readelf", &["-dW", "output"], dir);
    assert!(dynamic.contains("BIND_NOW"), "{dynamic}");
}

/// PLT0 is the lazy resolver stub elsewhere. weld binds eagerly and never
/// reaches it, so it must trap rather than run whatever happens to be there.
#[test]
fn the_first_plt_slot_traps_instead_of_resolving_lazily() {
    let guard = TempDir::new("weld-aarch64-plt0");
    let dir = guard.path();
    let object = compile(dir, "plt0", PRINTS_SUM, &["-O1"]);
    weld_link(dir, &object, "output");
    let disassembly = run(
        "aarch64-linux-gnu-objdump",
        &["-d", "--section=.plt", "output"],
        dir,
    );
    let instructions: Vec<&str> = disassembly
        .lines()
        .filter_map(|line| line.splitn(3, '\t').nth(2))
        .collect();
    assert_eq!(&instructions[..4], &["brk\t#0x0"; 4], "{disassembly}");
    assert!(instructions[4].starts_with("adrp"), "{disassembly}");
    assert_eq!(instructions[7], "br\tx17", "{disassembly}");
}

#[test]
fn a_got_page_pair_reaches_a_defined_symbol() {
    let guard = TempDir::new("weld-aarch64-got");
    let dir = guard.path();
    let object = compile(dir, "got", PRINTS_SUM, &["-O1", "-fPIC", "-fno-plt"]);
    let relocations = run("aarch64-linux-gnu-readelf", &["-rW", &object], dir);
    assert!(
        relocations.contains("R_AARCH64_ADR_GOT_PAGE"),
        "{relocations}"
    );
    weld_link(dir, &object, "output");
    assert_eq!(emulate(dir, "output"), "10 3\n");
}

#[test]
fn local_exec_thread_locals_match_ld() {
    let guard = TempDir::new("weld-aarch64-tls-le");
    let dir = guard.path();
    let object = compile(dir, "le", THREAD_LOCAL, &["-O1", "-ftls-model=local-exec"]);
    let relocations = run("aarch64-linux-gnu-readelf", &["-rW", &object], dir);
    assert!(
        relocations.contains("R_AARCH64_TLSLE_ADD_TPREL_HI12"),
        "{relocations}"
    );
    weld_link(dir, &object, "output");
    assert_eq!(emulate(dir, "output"), "12\n");

    let reference = link_with("aarch64-linux-gnu-ld", dir, &object, "reference");
    assert!(reference.status.success());
    assert_eq!(emulate(dir, "reference"), "12\n");
    assert_eq!(
        thread_pointer_adds(dir, "output"),
        thread_pointer_adds(dir, "reference")
    );
}

#[test]
fn initial_exec_thread_locals_resolve_through_the_got() {
    let guard = TempDir::new("weld-aarch64-tls-ie");
    let dir = guard.path();
    let object = compile(
        dir,
        "ie",
        THREAD_LOCAL,
        &["-O1", "-fPIC", "-ftls-model=initial-exec"],
    );
    let relocations = run("aarch64-linux-gnu-readelf", &["-rW", &object], dir);
    assert!(
        relocations.contains("R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21"),
        "{relocations}"
    );
    weld_link(dir, &object, "output");
    assert_eq!(emulate(dir, "output"), "12\n");
}

/// Immediates of every `add` that follows a read of the thread pointer, which
/// is how the thread-pointer offset reaches the code.
fn thread_pointer_adds(dir: &Path, binary: &str) -> Vec<String> {
    let text = run("aarch64-linux-gnu-objdump", &["-d", binary], dir);
    let mut adds = Vec::new();
    let mut after_tpidr = false;
    for line in text.lines() {
        let Some(instruction) = line.splitn(3, '\t').nth(2) else {
            continue;
        };
        if instruction.contains("tpidr_el0") {
            after_tpidr = true;
        } else if after_tpidr && instruction.starts_with("add\t") {
            adds.push(instruction.to_string());
        } else if !instruction.starts_with("add\t") {
            after_tpidr = false;
        }
    }
    assert!(!adds.is_empty(), "{text}");
    adds
}

#[test]
fn global_dynamic_thread_locals_are_refused_by_relocation_name() {
    let guard = TempDir::new("weld-aarch64-tls-gd");
    let dir = guard.path();
    let object = compile(
        dir,
        "gd",
        THREAD_LOCAL,
        &["-O1", "-fPIC", "-ftls-model=global-dynamic"],
    );
    let refused = link_with(env!("CARGO_BIN_EXE_weld"), dir, &object, "output");
    assert!(!refused.status.success());
    let message = String::from_utf8_lossy(&refused.stderr);
    assert!(message.contains("R_AARCH64_TLSDESC_"), "{message}");
    assert!(message.contains("counter"), "{message}");
}

#[test]
fn shared_objects_are_refused_for_aarch64() {
    let guard = TempDir::new("weld-aarch64-shared");
    let dir = guard.path();
    let object = compile(dir, "shared", PRINTS_SUM, &["-O1", "-fPIC"]);
    let refused = output_of(
        env!("CARGO_BIN_EXE_weld"),
        &["-m", "aarch64linux", "-shared", &object, "-o", "out.so"],
        dir,
    );
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("-shared is not supported for AArch64"),
    );
}
