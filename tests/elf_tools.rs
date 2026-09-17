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
        "{program}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        result.stderr.is_empty(),
        "{program}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}

#[test]
fn elf_tools_agree_with_ld_on_defined_symbols() {
    let dir = std::env::temp_dir().join(format!("weld-elf-tools-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("input.s"), ".file \"input.s\"\n.text\n.globl _start\n.type _start,@function\n_start:\n mov $60,%eax\n xor %edi,%edi\n syscall\n.size _start,.-_start\n.local helper\n.type helper,@function\nhelper: ret\n.size helper,.-helper\n.section .rodata\nmessage: .asciz \"hello\"\n.data\n.globl value\n.type value,@object\nvalue: .quad 42\n.size value,8\n.bss\n.balign 16\n.weak buffer\n.type buffer,@object\nbuffer: .skip 4096\n.size buffer,4096\n.globl absolute\n.set absolute,123\n").unwrap();
    fs::write(dir.join("layout.ld"), "SECTIONS { . = 0x400000; .text : { *(.text) } .rodata : { *(.rodata) } .data : { *(.data) } .bss : { *(.bss) } }").unwrap();
    run("as", &["input.s", "-o", "input.o"], &dir);
    run(env!("CARGO_BIN_EXE_weld"), &["input.o", "-o", "weld"], &dir);
    run(
        "ld",
        &[
            "--no-warn-rwx-segments",
            "-T",
            "layout.ld",
            "input.o",
            "-o",
            "reference",
        ],
        &dir,
    );
    let sections = run("readelf", &["-SW", "weld"], &dir);
    assert!(sections.contains(".bss") && sections.contains("NOBITS"));
    assert!(
        sections.contains(".symtab")
            && sections.contains(".strtab")
            && sections.contains(".shstrtab")
    );
    let symbols = |file| {
        let text = run("readelf", &["-sW", file], &dir);
        let mut rows: Vec<_> = text
            .lines()
            .filter_map(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                (fields.len() == 8 && fields[0].ends_with(':'))
                    .then(|| (fields[7].to_string(), fields[1..6].join(" ")))
            })
            .collect();
        rows.sort();
        rows
    };
    assert_eq!(symbols("weld"), symbols("reference"));
    assert!(run("objdump", &["-d", "weld"], &dir).contains("<_start>:"));
    let data = fs::read(dir.join("weld")).unwrap();
    let number = |offset| u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
    assert!(number(64 + 32) < number(64 + 40));
    assert!(Command::new(dir.join("weld")).status().unwrap().success());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn as_needed_tracks_state_and_deduplicates_sonames() {
    let dir = std::env::temp_dir().join(format!("weld-needed-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("used.s"),
        ".globl used\n.type used,@function\nused: ret\n",
    )
    .unwrap();
    fs::write(
        dir.join("unused.s"),
        ".globl unused\n.type unused,@function\nunused: ret\n",
    )
    .unwrap();
    fs::write(
        dir.join("main.s"),
        ".globl _start\n_start: call used\n mov $60,%eax\n xor %edi,%edi\n syscall\n",
    )
    .unwrap();
    for name in ["used", "unused", "main"] {
        run(
            "as",
            &[&format!("{name}.s"), "-o", &format!("{name}.o")],
            &dir,
        );
    }
    for name in ["used", "unused"] {
        run(
            "ld",
            &[
                "-shared",
                "-soname",
                &format!("lib{name}.so"),
                &format!("{name}.o"),
                "-o",
                &format!("lib{name}.so"),
            ],
            &dir,
        );
    }
    for (flags, expected) in [
        (
            vec!["--as-needed", "-lunused", "-lused", "-lused"],
            vec!["libused.so"],
        ),
        (
            vec![
                "--as-needed",
                "--push-state",
                "--no-as-needed",
                "-lunused",
                "--pop-state",
                "-lused",
            ],
            vec!["libunused.so", "libused.so"],
        ),
    ] {
        let mut args = vec!["main.o", "-L."];
        args.extend(flags);
        args.extend(["-o", "output"]);
        for linker in [env!("CARGO_BIN_EXE_weld"), "ld"] {
            run(linker, &args, &dir);
            let dynamic = run("readelf", &["-dW", "output"], &dir);
            let needed: Vec<_> = dynamic
                .lines()
                .filter(|s| s.contains("(NEEDED)"))
                .map(|s| s.split('[').nth(1).unwrap().trim_end_matches(']'))
                .collect();
            assert_eq!(needed, expected);
        }
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn gc_follows_relocations_and_prunes_unwind_records() {
    let dir = std::env::temp_dir().join(format!("weld-gc-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("input.c"), "int live_data=42; int dead_data[4096]={1}; __attribute__((noinline)) int live(void){return live_data;} __attribute__((noinline)) int dead(void){return dead_data[0];} int main(void){return live()!=42;}").unwrap();
    run(
        "gcc",
        &[
            "-O0",
            "-fno-pie",
            "-ffunction-sections",
            "-fdata-sections",
            "-c",
            "input.c",
            "-o",
            "input.o",
        ],
        &dir,
    );
    let linker = env!("CARGO_BIN_EXE_weld");
    run(linker, &["input.o", "-lc", "-o", "full"], &dir);
    run(
        linker,
        &["input.o", "-lc", "--gc-sections", "-o", "gc"],
        &dir,
    );
    assert!(Command::new(dir.join("gc")).status().unwrap().success());
    let symbols = run("readelf", &["-sW", "gc"], &dir);
    assert!(symbols.contains("live_data"));
    assert!(!symbols.contains("dead"));
    let frames = run("readelf", &["--debug-dump=frames", "gc"], &dir);
    assert_eq!(frames.matches(" FDE ").count(), 2);
    assert!(
        fs::metadata(dir.join("gc")).unwrap().len() + 16000
            < fs::metadata(dir.join("full")).unwrap().len()
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn strip_preserves_dynamic_symbols_and_map_retains_definitions() {
    let dir = std::env::temp_dir().join(format!("weld-strip-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("main.c"),
        "#include <stdio.h>\nint main(void){puts(\"hello\");return 0;}\n",
    )
    .unwrap();
    run("gcc", &["-fno-pie", "-c", "main.c", "-o", "main.o"], &dir);
    for flag in ["-s", "--strip-all"] {
        run(
            env!("CARGO_BIN_EXE_weld"),
            &["main.o", "-lc", flag, "--Map=output.map", "-o", "output"],
            &dir,
        );
        let sections = run("readelf", &["-SW", "output"], &dir);
        assert!(sections.contains(".dynsym") && sections.contains(".dynstr"));
        assert!(!sections.contains(".symtab") && !sections.contains(" .strtab"));
        let map = fs::read_to_string(dir.join("output.map")).unwrap();
        assert!(map.contains("main") && map.contains(".text") && map.contains("Entry point"));
        assert_eq!(
            run(dir.join("output").to_str().unwrap(), &[], &dir),
            "hello\n"
        );
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn parallel_loading_preserves_local_symbols_and_archive_selection() {
    let dir = std::env::temp_dir().join(format!("weld-parallel-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let mut names = Vec::new();
    for i in 0..40 {
        let next = if i == 39 {
            "archive_fn".into()
        } else {
            format!("chain{}", i + 1)
        };
        let start = if i == 0 {
            ".globl _start\n_start: call chain0\n mov %eax,%edi\n mov $60,%eax\n syscall\n"
        } else {
            ""
        };
        fs::write(dir.join("input.s"), format!(".text\n{start}.globl chain{i}\nchain{i}: lea private(%rip),%r11\n call {next}\n ret\n.data\nprivate: .quad {i}\n")).unwrap();
        let name = format!("input{i}.o");
        run("as", &["input.s", "-o", &name], &dir);
        names.push(name);
    }
    for (name, source) in [
        (
            "used",
            ".globl archive_fn\narchive_fn: xor %eax,%eax\n ret\n",
        ),
        ("unused", ".globl unreachable\nunreachable: ret\n"),
    ] {
        fs::write(dir.join("archive.s"), source).unwrap();
        run("as", &["archive.s", "-o", &format!("{name}.o")], &dir);
    }
    run("ar", &["rcs", "libinput.a", "used.o", "unused.o"], &dir);
    let mut args: Vec<_> = names.iter().map(String::as_str).collect();
    args.extend(["libinput.a", "-o", "output"]);
    run(env!("CARGO_BIN_EXE_weld"), &args, &dir);
    assert!(Command::new(dir.join("output")).status().unwrap().success());
    let symbols = run("readelf", &["-sW", "output"], &dir);
    assert!(symbols.contains("archive_fn") && !symbols.contains("unreachable"));
    assert_eq!(
        symbols.lines().filter(|s| s.ends_with(" private")).count(),
        40
    );
    fs::remove_dir_all(dir).unwrap();
}
