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
