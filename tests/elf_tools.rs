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
