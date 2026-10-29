#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

mod common;
use common::TempDir;
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
    let guard = TempDir::new("weld-elf-tools");
    let dir = guard.path();
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("input.s"), ".file \"input.s\"\n.text\n.globl _start\n.type _start,@function\n_start:\n mov $60,%eax\n xor %edi,%edi\n syscall\n.size _start,.-_start\n.local helper\n.type helper,@function\nhelper: ret\n.size helper,.-helper\n.section .rodata\nmessage: .asciz \"hello\"\n.data\n.globl value\n.type value,@object\nvalue: .quad 42\n.size value,8\n.bss\n.balign 16\n.weak buffer\n.type buffer,@object\nbuffer: .skip 4096\n.size buffer,4096\n.globl absolute\n.set absolute,123\n").unwrap();
    fs::write(dir.join("layout.ld"), "SECTIONS { . = 0x400000; .text : { *(.text) } . = ALIGN(4096); .rodata : { *(.rodata) } . = ALIGN(4096); .data : { *(.data) } .bss : { *(.bss) } }").unwrap();
    run("as", &["input.s", "-o", "input.o"], dir);
    run(env!("CARGO_BIN_EXE_weld"), &["input.o", "-o", "weld"], dir);
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
        dir,
    );
    let sections = run("readelf", &["-SW", "weld"], dir);
    assert!(sections.contains(".bss") && sections.contains("NOBITS"));
    assert!(
        sections.contains(".symtab")
            && sections.contains(".strtab")
            && sections.contains(".shstrtab")
    );
    let symbols = |file| {
        let text = run("readelf", &["-sW", file], dir);
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
    assert!(run("objdump", &["-d", "weld"], dir).contains("<_start>:"));
    let data = fs::read(dir.join("weld")).unwrap();
    let number = |offset| u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
    let phnum = u16::from_le_bytes(data[56..58].try_into().unwrap()) as usize;
    assert!((0..phnum).any(|i| number(64 + i * 56 + 32) < number(64 + i * 56 + 40)));
    assert!(Command::new(dir.join("weld")).status().unwrap().success());
}

#[test]
fn as_needed_tracks_state_and_deduplicates_sonames() {
    let guard = TempDir::new("weld-needed");
    let dir = guard.path();
    fs::create_dir_all(dir).unwrap();
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
            dir,
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
            dir,
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
            run(linker, &args, dir);
            let dynamic = run("readelf", &["-dW", "output"], dir);
            let needed: Vec<_> = dynamic
                .lines()
                .filter(|s| s.contains("(NEEDED)"))
                .map(|s| s.split('[').nth(1).unwrap().trim_end_matches(']'))
                .collect();
            assert_eq!(needed, expected);
        }
    }
}

#[test]
fn gc_follows_relocations_and_prunes_unwind_records() {
    let guard = TempDir::new("weld-gc");
    let dir = guard.path();
    fs::create_dir_all(dir).unwrap();
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
        dir,
    );
    let linker = env!("CARGO_BIN_EXE_weld");
    run(linker, &["input.o", "-lc", "-o", "full"], dir);
    run(
        linker,
        &["input.o", "-lc", "--gc-sections", "-o", "gc"],
        dir,
    );
    assert!(Command::new(dir.join("gc")).status().unwrap().success());
    let symbols = run("readelf", &["-sW", "gc"], dir);
    assert!(symbols.contains("live_data"));
    assert!(!symbols.contains("dead"));
    let frames = run("readelf", &["--debug-dump=frames", "gc"], dir);
    assert_eq!(frames.matches(" FDE ").count(), 2);
    assert!(
        fs::metadata(dir.join("gc")).unwrap().len() + 16000
            < fs::metadata(dir.join("full")).unwrap().len()
    );
}

const MID_EH_FRAME_SOURCE: &str = r#".text
.globl _start
.type _start,@function
_start:
    call helper
    mov $60, %eax
    xor %edi, %edi
    syscall
_start_end:
.size _start, .-_start

.section .text.helper,"ax",@progbits
.type helper,@function
helper:
    ret
helper_end:
.size helper, .-helper

.section .text.pers,"ax",@progbits
.type pers,@function
pers:
    ret
.size pers, .-pers

.section .eh_frame,"a",@progbits
cie1:
    .long cie1_end - cie1_body
cie1_body:
    .long 0
    .byte 1
    .asciz "zR"
    .uleb128 1
    .sleb128 -8
    .uleb128 16
    .uleb128 1
    .byte 0x1b
    .byte 0x0c, 7, 8, 0x90, 1
    .balign 8
cie1_end:
fde1:
    .long fde1_end - fde1_body
fde1_body:
    .long fde1_body - cie1
    .long _start - .
    .long _start_end - _start
    .uleb128 0
    .balign 8
fde1_end:
    .long 0
cie2:
    .long cie2_end - cie2_body
cie2_body:
    .long 0
    .byte 1
    .asciz "zPR"
    .uleb128 1
    .sleb128 -8
    .uleb128 16
    .uleb128 10
    .byte 0
    .quad pers
    .byte 0x1b
    .byte 0x0c, 7, 8
    .balign 8
cie2_end:
fde2:
    .long fde2_end - fde2_body
fde2_body:
    .long fde2_body - cie2
    .long helper - .
    .long helper_end - helper
    .uleb128 0
    .balign 8
fde2_end:
.section .note.GNU-stack,"",@progbits
"#;

#[test]
fn gc_scans_records_after_an_eh_frame_terminator() {
    let guard = TempDir::new("weld-gc-eh");
    let dir = guard.path();
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("mid.s"), MID_EH_FRAME_SOURCE).unwrap();
    fs::write(
        dir.join("tail.c"),
        "__attribute__((noinline)) int leaf(int x) { return x + 1; }\nint tail_entry(int x) { return leaf(x) * 2; }\n",
    )
    .unwrap();
    run("as", &["mid.s", "-o", "mid.o"], dir);
    run(
        "gcc",
        &["-c", "-O0", "-fno-pie", "tail.c", "-o", "tail.o"],
        dir,
    );
    run(
        env!("CARGO_BIN_EXE_weld"),
        &["mid.o", "tail.o", "--gc-sections", "-o", "output"],
        dir,
    );
    assert!(Command::new(dir.join("output")).status().unwrap().success());
    let symbols = run("nm", &["output"], dir);
    assert!(symbols.contains(" helper") && symbols.contains(" pers"));
    let frames = run("readelf", &["--debug-dump=frames", "output"], dir);
    assert_eq!(frames.matches(" FDE ").count(), 2);
}

#[test]
fn strip_preserves_dynamic_symbols_and_map_retains_definitions() {
    let guard = TempDir::new("weld-strip");
    let dir = guard.path();
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("main.c"),
        "#include <stdio.h>\nint main(void){puts(\"hello\");return 0;}\n",
    )
    .unwrap();
    run("gcc", &["-fno-pie", "-c", "main.c", "-o", "main.o"], dir);
    for flag in ["-s", "--strip-all"] {
        run(
            env!("CARGO_BIN_EXE_weld"),
            &["main.o", "-lc", flag, "--Map=output.map", "-o", "output"],
            dir,
        );
        let sections = run("readelf", &["-SW", "output"], dir);
        assert!(sections.contains(".dynsym") && sections.contains(".dynstr"));
        assert!(!sections.contains(".symtab") && !sections.contains(" .strtab"));
        let map = fs::read_to_string(dir.join("output.map")).unwrap();
        assert!(map.contains("main") && map.contains(".text") && map.contains("Entry point"));
        assert_eq!(
            run(dir.join("output").to_str().unwrap(), &[], dir),
            "hello\n"
        );
    }
}

#[test]
fn parallel_loading_preserves_local_symbols_and_archive_selection() {
    let guard = TempDir::new("weld-parallel");
    let dir = guard.path();
    fs::create_dir_all(dir).unwrap();
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
        run("as", &["input.s", "-o", &name], dir);
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
        run("as", &["archive.s", "-o", &format!("{name}.o")], dir);
    }
    run("ar", &["rcs", "libinput.a", "used.o", "unused.o"], dir);
    let mut args: Vec<_> = names.iter().map(String::as_str).collect();
    args.extend(["libinput.a", "-o", "output"]);
    run(env!("CARGO_BIN_EXE_weld"), &args, dir);
    assert!(Command::new(dir.join("output")).status().unwrap().success());
    let symbols = run("readelf", &["-sW", "output"], dir);
    assert!(symbols.contains("archive_fn") && !symbols.contains("unreachable"));
    assert_eq!(
        symbols.lines().filter(|s| s.ends_with(" private")).count(),
        40
    );
}

#[test]
fn nobits_boundary_symbols_follow_dynamic_layout() {
    let guard = TempDir::new("weld-nobits-end");
    let dir = guard.path();
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("start.s"), ".globl _start\n_start: lea buffer_end(%rip),%rax\n lea buffer(%rip),%rdx\n sub %rdx,%rax\n cmp $4096,%rax\n setne %dil\n movzbl %dil,%edi\n mov $60,%eax\n syscall\n").unwrap();
    fs::write(
        dir.join("data.s"),
        ".bss\n.balign 16\n.globl buffer\nbuffer: .skip 4096\n.globl buffer_end\nbuffer_end:\n",
    )
    .unwrap();
    for name in ["start", "data"] {
        run(
            "as",
            &[&format!("{name}.s"), "-o", &format!("{name}.o")],
            dir,
        );
    }
    run(
        env!("CARGO_BIN_EXE_weld"),
        &["start.o", "data.o", "-lc", "-o", "output"],
        dir,
    );
    assert!(Command::new(dir.join("output")).status().unwrap().success());
    let symbols = run("readelf", &["-sW", "output"], dir);
    let address = |name: &str| {
        let line = symbols
            .lines()
            .find(|s| s.ends_with(&format!(" {name}")))
            .unwrap();
        u64::from_str_radix(line.split_whitespace().nth(1).unwrap(), 16).unwrap()
    };
    assert_eq!(address("buffer_end") - address("buffer"), 4096);
}

#[test]
fn as_needed_counts_archive_members_and_retained_dso_references() {
    let guard = TempDir::new("weld-needed-origins");
    let dir = guard.path();
    fs::create_dir_all(dir).unwrap();
    for (name, source) in [
        (
            "main",
            ".globl _start\n_start: call entry\n mov $60,%eax\n xor %edi,%edi\n syscall\n",
        ),
        ("first", ".globl entry\nentry: call internal\n ret\n"),
        (
            "second",
            ".globl internal\ninternal: call dependency\n ret\n",
        ),
        ("late", ".globl late\nlate: ret\n"),
        ("provider", ".globl dependency\ndependency: ret\n"),
        ("shared", ".globl entry\nentry: call dependency\n ret\n"),
    ] {
        fs::write(dir.join("input.s"), source).unwrap();
        run("as", &["input.s", "-o", &format!("{name}.o")], dir);
    }
    run("ar", &["rcs", "libarchive.a", "first.o", "second.o"], dir);
    run(
        "ld",
        &[
            "-shared",
            "-soname",
            "libprovider.so",
            "provider.o",
            "-o",
            "libprovider.so",
        ],
        dir,
    );
    run(
        "ld",
        &[
            "-shared",
            "-soname",
            "libshared.so",
            "shared.o",
            "-o",
            "libshared.so",
        ],
        dir,
    );
    for (input, expected) in [
        (
            vec![
                "main.o",
                "libarchive.a",
                "--as-needed",
                "-lprovider",
                "late.o",
            ],
            vec!["libprovider.so"],
        ),
        (
            vec!["main.o", "-larchive", "--as-needed", "-lprovider", "late.o"],
            vec!["libprovider.so"],
        ),
        (
            vec!["main.o", "--as-needed", "-lshared", "-lprovider"],
            vec!["libshared.so", "libprovider.so"],
        ),
    ] {
        let mut args = vec!["-L."];
        args.extend(input);
        args.extend(["-o", "output"]);
        for linker in [env!("CARGO_BIN_EXE_weld"), "ld"] {
            run(linker, &args, dir);
            let dynamic = run("readelf", &["-dW", "output"], dir);
            let needed: Vec<_> = dynamic
                .lines()
                .filter(|s| s.contains("(NEEDED)"))
                .map(|s| s.split('[').nth(1).unwrap().trim_end_matches(']'))
                .collect();
            assert_eq!(needed, expected);
        }
    }
}

#[test]
fn load_segments_enforce_wx_for_pie_exec_and_static() {
    let guard = TempDir::new("weld-segments");
    let dir = guard.path();
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("input.s"), ".text\n.globl _start\n_start: mov $60,%eax\n xor %edi,%edi\n syscall\n.section .init,\"ax\"\nret\n.section .fini,\"ax\"\nret\n.section .rodata\n.asciz \"constant\"\n.section .data.rel.ro,\"aw\"\n.quad _start\n.data\n.quad 42\n.bss\n.skip 8192\n").unwrap();
    run("as", &["input.s", "-o", "input.o"], dir);
    for flags in [vec!["-pie", "-lc"], vec!["-no-pie", "-lc"], vec!["-static"]] {
        let mut args = flags;
        args.extend(["input.o", "-o", "output"]);
        run(env!("CARGO_BIN_EXE_weld"), &args, dir);
        let bytes = fs::read(dir.join("output")).unwrap();
        let count = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
        let mut loads = 0;
        for header in bytes[64..64 + count * 56].as_chunks::<56>().0 {
            let kind = u32::from_le_bytes(header[..4].try_into().unwrap());
            let rights = u32::from_le_bytes(header[4..8].try_into().unwrap());
            if kind == 1 {
                loads += 1;
                assert_ne!(rights & 3, 3);
            }
        }
        assert!(loads >= 3);
        let headers = run("readelf", &["-lW", "output"], dir);
        assert!(headers.contains("GNU_RELRO"));
        let sections = run("readelf", &["-SW", "output"], dir);
        let address = |name: &str| {
            let row = sections
                .lines()
                .find(|line| line.split_whitespace().any(|field| field == name))
                .unwrap();
            let fields: Vec<_> = row.split_whitespace().collect();
            let position = fields.iter().position(|&field| field == name).unwrap();
            u64::from_str_radix(fields[position + 2], 16).unwrap()
        };
        assert!(address(".init") < address(".text"));
        assert!(address(".text") < address(".fini"));
        if sections
            .lines()
            .any(|line| line.split_whitespace().any(|field| field == ".plt"))
        {
            assert!(address(".init") < address(".plt") && address(".plt") < address(".text"));
        }

        assert!(Command::new(dir.join("output")).status().unwrap().success());
    }
}

#[test]
fn subsection_mapping_preserves_relocations_and_relro() {
    let guard = TempDir::new("weld-subsections");
    let dir = guard.path();
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("input.s"),
        r#"
.section .text.startup,"ax"
.globl _start
_start:
    call helper
    mov %eax,%edi
    mov $60,%eax
    syscall
.section .text.helper,"ax"
helper:
    mov value(%rip),%eax
    sub constant(%rip),%eax
    ret
.section .rodata.cst4,"aM",@progbits,4
constant: .long 42
.section .data.rel.local,"aw"
value: .long 42
.section .data.rel.ro.local,"aw"
.quad helper
.section .bss.buffer,"aw",@nobits
.skip 8192
"#,
    )
    .unwrap();
    run("as", &["input.s", "-o", "input.o"], dir);
    run(
        env!("CARGO_BIN_EXE_weld"),
        &["input.o", "-o", "output"],
        dir,
    );
    let sections = run("readelf", &["-SW", "output"], dir);
    for name in [
        ".text.startup",
        ".text.helper",
        ".rodata.cst4",
        ".data.rel.local",
        ".data.rel.ro.local",
        ".bss.buffer",
    ] {
        assert!(!sections.contains(name), "{sections}");
    }
    for name in [".text ", ".rodata ", ".data ", ".data.rel.ro ", ".bss "] {
        assert!(sections.contains(name), "{sections}");
    }
    assert!(Command::new(dir.join("output")).status().unwrap().success());
}

#[test]
fn merge_elements_deduplicate_strings_constants_and_interior_references() {
    let guard = TempDir::new("weld-merge-elements");
    let dir = guard.path();
    fs::create_dir_all(dir).unwrap();
    for (name, prefix) in [("first", ".asciz \"unique\"\n"), ("second", "")] {
        fs::write(
            dir.join(format!("{name}.s")),
            format!(
                r#"
.section .rodata.str1.1,"aMS",@progbits,1
{prefix}.globl {name}_string
{name}_string: .asciz "repeated string"
.Lduplicate: .asciz "repeated string"
.section .rodata.cst4,"aM",@progbits,4
.balign 4
.globl {name}_constant
{name}_constant: .long 123456
.long 123456
.section .rodata.str2.2,"aMS",@progbits,2
.balign 2
.globl {name}_wide
{name}_wide: .short 65,66,0
.section .data.rel.ro.{name},"aw"
.globl {name}_pointer
{name}_pointer: .quad .Lduplicate + 3
"#
            ),
        )
        .unwrap();
        run(
            "as",
            &[&format!("{name}.s"), "-o", &format!("{name}.o")],
            dir,
        );
    }
    fs::write(
        dir.join("start.s"),
        r#"
.text
.globl _start
_start:
    lea first_string(%rip),%rax
    lea second_string(%rip),%rdx
    cmp %rax,%rdx
    jne fail
    add $3,%rax
    cmp first_pointer(%rip),%rax
    jne fail
    cmp second_pointer(%rip),%rax
    jne fail
    cmpb $101,(%rax)
    jne fail
    lea first_constant(%rip),%rax
    lea second_constant(%rip),%rdx
    cmp %rax,%rdx
    jne fail
    cmpl $123456,(%rax)
    jne fail
    lea first_wide(%rip),%rax
    lea second_wide(%rip),%rdx
    cmp %rax,%rdx
    jne fail
    cmpw $66,2(%rax)
    jne fail
    xor %edi,%edi
    jmp exit
fail: mov $1,%edi
exit: mov $60,%eax
    syscall
"#,
    )
    .unwrap();
    run("as", &["start.s", "-o", "start.o"], dir);
    for flags in [vec!["-pie", "-lc"], vec!["-no-pie", "-lc"], vec!["-static"]] {
        let mut args = flags;
        args.extend(["start.o", "first.o", "second.o", "-o", "output"]);
        run(env!("CARGO_BIN_EXE_weld"), &args, dir);
        assert!(Command::new(dir.join("output")).status().unwrap().success());
        let sections = run("readelf", &["-SW", "output"], dir);
        let rodata = sections
            .lines()
            .find(|line| line.contains(".rodata "))
            .unwrap();
        assert!(rodata.contains("000022"), "{rodata}");
    }
}

#[test]
fn build_ids_hash_output_and_notes_survive_stripping() {
    let guard = TempDir::new("weld-notes");
    let dir = guard.path();
    fs::create_dir_all(dir).unwrap();
    for (name, features) in [("first", 3), ("second", 1)] {
        let text = if name == "first" {
            ".text\n.globl _start\n_start: endbr64\n mov $60,%eax\n xor %edi,%edi\n syscall\n"
        } else {
            ""
        };
        fs::write(
            dir.join(format!("{name}.s")),
            format!(
                r#"
{text}
.ident "compiler {name}"
.section .note.gnu.property,"a",@note
.balign 8
.long 4,32,5
.asciz "GNU"
.long 0xc0000002,4,{features},0
.long 0xc0008002,4,1,0
.section .note.ABI-tag,"a",@note
.balign 4
.long 4,16,1
.asciz "GNU"
.long 0,3,2,0
"#
            ),
        )
        .unwrap();
        run(
            "as",
            &[&format!("{name}.s"), "-o", &format!("{name}.o")],
            dir,
        );
    }
    let args = ["--build-id", "-s", "first.o", "second.o", "-o", "output"];
    run(env!("CARGO_BIN_EXE_weld"), &args, dir);
    let original = fs::read(dir.join("output")).unwrap();
    run(env!("CARGO_BIN_EXE_weld"), &args, dir);
    assert_eq!(original, fs::read(dir.join("output")).unwrap());
    let notes = run("readelf", &["-nW", "output"], dir);
    assert!(notes.contains("NT_GNU_ABI_TAG") && notes.contains("NT_GNU_BUILD_ID"));
    assert!(notes.contains("x86 feature: IBT") && !notes.contains("SHSTK"));
    let comments = run("readelf", &["-p", ".comment", "output"], dir);
    assert!(comments.contains("compiler first") && comments.contains("compiler second"));
    let headers = run("readelf", &["-lW", "output"], dir);
    assert!(headers.contains("GNU_PROPERTY"));
    let sections = run("readelf", &["-SW", "output"], dir);
    assert!(!sections.contains(".symtab"));
    let id = notes
        .lines()
        .find_map(|line| line.split_once("Build ID: ").map(|(_, id)| id.trim()))
        .unwrap();
    assert_eq!(id.len(), 40);
    let mut zeroed = original.clone();
    let descriptor: Vec<_> = (0..20)
        .map(|i| u8::from_str_radix(&id[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    let offset = zeroed.windows(20).position(|v| v == descriptor).unwrap();
    zeroed[offset..offset + 20].fill(0);
    fs::write(dir.join("zeroed"), zeroed).unwrap();
    assert_eq!(
        run("sha1sum", &["zeroed"], dir)
            .split_whitespace()
            .next()
            .unwrap(),
        id
    );
    assert!(Command::new(dir.join("output")).status().unwrap().success());
    fs::write(dir.join("bare.s"), ".data\n.quad 42\n").unwrap();
    run("as", &["bare.s", "-o", "bare.o"], dir);
    run(
        env!("CARGO_BIN_EXE_weld"),
        &[
            "--build-id=sha1",
            "first.o",
            "second.o",
            "bare.o",
            "-o",
            "output",
        ],
        dir,
    );
    let changed = run("readelf", &["-nW", "output"], dir);
    assert!(!changed.contains(id) && !changed.contains("x86 feature:"));
    run(
        env!("CARGO_BIN_EXE_weld"),
        &["--build-id", "--build-id=none", "first.o", "-o", "output"],
        dir,
    );
    assert!(!run("readelf", &["-nW", "output"], dir).contains("NT_GNU_BUILD_ID"));
    let result = Command::new(env!("CARGO_BIN_EXE_weld"))
        .args(["--build-id=unsupported", "first.o", "-o", "bad"])
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(!result.status.success() && !dir.join("bad").exists());
}

#[test]
fn output_locals_match_ld_for_merge_labels_and_section_symbols() {
    let guard = TempDir::new("weld-output-locals");
    let dir = guard.path();
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("input.s"),
        r#"
.file "input.s"
.text
.globl _start
_start: mov $60,%eax
    xor %edi,%edi
    syscall
.Ltext: .byte 0
.section .rodata
.Lro: .asciz "normal"
.section .rodata.str1.1,"aMS",@progbits,1
.Lmerge: .asciz "merged"
named: .asciz "named"
.data
.quad .rodata
.Ldata: .quad 0
"#,
    )
    .unwrap();
    run("as", &["-L", "input.s", "-o", "input.o"], dir);
    for (linker, output) in [(env!("CARGO_BIN_EXE_weld"), "output"), ("ld", "reference")] {
        run(linker, &["input.o", "-o", output], dir);
    }
    let locals = |file| {
        let text = run("readelf", &["-sW", file], dir);
        let mut result: Vec<_> = text
            .lines()
            .filter_map(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                (fields.len() == 8 && fields[4] == "LOCAL")
                    .then(|| (fields[3].to_owned(), fields[7].to_owned()))
            })
            .collect();
        result.sort();
        result
    };
    assert_eq!(locals("output"), locals("reference"));
}

#[test]
fn debug_sections_survive_linking_and_match_ld_line_tables() {
    let guard = TempDir::new("weld-debug-info");
    let dir = guard.path();
    fs::create_dir_all(dir.join("prefix")).unwrap();
    let _ = fs::remove_file(dir.join("prefix/ld"));
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_weld"), dir.join("prefix/ld")).unwrap();
    fs::write(
        dir.join("one.c"),
        "int other(int x);\nint total;\nint main(void) {\n  int t = 0;\n  for (int i = 0; i < 3; i++) {\n    t += other(i);\n  }\n  return t - 9;\n}\n",
    )
    .unwrap();
    fs::write(
        dir.join("two.c"),
        "extern int total;\nint other(int x) {\n  int y = x * 2;\n  total += y;\n  return y + 1;\n}\n",
    )
    .unwrap();

    for mode in ["-no-pie", "-pie"] {
        let pic = if mode == "-pie" { "-fPIE" } else { "-fno-pie" };
        run(
            "gcc",
            &["-g", "-O0", pic, "-c", "one.c", "-o", "one.o"],
            dir,
        );
        run(
            "gcc",
            &["-g", "-O0", pic, "-c", "two.c", "-o", "two.o"],
            dir,
        );
        run(
            "gcc",
            &[
                "-B", "prefix", mode, "-g", "one.o", "two.o", "-o", "weld-dbg",
            ],
            dir,
        );
        run("gcc", &[mode, "-g", "one.o", "two.o", "-o", "ld-dbg"], dir);

        let sections = run("readelf", &["-SW", "weld-dbg"], dir);
        for name in [".debug_info", ".debug_line", ".debug_abbrev", ".debug_str"] {
            assert!(sections.contains(name), "{mode}: {name} was dropped");
        }

        let image = fs::read(dir.join("weld-dbg")).unwrap();
        let number =
            |offset: usize| u64::from_le_bytes(image[offset..offset + 8].try_into().unwrap());
        let phnum = u16::from_le_bytes(image[56..58].try_into().unwrap()) as usize;
        let loads: Vec<(u64, u64)> = (0..phnum)
            .map(|i| 64 + i * 56)
            .filter(|&p| u32::from_le_bytes(image[p..p + 4].try_into().unwrap()) == 1)
            .map(|p| (number(p + 8), number(p + 32)))
            .collect();
        let shoff = number(40) as usize;
        let shnum = u16::from_le_bytes(image[60..62].try_into().unwrap()) as usize;
        let shstrndx = u16::from_le_bytes(image[62..64].try_into().unwrap()) as usize;
        let strings = number(shoff + shstrndx * 64 + 24) as usize;
        for i in 0..shnum {
            let header = shoff + i * 64;
            let start = strings
                + u32::from_le_bytes(image[header..header + 4].try_into().unwrap()) as usize;
            let end = start + image[start..].iter().position(|&b| b == 0).unwrap();
            let name = std::str::from_utf8(&image[start..end]).unwrap();
            if !name.starts_with(".debug_") {
                continue;
            }
            let (address, offset, size) = (
                number(header + 16),
                number(header + 24),
                number(header + 32),
            );
            assert_eq!(address, 0, "{mode}: {name} has an address");
            for (load_offset, load_size) in &loads {
                assert!(
                    offset >= load_offset + load_size || offset + size <= *load_offset,
                    "{mode}: {name} lies inside a PT_LOAD"
                );
            }
        }

        let lines = |file| {
            let text = run("readelf", &["--debug-dump=decodedline", file], dir);
            let mut rows: Vec<(String, String)> = text
                .lines()
                .filter_map(|line| {
                    let fields: Vec<_> = line.split_whitespace().collect();
                    (fields.len() >= 3 && fields[0].ends_with(".c") && fields[2].starts_with("0x"))
                        .then(|| (fields[0].to_string(), fields[1].to_string()))
                })
                .collect();
            rows.sort();
            rows
        };
        let rows = lines("weld-dbg");
        assert!(rows.len() > 10, "{mode}: line table is empty");
        assert!(
            rows.iter().any(|(file, _)| file == "one.c")
                && rows.iter().any(|(file, _)| file == "two.c"),
            "{mode}: only one input object reached the line table"
        );
        assert_eq!(
            rows,
            lines("ld-dbg"),
            "{mode}: line tables disagree with ld"
        );

        assert_eq!(
            Command::new(dir.join("weld-dbg"))
                .status()
                .unwrap()
                .code()
                .unwrap(),
            0
        );
    }
}

#[test]
fn gc_sections_refuses_debug_info_instead_of_zeroing_addresses() {
    let guard = TempDir::new("weld-gc-debug");
    let dir = guard.path();
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("one.c"),
        "int other(int x);\nint main(void) {\n  return other(21) * 2;\n}\n",
    )
    .unwrap();
    fs::write(dir.join("two.c"), "int other(int x) {\n  return x;\n}\n").unwrap();
    run("gcc", &["-g", "-O0", "-c", "one.c", "-o", "dbg1.o"], dir);
    run("gcc", &["-g", "-O0", "-c", "two.c", "-o", "dbg2.o"], dir);
    run("gcc", &["-O0", "-c", "one.c", "-o", "bare1.o"], dir);
    run("gcc", &["-O0", "-c", "two.c", "-o", "bare2.o"], dir);

    let link = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_weld"))
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap()
    };

    let refused = link(&["--gc-sections", "-o", "gc-dbg", "dbg1.o", "dbg2.o"]);
    assert!(
        !refused.status.success(),
        "gc with debug info linked anyway"
    );
    let message = String::from_utf8_lossy(&refused.stderr);
    assert!(message.contains("--gc-sections"), "{message}");
    assert!(
        !dir.join("gc-dbg").exists(),
        "a binary was written despite the refusal"
    );

    let bare = link(&["--gc-sections", "-o", "gc-bare", "bare1.o", "bare2.o"]);
    assert!(
        bare.status.success(),
        "gc without debug info: {}",
        String::from_utf8_lossy(&bare.stderr)
    );

    let kept = link(&["-o", "dbg-only", "dbg1.o", "dbg2.o"]);
    assert!(
        kept.status.success(),
        "debug info without gc: {}",
        String::from_utf8_lossy(&kept.stderr)
    );
    let lines = run("readelf", &["--debug-dump=decodedline", "dbg-only"], dir);
    assert!(
        lines.contains("0x4") || lines.contains("0x2"),
        "line table has no real addresses:\n{lines}"
    );
}
