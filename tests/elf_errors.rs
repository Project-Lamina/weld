#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::{fs, os::unix::fs::symlink, process::Command};

#[test]
fn rejects_lto_and_unresolved_symbols_before_emission() {
    let dir = std::env::temp_dir().join(format!("weld-errors-{}", std::process::id()));
    fs::create_dir_all(dir.join("drv")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("drv/ld")).unwrap();
    for (source, flags, diagnostic) in [
        (
            "int main(void) { return 0; }",
            vec!["-flto"],
            "LTO is not supported",
        ),
        (
            "extern int missing(void); int main(void) { return missing(); }",
            vec![],
            "undefined symbol missing",
        ),
        (
            "int other(void) { return 0; }",
            vec![],
            "undefined symbol main",
        ),
        (
            "extern int missing; int main(void) { return missing; }",
            vec!["-no-pie"],
            "undefined symbol missing",
        ),
        (
            "extern int missing(void); int main(void) { return missing(); }",
            vec!["-nostdlib", "-no-pie"],
            "undefined symbol missing",
        ),
    ] {
        fs::write(dir.join("input.c"), source).unwrap();
        let output = Command::new("gcc")
            .current_dir(&dir)
            .args(["-Bdrv", "input.c", "-o", "output"])
            .args(flags)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{stderr}");
        assert!(stderr.contains(diagnostic), "{stderr}");
        assert!(!dir.join("output").exists());
    }
    fs::write(dir.join("input.c"), "extern int optional(void) __attribute__((weak)); int main(void) { return optional ? optional() : 0; }").unwrap();
    let status = Command::new("gcc")
        .current_dir(&dir)
        .args(["-Bdrv", "input.c", "-o", "output"])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(Command::new(dir.join("output")).status().unwrap().success());
    fs::remove_dir_all(dir).unwrap();
}

fn elf_section_field(bytes: &[u8], sh_type: u32) -> Option<usize> {
    let shoff = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
    let shnum = u16::from_le_bytes(bytes[60..62].try_into().unwrap()) as usize;
    (0..shnum)
        .map(|i| shoff + i * 64)
        .find(|&off| u32::from_le_bytes(bytes[off + 4..off + 8].try_into().unwrap()) == sh_type)
}

#[test]
fn rejects_malformed_object_sections_before_allocating() {
    let dir = std::env::temp_dir().join(format!("weld-malformed-{}", std::process::id()));
    fs::create_dir_all(dir.join("drv")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("drv/ld")).unwrap();
    fs::write(
        dir.join("input.c"),
        "static char buf[64]; int main(void) { return buf[0]; }",
    )
    .unwrap();
    let status = Command::new("gcc")
        .current_dir(&dir)
        .args(["-c", "input.c", "-o", "input.o"])
        .status()
        .unwrap();
    assert!(status.success());
    let original = fs::read(dir.join("input.o")).unwrap();

    // SHT_SYMTAB (2) sh_size, SHT_PROGBITS (1) sh_offset past EOF, and sh_addralign of
    // .text: not a power of two, then far past any real alignment.
    let symtab = elf_section_field(&original, 2).unwrap();
    let progbits = elf_section_field(&original, 1).unwrap();
    let nobits = elf_section_field(&original, 8).unwrap();
    let past_end = original.len() as u64 + 16;
    for (name, field, value, diagnostic) in [
        (
            "symtab size",
            symtab + 32,
            1u64 << 60,
            "extends past end of file",
        ),
        (
            "progbits offset",
            progbits + 24,
            past_end,
            "extends past end of file",
        ),
        ("alignment 3", progbits + 48, 3, "unsupported alignment 3"),
        (
            "alignment 2^40",
            progbits + 48,
            1u64 << 40,
            "unsupported alignment",
        ),
        ("bss size 2^40", nobits + 32, 1u64 << 40, "is too large"),
    ] {
        let mut mutant = original.clone();
        mutant[field..field + 8].copy_from_slice(&value.to_le_bytes());
        fs::write(dir.join("mutant.o"), &mutant).unwrap();
        let output = Command::new("gcc")
            .current_dir(&dir)
            .args(["-Bdrv", "mutant.o", "-o", "output"])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{name}: {stderr}");
        assert!(stderr.contains(diagnostic), "{name}: {stderr}");
        assert!(!stderr.contains("panicked"), "{name}: {stderr}");
        assert!(!dir.join("output").exists());
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_pc_relative_relocation_that_does_not_fit() {
    let dir = std::env::temp_dir().join(format!("weld-pc32-{}", std::process::id()));
    fs::create_dir_all(dir.join("drv")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("drv/ld")).unwrap();
    fs::write(
        dir.join("far.s"),
        ".globl main\nmain:\n  leaq farsym(%rip), %rax\n  xor %eax, %eax\n  ret\n.globl farsym\n.set farsym, 0x90000000\n",
    )
    .unwrap();
    let status = Command::new("gcc")
        .current_dir(&dir)
        .args(["-c", "far.s", "-o", "far.o"])
        .status()
        .unwrap();
    assert!(status.success());
    let output = Command::new("gcc")
        .current_dir(&dir)
        .args(["-Bdrv", "-nostdlib", "-no-pie", "far.o", "-o", "output"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("does not fit in i32"), "{stderr}");
    assert!(!dir.join("output").exists());
    fs::remove_dir_all(dir).unwrap();
}
