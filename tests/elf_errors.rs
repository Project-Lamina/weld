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
            "extern __thread int value; int main(void) { return value; }",
            vec!["-fPIC"],
            "thread-local symbol value is not defined by the inputs",
        ),
        (
            "static __thread int value = 1; int get(void) { return value; } int main(void) { return get(); }",
            vec!["-fPIC", "-ftls-model=local-dynamic"],
            "local dynamic TLS is not supported",
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

#[test]
fn rejects_duplicate_strong_definitions() {
    let dir = std::env::temp_dir().join(format!("weld-dupdef-{}", std::process::id()));
    fs::create_dir_all(dir.join("drv")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("drv/ld")).unwrap();
    fs::write(
        dir.join("a.c"),
        "int dupsym = 1; int main(void) { return dupsym; }",
    )
    .unwrap();
    fs::write(dir.join("b.c"), "int dupsym = 2;").unwrap();
    let output = Command::new("gcc")
        .current_dir(&dir)
        .args(["-Bdrv", "a.c", "b.c", "-o", "output"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("multiple definition of dupsym"), "{stderr}");
    assert!(!dir.join("output").exists());
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn strong_definition_overrides_weak_in_either_order() {
    let dir = std::env::temp_dir().join(format!("weld-weakdef-{}", std::process::id()));
    fs::create_dir_all(dir.join("drv")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("drv/ld")).unwrap();
    fs::write(
        dir.join("weak.c"),
        "__attribute__((weak)) int wd(void) { return 11; } int main(void) { return wd(); }",
    )
    .unwrap();
    fs::write(dir.join("strong.c"), "int wd(void) { return 42; }").unwrap();
    for order in [["weak.c", "strong.c"], ["strong.c", "weak.c"]] {
        let status = Command::new("gcc")
            .current_dir(&dir)
            .args(["-Bdrv", order[0], order[1], "-o", "output"])
            .status()
            .unwrap();
        assert!(status.success(), "{order:?}");
        assert_eq!(
            Command::new(dir.join("output")).status().unwrap().code(),
            Some(42),
            "{order:?}"
        );
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_relocation_section_targeting_missing_section() {
    let dir = std::env::temp_dir().join(format!("weld-rela-info-{}", std::process::id()));
    fs::create_dir_all(dir.join("drv")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("drv/ld")).unwrap();
    fs::write(
        dir.join("input.c"),
        "int puts(const char *); int main(void) { return puts(\"x\") > 0; }",
    )
    .unwrap();
    let status = Command::new("gcc")
        .current_dir(&dir)
        .args(["-c", "input.c", "-o", "input.o"])
        .status()
        .unwrap();
    assert!(status.success());
    let mut mutant = fs::read(dir.join("input.o")).unwrap();
    let rela = elf_section_field(&mutant, 4).unwrap();
    mutant[rela + 44..rela + 48].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
    fs::write(dir.join("mutant.o"), &mutant).unwrap();
    let output = Command::new("gcc")
        .current_dir(&dir)
        .args(["-Bdrv", "mutant.o", "-o", "output"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("does not exist"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_relocation_offset_that_wraps() {
    let dir = std::env::temp_dir().join(format!("weld-rela-wrap-{}", std::process::id()));
    fs::create_dir_all(dir.join("drv")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("drv/ld")).unwrap();
    fs::write(dir.join("input.c"), "int main(void) { return 0; }").unwrap();
    let status = Command::new("gcc")
        .current_dir(&dir)
        .args(["-c", "input.c", "-o", "input.o"])
        .status()
        .unwrap();
    assert!(status.success());
    let mut mutant = fs::read(dir.join("input.o")).unwrap();
    let rela = elf_section_field(&mutant, 4).unwrap();
    let rela_off = u64::from_le_bytes(mutant[rela + 24..rela + 32].try_into().unwrap()) as usize;
    let rela_size = u64::from_le_bytes(mutant[rela + 32..rela + 40].try_into().unwrap()) as usize;
    assert!(rela_size >= 24);
    mutant[rela_off..rela_off + 8].copy_from_slice(&u64::MAX.wrapping_sub(3).to_le_bytes());
    fs::write(dir.join("mutant.o"), &mutant).unwrap();
    let output = Command::new("gcc")
        .current_dir(&dir)
        .args(["-Bdrv", "-nostdlib", "-no-pie", "mutant.o", "-o", "output"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("out of bounds"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn links_common_symbols_with_strong_override() {
    let dir = std::env::temp_dir().join(format!("weld-common-{}", std::process::id()));
    fs::create_dir_all(dir.join("drv")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("drv/ld")).unwrap();
    fs::write(
        dir.join("a.c"),
        "int cx; int ca[4] __attribute__((aligned(64))); int cz;",
    )
    .unwrap();
    fs::write(
        dir.join("b.c"),
        "int cx; int cz = 5; extern int ca[]; \
         int main(void) { cx = 5; ca[0] = 2; return cx + ca[0] + cz + (((unsigned long)ca) & 63 ? 100 : 0); }",
    )
    .unwrap();
    for source in ["a.c", "b.c"] {
        let status = Command::new("gcc")
            .current_dir(&dir)
            .args(["-fcommon", "-c", source])
            .status()
            .unwrap();
        assert!(status.success());
    }
    let output = Command::new("gcc")
        .current_dir(&dir)
        .args([
            "-Bdrv",
            "-nostdlib",
            "-no-pie",
            "-nostartfiles",
            "a.o",
            "b.o",
            "-o",
            "output",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.is_empty() || !stderr.contains("undefined"),
        "{stderr}"
    );
    fs::remove_dir_all(dir).unwrap();
}

fn elf_section(bytes: &[u8], index: usize) -> (u32, u64, u64, u32) {
    let shoff = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
    let at = shoff + index * 64;
    let sh_type = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap());
    let offset = u64::from_le_bytes(bytes[at + 24..at + 32].try_into().unwrap());
    let size = u64::from_le_bytes(bytes[at + 32..at + 40].try_into().unwrap());
    let link = u32::from_le_bytes(bytes[at + 40..at + 44].try_into().unwrap());
    (sh_type, offset, size, link)
}

#[test]
fn rejects_imported_data_larger_than_cap() {
    let dir = std::env::temp_dir().join(format!("weld-bigimport-{}", std::process::id()));
    fs::create_dir_all(dir.join("drv")).unwrap();
    symlink(env!("CARGO_BIN_EXE_weld"), dir.join("drv/ld")).unwrap();
    fs::write(dir.join("lib.c"), "int bigdata = 1;").unwrap();
    fs::write(
        dir.join("main.c"),
        "extern int bigdata; int main(void) { return bigdata; }",
    )
    .unwrap();
    let status = Command::new("gcc")
        .current_dir(&dir)
        .args(["-shared", "-fPIC", "lib.c", "-o", "libbig.so"])
        .status()
        .unwrap();
    assert!(status.success());
    let mut lib = fs::read(dir.join("libbig.so")).unwrap();
    let shnum = u16::from_le_bytes(lib[60..62].try_into().unwrap()) as usize;
    let dynsym = (0..shnum).find(|&i| elf_section(&lib, i).0 == 11).unwrap();
    let (_, sym_off, sym_size, strtab_index) = elf_section(&lib, dynsym);
    let (_, str_off, _, _) = elf_section(&lib, strtab_index as usize);
    let entry = (0..sym_size / 24)
        .map(|k| (sym_off + k * 24) as usize)
        .find(|&at| {
            let name_at =
                str_off as usize + u32::from_le_bytes(lib[at..at + 4].try_into().unwrap()) as usize;
            lib[name_at..].starts_with(b"bigdata\0")
        })
        .unwrap();
    lib[entry + 16..entry + 24].copy_from_slice(&(1u64 << 40).to_le_bytes());
    fs::write(dir.join("libbig.so"), &lib).unwrap();
    let output = Command::new("gcc")
        .current_dir(&dir)
        .args(["-Bdrv", "-no-pie", "main.c", "-L.", "-lbig", "-o", "output"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("imported data bigdata is too large"),
        "{stderr}"
    );
    assert!(!stderr.contains("memory allocation"), "{stderr}");
    fs::remove_dir_all(dir).unwrap();
}
