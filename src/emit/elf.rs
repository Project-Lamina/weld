//! ELF64 executable emission.
//!
//! Emits ET_EXEC with permission-separated PT_LOAD and PT_GNU_STACK. Architecture-agnostic
//! layout; e_machine comes from TargetArch.
//! Dynamic linking: PT_INTERP, PT_DYNAMIC, .dynamic, .dynsym, .dynstr, .rela.plt.

use crate::{
    arch::TargetArch,
    link::{DynamicLinkInfo, MergedLayout, OutputSymbol, tls_segment},
    segment::{align_up_u64, build_segment_buffer},
};
use std::io::{Error, ErrorKind, Result, Write};

const EI_MAG0: u8 = 0x7f;
const EI_MAG1: u8 = b'E';
const EI_MAG2: u8 = b'L';
const EI_MAG3: u8 = b'F';
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EV_CURRENT_U32: u32 = 1;
const PT_PHDR: u32 = 6;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_TLS: u32 = 7;
const PT_GNU_STACK: u32 = 0x6474e551;
const PF_R: u32 = 4;
const PF_W: u32 = 2;
const PF_X: u32 = 1;
const ELF64_PHDR_SIZE: usize = 56;

#[allow(dead_code)]
const DT_NEEDED: u64 = 1;
#[allow(dead_code)]
const DT_PLTRELSZ: u64 = 2;
#[allow(dead_code)]
const DT_PLTGOT: u64 = 3;
#[allow(dead_code)]
const DT_STRTAB: u64 = 5;
#[allow(dead_code)]
const DT_SYMTAB: u64 = 6;
#[allow(dead_code)]
const DT_RELA: u64 = 7;
#[allow(dead_code)]
const DT_RELASZ: u64 = 8;
#[allow(dead_code)]
const DT_RELAENT: u64 = 9;
#[allow(dead_code)]
const DT_STRSZ: u64 = 10;
#[allow(dead_code)]
const DT_SYMENT: u64 = 11;
#[allow(dead_code)]
const DT_PLTREL: u64 = 20;
#[allow(dead_code)]
const DT_JMPREL: u64 = 23;

#[allow(dead_code)]
const STB_GLOBAL: u8 = 1;
#[allow(dead_code)]
const STT_FUNC: u8 = 2;
#[allow(dead_code)]
const SHN_UNDEF: u16 = 0;
#[allow(dead_code)]
const R_X86_64_JUMP_SLOT: u32 = 7;

pub fn emit_elf_executable(
    layout: &MergedLayout,
    arch: TargetArch,
    entry: u64,
    os_abi: u8,
    symbols: Option<&[OutputSymbol]>,
    out: &mut impl Write,
) -> Result<()> {
    emit(layout, arch, entry, os_abi, None, symbols, out)
}

pub fn emit_elf_executable_dynamic(
    layout: &MergedLayout,
    arch: TargetArch,
    entry: u64,
    os_abi: u8,
    dynamic: &DynamicLinkInfo,
    symbols: Option<&[OutputSymbol]>,
    out: &mut impl Write,
) -> Result<()> {
    emit(layout, arch, entry, os_abi, Some(dynamic), symbols, out)
}

#[allow(clippy::too_many_arguments)]
fn emit(
    layout: &MergedLayout,
    arch: TargetArch,
    entry: u64,
    os_abi: u8,
    dynamic: Option<&DynamicLinkInfo>,
    symbols: Option<&[OutputSymbol]>,
    out: &mut impl Write,
) -> Result<()> {
    if layout.section_by_name.contains_key(".note.gnu.build-id") {
        let mut bytes = Vec::new();
        emit_image(layout, arch, entry, os_abi, dynamic, symbols, &mut bytes)?;
        let (_, sections, names) = crate::elf::parse_elf64_slice(&bytes)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
        let index = names
            .iter()
            .position(|n| n == ".note.gnu.build-id")
            .unwrap();
        let offset = sections[index].sh_offset as usize + 16;
        let digest = super::build_id::sha1(&bytes);
        bytes[offset..offset + 20].copy_from_slice(&digest);
        out.write_all(&bytes)
    } else {
        emit_image(layout, arch, entry, os_abi, dynamic, symbols, out)
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_image(
    layout: &MergedLayout,
    arch: TargetArch,
    entry: u64,
    os_abi: u8,
    dynamic: Option<&DynamicLinkInfo>,
    symbols: Option<&[OutputSymbol]>,
    out: &mut impl Write,
) -> Result<()> {
    let page = arch.page_align();
    let (base, mut buffer) = build_segment_buffer(layout, arch.default_load_base());
    let file_size = layout
        .sections
        .iter()
        .filter(|s| s.sh_type != 8 && s.flags & 2 != 0)
        .map(|s| s.vaddr - base + s.data.len() as u64)
        .max()
        .unwrap_or(0);
    buffer.truncate(file_size as usize);
    let mut groups = Vec::new();
    for class in 0..5 {
        let sections: Vec<_> = layout
            .sections
            .iter()
            .filter(|s| {
                crate::link::segment_class(s) == class && !s.data.is_empty() && s.flags & 2 != 0
            })
            .collect();
        if sections.is_empty() {
            continue;
        }
        let start = sections.iter().map(|s| s.vaddr).min().unwrap();
        let end = sections
            .iter()
            .map(|s| s.vaddr + s.data.len() as u64)
            .max()
            .unwrap();
        let file_end = sections
            .iter()
            .filter(|s| s.sh_type != 8 && s.flags & 2 != 0)
            .map(|s| s.vaddr + s.data.len() as u64)
            .max()
            .unwrap_or(start);
        let flags = PF_R
            | if class == 1 {
                PF_X
            } else if class >= 3 {
                PF_W
            } else {
                0
            };
        groups.push((start, end, file_end, flags));
    }
    let protected: Vec<_> = layout
        .sections
        .iter()
        .filter(|s| s.is_relro() && !s.data.is_empty())
        .collect();
    let unwind = layout
        .section_by_name
        .get(".eh_frame_hdr")
        .map(|&i| &layout.sections[i]);
    let combine_headers = groups.first().is_some_and(|g| g.3 == PF_R && g.0 == base);
    let notes: Vec<_> = layout
        .sections
        .iter()
        .filter(|s| s.sh_type == 7 && s.flags & 2 != 0 && !s.data.is_empty())
        .collect();
    let property = layout
        .section_by_name
        .get(".note.gnu.property")
        .map(|&i| &layout.sections[i])
        .filter(|s| !s.data.is_empty());
    let tls = tls_segment(layout).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
    let interp = dynamic.and_then(|d| d.interpreter.as_ref());
    let interp = interp.map(|s| format!("{s}\0")).unwrap_or_default();
    let phnum = 2 - u16::from(combine_headers)
        + u16::from(tls.is_some())
        + notes.len() as u16
        + u16::from(property.is_some())
        + groups.len() as u16
        + if dynamic.is_some() {
            2 + u16::from(!interp.is_empty())
        } else {
            0
        }
        + u16::from(!protected.is_empty())
        + u16::from(unwind.is_some());
    let phsize = u64::from(phnum) * ELF64_PHDR_SIZE as u64;
    let segment_offset = align_up_u64(64 + phsize + interp.len() as u64, page);
    let header_base = base - segment_offset;
    let mut ehdr = [0u8; 64];
    ehdr[..4].copy_from_slice(&[EI_MAG0, EI_MAG1, EI_MAG2, EI_MAG3]);
    ehdr[4] = ELFCLASS64;
    ehdr[5] = ELFDATA2LSB;
    ehdr[6] = EV_CURRENT;
    ehdr[7] = os_abi;
    ehdr[16..18].copy_from_slice(
        &(if dynamic.is_some_and(|d| d.pie) {
            ET_DYN
        } else {
            ET_EXEC
        })
        .to_le_bytes(),
    );
    ehdr[18..20].copy_from_slice(&arch.to_elf_machine().to_le_bytes());
    ehdr[48..52].copy_from_slice(&arch.elf_flags().to_le_bytes());
    ehdr[20..24].copy_from_slice(&EV_CURRENT_U32.to_le_bytes());
    ehdr[24..32].copy_from_slice(&entry.to_le_bytes());
    ehdr[32..40].copy_from_slice(&64u64.to_le_bytes());
    ehdr[52..54].copy_from_slice(&64u16.to_le_bytes());
    ehdr[54..56].copy_from_slice(&(ELF64_PHDR_SIZE as u16).to_le_bytes());
    ehdr[56..58].copy_from_slice(&phnum.to_le_bytes());
    let metadata = SectionMetadata::new(layout, symbols, segment_offset, base, buffer.len());
    metadata.set_header(&mut ehdr);
    out.write_all(&ehdr)?;
    let mut header = |kind: u32,
                      flags: u32,
                      offset: u64,
                      address: u64,
                      filesz: u64,
                      memsz: u64,
                      align: u64|
     -> Result<()> {
        let mut bytes = [0u8; ELF64_PHDR_SIZE];
        bytes[..4].copy_from_slice(&kind.to_le_bytes());
        bytes[4..8].copy_from_slice(&flags.to_le_bytes());
        for (off, value) in [
            (8, offset),
            (16, address),
            (24, address),
            (32, filesz),
            (40, memsz),
            (48, align),
        ] {
            bytes[off..off + 8].copy_from_slice(&value.to_le_bytes());
        }
        out.write_all(&bytes)
    };
    if dynamic.is_some() {
        header(PT_PHDR, PF_R, 64, header_base + 64, phsize, phsize, 8)?;
        if !interp.is_empty() {
            header(
                PT_INTERP,
                PF_R,
                64 + phsize,
                header_base + 64 + phsize,
                interp.len() as u64,
                interp.len() as u64,
                1,
            )?;
        }
    }
    if !combine_headers {
        header(
            PT_LOAD,
            PF_R,
            0,
            header_base,
            segment_offset,
            segment_offset,
            page,
        )?;
    }
    for (start, end, file_end, flags) in groups {
        if combine_headers && start == base {
            header(
                PT_LOAD,
                flags,
                0,
                header_base,
                segment_offset + file_end - base,
                segment_offset + end - base,
                page,
            )?;
            continue;
        }
        header(
            PT_LOAD,
            flags,
            segment_offset + start - base,
            start,
            file_end - start,
            end - start,
            page,
        )?;
    }
    if dynamic.is_some() {
        let section = layout
            .section_by_name
            .get(".dynamic")
            .map(|&i| &layout.sections[i])
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "no .dynamic"))?;
        header(
            PT_DYNAMIC,
            PF_R | PF_W,
            segment_offset + section.vaddr - base,
            section.vaddr,
            section.data.len() as u64,
            section.data.len() as u64,
            8,
        )?;
    }
    if let Some(tls) = tls {
        header(
            PT_TLS,
            PF_R,
            segment_offset + tls.vaddr - base,
            tls.vaddr,
            tls.filesz,
            tls.memsz,
            tls.align,
        )?;
    }
    header(PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 16)?;
    if let Some(section) = unwind {
        header(
            0x6474e550,
            PF_R,
            segment_offset + section.vaddr - base,
            section.vaddr,
            section.data.len() as u64,
            section.data.len() as u64,
            4,
        )?;
    }
    for section in notes {
        header(
            4,
            PF_R,
            segment_offset + section.vaddr - base,
            section.vaddr,
            section.data.len() as u64,
            section.data.len() as u64,
            section.align,
        )?;
    }
    if let Some(section) = property {
        header(
            0x6474e553,
            PF_R,
            segment_offset + section.vaddr - base,
            section.vaddr,
            section.data.len() as u64,
            section.data.len() as u64,
            8,
        )?;
    }
    if let Some(start) = protected.iter().map(|s| s.vaddr).min() {
        let end = align_up_u64(
            protected
                .iter()
                .map(|s| s.vaddr + s.data.len() as u64)
                .max()
                .unwrap(),
            page,
        );
        header(
            0x6474e552,
            PF_R,
            segment_offset + start - base,
            start,
            end - start,
            end - start,
            1,
        )?;
    }
    out.write_all(interp.as_bytes())?;
    out.write_all(&vec![
        0;
        (segment_offset - 64 - phsize - interp.len() as u64)
            as usize
    ])?;
    out.write_all(&buffer)?;
    out.write_all(&metadata.bytes)
}

struct SectionMetadata {
    bytes: Vec<u8>,
    shoff: u64,
    count: u16,
    names_index: u16,
}

impl SectionMetadata {
    fn new(
        layout: &MergedLayout,
        symbols: Option<&[OutputSymbol]>,
        segment_offset: u64,
        base: u64,
        segment_size: usize,
    ) -> Self {
        use crate::elf::SectionHeader;
        let start = segment_offset + segment_size as u64;
        let mut bytes = Vec::new();
        let mut names = vec![0];
        let mut headers = Vec::new();
        let index = |name: &str| {
            layout
                .section_by_name
                .get(name)
                .map_or(0, |i| (i + 1) as u32)
        };
        for section in &layout.sections {
            let name_offset = names.len() as u32;
            names.extend_from_slice(section.name.as_bytes());
            names.push(0);
            let (kind, link, info, entsize) = match section.name.as_str() {
                ".dynsym" => (11, index(".dynstr"), 1, 24),
                ".dynstr" => (3, 0, 0, 0),
                ".dynamic" => (6, index(".dynstr"), 0, 16),
                ".hash" => (5, index(".dynsym"), 0, 4),
                ".rela.plt" => (4, index(".dynsym"), index(".got.plt"), 24),
                ".rela.dyn" => (4, index(".dynsym"), 0, 24),
                ".gnu.version" => (0x6fffffff, index(".dynsym"), 0, 2),
                ".gnu.version_r" => (
                    0x6ffffffe,
                    index(".dynstr"),
                    {
                        let mut count = 0;
                        let mut offset = 0;
                        while offset + 16 <= section.data.len() {
                            count += 1;
                            let next = u32::from_le_bytes(
                                section.data[offset + 12..offset + 16].try_into().unwrap(),
                            ) as usize;
                            if next == 0 {
                                break;
                            }
                            offset += next;
                        }
                        count
                    },
                    0,
                ),
                ".gnu.hash" => (0x6ffffff6, index(".dynsym"), 0, 0),
                ".got" | ".got.plt" => (1, 0, 0, 8),
                ".plt" => (1, 0, 0, 16),
                _ => (section.sh_type, 0, 0, section.entsize),
            };
            let (address, offset) = if section.flags & 2 != 0 {
                (section.vaddr, segment_offset + section.vaddr - base)
            } else {
                let offset = align_up_u64(start + bytes.len() as u64, section.align);
                bytes.resize((offset - start) as usize, 0);
                bytes.extend_from_slice(&section.data);
                (0, offset)
            };
            headers.push(SectionHeader {
                name_offset,
                sh_type: kind,
                sh_flags: section.flags,
                sh_addr: address,
                sh_offset: offset,
                sh_size: section.data.len() as u64,
                sh_link: link,
                sh_info: info,
                sh_addralign: section.align,
                sh_entsize: entsize,
            });
        }
        let mut strtab = vec![0];
        let mut symbol_names = crate::collections::HashMap::default();
        let mut symtab = vec![0; 24];
        let mut first_global = 1;
        for local in [true, false] {
            for symbol in symbols
                .unwrap_or_default()
                .iter()
                .filter(|s| (s.info >> 4 == 0) == local)
            {
                let name = if symbol.name.is_empty() {
                    0
                } else {
                    *symbol_names.entry(symbol.name.as_str()).or_insert_with(|| {
                        let offset = strtab.len() as u32;
                        strtab.extend_from_slice(symbol.name.as_bytes());
                        strtab.push(0);
                        offset
                    })
                };
                symtab.extend_from_slice(&name.to_le_bytes());
                symtab.extend_from_slice(&[symbol.info, 0]);
                symtab.extend_from_slice(&symbol.shndx.to_le_bytes());
                symtab.extend_from_slice(&symbol.value.to_le_bytes());
                symtab.extend_from_slice(&symbol.size.to_le_bytes());
                if local {
                    first_global += 1;
                }
            }
        }
        let sym_index = headers.len() as u32 + 1;
        let mut tables = Vec::new();
        if symbols.is_some() {
            tables.push((".symtab", symtab, 2, sym_index + 1, first_global, 8, 24));
            tables.push((".strtab", strtab, 3, 0, 0, 1, 0));
        }
        tables.push((".shstrtab", Vec::new(), 3, 0, 0, 1, 0));
        for (name, data, kind, link, info, align, entsize) in tables {
            let offset = align_up_u64(start + bytes.len() as u64, align);
            bytes.resize((offset - start) as usize, 0);
            let name_offset = names.len() as u32;
            names.extend_from_slice(name.as_bytes());
            names.push(0);
            let data = if name == ".shstrtab" { &names } else { &data };
            bytes.extend_from_slice(data);
            headers.push(SectionHeader {
                name_offset,
                sh_type: kind,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: offset,
                sh_size: data.len() as u64,
                sh_link: link,
                sh_info: info,
                sh_addralign: align,
                sh_entsize: entsize,
            });
        }
        let shoff = align_up_u64(start + bytes.len() as u64, 8);
        bytes.resize((shoff - start) as usize + 64, 0);
        for h in &headers {
            bytes.extend_from_slice(&h.name_offset.to_le_bytes());
            bytes.extend_from_slice(&h.sh_type.to_le_bytes());
            for value in [h.sh_flags, h.sh_addr, h.sh_offset, h.sh_size] {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            bytes.extend_from_slice(&h.sh_link.to_le_bytes());
            bytes.extend_from_slice(&h.sh_info.to_le_bytes());
            bytes.extend_from_slice(&h.sh_addralign.to_le_bytes());
            bytes.extend_from_slice(&h.sh_entsize.to_le_bytes());
        }
        Self {
            bytes,
            shoff,
            count: headers.len() as u16 + 1,
            names_index: headers.len() as u16,
        }
    }

    fn set_header(&self, header: &mut [u8; 64]) {
        header[40..48].copy_from_slice(&self.shoff.to_le_bytes());
        header[58..60].copy_from_slice(&64u16.to_le_bytes());
        header[60..62].copy_from_slice(&self.count.to_le_bytes());
        header[62..64].copy_from_slice(&self.names_index.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collections::HashMap;
    use crate::link::{MergedSection, link_single_object};
    use crate::test_support::TempDir;
    use lamina_platform::{TargetArchitecture, TargetOperatingSystem};

    #[test]
    fn test_emit_elf_header() {
        let layout = MergedLayout {
            sections: vec![MergedSection {
                entsize: 0,
                sh_type: 1,
                name: ".text".into(),
                data: vec![0xc3],
                vaddr: 0x400000,
                flags: 4,
                align: 16,
            }],
            section_by_name: {
                let mut m = HashMap::default();
                m.insert(".text".into(), 0);
                m
            },
        };

        let mut out = Vec::new();
        emit_elf_executable(
            &layout,
            TargetArch::X86_64,
            0x400000,
            0,
            Some(&[]),
            &mut out,
        )
        .expect("emit");

        assert!(out.len() >= 64);
        assert_eq!(&out[0..4], &[0x7f, b'E', b'L', b'F']);
        assert_eq!(out[4], 2);
        assert_eq!(out[16..18], 2u16.to_le_bytes());
        assert_eq!(out[18..20], 62u16.to_le_bytes());
    }

    #[test]
    fn test_emit_aarch64() {
        let layout = MergedLayout {
            sections: vec![MergedSection {
                entsize: 0,
                sh_type: 1,
                name: ".text".into(),
                data: vec![0xd6, 0x5f, 0x03, 0xc0],
                vaddr: 0x400000,
                flags: 4,
                align: 16,
            }],
            section_by_name: {
                let mut m = HashMap::default();
                m.insert(".text".into(), 0);
                m
            },
        };

        let mut out = Vec::new();
        emit_elf_executable(
            &layout,
            TargetArch::AArch64,
            0x400000,
            0,
            Some(&[]),
            &mut out,
        )
        .expect("emit");
        assert!(out.len() >= 64);
        assert_eq!(&out[0..4], &[0x7f, b'E', b'L', b'F']);
        assert_eq!(out[18..20], 183u16.to_le_bytes());
    }

    #[test]
    fn test_link_and_emit() {
        let asm = ".text\n.globl main\nmain:\n  movq $42, %rax\n  ret\n";
        let tmp_dir = TempDir::new("weld_emit_test");
        let tmp = tmp_dir.path().join("weld_emit_test.o");

        let mut ras =
            ras::Ras::new(TargetArchitecture::X86_64, TargetOperatingSystem::Linux).expect("ras");
        ras.assemble(asm, &tmp).expect("assemble");

        let data = std::fs::read(&tmp).expect("read");
        let _ = std::fs::remove_file(&tmp);

        let result = link_single_object(&data).expect("link");
        let arch = TargetArch::from_elf_machine(result.e_machine).expect("arch");
        let entry = result
            .symbol_addrs
            .get("main")
            .copied()
            .unwrap_or_else(|| result.layout.sections.first().map(|s| s.vaddr).unwrap());

        let mut out = Vec::new();
        emit_elf_executable(&result.layout, arch, entry, 0, Some(&[]), &mut out).expect("emit");

        assert!(out.len() >= 64);
        assert_eq!(&out[0..4], &[0x7f, b'E', b'L', b'F']);
        assert_eq!(out[16..18], 2u16.to_le_bytes());
    }

    /// aarch64 ELF links.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    mod aarch64 {
        use crate::test_support::TempDir;
        use crate::test_support::weld_binary;
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
            let result = link_with(&weld_binary(), dir, object, out);
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
            if !crate::test_support::tool_available(GCC) {
                return;
            }
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
            if !crate::test_support::tool_available(GCC) {
                return;
            }
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
            if !crate::test_support::tool_available(GCC) {
                return;
            }
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
            if !crate::test_support::tool_available(GCC) {
                return;
            }
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
            if !crate::test_support::tool_available(GCC) {
                return;
            }
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
            if !crate::test_support::tool_available(GCC) {
                return;
            }
            let guard = TempDir::new("weld-aarch64-tls-gd");
            let dir = guard.path();
            let object = compile(
                dir,
                "gd",
                THREAD_LOCAL,
                &["-O1", "-fPIC", "-ftls-model=global-dynamic"],
            );
            let refused = link_with(&weld_binary(), dir, &object, "output");
            assert!(!refused.status.success());
            let message = String::from_utf8_lossy(&refused.stderr);
            assert!(message.contains("R_AARCH64_TLSDESC_"), "{message}");
            assert!(message.contains("counter"), "{message}");
        }

        #[test]
        fn shared_objects_are_refused_for_aarch64() {
            if !crate::test_support::tool_available(GCC) {
                return;
            }
            let guard = TempDir::new("weld-aarch64-shared");
            let dir = guard.path();
            let object = compile(dir, "shared", PRINTS_SUM, &["-O1", "-fPIC"]);
            let refused = output_of(
                &weld_binary(),
                &["-m", "aarch64linux", "-shared", &object, "-o", "out.so"],
                dir,
            );
            assert!(!refused.status.success());
            assert!(
                String::from_utf8_lossy(&refused.stderr)
                    .contains("-shared is not supported for AArch64"),
            );
        }
    }

    /// What weld refuses, and how it says so.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    mod errors {
        use crate::test_support::TempDir;
        use crate::test_support::weld_binary;
        use std::{fs, os::unix::fs::symlink, process::Command};

        #[test]
        fn rejects_lto_and_unresolved_symbols_before_emission() {
            let guard = TempDir::new("weld-errors");
            let dir = guard.path();
            fs::create_dir_all(dir.join("drv")).unwrap();
            symlink(weld_binary(), dir.join("drv/ld")).unwrap();
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
                    .current_dir(dir)
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
                .current_dir(dir)
                .args(["-Bdrv", "input.c", "-o", "output"])
                .status()
                .unwrap();
            assert!(status.success());
            assert!(Command::new(dir.join("output")).status().unwrap().success());
        }

        fn elf_section_field(bytes: &[u8], sh_type: u32) -> Option<usize> {
            let shoff = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
            let shnum = u16::from_le_bytes(bytes[60..62].try_into().unwrap()) as usize;
            (0..shnum).map(|i| shoff + i * 64).find(|&off| {
                u32::from_le_bytes(bytes[off + 4..off + 8].try_into().unwrap()) == sh_type
            })
        }

        #[test]
        fn rejects_malformed_object_sections_before_allocating() {
            let guard = TempDir::new("weld-malformed");
            let dir = guard.path();
            fs::create_dir_all(dir.join("drv")).unwrap();
            symlink(weld_binary(), dir.join("drv/ld")).unwrap();
            fs::write(
                dir.join("input.c"),
                "static char buf[64]; int main(void) { return buf[0]; }",
            )
            .unwrap();
            let status = Command::new("gcc")
                .current_dir(dir)
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
                    .current_dir(dir)
                    .args(["-Bdrv", "mutant.o", "-o", "output"])
                    .output()
                    .unwrap();
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(!output.status.success(), "{name}: {stderr}");
                assert!(stderr.contains(diagnostic), "{name}: {stderr}");
                assert!(!stderr.contains("panicked"), "{name}: {stderr}");
                assert!(!dir.join("output").exists());
            }
        }

        #[test]
        fn rejects_pc_relative_relocation_that_does_not_fit() {
            let guard = TempDir::new("weld-pc32");
            let dir = guard.path();
            fs::create_dir_all(dir.join("drv")).unwrap();
            symlink(weld_binary(), dir.join("drv/ld")).unwrap();
            fs::write(
                dir.join("far.s"),
                ".globl main\nmain:\n  leaq farsym(%rip), %rax\n  xor %eax, %eax\n  ret\n.globl farsym\n.set farsym, 0x90000000\n",
            )
            .unwrap();
            let status = Command::new("gcc")
                .current_dir(dir)
                .args(["-c", "far.s", "-o", "far.o"])
                .status()
                .unwrap();
            assert!(status.success());
            let output = Command::new("gcc")
                .current_dir(dir)
                .args(["-Bdrv", "-nostdlib", "-no-pie", "far.o", "-o", "output"])
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!output.status.success(), "{stderr}");
            assert!(stderr.contains("does not fit in i32"), "{stderr}");
            assert!(!dir.join("output").exists());
        }

        #[test]
        fn rejects_duplicate_strong_definitions() {
            let guard = TempDir::new("weld-dupdef");
            let dir = guard.path();
            fs::create_dir_all(dir.join("drv")).unwrap();
            symlink(weld_binary(), dir.join("drv/ld")).unwrap();
            fs::write(
                dir.join("a.c"),
                "int dupsym = 1; int main(void) { return dupsym; }",
            )
            .unwrap();
            fs::write(dir.join("b.c"), "int dupsym = 2;").unwrap();
            let output = Command::new("gcc")
                .current_dir(dir)
                .args(["-Bdrv", "a.c", "b.c", "-o", "output"])
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!output.status.success(), "{stderr}");
            assert!(stderr.contains("multiple definition of dupsym"), "{stderr}");
            assert!(!dir.join("output").exists());
        }
        #[test]
        fn strong_definition_overrides_weak_in_either_order() {
            let guard = TempDir::new("weld-weakdef");
            let dir = guard.path();
            fs::create_dir_all(dir.join("drv")).unwrap();
            symlink(weld_binary(), dir.join("drv/ld")).unwrap();
            fs::write(
                dir.join("weak.c"),
                "__attribute__((weak)) int wd(void) { return 11; } int main(void) { return wd(); }",
            )
            .unwrap();
            fs::write(dir.join("strong.c"), "int wd(void) { return 42; }").unwrap();
            for order in [["weak.c", "strong.c"], ["strong.c", "weak.c"]] {
                let status = Command::new("gcc")
                    .current_dir(dir)
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
        }

        #[test]
        fn rejects_relocation_section_targeting_missing_section() {
            let guard = TempDir::new("weld-rela-info");
            let dir = guard.path();
            fs::create_dir_all(dir.join("drv")).unwrap();
            symlink(weld_binary(), dir.join("drv/ld")).unwrap();
            fs::write(
                dir.join("input.c"),
                "int puts(const char *); int main(void) { return puts(\"x\") > 0; }",
            )
            .unwrap();
            let status = Command::new("gcc")
                .current_dir(dir)
                .args(["-c", "input.c", "-o", "input.o"])
                .status()
                .unwrap();
            assert!(status.success());
            let mut mutant = fs::read(dir.join("input.o")).unwrap();
            let rela = elf_section_field(&mutant, 4).unwrap();
            mutant[rela + 44..rela + 48].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
            fs::write(dir.join("mutant.o"), &mutant).unwrap();
            let output = Command::new("gcc")
                .current_dir(dir)
                .args(["-Bdrv", "mutant.o", "-o", "output"])
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!output.status.success(), "{stderr}");
            assert!(stderr.contains("does not exist"), "{stderr}");
            assert!(!stderr.contains("panicked"), "{stderr}");
        }

        #[test]
        fn rejects_relocation_offset_that_wraps() {
            let guard = TempDir::new("weld-rela-wrap");
            let dir = guard.path();
            fs::create_dir_all(dir.join("drv")).unwrap();
            symlink(weld_binary(), dir.join("drv/ld")).unwrap();
            fs::write(dir.join("input.c"), "int main(void) { return 0; }").unwrap();
            let status = Command::new("gcc")
                .current_dir(dir)
                .args(["-c", "input.c", "-o", "input.o"])
                .status()
                .unwrap();
            assert!(status.success());
            let mut mutant = fs::read(dir.join("input.o")).unwrap();
            let rela = elf_section_field(&mutant, 4).unwrap();
            let rela_off =
                u64::from_le_bytes(mutant[rela + 24..rela + 32].try_into().unwrap()) as usize;
            let rela_size =
                u64::from_le_bytes(mutant[rela + 32..rela + 40].try_into().unwrap()) as usize;
            assert!(rela_size >= 24);
            mutant[rela_off..rela_off + 8].copy_from_slice(&u64::MAX.wrapping_sub(3).to_le_bytes());
            fs::write(dir.join("mutant.o"), &mutant).unwrap();
            let output = Command::new("gcc")
                .current_dir(dir)
                .args(["-Bdrv", "-nostdlib", "-no-pie", "mutant.o", "-o", "output"])
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!output.status.success(), "{stderr}");
            assert!(stderr.contains("out of bounds"), "{stderr}");
            assert!(!stderr.contains("panicked"), "{stderr}");
        }

        #[test]
        fn links_common_symbols_with_strong_override() {
            let guard = TempDir::new("weld-common");
            let dir = guard.path();
            fs::create_dir_all(dir.join("drv")).unwrap();
            symlink(weld_binary(), dir.join("drv/ld")).unwrap();
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
                    .current_dir(dir)
                    .args(["-fcommon", "-c", source])
                    .status()
                    .unwrap();
                assert!(status.success());
            }
            let output = Command::new("gcc")
                .current_dir(dir)
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
            let guard = TempDir::new("weld-bigimport");
            let dir = guard.path();
            fs::create_dir_all(dir.join("drv")).unwrap();
            symlink(weld_binary(), dir.join("drv/ld")).unwrap();
            fs::write(dir.join("lib.c"), "int bigdata = 1;").unwrap();
            fs::write(
                dir.join("main.c"),
                "extern int bigdata; int main(void) { return bigdata; }",
            )
            .unwrap();
            let status = Command::new("gcc")
                .current_dir(dir)
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
                    let name_at = str_off as usize
                        + u32::from_le_bytes(lib[at..at + 4].try_into().unwrap()) as usize;
                    lib[name_at..].starts_with(b"bigdata\0")
                })
                .unwrap();
            lib[entry + 16..entry + 24].copy_from_slice(&(1u64 << 40).to_le_bytes());
            fs::write(dir.join("libbig.so"), &lib).unwrap();
            let output = Command::new("gcc")
                .current_dir(dir)
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
        }

        #[test]
        fn rejects_merge_relocation_section_with_a_partial_entry() {
            let guard = TempDir::new("weld-merge-rela");
            let dir = guard.path();
            fs::write(
                dir.join("merge.s"),
                r#"
        .section .rodata.str1.1,"aMS",@progbits,1
        .globl merged
        merged: .asciz "repeated string"
        .Lduplicate: .asciz "repeated string"
        .section .data.rel.ro,"aw"
        .globl pointer
        pointer: .quad .Lduplicate + 3
        .text
        .globl _start
        _start:
            lea merged(%rip),%rax
            mov $60,%eax
            xor %edi,%edi
            syscall
        "#,
            )
            .unwrap();
            let status = Command::new("as")
                .current_dir(dir)
                .args(["merge.s", "-o", "merge.o"])
                .status()
                .unwrap();
            assert!(status.success());

            let mut mutant = fs::read(dir.join("merge.o")).unwrap();
            let rela = elf_section_field(&mutant, 4).unwrap();
            let tail = (mutant.len() - 32) as u64;
            mutant[rela + 24..rela + 32].copy_from_slice(&tail.to_le_bytes());
            mutant[rela + 32..rela + 40].copy_from_slice(&32u64.to_le_bytes());
            fs::write(dir.join("mutant.o"), &mutant).unwrap();

            let output = Command::new(weld_binary())
                .current_dir(dir)
                .args(["-o", "output", "mutant.o"])
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!output.status.success(), "{stderr}");
            assert!(stderr.contains("is not a multiple of 24"), "{stderr}");
            assert!(!stderr.contains("panicked"), "{stderr}");
            assert!(!dir.join("output").exists());
        }
    }

    /// Position independent executables.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    mod pie {
        use crate::test_support::TempDir;
        use crate::test_support::weld_binary;
        use std::{fs, os::unix::fs::symlink, path::Path, process::Command};

        fn run(program: &str, args: &[&str], dir: &Path) -> String {
            let output = Command::new(program)
                .args(args)
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{program} {args:?}: {}",
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
        fn default_gcc_pie_rebases_data_functions_and_got() {
            let guard = TempDir::new("weld-pie-runtime");
            let dir = guard.path();
            fs::create_dir_all(dir.join("prefix")).unwrap();
            symlink(weld_binary(), dir.join("prefix/ld")).unwrap();
            fs::write(
                dir.join("data.c"),
                "int value = 42; int buffer[2048]; int get(void) { return value; }\n",
            )
            .unwrap();
            fs::write(dir.join("main.c"), r#"
        #include <stdio.h>
        extern int value, buffer[], get(void);
        static int local = 7;
        int *pointers[] = { &value, &local, buffer + 2047 };
        int (*function)(void) = get;
        int main(void) {
            if (pointers[0] != &value || pointers[1] != &local || pointers[2] != buffer + 2047 || function != get) return 1;
            *pointers[2] = 3;
            printf("%d %d %d\n", *pointers[0], *pointers[1], function() + buffer[2047]);
        }
        "#).unwrap();
            for flags in ["-fPIE", "-fPIC"] {
                run(
                    "gcc",
                    &["-Bprefix", flags, "main.c", "data.c", "-o", "output"],
                    dir,
                );
                for _ in 0..3 {
                    assert_eq!(run("./output", &[], dir), "42 7 45\n");
                }
                let header = run("readelf", &["-hW", "output"], dir);
                assert!(header.contains("DYN (Position-Independent Executable file)"));
                let tags = run("readelf", &["-dW", "output"], dir);
                for tag in ["(RELA)", "(RELASZ)", "(RELAENT)", "(RELACOUNT)", "NOW PIE"] {
                    assert!(tags.contains(tag), "missing {tag}: {tags}");
                }
                let headers = run("readelf", &["-lW", "output"], dir);
                assert!(
                    headers
                        .lines()
                        .any(|line| line.contains("LOAD") && line.contains("0x0000000000000000"))
                );
                assert!(run("readelf", &["-rW", "output"], dir).contains("R_X86_64_RELATIVE"));
            }
        }

        #[test]
        fn freestanding_pie_preserves_absolute_symbols() {
            let guard = TempDir::new("weld-pie-absolute");
            let dir = guard.path();
            fs::create_dir_all(dir).unwrap();
            fs::write(
                dir.join("input.s"),
                r#"
        .text
        .globl _start
        _start:
            lea value(%rip), %rax
            cmp pointer(%rip), %rax
            jne fail
            lea _start(%rip), %rax
            cmp relative(%rip), %rax
            jne fail
            cmpq $123, constant(%rip)
            jne fail
            xor %edi, %edi
            jmp exit
        fail:
            mov $1, %edi
        exit:
            mov $60, %eax
            syscall
        .data
        value: .quad 42
        pointer: .quad value
        relative: .quad 0
        .reloc relative, R_X86_64_RELATIVE, 0x1000
        constant: .quad absolute
        .globl absolute
        .set absolute, 123
        "#,
            )
            .unwrap();
            run("as", &["input.s", "-o", "input.o"], dir);
            run(&weld_binary(), &["-pie", "input.o", "-o", "output"], dir);
            run("./output", &[], dir);
            let relocs = run("readelf", &["-rW", "output"], dir);
            assert_eq!(relocs.matches("R_X86_64_RELATIVE").count(), 2);
            fs::write(
                dir.join("bad.s"),
                ".text\n.globl _start\n_start: mov $value, %eax\n.data\nvalue: .quad 0\n",
            )
            .unwrap();
            run("as", &["bad.s", "-o", "bad.o"], dir);
            let rejected = Command::new(weld_binary())
                .args(["-pie", "bad.o", "-o", "bad"])
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(!rejected.status.success());
            assert!(
                String::from_utf8_lossy(&rejected.stderr)
                    .contains("requires position independent input")
            );
        }

        #[test]
        fn cross_architecture_pie_emits_relative_relocations() {
            let guard = TempDir::new("weld-pie-cross");
            let dir = guard.path();
            fs::create_dir_all(dir).unwrap();
            for (target, instruction, relocation, interpreter) in [
                (
                    "aarch64-linux-gnu",
                    "ret",
                    "R_AARCH64_RELATIVE",
                    "/lib/ld-linux-aarch64.so.1",
                ),
                (
                    "riscv64-linux-gnu",
                    "ret",
                    "R_RISCV_RELATIVE",
                    "/lib/ld-linux-riscv64-lp64d.so.1",
                ),
            ] {
                fs::write(dir.join("input.s"), format!(".text\n.globl _start\n_start: {instruction}\n.data\n.globl value\nvalue: .quad 42\npointer: .quad value+8\n")).unwrap();
                run(
                    "clang",
                    &["-target", target, "-c", "input.s", "-o", "input.o"],
                    dir,
                );
                run(&weld_binary(), &["--pie", "input.o", "-o", "output"], dir);
                let relocs = run("readelf", &["-rW", "output"], dir);
                assert_eq!(relocs.matches(relocation).count(), 1, "{relocs}");
                let symbols = run("nm", &["output"], dir);
                let value = symbols
                    .lines()
                    .find_map(|line| {
                        let fields: Vec<_> = line.split_whitespace().collect();
                        (fields.last() == Some(&"value"))
                            .then(|| u64::from_str_radix(fields[0], 16).unwrap())
                    })
                    .unwrap();
                let addend = relocs
                    .lines()
                    .find(|line| line.contains(relocation))
                    .unwrap()
                    .split_whitespace()
                    .last()
                    .unwrap();
                assert_eq!(u64::from_str_radix(addend, 16).unwrap(), value + 8);
                assert!(run("readelf", &["-dW", "output"], dir).contains("PIE"));
                assert!(run("readelf", &["-lW", "output"], dir).contains(interpreter));
                assert!(
                    run("readelf", &["-hW", "output"], dir)
                        .contains("DYN (Position-Independent Executable file)")
                );
            }
        }
    }

    /// Relocatable output.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    mod relocatable {
        use crate::test_support::TempDir;
        use crate::test_support::weld_binary;
        use std::{fs, path::Path, process::Command};

        fn run(program: &str, args: &[&str], dir: &Path) -> (i32, String) {
            let result = Command::new(program)
                .args(args)
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(
                result.stderr.is_empty(),
                "{program}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            (
                result.status.code().unwrap_or(-1),
                String::from_utf8(result.stdout).unwrap(),
            )
        }

        #[test]
        fn relocatable_output_relinks_and_runs() {
            let guard = TempDir::new("weld-relocatable");
            let dir = guard.path();
            fs::create_dir_all(dir).unwrap();
            fs::write(
                dir.join("main.s"),
                ".text\n.globl main\nmain:\n push %rbx\n call foo\n mov gv(%rip),%ecx\n add %ecx,%eax\n pop %rbx\n ret\n.data\n.globl gv\ngv: .long 7\n",
            )
            .unwrap();
            fs::write(
                dir.join("foo.s"),
                ".text\n.globl foo\nfoo:\n movl $35,%eax\n lea msg(%rip),%rdx\n movzbl (%rdx),%edx\n ret\n.section .rodata\nmsg: .byte 0\n",
            )
            .unwrap();
            run("as", &["main.s", "-o", "main.o"], dir);
            run("as", &["foo.s", "-o", "foo.o"], dir);
            let weld = &weld_binary();
            run(weld, &["-r", "main.o", "foo.o", "-o", "combined.o"], dir);

            let (_, header) = run("readelf", &["-hW", "combined.o"], dir);
            assert!(header.contains("REL (Relocatable file)"));
            let (_, relocs) = run("readelf", &["-rW", "combined.o"], dir);
            assert!(relocs.contains("R_X86_64_PLT32") && relocs.contains("R_X86_64_PC32"));

            run(weld, &["combined.o", "-o", "combined"], dir);
            let (code, _) = run("./combined", &[], dir);
            assert_eq!(code, 42);
        }
    }

    /// Programs weld links and runs.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    mod runtime {
        use crate::test_support::TempDir;
        use crate::test_support::weld_binary;
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
            let guard = TempDir::new("weld-cpp-runtime");
            let dir = guard.path();
            fs::create_dir_all(dir.join("prefix")).unwrap();
            symlink(weld_binary(), dir.join("prefix/ld")).unwrap();
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
                    dir,
                );
                run("g++", &[mode, "input.o", "-o", "reference"], dir);
                run("g++", &[mode, "-Bprefix", "input.o", "-o", "output"], dir);
                assert_eq!(run("./reference", &[], dir), expected);
                assert_eq!(run("./output", &[], dir), expected);
                let tags = run("readelf", &["-dW", "output"], dir);
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
                let headers = run("readelf", &["-lW", "output"], dir);
                assert!(headers.contains("GNU_EH_FRAME") && headers.contains("GNU_RELRO"));
            }
        }

        #[test]
        fn imported_data_pointers_and_version_requirements() {
            let guard = TempDir::new("weld-data-runtime");
            let dir = guard.path();
            fs::create_dir_all(dir.join("prefix")).unwrap();
            symlink(weld_binary(), dir.join("prefix/ld")).unwrap();
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
                dir,
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
                    dir,
                );
                assert_eq!(run("./output", &[], dir), "73 73\n");
                let versions = run("readelf", &["-VW", "output"], dir);
                assert!(versions.contains("CHECK_1"));
                let relocs = run("readelf", &["-rW", "output"], dir);
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
                dir,
            );
            let output = Command::new(dir.join("output")).output().unwrap();
            assert!(!output.status.success());
            let error = String::from_utf8_lossy(&output.stderr);
            assert!(
                error.contains("CHECK_1") && error.contains("not found"),
                "{error}"
            );
        }

        #[test]
        fn init_array_priorities_and_weak_got_entries() {
            let guard = TempDir::new("weld-init-runtime");
            let dir = guard.path();
            fs::create_dir_all(dir.join("prefix")).unwrap();
            symlink(weld_binary(), dir.join("prefix/ld")).unwrap();
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
                run("gcc", &[mode, "-Bprefix", "input.c", "-o", "output"], dir);
                assert_eq!(run("./output", &[], dir), "123\nfirst dtor\nlast dtor\n");
            }
        }

        #[test]
        fn explicit_symbol_versions_select_nondefault_exports() {
            let guard = TempDir::new("weld-version-runtime");
            let dir = guard.path();
            fs::create_dir_all(dir.join("prefix")).unwrap();
            symlink(weld_binary(), dir.join("prefix/ld")).unwrap();
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
                dir,
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
                dir,
            );
            assert_eq!(run("./output", &[], dir), "12 34\n");
        }

        #[test]
        fn read_only_table_of_imported_function_pointers_is_relocated_in_place() {
            let guard = TempDir::new("weld-rodata-runtime");
            let dir = guard.path();
            fs::create_dir_all(dir.join("prefix")).unwrap();
            symlink(weld_binary(), dir.join("prefix/ld")).unwrap();
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
                dir,
            );
            run("gcc", &["-no-pie", "input.o", "-o", "reference"], dir);
            run(
                "gcc",
                &["-no-pie", "-Bprefix", "input.o", "-o", "output"],
                dir,
            );
            assert_eq!(run("./reference", &[], dir), "from table\nalpha\n");
            assert_eq!(run("./output", &[], dir), "from table\nalpha\n");
        }

        #[test]
        fn imported_data_alias_shares_copy_relocation() {
            let guard = TempDir::new("weld-alias-runtime");
            let dir = guard.path();
            fs::create_dir_all(dir.join("prefix")).unwrap();
            symlink(weld_binary(), dir.join("prefix/ld")).unwrap();
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
                dir,
            );
            run("gcc", &["-no-pie", "input.o", "-o", "reference"], dir);
            run(
                "gcc",
                &["-no-pie", "-Bprefix", "input.o", "-o", "output"],
                dir,
            );
            assert_eq!(run("./reference", &[], dir), "1 1\n");
            assert_eq!(run("./output", &[], dir), "1 1\n");
        }

        #[test]
        fn atexit_resolves_from_libc_linker_script_archive() {
            let guard = TempDir::new("weld-atexit-runtime");
            let dir = guard.path();
            fs::create_dir_all(dir.join("prefix")).unwrap();
            symlink(weld_binary(), dir.join("prefix/ld")).unwrap();
            fs::write(
                dir.join("input.c"),
                r#"
        #include <stdio.h>
        #include <stdlib.h>
        static void bye(void) { puts("bye"); }
        int main(void) {
            if (atexit(bye) != 0) return 1;
            puts("hi");
            return 0;
        }
        "#,
            )
            .unwrap();
            run("gcc", &["-c", "input.c", "-o", "input.o"], dir);
            run("gcc", &["input.o", "-o", "reference"], dir);
            run("gcc", &["-Bprefix", "input.o", "-o", "output"], dir);
            assert_eq!(run("./reference", &[], dir), "hi\nbye\n");
            assert_eq!(run("./output", &[], dir), "hi\nbye\n");
        }
    }

    /// Shared objects.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    mod shared {
        use crate::test_support::TempDir;
        use crate::test_support::weld_binary;
        use std::{fs, os::unix::fs::symlink, path::Path, process::Command};

        fn run(program: &str, args: &[&str], dir: &Path) -> String {
            let output = Command::new(program)
                .args(args)
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{program} {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap()
        }

        #[test]
        fn gcc_shared_object_loads_with_dlopen() {
            let guard = TempDir::new("weld-shared");
            let dir = guard.path();
            fs::create_dir_all(dir.join("prefix")).unwrap();
            symlink(weld_binary(), dir.join("prefix/ld")).unwrap();
            fs::write(
                dir.join("lib.c"),
                "#include <stdio.h>\nint shared_value = 42;\nstatic int hidden = 3;\nint shared_add(int a, int b) { return a + b + hidden; }\nconst char *shared_name(void) { return \"weld\"; }\nvoid shared_print(const char *s) { printf(\"print:%s\\n\", s); }\n",
            )
            .unwrap();
            fs::write(
                dir.join("main.c"),
                r#"
        #include <dlfcn.h>
        #include <stdio.h>
        int main(void) {
            void *h = dlopen("./libweldshared.so", RTLD_NOW);
            if (!h) return 1;
            int (*add)(int, int) = (int (*)(int, int))dlsym(h, "shared_add");
            int *value = (int *)dlsym(h, "shared_value");
            const char *(*name)(void) = (const char *(*)(void))dlsym(h, "shared_name");
            void (*print)(const char *) = (void (*)(const char *))dlsym(h, "shared_print");
            if (!add || !value || !name || !print) return 1;
            printf("%d %d %s\n", add(1, 2), *value, name());
            print("x");
            return 0;
        }
        "#,
            )
            .unwrap();
            run(
                "gcc",
                &[
                    "-Bprefix",
                    "-shared",
                    "-fPIC",
                    "-Wl,-soname,libweldshared.so",
                    "lib.c",
                    "-o",
                    "libweldshared.so",
                ],
                dir,
            );
            let header = run("readelf", &["-hW", "libweldshared.so"], dir);
            assert!(header.contains("DYN (Shared object file)"), "{header}");
            let tags = run("readelf", &["-dW", "libweldshared.so"], dir);
            assert!(
                tags.contains("(SONAME)") && tags.contains("libweldshared.so"),
                "{tags}"
            );
            let symbols = run("readelf", &["--dyn-syms", "-W", "libweldshared.so"], dir);
            assert!(symbols.contains("shared_add"), "{symbols}");
            run("gcc", &["main.c", "-o", "main", "-ldl"], dir);
            assert_eq!(run("./main", &[], dir), "6 42 weld\nprint:x\n");
        }

        #[test]
        fn shared_rejects_non_x86_64_targets() {
            let guard = TempDir::new("weld-shared-arch");
            let dir = guard.path();
            fs::create_dir_all(dir).unwrap();
            fs::write(dir.join("f.s"), "    .text\n    .globl f\nf:\n    ret\n").unwrap();
            let assembled = Command::new("ras")
                .args(["--target", "aarch64_linux", "-o", "f.o", "f.s"])
                .current_dir(dir)
                .status();
            if !matches!(assembled, Ok(status) if status.success()) {
                return;
            }
            let output = Command::new(weld_binary())
                .args(["-shared", "-o", "libf.so", "f.o"])
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(!output.status.success());
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("-shared is not supported for AArch64")
            );
        }
    }

    /// Static links.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    mod static_link {
        use crate::test_support::TempDir;
        use crate::test_support::weld_binary;
        use std::{fs, os::unix::fs::symlink, path::Path, process::Command};

        fn run(dir: &Path, program: &str, args: &[&str]) -> String {
            let output = Command::new(program)
                .current_dir(dir)
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{program} {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap()
        }

        #[test]
        fn static_archives_rescan_cycles_and_preserve_runtime_arrays() {
            let guard = TempDir::new("weld-static");
            let dir = guard.path();
            fs::create_dir_all(dir.join("drv")).unwrap();
            symlink(weld_binary(), dir.join("drv/ld")).unwrap();
            fs::write(
                dir.join("start.s"),
                r#"
        .globl _start
        .text
        _start:
            call *init(%rip)
            call first
            cmp $42, %eax
            jne fail
            call *fini(%rip)
            xor %edi, %edi
            jmp exit
        fail:
            mov $1, %edi
        exit:
            mov $60, %eax
            syscall
        .section .init_array,"aw",@init_array
        init: .quad initialize
        .section .fini_array,"aw",@fini_array
        fini: .quad finalize
        .section .note.GNU-stack,"",@progbits
        "#,
            )
            .unwrap();
            for (name, source) in [
                (
                    "first",
                    "int value; void initialize(void) { value = 42; } void finalize(void) { value = 0; } extern int second(void); int first(void) { return second(); }",
                ),
                ("last", "extern int value; int last(void) { return value; }"),
                (
                    "second",
                    "extern int last(void); int second(void) { return last(); }",
                ),
            ] {
                fs::write(dir.join(format!("{name}.c")), source).unwrap();
                run(
                    dir,
                    "gcc",
                    &[
                        "-c",
                        "-fno-pie",
                        "-fno-stack-protector",
                        &format!("{name}.c"),
                        "-o",
                        &format!("{name}.o"),
                    ],
                );
            }
            run(dir, "gcc", &["-c", "start.s", "-o", "start.o"]);
            run(dir, "ar", &["rcs", "libfirst.a", "first.o", "last.o"]);
            run(dir, "ar", &["rcs", "libsecond.a", "second.o"]);
            run(
                dir,
                "gcc",
                &["-shared", "-nostdlib", "second.o", "-o", "libfirst.so"],
            );
            run(
                dir,
                "gcc",
                &[
                    "-Bdrv",
                    "-static",
                    "-nostdlib",
                    "start.o",
                    "-L.",
                    "-Wl,--start-group",
                    "-lfirst",
                    "-lsecond",
                    "-Wl,--end-group",
                    "-o",
                    "output",
                ],
            );
            run(dir, "./output", &[]);
            let headers = run(dir, "readelf", &["-hlSW", "output"]);
            assert!(
                headers.contains("EXEC")
                    && headers.contains(".init_array")
                    && headers.contains(".fini_array")
            );
            for forbidden in [
                "INTERP", "DYNAMIC", ".dynamic", ".dynsym", ".dynstr", ".plt", ".got",
            ] {
                assert!(!headers.contains(forbidden), "{forbidden}: {headers}");
            }
        }

        #[test]
        fn static_glibc_and_unsupported_runtime_features_fail_before_emission() {
            let guard = TempDir::new("weld-static-errors");
            let dir = guard.path();
            fs::create_dir_all(dir.join("drv")).unwrap();
            symlink(weld_binary(), dir.join("drv/ld")).unwrap();
            for (source, flags, diagnostic) in [
                (
                    "int main(void) { return 0; }",
                    vec![],
                    "static GNU IFUNC is not supported",
                ),
                (
                    "int impl(void) { return 0; } void *resolve(void) { return impl; } int func(void) __attribute__((ifunc(\"resolve\"))); int main(void) { return func(); }",
                    vec!["-nostdlib"],
                    "static GNU IFUNC is not supported",
                ),
                (
                    "int main(void) { return 0; }",
                    vec!["-nostdlib", "-lmissing_weld_library"],
                    "cannot find static library",
                ),
            ] {
                fs::write(dir.join("input.c"), source).unwrap();
                let output = Command::new("gcc")
                    .current_dir(dir)
                    .args(["-Bdrv", "-static", "input.c", "-o", "output"])
                    .args(flags)
                    .output()
                    .unwrap();
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(!output.status.success(), "{stderr}");
                assert!(stderr.contains(diagnostic), "{stderr}");
                assert!(!dir.join("output").exists());
            }
        }

        #[test]
        fn archive_listed_before_its_user_is_not_searched() {
            let guard = TempDir::new("weld-archive-order");
            let dir = guard.path();
            fs::create_dir_all(dir.join("drv")).unwrap();
            symlink(weld_binary(), dir.join("drv/ld")).unwrap();
            for (name, source) in [
                ("r", "int r(void) { return 20; }"),
                ("q", "int r(void); int q(void) { return r() * 2; }"),
                ("p", "int q(void); int p(void) { return q() + 1; }"),
                (
                    "main",
                    "#include <stdio.h>\nint p(void); int main(void) { printf(\"p=%d\\n\", p()); return 0; }",
                ),
            ] {
                fs::write(dir.join(format!("{name}.c")), source).unwrap();
                run(
                    dir,
                    "gcc",
                    &["-c", &format!("{name}.c"), "-o", &format!("{name}.o")],
                );
            }
            run(dir, "ar", &["rcs", "libchain.a", "r.o", "q.o", "p.o"]);
            let output = Command::new("gcc")
                .current_dir(dir)
                .args(["-Bdrv", "-o", "before", "libchain.a", "main.o"])
                .output()
                .unwrap();
            assert!(!output.status.success());
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("undefined"),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            run(
                dir,
                "gcc",
                &["-Bdrv", "-o", "after", "main.o", "libchain.a"],
            );
            assert_eq!(run(dir, "./after", &[]), "p=41\n");
        }

        #[test]
        fn archive_member_pulled_after_earlier_definition_is_duplicate() {
            let guard = TempDir::new("weld-archive-dup");
            let dir = guard.path();
            fs::create_dir_all(dir.join("drv")).unwrap();
            symlink(weld_binary(), dir.join("drv/ld")).unwrap();
            for (name, source) in [
                ("member", "int strongf(void) { return 7; }"),
                ("object", "int strongf(void) { return 5; }"),
                (
                    "main",
                    "int strongf(void); int main(void) { return strongf(); }",
                ),
            ] {
                fs::write(dir.join(format!("{name}.c")), source).unwrap();
                run(
                    dir,
                    "gcc",
                    &["-c", &format!("{name}.c"), "-o", &format!("{name}.o")],
                );
            }
            run(dir, "ar", &["rcs", "libmember.a", "member.o"]);
            let output = Command::new("gcc")
                .current_dir(dir)
                .args(["-Bdrv", "-o", "dup", "main.o", "libmember.a", "object.o"])
                .output()
                .unwrap();
            assert!(!output.status.success());
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("multiple definition of strongf"),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        #[test]
        fn archive_without_symbol_index_is_rejected_like_ld() {
            let guard = TempDir::new("weld-archive-noidx");
            let dir = guard.path();
            fs::create_dir_all(dir.join("drv")).unwrap();
            symlink(weld_binary(), dir.join("drv/ld")).unwrap();
            fs::write(dir.join("empty.c"), "int main(void) { return 0; }").unwrap();
            fs::write(dir.join("helper.c"), "int helper(void) { return 1; }").unwrap();
            run(dir, "gcc", &["-c", "empty.c", "-o", "empty.o"]);
            run(dir, "gcc", &["-c", "helper.c", "-o", "helper.o"]);
            run(dir, "ar", &["rcS", "libnoidx.a", "helper.o"]);
            let output = Command::new("gcc")
                .current_dir(dir)
                .args(["-Bdrv", "-o", "noidx", "empty.o", "libnoidx.a"])
                .output()
                .unwrap();
            assert!(!output.status.success());
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("archive has no index"),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        #[test]
        fn static_link_emits_eh_frame_hdr_for_unwinders() {
            let guard = TempDir::new("weld-static-eh-hdr");
            let dir = guard.path();
            fs::create_dir_all(dir.join("drv")).unwrap();
            symlink(weld_binary(), dir.join("drv/ld")).unwrap();
            fs::write(
                dir.join("start.s"),
                ".globl _start\n.text\n_start:\n call main\n mov %eax, %edi\n mov $60, %eax\n syscall\n.section .note.GNU-stack,\"\",@progbits\n",
            )
            .unwrap();
            fs::write(
                dir.join("prog.c"),
                "__attribute__((noinline)) int a(int x) { return x + 1; }\n__attribute__((noinline)) int b(int x) { return a(x) * 2; }\nint main(void) { return b(3) == 8 ? 0 : 1; }\n",
            )
            .unwrap();
            run(
                dir,
                "gcc",
                &["-c", "-O0", "-fno-pie", "prog.c", "-o", "prog.o"],
            );
            run(dir, "gcc", &["-c", "start.s", "-o", "start.o"]);
            run(
                dir,
                "gcc",
                &[
                    "-Bdrv",
                    "-static",
                    "-nostdlib",
                    "start.o",
                    "prog.o",
                    "-o",
                    "output",
                ],
            );
            assert!(Command::new(dir.join("output")).status().unwrap().success());
            let headers = run(dir, "readelf", &["-SlW", "output"]);
            assert!(headers.contains(".eh_frame_hdr") && headers.contains("GNU_EH_FRAME"));
            let frames = run(dir, "readelf", &["--debug-dump=frames", "output"]);
            let fdes = frames.matches(" FDE cie").count();
            assert_eq!(fdes, 3);
            let dump = run(dir, "readelf", &["-x", ".eh_frame_hdr", "output"]);
            let hex: String = dump
                .lines()
                .filter(|line| line.trim_start().starts_with("0x"))
                .flat_map(|line| {
                    line.split_whitespace()
                        .skip(1)
                        .take_while(|group| group.len() == 8)
                })
                .collect();
            assert!(hex.starts_with("011b033b"), "{hex}");
            let word = |at: usize| {
                let le = [
                    &hex[at + 6..at + 8],
                    &hex[at + 4..at + 6],
                    &hex[at + 2..at + 4],
                    &hex[at..at + 2],
                ];
                u32::from_str_radix(&le.concat(), 16).unwrap()
            };
            assert_eq!(word(16) as usize, fdes);
            assert_eq!(hex.len(), (12 + fdes * 8) * 2);
        }
    }

    /// Thread local storage.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    mod tls {
        use crate::test_support::TempDir;
        use crate::test_support::weld_binary;
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

        fn link_both(name: &str, sources: &[&str], cflags: &[&str]) -> TempDir {
            let guard = TempDir::new(&format!("weld-tls-{name}"));
            let dir = guard.path();
            fs::create_dir_all(dir.join("drv")).unwrap();
            std::os::unix::fs::symlink(weld_binary(), dir.join("drv/ld")).unwrap();
            let mut objects = Vec::new();
            for (i, source) in sources.iter().enumerate() {
                let file = format!("unit{i}.c");
                fs::write(dir.join(&file), source).unwrap();
                let object = format!("unit{i}.o");
                let mut args = cflags.to_vec();
                args.extend(["-c", &file, "-o", &object]);
                run("gcc", &args, dir);
                objects.push(object);
            }
            let mut ld_args = vec!["-no-pie"];
            ld_args.extend(objects.iter().map(String::as_str));
            ld_args.extend(["-o", "reference"]);
            run("gcc", &ld_args, dir);
            let mut weld_args = vec!["-no-pie", "-B", "drv/"];
            weld_args.extend(objects.iter().map(String::as_str));
            weld_args.extend(["-o", "weld"]);
            run("gcc", &weld_args, dir);
            guard
        }

        fn link_and_compare(name: &str, sources: &[&str]) {
            let guard = link_both(name, sources, &["-fno-pic"]);
            let dir = guard.path();
            let weld = pt_tls(dir, "weld");
            let reference = pt_tls(dir, "reference");
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
        }

        fn compare_program_output(name: &str, sources: &[&str], cflags: &[&str]) -> String {
            let guard = link_both(name, sources, cflags);
            let dir = guard.path();
            let expected = run("./reference", &[], dir);
            assert_eq!(run("./weld", &[], dir), expected, "{name} output");
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

        #[test]
        fn static_link_without_libc_keeps_pt_tls_for_local_exec_thread_locals() {
            let guard = TempDir::new("weld-tls-static");
            let dir = guard.path();
            fs::create_dir_all(dir.join("drv")).unwrap();
            std::os::unix::fs::symlink(weld_binary(), dir.join("drv/ld")).unwrap();
            fs::write(
                dir.join("main.c"),
                "__thread int value = 5; __thread long wide[3]; void _start(void) { value += (int)wide[0]; }",
            )
            .unwrap();
            run("gcc", &["-fno-pic", "-c", "main.c", "-o", "main.o"], dir);
            run(
                "gcc",
                &["-static", "-nostdlib", "-B", "drv/", "main.o", "-o", "weld"],
                dir,
            );
            run(
                "gcc",
                &["-static", "-nostdlib", "main.o", "-o", "reference"],
                dir,
            );
            let weld = pt_tls(dir, "weld");
            let reference = pt_tls(dir, "reference");
            assert_eq!(weld[1..], reference[1..]);
        }

        #[test]
        fn initial_exec_offsets_match_ld_across_object_files() {
            let probe = format!("{DECLARATIONS}\n{PROBE_MAIN}");
            let output = compare_program_output(
                "initial-exec-two-units",
                &[DEFINITIONS, &probe],
                &["-fPIC", "-ftls-model=initial-exec"],
            );
            assert_eq!(output, "-96 -64 -32 -92 2 9 6 120\n");
        }

        #[test]
        fn initial_exec_offsets_survive_pie_output() {
            let guard = TempDir::new("weld-tls-pie");
            let dir = guard.path();
            fs::create_dir_all(dir.join("drv")).unwrap();
            std::os::unix::fs::symlink(weld_binary(), dir.join("drv/ld")).unwrap();
            fs::write(dir.join("unit.c"), format!("{DEFINITIONS}\n{PROBE_MAIN}")).unwrap();
            run(
                "gcc",
                &[
                    "-fPIC",
                    "-ftls-model=initial-exec",
                    "-c",
                    "unit.c",
                    "-o",
                    "unit.o",
                ],
                dir,
            );
            run("gcc", &["-pie", "-B", "drv/", "unit.o", "-o", "weld"], dir);
            assert_eq!(run("./weld", &[], dir), "-96 -64 -32 -92 2 9 6 120\n");
        }

        #[test]
        fn initial_exec_rejects_thread_local_from_shared_library() {
            let guard = TempDir::new("weld-tls-shared");
            let dir = guard.path();
            fs::create_dir_all(dir.join("drv")).unwrap();
            std::os::unix::fs::symlink(weld_binary(), dir.join("drv/ld")).unwrap();
            fs::write(
                dir.join("unit.c"),
                "extern __thread int imported; int main(void) { return imported; }",
            )
            .unwrap();
            run(
                "gcc",
                &[
                    "-fPIC",
                    "-ftls-model=initial-exec",
                    "-c",
                    "unit.c",
                    "-o",
                    "unit.o",
                ],
                dir,
            );
            let output = Command::new("gcc")
                .current_dir(dir)
                .args(["-B", "drv/", "unit.o", "-o", "weld"])
                .output()
                .unwrap();
            assert!(!output.status.success());
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("thread-locals from shared libraries are not supported"),
                "{stderr}"
            );
        }

        #[test]
        fn global_dynamic_calls_relax_to_local_exec_like_ld() {
            let output = compare_program_output(
                "global-dynamic-two-units",
                &[DEFINITIONS, &format!("{DECLARATIONS}\n{PROBE_MAIN}")],
                &["-fPIC"],
            );
            assert_eq!(output, "-96 -64 -32 -92 2 9 6 120\n");
        }

        #[test]
        fn global_dynamic_relaxation_is_correct_in_pie() {
            let guard = TempDir::new("weld-tls-gd-pie");
            let dir = guard.path();
            fs::create_dir_all(dir.join("drv")).unwrap();
            std::os::unix::fs::symlink(weld_binary(), dir.join("drv/ld")).unwrap();
            fs::write(dir.join("defs.c"), DEFINITIONS).unwrap();
            fs::write(dir.join("probe.c"), format!("{DECLARATIONS}\n{PROBE_MAIN}")).unwrap();
            run("gcc", &["-fPIC", "-c", "defs.c", "-o", "defs.o"], dir);
            run("gcc", &["-fPIC", "-c", "probe.c", "-o", "probe.o"], dir);
            run(
                "gcc",
                &["-pie", "-B", "drv/", "defs.o", "probe.o", "-o", "weld"],
                dir,
            );
            assert_eq!(run("./weld", &[], dir), "-96 -64 -32 -92 2 9 6 120\n");
        }

        #[test]
        fn local_exec_rejects_undefined_weak_thread_local() {
            let guard = TempDir::new("weld-tls-weak");
            let dir = guard.path();
            fs::create_dir_all(dir.join("drv")).unwrap();
            std::os::unix::fs::symlink(weld_binary(), dir.join("drv/ld")).unwrap();
            fs::write(
                dir.join("unit.c"),
                "extern __thread int weak_value __attribute__((weak)); int main(void) { return &weak_value != 0; }",
            )
            .unwrap();
            run("gcc", &["-fno-pic", "-c", "unit.c", "-o", "unit.o"], dir);
            let output = Command::new("gcc")
                .current_dir(dir)
                .args(["-no-pie", "-B", "drv/", "unit.o", "-o", "weld"])
                .output()
                .unwrap();
            assert!(!output.status.success());
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("thread-local symbol weak_value is not defined by the inputs"),
                "{stderr}"
            );
        }
    }

    /// What the system binutils make of weld's output.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    mod tools {
        use crate::test_support::TempDir;
        use crate::test_support::weld_binary;
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
            run(&weld_binary(), &["input.o", "-o", "weld"], dir);
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
                for linker in [&weld_binary(), "ld"] {
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
            let linker = &weld_binary();
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
                &weld_binary(),
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
                    &weld_binary(),
                    &["main.o", "-lc", flag, "--Map=output.map", "-o", "output"],
                    dir,
                );
                let sections = run("readelf", &["-SW", "output"], dir);
                assert!(sections.contains(".dynsym") && sections.contains(".dynstr"));
                assert!(!sections.contains(".symtab") && !sections.contains(" .strtab"));
                let map = fs::read_to_string(dir.join("output.map")).unwrap();
                assert!(
                    map.contains("main") && map.contains(".text") && map.contains("Entry point")
                );
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
            run(&weld_binary(), &args, dir);
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
                &weld_binary(),
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
                for linker in [&weld_binary(), "ld"] {
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
                run(&weld_binary(), &args, dir);
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
                    assert!(
                        address(".init") < address(".plt") && address(".plt") < address(".text")
                    );
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
            run(&weld_binary(), &["input.o", "-o", "output"], dir);
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
                run(&weld_binary(), &args, dir);
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
            run(&weld_binary(), &args, dir);
            let original = fs::read(dir.join("output")).unwrap();
            run(&weld_binary(), &args, dir);
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
                &weld_binary(),
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
                &weld_binary(),
                &["--build-id", "--build-id=none", "first.o", "-o", "output"],
                dir,
            );
            assert!(!run("readelf", &["-nW", "output"], dir).contains("NT_GNU_BUILD_ID"));
            let result = Command::new(weld_binary())
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
            for (linker, output) in [
                (weld_binary(), "output".to_string()),
                ("ld".to_string(), "reference".to_string()),
            ] {
                run(&linker, &["input.o", "-o", &output], dir);
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
            std::os::unix::fs::symlink(weld_binary(), dir.join("prefix/ld")).unwrap();
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
                let number = |offset: usize| {
                    u64::from_le_bytes(image[offset..offset + 8].try_into().unwrap())
                };
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
                        + u32::from_le_bytes(image[header..header + 4].try_into().unwrap())
                            as usize;
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
                            (fields.len() >= 3
                                && fields[0].ends_with(".c")
                                && fields[2].starts_with("0x"))
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
                Command::new(weld_binary())
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
    }
}
