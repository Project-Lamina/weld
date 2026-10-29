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
        let tmp = std::env::temp_dir().join("weld_emit_test.o");

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
}
