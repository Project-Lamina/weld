//! ELF64 executable emission.
//!
//! Emits ET_EXEC with PT_LOAD and PT_GNU_STACK. Architecture-agnostic
//! layout; e_machine comes from TargetArch.
//! Dynamic linking: PT_INTERP, PT_DYNAMIC, .dynamic, .dynsym, .dynstr, .rela.plt.

use crate::{
    arch::TargetArch,
    link::{DynamicLinkInfo, MergedLayout, OutputSymbol},
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
const EV_CURRENT_U32: u32 = 1;
const PT_PHDR: u32 = 6;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
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

/// Emit a statically-linked ELF64 `ET_EXEC` executable.
///
/// Writes an ELF header, one `PT_LOAD` segment covering all sections, and a
/// `PT_GNU_STACK` segment with `RW` permissions (non-executable stack).
pub fn emit_elf_executable(
    layout: &MergedLayout,
    arch: TargetArch,
    entry: u64,
    os_abi: u8,
    symbols: Option<&[OutputSymbol]>,
    out: &mut impl Write,
) -> Result<()> {
    let (base, mut seg_buffer) = build_segment_buffer(layout, arch.default_load_base());
    let mem_size = seg_buffer.len() as u64;
    let file_size = layout
        .sections
        .iter()
        .filter(|s| s.sh_type != 8)
        .map(|s| s.vaddr - base + s.data.len() as u64)
        .max()
        .unwrap_or(0);
    seg_buffer.truncate(file_size as usize);
    let seg_size = seg_buffer.len() as u64;
    let seg_align = arch.page_align();

    let phoff = 64u64;
    let phnum = 2u16;
    let ph_size = (phnum as usize) * ELF64_PHDR_SIZE;
    let seg_offset = align_up_u64(phoff + ph_size as u64, seg_align);

    let mut ehdr = [0u8; 64];
    ehdr[0..4].copy_from_slice(&[EI_MAG0, EI_MAG1, EI_MAG2, EI_MAG3]);
    ehdr[4] = ELFCLASS64;
    ehdr[5] = ELFDATA2LSB;
    ehdr[6] = EV_CURRENT;
    ehdr[7] = os_abi;
    ehdr[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
    ehdr[18..20].copy_from_slice(&arch.to_elf_machine().to_le_bytes());
    ehdr[20..24].copy_from_slice(&EV_CURRENT_U32.to_le_bytes());
    ehdr[24..32].copy_from_slice(&entry.to_le_bytes());
    ehdr[32..40].copy_from_slice(&phoff.to_le_bytes());
    ehdr[40..48].copy_from_slice(&0u64.to_le_bytes());
    ehdr[52..54].copy_from_slice(&64u16.to_le_bytes());
    ehdr[54..56].copy_from_slice(&(ELF64_PHDR_SIZE as u16).to_le_bytes());
    ehdr[56..58].copy_from_slice(&phnum.to_le_bytes());

    let metadata = SectionMetadata::new(
        layout,
        symbols,
        seg_offset_for_metadata(&ehdr, seg_align),
        base,
        seg_buffer.len(),
    );
    metadata.set_header(&mut ehdr);
    out.write_all(&ehdr)?;

    let mut phdr_load = [0u8; ELF64_PHDR_SIZE];
    phdr_load[0..4].copy_from_slice(&PT_LOAD.to_le_bytes());
    phdr_load[4..8].copy_from_slice(&(PF_R | PF_W | PF_X).to_le_bytes());
    phdr_load[8..16].copy_from_slice(&seg_offset.to_le_bytes());
    phdr_load[16..24].copy_from_slice(&base.to_le_bytes());
    phdr_load[24..32].copy_from_slice(&base.to_le_bytes());
    phdr_load[32..40].copy_from_slice(&seg_size.to_le_bytes());
    phdr_load[40..48].copy_from_slice(&mem_size.to_le_bytes());
    phdr_load[48..56].copy_from_slice(&seg_align.to_le_bytes());
    out.write_all(&phdr_load)?;

    let mut phdr_stack = [0u8; ELF64_PHDR_SIZE];
    phdr_stack[0..4].copy_from_slice(&PT_GNU_STACK.to_le_bytes());
    phdr_stack[4..8].copy_from_slice(&(PF_R | PF_W).to_le_bytes());
    out.write_all(&phdr_stack)?;

    let pad_len = (seg_offset - phoff - ph_size as u64) as usize;
    if pad_len > 0 {
        out.write_all(&vec![0u8; pad_len])?;
    }

    out.write_all(&seg_buffer)?;
    out.write_all(&metadata.bytes)?;

    Ok(())
}

/// Emit a dynamically-linked ELF64 `ET_EXEC` executable.
///
/// Writes five program headers in order: `PT_PHDR`, `PT_LOAD` (covers file
/// offset 0 so the ELF header and phdrs are mapped), `PT_DYNAMIC`, `PT_INTERP`,
/// and `PT_GNU_STACK`. The interpreter path string is written in the padding gap
/// between the phdrs and the first page-aligned segment.
///
/// Returns `Err` if `dynamic.interpreter` is `None` or if the layout contains
/// no `.dynamic` section.
pub fn emit_elf_executable_dynamic(
    layout: &MergedLayout,
    arch: TargetArch,
    entry: u64,
    os_abi: u8,
    dynamic: &DynamicLinkInfo,
    symbols: Option<&[OutputSymbol]>,
    out: &mut impl Write,
) -> Result<()> {
    let interpreter = dynamic
        .interpreter
        .as_ref()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "no interpreter"))?;
    let interp_bytes = format!("{}\0", interpreter);
    let interp_len = interp_bytes.len();

    let (base, mut seg_buffer) = build_segment_buffer(layout, arch.default_load_base());
    let mem_size = seg_buffer.len() as u64;
    let file_size = layout
        .sections
        .iter()
        .filter(|s| s.sh_type != 8)
        .map(|s| s.vaddr - base + s.data.len() as u64)
        .max()
        .unwrap_or(0);
    seg_buffer.truncate(file_size as usize);
    let seg_align = arch.page_align();

    let phoff = 64u64;
    let unwind = layout
        .section_by_name
        .get(".eh_frame_hdr")
        .map(|&i| &layout.sections[i]);
    let protected: Vec<_> = layout.sections.iter().filter(|s| s.is_relro()).collect();
    let phnum = 5u16 + u16::from(unwind.is_some()) + u16::from(!protected.is_empty());
    let ph_size = (phnum as usize) * ELF64_PHDR_SIZE;
    let seg_start = align_up_u64(phoff + ph_size as u64, seg_align);

    // Place the interpreter path string in the padding between program headers
    // and the first LOAD segment. The kernel reads PT_INTERP from file offset
    // (not from a mapped VA), so it doesn't need to be in any LOAD segment.
    let interp_file_off = phoff + ph_size as u64; // right after phdrs

    let seg_size = seg_buffer.len() as u64;

    let dynamic_vaddr = layout
        .section_by_name
        .get(".dynamic")
        .and_then(|&i| layout.sections.get(i))
        .map(|s| s.vaddr)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "no .dynamic"))?;
    let dynamic_offset = seg_start + (dynamic_vaddr - base);

    let mut ehdr = [0u8; 64];
    ehdr[0..4].copy_from_slice(&[EI_MAG0, EI_MAG1, EI_MAG2, EI_MAG3]);
    ehdr[4] = ELFCLASS64;
    ehdr[5] = ELFDATA2LSB;
    ehdr[6] = EV_CURRENT;
    ehdr[7] = os_abi;
    ehdr[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
    ehdr[18..20].copy_from_slice(&arch.to_elf_machine().to_le_bytes());
    ehdr[20..24].copy_from_slice(&EV_CURRENT_U32.to_le_bytes());
    ehdr[24..32].copy_from_slice(&entry.to_le_bytes());
    ehdr[32..40].copy_from_slice(&phoff.to_le_bytes());
    ehdr[40..48].copy_from_slice(&0u64.to_le_bytes());
    ehdr[52..54].copy_from_slice(&64u16.to_le_bytes());
    ehdr[54..56].copy_from_slice(&(ELF64_PHDR_SIZE as u16).to_le_bytes());
    ehdr[56..58].copy_from_slice(&phnum.to_le_bytes());

    let metadata = SectionMetadata::new(
        layout,
        symbols,
        seg_offset_for_metadata(&ehdr, seg_align),
        base,
        seg_buffer.len(),
    );
    metadata.set_header(&mut ehdr);
    out.write_all(&ehdr)?;

    // PT_PHDR: glibc's dl_main scans the main executable's program headers and
    // uses PT_PHDR to compute the load bias (l_addr = AT_PHDR - PT_PHDR.p_vaddr).
    // It must be the first program header and lie within a PT_LOAD. The phdrs are
    // at file offset `phoff`, which maps to vaddr (load_vaddr_below + phoff).
    let load_vaddr = base - seg_start;
    let mut phdr_phdr = [0u8; ELF64_PHDR_SIZE];
    phdr_phdr[0..4].copy_from_slice(&PT_PHDR.to_le_bytes());
    phdr_phdr[4..8].copy_from_slice(&PF_R.to_le_bytes());
    phdr_phdr[8..16].copy_from_slice(&phoff.to_le_bytes());
    phdr_phdr[16..24].copy_from_slice(&(load_vaddr + phoff).to_le_bytes());
    phdr_phdr[24..32].copy_from_slice(&(load_vaddr + phoff).to_le_bytes());
    phdr_phdr[32..40].copy_from_slice(&(ph_size as u64).to_le_bytes());
    phdr_phdr[40..48].copy_from_slice(&(ph_size as u64).to_le_bytes());
    phdr_phdr[48..56].copy_from_slice(&8u64.to_le_bytes());
    out.write_all(&phdr_phdr)?;

    // The PT_LOAD must cover file offset 0 so the ELF header and program headers
    // are mapped. The kernel computes AT_PHDR = p_vaddr + (e_phoff - p_offset)
    // for the segment containing e_phoff; if the phdrs aren't mapped, the dynamic
    // linker dereferences a bad AT_PHDR and segfaults before it can run.
    // Map file offset 0 at (base - seg_start) so the actual sections (placed at
    // file offset seg_start) still land at their assigned vaddr `base`.
    let load_filesz = seg_start + seg_size;
    let mut phdr_load = [0u8; ELF64_PHDR_SIZE];
    phdr_load[0..4].copy_from_slice(&PT_LOAD.to_le_bytes());
    phdr_load[4..8].copy_from_slice(&(PF_R | PF_W | PF_X).to_le_bytes());
    phdr_load[8..16].copy_from_slice(&0u64.to_le_bytes());
    phdr_load[16..24].copy_from_slice(&load_vaddr.to_le_bytes());
    phdr_load[24..32].copy_from_slice(&load_vaddr.to_le_bytes());
    phdr_load[32..40].copy_from_slice(&load_filesz.to_le_bytes());
    phdr_load[40..48].copy_from_slice(&(seg_start + mem_size).to_le_bytes());
    phdr_load[48..56].copy_from_slice(&seg_align.to_le_bytes());
    out.write_all(&phdr_load)?;

    let mut phdr_dynamic = [0u8; ELF64_PHDR_SIZE];
    phdr_dynamic[0..4].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
    phdr_dynamic[8..16].copy_from_slice(&dynamic_offset.to_le_bytes());
    phdr_dynamic[16..24].copy_from_slice(&dynamic_vaddr.to_le_bytes());
    phdr_dynamic[24..32].copy_from_slice(&dynamic_vaddr.to_le_bytes());
    let dyn_sz = layout
        .section_by_name
        .get(".dynamic")
        .and_then(|&i| layout.sections.get(i))
        .map(|s| s.data.len() as u64)
        .unwrap_or(0);
    phdr_dynamic[32..40].copy_from_slice(&dyn_sz.to_le_bytes());
    phdr_dynamic[40..48].copy_from_slice(&dyn_sz.to_le_bytes());
    out.write_all(&phdr_dynamic)?;

    // PT_INTERP: the kernel reads the path from p_offset, but glibc's dl_main
    // ALSO reads it in memory via p_vaddr to set _dl_rtld_libname.name. The
    // interp string lives in the header padding gap which is inside the first
    // PT_LOAD (it covers file offset 0), so it is mapped at this vaddr.
    let interp_vaddr = load_vaddr + interp_file_off;
    let mut phdr_interp = [0u8; ELF64_PHDR_SIZE];
    phdr_interp[0..4].copy_from_slice(&PT_INTERP.to_le_bytes());
    phdr_interp[4..8].copy_from_slice(&PF_R.to_le_bytes());
    phdr_interp[8..16].copy_from_slice(&interp_file_off.to_le_bytes()); // file offset
    phdr_interp[16..24].copy_from_slice(&interp_vaddr.to_le_bytes()); // p_vaddr (mapped)
    phdr_interp[24..32].copy_from_slice(&interp_vaddr.to_le_bytes()); // p_paddr
    phdr_interp[32..40].copy_from_slice(&(interp_len as u64).to_le_bytes());
    phdr_interp[40..48].copy_from_slice(&(interp_len as u64).to_le_bytes());
    out.write_all(&phdr_interp)?;

    let mut phdr_stack = [0u8; ELF64_PHDR_SIZE];
    phdr_stack[0..4].copy_from_slice(&PT_GNU_STACK.to_le_bytes());
    phdr_stack[4..8].copy_from_slice(&(PF_R | PF_W).to_le_bytes());
    out.write_all(&phdr_stack)?;

    let mut extra_header = |kind: u32, address: u64, size: u64, align: u64| -> Result<()> {
        let mut header = [0u8; ELF64_PHDR_SIZE];
        header[..4].copy_from_slice(&kind.to_le_bytes());
        header[4..8].copy_from_slice(&PF_R.to_le_bytes());
        header[8..16].copy_from_slice(&(seg_start + address - base).to_le_bytes());
        header[16..24].copy_from_slice(&address.to_le_bytes());
        header[24..32].copy_from_slice(&address.to_le_bytes());
        header[32..40].copy_from_slice(&size.to_le_bytes());
        header[40..48].copy_from_slice(&size.to_le_bytes());
        header[48..56].copy_from_slice(&align.to_le_bytes());
        out.write_all(&header)
    };
    if let Some(section) = unwind {
        extra_header(0x6474e550, section.vaddr, section.data.len() as u64, 4)?;
    }
    if let Some(start) = protected.iter().map(|s| s.vaddr).min() {
        let end = protected
            .iter()
            .map(|s| s.vaddr + s.data.len() as u64)
            .max()
            .unwrap();
        extra_header(0x6474e552, start, end - start, 1)?;
    }

    // Write interpreter string in the padding gap, then pad to seg_start.
    out.write_all(interp_bytes.as_bytes())?;
    let used = ph_size + interp_len;
    let pad_to_seg = (seg_start as usize) - (phoff as usize) - used;
    if pad_to_seg > 0 {
        out.write_all(&vec![0u8; pad_to_seg])?;
    }
    // Write code segment (no INTERP prefix — sections map to correct VAs).
    out.write_all(&seg_buffer)?;
    out.write_all(&metadata.bytes)?;

    Ok(())
}

fn seg_offset_for_metadata(ehdr: &[u8; 64], align: u64) -> u64 {
    let phnum = u16::from_le_bytes(ehdr[56..58].try_into().unwrap()) as u64;
    align_up_u64(64 + phnum * ELF64_PHDR_SIZE as u64, align)
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
            headers.push(SectionHeader {
                name_offset,
                sh_type: kind,
                sh_flags: section.flags,
                sh_addr: section.vaddr,
                sh_offset: segment_offset + section.vaddr - base,
                sh_size: section.data.len() as u64,
                sh_link: link,
                sh_info: info,
                sh_addralign: section.align,
                sh_entsize: entsize,
            });
        }
        let mut strtab = vec![0];
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
                    let offset = strtab.len() as u32;
                    strtab.extend_from_slice(symbol.name.as_bytes());
                    strtab.push(0);
                    offset
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
