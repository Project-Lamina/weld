//! Relocatable output (`-r`): combine ELF64 relocatable objects into one
//! relocatable object. Sections are concatenated by name, global symbols are
//! merged by name, and relocations are rebased and left unapplied.

use crate::collections::HashMap;
use crate::elf::{
    SectionHeader, get_strtab_from_section, get_strtab_string, parse_elf64_slice,
    parse_rela_section, parse_symtab,
};

const SHT_NULL: u32 = 0;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_RELA: u32 = 4;
const SHT_REL: u32 = 9;
const SHT_NOBITS: u32 = 8;
const SHT_STRTAB: u32 = 3;
const SHT_GROUP: u32 = 17;
const SHT_SYMTAB_SHNDX: u32 = 18;
const SHF_INFO_LINK: u64 = 0x40;

const SHN_UNDEF: u16 = 0;
const SHN_ABS: u16 = 0xfff1;
const SHN_LORESERVE: u16 = 0xff00;
const STB_LOCAL: u8 = 0;
const STB_WEAK: u8 = 2;
const STT_SECTION: u8 = 3;
const STT_FILE: u8 = 4;

const ELF64_HEADER_SIZE: usize = 64;
const ELF64_SHDR_SIZE: usize = 64;
const ELF64_SYM_SIZE: usize = 24;
const ELF64_RELA_SIZE: usize = 24;

struct Input<'a> {
    data: &'a [u8],
    sections: Vec<SectionHeader>,
    names: Vec<String>,
}

struct OutSection {
    name: String,
    sh_type: u32,
    flags: u64,
    align: u64,
    entsize: u64,
    len: u64,
    data: Vec<u8>,
}

#[derive(Clone)]
struct OutSymbol {
    name: String,
    info: u8,
    shndx: u16,
    value: u64,
    size: u64,
}

#[derive(Clone, Copy)]
struct Placement {
    section: usize,
    offset: u64,
}

#[derive(Clone, Copy)]
enum SymRef {
    Local(usize),
    Global(usize),
}

#[derive(Clone, Copy)]
struct Mapped {
    sym: SymRef,
    bias: u64,
}

struct Rela {
    target: usize,
    entries: Vec<(u64, u32, u32, i64)>,
}

fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        value
    } else {
        value.div_ceil(align) * align
    }
}

fn place(out: &mut OutSection, align: u64, payload: Option<&[u8]>, size: u64) -> u64 {
    out.align = out.align.max(align);
    let offset = align_up(out.len, align);
    match payload {
        Some(bytes) => {
            if out.sh_type == SHT_NOBITS {
                out.sh_type = SHT_PROGBITS;
                out.data.resize(out.len as usize, 0);
            }
            out.data.resize(offset as usize, 0);
            out.data.extend_from_slice(bytes);
            out.len = offset + bytes.len() as u64;
        }
        None => {
            if out.sh_type != SHT_NOBITS {
                out.data.resize((offset + size) as usize, 0);
            }
            out.len = offset + size;
        }
    }
    offset
}

fn section_bytes<'a>(input: &Input<'a>, sh: &SectionHeader) -> Result<&'a [u8], String> {
    let start = sh.sh_offset as usize;
    input
        .data
        .get(start..start + sh.sh_size as usize)
        .ok_or_else(|| "section extends past end of file".to_string())
}

fn add_name(table: &mut Vec<u8>, name: &str) -> u32 {
    if name.is_empty() {
        return 0;
    }
    let off = table.len() as u32;
    table.extend_from_slice(name.as_bytes());
    table.push(0);
    off
}

fn push_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn push_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn push_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

struct Shdr {
    name: u32,
    sh_type: u32,
    flags: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    align: u64,
    entsize: u64,
}

fn push_shdr(buf: &mut Vec<u8>, h: &Shdr) {
    push_u32(buf, h.name);
    push_u32(buf, h.sh_type);
    push_u64(buf, h.flags);
    push_u64(buf, 0);
    push_u64(buf, h.offset);
    push_u64(buf, h.size);
    push_u32(buf, h.link);
    push_u32(buf, h.info);
    push_u64(buf, h.align);
    push_u64(buf, h.entsize);
}

/// Combine `objects` into one ELF64 relocatable object and return its bytes.
pub fn link_relocatable(objects: &[&[u8]]) -> Result<Vec<u8>, String> {
    if objects.is_empty() {
        return Err("no objects to link".into());
    }
    let mut inputs = Vec::with_capacity(objects.len());
    for data in objects {
        let (_, sections, names) = parse_elf64_slice(data)?;
        inputs.push(Input {
            data,
            sections,
            names,
        });
    }
    let first = objects[0];
    let machine = u16::from_le_bytes([first[18], first[19]]);
    for (i, data) in objects.iter().enumerate() {
        let e_type = u16::from_le_bytes([data[16], data[17]]);
        let e_machine = u16::from_le_bytes([data[18], data[19]]);
        if e_type != 1 {
            return Err(format!("input {i} is not a relocatable object"));
        }
        if e_machine != machine {
            return Err(format!("input {i} has a different machine type"));
        }
    }

    let mut sections: Vec<OutSection> = Vec::new();
    let mut section_index: HashMap<String, usize> = HashMap::default();
    let mut placements: Vec<Vec<Option<Placement>>> = Vec::with_capacity(inputs.len());
    for input in &inputs {
        let mut map = vec![None; input.sections.len()];
        for (i, sh) in input.sections.iter().enumerate() {
            match sh.sh_type {
                SHT_NULL | SHT_SYMTAB | SHT_STRTAB | SHT_RELA => continue,
                SHT_REL => return Err(".rel relocation sections are not supported by -r".into()),
                SHT_GROUP => return Err("COMDAT groups are not supported by -r".into()),
                SHT_SYMTAB_SHNDX => return Err("SHT_SYMTAB_SHNDX is not supported by -r".into()),
                _ => {}
            }
            let name = input.names[i].clone();
            let idx = *section_index.entry(name.clone()).or_insert_with(|| {
                sections.push(OutSection {
                    name: name.clone(),
                    sh_type: sh.sh_type,
                    flags: 0,
                    align: 1,
                    entsize: sh.sh_entsize,
                    len: 0,
                    data: Vec::new(),
                });
                sections.len() - 1
            });
            let out = &mut sections[idx];
            out.flags |= sh.sh_flags;
            let align = sh.sh_addralign.max(1);
            let offset = if sh.sh_type == SHT_NOBITS {
                place(out, align, None, sh.sh_size)
            } else {
                place(out, align, Some(section_bytes(input, sh)?), 0)
            };
            map[i] = Some(Placement {
                section: idx,
                offset,
            });
        }
        placements.push(map);
    }

    let mut symbol_tables = Vec::with_capacity(inputs.len());
    for input in &inputs {
        let table = input
            .sections
            .iter()
            .find(|sh| sh.sh_type == SHT_SYMTAB)
            .map(|sh| {
                let symbols = parse_symtab(input.data, sh)?;
                let strtab_sh = &input.sections[sh.sh_link as usize];
                let strtab = get_strtab_from_section(input.data, strtab_sh);
                Ok::<_, String>((symbols, strtab))
            })
            .transpose()?;
        symbol_tables.push(table);
    }
    let mut sym_maps: Vec<Vec<Option<Mapped>>> = symbol_tables
        .iter()
        .map(|t| t.as_ref().map_or(Vec::new(), |(s, _)| vec![None; s.len()]))
        .collect();

    let mut locals: Vec<OutSymbol> = Vec::new();
    let mut globals: Vec<OutSymbol> = Vec::new();
    let mut global_by_name: HashMap<String, usize> = HashMap::default();

    for (k, table) in symbol_tables.iter().enumerate() {
        let Some((symbols, strtab)) = table else {
            continue;
        };
        for (j, sym) in symbols.iter().enumerate().skip(1) {
            if sym.bind != STB_LOCAL || sym.sym_type == STT_FILE {
                continue;
            }
            if sym.sym_type == STT_SECTION {
                let Some(p) = placements[k].get(sym.st_shndx as usize).copied().flatten() else {
                    continue;
                };
                locals.push(OutSymbol {
                    name: String::new(),
                    info: (STB_LOCAL << 4) | STT_SECTION,
                    shndx: p.section as u16 + 1,
                    value: 0,
                    size: 0,
                });
                sym_maps[k][j] = Some(Mapped {
                    sym: SymRef::Local(locals.len() - 1),
                    bias: p.offset,
                });
                continue;
            }
            let name = get_strtab_string(strtab, sym.name_offset).unwrap_or_default();
            let (shndx, value) = match sym.st_shndx {
                SHN_UNDEF => continue,
                SHN_ABS => (SHN_ABS, sym.st_value),
                s if s >= SHN_LORESERVE => {
                    return Err(format!(
                        "unsupported section index {s} for local symbol {name}"
                    ));
                }
                s => match placements[k][s as usize] {
                    Some(p) => (p.section as u16 + 1, sym.st_value + p.offset),
                    None => continue,
                },
            };
            locals.push(OutSymbol {
                name,
                info: (sym.bind << 4) | sym.sym_type,
                shndx,
                value,
                size: sym.st_size,
            });
            sym_maps[k][j] = Some(Mapped {
                sym: SymRef::Local(locals.len() - 1),
                bias: 0,
            });
        }
    }

    for (k, table) in symbol_tables.iter().enumerate() {
        let Some((symbols, strtab)) = table else {
            continue;
        };
        for (j, sym) in symbols.iter().enumerate().skip(1) {
            if sym.bind == STB_LOCAL {
                continue;
            }
            let name = get_strtab_string(strtab, sym.name_offset).unwrap_or_default();
            let weak = sym.bind == STB_WEAK;
            let defined = sym.st_shndx != SHN_UNDEF;
            let (shndx, value) = if !defined {
                (SHN_UNDEF, 0)
            } else if sym.st_shndx == SHN_ABS {
                (SHN_ABS, sym.st_value)
            } else if sym.st_shndx >= SHN_LORESERVE {
                return Err(format!("unsupported section index for symbol {name}"));
            } else {
                match placements[k][sym.st_shndx as usize] {
                    Some(p) => (p.section as u16 + 1, sym.st_value + p.offset),
                    None => return Err(format!("symbol {name} is defined in a dropped section")),
                }
            };
            let candidate = OutSymbol {
                name: name.clone(),
                info: (sym.bind << 4) | sym.sym_type,
                shndx,
                value,
                size: sym.st_size,
            };
            let index = match global_by_name.get(&name).copied() {
                None => {
                    globals.push(candidate);
                    global_by_name.insert(name, globals.len() - 1);
                    globals.len() - 1
                }
                Some(i) => {
                    let existing = &globals[i];
                    let existing_defined = existing.shndx != SHN_UNDEF;
                    let existing_weak = existing.info >> 4 == STB_WEAK;
                    if !defined {
                        i
                    } else if !existing_defined {
                        globals[i] = candidate;
                        i
                    } else if weak {
                        i
                    } else if existing_weak {
                        globals[i] = candidate;
                        i
                    } else {
                        return Err(format!("multiple definition of {name}"));
                    }
                }
            };
            sym_maps[k][j] = Some(Mapped {
                sym: SymRef::Global(index),
                bias: 0,
            });
        }
    }

    let local_count = locals.len();
    let symbol_index = |sym: SymRef| -> u32 {
        match sym {
            SymRef::Local(i) => 1 + i as u32,
            SymRef::Global(i) => 1 + local_count as u32 + i as u32,
        }
    };

    let mut relas: Vec<Rela> = Vec::new();
    for (k, input) in inputs.iter().enumerate() {
        for sh in input.sections.iter().filter(|sh| sh.sh_type == SHT_RELA) {
            let target = sh.sh_info as usize;
            let Some(p) = placements[k].get(target).copied().flatten() else {
                continue;
            };
            let relocs = parse_rela_section(input.data, sh)?;
            let mut entries = Vec::with_capacity(relocs.len());
            for rel in relocs {
                let (index, bias) = if rel.r_sym == 0 {
                    (0, 0)
                } else {
                    match sym_maps[k].get(rel.r_sym as usize).and_then(Option::as_ref) {
                        Some(m) => (symbol_index(m.sym), m.bias),
                        None => {
                            return Err(format!(
                                "relocation against symbol {} that is not kept",
                                rel.r_sym
                            ));
                        }
                    }
                };
                entries.push((
                    rel.r_offset + p.offset,
                    rel.r_type,
                    index,
                    rel.r_addend.wrapping_add(bias as i64),
                ));
            }
            match relas.iter_mut().find(|r| r.target == p.section) {
                Some(r) => r.entries.extend(entries),
                None => relas.push(Rela {
                    target: p.section,
                    entries,
                }),
            }
        }
    }

    let mut strtab = vec![0u8];
    let mut shstrtab = vec![0u8];

    let mut symtab = Vec::with_capacity((1 + locals.len() + globals.len()) * ELF64_SYM_SIZE);
    symtab.extend_from_slice(&[0u8; ELF64_SYM_SIZE]);
    for sym in locals.iter().chain(globals.iter()) {
        let off = add_name(&mut strtab, &sym.name);
        push_u32(&mut symtab, off);
        symtab.push(sym.info);
        symtab.push(0);
        push_u16(&mut symtab, sym.shndx);
        push_u64(&mut symtab, sym.value);
        push_u64(&mut symtab, sym.size);
    }

    let nout = sections.len();
    let nrela = relas.len();
    let symtab_shndx = (1 + nout + nrela) as u32;
    let strtab_shndx = symtab_shndx + 1;
    let shstrtab_shndx = symtab_shndx + 2;
    let shnum = shstrtab_shndx as usize + 1;

    let mut shstr_names = Vec::with_capacity(shnum);
    for s in &sections {
        shstr_names.push(add_name(&mut shstrtab, &s.name));
    }
    let mut rela_names = Vec::with_capacity(nrela);
    for r in &relas {
        let name = format!(".rela{}", sections[r.target].name);
        rela_names.push(add_name(&mut shstrtab, &name));
    }
    let symtab_name = add_name(&mut shstrtab, ".symtab");
    let strtab_name = add_name(&mut shstrtab, ".strtab");
    let shstrtab_name = add_name(&mut shstrtab, ".shstrtab");

    let mut body: Vec<u8> = vec![0; ELF64_HEADER_SIZE];
    let mut section_offsets = Vec::with_capacity(nout);
    let mut section_sizes = Vec::with_capacity(nout);
    for s in &sections {
        let align = s.align.max(1);
        body.resize(align_up(body.len() as u64, align) as usize, 0);
        section_offsets.push(body.len() as u64);
        section_sizes.push(s.len);
        if s.sh_type != SHT_NOBITS {
            body.extend_from_slice(&s.data);
        }
    }
    let mut rela_offsets = Vec::with_capacity(nrela);
    let mut rela_sizes = Vec::with_capacity(nrela);
    for r in &relas {
        body.resize(align_up(body.len() as u64, 8) as usize, 0);
        rela_offsets.push(body.len() as u64);
        let start = body.len();
        for &(off, ty, sym, addend) in &r.entries {
            push_u64(&mut body, off);
            push_u64(&mut body, (sym as u64) << 32 | ty as u64);
            push_u64(&mut body, addend as u64);
        }
        rela_sizes.push((body.len() - start) as u64);
    }
    body.resize(align_up(body.len() as u64, 8) as usize, 0);
    let symtab_offset = body.len() as u64;
    body.extend_from_slice(&symtab);
    let strtab_offset = body.len() as u64;
    body.extend_from_slice(&strtab);
    let shstrtab_offset = body.len() as u64;
    body.extend_from_slice(&shstrtab);
    body.resize(align_up(body.len() as u64, 8) as usize, 0);
    let shoff = body.len() as u64;

    let mut shdrs = Vec::with_capacity(shnum * ELF64_SHDR_SIZE);
    shdrs.extend_from_slice(&[0u8; ELF64_SHDR_SIZE]);
    for (i, s) in sections.iter().enumerate() {
        push_shdr(
            &mut shdrs,
            &Shdr {
                name: shstr_names[i],
                sh_type: s.sh_type,
                flags: s.flags,
                offset: section_offsets[i],
                size: section_sizes[i],
                link: 0,
                info: 0,
                align: s.align.max(1),
                entsize: s.entsize,
            },
        );
    }
    for (i, r) in relas.iter().enumerate() {
        push_shdr(
            &mut shdrs,
            &Shdr {
                name: rela_names[i],
                sh_type: SHT_RELA,
                flags: SHF_INFO_LINK,
                offset: rela_offsets[i],
                size: rela_sizes[i],
                link: symtab_shndx,
                info: r.target as u32 + 1,
                align: 8,
                entsize: ELF64_RELA_SIZE as u64,
            },
        );
    }
    push_shdr(
        &mut shdrs,
        &Shdr {
            name: symtab_name,
            sh_type: SHT_SYMTAB,
            flags: 0,
            offset: symtab_offset,
            size: symtab.len() as u64,
            link: strtab_shndx,
            info: 1 + local_count as u32,
            align: 8,
            entsize: ELF64_SYM_SIZE as u64,
        },
    );
    push_shdr(
        &mut shdrs,
        &Shdr {
            name: strtab_name,
            sh_type: SHT_STRTAB,
            flags: 0,
            offset: strtab_offset,
            size: strtab.len() as u64,
            link: 0,
            info: 0,
            align: 1,
            entsize: 0,
        },
    );
    push_shdr(
        &mut shdrs,
        &Shdr {
            name: shstrtab_name,
            sh_type: SHT_STRTAB,
            flags: 0,
            offset: shstrtab_offset,
            size: shstrtab.len() as u64,
            link: 0,
            info: 0,
            align: 1,
            entsize: 0,
        },
    );
    body.extend_from_slice(&shdrs);

    let mut out = body;
    out[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    out[4] = 2;
    out[5] = 1;
    out[6] = 1;
    out[7] = first[7];
    out[16..18].copy_from_slice(&1u16.to_le_bytes());
    out[18..20].copy_from_slice(&machine.to_le_bytes());
    out[20..24].copy_from_slice(&1u32.to_le_bytes());
    out[40..48].copy_from_slice(&shoff.to_le_bytes());
    out[48..52].copy_from_slice(&first[48..52]);
    out[52..54].copy_from_slice(&(ELF64_HEADER_SIZE as u16).to_le_bytes());
    out[58..60].copy_from_slice(&(ELF64_SHDR_SIZE as u16).to_le_bytes());
    out[60..62].copy_from_slice(&(shnum as u16).to_le_bytes());
    out[62..64].copy_from_slice(&(shstrtab_shndx as u16).to_le_bytes());
    Ok(out)
}
