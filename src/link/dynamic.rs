//! ELF dynamic linking: .dynsym, .dynstr, DT_HASH, the PLT/GOT, and the .dynamic section.

use super::merge::{MergedLayout, align_up};

/// Four binary blobs produced when building ELF dynamic sections:
/// `.dynsym`, `.dynstr`, `.rela.plt`, and `.hash` (SysV DT_HASH).
pub(super) type DynSections = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u32>,
    Option<u32>,
    Option<u32>,
);
/// Standard SysV ELF hash function (used by DT_HASH).
pub(super) fn elf_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &b in name {
        h = (h << 4).wrapping_add(b as u32);
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

/// Build a SysV (.hash / DT_HASH) table over the dynamic symbol table.
/// `sym_names[i]` is the name of dynsym entry `i + 1` (entry 0 is the reserved
/// null symbol). The dynamic linker requires this to resolve symbols by name.
pub(super) fn build_sysv_hash(sym_names: &[&str]) -> Vec<u8> {
    let nchain = (sym_names.len() + 1) as u32;
    let nbucket = nchain.max(1);
    let mut buckets = vec![0u32; nbucket as usize];
    let mut chains = vec![0u32; nchain as usize];

    for (i, name) in sym_names.iter().enumerate() {
        let sym_idx = (i + 1) as u32;
        let b = (elf_hash(name.as_bytes()) % nbucket) as usize;
        chains[sym_idx as usize] = buckets[b];
        buckets[b] = sym_idx;
    }

    let mut out = Vec::with_capacity((2 + nbucket as usize + nchain as usize) * 4);
    out.extend_from_slice(&nbucket.to_le_bytes());
    out.extend_from_slice(&nchain.to_le_bytes());
    for b in &buckets {
        out.extend_from_slice(&b.to_le_bytes());
    }
    for c in &chains {
        out.extend_from_slice(&c.to_le_bytes());
    }
    out
}
#[derive(Debug, Default)]
pub struct DynamicLinkInfo {
    pub pie: bool,
    pub shared: bool,
    pub needed: Vec<String>,
    pub plt_symbols: Vec<String>,
    pub weak_plt_symbols: Vec<String>,
    pub interpreter: Option<String>,
    pub macho_rebase_addrs: Vec<u64>,
    pub macho_direct_binds: Vec<(u64, String, bool, i64)>,
}
/// Build the raw bytes for `.dynsym`, `.dynstr`, `.rela.plt`, and `.hash`
/// (SysV `DT_HASH`) from the list of symbols that require PLT entries.
///
/// `got_plt_vaddr` is the virtual address of `.got.plt`; it is used to compute
/// each `R_X86_64_JUMP_SLOT` relocation's `r_offset` (GOT slot address).
pub(super) fn build_dynamic_sections(
    plt_symbols: &[String],
    got_plt_vaddr: u64,
    needed: &[String],
    rpaths: &[String],
    exports: &[String],
    soname: Option<&str>,
) -> Result<DynSections, String> {
    let mut dynstr = vec![0u8];
    let mut needed_offsets: Vec<u32> = Vec::with_capacity(needed.len());
    let mut runpath_offset = None;
    let mut soname_offset = None;
    for soname in needed {
        needed_offsets.push(dynstr.len() as u32);
        dynstr.extend_from_slice(soname.as_bytes());
        dynstr.push(0);
    }
    if !rpaths.is_empty() {
        runpath_offset = Some(dynstr.len() as u32);
        dynstr.extend_from_slice(rpaths.join(":").as_bytes());
        dynstr.push(0);
    }
    if let Some(name) = soname {
        soname_offset = Some(dynstr.len() as u32);
        dynstr.extend_from_slice(name.as_bytes());
        dynstr.push(0);
    }

    let mut str_offsets: Vec<u32> = Vec::with_capacity(plt_symbols.len());
    for sym in plt_symbols {
        let off = dynstr.len() as u32;
        str_offsets.push(off);
        dynstr.extend_from_slice(sym.split('@').next().unwrap().as_bytes());
        dynstr.push(0);
    }

    // dynsym[0] MUST be the reserved STN_UNDEF null entry. Real symbols start
    // at index 1, so rela.plt r_sym below is (i + 1).
    let mut dynsym = vec![0u8; 24];
    for &off in &str_offsets {
        dynsym.extend_from_slice(&off.to_le_bytes());
        dynsym.push((1 << 4) | 2);
        dynsym.push(0);
        dynsym.extend_from_slice(&0u16.to_le_bytes());
        dynsym.extend_from_slice(&0u64.to_le_bytes());
        dynsym.extend_from_slice(&0u64.to_le_bytes());
    }
    let mut export_names: Vec<&str> = Vec::with_capacity(exports.len());
    for name in exports {
        let off = dynstr.len() as u32;
        dynstr.extend_from_slice(name.as_bytes());
        dynstr.push(0);
        dynsym.extend_from_slice(&off.to_le_bytes());
        dynsym.push(1 << 4);
        dynsym.push(0);
        dynsym.extend_from_slice(&1u16.to_le_bytes());
        dynsym.extend_from_slice(&0u64.to_le_bytes());
        dynsym.extend_from_slice(&0u64.to_le_bytes());
        export_names.push(name);
    }

    let mut rela_plt = Vec::with_capacity(plt_symbols.len() * 24);
    for (i, _) in plt_symbols.iter().enumerate() {
        let r_offset = got_plt_vaddr + 24 + (i as u64) * 8;
        // r_sym = i + 1 because dynsym index 0 is the reserved null entry.
        let r_info = (((i + 1) as u64) << 32) | 7u64;
        rela_plt.extend_from_slice(&r_offset.to_le_bytes());
        rela_plt.extend_from_slice(&r_info.to_le_bytes());
        rela_plt.extend_from_slice(&0i64.to_le_bytes());
    }

    let mut name_refs: Vec<&str> = plt_symbols
        .iter()
        .map(|s| s.split('@').next().unwrap())
        .collect();
    name_refs.extend(export_names);
    let hash = build_sysv_hash(&name_refs);

    Ok((
        dynsym,
        dynstr,
        rela_plt,
        hash,
        needed_offsets,
        runpath_offset,
        soname_offset,
    ))
}

/// Build the raw bytes for the `.dynamic` section (`Elf64_Dyn` array).
///
/// Emits `DT_HASH`, one `DT_NEEDED` per requested library, `DT_STRTAB`,
/// `DT_SYMTAB`, `DT_STRSZ`, `DT_SYMENT`, `DT_PLTGOT`, `DT_PLTRELSZ`,
/// `DT_PLTREL`, `DT_JMPREL`, `DT_BIND_NOW`, `DT_FLAGS` (`DF_BIND_NOW`),
/// `DT_FLAGS_1` (`DF_1_NOW`), and a `DT_NULL` terminator.
pub(super) struct DynamicAddrs {
    pub(super) got_plt_vaddr: u64,
    pub(super) dynsym_vaddr: u64,
    pub(super) dynstr_vaddr: u64,
    pub(super) dynstr_size: u64,
    pub(super) rela_plt_vaddr: u64,
    pub(super) rela_plt_size: u64,
    pub(super) hash_vaddr: u64,
    pub(super) pie: bool,
    pub(super) shared: bool,
}

pub(super) fn build_dynamic_section_content(
    addrs: &DynamicAddrs,
    needed_offsets: &[u32],
    runpath_offset: Option<u32>,
    soname_offset: Option<u32>,
) -> Result<Vec<u8>, String> {
    let DynamicAddrs {
        got_plt_vaddr,
        dynsym_vaddr,
        dynstr_vaddr,
        dynstr_size,
        rela_plt_vaddr,
        rela_plt_size,
        hash_vaddr,
        pie,
        shared,
    } = *addrs;
    let mut content = Vec::new();
    fn push_dyn(content: &mut Vec<u8>, tag: u64, val: u64) {
        content.extend_from_slice(&tag.to_le_bytes());
        content.extend_from_slice(&val.to_le_bytes());
    }
    push_dyn(&mut content, 4, hash_vaddr);
    for &off in needed_offsets {
        push_dyn(&mut content, 1, off as u64);
    }
    if let Some(off) = runpath_offset {
        push_dyn(&mut content, 29, off as u64);
    }
    if let Some(off) = soname_offset {
        push_dyn(&mut content, 14, off as u64);
    }
    push_dyn(&mut content, 5, dynstr_vaddr);
    push_dyn(&mut content, 6, dynsym_vaddr);
    push_dyn(&mut content, 10, dynstr_size);
    push_dyn(&mut content, 11, 24);
    push_dyn(&mut content, 3, got_plt_vaddr);
    push_dyn(&mut content, 2, rela_plt_size);
    push_dyn(&mut content, 20, 7);
    push_dyn(&mut content, 23, rela_plt_vaddr);
    // Force eager binding: loader resolves all JUMP_SLOT relocs at startup and
    // writes the final symbol address into each GOT slot. Avoids needing lazy
    // PLT trampoline state (GOT[0]=_DYNAMIC, GOT slot back-pointers).
    push_dyn(&mut content, 24, 0);
    push_dyn(&mut content, 30, 0x8);
    push_dyn(
        &mut content,
        0x6ffffffb,
        0x1 | if pie && !shared { 0x08000000 } else { 0 },
    );
    if shared {
        push_dyn(&mut content, 7, 0);
        push_dyn(&mut content, 8, 0);
        push_dyn(&mut content, 9, 24);
    }
    if pie {
        push_dyn(&mut content, 0x6ffffff9, 0);
    }
    push_dyn(&mut content, 0, 0);
    Ok(content)
}

/// Build the `.plt` and `.got.plt` byte vectors for x86_64 dynamic linking.
///
/// Returns `(plt_bytes, got_plt_bytes)`. The GOT is initialised to all-zeros;
/// the dynamic linker fills in the final symbol addresses at load time.
pub(super) fn build_plt_got_x86_64(
    plt_symbols: &[String],
    layout: &MergedLayout,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let last = layout.sections.last().ok_or("no sections")?;
    let vaddr = align_up(last.vaddr + last.data.len() as u64, 16);
    let plt0_vaddr = vaddr;
    let plt_size = 16 + (plt_symbols.len() as u64) * 16;
    let got_plt_vaddr = align_up(vaddr + plt_size, 8);

    let mut plt = Vec::new();
    plt.extend_from_slice(&[0xff, 0x35]);
    let disp_push = (got_plt_vaddr as i64 + 8 - (plt0_vaddr as i64 + 6)) as i32;
    plt.extend_from_slice(&disp_push.to_le_bytes());
    plt.extend_from_slice(&[0xff, 0x25]);
    let disp_jmp = (got_plt_vaddr as i64 + 16 - (plt0_vaddr as i64 + 12)) as i32;
    plt.extend_from_slice(&disp_jmp.to_le_bytes());
    // Pad PLT0 to the full 16-byte stride. PLT[i] entries are addressed at
    // plt0 + 16 + i*16, so PLT0 must occupy exactly 16 bytes (12 used + 4 pad).
    plt.extend_from_slice(&[0x90, 0x90, 0x90, 0x90]);

    for (i, _) in plt_symbols.iter().enumerate() {
        let plt_n_vaddr = plt0_vaddr + 16 + (i as u64) * 16;
        let got_slot_vaddr = got_plt_vaddr + 24 + (i as u64) * 8;
        plt.extend_from_slice(&[0xff, 0x25]);
        let disp = (got_slot_vaddr as i64 - (plt_n_vaddr as i64 + 6)) as i32;
        plt.extend_from_slice(&disp.to_le_bytes());
        plt.push(0x68);
        plt.extend_from_slice(&(i as u32).to_le_bytes());
        plt.extend_from_slice(&[0xe9]);
        let jmp_disp = (plt0_vaddr as i64 - (plt_n_vaddr as i64 + 11)) as i32;
        plt.extend_from_slice(&jmp_disp.to_le_bytes());
    }

    let got_size = 24 + plt_symbols.len() * 8;
    let got = vec![0u8; got_size];

    Ok((plt, got))
}

pub(super) fn set_relative_tags(layout: &mut MergedLayout, count: u64) {
    let relaidx = layout.section_by_name[".rela.dyn"];
    let dynidx = layout.section_by_name[".dynamic"];
    let address = layout.sections[relaidx].vaddr;
    let size = layout.sections[relaidx].data.len() as u64;
    for record in layout.sections[dynidx].data.as_chunks_mut::<16>().0 {
        let value = match u64::from_le_bytes(record[..8].try_into().unwrap()) {
            7 => address,
            8 => size,
            9 => 24,
            0x6ffffff9 => count,
            _ => continue,
        };
        record[8..].copy_from_slice(&value.to_le_bytes());
    }
}
