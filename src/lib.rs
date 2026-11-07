//! weld - Cross-platform linker for Lamina
//!
//! Native linking only. Supports object files and dynamic libs (-lc, -lSystem).
//! No delegation to system linker.
//!
//! The command line is the interface: [`main`] runs one link from `std::env::args`
//! and exits with the linker's status, exactly as the `weld` binary does.

mod arch;
mod archive;
mod cli;
mod coff;
mod collections;
mod elf;
mod emit;
mod link;
mod macho;
mod object;
mod parallel;
mod platform;
mod segment;
#[cfg(test)]
mod test_support;
mod timing;

use crate::{
    arch::TargetArch,
    cli::{ParseAction, ParsedArgs, parse_args, print_usage},
    link::{
        DynamicLinkInfo, LibraryResolver, LinkOptions, LinkResult, MergedSection,
        macho::link_macho_multi_object,
    },
    object::ObjectFormat,
    platform::TargetPlatform,
};
use std::{
    env,
    io::Write,
    path::{Path, PathBuf},
};

const ELFOSABI_NONE: u8 = 0;
const ELFOSABI_FREEBSD: u8 = 9;

/// Command-line settings the linker needs, gathered in one place.
fn link_options(args: &ParsedArgs) -> LinkOptions {
    LinkOptions {
        pie: args.pie || args.shared,
        shared: args.shared,
        soname: args.soname.clone(),
        build_id: args.build_id,
        static_link: args.static_link,
        interpreter: args.dynamic_linker.clone(),
        search_paths: args.search_paths.clone(),
        rpaths: args.rpaths.clone(),
        library_as_needed: args.library_as_needed.clone(),
        library_positions: args.library_positions.clone(),
        gc_sections: args.gc_sections,
        gc_roots: entry_seeds(args),
        object_positions: Vec::new(),
        target_os: args.target_os.clone(),
    }
}

fn os_abi_for_target(target_os: Option<&str>) -> u8 {
    match target_os {
        Some("orbis") | Some("ps4") | Some("prospero") | Some("ps5") | Some("freebsd") => {
            ELFOSABI_FREEBSD
        }
        _ => ELFOSABI_NONE,
    }
}

/// Create the output, unlinking any previous file first. Truncating in place returns ETXTBSY when relinking a binary that is still running.
fn create_output(path: &Path) -> std::io::Result<std::fs::File> {
    let _ = std::fs::remove_file(path);
    std::fs::File::create(path)
}

#[cfg(unix)]
fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(mut perms) = std::fs::metadata(path).map(|m| m.permissions()) {
        perms.set_mode(0o755);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) {}

#[cfg(target_os = "macos")]
fn ad_hoc_codesign(path: &Path) -> std::io::Result<()> {
    let status = std::process::Command::new("codesign")
        .arg("-s")
        .arg("-")
        .arg("-f")
        .arg(path)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other("codesign failed"))
    }
}

#[cfg(not(target_os = "macos"))]
fn ad_hoc_codesign(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// The version of this linker, as `--version` prints it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// What a link reports when it fails. The message is what the command line prints
/// after `weld: `.
type LinkResultOrMessage = std::result::Result<(), String>;

/// An output file error, named after the file.
fn output_error(path: &Path, error: impl std::fmt::Display) -> String {
    format!("{}: {error}", path.display())
}

/// The machine of a link result, which the link has already checked it can emit.
fn link_arch(result: &LinkResult) -> std::result::Result<TargetArch, String> {
    TargetArch::from_elf_machine(result.e_machine)
        .ok_or_else(|| format!("no output format for ELF machine {}", result.e_machine))
}

const UNREADABLE_INPUTS: &str = "could not read the input objects";

/// The address of the `-e` symbol, or of the default entry `_start`, `main` or `_main`.
fn entry_address(args: &ParsedArgs, result: &LinkResult) -> std::result::Result<u64, String> {
    if let Some(name) = args.entry.as_deref() {
        return result
            .symbol_addrs
            .get(name)
            .copied()
            .ok_or_else(|| format!("entry symbol {name} is not defined"));
    }
    ["_start", "main", "_main"]
        .iter()
        .find_map(|name| result.symbol_addrs.get(*name).copied())
        .ok_or_else(|| "no entry point: define _start, main or _main, or pass -e SYMBOL".into())
}

/// True when no real `_start` is defined, so weld must supply startup itself:
/// entering at `main` would `ret` into `argc`. The stub calls `main` then issues
/// `exit`. Dynamic links rely on BIND_NOW to have resolved the PLT/GOT before it runs.
fn needs_synthetic_start(result: &LinkResult) -> bool {
    !result.symbol_addrs.contains_key("_start")
}

/// Append a freestanding `_start` to a static x86_64 ELF layout and return its
/// entry address. The stub calls `main_addr`, then issues the `exit` syscall with
/// its return value. `freebsd_abi` selects SYS_exit=1 (FreeBSD/Orbis/Prospero)
/// vs SYS_exit=60 (Linux).
fn synthesize_elf_start_x86_64(
    result: &mut LinkResult,
    main_addr: u64,
    freebsd_abi: bool,
) -> Option<u64> {
    if TargetArch::from_elf_machine(result.e_machine) != Some(TargetArch::X86_64) {
        return None;
    }

    let reserved = result
        .layout
        .section_by_name
        .get(".text.__weld_start")
        .copied();
    let start_vaddr = reserved
        .map(|i| result.layout.sections[i].vaddr)
        .or_else(|| {
            result
                .layout
                .sections
                .iter()
                .filter(|s| s.flags & 2 != 0)
                .map(|s| (s.vaddr + s.data.len() as u64 + 15) & !15)
                .max()
        })?;

    let sys_exit: u32 = if freebsd_abi { 1 } else { 60 };

    // libc exit() flushes stdio; the raw syscall does not.
    let exit_addr = result.symbol_addrs.get("exit").copied();

    let mut code = Vec::new();
    code.push(0xe8);
    let call_next = start_vaddr + 5;
    let rel = i32::try_from(main_addr as i64 - call_next as i64).ok()?;
    code.extend_from_slice(&rel.to_le_bytes());
    code.extend_from_slice(&[0x89, 0xc7]);
    match exit_addr {
        Some(addr) => {
            code.push(0xe8);
            let next = start_vaddr + code.len() as u64 + 4;
            let rel = i32::try_from(addr as i64 - next as i64).ok()?;
            code.extend_from_slice(&rel.to_le_bytes());
            code.push(0xcc);
        }
        None => {
            code.push(0xb8);
            code.extend_from_slice(&sys_exit.to_le_bytes());
            code.extend_from_slice(&[0x0f, 0x05]);
        }
    }

    if let Some(index) = reserved {
        result.layout.sections[index].data[..code.len()].copy_from_slice(&code);
        return Some(start_vaddr);
    }
    let idx = result.layout.sections.len();
    result
        .layout
        .section_by_name
        .insert(".text.__weld_start".to_string(), idx);
    result.layout.sections.push(MergedSection {
        entsize: 0,
        sh_type: 1,
        name: ".text.__weld_start".to_string(),
        data: code,
        vaddr: start_vaddr,
        flags: 2 | 4,
        align: 16,
    });

    Some(start_vaddr)
}

/// Write a freestanding `_start` for AArch64 into the reserved section: load
/// argc and argv, call `main_addr`, then `bl exit` if libc provides it, else the
/// `exit` syscall with the result still in x0.
fn synthesize_elf_start_aarch64(result: &mut LinkResult, main_addr: u64) -> Option<u64> {
    let index = result
        .layout
        .section_by_name
        .get(".text.__weld_start")
        .copied()?;
    let start = result.layout.sections[index].vaddr;
    let exit_addr = result.symbol_addrs.get("exit").copied();

    let bl = |at: u64, target: u64| -> Option<u32> {
        let words = (target as i64 - at as i64) / 4;
        if !(-(1 << 25)..(1 << 25)).contains(&words) {
            return None;
        }
        Some(0x9400_0000 | (words as u32 & 0x03FF_FFFF))
    };
    let mut words = vec![0xF940_03E0, 0x9100_23E1, bl(start + 8, main_addr)?];
    match exit_addr {
        Some(addr) => words.push(bl(start + 12, addr)?),
        None => words.extend([0xD280_0BA8, 0xD400_0001]),
    }
    let code: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let data = &mut result.layout.sections[index].data;
    data.get_mut(..code.len())?.copy_from_slice(&code);
    Some(start)
}

/// Write a freestanding `_start` for PowerPC64 ELFv2 into the reserved section:
/// set r2 to `.TOC.`, load the target's global entry into r12, call it, then call
/// `exit` (r3 still holds the result) or issue the exit syscall.
fn synthesize_elf_start_ppc64(result: &mut LinkResult, main_addr: u64) -> Option<u64> {
    let toc = result.symbol_addrs.get(".TOC.").copied()?;
    let index = result
        .layout
        .section_by_name
        .get(".text.__weld_start")
        .copied()?;
    let start = result.layout.sections[index].vaddr;
    let exit_addr = result.symbol_addrs.get("exit").copied();

    let ha = |v: u64| ((v + 0x8000) >> 16) & 0xFFFF;
    let lo = |v: u64| v & 0xFFFF;
    let dform = |opcode: u32, rt: u32, ra: u32, si: u64| {
        (opcode << 26) | (rt << 21) | (ra << 16) | (si as u32 & 0xFFFF)
    };
    let bl = |at: u64, target: u64| -> Option<u32> {
        let disp = target as i64 - at as i64;
        if disp & 3 != 0 || !(-(1 << 25)..(1 << 25)).contains(&disp) {
            return None;
        }
        Some(0x4800_0001 | (disp as u32 & 0x03FF_FFFC))
    };

    let mut words = vec![
        dform(15, 2, 0, ha(toc)),
        dform(14, 2, 2, lo(toc)),
        dform(15, 12, 0, ha(main_addr)),
        dform(14, 12, 12, lo(main_addr)),
    ];
    words.push(bl(start + 4 * words.len() as u64, main_addr)?);
    match exit_addr {
        Some(addr) => {
            words.push(dform(15, 12, 0, ha(addr)));
            words.push(dform(14, 12, 12, lo(addr)));
            words.push(bl(start + 4 * words.len() as u64, addr)?);
        }
        None => words.extend([dform(14, 0, 0, 1), 0x4400_0002]),
    }
    let code: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let data = &mut result.layout.sections[index].data;
    data.get_mut(..code.len())?.copy_from_slice(&code);
    Some(start)
}

/// Write a freestanding RV64 `_start` into the reserved section: load argc and
/// argv from the initial stack, `jal` to `main_addr`, then `jal exit` if libc
/// provides it, else the `exit` syscall with the result still in a0.
fn synthesize_elf_start_riscv64(result: &mut LinkResult, main_addr: u64) -> Option<u64> {
    let index = result
        .layout
        .section_by_name
        .get(".text.__weld_start")
        .copied()?;
    let start = result.layout.sections[index].vaddr;
    let exit_addr = result.symbol_addrs.get("exit").copied();

    let jal = |at: u64, target: u64| -> Option<u32> {
        let disp = target as i64 - at as i64;
        if disp & 1 != 0 || !(-(1 << 20)..(1 << 20)).contains(&disp) {
            return None;
        }
        let imm = disp as u32;
        Some(
            (((imm >> 20) & 1) << 31)
                | (((imm >> 1) & 0x3FF) << 21)
                | (((imm >> 11) & 1) << 20)
                | (((imm >> 12) & 0xFF) << 12)
                | (1 << 7)
                | 0x6F,
        )
    };

    let mut words = vec![0x0001_3503, 0x0081_0593];
    words.push(jal(start + 4 * words.len() as u64, main_addr)?);
    match exit_addr {
        Some(addr) => words.push(jal(start + 4 * words.len() as u64, addr)?),
        None => words.extend([0x05D0_0893, 0x0000_0073]),
    }
    let code: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let data = &mut result.layout.sections[index].data;
    data.get_mut(..code.len())?.copy_from_slice(&code);
    Some(start)
}

fn synthesize_elf_start(result: &mut LinkResult, main_addr: u64, freebsd_abi: bool) -> Option<u64> {
    match TargetArch::from_elf_machine(result.e_machine)? {
        TargetArch::X86_64 => synthesize_elf_start_x86_64(result, main_addr, freebsd_abi),
        TargetArch::AArch64 => synthesize_elf_start_aarch64(result, main_addr),
        TargetArch::PowerPc64 => synthesize_elf_start_ppc64(result, main_addr),
        TargetArch::RiscV => synthesize_elf_start_riscv64(result, main_addr),
    }
}

/// The ELF entry address: the named or default entry, or a synthesized `_start`
/// that calls it when the objects define no `_start`.
fn elf_entry(
    args: &ParsedArgs,
    result: &mut LinkResult,
    freebsd_abi: bool,
) -> std::result::Result<u64, String> {
    let target = entry_address(args, result)?;
    if !needs_synthetic_start(result) {
        return Ok(target);
    }
    synthesize_elf_start(result, target, freebsd_abi)
        .ok_or_else(|| "cannot synthesize a _start for this target".to_string())
}

fn host_arch() -> TargetArch {
    if cfg!(target_arch = "aarch64") {
        TargetArch::AArch64
    } else if cfg!(target_arch = "riscv64") {
        TargetArch::RiscV
    } else {
        TargetArch::X86_64
    }
}

fn static_library_paths(args: &ParsedArgs) -> Vec<PathBuf> {
    static_library_inputs(args)
        .into_iter()
        .map(|(path, _)| path)
        .collect()
}

fn static_library_inputs(args: &ParsedArgs) -> Vec<(PathBuf, usize)> {
    let mut resolver = LibraryResolver::new(host_arch(), TargetPlatform::current());
    for path in args.search_paths.iter().rev() {
        resolver.add_path(path.clone());
    }
    args.libraries
        .iter()
        .enumerate()
        .flat_map(|(i, name)| {
            let position = args.library_positions.get(i).copied().unwrap_or(usize::MAX);
            let library = if args.static_link {
                resolver.resolve_static(name)
            } else {
                resolver.resolve(name)
            };
            let Some(library) = library else {
                return Vec::new();
            };
            if library.is_static {
                return vec![(library.path, position)];
            }
            if args.static_link {
                return Vec::new();
            }
            resolver
                .linker_script_archives(name)
                .into_iter()
                .map(|path| (path, position))
                .collect()
        })
        .collect()
}

fn entry_seeds(args: &ParsedArgs) -> Vec<String> {
    match args.entry.as_ref() {
        Some(entry) => vec![entry.clone()],
        None => ["_start", "_main", "main"].map(String::from).to_vec(),
    }
}

fn elf_link_map(result: &LinkResult, entry: u64) -> String {
    use std::fmt::Write;
    let mut map = format!(
        "Entry point 0x{entry:016x}\n\nAddress            Size               Section / Symbol\n"
    );
    let mut sections: Vec<_> = result.layout.sections.iter().enumerate().collect();
    sections.sort_by_key(|(_, s)| s.vaddr);
    let mut symbols: Vec<_> = result.symbols.iter().collect();
    symbols.sort_by(|a, b| (a.shndx, a.value, &a.name).cmp(&(b.shndx, b.value, &b.name)));
    for (index, section) in sections {
        writeln!(
            map,
            "0x{:016x} 0x{:016x} {}",
            section.vaddr,
            section.data.len(),
            section.name
        )
        .unwrap();
        for symbol in symbols
            .iter()
            .filter(|s| s.shndx as usize == index + 1 && !s.name.is_empty())
        {
            writeln!(
                map,
                "  0x{:016x} 0x{:016x} {}",
                symbol.value, symbol.size, symbol.name
            )
            .unwrap();
        }
    }
    for symbol in symbols
        .iter()
        .filter(|s| s.shndx == 0xfff1 && !s.name.is_empty())
    {
        writeln!(
            map,
            "0x{:016x} 0x{:016x} {} (ABS)",
            symbol.value, symbol.size, symbol.name
        )
        .unwrap();
    }
    map
}

fn try_weld_link_elf(
    args: &ParsedArgs,
    obj_data_list: Vec<Vec<u8>>,
    object_positions: Vec<usize>,
) -> LinkResultOrMessage {
    let mut timer = timing::PhaseTimer::new();
    let libs = if args.libraries.is_empty() {
        None
    } else {
        Some(args.libraries.as_slice())
    };
    let target_os = args.target_os.as_deref();
    let os_abi = os_abi_for_target(target_os);
    let freebsd_abi = os_abi == ELFOSABI_FREEBSD;
    let mut opts = link_options(args);
    opts.object_positions = object_positions;
    let mut result = link::link_elf_objects(obj_data_list, libs, &opts)?;
    timer.mark("link ELF objects");
    let arch = link_arch(&result)?;
    if let Some(emul) = args.emulation.as_deref() {
        match TargetArch::from_emulation(emul) {
            Some(want) if want != arch => {
                return Err(format!(
                    "-m {emul} does not match the objects, which are {arch:?}"
                ));
            }
            None => return Err(format!("unknown emulation {emul}")),
            _ => {}
        }
    }
    let entry = if opts.shared {
        0
    } else {
        elf_entry(args, &mut result, freebsd_abi)?
    };
    let out_path = args.output_file.as_deref().unwrap_or(Path::new("a.out"));
    if let Some(path) = args.map_file.as_deref() {
        let map = elf_link_map(&result, entry);
        if path == Path::new("-") {
            print!("{map}");
        } else {
            std::fs::write(path, map).map_err(|e| output_error(path, e))?;
        }
    }
    let symbols = (!args.strip_all).then_some(result.symbols.as_slice());
    let out_file = create_output(out_path).map_err(|e| output_error(out_path, e))?;
    let mut out = std::io::BufWriter::new(out_file);
    if let Some(ref dyn_info) = result.dynamic {
        emit::elf::emit_elf_executable_dynamic(
            &result.layout,
            arch,
            entry,
            os_abi,
            dyn_info,
            symbols,
            &mut out,
        )
    } else {
        emit::elf::emit_elf_executable(&result.layout, arch, entry, os_abi, symbols, &mut out)
    }
    .and_then(|()| out.flush())
    .map_err(|e| output_error(out_path, e))?;
    timer.mark("emit ELF");
    drop(out);
    set_executable(out_path);
    Ok(())
}

/// `-lNAME` as a dylib in a `-L` directory. ld prefers it to an archive in the same place.
fn macho_dylib_paths(args: &ParsedArgs) -> Vec<PathBuf> {
    args.libraries
        .iter()
        .filter_map(|name| {
            args.search_paths
                .iter()
                .map(|dir| dir.join(format!("lib{name}.dylib")))
                .find(|path| path.is_file())
        })
        .collect()
}

fn try_weld_link_macho(args: &ParsedArgs) -> LinkResultOrMessage {
    let mut inputs = args.input_files.clone();
    inputs.extend(macho_dylib_paths(args));
    let (obj_data_list, dylib_paths) =
        object::load_macho_objects(&inputs, &static_library_paths(args), &entry_seeds(args))
            .ok_or(UNREADABLE_INPUTS)?;
    let obj_refs: Vec<&[u8]> = obj_data_list.iter().map(|d| d.as_slice()).collect();
    let libs = if args.libraries.is_empty() {
        None
    } else {
        Some(args.libraries.as_slice())
    };
    let result = link_macho_multi_object(&obj_refs, libs, &dylib_paths, &args.input_files)?;
    let arch = link_arch(&result)?;
    let entry = if args.dylib {
        0
    } else {
        entry_address(args, &result)?
    };
    let out_path = args.output_file.as_deref().unwrap_or(Path::new("a.out"));
    let out_file = create_output(out_path).map_err(|e| output_error(out_path, e))?;
    let mut out = std::io::BufWriter::new(out_file);
    let fallback_dyn = DynamicLinkInfo {
        pie: false,
        shared: false,
        needed: vec!["/usr/lib/libSystem.B.dylib".to_string()],
        plt_symbols: Vec::new(),
        weak_plt_symbols: Vec::new(),
        interpreter: None,
        macho_rebase_addrs: Vec::new(),
        macho_direct_binds: Vec::new(),
    };
    let mut dyn_info = result.dynamic.unwrap_or(fallback_dyn);
    // The system frameworks live in the dyld cache, this path is how dyld names them.
    dyn_info.needed.extend(
        args.frameworks
            .iter()
            .map(|name| format!("/System/Library/Frameworks/{name}.framework/{name}")),
    );
    let min_os = emit::macho::macos_min_version().map_err(|e| e.to_string())?;
    if args.dylib {
        let install_name = args
            .install_name
            .clone()
            .unwrap_or_else(|| out_path.display().to_string());
        emit::macho::emit_macho_dylib(
            &result.layout,
            arch,
            &install_name,
            &result.macho_exports,
            &dyn_info,
            &args.rpaths,
            min_os,
            &result.debug_map,
            &mut out,
        )
    } else {
        emit::macho::emit_macho_executable_dynamic_with(
            &result.layout,
            arch,
            entry,
            &dyn_info,
            &args.rpaths,
            min_os,
            &result.debug_map,
            &mut out,
        )
    }
    .and_then(|()| out.flush())
    .map_err(|e| output_error(out_path, e))?;
    drop(out);
    set_executable(out_path);
    ad_hoc_codesign(out_path).map_err(|e| output_error(out_path, e))
}

fn try_weld_link_coff(args: &ParsedArgs, objects: Vec<Vec<u8>>) -> LinkResultOrMessage {
    if args.shared {
        return Err("-shared is not supported for PE output".into());
    }
    let refs: Vec<&[u8]> = objects.iter().map(Vec::as_slice).collect();
    let out_path = args.output_file.as_deref().unwrap_or(Path::new("a.exe"));
    let mut image = Vec::new();
    emit::pe::link_and_emit_pe_from_coffs(&refs, args.entry.as_deref(), &mut image)
        .map_err(|e| e.to_string())?;
    create_output(out_path)
        .and_then(|file| {
            let mut out = std::io::BufWriter::new(file);
            std::io::Write::write_all(&mut out, &image)?;
            out.flush()
        })
        .map_err(|e| output_error(out_path, e))
}

/// PE output is written from COFF objects only.
fn try_weld_link_pe(args: &ParsedArgs) -> LinkResultOrMessage {
    let (libraries, library_positions): (Vec<_>, Vec<_>) =
        static_library_inputs(args).into_iter().unzip();
    let loaded = object::load_objects_with_positions(
        &args.input_files,
        &libraries,
        &entry_seeds(args),
        &args.input_positions,
        &library_positions,
        &args.groups,
    )
    .ok_or(UNREADABLE_INPUTS)?;
    match loaded.format {
        ObjectFormat::Coff => try_weld_link_coff(args, loaded.objects),
        ObjectFormat::Elf => Err(
            "PE output cannot be built from ELF inputs: the PE writer only takes COFF objects"
                .into(),
        ),
        ObjectFormat::MachO => Err("PE output cannot be built from Mach-O inputs".into()),
    }
}

fn try_weld_link(args: &ParsedArgs) -> LinkResultOrMessage {
    if args.input_files.is_empty() {
        return Err("no input files".into());
    }

    object::check_archive_indexes(&args.input_files, &static_library_paths(args))?;

    let wants_pe = args
        .output_file
        .as_ref()
        .map(|p| {
            p.extension()
                .map(|e| e.eq_ignore_ascii_case("exe"))
                .unwrap_or(false)
        })
        .unwrap_or(false);

    if wants_pe {
        return try_weld_link_pe(args);
    }

    if args.static_link {
        let mut resolver = LibraryResolver::new(host_arch(), TargetPlatform::current());
        for path in args.search_paths.iter().rev() {
            resolver.add_path(path.clone());
        }
        for name in &args.libraries {
            if resolver.resolve_static(name).is_none() {
                return Err(format!("cannot find static library -l{name}"));
            }
        }
    }
    let mut timer = timing::PhaseTimer::new();
    let (libraries, library_positions): (Vec<_>, Vec<_>) =
        static_library_inputs(args).into_iter().unzip();
    let loaded = object::load_objects_with_positions(
        &args.input_files,
        &libraries,
        &entry_seeds(args),
        &args.input_positions,
        &library_positions,
        &args.groups,
    )
    .ok_or(UNREADABLE_INPUTS)?;
    object::reject_lto_objects(&loaded.objects)?;

    timer.mark("detect format and load objects");
    if args.relocatable {
        if loaded.format != ObjectFormat::Elf {
            return Err("-r supports ELF inputs only".into());
        }
        return try_weld_relocatable(args, &loaded.objects);
    }
    if args.dylib && loaded.format != ObjectFormat::MachO {
        return Err("-dylib needs Mach-O inputs".into());
    }
    match loaded.format {
        ObjectFormat::Elf => try_weld_link_elf(args, loaded.objects, loaded.positions),
        ObjectFormat::MachO => try_weld_link_macho(args),
        ObjectFormat::Coff => try_weld_link_coff(args, loaded.objects),
    }
}

fn try_weld_relocatable(args: &ParsedArgs, objects: &[Vec<u8>]) -> LinkResultOrMessage {
    let refs: Vec<&[u8]> = objects.iter().map(Vec::as_slice).collect();
    let image = link::link_relocatable(&refs)?;
    let out_path = args.output_file.as_deref().unwrap_or(Path::new("a.out"));
    create_output(out_path)
        .and_then(|file| {
            let mut out = std::io::BufWriter::new(file);
            out.write_all(&image)?;
            out.flush()
        })
        .map_err(|e| output_error(out_path, e))
}

struct StderrLogger;

impl log::Log for StderrLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!("[{}] {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

fn init_logging() {
    let level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(log::LevelFilter::Warn);
    log::set_max_level(level);
    let _ = log::set_logger(&StderrLogger);
}

fn write_archive_mode(args: &ParsedArgs) -> std::result::Result<(), String> {
    if !args.libraries.is_empty()
        || args.shared
        || args.relocatable
        || args.static_link
        || args.entry.is_some()
    {
        return Err("--archive cannot be combined with -l, -shared, -r, -static or -e".into());
    }
    let output = args
        .output_file
        .as_deref()
        .ok_or("--archive requires -o <file>")?;
    archive::create_archive(output, &args.input_files)
}

fn run(args: &ParsedArgs) -> LinkResultOrMessage {
    if args.archive {
        write_archive_mode(args)
    } else {
        // The output format follows the input objects, not the host, so ELF and
        // Mach-O links work when cross-linking from another host.
        try_weld_link(args)
    }
}

/// Run one link in process, with the arguments the command line takes (without the
/// program name), `--archive` included.
///
/// Returns instead of exiting. An error is the message the command line prints after
/// `weld: `; `--help` and `--version` are refused, as they only make sense there.
pub fn link(args: &[String]) -> std::result::Result<(), String> {
    match parse_args(args)? {
        ParseAction::Run(args) => run(&args),
        ParseAction::Help | ParseAction::Version => {
            Err("--help and --version are command line options".into())
        }
    }
}

/// Run one link from the process argument vector, then exit.
pub fn main() {
    init_logging();
    let link_args: Vec<String> = env::args().skip(1).collect();
    match parse_args(&link_args) {
        Ok(ParseAction::Run(args)) => match run(&args) {
            Ok(()) => {
                if args.verbose {
                    log::info!("{}", if args.archive { "archived" } else { "linked" });
                }
            }
            Err(e) => {
                eprintln!("weld: {e}");
                std::process::exit(1);
            }
        },
        Ok(ParseAction::Help) => print_usage(),
        Ok(ParseAction::Version) => println!("weld {}", VERSION),
        Err(e) => {
            eprintln!("Error: {}", e);
            print_usage();
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collections::HashMap;
    use crate::link::MergedLayout;

    fn static_main_result() -> LinkResult {
        let mut section_by_name = HashMap::default();
        section_by_name.insert(".text".to_string(), 0);
        let mut symbol_addrs = HashMap::default();
        symbol_addrs.insert("main".to_string(), 0x400000u64);
        LinkResult {
            debug_map: Vec::new(),
            symbols: Vec::new(),
            layout: MergedLayout {
                sections: vec![MergedSection {
                    entsize: 0,
                    sh_type: 1,
                    name: ".text".to_string(),
                    data: vec![0xc3],
                    vaddr: 0x400000,
                    flags: 2 | 4,
                    align: 16,
                }],
                section_by_name,
            },
            e_machine: 62,
            symbol_addrs,
            dynamic: None,
            macho_exports: Vec::new(),
        }
    }

    #[test]
    fn synthesizes_start_for_static_main() {
        let mut result = static_main_result();
        assert!(needs_synthetic_start(&result));

        let entry =
            synthesize_elf_start_x86_64(&mut result, 0x400000, false).expect("start synthesized");
        assert!(entry >= 0x400000);
        assert!(
            result
                .layout
                .section_by_name
                .contains_key(".text.__weld_start")
        );

        let start = &result.layout.sections[result.layout.sections.len() - 1];
        assert_eq!(start.data[0], 0xe8);
        assert_eq!(&start.data[start.data.len() - 2..], &[0x0f, 0x05]);
    }

    #[test]
    fn synthetic_start_calls_libc_exit_when_available() {
        let mut result = static_main_result();
        result.symbol_addrs.insert("exit".to_string(), 0x401200);
        let entry =
            synthesize_elf_start_x86_64(&mut result, 0x400000, false).expect("start synthesized");

        let start = result.layout.sections.last().expect("start section");
        assert_eq!(start.data[7], 0xe8);
        let rel = i32::from_le_bytes(start.data[8..12].try_into().unwrap());
        assert_eq!(entry as i64 + 12 + rel as i64, 0x401200);
    }

    #[test]
    fn no_synthetic_start_when_start_is_defined() {
        let mut result = static_main_result();
        result.symbol_addrs.insert("_start".to_string(), 0x401000);
        assert!(!needs_synthetic_start(&result));
    }

    #[test]
    fn synthesizes_start_for_dynamic_link_without_start() {
        // A dynamic link (libc) with no crt-provided `_start` still needs the
        // synthetic stub, otherwise entering at `main` returns into `argc`.
        let mut result = static_main_result();
        result.dynamic = Some(DynamicLinkInfo::default());
        assert!(needs_synthetic_start(&result));
    }

    #[test]
    fn no_synthetic_start_for_dynamic_link_with_start() {
        let mut result = static_main_result();
        result.dynamic = Some(DynamicLinkInfo::default());
        result.symbol_addrs.insert("_start".to_string(), 0x401000);
        assert!(!needs_synthetic_start(&result));
    }

    fn decode_jal(word: u32) -> i64 {
        let imm = ((word >> 31) & 1) << 20
            | ((word >> 21) & 0x3FF) << 1
            | ((word >> 20) & 1) << 11
            | ((word >> 12) & 0xFF) << 12;
        let imm = i64::from(imm);
        if imm & (1 << 20) != 0 {
            imm - (1 << 21)
        } else {
            imm
        }
    }

    fn riscv_main_result() -> LinkResult {
        let mut result = static_main_result();
        result.e_machine = 243;
        result
            .layout
            .section_by_name
            .insert(".text.__weld_start".to_string(), 1);
        result.layout.sections.push(MergedSection {
            entsize: 0,
            sh_type: 1,
            name: ".text.__weld_start".to_string(),
            data: vec![0; 64],
            vaddr: 0x400010,
            flags: 6,
            align: 16,
        });
        result
    }

    fn riscv_words(result: &LinkResult, start: u64) -> Vec<u32> {
        let section = result.layout.sections.last().expect("start section");
        assert_eq!(section.vaddr, start);
        section
            .data
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
            .collect()
    }

    #[test]
    fn riscv_start_loads_argc_and_calls_main() {
        let mut result = riscv_main_result();
        let entry = elf_entry(&ParsedArgs::default(), &mut result, false).expect("entry");
        assert_eq!(entry, 0x400010);

        let words = riscv_words(&result, entry);
        assert_eq!(words[0], 0x0001_3503, "ld a0, 0(sp)");
        assert_eq!(words[1], 0x0081_0593, "addi a1, sp, 8");
        assert_eq!(entry as i64 + 8 + decode_jal(words[2]), 0x400000);
        assert_eq!(words[3], 0x05D0_0893, "addi a7, zero, 93");
        assert_eq!(words[4], 0x0000_0073, "ecall");
    }

    #[test]
    fn riscv_start_calls_libc_exit_when_available() {
        let mut result = riscv_main_result();
        result.symbol_addrs.insert("exit".to_string(), 0x400100);
        let entry = elf_entry(&ParsedArgs::default(), &mut result, false).expect("entry");

        let words = riscv_words(&result, entry);
        assert_eq!(entry as i64 + 12 + decode_jal(words[3]), 0x400100);
    }

    #[test]
    fn synthetic_start_calls_the_named_entry() {
        let mut result = static_main_result();
        result
            .symbol_addrs
            .insert("entry_point".to_string(), 0x400100);
        let args = ParsedArgs {
            entry: Some("entry_point".to_string()),
            ..ParsedArgs::default()
        };
        let entry = elf_entry(&args, &mut result, false).expect("entry");

        let start = result.layout.sections.last().expect("start section");
        assert_eq!(start.vaddr, entry);
        assert_eq!(start.data[0], 0xe8);
        let rel = i32::from_le_bytes(start.data[1..5].try_into().unwrap());
        assert_eq!(entry as i64 + 5 + i64::from(rel), 0x400100);
    }

    #[test]
    fn undefined_entry_symbol_is_an_error() {
        let mut result = static_main_result();
        let args = ParsedArgs {
            entry: Some("missing".to_string()),
            ..ParsedArgs::default()
        };
        let error = elf_entry(&args, &mut result, false).expect_err("must fail");
        assert!(error.contains("missing"), "{error}");
    }

    #[test]
    fn missing_entry_point_is_an_error() {
        let mut result = static_main_result();
        result.symbol_addrs.remove("main");
        let error = entry_address(&ParsedArgs::default(), &result).expect_err("must fail");
        assert!(error.contains("no entry point"), "{error}");
    }

    #[test]
    fn shared_pe_output_is_refused_before_writing() {
        let args = ParsedArgs {
            shared: true,
            output_file: Some(PathBuf::from("target/scratch-cli/never.dll")),
            ..ParsedArgs::default()
        };
        assert_eq!(
            try_weld_link_coff(&args, Vec::new()),
            Err("-shared is not supported for PE output".to_string())
        );
        assert!(!Path::new("target/scratch-cli/never.dll").exists());
    }

    /// `weld::link` returns the error the command line would print, and does not exit.
    mod api {

        fn link(args: &[&str]) -> Result<(), String> {
            let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            crate::link(&args)
        }

        #[test]
        fn errors_come_back_as_messages() {
            assert_eq!(link(&["-o", "out"]), Err("no input files".to_string()));
            assert_eq!(
                link(&["no-such-input.o", "-o", "out"]),
                Err("could not read the input objects".to_string())
            );
            assert!(
                link(&["--archive", "x.o"])
                    .unwrap_err()
                    .contains("requires -o")
            );
        }

        #[test]
        fn command_line_only_flags_are_refused() {
            for flag in ["--help", "--version"] {
                assert!(link(&[flag]).unwrap_err().contains("command line options"));
            }
        }
    }
}
