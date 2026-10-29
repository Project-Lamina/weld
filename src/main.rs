//! weld - Cross-platform linker for Lamina
//!
//! Native linking only. Supports object files and dynamic libs (-lc, -lSystem).
//! No delegation to system linker.

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
        link_multi_object_with_options, macho::link_macho_multi_object,
    },
    object::{ObjectFormat, load_objects},
    platform::TargetPlatform,
};
use std::{
    env,
    io::{Result, Write},
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
fn ad_hoc_codesign(_path: &Path) -> Result<()> {
    Ok(())
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn select_entry(args: &ParsedArgs, result: &LinkResult) -> Option<u64> {
    if let Some(s) = args.entry.as_ref()
        && let Some(&addr) = result.symbol_addrs.get(s)
    {
        return Some(addr);
    }
    result
        .symbol_addrs
        .get("_start")
        .copied()
        .or_else(|| result.symbol_addrs.get("main").copied())
        .or_else(|| result.symbol_addrs.get("_main").copied())
        .or_else(|| {
            result
                .layout
                .sections
                .first()
                .filter(|s| s.name == ".text")
                .map(|s| s.vaddr)
        })
}

/// True when no real `_start` is defined, so weld must supply startup itself:
/// entering at `main` would `ret` into `argc`. The stub calls `main` then issues
/// `exit`. Dynamic links rely on BIND_NOW to have resolved the PLT/GOT before it runs.
fn needs_synthetic_start(result: &LinkResult) -> bool {
    !result.symbol_addrs.contains_key("_start")
}

/// Append a freestanding `_start` to a static x86_64 ELF layout and return its
/// entry address. The stub calls `main`, then issues the `exit` syscall with
/// `main`'s return value. `freebsd_abi` selects SYS_exit=1 (FreeBSD/Orbis/Prospero)
/// vs SYS_exit=60 (Linux).
fn synthesize_elf_start_x86_64(result: &mut LinkResult, freebsd_abi: bool) -> Option<u64> {
    if TargetArch::from_elf_machine(result.e_machine) != Some(TargetArch::X86_64) {
        return None;
    }

    let main_addr = result
        .symbol_addrs
        .get("main")
        .or_else(|| result.symbol_addrs.get("_main"))
        .copied()?;

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
/// argc and argv, call `main`, then `bl exit` if libc provides it, else the
/// `exit` syscall with `main`'s return value still in x0.
fn synthesize_elf_start_aarch64(result: &mut LinkResult) -> Option<u64> {
    let main_addr = result
        .symbol_addrs
        .get("main")
        .or_else(|| result.symbol_addrs.get("_main"))
        .copied()?;
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
/// set r2 to `.TOC.`, load main's global entry into r12, call it, then call
/// `exit` (r3 still holds main's result) or issue the exit syscall.
fn synthesize_elf_start_ppc64(result: &mut LinkResult) -> Option<u64> {
    let main_addr = result
        .symbol_addrs
        .get("main")
        .or_else(|| result.symbol_addrs.get("_main"))
        .copied()?;
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

fn synthesize_elf_start(result: &mut LinkResult, freebsd_abi: bool) -> Option<u64> {
    match TargetArch::from_elf_machine(result.e_machine)? {
        TargetArch::X86_64 => synthesize_elf_start_x86_64(result, freebsd_abi),
        TargetArch::AArch64 => synthesize_elf_start_aarch64(result),
        TargetArch::PowerPc64 => synthesize_elf_start_ppc64(result),
        TargetArch::RiscV => None,
    }
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
) -> Option<i32> {
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
    let mut result = link::link_elf_objects(obj_data_list, libs, &opts).ok()?;
    timer.mark("link ELF objects");
    let arch = TargetArch::from_elf_machine(result.e_machine)?;
    if let Some(emul) = args.emulation.as_deref() {
        match TargetArch::from_emulation(emul) {
            Some(want) if want != arch => {
                eprintln!("weld: -m {emul} does not match the objects, which are {arch:?}");
                return None;
            }
            None => {
                eprintln!("weld: unknown emulation {emul}");
                return None;
            }
            _ => {}
        }
    }
    let entry = if opts.shared {
        0
    } else if needs_synthetic_start(&result) {
        synthesize_elf_start(&mut result, freebsd_abi).or_else(|| select_entry(args, &result))?
    } else {
        select_entry(args, &result)?
    };
    let out_path = args.output_file.as_deref().unwrap_or(Path::new("a.out"));
    if let Some(path) = args.map_file.as_deref() {
        let map = elf_link_map(&result, entry);
        if path == Path::new("-") {
            print!("{map}");
        } else {
            std::fs::write(path, map).ok()?;
        }
    }
    let symbols = (!args.strip_all).then_some(result.symbols.as_slice());
    let out_file = create_output(out_path).ok()?;
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
        .ok()?;
    } else {
        emit::elf::emit_elf_executable(&result.layout, arch, entry, os_abi, symbols, &mut out)
            .ok()?;
    }
    out.flush().ok()?;
    timer.mark("emit ELF");
    drop(out);
    set_executable(out_path);
    Some(0)
}

fn try_weld_link_macho(args: &ParsedArgs) -> Option<i32> {
    let (obj_data_list, dylib_paths) = object::load_macho_objects(
        &args.input_files,
        &static_library_paths(args),
        &entry_seeds(args),
    )?;
    let obj_refs: Vec<&[u8]> = obj_data_list.iter().map(|d| d.as_slice()).collect();
    let libs = if args.libraries.is_empty() {
        None
    } else {
        Some(args.libraries.as_slice())
    };
    let result = link_macho_multi_object(&obj_refs, libs, &dylib_paths, &args.input_files).ok()?;
    let arch = TargetArch::from_elf_machine(result.e_machine)?;
    let entry = select_entry(args, &result)?;
    let out_path = args.output_file.as_deref().unwrap_or(Path::new("a.out"));
    let out_file = create_output(out_path).ok()?;
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
    let dyn_info = result.dynamic.as_ref().unwrap_or(&fallback_dyn);
    emit::macho::emit_macho_executable_dynamic(&result.layout, arch, entry, dyn_info, &mut out)
        .ok()?;
    out.flush().ok()?;
    drop(out);
    set_executable(out_path);
    ad_hoc_codesign(out_path).ok()?;
    Some(0)
}

fn try_weld_link_coff(args: &ParsedArgs, objects: Vec<Vec<u8>>) -> Option<i32> {
    let refs: Vec<&[u8]> = objects.iter().map(Vec::as_slice).collect();
    let out_path = args.output_file.as_deref().unwrap_or(Path::new("a.exe"));
    let mut image = Vec::new();
    if let Err(error) = emit::pe::link_and_emit_pe_from_coffs(&refs, &mut image) {
        eprintln!("weld: {error}");
        return Some(1);
    }
    let out_file = create_output(out_path).ok()?;
    let mut out = std::io::BufWriter::new(out_file);
    std::io::Write::write_all(&mut out, &image).ok()?;
    out.flush().ok()?;
    Some(0)
}

fn try_weld_link_pe(args: &ParsedArgs) -> Option<i32> {
    // COFF inputs take the direct COFF to PE path; ELF inputs fall through to the legacy path.
    let (libraries, library_positions): (Vec<_>, Vec<_>) =
        static_library_inputs(args).into_iter().unzip();
    let loaded = object::load_objects_with_positions(
        &args.input_files,
        &libraries,
        &entry_seeds(args),
        &args.input_positions,
        &library_positions,
        &args.groups,
    )?;
    if loaded.format == ObjectFormat::Coff {
        return try_weld_link_coff(args, loaded.objects);
    }
    if loaded.format != ObjectFormat::Elf {
        return None;
    }
    let obj_data_list = loaded.objects;
    let obj_refs: Vec<&[u8]> = obj_data_list.iter().map(|d| d.as_slice()).collect();
    let libs = if args.libraries.is_empty() {
        None
    } else {
        Some(args.libraries.as_slice())
    };
    let result = link_multi_object_with_options(&obj_refs, libs, &link_options(args)).ok()?;
    let entry = select_entry(args, &result)?;
    let out_path = args.output_file.as_deref().unwrap_or(Path::new("a.exe"));
    let out_file = create_output(out_path).ok()?;
    let mut out = std::io::BufWriter::new(out_file);
    emit::pe::emit_pe_executable(&result.layout, entry, result.dynamic.as_ref(), &mut out).ok()?;
    out.flush().ok()?;
    Some(0)
}

fn try_weld_link(args: &ParsedArgs) -> Option<i32> {
    if args.input_files.is_empty() {
        return None;
    }

    if let Err(error) =
        object::check_archive_indexes(&args.input_files, &static_library_paths(args))
    {
        eprintln!("weld: {error}");
        return Some(1);
    }

    // Windows PE: triggered by explicit --target=windows or .exe output suffix.
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
                eprintln!("weld: cannot find static library -l{name}");
                return Some(1);
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
    )?;
    if let Err(error) = object::reject_lto_objects(&loaded.objects) {
        eprintln!("weld: {error}");
        return Some(1);
    }

    timer.mark("detect format and load objects");
    if args.relocatable {
        if loaded.format != ObjectFormat::Elf {
            eprintln!("weld: -r supports ELF inputs only");
            return Some(1);
        }
        return try_weld_relocatable(args, &loaded.objects);
    }
    match loaded.format {
        ObjectFormat::Elf => try_weld_link_elf(args, loaded.objects, loaded.positions),
        ObjectFormat::MachO => try_weld_link_macho(args),
        ObjectFormat::Coff => try_weld_link_coff(args, loaded.objects),
    }
}

fn try_weld_relocatable(args: &ParsedArgs, objects: &[Vec<u8>]) -> Option<i32> {
    let refs: Vec<&[u8]> = objects.iter().map(Vec::as_slice).collect();
    let image = match link::link_relocatable(&refs) {
        Ok(image) => image,
        Err(error) => {
            eprintln!("weld: {error}");
            return Some(1);
        }
    };
    let out_path = args.output_file.as_deref().unwrap_or(Path::new("a.out"));
    let mut out = std::io::BufWriter::new(create_output(out_path).ok()?);
    out.write_all(&image).ok()?;
    out.flush().ok()?;
    Some(0)
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

fn main() {
    init_logging();
    let argv: Vec<String> = env::args().collect();
    let link_args: Vec<String> = argv.get(1..).unwrap_or(&[]).to_vec();

    match parse_args(&link_args) {
        Ok(ParseAction::Run(args)) => {
            // Output format is chosen from the input objects, not the host OS, so
            // ELF/Mach-O linking works even when cross-linking from another host.
            // Unsupported output formats are reported per-format in `try_weld_link`.
            match try_weld_link(&args) {
                Some(0) => {
                    if args.verbose {
                        log::info!("linked");
                    }
                    std::process::exit(0);
                }
                None => {
                    {
                        if let Some((format, data, dylib_paths)) = load_objects(
                            &args.input_files,
                            &static_library_paths(&args),
                            &entry_seeds(&args),
                        ) {
                            let refs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
                            let err = match format {
                                ObjectFormat::Elf => link_multi_object_with_options(
                                    &refs,
                                    Some(&args.libraries),
                                    &link_options(&args),
                                )
                                .err(),
                                ObjectFormat::MachO => link_macho_multi_object(
                                    &refs,
                                    Some(&args.libraries),
                                    &dylib_paths,
                                    &args.input_files,
                                )
                                .err(),
                                ObjectFormat::Coff => {
                                    Some("COFF/PE linking not yet implemented".to_string())
                                }
                            };
                            if let Some(e) = err {
                                eprintln!("weld: {e}");
                            }
                        } else {
                            eprintln!("weld: could not read the input objects");
                        }
                    }
                    eprintln!("weld: link failed");
                    std::process::exit(1);
                }
                Some(code) => std::process::exit(code),
            }
        }
        Ok(ParseAction::Help) => {
            print_usage();
        }
        Ok(ParseAction::Version) => {
            println!("weld {}", VERSION);
        }
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
        }
    }

    #[test]
    fn synthesizes_start_for_static_main() {
        let mut result = static_main_result();
        assert!(needs_synthetic_start(&result));

        let entry = synthesize_elf_start_x86_64(&mut result, false).expect("start synthesized");
        assert!(entry >= 0x400000);
        assert!(
            result
                .layout
                .section_by_name
                .contains_key(".text.__weld_start")
        );

        let start = &result.layout.sections[result.layout.sections.len() - 1];
        assert_eq!(start.data.len(), 14);
        assert_eq!(start.data[0], 0xe8);
        assert_eq!(&start.data[12..14], &[0x0f, 0x05]);
    }

    #[test]
    fn synthetic_start_calls_libc_exit_when_available() {
        let mut result = static_main_result();
        result.symbol_addrs.insert("exit".to_string(), 0x401200);
        let entry = synthesize_elf_start_x86_64(&mut result, false).expect("start synthesized");

        let start = result.layout.sections.last().expect("start section");
        assert_eq!(start.data.len(), 13);
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
}
