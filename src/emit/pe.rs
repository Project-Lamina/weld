//! PE32+ (64-bit Windows) executable emission.

use crate::coff::{
    self, IMAGE_SCN_LNK_COMDAT, IMAGE_SCN_MEM_DISCARDABLE, IMAGE_SYM_ABSOLUTE_SECTION,
    IMAGE_SYM_CLASS_EXTERNAL, IMAGE_SYM_CLASS_WEAK_EXTERNAL, IMAGE_SYM_UNDEFINED_SECTION,
    MACHINE_AMD64, MACHINE_ARM64,
};
use crate::collections::{HashMap, HashSet};
use std::io::{Result, Write};

const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
const IMAGE_OPTIONAL_HDR64_MAGIC: u16 = 0x020B;
const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;
const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
const IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: u16 = 0x8000;

/// Default image base for 64-bit PE executables (conventional Windows default).
const IMAGE_BASE: u64 = 0x0000_0001_4000_0000;
const SECTION_ALIGN: u64 = 0x1000;
const FILE_ALIGN: u64 = 0x0200;
const SIZEOF_OPTIONAL_HEADER: u16 = 240;
const SIZEOF_SECTION_HEADER: usize = 40;
const SIZEOF_DOS_STUB: usize = 64;
const SIZEOF_PE_SIGNATURE: usize = 4;
const SIZEOF_COFF_HEADER: usize = 20;

/// Number of data directory entries we always write.
const NUM_DATA_DIRS: u32 = 16;
const _DATA_DIR_IMPORT: usize = 1;
const _DATA_DIR_IAT: usize = 12;

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

fn align_up(v: u64, align: u64) -> u64 {
    if align == 0 {
        return v;
    }
    (v + align - 1) & !(align - 1)
}

fn align_up_usize(v: usize, align: usize) -> usize {
    if align == 0 {
        return v;
    }
    (v + align - 1) & !(align - 1)
}

/// Names of symbols that will be imported from the given DLL.
struct ImportEntry<'a> {
    dll_name: &'a str,
    /// (hint, symbol_name) pairs.  hint=0 is fine for ExitProcess etc.
    symbols: Vec<(u16, &'a str)>,
}

/// Build the raw bytes for a minimal .rdata import section and return
/// `(bytes, import_dir_rva_relative, iat_rva_relative, size_of_import_dir, size_of_iat)`
/// where the RVAs are *relative to the start of the .rdata section*.
///
/// `rdata_rva` is the RVA (relative to image base) of the .rdata section.
fn build_import_section(
    rdata_rva: u64,
    entries: &[ImportEntry<'_>],
) -> (Vec<u8>, u32, u32, u32, u32) {
    // Import Directory Table (IDT): (entries.len() + 1) * 20 bytes (null-terminated)
    // Import Lookup Table (ILT) for each DLL: (symbols.len() + 1) * 8 bytes
    // Import Address Table (IAT): same layout as ILT

    let num_dlls = entries.len();
    let idt_size = (num_dlls + 1) * 20;

    // The ILT and IAT hold 8-byte thunks, and an aarch64 thunk reaches its slot
    // with a scaled `ldr`, so both tables start on an 8-byte boundary.
    let tables_base = align_up_usize(idt_size, 8);
    let mut ilt_offsets: Vec<usize> = Vec::with_capacity(num_dlls);
    let mut ilt_total_size = 0usize;
    for e in entries {
        ilt_offsets.push(tables_base + ilt_total_size);
        ilt_total_size += (e.symbols.len() + 1) * 8;
    }

    let iat_base_off = tables_base + ilt_total_size;
    let mut iat_offsets: Vec<usize> = Vec::with_capacity(num_dlls);
    let mut iat_total_size = 0usize;
    for e in entries {
        iat_offsets.push(iat_base_off + iat_total_size);
        iat_total_size += (e.symbols.len() + 1) * 8;
    }

    let hint_names_base = iat_base_off + iat_total_size;
    let mut hint_name_offsets: Vec<Vec<usize>> = Vec::with_capacity(num_dlls);
    let mut hint_name_cursor = hint_names_base;
    for e in entries {
        let mut sym_offs = Vec::with_capacity(e.symbols.len());
        for (_, name) in &e.symbols {
            sym_offs.push(hint_name_cursor);
            hint_name_cursor += 2 + name.len() + 1; // hint(u16) + name + NUL
            hint_name_cursor = align_up_usize(hint_name_cursor, 2);
        }
        hint_name_offsets.push(sym_offs);
    }

    let dll_name_base = hint_name_cursor;
    let mut dll_name_offsets: Vec<usize> = Vec::with_capacity(num_dlls);
    let mut dll_name_cursor = dll_name_base;
    for e in entries {
        dll_name_offsets.push(dll_name_cursor);
        dll_name_cursor += e.dll_name.len() + 1;
    }

    let total_size = align_up_usize(dll_name_cursor, FILE_ALIGN as usize);
    let mut buf = vec![0u8; total_size];

    let section_rva = rdata_rva as u32;

    for (di, _e) in entries.iter().enumerate() {
        let base = di * 20;
        let ilt_rva = section_rva + ilt_offsets[di] as u32;
        let iat_rva = section_rva + iat_offsets[di] as u32;
        let name_rva = section_rva + dll_name_offsets[di] as u32;

        buf[base..base + 4].copy_from_slice(&ilt_rva.to_le_bytes()); // OriginalFirstThunk
        buf[base + 12..base + 16].copy_from_slice(&name_rva.to_le_bytes()); // Name
        buf[base + 16..base + 20].copy_from_slice(&iat_rva.to_le_bytes()); // FirstThunk
    }

    for (di, e) in entries.iter().enumerate() {
        for (si, _) in e.symbols.iter().enumerate() {
            let hint_name_rva = section_rva + hint_name_offsets[di][si] as u32;
            let thunk: u64 = hint_name_rva as u64; // bit 63 = 0 → by name
            let ilt_off = ilt_offsets[di] + si * 8;
            let iat_off = iat_offsets[di] + si * 8;
            buf[ilt_off..ilt_off + 8].copy_from_slice(&thunk.to_le_bytes());
            buf[iat_off..iat_off + 8].copy_from_slice(&thunk.to_le_bytes());
        }
    }

    for (di, e) in entries.iter().enumerate() {
        for (si, (hint, name)) in e.symbols.iter().enumerate() {
            let off = hint_name_offsets[di][si];
            buf[off..off + 2].copy_from_slice(&hint.to_le_bytes());
            let name_bytes = name.as_bytes();
            buf[off + 2..off + 2 + name_bytes.len()].copy_from_slice(name_bytes);
        }
    }

    for (di, e) in entries.iter().enumerate() {
        let off = dll_name_offsets[di];
        buf[off..off + e.dll_name.len()].copy_from_slice(e.dll_name.as_bytes());
    }

    let idt_rva = 0u32;
    let iat_rva = iat_base_off as u32;
    let iat_size_u32 = iat_total_size as u32;

    (buf, idt_rva, iat_rva, idt_size as u32, iat_size_u32)
}

struct PeSection {
    name: [u8; 8],
    data: Vec<u8>,
    characteristics: u32,
}

impl PeSection {
    fn new(name: &str, data: Vec<u8>, characteristics: u32) -> Self {
        let mut n = [0u8; 8];
        let b = name.as_bytes();
        n[..b.len().min(8)].copy_from_slice(&b[..b.len().min(8)]);
        Self {
            name: n,
            data,
            characteristics,
        }
    }

    fn raw_size(&self) -> u32 {
        align_up(self.data.len() as u64, FILE_ALIGN) as u32
    }
}

const IMAGE_REL_AMD64_ABSOLUTE: u16 = 0x0000;
const IMAGE_REL_AMD64_ADDR32NB: u16 = 0x0003;
const IMAGE_REL_AMD64_ADDR64: u16 = 0x0001;
const IMAGE_REL_AMD64_ADDR32: u16 = 0x0002;
const IMAGE_REL_AMD64_REL32: u16 = 0x0004;
const IMAGE_REL_ARM64_ADDR32: u16 = 0x0001;
const IMAGE_REL_ARM64_BRANCH26: u16 = 0x0003;
const IMAGE_REL_ARM64_PAGEBASE_REL21: u16 = 0x0004;
const IMAGE_REL_ARM64_PAGEOFFSET_12A: u16 = 0x0006;
const IMAGE_REL_ARM64_PAGEOFFSET_12L: u16 = 0x0007;
const IMAGE_REL_ARM64_ADDR64: u16 = 0x000E;
const IMAGE_REL_ARM64_BRANCH19: u16 = 0x000F;
const IMAGE_REL_ARM64_BRANCH14: u16 = 0x0010;
/// adrp x16 / ldr x16, [x16, #off] / br x16.
const ARM64_THUNK_SIZE: usize = 12;
const X86_THUNK_SIZE: usize = 6;

const OPCODE_CALL_REL32: u8 = 0xE8;
const OPCODE_JMP_REL32: u8 = 0xE9;
const IMAGE_REL_BASED_DIR64: u16 = 10;
const BASE_RELOC_PAGE: u32 = 0x1000;
const DATA_DIR_BASE_RELOC: usize = 5;
const DATA_DIR_EXCEPTION: usize = 3;
const DATA_DIR_TLS: usize = 9;
const TLS_DIRECTORY_SIZE: usize = 40;
const TLS_INDEX_SYMBOL: &str = "_tls_index";
const TLS_USED_SYMBOL: &str = "_tls_used";
const IMAGE_REL_AMD64_SECREL: u16 = 0x000B;
const PDATA_RECORD_SIZE: usize = 12;
const IMAGE_REL_AMD64_REL32_5: u16 = 0x0009;
const IMAGE_SYM_DTYPE_FUNCTION: u16 = 0x20;
const IMPORT_SYMBOL_PREFIX: &str = "__imp_";

const IMAGE_COMDAT_SELECT_NODUPLICATES: u8 = 1;
const IMAGE_COMDAT_SELECT_ANY: u8 = 2;
const IMAGE_COMDAT_SELECT_SAME_SIZE: u8 = 3;
const IMAGE_COMDAT_SELECT_EXACT_MATCH: u8 = 4;
const IMAGE_COMDAT_SELECT_ASSOCIATIVE: u8 = 5;
const IMAGE_COMDAT_SELECT_LARGEST: u8 = 6;
const CRT_MAIN_SYMBOL: &str = "__main";
const COFF_RET: u8 = 0xC3;

/// Whether a COFF section holds `RUNTIME_FUNCTION` records.
fn is_exception_table(name: &str) -> bool {
    name == ".pdata" || name.starts_with(".pdata$")
}

/// Store an image-relative address in a four-byte field.
fn write_rva(field: &mut [u8], target: i64, section: &str) -> Result<()> {
    let rva = u32::try_from(target - IMAGE_BASE as i64)
        .map_err(|_| coff_error(format!("image-relative address out of range in {section}")))?;
    field.copy_from_slice(&rva.to_le_bytes());
    Ok(())
}

#[derive(Clone, Copy)]
enum CoffRegion {
    Text = 0,
    ReadOnly = 1,
    Writable = 2,
    Pdata = 3,
    Tls = 4,
}

#[derive(Clone, Copy)]
struct CoffComdat {
    selection: u8,
    assoc: usize,
}

struct CoffSection<'a> {
    object: usize,
    name: String,
    region: CoffRegion,
    align: usize,
    size: usize,
    raw: &'a [u8],
    relocs: Vec<(u32, u32, u16)>,
    offset: usize,
    comdat: Option<CoffComdat>,
    keep: bool,
    uninit: bool,
}

#[derive(Clone, Copy)]
enum CoffDef {
    Section { index: usize, value: u32 },
    Absolute(u32),
}

fn coff_error(message: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

fn coff_section_align(flags: u32) -> usize {
    match (flags >> 20) & 0xF {
        0 => 1,
        n => 1 << (n - 1),
    }
}

fn rel32(target: u64, end: u64) -> Result<i32> {
    i32::try_from(target as i64 - end as i64)
        .map_err(|_| coff_error("branch target out of 32-bit range".to_string()))
}

/// Windows kernel32.dll API functions.
fn is_kernel32_symbol(name: &str) -> bool {
    matches!(
        name,
        "ExitProcess"
            | "GetStdHandle"
            | "WriteFile"
            | "WriteConsoleA"
            | "WriteConsoleW"
            | "ReadFile"
            | "CloseHandle"
            | "CreateFileA"
            | "CreateFileW"
            | "VirtualAlloc"
            | "VirtualFree"
            | "GetLastError"
            | "SetLastError"
            | "LoadLibraryA"
            | "GetProcAddress"
            | "FreeLibrary"
            | "HeapAlloc"
            | "HeapFree"
            | "GetProcessHeap"
            | "CreateThread"
            | "WaitForSingleObject"
            | "GetCurrentThreadId"
            | "Sleep"
    )
}

/// C runtime functions that msvcrt.dll exports under their plain C names.
/// Undefined symbols outside this list and the kernel32 list are link errors.
// Names msvcrt.dll exports, taken from the __imp_ entries of mingw-w64's
// libmsvcrt.a import library. Sorted, so lookup can binary search.
const MSVCRT_SYMBOLS: &[&str] = &[
    "$I10_OUTPUT",
    "??0__non_rtti_object@@QEAA@AEBV0@@Z",
    "??0__non_rtti_object@@QEAA@PEBD@Z",
    "??0bad_cast@@AEAA@PEBQEBD@Z",
    "??0bad_cast@@QEAA@AEBQEBD@Z",
    "??0bad_cast@@QEAA@AEBV0@@Z",
    "??0bad_cast@@QEAA@PEBD@Z",
    "??0bad_typeid@@QEAA@AEBV0@@Z",
    "??0bad_typeid@@QEAA@PEBD@Z",
    "??0exception@@QEAA@AEBQEBD@Z",
    "??0exception@@QEAA@AEBQEBDH@Z",
    "??0exception@@QEAA@AEBV0@@Z",
    "??0exception@@QEAA@XZ",
    "??1__non_rtti_object@@UEAA@XZ",
    "??1bad_cast@@UEAA@XZ",
    "??1bad_typeid@@UEAA@XZ",
    "??1exception@@UEAA@XZ",
    "??1type_info@@UEAA@XZ",
    "??2@YAPEAX_K@Z",
    "??3@YAXPEAX@Z",
    "??4__non_rtti_object@@QEAAAEAV0@AEBV0@@Z",
    "??4bad_cast@@QEAAAEAV0@AEBV0@@Z",
    "??4bad_typeid@@QEAAAEAV0@AEBV0@@Z",
    "??4exception@@QEAAAEAV0@AEBV0@@Z",
    "??8type_info@@QEBAHAEBV0@@Z",
    "??9type_info@@QEBAHAEBV0@@Z",
    "??_7__non_rtti_object@@6B@",
    "??_7bad_cast@@6B@",
    "??_7bad_typeid@@6B@",
    "??_7exception@@6B@",
    "??_Fbad_cast@@QEAAXXZ",
    "??_Fbad_typeid@@QEAAXXZ",
    "??_U@YAPEAX_K@Z",
    "??_V@YAXPEAX@Z",
    "?_query_new_handler@@YAP6AH_K@ZXZ",
    "?_query_new_mode@@YAHXZ",
    "?_set_new_handler@@YAP6AH_K@ZP6AH0@Z@Z",
    "?_set_new_mode@@YAHH@Z",
    "?_set_se_translator@@YAP6AXIPEAU_EXCEPTION_POINTERS@@@ZP6AXI0@Z@Z",
    "?before@type_info@@QEBAHAEBV1@@Z",
    "?name@type_info@@QEBAPEBDXZ",
    "?raw_name@type_info@@QEBAPEBDXZ",
    "?set_new_handler@@YAP6AXXZP6AXXZ@Z",
    "?set_terminate@@YAP6AXXZP6AXXZ@Z",
    "?set_unexpected@@YAP6AXXZP6AXXZ@Z",
    "?terminate@@YAXXZ",
    "?unexpected@@YAXXZ",
    "?what@exception@@UEBAPEBDXZ",
    "_CxxThrowException",
    "_Getdays",
    "_Getmonths",
    "_Gettnames",
    "_HUGE",
    "_Strftime",
    "_XcptFilter",
    "__C_specific_handler",
    "__CppXcptFilter",
    "__CxxFrameHandler",
    "__DestructExceptionObject",
    "__RTCastToVoid",
    "__RTDynamicCast",
    "__RTtypeid",
    "__STRINGTOLD",
    "___lc_codepage_func",
    "___lc_collate_cp_func",
    "___lc_handle_func",
    "___mb_cur_max_func",
    "___setlc_active_func",
    "___unguarded_readlc_active_add_func",
    "__acrt_iob_func",
    "__argc",
    "__argv",
    "__badioinfo",
    "__crtCompareStringA",
    "__crtCompareStringW",
    "__crtGetLocaleInfoW",
    "__crtGetStringTypeW",
    "__crtLCMapStringA",
    "__crtLCMapStringW",
    "__dllonexit",
    "__doserrno",
    "__fpecode",
    "__getmainargs",
    "__initenv",
    "__iob_func",
    "__isascii",
    "__iscsym",
    "__iscsymf",
    "__lc_codepage",
    "__lc_collate_cp",
    "__lc_handle",
    "__lconv_init",
    "__mb_cur_max",
    "__ms_fprintf",
    "__ms_fscanf",
    "__ms_fwprintf",
    "__ms_fwscanf",
    "__ms_printf",
    "__ms_scanf",
    "__ms_sprintf",
    "__ms_sscanf",
    "__ms_swprintf",
    "__ms_swscanf",
    "__ms_vfprintf",
    "__ms_vfwprintf",
    "__ms_vprintf",
    "__ms_vsprintf",
    "__ms_vswprintf",
    "__ms_vwprintf",
    "__ms_wprintf",
    "__ms_wscanf",
    "__p___argv",
    "__p__acmdln",
    "__p__commode",
    "__p__fmode",
    "__p__wcmdln",
    "__pctype_func",
    "__pioinfo",
    "__pwctype_func",
    "__pxcptinfoptrs",
    "__set_app_type",
    "__setlc_active",
    "__setusermatherr",
    "__threadhandle",
    "__threadid",
    "__toascii",
    "__unDName",
    "__unDNameEx",
    "__uncaught_exception",
    "__unguarded_readlc_active",
    "__wargv",
    "__wcserror",
    "__wcserror_s",
    "__wgetmainargs",
    "__winitenv",
    "_abs64",
    "_access",
    "_access_s",
    "_acmdln",
    "_aexit_rtn",
    "_aligned_free",
    "_aligned_malloc",
    "_aligned_offset_malloc",
    "_aligned_offset_realloc",
    "_aligned_realloc",
    "_amsg_exit",
    "_assert",
    "_atodbl",
    "_atodbl_l",
    "_atof_l",
    "_atoflt_l",
    "_atoi64",
    "_atoi64_l",
    "_atoi_l",
    "_atol_l",
    "_atoldbl",
    "_atoldbl_l",
    "_atoll_l",
    "_beep",
    "_beginthread",
    "_beginthreadex",
    "_c_exit",
    "_cabs",
    "_callnewh",
    "_cexit",
    "_cgets",
    "_cgets_s",
    "_cgetws",
    "_cgetws_s",
    "_chdir",
    "_chdrive",
    "_chgsign",
    "_chgsignf",
    "_chmod",
    "_chsize",
    "_chsize_s",
    "_clearfp",
    "_close",
    "_commit",
    "_commode",
    "_configthreadlocale",
    "_control87",
    "_controlfp",
    "_controlfp_s",
    "_copysign",
    "_copysignf",
    "_cprintf",
    "_cprintf_l",
    "_cprintf_p",
    "_cprintf_p_l",
    "_cprintf_s",
    "_cprintf_s_l",
    "_cputs",
    "_cputws",
    "_creat",
    "_create_locale",
    "_cscanf",
    "_cscanf_l",
    "_cscanf_s",
    "_cscanf_s_l",
    "_ctime32_s",
    "_ctime64",
    "_ctime64_s",
    "_ctype",
    "_cwait",
    "_cwprintf",
    "_cwprintf_l",
    "_cwprintf_p",
    "_cwprintf_p_l",
    "_cwprintf_s",
    "_cwprintf_s_l",
    "_cwscanf",
    "_cwscanf_l",
    "_cwscanf_s",
    "_cwscanf_s_l",
    "_daylight",
    "_difftime32",
    "_difftime64",
    "_dstbias",
    "_dup",
    "_dup2",
    "_ecvt",
    "_ecvt_s",
    "_endthread",
    "_endthreadex",
    "_environ",
    "_eof",
    "_errno",
    "_execl",
    "_execle",
    "_execlp",
    "_execlpe",
    "_execute_onexit_table",
    "_execv",
    "_execve",
    "_execvp",
    "_execvpe",
    "_exit",
    "_expand",
    "_fcloseall",
    "_fcvt",
    "_fcvt_s",
    "_fdopen",
    "_fgetchar",
    "_fgetwchar",
    "_filbuf",
    "_fileinfo",
    "_filelength",
    "_filelengthi64",
    "_fileno",
    "_findclose",
    "_findfirst",
    "_findfirst64",
    "_findfirst64i32",
    "_findfirsti64",
    "_findnext",
    "_findnext64",
    "_findnext64i32",
    "_findnexti64",
    "_finite",
    "_finitef",
    "_flsbuf",
    "_flushall",
    "_fmode",
    "_fpclass",
    "_fpclassf",
    "_fpreset",
    "_fprintf_l",
    "_fprintf_p",
    "_fprintf_p_l",
    "_fprintf_s_l",
    "_fputchar",
    "_fputwchar",
    "_free_locale",
    "_fscanf_l",
    "_fscanf_s_l",
    "_fseeki64",
    "_fsopen",
    "_fstat",
    "_fstat64",
    "_fstat64i32",
    "_fstati64",
    "_ftelli64",
    "_ftime",
    "_ftime32",
    "_ftime32_s",
    "_ftime64",
    "_ftime64_s",
    "_ftime_s",
    "_fullpath",
    "_futime",
    "_futime32",
    "_futime64",
    "_fwprintf_l",
    "_fwprintf_p",
    "_fwprintf_p_l",
    "_fwprintf_s_l",
    "_fwscanf_l",
    "_fwscanf_s_l",
    "_gcvt",
    "_gcvt_s",
    "_get_current_locale",
    "_get_doserrno",
    "_get_heap_handle",
    "_get_invalid_parameter_handler",
    "_get_osfhandle",
    "_get_output_format",
    "_get_sbh_threshold",
    "_getch",
    "_getche",
    "_getcwd",
    "_getdcwd",
    "_getdiskfree",
    "_getdllprocaddr",
    "_getdrive",
    "_getdrives",
    "_getmaxstdio",
    "_getmbcp",
    "_getpid",
    "_getsystime",
    "_getw",
    "_getwch",
    "_getwche",
    "_getws",
    "_gmtime32",
    "_gmtime32_s",
    "_gmtime64",
    "_gmtime64_s",
    "_heapadd",
    "_heapchk",
    "_heapmin",
    "_heapset",
    "_heapused",
    "_heapwalk",
    "_hypot",
    "_hypotf",
    "_i64toa",
    "_i64toa_s",
    "_i64tow",
    "_i64tow_s",
    "_initialize_onexit_table",
    "_initterm",
    "_iob",
    "_isalnum_l",
    "_isalpha_l",
    "_isatty",
    "_iscntrl_l",
    "_isctype",
    "_isctype_l",
    "_isdigit_l",
    "_isgraph_l",
    "_isleadbyte_l",
    "_islower_l",
    "_ismbbalnum",
    "_ismbbalnum_l",
    "_ismbbalpha",
    "_ismbbalpha_l",
    "_ismbbgraph",
    "_ismbbgraph_l",
    "_ismbbkalnum",
    "_ismbbkalnum_l",
    "_ismbbkana",
    "_ismbbkana_l",
    "_ismbbkprint",
    "_ismbbkprint_l",
    "_ismbbkpunct",
    "_ismbbkpunct_l",
    "_ismbblead",
    "_ismbblead_l",
    "_ismbbprint",
    "_ismbbprint_l",
    "_ismbbpunct",
    "_ismbbpunct_l",
    "_ismbbtrail",
    "_ismbbtrail_l",
    "_ismbcalnum",
    "_ismbcalnum_l",
    "_ismbcalpha",
    "_ismbcalpha_l",
    "_ismbcdigit",
    "_ismbcdigit_l",
    "_ismbcgraph",
    "_ismbcgraph_l",
    "_ismbchira",
    "_ismbchira_l",
    "_ismbckata",
    "_ismbckata_l",
    "_ismbcl0",
    "_ismbcl0_l",
    "_ismbcl1",
    "_ismbcl1_l",
    "_ismbcl2",
    "_ismbcl2_l",
    "_ismbclegal",
    "_ismbclegal_l",
    "_ismbclower",
    "_ismbclower_l",
    "_ismbcprint",
    "_ismbcprint_l",
    "_ismbcpunct",
    "_ismbcpunct_l",
    "_ismbcspace",
    "_ismbcspace_l",
    "_ismbcsymbol",
    "_ismbcsymbol_l",
    "_ismbcupper",
    "_ismbcupper_l",
    "_ismbslead",
    "_ismbslead_l",
    "_ismbstrail",
    "_ismbstrail_l",
    "_isnan",
    "_isnanf",
    "_isprint_l",
    "_isspace_l",
    "_isupper_l",
    "_iswalnum_l",
    "_iswalpha_l",
    "_iswcntrl_l",
    "_iswctype_l",
    "_iswdigit_l",
    "_iswgraph_l",
    "_iswlower_l",
    "_iswprint_l",
    "_iswpunct_l",
    "_iswspace_l",
    "_iswupper_l",
    "_iswxdigit_l",
    "_isxdigit_l",
    "_itoa",
    "_itoa_s",
    "_itow",
    "_itow_s",
    "_j0",
    "_j1",
    "_jn",
    "_kbhit",
    "_lfind",
    "_lfind_s",
    "_loaddll",
    "_local_unwind",
    "_localtime32",
    "_localtime32_s",
    "_localtime64",
    "_localtime64_s",
    "_lock",
    "_lock_file",
    "_locking",
    "_logb",
    "_logbf",
    "_lrotl",
    "_lrotr",
    "_lsearch",
    "_lsearch_s",
    "_lseek",
    "_lseeki64",
    "_ltoa",
    "_ltoa_s",
    "_ltow",
    "_ltow_s",
    "_makepath",
    "_makepath_s",
    "_mbbtombc",
    "_mbbtombc_l",
    "_mbbtype",
    "_mbcasemap",
    "_mbccpy",
    "_mbccpy_l",
    "_mbccpy_s",
    "_mbccpy_s_l",
    "_mbcjistojms",
    "_mbcjistojms_l",
    "_mbcjmstojis",
    "_mbcjmstojis_l",
    "_mbclen",
    "_mbclen_l",
    "_mbctohira",
    "_mbctohira_l",
    "_mbctokata",
    "_mbctokata_l",
    "_mbctolower",
    "_mbctolower_l",
    "_mbctombb",
    "_mbctombb_l",
    "_mbctoupper",
    "_mbctoupper_l",
    "_mbctype",
    "_mblen_l",
    "_mbsbtype",
    "_mbsbtype_l",
    "_mbscat",
    "_mbscat_s",
    "_mbscat_s_l",
    "_mbschr",
    "_mbschr_l",
    "_mbscmp",
    "_mbscmp_l",
    "_mbscoll",
    "_mbscoll_l",
    "_mbscpy",
    "_mbscpy_s",
    "_mbscpy_s_l",
    "_mbscspn",
    "_mbscspn_l",
    "_mbsdec",
    "_mbsdec_l",
    "_mbsdup",
    "_mbsicmp",
    "_mbsicmp_l",
    "_mbsicoll",
    "_mbsicoll_l",
    "_mbsinc",
    "_mbsinc_l",
    "_mbslen",
    "_mbslen_l",
    "_mbslwr",
    "_mbslwr_l",
    "_mbslwr_s",
    "_mbslwr_s_l",
    "_mbsnbcat",
    "_mbsnbcat_l",
    "_mbsnbcat_s",
    "_mbsnbcat_s_l",
    "_mbsnbcmp",
    "_mbsnbcmp_l",
    "_mbsnbcnt",
    "_mbsnbcnt_l",
    "_mbsnbcoll",
    "_mbsnbcoll_l",
    "_mbsnbcpy",
    "_mbsnbcpy_l",
    "_mbsnbcpy_s",
    "_mbsnbcpy_s_l",
    "_mbsnbicmp",
    "_mbsnbicmp_l",
    "_mbsnbicoll",
    "_mbsnbicoll_l",
    "_mbsnbset",
    "_mbsnbset_l",
    "_mbsnbset_s",
    "_mbsnbset_s_l",
    "_mbsncat",
    "_mbsncat_l",
    "_mbsncat_s",
    "_mbsncat_s_l",
    "_mbsnccnt",
    "_mbsnccnt_l",
    "_mbsncmp",
    "_mbsncmp_l",
    "_mbsncoll",
    "_mbsncoll_l",
    "_mbsncpy",
    "_mbsncpy_l",
    "_mbsncpy_s",
    "_mbsncpy_s_l",
    "_mbsnextc",
    "_mbsnextc_l",
    "_mbsnicmp",
    "_mbsnicmp_l",
    "_mbsnicoll",
    "_mbsnicoll_l",
    "_mbsninc",
    "_mbsninc_l",
    "_mbsnlen",
    "_mbsnlen_l",
    "_mbsnset",
    "_mbsnset_l",
    "_mbsnset_s",
    "_mbsnset_s_l",
    "_mbspbrk",
    "_mbspbrk_l",
    "_mbsrchr",
    "_mbsrchr_l",
    "_mbsrev",
    "_mbsrev_l",
    "_mbsset",
    "_mbsset_l",
    "_mbsset_s",
    "_mbsset_s_l",
    "_mbsspn",
    "_mbsspn_l",
    "_mbsspnp",
    "_mbsspnp_l",
    "_mbsstr",
    "_mbsstr_l",
    "_mbstok",
    "_mbstok_l",
    "_mbstok_s",
    "_mbstok_s_l",
    "_mbstowcs_l",
    "_mbstowcs_s_l",
    "_mbstrlen",
    "_mbstrlen_l",
    "_mbstrnlen",
    "_mbstrnlen_l",
    "_mbsupr",
    "_mbsupr_l",
    "_mbsupr_s",
    "_mbsupr_s_l",
    "_mbtowc_l",
    "_memccpy",
    "_memicmp",
    "_memicmp_l",
    "_mkdir",
    "_mkgmtime",
    "_mkgmtime32",
    "_mkgmtime64",
    "_mktemp",
    "_mktemp_s",
    "_mktime64",
    "_msize",
    "_nextafter",
    "_nextafterf",
    "_onexit",
    "_open",
    "_open_osfhandle",
    "_osplatform",
    "_osver",
    "_pclose",
    "_pctype",
    "_pgmptr",
    "_pipe",
    "_popen",
    "_printf_l",
    "_printf_p",
    "_printf_p_l",
    "_printf_s_l",
    "_purecall",
    "_putch",
    "_putenv",
    "_putenv_s",
    "_putw",
    "_putwch",
    "_putws",
    "_pwctype",
    "_read",
    "_register_onexit_function",
    "_register_thread_local_exe_atexit_callback",
    "_resetstkoflw",
    "_rmdir",
    "_rmtmp",
    "_rotl",
    "_rotl64",
    "_rotr",
    "_rotr64",
    "_scalb",
    "_scalbf",
    "_scanf_l",
    "_scanf_s_l",
    "_scprintf",
    "_scprintf_l",
    "_scprintf_p_l",
    "_scwprintf",
    "_scwprintf_l",
    "_scwprintf_p_l",
    "_searchenv",
    "_searchenv_s",
    "_set_controlfp",
    "_set_doserrno",
    "_set_error_mode",
    "_set_invalid_parameter_handler",
    "_set_output_format",
    "_set_purecall_handler",
    "_set_sbh_threshold",
    "_seterrormode",
    "_setjmp",
    "_setjmpex",
    "_setmaxstdio",
    "_setmbcp",
    "_setmode",
    "_setsystime",
    "_sleep",
    "_snprintf",
    "_snprintf_c",
    "_snprintf_c_l",
    "_snprintf_l",
    "_snprintf_s",
    "_snprintf_s_l",
    "_snscanf",
    "_snscanf_l",
    "_snscanf_s",
    "_snscanf_s_l",
    "_snwprintf",
    "_snwprintf_l",
    "_snwprintf_s",
    "_snwprintf_s_l",
    "_snwscanf",
    "_snwscanf_l",
    "_snwscanf_s",
    "_snwscanf_s_l",
    "_sopen",
    "_sopen_s",
    "_spawnl",
    "_spawnle",
    "_spawnlp",
    "_spawnlpe",
    "_spawnv",
    "_spawnve",
    "_spawnvp",
    "_spawnvpe",
    "_splitpath",
    "_splitpath_s",
    "_sprintf_l",
    "_sprintf_p_l",
    "_sprintf_s_l",
    "_sscanf_l",
    "_sscanf_s_l",
    "_stat",
    "_stat64",
    "_stat64i32",
    "_stati64",
    "_statusfp",
    "_strcmpi",
    "_strcoll_l",
    "_strdate",
    "_strdate_s",
    "_strdup",
    "_strerror",
    "_strerror_s",
    "_stricmp",
    "_stricmp_l",
    "_stricoll",
    "_stricoll_l",
    "_strlwr",
    "_strlwr_l",
    "_strlwr_s",
    "_strlwr_s_l",
    "_strncoll",
    "_strncoll_l",
    "_strnicmp",
    "_strnicmp_l",
    "_strnicoll",
    "_strnicoll_l",
    "_strnset",
    "_strnset_s",
    "_strrev",
    "_strset",
    "_strset_s",
    "_strtime",
    "_strtime_s",
    "_strtod_l",
    "_strtoi64",
    "_strtoi64_l",
    "_strtoimax_l",
    "_strtol_l",
    "_strtoll_l",
    "_strtoui64",
    "_strtoui64_l",
    "_strtoul_l",
    "_strtoull_l",
    "_strtoumax_l",
    "_strupr",
    "_strupr_l",
    "_strupr_s",
    "_strupr_s_l",
    "_strxfrm_l",
    "_swab",
    "_swprintf",
    "_swprintf_c",
    "_swprintf_c_l",
    "_swprintf_p_l",
    "_swprintf_s_l",
    "_swscanf_l",
    "_swscanf_s_l",
    "_sys_errlist",
    "_sys_nerr",
    "_tell",
    "_telli64",
    "_tempnam",
    "_time64",
    "_timezone",
    "_tolower",
    "_tolower_l",
    "_toupper",
    "_toupper_l",
    "_towlower_l",
    "_towupper_l",
    "_tzname",
    "_tzset",
    "_ui64toa",
    "_ui64toa_s",
    "_ui64tow",
    "_ui64tow_s",
    "_ultoa",
    "_ultoa_s",
    "_ultow",
    "_ultow_s",
    "_umask",
    "_umask_s",
    "_ungetch",
    "_ungetwch",
    "_unlink",
    "_unloaddll",
    "_unlock",
    "_unlock_file",
    "_utime",
    "_utime32",
    "_utime64",
    "_vcprintf",
    "_vcprintf_l",
    "_vcprintf_p",
    "_vcprintf_p_l",
    "_vcprintf_s",
    "_vcprintf_s_l",
    "_vcwprintf",
    "_vcwprintf_l",
    "_vcwprintf_p",
    "_vcwprintf_p_l",
    "_vcwprintf_s",
    "_vcwprintf_s_l",
    "_vfprintf_l",
    "_vfprintf_p",
    "_vfprintf_p_l",
    "_vfprintf_s_l",
    "_vfwprintf_l",
    "_vfwprintf_p",
    "_vfwprintf_p_l",
    "_vfwprintf_s_l",
    "_vprintf_l",
    "_vprintf_p",
    "_vprintf_p_l",
    "_vprintf_s_l",
    "_vscprintf",
    "_vscprintf_l",
    "_vscprintf_p",
    "_vscprintf_p_l",
    "_vscwprintf",
    "_vscwprintf_l",
    "_vscwprintf_p",
    "_vscwprintf_p_l",
    "_vsnprintf",
    "_vsnprintf_c",
    "_vsnprintf_c_l",
    "_vsnprintf_l",
    "_vsnprintf_s",
    "_vsnprintf_s_l",
    "_vsnwprintf",
    "_vsnwprintf_l",
    "_vsnwprintf_s",
    "_vsnwprintf_s_l",
    "_vsprintf_l",
    "_vsprintf_p",
    "_vsprintf_p_l",
    "_vsprintf_s_l",
    "_vswprintf",
    "_vswprintf_c",
    "_vswprintf_c_l",
    "_vswprintf_l",
    "_vswprintf_p",
    "_vswprintf_p_l",
    "_vswprintf_s_l",
    "_vwprintf_l",
    "_vwprintf_p",
    "_vwprintf_p_l",
    "_vwprintf_s_l",
    "_waccess",
    "_waccess_s",
    "_wasctime",
    "_wasctime_s",
    "_wassert",
    "_wchdir",
    "_wchmod",
    "_wcmdln",
    "_wcreat",
    "_wcscoll_l",
    "_wcsdup",
    "_wcserror",
    "_wcserror_s",
    "_wcsftime_l",
    "_wcsicmp",
    "_wcsicmp_l",
    "_wcsicoll",
    "_wcsicoll_l",
    "_wcslwr",
    "_wcslwr_l",
    "_wcslwr_s",
    "_wcslwr_s_l",
    "_wcsncoll",
    "_wcsncoll_l",
    "_wcsnicmp",
    "_wcsnicmp_l",
    "_wcsnicoll",
    "_wcsnicoll_l",
    "_wcsnset",
    "_wcsnset_s",
    "_wcsrev",
    "_wcsset",
    "_wcsset_s",
    "_wcstoi64",
    "_wcstoi64_l",
    "_wcstol_l",
    "_wcstombs_l",
    "_wcstombs_s_l",
    "_wcstoui64",
    "_wcstoui64_l",
    "_wcstoul_l",
    "_wcsupr",
    "_wcsupr_l",
    "_wcsupr_s",
    "_wcsupr_s_l",
    "_wcsxfrm_l",
    "_wctime",
    "_wctime32_s",
    "_wctime64",
    "_wctime64_s",
    "_wctomb_l",
    "_wctomb_s_l",
    "_wctype",
    "_wenviron",
    "_wexecl",
    "_wexecle",
    "_wexeclp",
    "_wexeclpe",
    "_wexecv",
    "_wexecve",
    "_wexecvp",
    "_wexecvpe",
    "_wfdopen",
    "_wfindfirst",
    "_wfindfirst64",
    "_wfindfirst64i32",
    "_wfindfirsti64",
    "_wfindnext",
    "_wfindnext64",
    "_wfindnext64i32",
    "_wfindnexti64",
    "_wfopen",
    "_wfopen_s",
    "_wfreopen",
    "_wfreopen_s",
    "_wfsopen",
    "_wfullpath",
    "_wgetcwd",
    "_wgetdcwd",
    "_wgetenv",
    "_wgetenv_s",
    "_winmajor",
    "_winminor",
    "_winput_s",
    "_winver",
    "_wmakepath",
    "_wmakepath_s",
    "_wmkdir",
    "_wmktemp",
    "_wmktemp_s",
    "_wopen",
    "_woutput_s",
    "_wperror",
    "_wpgmptr",
    "_wpopen",
    "_wprintf_l",
    "_wprintf_p",
    "_wprintf_p_l",
    "_wprintf_s_l",
    "_wputenv",
    "_wputenv_s",
    "_wremove",
    "_wrename",
    "_write",
    "_wrmdir",
    "_wscanf_l",
    "_wscanf_s_l",
    "_wsearchenv",
    "_wsearchenv_s",
    "_wsetlocale",
    "_wsopen",
    "_wsopen_s",
    "_wspawnl",
    "_wspawnle",
    "_wspawnlp",
    "_wspawnlpe",
    "_wspawnv",
    "_wspawnve",
    "_wspawnvp",
    "_wspawnvpe",
    "_wsplitpath",
    "_wsplitpath_s",
    "_wstat",
    "_wstat64",
    "_wstat64i32",
    "_wstati64",
    "_wstrdate",
    "_wstrdate_s",
    "_wstrtime",
    "_wstrtime_s",
    "_wsystem",
    "_wtempnam",
    "_wtmpnam",
    "_wtmpnam_s",
    "_wtof",
    "_wtof_l",
    "_wtoi",
    "_wtoi64",
    "_wtoi64_l",
    "_wtoi_l",
    "_wtol",
    "_wtol_l",
    "_wunlink",
    "_wutime",
    "_wutime32",
    "_wutime64",
    "_y0",
    "_y1",
    "_yn",
    "abort",
    "abs",
    "access",
    "acos",
    "acosf",
    "asctime",
    "asctime_s",
    "asin",
    "asinf",
    "atan",
    "atan2",
    "atan2f",
    "atanf",
    "atexit",
    "atof",
    "atoi",
    "atol",
    "atoll",
    "bsearch",
    "bsearch_s",
    "calloc",
    "ceil",
    "ceilf",
    "chdir",
    "chgsign",
    "chmod",
    "chsize",
    "clearerr",
    "clearerr_s",
    "clock",
    "close",
    "cos",
    "cosf",
    "cosh",
    "coshf",
    "creat",
    "ctime",
    "cwait",
    "daylight",
    "difftime",
    "div",
    "dup",
    "dup2",
    "ecvt",
    "eof",
    "execl",
    "execle",
    "execlp",
    "execlpe",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "exit",
    "exp",
    "expf",
    "fabs",
    "fclose",
    "fcvt",
    "fdopen",
    "feof",
    "ferror",
    "fflush",
    "fgetc",
    "fgetchar",
    "fgetpos",
    "fgets",
    "fgetwc",
    "fgetwchar",
    "fgetws",
    "filelength",
    "fileno",
    "finite",
    "floor",
    "floorf",
    "fmod",
    "fmodf",
    "fopen",
    "fopen_s",
    "fpclass",
    "fprintf",
    "fprintf_s",
    "fputc",
    "fputchar",
    "fputs",
    "fputwc",
    "fputwchar",
    "fputws",
    "fread",
    "free",
    "freopen",
    "freopen_s",
    "frexp",
    "fscanf",
    "fscanf_s",
    "fseek",
    "fsetpos",
    "ftell",
    "fwprintf",
    "fwprintf_s",
    "fwrite",
    "fwscanf",
    "fwscanf_s",
    "gcvt",
    "getc",
    "getch",
    "getchar",
    "getche",
    "getcwd",
    "getenv",
    "getenv_s",
    "getpid",
    "gets",
    "getw",
    "getwc",
    "getwchar",
    "gmtime",
    "heapwalk",
    "hypot",
    "imaxabs",
    "imaxdiv",
    "is_wctype",
    "isalnum",
    "isalpha",
    "isascii",
    "isatty",
    "iscntrl",
    "iscsym",
    "iscsymf",
    "isdigit",
    "isgraph",
    "isleadbyte",
    "islower",
    "isprint",
    "ispunct",
    "isspace",
    "isupper",
    "iswalnum",
    "iswalpha",
    "iswascii",
    "iswcntrl",
    "iswctype",
    "iswdigit",
    "iswgraph",
    "iswlower",
    "iswprint",
    "iswpunct",
    "iswspace",
    "iswupper",
    "iswxdigit",
    "isxdigit",
    "itoa",
    "j0",
    "j1",
    "jn",
    "kbhit",
    "labs",
    "ldexp",
    "ldiv",
    "lfind",
    "llabs",
    "lldiv",
    "localeconv",
    "localtime",
    "log",
    "log10",
    "log10f",
    "logf",
    "longjmp",
    "lsearch",
    "lseek",
    "ltoa",
    "malloc",
    "mblen",
    "mbsrtowcs_s",
    "mbstowcs",
    "mbstowcs_s",
    "mbtowc",
    "memccpy",
    "memchr",
    "memcmp",
    "memcpy",
    "memcpy_s",
    "memicmp",
    "memmove",
    "memmove_s",
    "memset",
    "mkdir",
    "mktemp",
    "mktime",
    "modf",
    "modff",
    "nextafter",
    "open",
    "pclose",
    "perror",
    "popen",
    "pow",
    "powf",
    "printf",
    "printf_s",
    "putc",
    "putch",
    "putchar",
    "putenv",
    "puts",
    "putw",
    "putwc",
    "putwchar",
    "qsort",
    "qsort_s",
    "raise",
    "rand",
    "rand_s",
    "read",
    "realloc",
    "remove",
    "rename",
    "rewind",
    "rmdir",
    "rmtmp",
    "scanf",
    "scanf_s",
    "searchenv",
    "setbuf",
    "setjmp",
    "setlocale",
    "setmode",
    "setvbuf",
    "signal",
    "sin",
    "sinf",
    "sinh",
    "sinhf",
    "snwprintf",
    "sopen",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "sprintf",
    "sprintf_s",
    "sqrt",
    "sqrtf",
    "srand",
    "sscanf",
    "sscanf_s",
    "strcasecmp",
    "strcat",
    "strcat_s",
    "strchr",
    "strcmp",
    "strcmpi",
    "strcoll",
    "strcpy",
    "strcpy_s",
    "strcspn",
    "strdup",
    "strerror",
    "strerror_s",
    "strftime",
    "stricmp",
    "stricoll",
    "strlen",
    "strlwr",
    "strncasecmp",
    "strncat",
    "strncat_s",
    "strncmp",
    "strncpy",
    "strncpy_s",
    "strnicmp",
    "strnset",
    "strpbrk",
    "strrchr",
    "strrev",
    "strset",
    "strspn",
    "strstr",
    "strtod",
    "strtoimax",
    "strtok",
    "strtok_s",
    "strtol",
    "strtoll",
    "strtoul",
    "strtoull",
    "strtoumax",
    "strupr",
    "strxfrm",
    "swab",
    "swprintf",
    "swprintf_s",
    "swscanf",
    "swscanf_s",
    "system",
    "tan",
    "tanf",
    "tanh",
    "tell",
    "tempnam",
    "time",
    "timezone",
    "tmpfile",
    "tmpfile_s",
    "tmpnam",
    "tmpnam_s",
    "toascii",
    "tolower",
    "toupper",
    "towlower",
    "towupper",
    "tzname",
    "tzset",
    "umask",
    "ungetc",
    "ungetch",
    "ungetwc",
    "unlink",
    "utime",
    "vfprintf",
    "vfprintf_s",
    "vfwprintf",
    "vfwprintf_s",
    "vprintf",
    "vprintf_s",
    "vsnprintf_s",
    "vsnwprintf",
    "vsprintf",
    "vsprintf_s",
    "vswprintf",
    "vswprintf_s",
    "vwprintf",
    "vwprintf_s",
    "wcrtomb_s",
    "wcscat",
    "wcscat_s",
    "wcschr",
    "wcscmp",
    "wcscmpi",
    "wcscoll",
    "wcscpy",
    "wcscpy_s",
    "wcscspn",
    "wcsdup",
    "wcsftime",
    "wcsicmp",
    "wcsicoll",
    "wcslen",
    "wcslwr",
    "wcsncat",
    "wcsncat_s",
    "wcsncmp",
    "wcsncpy",
    "wcsncpy_s",
    "wcsnicmp",
    "wcsnlen",
    "wcsnset",
    "wcspbrk",
    "wcsrchr",
    "wcsrev",
    "wcsrtombs_s",
    "wcsset",
    "wcsspn",
    "wcsstr",
    "wcstod",
    "wcstok",
    "wcstok_s",
    "wcstol",
    "wcstombs",
    "wcstombs_s",
    "wcstoul",
    "wcsupr",
    "wcsxfrm",
    "wctomb",
    "wctomb_s",
    "wmemcpy_s",
    "wmemmove_s",
    "wpopen",
    "wprintf",
    "wprintf_s",
    "write",
    "wscanf",
    "wscanf_s",
    "y0",
    "y1",
    "yn",
];

#[cfg(test)]
mod msvcrt_table_tests {
    use super::*;

    #[test]
    fn msvcrt_symbol_table_is_sorted_and_unique() {
        assert!(
            MSVCRT_SYMBOLS.windows(2).all(|p| p[0] < p[1]),
            "MSVCRT_SYMBOLS must stay sorted and unique for binary_search"
        );
    }
}

fn is_msvcrt_symbol(name: &str) -> bool {
    MSVCRT_SYMBOLS.binary_search(&name).is_ok()
}

fn coff_duplicate_symbol(name: &str, first: usize, second: usize) -> std::io::Error {
    coff_error(format!(
        "duplicate symbol {name} defined in object {first} and object {second}"
    ))
}

fn reloc_target_name(symbols: &[coff::Symbol], index: u32) -> Option<&str> {
    symbols.get(index as usize).map(|s| s.name.as_str())
}

fn comdat_bodies_match(
    a: &CoffSection,
    a_symbols: &[coff::Symbol],
    b: &CoffSection,
    b_symbols: &[coff::Symbol],
) -> bool {
    a.size == b.size
        && a.raw == b.raw
        && a.relocs.len() == b.relocs.len()
        && a.relocs.iter().zip(&b.relocs).all(|(ra, rb)| {
            ra.0 == rb.0
                && ra.2 == rb.2
                && reloc_target_name(a_symbols, ra.1)
                    .is_some_and(|name| Some(name) == reloc_target_name(b_symbols, rb.1))
        })
}

/// Base relocation blocks: one per 4 KiB page, each with `(type << 12) | offset` entries.
fn build_base_relocs(sites: &[(u32, u16)]) -> Vec<u8> {
    let mut sites = sites.to_vec();
    sites.sort_unstable();
    let mut out = Vec::new();
    let mut i = 0;
    while i < sites.len() {
        let page = sites[i].0 & !(BASE_RELOC_PAGE - 1);
        let mut j = i;
        while j < sites.len() && sites[j].0 & !(BASE_RELOC_PAGE - 1) == page {
            j += 1;
        }
        let mut entries: Vec<u16> = sites[i..j]
            .iter()
            .map(|&(rva, ty)| (ty << 12) | ((rva & (BASE_RELOC_PAGE - 1)) as u16))
            .collect();
        if entries.len() % 2 == 1 {
            entries.push(0);
        }
        out.extend_from_slice(&page.to_le_bytes());
        out.extend_from_slice(&((8 + 2 * entries.len()) as u32).to_le_bytes());
        for entry in entries {
            out.extend_from_slice(&entry.to_le_bytes());
        }
        i = j;
    }
    out
}

fn coff_problem(problem: coff::Problem, object: usize) -> std::io::Error {
    coff_error(match problem {
        coff::Problem::Truncated => format!("truncated COFF object {object}"),
        coff::Problem::SymbolTable => {
            format!("symbol table of object {object} lies outside the object")
        }
        coff::Problem::SectionData(name) => {
            format!("section {name} data lies outside the object")
        }
        coff::Problem::Relocs(name) => {
            format!("relocations of section {name} lie outside the object")
        }
    })
}

/// `adrp x16, page(iat)` / `ldr x16, [x16, #iat & 0xfff]` / `br x16`.
fn arm64_import_thunk(iat_va: u64, thunk_va: u64, name: &str) -> Result<[u32; 3]> {
    let adrp = arm64_apply_instruction(
        0x9000_0010,
        IMAGE_REL_ARM64_PAGEBASE_REL21,
        iat_va as i64,
        thunk_va as i64,
        name,
        ".text",
    )?;
    let ldr = arm64_apply_instruction(
        0xF940_0210,
        IMAGE_REL_ARM64_PAGEOFFSET_12L,
        iat_va as i64,
        thunk_va as i64 + 4,
        name,
        ".text",
    )?;
    Ok([adrp, ldr, 0xD61F_0200])
}

fn arm64_reloc_name(rel_type: u16) -> &'static str {
    match rel_type {
        IMAGE_REL_ARM64_ADDR32 => "IMAGE_REL_ARM64_ADDR32",
        0x0002 => "IMAGE_REL_ARM64_ADDR32NB",
        IMAGE_REL_ARM64_BRANCH26 => "IMAGE_REL_ARM64_BRANCH26",
        IMAGE_REL_ARM64_PAGEBASE_REL21 => "IMAGE_REL_ARM64_PAGEBASE_REL21",
        0x0005 => "IMAGE_REL_ARM64_REL21",
        IMAGE_REL_ARM64_PAGEOFFSET_12A => "IMAGE_REL_ARM64_PAGEOFFSET_12A",
        IMAGE_REL_ARM64_PAGEOFFSET_12L => "IMAGE_REL_ARM64_PAGEOFFSET_12L",
        0x0008 => "IMAGE_REL_ARM64_SECREL",
        IMAGE_REL_ARM64_ADDR64 => "IMAGE_REL_ARM64_ADDR64",
        IMAGE_REL_ARM64_BRANCH19 => "IMAGE_REL_ARM64_BRANCH19",
        IMAGE_REL_ARM64_BRANCH14 => "IMAGE_REL_ARM64_BRANCH14",
        0x0011 => "IMAGE_REL_ARM64_REL32",
        _ => "unknown ARM64 relocation",
    }
}

/// Scale of the immediate in a load or store: the size field, plus the 128-bit
/// SIMD form which sets both bit 26 and bit 23.
fn arm64_ldst_scale(word: u32) -> u32 {
    let size = word >> 30;
    if word & 0x0480_0000 == 0x0480_0000 {
        size + 4
    } else {
        size
    }
}

/// One ARM64 immediate field: the bits it occupies, how the value is split
/// across them, and the signed range it holds.
struct Arm64Field {
    mask: u32,
    /// `(width, bit in the value, bit in the instruction)` for each run.
    parts: [(u32, u32, u32); 2],
    span: i64,
}

const ARM64_BRANCH26: Arm64Field = Arm64Field {
    mask: 0x03FF_FFFF,
    parts: [(26, 0, 0), (0, 0, 0)],
    span: 1 << 25,
};
const ARM64_BRANCH19: Arm64Field = Arm64Field {
    mask: 0x00FF_FFE0,
    parts: [(19, 0, 5), (0, 0, 0)],
    span: 1 << 18,
};
const ARM64_BRANCH14: Arm64Field = Arm64Field {
    mask: 0x0007_FFE0,
    parts: [(14, 0, 5), (0, 0, 0)],
    span: 1 << 13,
};
const ARM64_ADR_PAGE: Arm64Field = Arm64Field {
    mask: 0x60FF_FFE0,
    parts: [(2, 0, 29), (19, 2, 5)],
    span: 1 << 20,
};
const ARM64_IMM12: Arm64Field = Arm64Field {
    mask: 0x003F_FC00,
    parts: [(12, 0, 10), (0, 0, 0)],
    span: 1 << 12,
};

/// Place `value` in `field` of `word`. The field must already be zero: a
/// non-zero field is an in-instruction addend, which this linker does not
/// decode, so it refuses rather than resolve it wrongly.
fn arm64_put_imm(
    word: u32,
    field: &Arm64Field,
    value: i64,
    rel_type: u16,
    (symbol, section): (&str, &str),
) -> Result<u32> {
    if word & field.mask != 0 {
        return Err(coff_error(format!(
            "{} against {symbol} in section {section} has a non-zero immediate field; \
             weld does not decode in-instruction addends",
            arm64_reloc_name(rel_type)
        )));
    }
    if !(-field.span..field.span).contains(&value) {
        return Err(coff_error(format!(
            "{} against {symbol} in section {section} is out of range",
            arm64_reloc_name(rel_type)
        )));
    }
    let value = value as u64;
    let mut word = word;
    for (width, from, to) in field.parts {
        if width == 0 {
            continue;
        }
        let part = ((value >> from) & ((1u64 << width) - 1)) as u32;
        word |= part << to;
    }
    Ok(word)
}

/// Resolve one ARM64 relocation that lives inside an instruction word.
/// `s` is the target virtual address and `p` the address of the instruction.
fn arm64_apply_instruction(
    word: u32,
    rel_type: u16,
    s: i64,
    p: i64,
    symbol: &str,
    section: &str,
) -> Result<u32> {
    let owner = (symbol, section);
    let branch = || -> Result<i64> {
        let delta = s - p;
        if delta % 4 != 0 {
            return Err(coff_error(format!(
                "{} against {symbol} in section {section} is not 4-byte aligned",
                arm64_reloc_name(rel_type)
            )));
        }
        Ok(delta / 4)
    };
    match rel_type {
        IMAGE_REL_ARM64_BRANCH26 => {
            arm64_put_imm(word, &ARM64_BRANCH26, branch()?, rel_type, owner)
        }
        IMAGE_REL_ARM64_BRANCH19 => {
            arm64_put_imm(word, &ARM64_BRANCH19, branch()?, rel_type, owner)
        }
        IMAGE_REL_ARM64_BRANCH14 => {
            arm64_put_imm(word, &ARM64_BRANCH14, branch()?, rel_type, owner)
        }
        IMAGE_REL_ARM64_PAGEBASE_REL21 => arm64_put_imm(
            word,
            &ARM64_ADR_PAGE,
            (s >> 12) - (p >> 12),
            rel_type,
            owner,
        ),
        IMAGE_REL_ARM64_PAGEOFFSET_12A => {
            arm64_put_imm(word, &ARM64_IMM12, s & 0xFFF, rel_type, owner)
        }
        IMAGE_REL_ARM64_PAGEOFFSET_12L => {
            let scale = arm64_ldst_scale(word);
            let offset = s & 0xFFF;
            if offset & ((1i64 << scale) - 1) != 0 {
                return Err(coff_error(format!(
                    "{} against {symbol} in section {section} is not aligned to the access size",
                    arm64_reloc_name(rel_type)
                )));
            }
            arm64_put_imm(word, &ARM64_IMM12, offset >> scale, rel_type, owner)
        }
        other => Err(coff_error(format!(
            "{} against {symbol} in section {section} is not implemented by weld",
            arm64_reloc_name(other)
        ))),
    }
}

/// Parse one COFF object. Sections that are not linked are `None`, so the
/// index of an entry is its section number minus one.
struct ParsedCoff<'a> {
    symbols: Vec<coff::Symbol>,
    sections: Vec<Option<CoffSection<'a>>>,
    deferred_error: Option<std::io::Error>,
    machine: u16,
}

fn parse_coff_object(object: usize, coff_data: &[u8]) -> Result<ParsedCoff<'_>> {
    let machine = coff::read_u16(coff_data, 0)
        .ok_or_else(|| coff_problem(coff::Problem::Truncated, object))?;
    if machine != MACHINE_AMD64 && machine != MACHINE_ARM64 {
        return Err(coff_error(format!(
            "object {object} has machine type {machine:#06x}; \
             only x86-64 and aarch64 objects can be linked"
        )));
    }
    let parsed = coff::parse(coff_data);
    let deferred = match parsed.problem {
        Some(coff::Problem::SymbolTable) if parsed.symbol_table_offset != 0 => {
            Some(coff_problem(coff::Problem::SymbolTable, object))
        }
        Some(problem) => return Err(coff_problem(problem, object)),
        None => None,
    };
    let comdat_aux = parsed.comdat_aux;
    let sections = parsed
        .sections
        .into_iter()
        .enumerate()
        .map(|(s, sec)| {
            if sec.skipped {
                return None;
            }
            let region = if sec.name == ".tls" || sec.name.starts_with(".tls$") {
                CoffRegion::Tls
            } else if is_exception_table(&sec.name) {
                CoffRegion::Pdata
            } else if sec.flags & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) != 0 {
                CoffRegion::Text
            } else if sec.flags & coff::IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0
                || sec.flags & IMAGE_SCN_MEM_WRITE != 0
            {
                CoffRegion::Writable
            } else {
                CoffRegion::ReadOnly
            };
            let comdat = (sec.flags & IMAGE_SCN_LNK_COMDAT != 0).then(|| {
                let (selection, assoc) = comdat_aux
                    .get(&(s + 1))
                    .copied()
                    .unwrap_or((IMAGE_COMDAT_SELECT_ANY, 0));
                CoffComdat { selection, assoc }
            });
            Some(CoffSection {
                object,
                name: sec.name,
                region,
                align: coff_section_align(sec.flags),
                size: sec.size,
                raw: sec.raw,
                relocs: sec.relocs,
                offset: 0,
                comdat,
                keep: true,
                uninit: sec.flags & coff::IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0,
            })
        })
        .collect();
    Ok(ParsedCoff {
        symbols: parsed.symbols,
        sections,
        deferred_error: deferred,
        machine,
    })
}

/// Link COFF objects and emit a PE32+ executable directly.
///
/// Code sections go to `.text`, read-only data to `.rdata`, writable and
/// uninitialized data to `.data`. Undefined externals get `jmp [iat]` thunks.
/// `entry` names the entry symbol; without it the entry is `main` or `_main`.
pub fn link_and_emit_pe_from_coffs(
    objects: &[&[u8]],
    entry: Option<&str>,
    out: &mut impl Write,
) -> Result<()> {
    let mut syms_of: Vec<Vec<coff::Symbol>> = Vec::with_capacity(objects.len());
    let mut slot_of: Vec<Vec<Option<usize>>> = Vec::with_capacity(objects.len());
    let mut sections: Vec<CoffSection> = Vec::new();
    let mut deferred_error: Option<std::io::Error> = None;
    let mut machine: Option<u16> = None;
    for (oi, coff) in objects.iter().enumerate() {
        let ParsedCoff {
            symbols: syms,
            sections: parsed,
            deferred_error: deferred,
            machine: object_machine,
        } = parse_coff_object(oi, coff)?;
        match machine {
            Some(first) if first != object_machine => {
                return Err(coff_error(format!(
                    "object {oi} has machine type {object_machine:#06x}, \
                     but an earlier object has {first:#06x}"
                )));
            }
            _ => machine = Some(object_machine),
        }
        deferred_error = deferred_error.or(deferred);
        let mut slots = Vec::with_capacity(parsed.len());
        for sec in parsed {
            slots.push(sec.map(|s| {
                sections.push(s);
                sections.len() - 1
            }));
        }
        syms_of.push(syms);
        slot_of.push(slots);
    }

    let mut comdat_key: Vec<Option<&str>> = vec![None; sections.len()];
    for (oi, syms) in syms_of.iter().enumerate() {
        for s in syms {
            if s.class != IMAGE_SYM_CLASS_EXTERNAL || s.section <= 0 {
                continue;
            }
            let Some(Some(k)) = slot_of[oi].get(s.section as usize - 1) else {
                continue;
            };
            if sections[*k].comdat.is_some() && comdat_key[*k].is_none() {
                comdat_key[*k] = Some(s.name.as_str());
            }
        }
    }
    let mut comdat_owner: HashMap<&str, usize> = HashMap::default();
    for k in 0..sections.len() {
        let (Some(comdat), Some(key)) = (sections[k].comdat, comdat_key[k]) else {
            continue;
        };
        if comdat.selection == IMAGE_COMDAT_SELECT_ASSOCIATIVE {
            continue;
        }
        match comdat_owner.get(key).copied() {
            None => {
                comdat_owner.insert(key, k);
            }
            Some(first) => {
                let mismatch = |what: &str| {
                    coff_error(format!(
                        "comdat {key} differs in {what} between objects {} and {}",
                        sections[first].object, sections[k].object
                    ))
                };
                match comdat.selection {
                    IMAGE_COMDAT_SELECT_NODUPLICATES => {
                        return Err(coff_duplicate_symbol(
                            key,
                            sections[first].object,
                            sections[k].object,
                        ));
                    }
                    IMAGE_COMDAT_SELECT_SAME_SIZE if sections[first].size != sections[k].size => {
                        return Err(mismatch("size"));
                    }
                    IMAGE_COMDAT_SELECT_EXACT_MATCH
                        if !comdat_bodies_match(
                            &sections[first],
                            &syms_of[sections[first].object],
                            &sections[k],
                            &syms_of[sections[k].object],
                        ) =>
                    {
                        return Err(coff_duplicate_symbol(
                            key,
                            sections[first].object,
                            sections[k].object,
                        ));
                    }
                    IMAGE_COMDAT_SELECT_LARGEST if sections[k].size > sections[first].size => {
                        sections[first].keep = false;
                        comdat_owner.insert(key, k);
                        continue;
                    }
                    _ => {}
                }
                sections[k].keep = false;
            }
        }
    }
    loop {
        let mut changed = false;
        for k in 0..sections.len() {
            let Some(CoffComdat {
                selection: IMAGE_COMDAT_SELECT_ASSOCIATIVE,
                assoc,
            }) = sections[k].comdat
            else {
                continue;
            };
            let target_kept = slot_of[sections[k].object]
                .get(assoc.wrapping_sub(1))
                .copied()
                .flatten()
                .is_some_and(|t| sections[t].keep);
            if sections[k].keep && !target_kept {
                sections[k].keep = false;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let mut defs: HashMap<&str, (CoffDef, usize)> = HashMap::default();
    for (oi, syms) in syms_of.iter().enumerate() {
        for s in syms {
            if s.class != IMAGE_SYM_CLASS_EXTERNAL || s.name.is_empty() {
                continue;
            }
            let def = if s.section > 0 {
                match slot_of[oi].get(s.section as usize - 1).copied().flatten() {
                    Some(k) if sections[k].keep => CoffDef::Section {
                        index: k,
                        value: s.value,
                    },
                    _ => continue,
                }
            } else if s.section == IMAGE_SYM_ABSOLUTE_SECTION {
                CoffDef::Absolute(s.value)
            } else {
                continue;
            };
            if let Some(&(_, first)) = defs.get(s.name.as_str()) {
                return Err(coff_duplicate_symbol(&s.name, first, oi));
            }
            defs.insert(s.name.as_str(), (def, oi));
        }
    }

    let mut referenced: HashSet<(usize, usize)> = HashSet::default();
    for sec in sections.iter().filter(|sec| sec.keep) {
        for &(_, sym_idx, _) in &sec.relocs {
            referenced.insert((sec.object, sym_idx as usize));
        }
    }
    let weak_defaults: HashSet<(usize, usize)> = syms_of
        .iter()
        .enumerate()
        .flat_map(|(oi, syms)| {
            syms.iter()
                .filter(|rec| rec.class == IMAGE_SYM_CLASS_WEAK_EXTERNAL)
                .map(move |rec| (oi, rec.tag))
        })
        .collect();
    let mut tls_refs = false;
    let mut undefined: Vec<&str> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::default();
    for (oi, syms) in syms_of.iter().enumerate() {
        for (ri, rec) in syms.iter().enumerate() {
            if rec.class == IMAGE_SYM_CLASS_WEAK_EXTERNAL && rec.num_aux == 0 {
                return Err(coff_error(format!(
                    "weak external {} in object {oi} has no default record",
                    rec.name
                )));
            }
            let s = if rec.class == IMAGE_SYM_CLASS_WEAK_EXTERNAL {
                if defs.contains_key(rec.name.as_str()) || !referenced.contains(&(oi, ri)) {
                    continue;
                }
                match syms.get(rec.tag) {
                    Some(default) => default,
                    None => continue,
                }
            } else if weak_defaults.contains(&(oi, ri)) && !referenced.contains(&(oi, ri)) {
                continue;
            } else {
                rec
            };
            if s.section != IMAGE_SYM_UNDEFINED_SECTION
                || s.class != IMAGE_SYM_CLASS_EXTERNAL
                || s.name.is_empty()
                || defs.contains_key(s.name.as_str())
            {
                continue;
            }
            if matches!(s.name.as_str(), TLS_INDEX_SYMBOL | TLS_USED_SYMBOL) {
                tls_refs = true;
                continue;
            }
            if s.value != 0 {
                return Err(coff_error(format!(
                    "common symbol {} is not supported",
                    s.name
                )));
            }
            let import = match s.name.strip_prefix(IMPORT_SYMBOL_PREFIX) {
                Some(base) => {
                    if defs.contains_key(base) {
                        return Err(coff_error(format!(
                            "{IMPORT_SYMBOL_PREFIX}{base} refers to a symbol defined in this link; \
                             pointer slots for local symbols are not supported"
                        )));
                    }
                    base
                }
                None => {
                    if s.name == CRT_MAIN_SYMBOL {
                        return Err(coff_error(format!(
                            "undefined {CRT_MAIN_SYMBOL}: it runs global constructors from libgcc and weld \
                             cannot supply it; link a runtime that defines it"
                        )));
                    }
                    s.name.as_str()
                }
            };
            if !is_kernel32_symbol(import) && !is_msvcrt_symbol(import) {
                return Err(coff_error(format!(
                    "undefined symbol {import} referenced from object {oi}: \
                     not defined by the inputs and not a known kernel32 or msvcrt export"
                )));
            }
            if seen.insert(import) {
                undefined.push(import);
            }
        }
    }
    let thunk_index: HashMap<&str, usize> =
        undefined.iter().enumerate().map(|(i, n)| (*n, i)).collect();

    if defs.contains_key(TLS_USED_SYMBOL) {
        return Err(coff_error(format!(
            "{TLS_USED_SYMBOL} is defined by an input; weld builds the TLS directory itself"
        )));
    }

    let mut region_len = [0usize; 5];
    for sec in sections
        .iter_mut()
        .filter(|sec| sec.keep && !matches!(sec.region, CoffRegion::Tls))
    {
        let r = sec.region as usize;
        let align = match sec.region {
            CoffRegion::Pdata => {
                // An assembler pads a section's raw data to its own alignment, so a
                // whole number of records can be followed by zeroes. Those are dropped,
                // which also keeps the next object's records on the record grid.
                let whole = sec.size - sec.size % PDATA_RECORD_SIZE;
                if sec.raw[whole..].iter().any(|&byte| byte != 0) {
                    return Err(coff_error(format!(
                        "{} in object {} is not a whole number of exception records",
                        sec.name, sec.object
                    )));
                }
                sec.size = whole;
                sec.raw = &sec.raw[..whole];
                1
            }
            _ => sec.align,
        };
        region_len[r] = align_up_usize(region_len[r], align);
        sec.offset = region_len[r];
        region_len[r] += sec.size;
    }

    if let Some(sec) = sections
        .iter()
        .find(|sec| sec.keep && matches!(sec.region, CoffRegion::Tls) && sec.align > 8)
    {
        return Err(coff_error(format!(
            "thread-local section {} in object {} is aligned above 8 bytes, which the TLS directory cannot express",
            sec.name, sec.object
        )));
    }
    let mut tls_init_len = 0usize;
    for uninit in [false, true] {
        for sec in sections
            .iter_mut()
            .filter(|sec| sec.keep && matches!(sec.region, CoffRegion::Tls) && sec.uninit == uninit)
        {
            let at = align_up_usize(region_len[CoffRegion::Tls as usize], sec.align);
            sec.offset = at;
            region_len[CoffRegion::Tls as usize] = at + sec.size;
        }
        if !uninit {
            tls_init_len = region_len[CoffRegion::Tls as usize];
        }
    }
    let tls_len = region_len[CoffRegion::Tls as usize];
    let has_tls = tls_refs || tls_len > 0;
    let tls_index_off = if has_tls && !defs.contains_key(TLS_INDEX_SYMBOL) {
        let off = align_up_usize(region_len[CoffRegion::Writable as usize], 4);
        region_len[CoffRegion::Writable as usize] = off + 4;
        Some(off)
    } else {
        None
    };

    let machine = machine.unwrap_or(MACHINE_AMD64);
    let arm64 = machine == MACHINE_ARM64;
    let thunk_size = if arm64 {
        ARM64_THUNK_SIZE
    } else {
        X86_THUNK_SIZE
    };

    let needs_main_stub = false;
    let thunks_off = if arm64 {
        align_up_usize(region_len[CoffRegion::Text as usize], 4)
    } else {
        region_len[CoffRegion::Text as usize]
    };
    let stub_off = thunks_off + undefined.len() * thunk_size;
    let text_size = stub_off + usize::from(needs_main_stub);

    let has_data = region_len[CoffRegion::Writable as usize] > 0;
    let has_pdata = region_len[CoffRegion::Pdata as usize] > 0;
    let has_base_relocs = has_tls
        || sections.iter().any(|sec| {
            sec.keep
                && sec.relocs.iter().any(|&(_, _, t)| {
                    if arm64 {
                        t == IMAGE_REL_ARM64_ADDR64
                    } else {
                        t == IMAGE_REL_AMD64_ADDR64 || t == IMAGE_REL_AMD64_ADDR32
                    }
                })
        });
    let n_regions = 2 + usize::from(has_data) + usize::from(has_pdata) + usize::from(tls_len > 0);
    let n_out_sections = n_regions + usize::from(has_base_relocs);
    let headers_raw: usize = SIZEOF_DOS_STUB
        + SIZEOF_PE_SIGNATURE
        + SIZEOF_COFF_HEADER
        + SIZEOF_OPTIONAL_HEADER as usize
        + n_out_sections * SIZEOF_SECTION_HEADER;
    let size_of_headers = align_up(headers_raw as u64, FILE_ALIGN) as u32;
    let text_rva = align_up(size_of_headers as u64, SECTION_ALIGN) as u32;
    let rdata_rva = text_rva + align_up(text_size as u64, SECTION_ALIGN) as u32;

    let kernel32_syms: Vec<&str> = undefined
        .iter()
        .copied()
        .filter(|n| is_kernel32_symbol(n))
        .collect();
    let has_exit_process = kernel32_syms.contains(&"ExitProcess");
    let mut k32_syms: Vec<&str> = if has_exit_process {
        kernel32_syms.clone()
    } else {
        let mut v = vec!["ExitProcess"];
        v.extend(kernel32_syms.iter().copied());
        v
    };
    k32_syms.dedup();

    let ucrt_syms: Vec<&str> = undefined
        .iter()
        .copied()
        .filter(|n| !is_kernel32_symbol(n))
        .collect();

    // msvcrt.dll exports plain `printf`; ucrtbase.dll does not.
    // msvcrt.dll exports plain `printf`; ucrtbase.dll does not.
    let crt_dll_name = "msvcrt.dll";
    let entries = if ucrt_syms.is_empty() {
        vec![ImportEntry {
            dll_name: "KERNEL32.DLL",
            symbols: k32_syms.iter().map(|&n| (0u16, n)).collect(),
        }]
    } else {
        vec![
            ImportEntry {
                dll_name: "KERNEL32.DLL",
                symbols: k32_syms.iter().map(|&n| (0u16, n)).collect(),
            },
            ImportEntry {
                dll_name: crt_dll_name,
                symbols: ucrt_syms.iter().map(|&n| (0u16, n)).collect(),
            },
        ]
    };

    let rdata_import_off = align_up_usize(region_len[CoffRegion::ReadOnly as usize], 16);
    let (import_bytes, idt_off, iat_rel_off, idt_sz, iat_sz) =
        build_import_section(rdata_rva as u64 + rdata_import_off as u64, &entries);
    let import_base_rva = rdata_rva + rdata_import_off as u32;
    let import_dir_rva = import_base_rva + idt_off;
    let iat_rva = import_base_rva + iat_rel_off;

    // IAT structure: all entries for all DLLs, each 8 bytes, null-terminated per DLL.
    // Within the IAT region, entries are ordered: k32_syms (with null), then ucrt_syms (with null).
    fn iat_entry_va(
        rdata_vaddr: u64,
        iat_rel_off: u32,
        dll_idx: usize,
        sym_idx_in_dll: usize,
        dll_sym_counts: &[usize],
    ) -> u64 {
        let mut base_entry = 0usize;
        for count in dll_sym_counts.iter().take(dll_idx) {
            base_entry += count + 1;
        }
        base_entry += sym_idx_in_dll;
        rdata_vaddr + iat_rel_off as u64 + base_entry as u64 * 8
    }

    let dll_sym_counts = vec![k32_syms.len(), ucrt_syms.len()];
    let import_va = IMAGE_BASE + import_base_rva as u64;
    let mut sym_iat_va: HashMap<&str, u64> = HashMap::default();
    for (i, name) in k32_syms.iter().enumerate() {
        sym_iat_va.insert(
            *name,
            iat_entry_va(import_va, iat_rel_off, 0, i, &dll_sym_counts),
        );
    }
    for (i, name) in ucrt_syms.iter().enumerate() {
        sym_iat_va.insert(
            *name,
            iat_entry_va(import_va, iat_rel_off, 1, i, &dll_sym_counts),
        );
    }

    let tls_dir_off = align_up_usize(rdata_import_off + import_bytes.len(), 8);
    let rdata_len = if has_tls {
        tls_dir_off + TLS_DIRECTORY_SIZE
    } else {
        rdata_import_off + import_bytes.len()
    };
    let data_rva = rdata_rva + align_up(rdata_len as u64, SECTION_ALIGN) as u32;
    let tls_rva = data_rva
        + align_up(
            region_len[CoffRegion::Writable as usize] as u64,
            SECTION_ALIGN,
        ) as u32;
    let pdata_rva = tls_rva + align_up(tls_len as u64, SECTION_ALIGN) as u32;
    let region_rva = [text_rva, rdata_rva, data_rva, pdata_rva, tls_rva];
    let region_size = [
        text_size,
        rdata_len,
        region_len[CoffRegion::Writable as usize],
        region_len[CoffRegion::Pdata as usize],
        tls_len,
    ];
    let region_base = [
        0usize,
        (rdata_rva - text_rva) as usize,
        (data_rva - text_rva) as usize,
        (pdata_rva - text_rva) as usize,
        (tls_rva - text_rva) as usize,
    ];
    let mut blob = vec![0u8; region_base[3] + region_size[3]];

    for sec in sections
        .iter()
        .filter(|sec| sec.keep && !sec.raw.is_empty())
    {
        let at = region_base[sec.region as usize] + sec.offset;
        blob[at..at + sec.raw.len()].copy_from_slice(sec.raw);
    }
    let import_at = region_base[1] + rdata_import_off;
    blob[import_at..import_at + import_bytes.len()].copy_from_slice(&import_bytes);

    let thunk_va = |i: usize| IMAGE_BASE + text_rva as u64 + (thunks_off + i * thunk_size) as u64;
    for (i, name) in undefined.iter().enumerate() {
        let at = thunks_off + i * thunk_size;
        let iat_va = *sym_iat_va
            .get(name)
            .ok_or_else(|| coff_error(format!("no import slot for {name}")))?;
        if arm64 {
            let words = arm64_import_thunk(iat_va, thunk_va(i), name)?;
            for (w, word) in words.iter().enumerate() {
                blob[at + w * 4..at + w * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
        } else {
            let end_va = thunk_va(i) + X86_THUNK_SIZE as u64;
            blob[at..at + 2].copy_from_slice(&[0xFF, 0x25]);
            blob[at + 2..at + 6].copy_from_slice(&rel32(iat_va, end_va)?.to_le_bytes());
        }
    }
    if needs_main_stub {
        blob[stub_off] = COFF_RET;
    }

    let sec_rva = |sec: &CoffSection| region_rva[sec.region as usize] + sec.offset as u32;
    let def_va = |def: CoffDef| -> i64 {
        match def {
            CoffDef::Section { index, value } => {
                IMAGE_BASE as i64 + i64::from(sec_rva(&sections[index])) + i64::from(value)
            }
            CoffDef::Absolute(v) => i64::from(v),
        }
    };
    let tls_dir_rva = rdata_rva + tls_dir_off as u32;
    let tls_dir_va = IMAGE_BASE + u64::from(tls_dir_rva);
    let tls_va = IMAGE_BASE + u64::from(tls_rva);
    let tls_index_va: u64 = match defs.get(TLS_INDEX_SYMBOL) {
        Some(&(def @ CoffDef::Section { .. }, _)) => def_va(def) as u64,
        Some(_) => {
            return Err(coff_error(format!(
                "{TLS_INDEX_SYMBOL} must be a data symbol"
            )));
        }
        None => IMAGE_BASE + u64::from(data_rva) + tls_index_off.unwrap_or(0) as u64,
    };
    let is_undefined_external = |sym: &coff::Symbol| {
        sym.section == IMAGE_SYM_UNDEFINED_SECTION
            && sym.class == IMAGE_SYM_CLASS_EXTERNAL
            && !sym.name.is_empty()
    };
    // The flag is true when the value is an image address, which needs a base
    // relocation if it is stored in memory. Absolute symbols are not relocated.
    let resolve =
        |oi: usize, sym_idx: usize, allow_thunk: bool, owner: &str| -> Result<(i64, bool)> {
            let missing =
                |idx: usize| coff_error(format!("{owner} names missing symbol index {idx}"));
            let mut sym_idx = sym_idx;
            let mut sym = syms_of[oi].get(sym_idx).ok_or_else(|| missing(sym_idx))?;
            let mut hops = 0usize;
            while sym.class == IMAGE_SYM_CLASS_WEAK_EXTERNAL {
                if let Some(&(def, _)) = defs.get(sym.name.as_str()) {
                    return Ok(match def {
                        CoffDef::Section { .. } => (def_va(def), true),
                        CoffDef::Absolute(_) => (def_va(def), false),
                    });
                }
                hops += 1;
                if hops > syms_of[oi].len() {
                    return Err(coff_error(format!(
                        "weak external {} forms a cycle",
                        sym.name
                    )));
                }
                sym_idx = sym.tag;
                sym = syms_of[oi].get(sym_idx).ok_or_else(|| missing(sym_idx))?;
            }
            if sym.section > 0 {
                if let Some(k) = slot_of[oi]
                    .get(sym.section as usize - 1)
                    .copied()
                    .flatten()
                    .filter(|&k| sections[k].keep)
                {
                    let va =
                        IMAGE_BASE as i64 + i64::from(sec_rva(&sections[k])) + i64::from(sym.value);
                    return Ok((va, true));
                }
            } else if sym.section == IMAGE_SYM_ABSOLUTE_SECTION {
                return Ok((i64::from(sym.value), false));
            }
            if sym.class == IMAGE_SYM_CLASS_EXTERNAL
                && let Some(&(def, _)) = defs.get(sym.name.as_str())
            {
                return Ok(match def {
                    CoffDef::Section { .. } => (def_va(def), true),
                    CoffDef::Absolute(_) => (def_va(def), false),
                });
            }
            if is_undefined_external(sym) {
                if sym.name == TLS_INDEX_SYMBOL {
                    return Ok((tls_index_va as i64, true));
                }
                if sym.name == TLS_USED_SYMBOL {
                    return Ok((tls_dir_va as i64, true));
                }
                if let Some(base) = sym.name.strip_prefix(IMPORT_SYMBOL_PREFIX) {
                    return sym_iat_va
                        .get(base)
                        .map(|&va| (va as i64, true))
                        .ok_or_else(|| coff_error(format!("no import slot for {base}")));
                }
                if allow_thunk && let Some(&i) = thunk_index.get(sym.name.as_str()) {
                    return Ok((thunk_va(i) as i64, true));
                }
                return Err(coff_error(format!(
                    "undefined symbol {} referenced from {owner} as data or a function address; \
                 import it through {IMPORT_SYMBOL_PREFIX}{}",
                    sym.name, sym.name
                )));
            }
            Err(coff_error(format!(
                "unresolved symbol {} referenced from {owner}",
                sym.name
            )))
        };

    let mut base_relocs: Vec<(u32, u16)> = Vec::new();
    for sec in sections.iter().filter(|sec| sec.keep) {
        let base = region_base[sec.region as usize] + sec.offset;
        for &(vaddr, sym_idx, rel_type) in &sec.relocs {
            if rel_type == IMAGE_REL_AMD64_ABSOLUTE {
                continue;
            }
            let wide = if arm64 {
                rel_type == IMAGE_REL_ARM64_ADDR64
            } else {
                rel_type == IMAGE_REL_AMD64_ADDR64
            };
            let width = if wide { 8 } else { 4 };
            let field = vaddr as usize;
            if field + width > sec.size {
                return Err(coff_error(format!(
                    "relocation at {field:#x} lies outside section {}",
                    sec.name
                )));
            }
            let at = base + field;
            let p_va = IMAGE_BASE as i64 + i64::from(text_rva) + at as i64;
            let site_rva = text_rva + at as u32;
            let addend = if width == 8 {
                i64::from_le_bytes(blob[at..at + 8].try_into().unwrap())
            } else {
                i64::from(i32::from_le_bytes(blob[at..at + 4].try_into().unwrap()))
            };
            let object = sec.object;
            let call_site = if arm64 {
                rel_type == IMAGE_REL_ARM64_BRANCH26
            } else {
                matches!(rel_type, IMAGE_REL_AMD64_REL32..=IMAGE_REL_AMD64_REL32_5)
                    && matches!(
                        field.checked_sub(1).and_then(|p| sec.raw.get(p)),
                        Some(&(OPCODE_CALL_REL32 | OPCODE_JMP_REL32))
                    )
            };
            let function_sym = syms_of[object]
                .get(sym_idx as usize)
                .is_some_and(|s| s.typ & 0xF0 == IMAGE_SYM_DTYPE_FUNCTION);
            let allow_thunk = call_site || function_sym;
            if arm64 {
                let symbol = syms_of[object]
                    .get(sym_idx as usize)
                    .map(|s| s.name.clone())
                    .unwrap_or_default();
                match rel_type {
                    IMAGE_REL_ARM64_ADDR64 => {
                        let (target, image_addr) =
                            resolve(object, sym_idx as usize, allow_thunk, &sec.name)?;
                        let v = (target + addend) as u64;
                        blob[at..at + 8].copy_from_slice(&v.to_le_bytes());
                        if image_addr {
                            base_relocs.push((site_rva, IMAGE_REL_BASED_DIR64));
                        }
                    }
                    IMAGE_REL_ARM64_ADDR32 => {
                        return Err(coff_error(format!(
                            "ADDR32 relocation in {}: use ADDR32NB or ADDR64",
                            sec.name
                        )));
                    }
                    _ => {
                        let (target, _) =
                            resolve(object, sym_idx as usize, allow_thunk, &sec.name)?;
                        let word = u32::from_le_bytes(blob[at..at + 4].try_into().unwrap());
                        let word = arm64_apply_instruction(
                            word, rel_type, target, p_va, &symbol, &sec.name,
                        )?;
                        blob[at..at + 4].copy_from_slice(&word.to_le_bytes());
                    }
                }
                continue;
            }
            match rel_type {
                IMAGE_REL_AMD64_REL32..=IMAGE_REL_AMD64_REL32_5 => {
                    let (target, _) = resolve(object, sym_idx as usize, allow_thunk, &sec.name)?;
                    let trailing = i64::from(rel_type - IMAGE_REL_AMD64_REL32);
                    let v = target + addend - (p_va + 4 + trailing);
                    let v = i32::try_from(v)
                        .map_err(|_| coff_error(format!("REL32 out of range in {}", sec.name)))?;
                    blob[at..at + 4].copy_from_slice(&v.to_le_bytes());
                }
                IMAGE_REL_AMD64_ADDR64 => {
                    let (target, image_addr) =
                        resolve(object, sym_idx as usize, allow_thunk, &sec.name)?;
                    let v = (target + addend) as u64;
                    blob[at..at + 8].copy_from_slice(&v.to_le_bytes());
                    if image_addr {
                        base_relocs.push((site_rva, IMAGE_REL_BASED_DIR64));
                    }
                }
                IMAGE_REL_AMD64_SECREL => {
                    let (target, _) = resolve(object, sym_idx as usize, false, &sec.name)?;
                    let offset = target + addend - tls_va as i64;
                    if offset < 0 || offset >= tls_len as i64 {
                        return Err(coff_error(format!(
                            "SECREL in {} names a symbol outside .tls",
                            sec.name
                        )));
                    }
                    blob[at..at + 4].copy_from_slice(&(offset as u32).to_le_bytes());
                }
                IMAGE_REL_AMD64_ADDR32 if is_exception_table(&sec.name) => {
                    // Every field of a RUNTIME_FUNCTION is an image-relative address, so
                    // an absolute 32-bit one would name nothing the unwinder can use. An
                    // assembler without ADDR32NB is taken at its intent here.
                    log::debug!(
                        "reading ADDR32 at {site_rva:#x} in {} as image-relative",
                        sec.name
                    );
                    let (target, _) = resolve(object, sym_idx as usize, false, &sec.name)?;
                    write_rva(&mut blob[at..at + 4], target + addend, &sec.name)?;
                }
                IMAGE_REL_AMD64_ADDR32 => {
                    // The loader adds its base delta to these 32 bits only, so the stored
                    // value is a usable pointer only while the image stays below 4 GiB.
                    // ASLR does not guarantee that, and MSVC does not emit ADDR32 for x64.
                    return Err(coff_error(format!(
                        "ADDR32 relocation in {}: use ADDR32NB or ADDR64",
                        sec.name
                    )));
                }
                IMAGE_REL_AMD64_ADDR32NB => {
                    let (target, _) = resolve(object, sym_idx as usize, false, &sec.name)?;
                    write_rva(&mut blob[at..at + 4], target + addend, &sec.name)?;
                }
                other => {
                    return Err(coff_error(format!(
                        "unsupported relocation type {other:#06x} in section {}",
                        sec.name
                    )));
                }
            }
        }
    }

    let mut pdata_used = region_size[3];
    if has_pdata {
        let at = region_base[3];
        let (chunks, _) = blob[at..at + region_size[3]].as_chunks::<PDATA_RECORD_SIZE>();
        let mut records: Vec<[u8; PDATA_RECORD_SIZE]> = chunks.to_vec();
        // An object pads its section to a raw alignment, so the tail can hold records
        // that name nothing. Those sort last and stay outside the directory, because
        // Windows binary-searches the table and reads a record for every byte it covers.
        records.sort_by_key(|rec| {
            let start = u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]);
            (rec.iter().all(|&byte| byte == 0), start)
        });
        pdata_used = records
            .iter()
            .filter(|rec| rec.iter().any(|&byte| byte != 0))
            .count()
            * PDATA_RECORD_SIZE;
        for (i, rec) in records.iter().enumerate() {
            let off = at + i * PDATA_RECORD_SIZE;
            blob[off..off + PDATA_RECORD_SIZE].copy_from_slice(rec);
        }
    }

    if has_tls {
        let mut dir = [0u8; TLS_DIRECTORY_SIZE];
        dir[0..8].copy_from_slice(&tls_va.to_le_bytes());
        dir[8..16].copy_from_slice(&(tls_va + tls_init_len as u64).to_le_bytes());
        dir[16..24].copy_from_slice(&tls_index_va.to_le_bytes());
        dir[32..36].copy_from_slice(&((tls_len - tls_init_len) as u32).to_le_bytes());
        let dir_at = region_base[1] + tls_dir_off;
        blob[dir_at..dir_at + TLS_DIRECTORY_SIZE].copy_from_slice(&dir);
        for field in [0u32, 8, 16] {
            base_relocs.push((tls_dir_rva + field, IMAGE_REL_BASED_DIR64));
        }
    }

    let find_defined = |wanted: &str| {
        syms_of.iter().enumerate().find_map(|(oi, syms)| {
            syms.iter()
                .position(|s| s.section > 0 && s.name == wanted)
                .map(|i| (oi, i))
        })
    };
    let entry_sym = match entry {
        Some(name) => find_defined(name)
            .ok_or_else(|| coff_error(format!("entry symbol {name} is not defined")))?,
        None => ["main", "_main"]
            .iter()
            .find_map(|name| find_defined(name))
            .ok_or_else(|| {
                coff_error("no entry point: define main or _main, or pass -e SYMBOL".into())
            })?,
    };
    let entry_va = resolve(entry_sym.0, entry_sym.1, false, "entry point")?.0 as u64;

    let mut pe_sections = vec![
        PeSection::new(
            ".text",
            blob[..text_size].to_vec(),
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        ),
        PeSection::new(
            ".rdata",
            blob[region_base[1]..region_base[1] + rdata_len].to_vec(),
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        ),
    ];
    let mut sec_rvas: Vec<u32> = vec![text_rva, rdata_rva];
    if has_data {
        let at = region_base[2];
        pe_sections.push(PeSection::new(
            ".data",
            blob[at..at + region_size[2]].to_vec(),
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        ));
        sec_rvas.push(data_rva);
    }
    if tls_len > 0 {
        let at = region_base[4];
        pe_sections.push(PeSection::new(
            ".tls",
            blob[at..at + tls_len].to_vec(),
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        ));
        sec_rvas.push(tls_rva);
    }
    if has_pdata {
        let at = region_base[3];
        let kept = if pdata_used > 0 {
            pdata_used
        } else {
            region_size[3]
        };
        pe_sections.push(PeSection::new(
            ".pdata",
            blob[at..at + kept].to_vec(),
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        ));
        sec_rvas.push(pdata_rva);
    }
    let tls_dir = if has_tls {
        (tls_dir_rva, TLS_DIRECTORY_SIZE as u32)
    } else {
        (0, 0)
    };
    let pdata_dir = if has_pdata && pdata_used > 0 {
        (pdata_rva, pdata_used as u32)
    } else {
        (0, 0)
    };
    let regions_end = pdata_rva as u64 + align_up(region_size[3] as u64, SECTION_ALIGN);
    let mut image_end = regions_end;
    let mut base_reloc_dir = (0u32, 0u32);
    if !base_relocs.is_empty() {
        let bytes = build_base_relocs(&base_relocs);
        base_reloc_dir = (regions_end as u32, bytes.len() as u32);
        sec_rvas.push(regions_end as u32);
        image_end += align_up(bytes.len() as u64, SECTION_ALIGN);
        pe_sections.push(PeSection::new(
            ".reloc",
            bytes,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE,
        ));
    }
    let mut sec_file_offs = Vec::with_capacity(pe_sections.len());
    let mut file_off = size_of_headers;
    for sec in &pe_sections {
        sec_file_offs.push(file_off);
        file_off += sec.raw_size();
    }
    let size_of_image = align_up(image_end, SECTION_ALIGN) as u32;
    if let Some(error) = deferred_error {
        return Err(error);
    }

    emit_pe_raw(
        out,
        machine,
        &pe_sections,
        &sec_rvas,
        &sec_file_offs,
        size_of_headers,
        size_of_image,
        entry_va,
        import_dir_rva,
        iat_rva,
        idt_sz,
        iat_sz,
        base_reloc_dir,
        pdata_dir,
        tls_dir,
    )
}

#[allow(clippy::too_many_arguments)]
fn emit_pe_raw(
    out: &mut impl Write,
    machine: u16,
    sections: &[PeSection],
    sec_rvas: &[u32],
    sec_file_offs: &[u32],
    size_of_headers: u32,
    size_of_image: u32,
    entry_va: u64,
    import_dir_rva: u32,
    iat_rva: u32,
    idt_size: u32,
    iat_size: u32,
    base_reloc_dir: (u32, u32),
    pdata_dir: (u32, u32),
    tls_dir: (u32, u32),
) -> Result<()> {
    let mut dos = [0u8; SIZEOF_DOS_STUB];
    dos[0] = b'M';
    dos[1] = b'Z';
    let e_lfanew = SIZEOF_DOS_STUB as u32;
    dos[60..64].copy_from_slice(&e_lfanew.to_le_bytes());
    out.write_all(&dos)?;

    out.write_all(b"PE\0\0")?;

    let n_sec = sections.len() as u16;
    let mut coff_hdr = [0u8; SIZEOF_COFF_HEADER];
    coff_hdr[0..2].copy_from_slice(&machine.to_le_bytes());
    coff_hdr[2..4].copy_from_slice(&n_sec.to_le_bytes());
    coff_hdr[16..18].copy_from_slice(&SIZEOF_OPTIONAL_HEADER.to_le_bytes());
    let characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    coff_hdr[18..20].copy_from_slice(&characteristics.to_le_bytes());
    out.write_all(&coff_hdr)?;

    let mut opt = [0u8; SIZEOF_OPTIONAL_HEADER as usize];
    let entry_rva = (entry_va - IMAGE_BASE) as u32;
    let text_rva = sec_rvas[0];
    write_u16(&mut opt, 0, IMAGE_OPTIONAL_HDR64_MAGIC);
    let raw_sum = |flag: u32| -> u32 {
        sections
            .iter()
            .filter(|sec| sec.characteristics & flag != 0)
            .map(|sec| sec.raw_size())
            .sum()
    };
    write_u32_at_off(&mut opt, 4, raw_sum(IMAGE_SCN_CNT_CODE));
    write_u32_at_off(&mut opt, 8, raw_sum(IMAGE_SCN_CNT_INITIALIZED_DATA));
    write_u32_at_off(&mut opt, 16, entry_rva);
    write_u32_at_off(&mut opt, 20, text_rva);
    write_u64_at_off(&mut opt, 24, IMAGE_BASE);
    write_u32_at_off(&mut opt, 32, SECTION_ALIGN as u32);
    write_u32_at_off(&mut opt, 36, FILE_ALIGN as u32);
    write_u16_at_off(&mut opt, 40, 6);
    write_u16_at_off(&mut opt, 44, 0);
    write_u16_at_off(&mut opt, 48, 6);
    write_u32_at_off(&mut opt, 56, size_of_image);
    write_u32_at_off(&mut opt, 60, size_of_headers);
    write_u16_at_off(&mut opt, 68, IMAGE_SUBSYSTEM_WINDOWS_CUI);
    let dll_chars = IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        | IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE;
    write_u16_at_off(&mut opt, 70, dll_chars);
    write_u64_at_off(&mut opt, 72, 0x100000);
    write_u64_at_off(&mut opt, 80, 0x1000);
    write_u64_at_off(&mut opt, 88, 0x100000);
    write_u64_at_off(&mut opt, 96, 0x1000);
    write_u32_at_off(&mut opt, 108, NUM_DATA_DIRS);
    // Data directories start at offset 112. Each entry is 8 bytes (RVA + Size).
    // Index 1 = Import Directory Table, index 12 = Import Address Table.
    write_u32_at_off(&mut opt, 112 + 8, import_dir_rva);
    write_u32_at_off(&mut opt, 112 + 8 + 4, idt_size);
    write_u32_at_off(&mut opt, 112 + 12 * 8, iat_rva);
    write_u32_at_off(&mut opt, 112 + 12 * 8 + 4, iat_size);
    write_u32_at_off(&mut opt, 112 + DATA_DIR_BASE_RELOC * 8, base_reloc_dir.0);
    write_u32_at_off(
        &mut opt,
        112 + DATA_DIR_BASE_RELOC * 8 + 4,
        base_reloc_dir.1,
    );
    write_u32_at_off(&mut opt, 112 + DATA_DIR_EXCEPTION * 8, pdata_dir.0);
    write_u32_at_off(&mut opt, 112 + DATA_DIR_EXCEPTION * 8 + 4, pdata_dir.1);
    write_u32_at_off(&mut opt, 112 + DATA_DIR_TLS * 8, tls_dir.0);
    write_u32_at_off(&mut opt, 112 + DATA_DIR_TLS * 8 + 4, tls_dir.1);
    out.write_all(&opt)?;

    for (i, sec) in sections.iter().enumerate() {
        let mut sh = [0u8; SIZEOF_SECTION_HEADER];
        sh[0..8].copy_from_slice(&sec.name);
        let vsize = sec.data.len() as u32;
        let raw_size = align_up(vsize as u64, FILE_ALIGN) as u32;
        sh[8..12].copy_from_slice(&vsize.to_le_bytes());
        sh[12..16].copy_from_slice(&sec_rvas[i].to_le_bytes());
        sh[16..20].copy_from_slice(&raw_size.to_le_bytes());
        sh[20..24].copy_from_slice(&sec_file_offs[i].to_le_bytes());
        sh[36..40].copy_from_slice(&sec.characteristics.to_le_bytes());
        out.write_all(&sh)?;
    }

    let headers_written = SIZEOF_DOS_STUB
        + SIZEOF_PE_SIGNATURE
        + SIZEOF_COFF_HEADER
        + SIZEOF_OPTIONAL_HEADER as usize
        + sections.len() * SIZEOF_SECTION_HEADER;
    let pad = size_of_headers as usize - headers_written;
    out.write_all(&vec![0u8; pad])?;

    for sec in sections {
        let raw_size = align_up(sec.data.len() as u64, FILE_ALIGN) as usize;
        out.write_all(&sec.data)?;
        out.write_all(&vec![0u8; raw_size - sec.data.len()])?;
    }

    Ok(())
}

fn write_u32_at_off(buf: &mut [u8], off: usize, v: u32) {
    if off + 4 <= buf.len() {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
}
fn write_u16_at_off(buf: &mut [u8], off: usize, v: u16) {
    if off + 2 <= buf.len() {
        buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
}
fn write_u64_at_off(buf: &mut [u8], off: usize, v: u64) {
    if off + 8 <= buf.len() {
        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
}

fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coff::{
        IMAGE_SYM_CLASS_STATIC, RELOC_SIZE as SIZEOF_COFF_RELOC,
        SECTION_HEADER_SIZE as SIZEOF_COFF_SECTION_HEADER,
    };

    fn entry_rva(out: &[u8]) -> u32 {
        let e_lfanew = le_u32(out, 0x3C) as usize;
        le_u32(out, e_lfanew + 4 + 20 + 16)
    }

    fn two_function_object() -> Vec<u8> {
        let body = [0xC3, 0xC3];
        coff_object(
            &[TestSection {
                name: ".text",
                flags: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
                data: &body,
                relocs: &[],
                selection: 0,
                assoc: 0,
            }],
            &[
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                ("alt", 1, IMAGE_SYM_CLASS_EXTERNAL, 1),
            ],
        )
    }

    #[test]
    fn test_coff_entry_defaults_to_main() {
        let obj = two_function_object();
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).expect("links");
        let main_rva = entry_rva(&out);
        assert_eq!(main_rva as u64 % SECTION_ALIGN, 0);

        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], Some("alt"), &mut out).expect("links");
        assert_eq!(entry_rva(&out), main_rva + 1, "-e alt must enter at alt");
    }

    #[test]
    fn test_coff_entry_missing_symbol_is_an_error() {
        let obj = two_function_object();
        let mut out = Vec::new();
        let error = link_and_emit_pe_from_coffs(&[obj.as_slice()], Some("nope"), &mut out)
            .expect_err("undefined -e symbol must fail");
        assert!(error.to_string().contains("nope"), "{error}");

        let no_main = coff_object(
            &[TestSection {
                name: ".text",
                flags: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
                data: &[0xC3],
                relocs: &[],
                selection: 0,
                assoc: 0,
            }],
            &[("helper", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        let mut out = Vec::new();
        let error = link_and_emit_pe_from_coffs(&[no_main.as_slice()], None, &mut out)
            .expect_err("no main must fail, not fall back to .text");
        assert!(error.to_string().contains("no entry point"), "{error}");
    }

    struct TestSection<'a> {
        name: &'a str,
        flags: u32,
        data: &'a [u8],
        relocs: &'a [(u32, u32, u16)],
        selection: u8,
        assoc: u16,
    }

    fn push_test_name(o: &mut Vec<u8>, name: &str) {
        let mut bytes = [0u8; 8];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        o.extend_from_slice(&bytes);
    }

    /// Names longer than eight bytes are appended to the string table, whose
    /// first byte is at `base` from the start of the table.
    fn push_symbol_name(o: &mut Vec<u8>, name: &str, extra: &mut Vec<u8>, base: usize) {
        if name.len() <= 8 {
            push_test_name(o, name);
        } else {
            o.extend_from_slice(&[0u8; 4]);
            o.extend_from_slice(&((base + extra.len()) as u32).to_le_bytes());
            extra.extend_from_slice(name.as_bytes());
            extra.push(0);
        }
    }

    /// Builds a COFF object. Each section gets a section symbol with one
    /// auxiliary record; `symbols` follow them, so the first of them has
    /// index `2 * sections.len()`.
    fn coff_object(sections: &[TestSection], symbols: &[(&str, i16, u8, u32)]) -> Vec<u8> {
        coff_object_with_strtab(sections, symbols, &[])
    }

    /// `strtab_tail` is appended after the 4-byte string table size.
    fn coff_object_with_strtab(
        sections: &[TestSection],
        symbols: &[(&str, i16, u8, u32)],
        strtab_tail: &[u8],
    ) -> Vec<u8> {
        let n = sections.len();
        let mut at = 20 + n * SIZEOF_COFF_SECTION_HEADER;
        let mut raw_ptrs = Vec::new();
        for s in sections {
            raw_ptrs.push(at);
            at += s.data.len();
        }
        let mut reloc_ptrs = Vec::new();
        for s in sections {
            reloc_ptrs.push(at);
            at += s.relocs.len() * SIZEOF_COFF_RELOC;
        }
        let mut o = Vec::new();
        o.extend_from_slice(&MACHINE_AMD64.to_le_bytes());
        o.extend_from_slice(&(n as u16).to_le_bytes());
        o.extend_from_slice(&0u32.to_le_bytes());
        o.extend_from_slice(&(at as u32).to_le_bytes());
        let n_records: usize = symbols
            .iter()
            .map(|&(_, _, class, _)| {
                if class == IMAGE_SYM_CLASS_WEAK_EXTERNAL {
                    2
                } else {
                    1
                }
            })
            .sum();
        o.extend_from_slice(&((2 * n + n_records) as u32).to_le_bytes());
        o.extend_from_slice(&0u16.to_le_bytes());
        o.extend_from_slice(&0u16.to_le_bytes());
        for (i, s) in sections.iter().enumerate() {
            push_test_name(&mut o, s.name);
            o.extend_from_slice(&0u32.to_le_bytes());
            o.extend_from_slice(&0u32.to_le_bytes());
            o.extend_from_slice(&(s.data.len() as u32).to_le_bytes());
            o.extend_from_slice(&(raw_ptrs[i] as u32).to_le_bytes());
            o.extend_from_slice(&(reloc_ptrs[i] as u32).to_le_bytes());
            o.extend_from_slice(&0u32.to_le_bytes());
            o.extend_from_slice(&(s.relocs.len() as u16).to_le_bytes());
            o.extend_from_slice(&0u16.to_le_bytes());
            o.extend_from_slice(&s.flags.to_le_bytes());
        }
        for s in sections {
            o.extend_from_slice(s.data);
        }
        for s in sections {
            for &(vaddr, sym, rel_type) in s.relocs {
                o.extend_from_slice(&vaddr.to_le_bytes());
                o.extend_from_slice(&sym.to_le_bytes());
                o.extend_from_slice(&rel_type.to_le_bytes());
            }
        }
        for (i, s) in sections.iter().enumerate() {
            push_test_name(&mut o, s.name);
            o.extend_from_slice(&0u32.to_le_bytes());
            o.extend_from_slice(&((i + 1) as i16).to_le_bytes());
            o.extend_from_slice(&0u16.to_le_bytes());
            o.push(IMAGE_SYM_CLASS_STATIC);
            o.push(1);
            o.extend_from_slice(&(s.data.len() as u32).to_le_bytes());
            o.extend_from_slice(&(s.relocs.len() as u16).to_le_bytes());
            o.extend_from_slice(&0u16.to_le_bytes());
            o.extend_from_slice(&0u32.to_le_bytes());
            o.extend_from_slice(&s.assoc.to_le_bytes());
            o.push(s.selection);
            o.extend_from_slice(&[0u8; 3]);
        }
        let mut extra_strtab = Vec::new();
        for &(name, section, class, value) in symbols {
            // For a weak external the value is the TagIndex of its default symbol,
            // which is stored in the auxiliary record.
            let weak = class == IMAGE_SYM_CLASS_WEAK_EXTERNAL;
            push_symbol_name(&mut o, name, &mut extra_strtab, 4 + strtab_tail.len());
            o.extend_from_slice(&(if weak { 0 } else { value }).to_le_bytes());
            o.extend_from_slice(&section.to_le_bytes());
            o.extend_from_slice(&0u16.to_le_bytes());
            o.push(class);
            o.push(u8::from(weak));
            if weak {
                o.extend_from_slice(&value.to_le_bytes());
                o.extend_from_slice(&3u32.to_le_bytes());
                o.extend_from_slice(&[0u8; 10]);
            }
        }
        o.extend_from_slice(&((4 + strtab_tail.len() + extra_strtab.len()) as u32).to_le_bytes());
        o.extend_from_slice(strtab_tail);
        o.extend_from_slice(&extra_strtab);
        o
    }

    fn pe_section_vsize(out: &[u8], index: usize) -> u32 {
        let e_lfanew = u32::from_le_bytes(out[0x3C..0x40].try_into().unwrap()) as usize;
        let at = e_lfanew
            + 4
            + SIZEOF_COFF_HEADER
            + SIZEOF_OPTIONAL_HEADER as usize
            + index * SIZEOF_SECTION_HEADER;
        u32::from_le_bytes(out[at + 8..at + 12].try_into().unwrap())
    }

    const TEXT_FLAGS: u32 = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    const COMDAT_TEXT_FLAGS: u32 = TEXT_FLAGS | IMAGE_SCN_LNK_COMDAT;

    fn text_section<'a>(data: &'a [u8], relocs: &'a [(u32, u32, u16)]) -> TestSection<'a> {
        TestSection {
            name: ".text",
            flags: TEXT_FLAGS,
            data,
            relocs,
            selection: 0,
            assoc: 0,
        }
    }

    #[test]
    fn test_coff_relocation_into_rdata_resolves() {
        let text = [0x48, 0x8D, 0x0D, 0, 0, 0, 0, 0xC3];
        let relocs = [(3, 2, IMAGE_REL_AMD64_REL32)];
        let coff = coff_object(
            &[
                text_section(&text, &relocs),
                TestSection {
                    name: ".rdata",
                    flags: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
                    data: b"hi\0\0",
                    relocs: &[],
                    selection: 0,
                    assoc: 0,
                },
            ],
            &[("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );

        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[coff.as_slice()], None, &mut out).expect("links");
        let disp_at = 512 + 3;
        let disp = i32::from_le_bytes(out[disp_at..disp_at + 4].try_into().unwrap());
        assert_eq!(disp, 0x2000 - 0x1007);
        assert_eq!(&out[1024..1027], b"hi\0");
    }

    #[test]
    fn test_coff_objects_link_across_each_other() {
        let call = [0xE8, 0, 0, 0, 0, 0xC3];
        let call_relocs = [(1, 3, IMAGE_REL_AMD64_REL32)];
        let caller = coff_object(
            &[text_section(&call, &call_relocs)],
            &[
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                (
                    "helper",
                    IMAGE_SYM_UNDEFINED_SECTION,
                    IMAGE_SYM_CLASS_EXTERNAL,
                    0,
                ),
            ],
        );
        let body = [0xC3, 0xC3, 0x90, 0xC3];
        let callee = coff_object(
            &[text_section(&body, &[])],
            &[("helper", 1, IMAGE_SYM_CLASS_EXTERNAL, 2)],
        );

        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[caller.as_slice(), callee.as_slice()], None, &mut out)
            .expect("links");
        let disp = i32::from_le_bytes(out[512 + 1..512 + 5].try_into().unwrap());
        assert_eq!(disp, 3);
    }

    #[test]
    fn test_coff_duplicate_strong_definition_is_error() {
        let body = [0xC3];
        let obj = coff_object(
            &[text_section(&body, &[])],
            &[("dup", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        let mut out = Vec::new();
        let result = link_and_emit_pe_from_coffs(&[obj.as_slice(), obj.as_slice()], None, &mut out);
        assert!(result.is_err());
    }

    fn comdat_object(body: &[u8], selection: u8) -> Vec<u8> {
        coff_object(
            &[TestSection {
                name: ".text",
                flags: COMDAT_TEXT_FLAGS,
                data: body,
                relocs: &[],
                selection,
                assoc: 0,
            }],
            &[("inl", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        )
    }

    fn comdat_call_object(symbols: &[(&str, i16, u8, u32)], target: u32) -> Vec<u8> {
        let call = [0xE8, 0, 0, 0, 0, 0xC3];
        coff_object(
            &[TestSection {
                name: ".text",
                flags: COMDAT_TEXT_FLAGS,
                data: &call,
                relocs: &[(1, target, IMAGE_REL_AMD64_REL32)],
                selection: IMAGE_COMDAT_SELECT_EXACT_MATCH,
                assoc: 0,
            }],
            symbols,
        )
    }

    #[test]
    fn test_coff_comdat_exact_match_compares_relocation_targets_by_name() {
        let x_first = [
            ("inl", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
            (
                "printf",
                IMAGE_SYM_UNDEFINED_SECTION,
                IMAGE_SYM_CLASS_EXTERNAL,
                0,
            ),
            (
                "fflush",
                IMAGE_SYM_UNDEFINED_SECTION,
                IMAGE_SYM_CLASS_EXTERNAL,
                0,
            ),
        ];
        let y_first = [
            ("inl", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
            (
                "fflush",
                IMAGE_SYM_UNDEFINED_SECTION,
                IMAGE_SYM_CLASS_EXTERNAL,
                0,
            ),
            (
                "printf",
                IMAGE_SYM_UNDEFINED_SECTION,
                IMAGE_SYM_CLASS_EXTERNAL,
                0,
            ),
        ];
        let calls_x = comdat_call_object(&x_first, 3);
        let calls_y = comdat_call_object(&x_first, 4);
        let calls_x_at_other_index = comdat_call_object(&y_first, 4);

        let mut out = Vec::new();
        assert!(
            link_and_emit_pe_from_coffs(
                &[calls_x.as_slice(), calls_y.as_slice()],
                Some("inl"),
                &mut out
            )
            .is_err()
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(
            &[calls_x.as_slice(), calls_x_at_other_index.as_slice()],
            Some("inl"),
            &mut out,
        )
        .expect("links");
    }

    #[test]
    fn test_coff_comdat_largest_keeps_largest_copy() {
        let small = comdat_object(&[0xC3; 4], IMAGE_COMDAT_SELECT_LARGEST);
        let large = comdat_object(&[0x90; 8], IMAGE_COMDAT_SELECT_LARGEST);
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[small.as_slice(), large.as_slice()], Some("inl"), &mut out)
            .expect("links");
        assert_eq!(pe_section_vsize(&out, 0), 8);
        assert_eq!(&out[512..520], &[0x90; 8]);

        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[large.as_slice(), small.as_slice()], Some("inl"), &mut out)
            .expect("links");
        assert_eq!(pe_section_vsize(&out, 0), 8);
    }

    #[test]
    fn test_coff_comdat_same_size_rejects_different_sizes() {
        let a = comdat_object(&[0xC3; 4], IMAGE_COMDAT_SELECT_SAME_SIZE);
        let b = comdat_object(&[0xC3; 8], IMAGE_COMDAT_SELECT_SAME_SIZE);
        let mut out = Vec::new();
        assert!(
            link_and_emit_pe_from_coffs(&[a.as_slice(), b.as_slice()], None, &mut out).is_err()
        );
    }

    #[test]
    fn test_coff_comdat_exact_match_rejects_different_contents() {
        let a = comdat_object(&[0xC3; 4], IMAGE_COMDAT_SELECT_EXACT_MATCH);
        let b = comdat_object(&[0x90; 4], IMAGE_COMDAT_SELECT_EXACT_MATCH);
        let mut out = Vec::new();
        assert!(
            link_and_emit_pe_from_coffs(&[a.as_slice(), b.as_slice()], Some("inl"), &mut out)
                .is_err()
        );
        let same = comdat_object(&[0xC3; 4], IMAGE_COMDAT_SELECT_EXACT_MATCH);
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[a.as_slice(), same.as_slice()], Some("inl"), &mut out)
            .expect("links");
    }

    #[test]
    fn test_coff_comdat_is_linked_once() {
        let body = [0xC3; 4];
        let obj = coff_object(
            &[TestSection {
                name: ".text",
                flags: COMDAT_TEXT_FLAGS,
                data: &body,
                relocs: &[],
                selection: IMAGE_COMDAT_SELECT_ANY,
                assoc: 0,
            }],
            &[("inl", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice(), obj.as_slice()], Some("inl"), &mut out)
            .expect("links");
        assert_eq!(pe_section_vsize(&out, 0), 4);
    }

    fn pe_section_header(out: &[u8], index: usize) -> &[u8] {
        let e_lfanew = u32::from_le_bytes(out[0x3C..0x40].try_into().unwrap()) as usize;
        let at = e_lfanew
            + 4
            + SIZEOF_COFF_HEADER
            + SIZEOF_OPTIONAL_HEADER as usize
            + index * SIZEOF_SECTION_HEADER;
        &out[at..at + SIZEOF_SECTION_HEADER]
    }

    fn le_u32(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }

    fn pe_data_dir(out: &[u8], index: usize) -> (u32, u32) {
        let e_lfanew = u32::from_le_bytes(out[0x3C..0x40].try_into().unwrap()) as usize;
        let dir = e_lfanew + 24 + 112 + index * 8;
        (le_u32(out, dir), le_u32(out, dir + 4))
    }

    fn pe_base_reloc_dir(out: &[u8]) -> (u32, u32) {
        pe_data_dir(out, DATA_DIR_BASE_RELOC)
    }

    const DATA_FLAGS: u32 =
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    fn absolute_pointer_object(rel_type: u16) -> Vec<u8> {
        let text = [0xC3];
        let data = [0u8; 8];
        let relocs = [(0, 4, rel_type)];
        coff_object(
            &[
                text_section(&text, &[]),
                TestSection {
                    name: ".data",
                    flags: DATA_FLAGS,
                    data: &data,
                    relocs: &relocs,
                    selection: 0,
                    assoc: 0,
                },
            ],
            &[
                ("f", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
            ],
        )
    }

    fn weak_call_caller(default_index: u32) -> Vec<u8> {
        let call = [0xE8, 0, 0, 0, 0, 0xC3];
        coff_object(
            &[text_section(&call, &[(1, 4, IMAGE_REL_AMD64_REL32)])],
            &[
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                (
                    "dflt",
                    IMAGE_SYM_UNDEFINED_SECTION,
                    IMAGE_SYM_CLASS_EXTERNAL,
                    0,
                ),
                (
                    "foo",
                    IMAGE_SYM_UNDEFINED_SECTION,
                    IMAGE_SYM_CLASS_WEAK_EXTERNAL,
                    default_index,
                ),
            ],
        )
    }

    #[test]
    fn test_coff_weak_external_prefers_strong_definition() {
        let caller = weak_call_caller(3);
        let body = [0xC3, 0xC3, 0x90, 0xC3];
        let callee = coff_object(
            &[text_section(&body, &[])],
            &[("foo", 1, IMAGE_SYM_CLASS_EXTERNAL, 2)],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[caller.as_slice(), callee.as_slice()], None, &mut out)
            .expect("links");
        let disp = i32::from_le_bytes(out[512 + 1..512 + 5].try_into().unwrap());
        assert_eq!(disp, 3);
    }

    #[test]
    fn test_coff_weak_external_falls_back_to_default() {
        let caller = weak_call_caller(3);
        let body = [0xC3, 0xC3, 0x90, 0xC3];
        let callee = coff_object(
            &[text_section(&body, &[])],
            &[("dflt", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[caller.as_slice(), callee.as_slice()], None, &mut out)
            .expect("links");
        let disp = i32::from_le_bytes(out[512 + 1..512 + 5].try_into().unwrap());
        assert_eq!(disp, 1);
    }

    #[test]
    fn test_coff_weak_external_with_absolute_default_stores_null() {
        let text = [0xC3];
        let data = [0u8; 8];
        let relocs = [(0, 6, IMAGE_REL_AMD64_ADDR64)];
        let obj = coff_object(
            &[
                text_section(&text, &[]),
                TestSection {
                    name: ".data",
                    flags: DATA_FLAGS,
                    data: &data,
                    relocs: &relocs,
                    selection: 0,
                    assoc: 0,
                },
            ],
            &[
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                (
                    "zero",
                    IMAGE_SYM_ABSOLUTE_SECTION,
                    IMAGE_SYM_CLASS_EXTERNAL,
                    0,
                ),
                (
                    "foo",
                    IMAGE_SYM_UNDEFINED_SECTION,
                    IMAGE_SYM_CLASS_WEAK_EXTERNAL,
                    5,
                ),
            ],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).expect("links");
        let data = pe_section_header(&out, 2);
        let data_ptr = le_u32(data, 20) as usize;
        let stored = u64::from_le_bytes(out[data_ptr..data_ptr + 8].try_into().unwrap());
        assert_eq!(stored, 0);
        assert_eq!(pe_base_reloc_dir(&out), (0, 0));
    }

    #[test]
    fn test_coff_addr64_to_absolute_symbol_has_no_base_reloc() {
        let text = [0xC3];
        let data = [0u8; 8];
        let relocs = [(0, 5, IMAGE_REL_AMD64_ADDR64)];
        let obj = coff_object(
            &[
                text_section(&text, &[]),
                TestSection {
                    name: ".data",
                    flags: DATA_FLAGS,
                    data: &data,
                    relocs: &relocs,
                    selection: 0,
                    assoc: 0,
                },
            ],
            &[
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                (
                    "konst",
                    IMAGE_SYM_ABSOLUTE_SECTION,
                    IMAGE_SYM_CLASS_EXTERNAL,
                    0x42,
                ),
            ],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).expect("links");
        let data = pe_section_header(&out, 2);
        let data_ptr = le_u32(data, 20) as usize;
        let stored = u64::from_le_bytes(out[data_ptr..data_ptr + 8].try_into().unwrap());
        assert_eq!(stored, 0x42);
        assert_eq!(pe_base_reloc_dir(&out), (0, 0));
    }

    #[test]
    fn test_coff_addr64_emits_base_reloc() {
        let obj = absolute_pointer_object(IMAGE_REL_AMD64_ADDR64);
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).expect("links");

        let data = pe_section_header(&out, 2);
        let data_rva = le_u32(data, 12);
        let data_ptr = le_u32(data, 20) as usize;
        let stored = u64::from_le_bytes(out[data_ptr..data_ptr + 8].try_into().unwrap());
        assert_eq!(stored, IMAGE_BASE + 0x1000);

        let (reloc_rva, reloc_size) = pe_base_reloc_dir(&out);
        let reloc = pe_section_header(&out, 3);
        assert_eq!(le_u32(reloc, 12), reloc_rva);
        assert_eq!(reloc_size, 12);
        let ptr = le_u32(reloc, 20) as usize;
        assert_eq!(le_u32(&out, ptr), data_rva & !0xFFF);
        assert_eq!(le_u32(&out, ptr + 4), 12);
        let entry = u16::from_le_bytes(out[ptr + 8..ptr + 10].try_into().unwrap());
        assert_eq!(
            entry,
            (IMAGE_REL_BASED_DIR64 << 12) | (data_rva & 0xFFF) as u16
        );
    }

    #[test]
    fn test_coff_unknown_machine_object_is_rejected() {
        let mut obj = absolute_pointer_object(IMAGE_REL_AMD64_ADDR32NB);
        obj[0..2].copy_from_slice(&0x01C0u16.to_le_bytes());
        let mut out = Vec::new();
        let err = link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out)
            .expect_err("arm32 must be rejected");
        assert!(err.to_string().contains("0x01c0"), "{err}");
    }

    #[test]
    fn test_coff_addr32_is_rejected() {
        let obj = absolute_pointer_object(IMAGE_REL_AMD64_ADDR32);
        let mut out = Vec::new();
        let err = link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out)
            .expect_err("ADDR32 must be rejected");
        assert!(err.to_string().contains("ADDR32"), "{err}");
    }

    #[test]
    fn test_coff_without_absolute_relocs_has_no_base_reloc() {
        let text = [0xC3];
        let obj = coff_object(
            &[text_section(&text, &[])],
            &[("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).expect("links");
        assert_eq!(pe_base_reloc_dir(&out), (0, 0));
    }

    fn undefined_import_object(text: &[u8], relocs: &[(u32, u32, u16)], symbol: &str) -> Vec<u8> {
        coff_object(
            &[text_section(text, relocs)],
            &[
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                (
                    symbol,
                    IMAGE_SYM_UNDEFINED_SECTION,
                    IMAGE_SYM_CLASS_EXTERNAL,
                    0,
                ),
            ],
        )
    }

    #[test]
    fn test_coff_import_prefix_resolves_to_iat_slot() {
        let call = [0xFF, 0x15, 0, 0, 0, 0, 0xC3];
        let relocs = [(2, 3, IMAGE_REL_AMD64_REL32)];
        let obj = undefined_import_object(&call, &relocs, "__imp_printf");
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).expect("links");

        let disp = i32::from_le_bytes(out[512 + 2..512 + 6].try_into().unwrap());
        let slot_rva = (0x1000 + 2 + 4 + disp) as u32;
        let rdata = pe_section_header(&out, 1);
        let rdata_rva = le_u32(rdata, 12);
        let rdata_size = le_u32(rdata, 8);
        assert!(slot_rva >= rdata_rva && slot_rva + 8 <= rdata_rva + rdata_size);
        let slot_at = le_u32(rdata, 20) as usize + (slot_rva - rdata_rva) as usize;
        assert_ne!(
            u64::from_le_bytes(out[slot_at..slot_at + 8].try_into().unwrap()),
            0
        );
        assert!(!out.windows(12).any(|w| w == b"__imp_printf"));
    }

    #[test]
    fn test_coff_call_to_undefined_function_uses_thunk() {
        let call = [0xE8, 0, 0, 0, 0, 0xC3];
        let relocs = [(1, 3, IMAGE_REL_AMD64_REL32)];
        let obj = undefined_import_object(&call, &relocs, "printf");
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).expect("links");

        let disp = i32::from_le_bytes(out[512 + 1..512 + 5].try_into().unwrap());
        let target = (0x1000 + 1 + 4 + disp) as u32;
        let thunk_at = 512 + (target - 0x1000) as usize;
        assert_eq!(&out[thunk_at..thunk_at + 2], &[0xFF, 0x25]);
    }

    #[test]
    fn test_coff_call_to_undefined_non_crt_symbol_is_error() {
        let call = [0xE8, 0, 0, 0, 0, 0xC3];
        let relocs = [(1, 3, IMAGE_REL_AMD64_REL32)];
        let obj = undefined_import_object(&call, &relocs, "fmt_g");
        let mut out = Vec::new();
        let err = link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out)
            .expect_err("an unresolved non-CRT symbol must not become an import");
        assert!(err.to_string().contains("undefined symbol fmt_g"), "{err}");
    }

    #[test]
    fn test_coff_undefined_non_crt_import_prefix_is_error() {
        let call = [0xFF, 0x15, 0, 0, 0, 0, 0xC3];
        let relocs = [(2, 3, IMAGE_REL_AMD64_REL32)];
        let obj = undefined_import_object(&call, &relocs, "__imp_fmt_g");
        let mut out = Vec::new();
        let err = link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out)
            .expect_err("an unresolved pointer slot must not become an import");
        assert!(err.to_string().contains("undefined symbol fmt_g"), "{err}");
    }

    fn pe_rva_to_offset(out: &[u8], rva: u32) -> usize {
        let e_lfanew = u32::from_le_bytes(out[0x3C..0x40].try_into().unwrap()) as usize;
        let count = u16::from_le_bytes(out[e_lfanew + 6..e_lfanew + 8].try_into().unwrap());
        (0..count as usize)
            .map(|i| pe_section_header(out, i))
            .find(|sh| {
                let va = le_u32(sh, 12);
                rva >= va && rva - va < le_u32(sh, 8)
            })
            .map(|sh| (le_u32(sh, 20) + (rva - le_u32(sh, 12))) as usize)
            .expect("rva in a section")
    }

    fn pe_cstr(out: &[u8], at: usize) -> String {
        let end = out[at..].iter().position(|&b| b == 0).unwrap();
        String::from_utf8(out[at..at + end].to_vec()).unwrap()
    }

    /// Import table as (dll, names imported by name), read back from the image.
    fn pe_imports(out: &[u8]) -> Vec<(String, Vec<String>)> {
        let (dir_rva, _) = pe_data_dir(out, 1);
        let mut at = pe_rva_to_offset(out, dir_rva);
        let mut imports = Vec::new();
        while le_u32(out, at + 12) != 0 {
            let dll = pe_cstr(out, pe_rva_to_offset(out, le_u32(out, at + 12)));
            let mut ilt = pe_rva_to_offset(out, le_u32(out, at));
            let mut names = Vec::new();
            while u64::from_le_bytes(out[ilt..ilt + 8].try_into().unwrap()) != 0 {
                let entry = le_u32(out, ilt);
                names.push(pe_cstr(out, pe_rva_to_offset(out, entry) + 2));
                ilt += 8;
            }
            imports.push((dll, names));
            at += 20;
        }
        imports
    }

    #[test]
    fn test_coff_crt_calls_import_from_msvcrt() {
        let text = [0xE8, 0, 0, 0, 0, 0xE8, 0, 0, 0, 0, 0xE8, 0, 0, 0, 0, 0xC3];
        let relocs = [
            (1, 3, IMAGE_REL_AMD64_REL32),
            (6, 4, IMAGE_REL_AMD64_REL32),
            (11, 5, IMAGE_REL_AMD64_REL32),
        ];
        let obj = coff_object(
            &[text_section(&text, &relocs)],
            &[
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                (
                    "printf",
                    IMAGE_SYM_UNDEFINED_SECTION,
                    IMAGE_SYM_CLASS_EXTERNAL,
                    0,
                ),
                (
                    "fflush",
                    IMAGE_SYM_UNDEFINED_SECTION,
                    IMAGE_SYM_CLASS_EXTERNAL,
                    0,
                ),
                (
                    "putchar",
                    IMAGE_SYM_UNDEFINED_SECTION,
                    IMAGE_SYM_CLASS_EXTERNAL,
                    0,
                ),
            ],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).expect("links");

        let imports = pe_imports(&out);
        assert_eq!(imports.len(), 2, "{imports:?}");
        assert_eq!(imports[0].0, "KERNEL32.DLL");
        assert_eq!(imports[0].1, ["ExitProcess"]);
        assert_eq!(imports[1].0, "msvcrt.dll");
        let mut crt = imports[1].1.clone();
        crt.sort();
        assert_eq!(crt, ["fflush", "printf", "putchar"]);
    }

    #[test]
    fn test_coff_data_reference_to_undefined_symbol_is_error() {
        let lea = [0x48, 0x8D, 0x0D, 0, 0, 0, 0, 0xC3];
        let relocs = [(3, 3, IMAGE_REL_AMD64_REL32)];
        let obj = undefined_import_object(&lea, &relocs, "plain");
        let mut out = Vec::new();
        assert!(link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).is_err());
    }

    #[test]
    fn test_coff_absolute_reference_to_undefined_symbol_is_error() {
        let text = [0xC3];
        let data = [0u8; 8];
        let relocs = [(0, 3, IMAGE_REL_AMD64_ADDR64)];
        let obj = coff_object(
            &[
                text_section(&text, &[]),
                TestSection {
                    name: ".data",
                    flags: DATA_FLAGS,
                    data: &data,
                    relocs: &relocs,
                    selection: 0,
                    assoc: 0,
                },
            ],
            &[
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                (
                    "plain",
                    IMAGE_SYM_UNDEFINED_SECTION,
                    IMAGE_SYM_CLASS_EXTERNAL,
                    0,
                ),
            ],
        );
        let mut out = Vec::new();
        assert!(link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).is_err());
    }

    fn pdata_object(
        text: &[u8],
        pdata: &[u8],
        pdata_relocs: &[(u32, u32, u16)],
        symbols: &[(&str, i16, u8, u32)],
    ) -> Vec<u8> {
        coff_object(
            &[
                text_section(text, &[]),
                TestSection {
                    name: ".pdata",
                    flags: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
                    data: pdata,
                    relocs: pdata_relocs,
                    selection: 0,
                    assoc: 0,
                },
            ],
            symbols,
        )
    }

    #[test]
    fn test_coff_long_section_name_is_read_from_string_table() {
        let mut record = [0u8; 12];
        record[0] = 1;
        let obj = coff_object_with_strtab(
            &[
                text_section(&[0x90; 8], &[]),
                TestSection {
                    name: "/4",
                    flags: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
                    data: &record,
                    relocs: &[],
                    selection: 0,
                    assoc: 0,
                },
            ],
            &[("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
            b".pdata$longname\0",
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).expect("links");
        assert_eq!(pe_data_dir(&out, DATA_DIR_EXCEPTION), (0x3000, 12));
    }

    #[test]
    fn test_coff_pdata_is_contiguous_and_sorted() {
        let record = [0u8; 12];
        let obj0 = pdata_object(
            &[0x90; 8],
            &record,
            &[(0, 5, IMAGE_REL_AMD64_ADDR32NB)],
            &[
                ("f0", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                ("f1", 0, IMAGE_SYM_CLASS_EXTERNAL, 0),
            ],
        );
        let obj1 = pdata_object(
            &[0xC3; 8],
            &record,
            &[(0, 5, IMAGE_REL_AMD64_ADDR32NB)],
            &[
                ("f1", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                ("f0", 0, IMAGE_SYM_CLASS_EXTERNAL, 0),
            ],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj0.as_slice(), obj1.as_slice()], Some("f1"), &mut out)
            .expect("links");

        let pdata = pe_section_header(&out, 2);
        let pdata_rva = le_u32(pdata, 12);
        let pdata_ptr = le_u32(pdata, 20) as usize;
        assert_eq!(le_u32(&out, pdata_ptr), 0x1000);
        assert_eq!(le_u32(&out, pdata_ptr + 12), 0x1008);
        assert_eq!(pe_data_dir(&out, DATA_DIR_EXCEPTION), (pdata_rva, 24));
    }

    #[test]
    fn test_coff_without_pdata_has_no_exception_dir() {
        let text = [0xC3];
        let obj = coff_object(
            &[text_section(&text, &[])],
            &[("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).expect("links");
        assert_eq!(pe_data_dir(&out, DATA_DIR_EXCEPTION), (0, 0));
    }

    #[test]
    fn test_coff_pdata_size_not_multiple_of_record_is_error() {
        let obj = pdata_object(
            &[0xC3],
            &[1u8; 4],
            &[],
            &[("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        let mut out = Vec::new();
        let err = link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out)
            .expect_err("a truncated record must be refused");
        assert!(err.to_string().contains("exception records"), "{err}");
    }

    #[test]
    fn test_coff_pdata_padding_after_the_last_record_is_dropped() {
        // An assembler pads a section's raw data, so a record can be followed by zeroes.
        let mut pdata = [0u8; 16];
        pdata[0..4].copy_from_slice(&1u32.to_le_bytes());
        let obj = pdata_object(
            &[0xC3],
            &pdata,
            &[],
            &[("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).expect("links");
        let (_, size) = pe_data_dir(&out, DATA_DIR_EXCEPTION);
        assert_eq!(size, PDATA_RECORD_SIZE as u32);
    }

    #[test]
    fn test_coff_pdata_record_of_zeroes_stays_out_of_the_directory() {
        let mut pdata = [0u8; 24];
        pdata[12..16].copy_from_slice(&1u32.to_le_bytes());
        let obj = pdata_object(
            &[0xC3],
            &pdata,
            &[],
            &[("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).expect("links");
        let (_, size) = pe_data_dir(&out, DATA_DIR_EXCEPTION);
        assert_eq!(size, PDATA_RECORD_SIZE as u32);
    }

    #[test]
    fn test_coff_pdata_addr32_is_read_as_image_relative() {
        // ras has no ADDR32NB, and a RUNTIME_FUNCTION field is an RVA either way.
        let obj = pdata_object(
            &[0xC3],
            &[0u8; 12],
            &[(0, 4, IMAGE_REL_AMD64_ADDR32)],
            &[("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).expect("links");
        let (_, size) = pe_data_dir(&out, DATA_DIR_EXCEPTION);
        assert_eq!(size, PDATA_RECORD_SIZE as u32);
        let pdata = pe_section_header(&out, 2);
        let at = le_u32(pdata, 20) as usize;
        assert_eq!(le_u32(&out, at), 0x1000, "the field must hold main's RVA");
    }

    #[test]
    fn test_coff_symbol_table_past_object_is_error() {
        let text = [0xC3; 4];
        let mut obj = coff_object(
            &[text_section(&text, &[])],
            &[("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        obj[12..16].copy_from_slice(&1000u32.to_le_bytes());
        let mut out = Vec::new();
        assert!(link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).is_err());
    }

    #[test]
    fn test_coff_huge_symbol_count_is_error() {
        let text = [0xC3; 4];
        let mut obj = coff_object(
            &[text_section(&text, &[])],
            &[("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        obj[12..16].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
        let mut out = Vec::new();
        assert!(link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).is_err());
    }

    #[test]
    fn test_coff_symbol_table_at_offset_zero_is_error() {
        let text = [0xC3; 4];
        let mut obj = coff_object(
            &[text_section(&text, &[])],
            &[("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        obj[8..12].copy_from_slice(&0u32.to_le_bytes());
        let mut out = Vec::new();
        assert!(link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).is_err());
    }

    #[test]
    fn test_coff_unreferenced_weak_external_does_not_import_its_default() {
        let text = [0xC3, 0xC3, 0x90, 0xC3];
        let obj = coff_object(
            &[text_section(&text, &[])],
            &[
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                (
                    "dflt",
                    IMAGE_SYM_UNDEFINED_SECTION,
                    IMAGE_SYM_CLASS_EXTERNAL,
                    0,
                ),
                (
                    "foo",
                    IMAGE_SYM_UNDEFINED_SECTION,
                    IMAGE_SYM_CLASS_WEAK_EXTERNAL,
                    3,
                ),
            ],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).expect("links");
        assert!(!out.windows(5).any(|w| w == b"dflt\0"));
    }

    #[test]
    fn test_coff_weak_external_without_default_record_is_error() {
        let mut caller = weak_call_caller(3);
        let sym_off = u32::from_le_bytes(caller[8..12].try_into().unwrap()) as usize;
        let weak_at = sym_off + 4 * 18;
        assert_eq!(caller[weak_at + 16], IMAGE_SYM_CLASS_WEAK_EXTERNAL);
        caller[weak_at + 17] = 0;
        let callee = coff_object(
            &[text_section(&[0xC3], &[])],
            &[("dflt", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        let mut out = Vec::new();
        assert!(
            link_and_emit_pe_from_coffs(&[caller.as_slice(), callee.as_slice()], None, &mut out)
                .is_err()
        );
    }

    #[test]
    fn test_coff_section_error_precedes_symbol_table_error() {
        let text = [0xC3; 4];
        let mut obj = coff_object(
            &[text_section(&text, &[])],
            &[("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        obj[20 + 16..20 + 20].copy_from_slice(&1000u32.to_le_bytes());
        obj[12..16].copy_from_slice(&1000u32.to_le_bytes());
        let mut out = Vec::new();
        let message = link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out)
            .unwrap_err()
            .to_string();
        assert!(message.contains("data lies outside"), "{message}");
    }

    const TLS_FLAGS: u32 =
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    const TLS_BSS_FLAGS: u32 =
        coff::IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    struct PeSectionInfo {
        name: String,
        vsize: u32,
        rva: u32,
        raw: u32,
    }

    fn u32_at(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    fn u64_at(bytes: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
    }

    fn pe_section_table(out: &[u8]) -> Vec<PeSectionInfo> {
        let e_lfanew = u32_at(out, 0x3C) as usize;
        let count = u16::from_le_bytes([out[e_lfanew + 6], out[e_lfanew + 7]]) as usize;
        let first = e_lfanew + 4 + SIZEOF_COFF_HEADER + SIZEOF_OPTIONAL_HEADER as usize;
        (0..count)
            .map(|i| {
                let at = first + i * SIZEOF_SECTION_HEADER;
                PeSectionInfo {
                    name: String::from_utf8_lossy(&out[at..at + 8])
                        .trim_end_matches('\0')
                        .to_string(),
                    vsize: u32_at(out, at + 8),
                    rva: u32_at(out, at + 12),
                    raw: u32_at(out, at + 20),
                }
            })
            .collect()
    }

    fn pe_section<'a>(sections: &'a [PeSectionInfo], name: &str) -> &'a PeSectionInfo {
        sections
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("no {name} section"))
    }

    fn data_directory(out: &[u8], index: usize) -> (u32, u32) {
        let e_lfanew = u32_at(out, 0x3C) as usize;
        let at = e_lfanew + 4 + SIZEOF_COFF_HEADER + 112 + index * 8;
        (u32_at(out, at), u32_at(out, at + 4))
    }

    fn file_offset(sections: &[PeSectionInfo], rva: u32) -> usize {
        let s = sections
            .iter()
            .find(|s| rva >= s.rva && rva < s.rva + s.vsize)
            .unwrap_or_else(|| panic!("rva {rva:#x} is outside every section"));
        (s.raw + (rva - s.rva)) as usize
    }

    fn base_reloc_sites(dir: &[u8]) -> Vec<u32> {
        let mut sites = Vec::new();
        let mut at = 0;
        while at + 8 <= dir.len() {
            let page = u32_at(dir, at);
            let block = u32_at(dir, at + 4) as usize;
            for e in (at + 8..at + block).step_by(2) {
                let entry = u16::from_le_bytes([dir[e], dir[e + 1]]);
                if entry >> 12 != 0 {
                    sites.push(page + u32::from(entry & 0xFFF));
                }
            }
            at += block;
        }
        sites
    }

    fn tls_directory_fields(
        out: &[u8],
        sections: &[PeSectionInfo],
    ) -> (u64, u64, u64, u64, u32, u32) {
        let (dir_rva, dir_size) = data_directory(out, DATA_DIR_TLS);
        assert_eq!(dir_size as usize, TLS_DIRECTORY_SIZE);
        let at = file_offset(sections, dir_rva);
        (
            u64_at(out, at),
            u64_at(out, at + 8),
            u64_at(out, at + 16),
            u64_at(out, at + 24),
            u32_at(out, at + 32),
            u32_at(out, at + 36),
        )
    }

    #[test]
    fn test_coff_tls_directory_and_index_resolve() {
        let text = [0x8B, 0x0D, 0, 0, 0, 0, 0x8B, 0x80, 0, 0, 0, 0, 0xC3];
        let text_relocs = [
            (2, 7, IMAGE_REL_AMD64_REL32),
            (8, 8, IMAGE_REL_AMD64_SECREL),
        ];
        let tls_init = [0x11, 0x22, 0x33, 0x44];
        let mut obj = coff_object(
            &[
                text_section(&text, &text_relocs),
                TestSection {
                    name: ".tls$AAA",
                    flags: TLS_FLAGS,
                    data: &tls_init,
                    relocs: &[],
                    selection: 0,
                    assoc: 0,
                },
                TestSection {
                    name: ".tls$ZZZ",
                    flags: TLS_BSS_FLAGS,
                    data: &[],
                    relocs: &[],
                    selection: 0,
                    assoc: 0,
                },
            ],
            &[
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                (
                    "_tls_index",
                    IMAGE_SYM_UNDEFINED_SECTION,
                    IMAGE_SYM_CLASS_EXTERNAL,
                    0,
                ),
                ("tls_var", 2, IMAGE_SYM_CLASS_EXTERNAL, 4),
            ],
        );
        let bss_size_at = 20 + 2 * SIZEOF_SECTION_HEADER + 16;
        obj[bss_size_at..bss_size_at + 4].copy_from_slice(&16u32.to_le_bytes());

        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).expect("links");

        let sections = pe_section_table(&out);
        let text_sec = pe_section(&sections, ".text");
        let tls_sec = pe_section(&sections, ".tls");
        let data_sec = pe_section(&sections, ".data");
        assert_eq!(tls_sec.vsize, 4 + 16);

        let (start, end, index, callbacks, zero_fill, characteristics) =
            tls_directory_fields(&out, &sections);
        let tls_va = IMAGE_BASE + u64::from(tls_sec.rva);
        assert_eq!(start, tls_va);
        assert_eq!(end, tls_va + 4);
        assert_eq!(zero_fill, 16);
        assert_eq!(callbacks, 0);
        assert_eq!(characteristics, 0);
        assert_eq!(
            &out[tls_sec.raw as usize..tls_sec.raw as usize + 4],
            &tls_init
        );

        let index_rva = (index - IMAGE_BASE) as u32;
        assert!(index_rva >= data_sec.rva && index_rva + 4 <= data_sec.rva + data_sec.vsize);
        let slot = file_offset(&sections, index_rva);
        assert_eq!(&out[slot..slot + 4], &[0, 0, 0, 0]);

        let text_at = text_sec.raw as usize;
        let field_va = IMAGE_BASE + u64::from(text_sec.rva) + 2;
        let disp = u32_at(&out, text_at + 2) as i32;
        assert_eq!(field_va as i64 + 4 + i64::from(disp), index as i64);
        assert_eq!(u32_at(&out, text_at + 8), 4);

        let (reloc_rva, reloc_size) = data_directory(&out, DATA_DIR_BASE_RELOC);
        let reloc_at = file_offset(&sections, reloc_rva);
        let sites = base_reloc_sites(&out[reloc_at..reloc_at + reloc_size as usize]);
        let (dir_rva, _) = data_directory(&out, DATA_DIR_TLS);
        for field in [0, 8, 16] {
            assert!(
                sites.contains(&(dir_rva + field)),
                "no base reloc at field {field}"
            );
        }
    }

    #[test]
    fn test_coff_tls_index_without_template_still_emits_directory() {
        let text = [0x8B, 0x0D, 0, 0, 0, 0, 0xC3];
        let obj = coff_object(
            &[text_section(&text, &[(2, 3, IMAGE_REL_AMD64_REL32)])],
            &[
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                (
                    "_tls_index",
                    IMAGE_SYM_UNDEFINED_SECTION,
                    IMAGE_SYM_CLASS_EXTERNAL,
                    0,
                ),
            ],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).expect("links");

        let sections = pe_section_table(&out);
        assert!(sections.iter().all(|s| s.name != ".tls"));
        let (start, end, index, _, zero_fill, _) = tls_directory_fields(&out, &sections);
        assert_eq!(start, end);
        assert_eq!(zero_fill, 0);
        let data_sec = pe_section(&sections, ".data");
        let index_rva = (index - IMAGE_BASE) as u32;
        assert!(index_rva >= data_sec.rva && index_rva + 4 <= data_sec.rva + data_sec.vsize);
    }

    #[test]
    fn test_amd64_secrel_is_the_value_the_pe_spec_gives_it() {
        assert_eq!(IMAGE_REL_AMD64_SECREL, 0x000B);
    }

    #[test]
    fn test_coff_secrel_outside_tls_is_error() {
        let text = [0x8B, 0x80, 0, 0, 0, 0, 0xC3];
        let obj = coff_object(
            &[text_section(&text, &[(2, 2, IMAGE_REL_AMD64_SECREL)])],
            &[("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        let mut out = Vec::new();
        let message = link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out)
            .unwrap_err()
            .to_string();
        assert!(message.contains("outside .tls"), "{message}");
    }

    #[test]
    fn test_coff_defined_tls_used_is_error() {
        let text = [0xC3];
        let obj = coff_object(
            &[text_section(&text, &[])],
            &[
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                ("_tls_used", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
            ],
        );
        let mut out = Vec::new();
        let message = link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out)
            .unwrap_err()
            .to_string();
        assert!(message.contains("_tls_used"), "{message}");
    }

    const ARM64_RET: u32 = 0xD65F_03C0;
    const ARM64_ADRP_X0: u32 = 0x9000_0000;
    const ARM64_ADD_X0_X0: u32 = 0x9100_0000;
    const ARM64_LDR_X1_X0: u32 = 0xF940_0001;
    const ARM64_BL: u32 = 0x9400_0000;
    const ARM64_BR_X16: u32 = 0xD61F_0200;

    fn arm64_object(sections: &[TestSection], symbols: &[(&str, i16, u8, u32)]) -> Vec<u8> {
        let mut o = coff_object(sections, symbols);
        o[0..2].copy_from_slice(&MACHINE_ARM64.to_le_bytes());
        o
    }

    fn words(ws: &[u32]) -> Vec<u8> {
        ws.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    fn pe_machine(out: &[u8]) -> u16 {
        let e_lfanew = le_u32(out, 0x3C) as usize;
        u16::from_le_bytes(out[e_lfanew + 4..e_lfanew + 6].try_into().unwrap())
    }

    fn pe_word_at_rva(out: &[u8], rva: u32) -> u32 {
        le_u32(out, pe_rva_to_offset(out, rva))
    }

    fn sign_extend(value: u64, bits: u32) -> i64 {
        let shift = 64 - bits;
        ((value << shift) as i64) >> shift
    }

    fn decode_adrp_page(word: u32) -> i64 {
        let imm = u64::from(((word >> 29) & 0x3) | (((word >> 5) & 0x7FFFF) << 2));
        sign_extend(imm, 21)
    }

    fn decode_imm12(word: u32) -> u32 {
        (word >> 10) & 0xFFF
    }

    /// Two text words that take the address of a symbol in .rdata.
    fn arm64_page_pair_object() -> Vec<u8> {
        arm64_object(
            &[
                TestSection {
                    name: ".text",
                    flags: TEXT_FLAGS,
                    data: &words(&[ARM64_ADRP_X0, ARM64_ADD_X0_X0, ARM64_RET]),
                    relocs: &[
                        (0, 5, IMAGE_REL_ARM64_PAGEBASE_REL21),
                        (4, 5, IMAGE_REL_ARM64_PAGEOFFSET_12A),
                    ],
                    selection: 0,
                    assoc: 0,
                },
                TestSection {
                    name: ".rdata",
                    flags: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
                    data: &[0u8; 16],
                    relocs: &[],
                    selection: 0,
                    assoc: 0,
                },
            ],
            &[
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                ("msg", 2, IMAGE_SYM_CLASS_STATIC, 8),
            ],
        )
    }

    #[test]
    fn test_arm64_image_carries_the_arm64_machine() {
        let obj = arm64_page_pair_object();
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).expect("links");
        assert_eq!(pe_machine(&out), MACHINE_ARM64);
    }

    #[test]
    fn test_arm64_page_pair_addresses_its_symbol() {
        let obj = arm64_page_pair_object();
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).expect("links");
        let text_rva = entry_rva(&out);
        let adrp = pe_word_at_rva(&out, text_rva);
        let add = pe_word_at_rva(&out, text_rva + 4);
        let p = IMAGE_BASE + u64::from(text_rva);
        let page = ((p as i64) >> 12) + decode_adrp_page(adrp);
        let target = ((page << 12) as u64) + u64::from(decode_imm12(add));
        let rdata_rva = (target - IMAGE_BASE) as u32;
        // `msg` sits 8 bytes into .rdata, which follows .text.
        assert_eq!(
            pe_rva_to_offset(&out, rdata_rva),
            pe_rva_to_offset(&out, rdata_rva - 8) + 8
        );
        assert!(rdata_rva > text_rva, "{rdata_rva:#x} vs {text_rva:#x}");
    }

    #[test]
    fn test_arm64_call_to_an_import_goes_through_a_three_word_thunk() {
        let obj = arm64_object(
            &[TestSection {
                name: ".text",
                flags: TEXT_FLAGS,
                data: &words(&[ARM64_BL, ARM64_RET]),
                relocs: &[(0, 3, IMAGE_REL_ARM64_BRANCH26)],
                selection: 0,
                assoc: 0,
            }],
            &[
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                ("printf", 0, IMAGE_SYM_CLASS_EXTERNAL, 0),
            ],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).expect("links");
        let text_rva = entry_rva(&out);
        let bl = pe_word_at_rva(&out, text_rva);
        let delta = sign_extend(u64::from(bl & 0x03FF_FFFF), 26) * 4;
        let thunk_rva = (i64::from(text_rva) + delta) as u32;

        let adrp = pe_word_at_rva(&out, thunk_rva);
        let ldr = pe_word_at_rva(&out, thunk_rva + 4);
        assert_eq!(pe_word_at_rva(&out, thunk_rva + 8), ARM64_BR_X16);

        let p = IMAGE_BASE + u64::from(thunk_rva);
        let page = ((p as i64) >> 12) + decode_adrp_page(adrp);
        let slot = ((page << 12) as u64) + u64::from(decode_imm12(ldr)) * 8;
        let (iat_rva, iat_size) = pe_data_dir(&out, 12);
        let slot_rva = (slot - IMAGE_BASE) as u32;
        assert!(
            slot_rva >= iat_rva && slot_rva < iat_rva + iat_size,
            "{slot_rva:#x} outside IAT {iat_rva:#x}+{iat_size:#x}"
        );
    }

    #[test]
    fn test_arm64_absolute_pointer_gets_a_base_relocation() {
        let obj = arm64_object(
            &[
                TestSection {
                    name: ".text",
                    flags: TEXT_FLAGS,
                    data: &words(&[ARM64_RET]),
                    relocs: &[],
                    selection: 0,
                    assoc: 0,
                },
                TestSection {
                    name: ".data",
                    flags: IMAGE_SCN_CNT_INITIALIZED_DATA
                        | IMAGE_SCN_MEM_READ
                        | IMAGE_SCN_MEM_WRITE,
                    data: &[0u8; 8],
                    relocs: &[(0, 4, IMAGE_REL_ARM64_ADDR64)],
                    selection: 0,
                    assoc: 0,
                },
            ],
            &[("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        let mut out = Vec::new();
        link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out).expect("links");
        let (reloc_rva, reloc_size) = pe_base_reloc_dir(&out);
        assert!(reloc_rva != 0 && reloc_size >= 12);
    }

    #[test]
    fn test_arm64_unimplemented_relocation_is_refused_by_name() {
        let obj = arm64_object(
            &[TestSection {
                name: ".text",
                flags: TEXT_FLAGS,
                data: &words(&[ARM64_LDR_X1_X0, ARM64_RET]),
                relocs: &[(0, 3, 0x0008)],
                selection: 0,
                assoc: 0,
            }],
            &[
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                ("tvar", 1, IMAGE_SYM_CLASS_EXTERNAL, 4),
            ],
        );
        let mut out = Vec::new();
        let message = link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out)
            .unwrap_err()
            .to_string();
        assert!(message.contains("IMAGE_REL_ARM64_SECREL"), "{message}");
        assert!(message.contains("tvar"), "{message}");
    }

    #[test]
    fn test_arm64_in_instruction_addend_is_refused() {
        let obj = arm64_object(
            &[
                TestSection {
                    name: ".text",
                    flags: TEXT_FLAGS,
                    data: &words(&[ARM64_ADRP_X0 | (1 << 29), ARM64_RET]),
                    relocs: &[(0, 5, IMAGE_REL_ARM64_PAGEBASE_REL21)],
                    selection: 0,
                    assoc: 0,
                },
                TestSection {
                    name: ".rdata",
                    flags: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
                    data: &[0u8; 16],
                    relocs: &[],
                    selection: 0,
                    assoc: 0,
                },
            ],
            &[
                ("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0),
                ("msg", 2, IMAGE_SYM_CLASS_STATIC, 0),
            ],
        );
        let mut out = Vec::new();
        let message = link_and_emit_pe_from_coffs(&[obj.as_slice()], None, &mut out)
            .unwrap_err()
            .to_string();
        assert!(message.contains("non-zero immediate field"), "{message}");
        assert!(message.contains("msg"), "{message}");
    }

    #[test]
    fn test_mixed_machine_objects_are_refused() {
        let x86 = coff_object(
            &[text_section(&[0xC3], &[])],
            &[("main", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        let arm = arm64_object(
            &[TestSection {
                name: ".text",
                flags: TEXT_FLAGS,
                data: &words(&[ARM64_RET]),
                relocs: &[],
                selection: 0,
                assoc: 0,
            }],
            &[("other", 1, IMAGE_SYM_CLASS_EXTERNAL, 0)],
        );
        let mut out = Vec::new();
        let message =
            link_and_emit_pe_from_coffs(&[x86.as_slice(), arm.as_slice()], None, &mut out)
                .unwrap_err()
                .to_string();
        assert!(message.contains("0xaa64"), "{message}");
        assert!(message.contains("0x8664"), "{message}");
    }
}
