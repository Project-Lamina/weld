# weld

Cross-platform linker from the Lamina project

weld is a library (`lamina-weld`, `[lib] name = "weld"`) and a `weld` binary. The
binary calls `weld::main`, which runs one link from `std::env::args`.

`cargo install lamina` installs `weld` beside `lamina`, which uses it as the default
linker. `weld --version` prints `weld 0.2.3` for this release.

Output formats live in `src/emit/`: ELF, PE and Mach-O.

## Static linking

`-static` links freestanding ELF executables and static archives. Archive dependency
cycles resolve inside `--start-group` / `--end-group`. Without the group, a cycle across
archives fails with `weld: undefined symbol <name>`.

Static library lookup uses `.a` files only. Output is `ET_EXEC` with no interpreter and
no dynamic symbol tables. `.init_array`, `.fini_array` and `.preinit_array` are kept for
startup code to run.

Static glibc linking is not supported. Linking against glibc's static `libc.a` fails with
`weld: static GNU IFUNC is not supported: <name>`. A static IFUNC needs resolver stubs and
IRELATIVE startup relocations, which weld does not supply yet. This check runs before the
output file is created.

## TLS

`.tdata` and `.tbss` are laid out under `PT_TLS`. The local-exec and initial-exec
relocations are applied against the thread pointer. Global-dynamic sequences are relaxed
to local-exec.

Local-dynamic TLS is rejected with an error that names the relocation and section, for
example `weld: local dynamic TLS is not supported (R_X86_64_TLSLD in section .text); use
-ftls-model=global-dynamic or local-exec`.

## Inputs and symbols

GCC LTO objects are rejected with `weld: GCC LTO is not supported`. The message does not
name the file.

Unresolved strong symbols are link errors: `weld: undefined symbol <name>`. Unresolved
weak symbols are allowed.
