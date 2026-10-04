# weld
Cross-platform Liner from the Lamina project

`-static` supports freestanding ELF executables and static archives, including
archive dependency cycles inside `--start-group` / `--end-group`. Static library
lookup uses `.a` files exclusively. Output uses `ET_EXEC` without an interpreter
or dynamic symbol tables; `.init_array` and `.fini_array` are preserved for startup
code to execute.

Static glibc linking remains unsupported. Inputs requiring TLS (`.tdata` / `.tbss`)
or GNU IFUNC resolvers fail before output is created. TLS needs segment layout,
`PT_TLS`, and thread-pointer relocations; static IFUNC needs resolver stubs and
IRELATIVE startup relocation tables. Weld does not yet supply these facilities.
GCC LTO inputs also fail explicitly with their input filename. Unresolved strong
symbols are link errors; unresolved weak symbols remain permitted.
