# weld
Cross-platform Liner from the Lamina project

`-static` supports freestanding ELF executables and static archives, including
archive dependency cycles inside `--start-group` / `--end-group`. Static library
lookup uses `.a` files exclusively. Output uses `ET_EXEC` without an interpreter
or dynamic symbol tables; `.init_array` and `.fini_array` are preserved for startup
code to execute.

Static glibc linking remains unsupported. Inputs requiring GNU IFUNC resolvers
fail before output is created; static IFUNC needs resolver stubs and IRELATIVE
startup relocation tables, which weld does not yet supply. TLS is supported:
`.tdata` and `.tbss` are laid out under `PT_TLS`, local-exec and initial-exec
relocations are applied against the thread pointer, and global-dynamic sequences
relax to local-exec. Local-dynamic TLS and thread-local symbols imported from a
shared library are rejected with an error. GCC LTO inputs also fail explicitly
with their input filename. Unresolved strong symbols are link errors;
unresolved weak symbols remain permitted.
