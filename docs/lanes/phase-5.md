# Phase 5 Task Cards — Dynamic Linking (`PT_INTERP`), BusyBox, Target `libc` Matrix (`sparc32rt`)

Run after `RC4` is merged to `master`. All lanes code against SPEC §5,
the frozen headers, and `docs/lanes/phase-*.md` 0–4. No lane edits
frozen headers or another lane's exclusive files except the explicit
hook hunks below. Curated C11, every file ≤ 900 lines, never read/write
`x18`, guest memory only via the `G`-window helpers.

## Frozen cross-lane contracts

1. The interpreter loads at `0x3F000000+` (existing `rt32_elf_load`
   behavior, `interp_base`/`interp_bias` in `ctx`); `AT_ENTRY` is the
   APP entry, `AT_BASE` the interpreter base, `AT_PHDR`/`PHENT`/`PHNUM`
   the APP's.
2. auxv already carries `PHDR/PHENT/PHNUM/PAGESZ/FLAGS/ENTRY/UID/
   EUID/GID/EGID/HWCAP/CLKTCK/SECURE/RANDOM/EXECFN` (`stack32.c`);
   L5a adds exactly `AT_BASE` (value 4) and `AT_HWCAP2` (value 26,
   value 0 until a V8 HWCAP2 bit is defined) without disturbing slots.
3. `/proc/self/{exe,maps,cmdline,stat,auxv}` interception happens in
   the `openat`/`readlink` path (`syscalls.c`), served from translator
   state (guest mappings, `argv`, `auxv` snapshot) — never the host's.
   `oom_score_adj` stays passthrough (Phase-4 finding).
4. Dynamic V8 userland must come from a real sysroot
   (`sparc-linux-gnu`, pure `EM_SPARC`): the oracle image's Debian
   `sparc64` toolchain links `EM_SPARC32PLUS` with `BPcc`/V9 encodings
   (RC2/RC4 finding) and is NOT admissible input. Network works in
   this environment (`curl` reaches caches); try a nix-provided
   `sparc-linux-gnu` toolchain first, document exactly what was
   tried if it is unobtainable.

---

### Lane `L5a` — loader, auxv, `/proc/self` (`src/rt32/`, `src/os/`)

- **Worktree**: `../sparc32rt-l5a` on branch `lane/p5-l5a`
- **Exclusive files**: `src/rt32/elf32.c`, `src/rt32/stack32.c`
  (extend), `src/rt32/procfs.c` + `src/rt32/procfs.h` (new,
  `/proc/self` content builders).
- **Explicit hook hunks**: `src/os/syscalls.c` `openat`/`readlink`
  interception point ONLY (route `/proc/self/*` to `procfs.c`;
  everything else falls through untouched).
- **Task**:
  1. `AT_BASE` + `AT_HWCAP2` in the auxv builder (grow the 34-entry
     table, keep 16-alignment + `AT_NULL` terminator).
  2. Verify `AT_ENTRY` is the app entry and `AT_PHDR` the app
     phdrs when `PT_INTERP` is present (fix the wiring if the
     interpreter's values leak in); `AT_EXECFN` = guest argv[0].
  3. `/proc/self/{exe,maps,cmdline,stat,auxv}`: `exe` → guest
     path (symlink semantics via `readlink`), `maps` → guest
     region table, `cmdline` → guest `argv` (NUL-joined),
     `stat` → minimal fields (pid/comm/state), `auxv` → the exact
     auxv bytes handed to the guest.
  4. Synthetic `PT_INTERP` test (no libc needed): hand-assemble a
     tiny `PT_INTERP` ELF whose interpreter path names a V8-clean
     freestanding probe; assert both images map, `AT_BASE` set,
     and the interpreter entry runs first under
     `qemu-sparc -cpu LEON3` AND `--interp`/`--dbt` (byte-identical
     stdout).
  5. Static-binary auxv/`procfs` self-inspection test
     (`tests/test_p5_auxv.c`, freestanding): dump own auxv
     (`AT_PHDR/ENTRY/BASE/HWCAP`), read own
     `/proc/self/{cmdline,maps,auxv}`, compare against loader-known
     values; must pass on oracle + both engines.
- **Acceptance** (inside `sparc32rt-oracle` container): synthetic
  `PT_INTERP` pair + `test_p5_auxv` exit 0 with deterministic,
  oracle-identical stdout on `qemu-sparc -cpu LEON3`, `--interp`,
  `--dbt`; `make check` clean.

---

### Lane `L5b` — dynamic `libc` matrix (`tests/`, sysroot)

- **Worktree**: `../sparc32rt-l5b` on branch `lane/p5-l5b`
- **Exclusive files**: `tests/test_p5_dyn.c` (new, C with libc:
  `dlopen`/`dlsym`, `__thread` TLS, shared-library call),
  `tests/test_p5_dynlib.c` (new, the shared object),
  `docs/lanes/phase-5-sysroot.md` (new: what was tried, exact
  toolchain provenance, residual gaps).
- **Task**:
  1. Obtain a pure-V8 dynamic sysroot: try
     `nix shell nixpkgs#pkgsCross.sparc-linux-gnu.stdenv.cc`
     (record exact nixpkgs revision + store paths) or a
     `sparc-linux-gnu` libc build from source; document every
     attempt with commands + hashes in `phase-5-sysroot.md`.
     Fallback (only if the sysroot proves unobtainable): prove
     the negative — show the Debian-linked binary is
     `EM_SPARC32PLUS` and correctly rejected with `ENOEXEC`.
  2. With a V8 sysroot: build `test_p5_dyn` + `test_p5_dynlib`
     dynamic, verify `qemu-sparc -cpu LEON3` runs them, then verify
     `--interp`/`--dbt` byte-identical + `--difftest` 0.
  3. BusyBox: same sysroot, `sh -c 'ls / && echo ok | wc -c'`
     oracle-vs-both-engines.
- **Acceptance**: sysroot documented with provenance; dynamic
  binaries exit 0 with deterministic oracle-identical stdout on
  `qemu-sparc -cpu LEON3`, `--interp`, `--dbt`; `make check` clean.
  If the sysroot is unobtainable, acceptance is the documented
  negative (rejection proof + oracle outputs) plus an explicit
  `unresolved` escalation — do NOT weaken the loader to admit
  `EM_SPARC32PLUS`.

---

### Escalation rule

A lane stops and reports to the Coordinator when its acceptance fails
twice, when it needs an edit outside its exclusive files + hook
hunks (especially any frozen header), or when oracle behavior
contradicts a frozen contract above.
