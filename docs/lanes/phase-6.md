# Phase 6 Task Cards — `hyper-linux` Host Contract & Dual-Host Parity (`sparc32rt`)

Run after `RC5` is merged to `master`. All lanes code against
[`../rt-series/docs/HOST-CONTRACT.md`](../rt-series/docs/HOST-CONTRACT.md)
(Class-A 32-bit), the frozen headers, and phases 0–5. No lane edits
frozen headers or another lane's exclusive files except the explicit
hook hunks below. Curated C11, every file ≤ 900 lines, never read/write
`x18`, guest memory only via the `G`-window helpers.

## Frozen cross-lane contracts

1. **Class-A window**: `[G, G + 4 GiB)` with `G = 0` on native Linux
   or `G = 0x1_0000_0000` under `hyper-linux` (`/dev/a32host`
   `A32H_GET_INFO = 0x81006101`, `window_hint = 0x100000000`;
   `A32H_ABI_MAJOR` must be 1, any 1.x minor accepted).
   `SPARC32RT_HOST=none` opts out of the handshake (existing).
2. **Three-layer page contract** (§2.1): `AT_PAGESZ = 4096`;
   `mmap`/`mmap2` unaligned-`MAP_FIXED` addr/offset or `len == 0`
   → `-EINVAL`, positive `len` rounds up; `mprotect`/`munmap`
   unaligned addr → `-EINVAL`, `munmap len == 0` → `-EINVAL`,
   `mprotect len == 0` → success no-op; `mremap` unaligned
   old/new (FIXED) addr or `new_size == 0` → `-EINVAL`, sizes round
   up; `brk` keeps byte-exact `current_brk` with 4 KiB backing.
3. **Adjacent 4 KiB mappings with distinct permissions** must behave
   identically on native Linux and `hyper-linux` (stage-1 AP/UXN
   splits); `PT_GNU_RELRO` next to `.bss` is the canonical probe.
4. **CLI/env surface**: `--engine`, `--window`/`SPARC32RT_WINDOW`,
   `--sysroot`/`SPARC32RT_SYSROOT`, `--trace`, `--difftest`,
   `-- <guest> [args...]`. New flags (`--execfn`, `--image-fd`)
   only if the contract requires them for the harness — justify in
   the commit message, keep `main.c` parsing table-driven.
5. **No `hyper-linux` headers or host libraries** — coordination only
   through auxv/env/CLI/`/dev/a32host` at runtime. The oracle
   container has no `/dev/a32host`: native-Linux behavior is the
   tested path; `hl`-specific paths are verified by construction
   (constants, handshake flow) + documented residuals.

---

### Lane `L6a` — host-contract compliance audit (`src/rt32/`, `src/os/`)

- **Worktree**: `../sparc32rt-l6a` on branch `lane/p6-l6a`
- **Exclusive files**: `src/rt32/host.c` (extend),
  `src/rt32/vm_mmap.c` (extend), `src/os/syscalls_min.c` (hook
  hunks only: new `case` arms for any missing contract syscall).
- **Task**:
  1. Audit every §2.1 rule against `vm_mmap.c`/`syscalls.c` with a
     freestanding probe guest (`tests/test_p6_mmap.c`, new):
     unaligned `MAP_FIXED` addr/offset, `len == 0` (each call),
     `mprotect len == 0` no-op-success, `mremap` unaligned/new_size
     0, `brk` byte-exactness across page boundaries. Fix deviations
     (missing `-EINVAL`, missing round-up, `brk` page-half bugs).
  2. `mremap` fixed-moves + `MREMAP_MAYMOVE` growth covered by the
     same probe (oracle-compared where qemu implements it;
     document qemu gaps explicitly).
  3. `--window` with `0x1_0000_0000` accepted + mapped (probe:
     guest reads its own auxv/stack to confirm the window base
     semantics where observable); `SPARC32RT_HOST=none` still
     bypasses; handshake constants byte-matched to
     `include/a32host.h` (no magic numbers in code).
  4. CoW fork snapshot: document what happens today when
     `has_host_info` would be set (native Linux has no host —
     fork copies mappings); implement only what the contract
     mandates for correctness on native Linux, mark `hl`-only
     behavior as residual with justification.
- **Acceptance**: `tests/test_p6_mmap.c` exits 0 with deterministic
  oracle-identical stdout on `qemu-sparc -cpu LEON3`, `--interp`,
  `--dbt`; `make check` clean.

---

### Lane `L6b` — parity suite + 4 KiB adjacency (`tests/`)

- **Worktree**: `../sparc32rt-l6b` on branch `lane/p6-l6b`
- **Exclusive files**: `tests/test_p6_adjacent.c` (new,
  freestanding), `docs/lanes/phase-6-parity.md` (new: gate matrix).
- **Task**:
  1. Adjacent-4 KiB probe: `PROT_READ|PROT_EXEC` page next to
     `PROT_READ|PROT_WRITE` page (execute-near-write, write-near-execute
     fault expectations), `PROT_NONE` guard between two RW pages,
     `PT_GNU_RELRO`-style RELRO-then-`.bss` layout via a linked
     section pair; each expectation oracle-verified.
  2. Full parity sweep (single script, recorded in the report):
     `test_p1_isa`, `test_p2_sys`, `test_p3_fp_simd`,
     `tests/test_p4_*`, `tests/test_p5_*`, `test_p6_mmap`,
     `test_p6_adjacent`, `experiments/E0[1-6]` — every binary on
     (`qemu-sparc -cpu LEON3`, `--interp`, `--dbt`) plus
     `--difftest` 0-divergence where deterministic (exclude
     wall-clock `t4a`; fork-interleave `t4t`/`E04` multiset-only).
  3. Write `docs/lanes/phase-6-parity.md`: per-test table
     (oracle/interp/dbt/difftest verdicts + step counts), residual
     list with evidence, no green claims without command output.
- **Acceptance**: `test_p6_adjacent` exit 0 oracle-identical on all
  three engines; `phase-6-parity.md` committed with the full matrix
  (every cell backed by an observed run, not inferred).

---

### Escalation rule

A lane stops and reports to the Coordinator when its acceptance fails
twice, when it needs an edit outside its exclusive files + hook
hunks (especially any frozen header), or when oracle behavior
contradicts a frozen contract above.

---

### RC6 Sign-off (Coordinator, on `master`)

- **Merges**: `lane/p6-l6a` (mmap contract probe + mremap dispatch),
  `lane/p6-l6b` (adjacent-4KiB probe + parity matrix) — both
  `--no-ff`, no conflicts.
- **RC6 integration** (Coordinator-level):
  1. Fetch-X enforcement (L6b residual R1): the shared
     `sparc32_fetch_decode` region gate now requires `PROT_EXEC`
     as well as `PROT_READ`, so both engines fault
     (`EXIT_FAULT` → sync SIGSEGV path) instead of silently
     executing RW pages. No existing test executes from a
     non-EXEC page (full gate re-verified green).
  2. `test_p6_mmap` swept into the parity matrix (was R7 pending).
- **Gate evidence** (`sparc32rt-oracle`, all exit 0):
  full Phase 0–5 suite green on `qemu-sparc -cpu LEON3`,
  `--interp`, `--dbt`: `test_p1_isa`, `test_p2_sys`,
  `test_p3_fp_simd`, `test_p4_threads`, `test_p4_async`,
  `test_p5_auxv`, `test_p5_app`+interp, `test_p6_mmap`,
  `test_p6_adjacent`, E01–E06; difftest `0` divergences on all
  deterministic suites (`t4a` excluded: wall-clock SIGALRM;
  E04/`t4t` multiset-only: fork-print interleave varies even
  qemu-vs-qemu). `make check` + L4b host test pass natively.
- **Residuals**: `hl`-only paths (stage-1 AP/UXN splits,
  CoW-fork snapshot cooperation beyond native `fork` duplication)
  are construction-verified, not runtime-verified (no `hl` host
  here); dynamic `dlopen`/`DT_NEEDED` loading still unimplemented
  (Phase 5 residual); `t4a` excluded from difftest (wall-clock).
