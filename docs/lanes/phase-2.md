# Phase 2 Task Cards — Static Libc Syscalls & Base Integer AArch64 DBT (`sparc32rt`)

Run after `RC1` is merged to `master`. All lanes code against SPEC §2-§3
and the Phase-0/1 frozen headers plus the Phase-1 engines
(`src/interp/decode.h`, `src/interp/interp.h`, `src/os/syscalls_min.h`).
No lane may edit frozen files or another lane's exclusive files (escalate).
Curated C11, every file ≤ 900 lines, never read/write `x18`, W^X for all
emitted code, guest memory only via the `G`-window helpers.

`main.c` wiring (`--dbt`, `--difftest` run paths) is Coordinator-owned and
happens after the merge; lanes expose library entry points only and must
not edit `src/main.c`, `Makefile`, or `flake.nix`.

---

### Lane `L2a` — Static-libc syscall & struct conversion layer
- **Worktree**: `../sparc32rt-l2a` on branch `lane/p2-l2a`
- **Exclusive Files**: `src/os/syscalls.c`, plus explicitly allowed
  extension of the `L1c` dispatch table in `src/os/syscalls_min.c`
  (additive cases only; do not restructure it)
- **Task**:
  1. New file `src/os/syscalls.c`: struct conversions + the static-libc
     set — `stat`/`stat64`/`statx` (fill the Linux layouts from host
     `fstatat64`/`statx`, error-mapped), `readv`/`writev` (`iovec` chains),
     `openat` (+ `open`/`creat` wrappers), `fcntl` (`F_DUPFD`, `F_GETFD`,
     `F_SETFD`, `F_GETFL`, `F_SETFL(O_NONBLOCK|O_APPEND)`; reject the rest
     with `EINVAL`), `clock_gettime` (`CLOCK_REALTIME`/`MONOTONIC` via host,
     64-bit `tv_sec`), `getrandom` (host call, honour flags), `futex`
     (`FUTEX_WAIT`/`FUTEX_WAKE` via host futex, single-threaded fast path),
     `rt_sigprocmask` (blocked-mask bookkeeping; delivery itself stays
     Phase 1/4 machinery), `ioctl` (`FIONREAD` + `TCGETS`-isatty query,
     `ENOTTY` otherwise), `lseek`, `getpid`/`getuid`/`geteuid`/`getgid`/
     `getegid`, `close` (move the RC1 `close` case here if cleaner, keeping
     behaviour identical).
  2. Blocked-mask state: keep a file-static mask in `syscalls.c`
     (single-threaded Phase 1–2 assumption, documented); do NOT touch the
     frozen `sparc32_ctx_t` layout.
  3. Reuse the `L1c` carry convention + `sparc_errno_from_host` mapping;
     every guest pointer translated through the `G` window (no host
     pointer leaks), unmapped structs -> `EFAULT`.
- **Acceptance Command** (from worktree root):
  ```sh
  cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Iinclude -Isrc -c src/os/syscalls.c -o /tmp/syscalls.o
  ```

---

### Lane `L2b` — AArch64 DBT core (dispatcher, block cache, IBTC, RAS)
- **Worktree**: `../sparc32rt-l2b` on branch `lane/p2-l2b`
- **Exclusive Files**: `src/dbt/dbt.h`, `src/dbt/dbt.c`,
  `src/dbt/trampoline_a64.S`
- **Task**:
  1. Block cache keyed by guest PC (up to 64 guest insns per block,
     terminating at control transfers or guest page boundaries), emitted
     into RW staging pages flipped to `PROT_READ | PROT_EXEC` with an
     I-cache flush before execution; never map guest data pages `PROT_EXEC`;
     never touch `x18`.
  2. Dispatcher with direct block chaining, a 4096-entry Indirect Branch
     Target Cache (IBTC) and a Return Address Stack (RAS).
  3. Two execution entries with identical exit-reason protocol as
     `interp_run`/`interp_step` (`SPARC32_EXIT_*`, `fault_addr`,
     `exit_dest`):
     `int dbt_run(sparc32_ctx_t *ctx)` (cached, chained fast path) and
     `int dbt_step(sparc32_ctx_t *ctx)` (translate+execute exactly one
     guest instruction, no chaining — the `--difftest` oracle stepping
     stone; correctness over speed).
  4. Fallback: `EXIT_UNDEF` / `EXIT_SINGLE_STEP` (and any unemitted class)
     calls `interp_step(ctx)` for that single instruction and resumes DBT
     afterwards, so valid instructions never abort execution.
  5. Emit calls go through `L2c`'s emitter interface (`src/dbt/emit_int.h`,
     which `L2c` owns — code against SPEC §2 + `decode.h`; if the interface
     shape blocks you, report unresolved instead of working around).
- **Acceptance Command**:
  ```sh
  cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Iinclude -Isrc -c src/dbt/dbt.c -o /tmp/dbt.o
  ```

---

### Lane `L2c` — AArch64 integer instruction emitter
- **Worktree**: `../sparc32rt-l2c` on branch `lane/p2-l2c`
- **Exclusive Files**: `src/dbt/emit_int.h`, `src/dbt/emit_int.c`
  (and `src/dbt/emit_priv.h` if needed)
- **Task**:
  1. `emit_int.h` declares the emitter interface `L2b` consumes:
     per-class translate functions taking `(emit context, decoded insn)`
     and appending AArch64 to the code buffer (buffer management owned by
     `L2b`; the emitter never emits direct jumps to host addresses outside
     the buffer except via `L2b` chaining hooks).
  2. `emit_int.c` implements every SPEC §2 base-integer class the decoder
     produces: ALU/shifts/MUL/DIV (with `Y` threading + `icc` N/Z/V/C
     exactly as `interp` computes them, E03 table), branches/JMPL/CALL with
     delay slots + annul (E02), SAVE/RESTORE against the WIM backing-file
     model (E01: spill/fill via guest stack only on overflow/underflow),
     loads/stores/LDSTUB/SWAP/CASA per the manual (supervisor ASIs trap),
     `ta 0x10` exit to the dispatcher syscall gate, `STBAR` as nop,
     FPU/odd encodings as dispatcher fallback (never silently execute).
  3. Misaligned multi-byte data access must fault (SIGBUS path), matching
     `interp`/`qemu-sparc` — never emulate.
- **Acceptance Command**:
  ```sh
  cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Iinclude -Isrc -c src/dbt/emit_int.c -o /tmp/emit_int.o
  ```

---

### Lane `L2d` — Differential harness + static libc test suite
- **Worktree**: `../sparc32rt-l2d` on branch `lane/p2-l2d`
- **Exclusive Files**: `src/dbt/difftest.h`, `src/dbt/difftest.c`,
  `tests/test_p2_libc.c` (guest sources; binaries are build artifacts and
  stay untracked)
- **Task**:
  1. `difftest.{h,c}`: `int difftest_run(sparc32_ctx_t *ctx)` — lockstep
     `interp_step` vs `dbt_step` from the same loaded guest, comparing the
     full user-visible state after every instruction (`r[32]`, `pc`,
     `npc`, `psr.icc`, `y`, `fsr`, `f[32]`, `cwp` + WIM/backing-file
     state); prints `difftest: 0 divergences` on success or the first
     divergence (PC, differing fields, guest backtrace) and returns
     nonzero. Handles `EXIT_SYSCALL` by running the syscall once (shared
     handler, not per-engine) and resuming both engines.
  2. `tests/test_p2_libc.c`: static-libc guest exercising exactly
     `hello`, `printf` (int/%x/%s), `malloc`/`free`/`calloc`/`realloc`
     (including a 1 MiB block), `qsort` (10k ints, verified order), and
     file I/O (`openat`/`write`/`read`/`lseek`/`stat`/`close` round-trip of
     64 KiB, byte-compared). Deterministic stdout + `exit(0)`; must pass
     under `qemu-sparc -cpu LEON3` bit-for-bit (build with the target
     cross-CC `-static`; if static libc is unavailable in the oracle
     image, report unresolved instead of weakening the test).
- **Acceptance Command** (inside the `sparc32rt-oracle` container):
  ```sh
  sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static -o /tmp/t1 tests/test_p1_isa.c && qemu-sparc -cpu LEON3 /tmp/t1
  ```

---

### RC2 Sign-off (Coordinator, on `master`)

- **Page-final alignment fix** (`0x11ffc` `ba,a` divergence
  `interp=NONE` vs `dbt=SINGLE_STEP`): `dbt_replay` now clears
  `exit_reason` before the replayed `interp_step` (the annulled-away
  early return leaves it untouched); `emit_int.c`'s conditional
  page-final path completes annulled-not-taken transfers with a plain
  `BRANCH` exit instead of `SINGLE_STEP`; `difftest.c` documents the
  contract (`SINGLE_STEP` iff the delay ran, else `NONE` on both
  sides). `sparc32_dbt_invalidate_range` wired to whole-cache flush and
  `-DSPARC32RT_NO_DBT` dropped from `Makefile` (Phase-2-promised state).
- **L2a gap closed**: `unlink(10)` implemented (`syscalls.c` +
  dispatch) after `tests/test_p2_sys.c` exposed `-ENOSYS`.
- **Gate evidence** (`sparc32rt-oracle`, `qemu-sparc -cpu LEON3`):
  `test_p1_isa` — `interp`/`dbt` exit 0, byte-identical to oracle,
  `--difftest` reports `0 divergences (6170 steps)`;
  `tests/test_p2_sys.c` (new freestanding V8-only raw-syscall guest:
  `getpid`, `brk`, `mmap2`/`munmap`, `openat`/`write`/`close`/`stat`/
  `lseek`/`read`/`unlink`, `clock_gettime`, `getrandom`) —
  `interp`/`dbt` exit 0, byte-identical to oracle, `0 divergences
  (844 steps)`; `make check` (build + `<= 900` lines + ABI
  invariants) passes.
- **Known toolchain caveat**: the oracle image's `sparc64-linux-gnu`
  GCC links static libc as `EM_SPARC32PLUS` with `BPcc` encodings, so
  `tests/test_p2_libc.c` cannot execute under the V8-only SPEC oracle
  (correctly rejected with `ENOEXEC`; `qemu-sparc -cpu LEON3` SIGILLs
  on the same stream; both engines agree loudly with `UNDEF` at the
  first V9 encoding). Full C-libc qualification waits on the SPEC
  `sparc-linux-gnu` sysroot (Phase 5).
