# Phase 4 Task Cards — Signals & Threads (`sparc32rt`)

Run after `RC3` is merged to `master`. All lanes code against SPEC §4,
the frozen headers, `experiments/E04/FINDINGS.md`,
`experiments/E05/FINDINGS.md`, and `src/interp/interp_signal.c` (153
lines, RC1 sync delivery — read it first). No lane edits frozen
headers or another lane's exclusive files except the explicit hook
hunks below. Curated C11, every file ≤ 900 lines, never read/write
`x18`, guest memory only via the `G`-window helpers.

## Frozen cross-lane contracts

1. **E04 conventions** (oracle-pinned): `ta 0x10`, nr in `%g1`, carry
   error convention; `pipe(42)` is SPARC dual-return (`%o0`=read end,
   `%o1`=write end, no pointer arg); `fork(2)` dual-return (parent
   `%o0`=child pid/`%o1`=0, child `%o0`=`%o1`=0); `wait4(7)` reaps
   with `status=0x700` shape for `exit(0)`.
2. **Signal frame** (`os/sigframe_sparc32rt.h`, frozen): 344 B
   16-aligned `rt_signal_frame32`, `%sp`=frame, `%o0`=signo,
   `%o1`=`&siginfo`, `%o2`=`&regs`, `%o7`=restorer; `si_addr` =
   fault address, `si_code` 2-in-mapped/1-unmapped; `sigreturn(216)`
   reads `pc`/`npc` at frame+100/+104.
3. **Thread model**: guest threads are host `pthread`s sharing one
   process (hence one `G`-window mapping). `ctx` (regs/fpu/wim/`%g7`
   TLS base) is per-thread; `regions` page table is shared under the
   existing `CLONE_VM` lock (`vm.c`); signal dispositions are
   process-wide (make `syscalls.c` signal state thread-safe; the
   `file-static (single-thread)` mask comment goes away).
4. **TLS**: SPARC thread pointer is `%g7` (a `ctx` field, never host
   `x18`/`TPIDR`). `CLONE_SETTLS` delivers the base; static binaries
   without explicit setup keep the loader-provided value.
5. **Async delivery**: host handlers only set a per-thread pending
   flag (async-signal-safe, no `longjmp` out of translated code).
   Delivery happens at safe points only: `interp` checks the flag
   every step; `dbt` checks at block entry/exit (dispatcher loop).
   Synchronous faults keep the `D18` `safe_syscall` window path.
6. **`_Thread_local`** (C11 keyword, not `<threads.h>`) is allowed
   for former process-globals that must become per-thread (e.g.
   `interp_wim`); verify with `musl static-pie` link + threaded test.
7. **qemu `-strace`** is the oracle for argument conventions
   (`clone` arg order, signal numbers); use it before guessing.

---

### Lane `L4a` — clone/fork/execve/async signals (`src/os/threads.c`)

- **Worktree**: `../sparc32rt-l4a` on branch `lane/p4-l4a`
- **Exclusive files**: `src/os/threads.c`, `src/os/threads.h` (new:
  thread/process machinery), `src/interp/interp_signal.c` (extend:
  async pending-flag delivery; keep the sync path byte-identical).
- **Explicit hook hunks**: `src/os/syscalls_min.c` — new `case`
  arms only (`fork`, `pipe`, `pipe2`, `wait4`, `waitpid`, `clone`,
  `vfork`, `execve`, `set_tid_address` completion, `kill`/`tgkill`
  if needed).
- **Task**:
  1. `pipe`/`pipe2` (SPARC dual-return), `fork` (host `fork(2)`;
     child `%o0`=`%o1`=0; DBT cache survives as shared mappings),
     `wait4`/`waitpid`, `vfork` (as `fork` + document, or trap with
     oracle evidence), `execve` (reload ELF into the same window,
     reset regs/signals/threads).
  2. `clone` with the qemu-observed arg convention (`-strace`
     first): thread creation via `pthread` (shared window), exit
     via `clear_child_tid` + `futex` wake, `CLONE_SETTLS` → `%g7`,
     `CLONE_PARENT_SETTID`/`CHILD_CLEARTID` bookkeeping.
  3. Async delivery: pending-flag set + safe-point checks in
     `interp` (every step) with `sigmask`/`sigpending` semantics;
     `rt_sigprocmask`/`rt_sigpending`/`rt_sigsuspend` complete.
  4. Thread-safety: signal disposition table + mask state locking;
     `interp_wim` → `_Thread_local` (or per-`ctx` if feasible
     without header edits — escalate if a header edit is required).
- **Acceptance** (inside `sparc32rt-oracle` container):
  ```sh
  sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static -o /tmp/e04 experiments/E04/probe.S && qemu-sparc -cpu LEON3 /tmp/e04 > /tmp/q.out 2>&1
  /w/_build/sparc32rt --interp -- /tmp/e04 > /tmp/i.out 2>&1; cmp /tmp/q.out /tmp/i.out
  ```
  plus E05 `--interp` matches oracle (sync path unbroken) and
  integer/FP no-regression (`t1`/`tsys`/`t3` `--difftest` 0).

---

### Lane `L4b` — thread entry & signal windows (`src/rt32/`)

- **Worktree**: `../sparc32rt-l4b` on branch `lane/p4-l4b`
- **Exclusive files**: `src/rt32/safe_syscall_a64.S` (extend),
  `src/rt32/thread_entry.S` (new, only if a separate trampoline is
  needed — justify in the commit message).
- **Task**:
  1. Host-thread entry: new `pthread` starts in translated code
     with the correct `x20` (`G`), `x19` (`ctx`), cleared NZCV
     (except deliberate flag inputs), and 16-aligned SP; exit path
     reports the guest exit reason identically to the main
     dispatcher entry.
  2. Keep the `D18` signal window semantics for sync faults on ANY
     thread; async host signals never interrupt translated code
     except through the pending-flag protocol (mask around
     translated regions where the kernel allows).
  3. Never touch `x18`; document the register contract at the top
     of the file.
- **Acceptance**: cross-build clean + `make check-line-limits`;
  a host-`cc` unit test (new file under `tests/`, e.g.
  `tests/check_thread_entry.c` following the
  `check_abi_invariants.c` pattern) proving entry/exit register
  conventions; `--dbt` no-regression on `t1`/`tsys`/`t3`
  (translator still runs single-threaded guests identically).
  Full threaded-`dbt` proof is the Coordinator's `RC4` gate.

---

### Lane `L4c` — threading/async tests + rlimit/oom (`tests/`)

- **Worktree**: `../sparc32rt-l4c` on branch `lane/p4-l4c`
- **Exclusive files**: `tests/test_p4_threads.c`,
  `tests/test_p4_async.c` (new, freestanding asm style).
- **Task**:
  1. `test_p4_threads`: `clone` thread + shared-memory counter
     (both threads increment; deterministic join + exact expected
     total), `%g7` TLS independence (each thread writes its own
     value, reads it back after the sibling ran), `futex`
     wait/wake rendezvous, `fork`+`wait4` round-trip (E04 shape),
     deterministic stdout.
  2. `test_p4_async`: `rt_sigaction` + self-`kill`/`setitimer`
     handler-flag test (async delivery observed, exact flag count),
     `sigprocmask` block/unblock ordering, `sigsuspend` wake.
  3. **RLIMIT_AS + oom-score-adj**: probe under
     `qemu-sparc -cpu LEON3` (`prlimit64`/`getrlimit` values,
     `/proc/self/oom_score_adj` read/write behavior), document the
     oracle behavior, fix `prlimit64`/`getrlimit` mapping if it
     deviates, and prove no regression (or fix `oom_score_adj`
     passthrough if it faults).
- **Acceptance** (inside `sparc32rt-oracle` container):
  ```sh
  sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static -o /tmp/t4t tests/test_p4_threads.c && qemu-sparc -cpu LEON3 /tmp/t4t
  sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static -o /tmp/t4a tests/test_p4_async.c && qemu-sparc -cpu LEON3 /tmp/t4a
  ```
  both exit 0 with deterministic stdout. Translator parity is the
  Coordinator's `RC4` gate.

---

### Escalation rule

A lane stops and reports to the Coordinator when its acceptance fails
twice, when it needs an edit outside its exclusive files + hook
hunks (especially any frozen header), or when oracle behavior
contradicts a frozen contract above.

---

### RC4 Sign-off (Coordinator, on `master`)

- **Merges**: `lane/p4-l4a` (threads/signals), `lane/p4-l4b`
  (thread entry/host test), `lane/p4-l4c` (threading/async guests,
  rlimit mapping) — all `--no-ff` (`syscalls_min.c` conflict
  resolved by taking L4c's rlimit hunk).
- **RC4 integration fixes** (Coordinator-level, found by the RC4 gate):
  1. `+100/+104` compat mirror in async frame builds (async handlers
     return without patching, unlike L1d/E05-style handlers).
  2. Late async delivery (tail commits first, poll delivers next):
     kill/tkill/tgkill drop in-dispatch delivery so handler `%o0`
     is not clobbered; sigsuspend keeps in-dispatch delivery (its
     test asserts the handler ran before return) with the tail
     committing `O0=EINTR/C=1` over it.
  3. `interp_poll_async` wired at `interp_step` top + `dbt` block
     entry + `dbt_step` pre-exec (lockstep-aligned); the dbt
     chain-break on pending removed (it stranded `main` in a stop).
  4. Thread-entry loop re-arms `exit_reason=NONE` after dispatch
     (else the first syscall re-dispatches forever, marching `pc`).
  5. `CLONE_SYSVSEM` accepted (qemu requires it); `setitimer(83)`
     `ITIMER_REAL` via host timer; SPARC `rt_sigprocmask` how 1/2/4
     (L2a used generic 0/1/2); `sparc32_signal_reset_all` on execve;
     `execve` split to `src/os/threads_exec.c` (900-line rule).
- **Gate evidence** (`sparc32rt-oracle`, `qemu-sparc -cpu LEON3`,
  all exit 0): `test_p4_threads` + `test_p4_async` pass functionally
  identical to oracle on `interp` and `dbt` (`t4t` multiset-identical
  modulo fork-print interleave, which varies even qemu-vs-qemu);
  E04 matches modulo pids, E05 structurally
  (stack addresses differ); `t1`/`tsys`/`t3`/E06 unchanged
  (byte-identical, E06 single documented `RD` line); difftest
  `0` divergences on `t1` (6170), `tsys` (844), `t3` (8997),
  E04 (1254), E05 (12218), `t4t` (1186). `t4a` difftest diverges:
  wall-clock SIGALRM delivery point differs per engine (functional
  parity holds on both). `make check` passes; L4b host test passes
  natively.
- **Residuals**: threaded `dbt` runs guest threads on the interp
  loop (correctness first; DBT-threaded execution is H3 scope);
  `RLIMIT_AS`/`oom_score_adj` probed per L4c (passthrough, no
  mapping needed); arithmetic `RD≠RN` still RN (Phase 3 residual).
