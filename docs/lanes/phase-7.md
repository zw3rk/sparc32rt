# Phase 7 Task Cards — Hardening (`sparc32rt`, `RC-H`)

Run after `RC6` is merged to `master`. All lanes code against SPEC §7
(residuals), the frozen headers, and phases 0–6. No lane edits frozen
headers or another lane's exclusive files except the explicit hook
hunks below. Curated C11, every file ≤ 900 lines, never read/write
`x18`, guest memory only via the `G`-window helpers.

## Frozen cross-lane contracts

1. **W^X is structural**: guest data pages are never `PROT_EXEC` on
   the host; AArch64 code goes to RW staging/pages, flips to
   `PROT_READ|PROT_EXEC`, and flushes I-cache before execution.
   SMC tests must `mprotect` a guest page +EXEC explicitly before
   executing rewritten code (and back), matching what real JITs do.
2. **Fetch-X is enforced on both engines** (RC6 R1/R8): executing a
   non-EXEC page faults (`EXIT_FAULT` → sync SIGSEGV path). SMC
   without `+PROT_EXEC` must fault, not silently run stale code.
3. **SMC invalidation exists** (`vm_invalidate_jit` →
   whole-cache `dbt_flush` on mmap/mprotect/munmap/guest writes);
   H1 proves it end-to-end (stale-block re-execution is a FAIL).
4. **No V8 sysroot exists in this environment** (Phase 5 finding:
   no `pkgsCross.sparc*` target, glibc refuses `sparc-linux`,
   Debian userland is `EM_SPARC32PLUS`+V9 and correctly rejected).
   H2/H4 lanes must verify against `qemu-sparc -cpu LEON3` whatever
   runs, obey the loader, and document un-runnable parts precisely
   instead of weakening any gate. Host-side logic checks
   (`cc -std=c11`, `check_abi_invariants`-style) are supporting
   evidence, never oracle substitutes.
5. **Performance claims require the 6-step loop** (Instrument →
   Measure → Hypothesise → Fix → Measure again → Validate) with
   numbers in `docs/h3-coremark.md`; a single before/after pair is
   not a validated claim. `dbt > interp` must hold on the committed
   CoreMark configuration.

---

### Lane `H1` — self-modifying code & W^X (`tests/test_h1_smc.c`)

- **Worktree**: `../sparc32rt-h1` on branch `lane/p7-h1`
- **Exclusive files**: `tests/test_h1_smc.c` (new, freestanding);
  `src/dbt/dbt.c` hook hunk ONLY for a missing invalidation call
  site if the gate proves one (document the exactdivergence first).
- **Task**: rewrite guest instructions on stack, heap, and
  anonymous-`mmap` pages; `mprotect` +EXEC; flush (guest
  `flushw`? no — `mprotect` barrier semantics); re-execute and
  verify the NEW bytes run on `--interp` AND `--dbt`; then remove
  EXEC and verify both fault. Cover: rewrite inside the currently
  executing translation (self-patch a later block), cross-page
  rewrite, and write-while-executing (racy by design — assert
  *eventual* consistency: after the write completes + invalidate,
  100/100 re-executions run new code).
- **Acceptance**: exit 0 with deterministic stdout on
  `qemu-sparc -cpu LEON3`, `--interp`, `--dbt`; 0 stale-block
  executions observed.

---

### Lane `H2` — target `libc-test` + LTP subset (`docs/h2-report.md`)

- **Worktree**: `../sparc32rt-h2` on branch `lane/p7-h2`
- **Exclusive files**: `docs/h2-report.md` (new, the gate artifact);
  test harness files under `tests/` ONLY if freestanding and
  V8-clean (no libc-linked V8 binaries exist here).
- **Task**: run every runnable piece of the target `libc-test`
  (math, string, pthread, signal, functional) and the LTP syscall
  subset that V8 freestanding harnesses can express; for each,
  report pass/skip/fail with the oracle command. Where the V8
  sysroot blocks execution, port the *assertions* into freestanding
  guests (oracle-verified) and mark the libc-linked originals
  `SKIP-sysroot` with the Phase-5 proof linked. Commit
  `docs/h2-report.md` with machine-enforced pass/skip/fail
  assertions: `0` unexpected failures, every skip justified by
  evidence (contract §4).
- **Acceptance**: `docs/h2-report.md` committed with a full table;
  every `fail` is either fixed in-tree (with the fix + gate proof)
  or an explicit unresolved escalation with oracle evidence.

---

### Lane `H3` — instrumented CoreMark (`docs/h3-coremark.md`)

- **Worktree**: `../sparc32rt-h3` on branch `lane/p7-h3`
- **Exclusive files**: `docs/h3-coremark.md` (new),
  `tests/test_h3_coremark.*` (new only if a freestanding harness
  is needed; prefer an existing V8-clean CoreMark port if one
  builds with the freestanding recipe).
- **Task**: follow the mandatory 6-step loop and commit
  `docs/h3-coremark.md` demonstrating verified `dbt > interp`
  throughput on the committed configuration (exact build flags,
  iteration counts, medians over ≥3 runs each, host load notes).
  If CoreMark cannot build V8-clean here, say so with the exact
  blocker and substitute the closest honest throughput comparison
  available (e.g. `test_p1_isa`/`test_p3_fp_simd` steady-state
  loops under `--interp` vs `--dbt`), clearly labeled.
- **Acceptance**: `docs/h3-coremark.md` with numbers proving the
  claimed direction, or a documented blocker + substitute with the
  same rigor.

---

### Lane `H4` — C++17 (`tests/test_h4_cxx17.cc`)

- **Worktree**: `../sparc32rt-h4` on branch `lane/p7-h4`
- **Exclusive files**: `tests/test_h4_cxx17.cc` (new).
- **Task**: compile and verify a C++17 binary exercising
  `try`/`catch` stack unwinding across signal/call frames,
  `dynamic_cast` RTTI, `std::thread`, and `thread_local`
  destructors. This needs a V8 C++ toolchain + libstdc++ that does
  not exist here (contract §4); investigate realistically
  ( freestanding `-ffreestanding -fno-exceptions` subset? a minimal
  `libstdc++` build? ), verify whatever builds against
  `qemu-sparc -cpu LEON3` + both engines, and document the rest as
  explicit unresolved scope with the exact missing piece — do not
  fake C++ semantics with C constructs and call it done.
- **Acceptance**: every *committed* C++ feature verified on the
  oracle + both engines, OR a documented negative with the precise
  toolchain gap and a host-logic check proving the test itself is
  sound.

---

### Escalation rule

A lane stops and reports to the Coordinator when its acceptance fails
twice, when it needs an edit outside its exclusive files + hook
hunks (especially any frozen header), or when oracle behavior
contradicts a frozen contract above. Documented negatives (contract
§4) are completed work, not failures — but they must name the exact
missing piece and the attempted alternatives.
