# Phase 3 Task Cards — Floating-Point & SIMD (`sparc32rt`)

Run after `RC2` is merged to `master` (`f6b5128`). All lanes code against
SPEC §2, the frozen headers (`src/sparc32rt.h`: `f[32]`, `fsr` with `fcc`
bits 11:10; `src/os/syscall_nr.h`), the Phase-1/2 engines, and
`experiments/E06/FINDINGS.md` (oracle ground truth — read it first).
No lane edits frozen headers or another lane's exclusive files except the
explicit hook hunks listed below (escalate anything else). Curated C11,
every file ≤ 900 lines, never read/write `x18`, W^X for emitted code,
guest memory only via the `G`-window helpers.

`main.c` wiring is Coordinator-owned and untouched by lanes.

## Frozen cross-lane contracts (do not renegotiate; escalate on conflict)

1. **FSR**: full 32-bit storage, round-trips via `LDFSR`/`STFSR`.
   `fcc` = bits 11:10 (`0`=equal, `1`=less, `2`=greater, `3`=unordered).
   `RD` (rounding direction) = bits 31:30 (`0`=nearest `RN`,
   `1`=zero `RZ`, `2`=+inf `RP`, `3`=-inf `RM`).
2. **E06 oracle rules**: NaN payloads propagate unchanged; `0.0/0.0`
   → `0x7FFFFFFF_FFFFFFFF`; NaN-vs-number `FCMP` → `fcc=3`, `fsr`
   reads back `0xe00`; `FDTOI` under `RD=RN` rounds to nearest-even.
   qemu ignores `RD≠RN` (converts as `RN`): lanes implement `RD` per
   the V8 manual, the oracle test pins only `RN`, and `interp`-vs-`dbt`
   difftest proves `RD≠RN` parity.
3. **Strict traps (translator is manual-strict, test excludes them)**:
   even-pair-double-dest `FPop` with odd `rd` → `UNDEF` (E06 #8);
   quad (`FqTOd`, `FDMULq`, `LDQF`/`STQF` 0x22/0x26) → `UNDEF`.
   `difftest` needs no mask: both engines `UNDEF` identically.
4. **FBfcc transfer mirrors Bicc exactly** (dual-PC, delay executes
   unless annulled away, annulled-not-taken never fetches, page-final
   `(pc & 0xfff) == 0xffc` rule), except the condition evaluates
   `FSR.fcc`, not `PSR.icc`. `FBN` (cond 0) / `FBA` (cond 8) behave as
   `BN`/`BA`.
5. **Delay slots**: `FPop`/`FPMEM` in a delay slot EXECUTE (both
   engines); `FBRANCH`/CTI/`TRAP` in a delay slot keeps the pristine
   `SINGLE_STEP` fallback (dispatcher replays the outer insn).
6. **FP memory op3s** (`op == 3`, empirically verified with GAS:
   `LDF=0x20`, `LDFSR=0x21`, `LDDF=0x23`, `STF=0x24`, `STFSR=0x25`,
   `STDF=0x27`; quad `0x22`/`0x26` → `UNDEF`): new
   `SPARC32_OP_FPMEM` class (Coordinator decode change, already on
   `master` when lanes start). Coprocessor `LDC/STC/LDCSR/STCSR`:
   probe with GAS; if un-assemblable they stay `UNDEF`.
7. **SIMD scope**: V8 has no VIS. "SIMD lanes" = paired-single lanes
   (`%f2k`/`%f2k+1` independence inside one double register).

---

### Lane `L3a` — FPU/SIMD reference interpreter (`src/interp/fp.c`)

- **Worktree**: `../sparc32rt-l3a` on branch `lane/p3-l3a`
- **Exclusive files**: `src/interp/fp.c`, `src/interp/fp.h` (new;
  declare `bool sparc32_fp_step(...)`, `bool sparc32_fp_mem(...)`,
  `bool sparc32_fbranch_is_cti(...)`-style helpers as needed).
- **Explicit hook hunks** (only these lines outside the exclusive
  files): `src/interp/interp.c` — route `SPARC32_OP_FPU` /
  `SPARC32_OP_FPMEM` from `interp_single` to `fp.c`, and extend
  `interp_is_cti` + `interp_step` CTI routing to `SPARC32_OP_FBRANCH`
  via an `fp.c` transfer helper (mirrors `interp_cti`, evaluates
  `fcc`). `FBRANCH`-in-delay and `FPU`-in-delay execute through the
  same hooked paths (delay CTI still falls back pristine).
- **Task**:
  1. Every `FPop1`/`FPop2` encoding the decoder yields (`opf` field):
     `FMOVs/d`, `FNEGs/d`, `FABSs/d`, `FADD/SUB/MUL/DIV s+d`,
     `FSQRTs/d`, `FiTOs/d`, `FsTOs/d/i/x`?, `FdTOs/i/x`?, `FsMULd`,
     `FiTOx`/`FxTOs/d` (64-bit: probe oracle; trap if LEON lacks),
     `FCMP/FCMPE s/d` (+`fcc`, NV semantics per E06), unlisted/quad
     `opf` → `UNDEF`. `FsTOx/FdTOx/FxTO*`: implement only what the
     oracle executes; otherwise `UNDEF` + document.
     Arithmetic executes round-to-nearest regardless of `RD` (matches
     every oracle-observable behavior; `RD≠RN` arithmetic is a
     documented residual — no available oracle distinguishes it, and
     both engines agree via difftest).
  2. `FDTOI`/`FSTOI` with all four `RD` modes (manual); oracle test
     pins `RN`.
  3. `LDF/LDDF/STF/STDF` (misaligned multi-byte → `FAULT`/SIGBUS,
     same rule as integer memory), `LDFSR`/`STFSR` (full 32-bit).
     Odd-`rd` double/quad mem → `UNDEF`.
  4. Reuse `interp_priv.h` window/memory/fault helpers; no translator
     duplicate state.
- **Acceptance** (inside `sparc32rt-oracle` container):
  ```sh
  sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static -o /tmp/e06 experiments/E06/probe.S
  qemu-sparc -cpu LEON3 /tmp/e06 > /tmp/q.out 2>&1
  /w/_build/sparc32rt --interp -- /tmp/e06 > /tmp/i.out 2>&1
  cmp /tmp/q.out /tmp/i.out
  ```
  plus integer no-regression: `--interp`/`--difftest` on
  `test_p1_isa` + `test_p2_sys` still exit 0 with `0 divergences`.
  Documented-gap form: `E06/probe.S` pins qemu's `RD`-blindness
  (E06#6: `fdtoi(2.5) RM+inf` prints `2` on qemu, `3` per the manual);
  `interp` must print the manual value there and match qemu on every
  other line.

---

### Lane `L3b` — AArch64 FP/NEON emitter (`src/dbt/emit_fp.c`)

- **Worktree**: `../sparc32rt-l3b` on branch `lane/p3-l3b`
- **Exclusive files**: `src/dbt/emit_fp.c`, `src/dbt/emit_fp.h` (new).
- **Explicit hook hunks**: `src/dbt/emit_int.c` — `e_emit_one`
  `FPU`/`FBRANCH`/`FPMEM` cases route to `emit_fp.c`; `e_emit_delay`
  `FPU`/`FPMEM`-in-delay emits inline via `emit_fp.c` (CTI/TRAP/
  `FBRANCH`-in-delay keeps pristine `SINGLE_STEP`).
  `src/dbt/dbt.c` — add `FBRANCH` to `dbt_is_cti` + `dbt_block_ends`
  (mirror `BRANCH`: `cond != 0U`) so chaining, IBTC/RAS, and the
  page-final superset treat `FBfcc` exactly like `Bicc`.
  `src/rt32/stack32.c` — exactly the
  `AUXV_PUT(SPARC_AT_HWCAP, 0U)` line: set the FP feature bit.
- **Task**:
  1. Lower every `FPop`/`FPMEM` op `L3a` implements to AArch64 scalar
     FP/NEON (`FMOV/FADD/FSUB/FMUL/FDIV/FSQRT/FCMP/FABS/FNEG/FRINT* /
     FCVT* S and D`, GPR↔FPR moves for conversions, FP loads/stores).
     Integer-bridge EA/fault helpers: reuse non-static helpers where
     they exist, else implement locally in `emit_fp.c` (no edits to
     `emit_int.c` beyond the hook hunks).
  2. `fcc` extraction from AArch64 flags (map `NZCV` → `fcc` bits;
     unordered → `fcc=3`); `RD` → `FPCR.RMode` around convert ops and
     restore after.
  3. **NaN hazards**: AArch64 must reproduce qemu exactly —
     payload-preserving propagation, `0.0/0.0` → `0x7FFFFFFF...`
     (canonicalize the Invalid-Operation result when the hardware
     default differs; detect via `FPSR.IXC`/explicit operand check,
     never via `x18`), quieting without payload change.
  4. `FBfcc` emitter mirrors `emit_branch` (cond on `fcc`, annul,
     not-taken fallthrough exit; page-final handled by the `dbt.c`
     superset — no per-class `SINGLE_STEP` needed).
  5. **Phase-gated `AT_HWCAP`**: probe what `qemu-sparc -cpu LEON3`
     advertises (tiny auxv-dump guest), set exactly the feature bit
     for what this phase implements, cite the kernel `HWCAP_SPARC_*`
     value in a comment.
- **Acceptance** (inside `sparc32rt-oracle` container):
  ```sh
  sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static -o /tmp/e06 experiments/E06/probe.S
  qemu-sparc -cpu LEON3 /tmp/e06 > /tmp/q.out 2>&1
  /w/_build/sparc32rt --dbt -- /tmp/e06 > /tmp/d.out 2>&1
  cmp /tmp/q.out /tmp/d.out
  ```
  plus integer no-regression: `--dbt`/`--difftest` on `test_p1_isa`
  + `test_p2_sys` still exit 0 with `0 divergences`. (Full
  `interp`-vs-`dbt` FP difftest on the L3c test is the Coordinator's
  `RC3` gate after all three lanes merge.)

---

### Lane `L3c` — `tests/test_p3_fp_simd.c`

- **Worktree**: `../sparc32rt-l3c` on branch `lane/p3-l3c`
- **Exclusive files**: `tests/test_p3_fp_simd.c` (new, freestanding
  top-level asm in the `test_p1_isa.c` style: `_start`, `puts`-style
  helpers, `snapshot-before-print`, deterministic stdout, `exit(0)`
  on success / `fail` + `exit(1)`).
- **Task**: cover scalar FP (`FADD/SUB/MUL/DIV` s+d incl. `0.0/0.0`
  NaN + propagation), `FSQRTs/d`, conversions (`FiTOs/d`,
  `FsTOi/d`, `FdTOi`, `FsMULd`; `RN` only), `FCMP/FCMPE` s+d for all
  four `fcc` outcomes + `FBfcc` taken/not-taken/annulled both ways,
  paired-single lane independence (write `%f0` lane, prove `%f1`
  lane undisturbed and vice versa), `LDF/STF/LDDF/STDF` round-trip,
  `LDFSR`/`STFSR` (`RN` default + explicit `RD=RN` set/restore).
  **Exclude** (translator-strict, oracle-lenient): odd-`rd`
  doubles, quads, `RD≠RN` oracle cases. **V8 purity**: `Bicc`
  mnemonics only (no `BPcc`), and objdump-verify every `FPU`-class
  word's `opf` is in the L3a-implemented set before finishing.
- **Acceptance** (inside `sparc32rt-oracle` container):
  ```sh
  sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static -o /tmp/t3 tests/test_p3_fp_simd.c
  qemu-sparc -cpu LEON3 /tmp/t3
  ```
  exit 0 with deterministic stdout.

---

### Escalation rule

A lane stops and reports to the Coordinator when its acceptance fails
twice, when it needs an edit outside its exclusive files + hook
hunks, or when oracle behavior contradicts a frozen contract above.

---

### RC3 Sign-off (Coordinator, on `master`)

- **Merges**: `lane/p3-l3a` (interp `fp.c`/`fp_arith.c`), `lane/p3-l3b`
  (`emit_fp.c`, `emit_fp.h`, `stack32.c` HWCAP hook, `dbt.c` FBRANCH
  arms), `lane/p3-l3c` (`tests/test_p3_fp_simd.c`) — all `--no-ff`.
- **RC3 integration fixes** (Coordinator-level, found by the RC3
  gate):
  1. `emit_fp.c` never committed AArch64 `FPSR` exception flags to
     guest `FSR` (first divergence: `fdivs 0/0`, `fsr 0x210` vs
     `0x0`). Fix: `MSR FPSR,xzr` pre-clear + post-op permute/merge
     (`IXC/UFC/OFC/DZC/IOC` → `NXC/UFC/OFC/DZC/NVC`, cexc cleared,
     aexc accrued), `cexc` clear on moves, signal-aware `NVC` on
     compares (`IOC || (FCMPE && unordered)`), `FRINTI` →
     `FRINT32X` (FRINTI never signals inexact — verified on Apple
     Silicon against clang ground truth).
  2. `FPMEM` block split to `src/dbt/emit_fpmem.c` (900-line file
     discipline; `fp_mov64x` shared via `emit_fp.h` static inline).
- **Gate evidence** (`sparc32rt-oracle`, `qemu-sparc -cpu LEON3`,
  all exit 0): `test_p1_isa` 0/6170, `test_p2_sys` 0/844,
  `test_p3_fp_simd` 0/8997, E06 0/2817 divergences;
  `interp`/`dbt` byte-identical to oracle on `t1`/`tsys`/`t3`; E06
  matches except the single documented `RD`-blindness line
  (`fdtoi RM` manual-correct `3` on both engines vs oracle `2`,
  E06#6). `make check` passes.
- **Residuals** (documented, no available oracle distinguishes):
  FP arithmetic executes round-to-nearest regardless of `RD` on both
  engines; odd-`rd` doubles, quads, `RD≠RN` oracle cases excluded
  from `test_p3_fp_simd`; `FMOVd/FNEGd/FABSd` SIGILL on qemu-LEON3
  (singles only in the test, doubles implemented per manual).
