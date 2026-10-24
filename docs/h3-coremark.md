# H3 — Instrumented throughput: `dbt > interp` (`docs/h3-coremark.md`)

Lane H3 (Phase 7 hardening, `RC-H`), worktree `../sparc32rt-h3` on
`lane/p7-h3`. Frozen contract §5 requires the mandatory 6-step perf
loop (Instrument → Measure → Hypothesise → Fix → Measure again →
Validate) with numbers; a single before/after pair is not a
validated claim, and `dbt > interp` must hold on the committed
configuration.

**Result: `dbt` beats `interp` 7.52x (wall medians) / 7.25x
(guest self-time) on the committed workload. Claim validated.**

## 1. Committed configuration (exact)

- Translator (frozen tree, no source edits by this lane):
  commit `dae32fc`, built with
  `make build CC=/nix/store/82ac69jwkpj68v4mx22yxnwzqj0ql4l5-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin/aarch64-unknown-linux-musl-gcc BUILD_DIR=_build`
  (`-std=c11 -Wall -Wextra -Werror=vla -pedantic -Os -fPIE`,
  `-static-pie`; `aarch64-unknown-linux-musl-gcc 15.2.0`).
- Workload guest: `tests/test_h3_coremark.c` (new, freestanding,
  committed), built with
  `sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static`
  (`sparc64-linux-gnu-gcc (Debian 12.2.0-13) 12.2.0`,
  `qemu-sparc 7.2.22`, image `sparc32rt-oracle:latest`).
  `readelf -h` says `ELF32` / `Machine: Sparc` (pure V8, admissible).
- Guest config: `H3_ITERS = 1000` passes; each pass runs a
  xorshift32 fill + insertion sort over 256 words, a bitwise
  CRC16-CCITT over 1024 bytes, and an 8-state transition walk with
  per-state counters (`.equ` constants at the top of the file).
- Runner image: `debian:bookworm-slim` (arm64, GNU `date +%s%N`),
  `docker run --rm --memory 2g --cpus 2 --platform linux/arm64
  -v "$PWD:/w" -w /w`, one engine invocation per timing sample.
- Host load: Docker Desktop VM on Apple Silicon; container sees
  `nproc = 10`, `/proc/loadavg` read `2.97 2.24 1.52` at the dbt
  batch start; two idle `sleep` containers coexisted
  (`mips32rt-p5`, `ppc32rt-l3a-tool`, no CPU use); every sample ran
  sequentially inside one container invocation; medians over 5 runs.

## 2. Documented negative: real CoreMark cannot build V8-clean here

CoreMark upstream requires a hosted C library (`printf`, `malloc`)
and a POSIX timer/porting layer. This environment has no V8
sysroot (frozen contract §4; `docs/lanes/phase-5-sysroot.md`
§§3–4: no `pkgsCross.sparc*` target, glibc refuses `sparc-linux`):

- `command -v sparc-linux-gnu-gcc` in the oracle image: absent
  (this session, `sparc32rt-h3-build` run).
- A libc-linked probe (`int main(){return 0;}`, Debian
  `sparc64-linux-gnu-gcc -m32`, this session, `sparc32rt-h3-neg`
  run) reports `Machine: Sparc v8+`, and
  `qemu-sparc -cpu LEON3` refuses it:
  `Invalid ELF image for this architecture`, exit 255.
  Only `-nostdlib -static` freestanding guests (pure `EM_SPARC`,
  Bicc only, no `BPcc`/V9) run on the oracle and the translator.

Substitute (clearly labeled): `tests/test_h3_coremark.c` is a
freestanding workload with CoreMark's character — list sort,
state-machine walk, CRC16 over a fixed buffer, repeated `ITERS`
times — but it is not CoreMark and is not named as such in its
output (`H3-COREMARK` prefix marks the lane, not the benchmark).

## 3. The 6-step loop

### Step 1 — Instrument

Two independent clocks, no translator changes:

- Outer wall time: GNU `date +%s%N` around one translator
  invocation inside the runner container (nanosecond resolution).
- Guest self time: the guest calls `clock_gettime(CLOCK_MONOTONIC)`
  (SPARC nr 257, supported by `src/os/syscalls_min.c`) before and
  after the pass loop and prints the four raw 32-bit words of each
  stamp buffer. Layouts differ by platform and are selected on the
  host: qemu/kernel sparc32 `timespec` is sec at w0 + nsec at w1;
  the translator's `l2a` 16-byte `__kernel_timespec` is zero at w0,
  sec at w1, nsec at w2 (see `sparc32_l2a_clock_gettime` in
  `src/os/syscalls.c`). The stamp words are parsed, never diffed.

### Step 2 — Measure (before: single-shot guests, startup-dominated)

Existing V8-clean guests, 5x `t1` / 3x `t3`, outer wall time:

| guest | interp median | dbt median | direction |
|---|---|---|---|
| `test_p1_isa` single-shot | 12.95 ms | 30.28 ms | dbt 2.34x *slower* |
| `test_p3_fp_simd` single-shot | 5.84 ms | 47.19 ms | dbt 8.08x *slower* |

Raw `t1` (ns): interp 15934625 12954584 18316458 11860334
11428791; dbt 96102708 34613709 28838625 30276792 29177791
(note dbt run1 = 96.1 ms cold). Raw `t3` (ns): interp 6162375
5841834 5390875; dbt 49327666 47190875 46503750. All exits 0.

### Step 3 — Hypothesise

Per-invocation fixed costs — container/exec, ELF load, and the
dbt one-time translation cost (emit + `mprotect` + I-cache flush
per block, structural W^X) — dominate guests that execute for a
few milliseconds. The interpreter pays only decode-per-instruction
and wins short runs. Prediction: a steady-state workload that
re-executes the same translated blocks `ITERS` times amortises
translation and flips the sign, which is exactly the regime
CoreMark measures. Nothing in the translator needs changing; the
measurement needs a workload that lives in steady state.

### Step 4 — Fix (measurement harness, not the translator)

Committed `tests/test_h3_coremark.c` (`H3_ITERS = 1000`): the
whole working set (a few dozen basic blocks) is translated once
under `--dbt`, then re-executed 1000 times natively; under
`--interp` every pass is re-decoded. Bring-up caught and fixed
two harness bugs, both verified against the oracle: an unaligned
`.data` word (`seed0` at an odd address → SIGBUS, fixed with
`.align 4`) and the kernel-vs-`l2a` timespec layout difference
(§Step 1; guest now prints raw stamp words).

### Step 5 — Measure again (committed configuration, 5 runs each)

| engine | wall samples (s) | wall median | guest self-time |
|---|---|---|---|
| `--interp` | 14.810 14.871 14.984 13.530 13.256 | **14.810 s** | 14.253 s |
| `--dbt` | 1.984 1.970 1.970 1.908 1.857 | **1.970 s** | 1.966 s |

Throughput: `interp` 67.5 passes/s, `dbt` 507.6 passes/s.
**`dbt` is 7.52x faster by wall median (7.25x by guest
self-time).** Wall/self agree within the fixed startup gap
(~0.5 s interp, ~19 ms dbt: ELF load + translator init, excluded
from the guest stamps by construction).

### Step 6 — Validate

- Oracle ground truth: `qemu-sparc -cpu LEON3` exit 0,
  `iters 00000003e8 crc 0000000c78`, `H3-COREMARK-PASS`.
- Both engines exit 0 on every timed run (10/10).
- Deterministic stdout is byte-identical across all three
  runners: the three 147-byte outputs differ *only* inside the
  `t0`/`t1` stamp words (byte offsets 56–118; oracle-vs-engine
  diffs additionally cover the documented layout shift, w0 sec
  vs w0 zero). Start line, `iters/crc` prefix and PASS line are
  identical bytes (`\x00iters \x00000003e8 crc \x0000000c78`).
- No `FAIL` line, no nonzero exit, no fault line in any run;
  `docker ps` shows no `sparc32rt-h3-*` container left after
  any step (each `docker run` used `--rm`).
- The two clocks corroborate each other (7.52x vs 7.25x); the
  single before/after pair was *not* used as proof — the claim
  rests on medians over 5 runs per engine on the committed
  workload.

## 4. Reproduction (exact commands)

Build translator (worktree root):

```sh
make build CC=/nix/store/82ac69jwkpj68v4mx22yxnwzqj0ql4l5-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin/aarch64-unknown-linux-musl-gcc BUILD_DIR=_build
```

Build guest + oracle baseline:

```sh
docker run --rm --name sparc32rt-h3-repro --memory 2g --cpus 2 \
  -v "$PWD:/w" -w /w sparc32rt-oracle:latest sh -c \
  'sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static \
     -o /w/_build/guest/h3 /w/tests/test_h3_coremark.c && \
   qemu-sparc -cpu LEON3 /w/_build/guest/h3; echo "oracle exit=$?"'
```

Timed runs (repeat ≥3x per engine; median the `wall_ns` values):

```sh
docker run --rm --name sparc32rt-h3-repro --memory 2g --cpus 2 \
  --platform linux/arm64 -v "$PWD:/w" -w /w debian:bookworm-slim sh -c \
  'for e in interp dbt; do for i in 1 2 3 4 5; do s=$(date +%s%N); \
     /w/_build/sparc32rt --$e -- /w/_build/guest/h3 > /dev/null 2>&1; \
     t=$(date +%s%N); echo "$e run$i wall_ns=$((t-s))"; done; done'
docker ps | grep sparc32rt-h3-repro || echo "container cleaned up"
```
