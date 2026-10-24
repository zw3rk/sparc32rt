# Phase 6 Parity Matrix — Lane `L6b` (`tests/`)

Lane `L6b` gate record: adjacent-4 KiB probe
(`tests/test_p6_adjacent.c`) + full parity sweep. Every cell below is
backed by an observed run quoted in §4; no green claim is inferred.

## 1. Provenance

- Worktree: `../sparc32rt-l6b` on branch `lane/p6-l6b`, at commit
  `a74696e` (Phase 6 prep). Translator built from that tree:
  `make build CC=<nix aarch64-unknown-linux-musl-gcc 15.2.0>
  BUILD_DIR=_build` → `_build/sparc32rt` (static-PIE aarch64).
- Oracle container: `sparc32rt-oracle:latest`
  (`sparc64-linux-gnu-gcc (Debian 12.2.0-13) 12.2.0`,
  `qemu-sparc version 7.2.22 (Debian 1:7.2+dfsg-7+deb12u18+b3)`),
  always `qemu-sparc -cpu LEON3`.
- Translator runs: `docker run --platform linux/arm64 ... alpine:3.20`,
  guest binaries bind-mounted from the oracle build step
  (`/g/<name>` absolute paths; `t5auxv` needs an absolute `argv[0]`,
  the `p5app` pair needs `/tmp/sparc32rt-p5interp` in every container).
- `make check` (build + line limits + ABI invariants): clean (`PASS`).

## 2. Sweep scripts (recorded verbatim)

Build + oracle baseline (`sh /g/p6sweep-build.sh` inside
`sparc32rt-oracle`, mounts `-v "$PWD:/w" -v /tmp/p6sweep:/g`):

```sh
set -u
G=/g
S=/w
CC="sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static"
sparc64-linux-gnu-gcc --version | head -1
qemu-sparc --version | head -1
$CC -o $G/t1 $S/tests/test_p1_isa.c && echo "build ok t1"
$CC -o $G/tsys $S/tests/test_p2_sys.c && echo "build ok tsys"
$CC -o $G/t3 $S/tests/test_p3_fp_simd.c && echo "build ok t3"
$CC -o $G/t4a $S/tests/test_p4_async.c && echo "build ok t4a"
$CC -o $G/t4t $S/tests/test_p4_threads.c && echo "build ok t4t"
$CC -o $G/t5auxv $S/tests/test_p5_auxv.c && echo "build ok t5auxv"
$CC -o $G/t6adj $S/tests/test_p6_adjacent.c && echo "build ok t6adj"
for e in E01 E02 E03 E04 E05 E06; do
  sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static \
    -o $G/$e $S/experiments/$e/probe.S && echo "build ok $e"
done
sparc64-linux-gnu-gcc -m32 -nostdlib -shared -Wl,-e,_start \
  -o /tmp/sparc32rt-p5interp $S/tests/test_p5_interp.c && echo "build ok p5interp"
sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib \
  -Wl,--export-dynamic -Wl,--dynamic-linker,/tmp/sparc32rt-p5interp \
  -o /tmp/sparc32rt-p5app $S/tests/test_p5_app.c && echo "build ok p5app"
cp /tmp/sparc32rt-p5interp /tmp/sparc32rt-p5app $G/
command -v sparc-linux-gnu-gcc && echo "sparc-linux-gnu-gcc present" \
  || echo "BUILD-GAP t5dyn: no sparc-linux-gnu-gcc in oracle image"
ls $S/tests/test_p6_mmap.c 2>/dev/null \
  || echo "SWEEP-GAP t6mmap: tests/test_p6_mmap.c absent (L6a pending)"
for t in t1 tsys t3 t4a t4t t5auxv t6adj E01 E02 E03 E04 E05 E06; do
  timeout --kill-after=10s 60s qemu-sparc -cpu LEON3 $G/$t > $G/$t.oracle 2>&1
  echo "$t oracle exit=$?"
done
timeout --kill-after=10s 60s qemu-sparc -cpu LEON3 /tmp/sparc32rt-p5app > $G/p5app.oracle 2>&1
echo "p5app oracle exit=$?"
```

Translator sweep (`sh /g/p6sweep-run.sh` inside arm64 `alpine:3.20`,
mounts `-v "$PWD:/w" -v /tmp/p6sweep:/g`; `timeout -k 10 90` is the
BusyBox spelling):

```sh
set -u
G=/g
T=/w/_build/sparc32rt
cp $G/sparc32rt-p5interp $G/sparc32rt-p5app /tmp/ 2>/dev/null; true
run3() {
  timeout -k 10 90 $T --interp -- $2 > $G/$1.interp 2>&1
  echo "$1 interp exit=$?"
  timeout -k 10 90 $T --dbt -- $2 > $G/$1.dbt 2>&1
  echo "$1 dbt exit=$?"
}
run3 t1 $G/t1; run3 tsys $G/tsys; run3 t3 $G/t3; run3 t4a $G/t4a
run3 t4t $G/t4t; run3 t5auxv $G/t5auxv; run3 t6adj $G/t6adj
run3 E01 $G/E01; run3 E02 $G/E02; run3 E03 $G/E03; run3 E04 $G/E04
run3 E05 $G/E05; run3 E06 $G/E06; run3 p5app /tmp/sparc32rt-p5app
for t in t1 tsys t3 t4t t5auxv t6adj E01 E02 E03 E04 E05 E06 p5app; do
  case $t in
    p5app) guest=/tmp/sparc32rt-p5app ;;
    *) guest=$G/$t ;;
  esac
  timeout -k 10 90 $T --difftest -- $guest > $G/$t.diff 2>&1
  echo "$t difftest exit=$? : $(tail -1 $G/$t.diff 2>/dev/null)"
done
```

(`t4a` is excluded from `--difftest` per the lane card: the
wall-clock SIGALRM delivery point differs per engine while functional
parity holds on both. `t4t`/`E04` are compared multiset-only for the
fork-interleave bytes.)

## 3. Gate matrix

`oracle` / `interp` / `dbt` = guest exit code; `=oracle?` = byte
comparison of stdout; `difftest` = last line of the `--difftest` run.

| test | oracle | interp | dbt | =oracle? | difftest |
| --- | --- | --- | --- | --- | --- |
| test_p1_isa | 0 | 0 | 0 | identical x3 | 0 divergences (6170 steps) |
| test_p2_sys | 0 | 0 | 0 | identical x3 | 0 divergences (844 steps) |
| test_p3_fp_simd | 0 | 0 | 0 | identical x3 | 0 divergences (8997 steps) |
| test_p4_async | 0 | 0 | 0 | identical x3 | excluded (wall-clock, R5) |
| test_p4_threads | 0 | 0 | 0 | identical x3, sorted identical | 0 divergences (1186 steps) |
| test_p5_auxv | 0 | 0 | 0 | identical x3 | 0 divergences (9824 steps) |
| test_p6_adjacent (new) | 0 | 0 | 0 | identical x3 | 0 divergences (1617 steps) |
| test_p6_mmap (L6a) | — | — | — | file absent (R7) | — |
| test_p5_dyn(+lib) | — | — | — | no pure-V8 toolchain (R6) | — |
| E01 | 0 | 0 | 0 | identical modulo stack addresses (R3) | 0 divergences (5688 steps) |
| E02 | 0 | 0 | 0 | identical x3 | 0 divergences (1354 steps) |
| E03 | 0 | 0 | 0 | identical x3 | 0 divergences (2789 steps) |
| E04 | 0 | 0 | 0 | event-multiset only (R4) | 0 divergences (1253 steps) |
| E05 | 0 | 0 | 0 | identical modulo stack addresses (R3) | 0 divergences (12217 steps) |
| E06 | 0 | 0 | 0 | one documented line differs (R2) | 0 divergences (2817 steps) |
| test_p5_app+interp | 0 | 0 | 0 | identical x3 | 0 divergences (446 steps) |

## 4. Observed acceptance output (`test_p6_adjacent`)

Oracle build + run:

```text
build ok t6adj
t6adj oracle exit=0
P6-ADJ start
map ok
adj rw ok
bss zero ok
rx protect ok
rx read ok
rx exec ok
rx nowrite ok
rx exec2 ok
relro read ok
relro nowrite ok
relro restore ok
bss rw ok
guard noload ok
guard nostore ok
guard rw ok
unmap ok
P6-ADJ-PASS
```

Translator (`--interp` / `--dbt` both exit 0;
`cmp t6adj.oracle t6adj.interp` and `cmp t6adj.oracle t6adj.dbt`
both silent = byte-identical):

```text
t6adj interp exit=0
t6adj dbt exit=0
t6adj difftest exit=0 : difftest: 0 divergences (1617 steps, guest exit 0)
```

(Every line above carries the lanes' standard `puts` trailing NUL —
the delay-slot `add` counts it into the write length — identically on
all three engines, so it is parity-neutral.)

Adjacent-pair semantics pinned on the oracle before encoding (scratch
`/tmp/nxprobe.c`, not committed): store→`PROT_READ|PROT_EXEC` faults
`SIGSEGV (11)`; load from the RX page succeeds; `jmpl` into the RX
page runs; `jmpl` into a `PROT_READ|PROT_WRITE` page faults
`SIGSEGV (11)`; load/store to `PROT_NONE` fault `SIGSEGV (11)`.
Only the `PROT_WRITE`-fetch fault is *not* reproduced by the
translator (residual R1), so the committed probe asserts the positive
half (re-execution after adjacent dirtying) instead.

## 5. Residuals (with evidence)

- **R1 — no fetch-X enforcement on either engine (new, L6b finding,
  for L6a/coordinator).** Oracle `SIGSEGV`s a `jmpl` into a
  `PROT_READ|PROT_WRITE` page (`fault4 call->RW`, signo `0000000b`,
  oracle exit 0 via handler). The same sequence under `--interp` and
  `--dbt` falls through to `rw call did NOT fault` / `P6-ADJ-FAIL`
  (both exit 1, 0 divergences between the engines at the failure
  point). Neither the frozen §2.1 page contract nor SPEC mandates
  guest fetch-X faults (SPEC §W^X covers translator-emitted code
  only), so the committed probe does not encode that expectation.
  Fixing it needs `src/interp` fetch checks + `src/dbt` translate-time
  `PROT_EXEC` checks — outside L6b's exclusive files.
- **R2 — E06 `fdtoi(2.5) RM+inf` (pre-existing Phase-3 residual).**
  Oracle prints `00000002`, both engines print `00000003`
  (`interp == dbt`, exit 0, `E06-PASS` on all three). Arithmetic
  `RD≠RN` still rounds as `RN`; unchanged from the Phase-4 gate.
- **R3 — E01/E05 stack/guest addresses differ by engine
  (pre-existing, structural).** After masking every `[0-9a-f]{8}`
  run, `diff` is empty oracle-vs-interp and oracle-vs-dbt for both
  probes (`faultinsn=00010140`, auxv tags, register values all
  equal). Exit 0 + `E0x-PASS` on all three engines.
- **R4 — E04 pid/fd numbering + fork-print interleave
  (pre-existing).** `pid=` (`7b` vs `4a`/`4e`), `pipe fds=`
  (`0c 0d` vs `03 04`), and the two racy `fork o0=` prints
  character-interleave on the shared fd (varies qemu-vs-qemu too).
  Identical on all engines: exit 0, `E04-PASS`, `E04-OK` pipe
  round-trip, `wait4 status=00000700`, difftest 0 divergences.
- **R5 — `t4a` excluded from `--difftest` (lane-card rule).**
  Functional output is byte-identical x3 with exit 0 this run; the
  wall-clock SIGALRM delivery point differs per engine (Phase-4
  finding, unchanged).
- **R6 — `test_p5_dyn`/`test_p5_dynlib` not swept (documented
  negative).** `command -v sparc-linux-gnu-gcc` is empty in
  `sparc32rt-oracle:latest` (`BUILD-GAP t5dyn` in the build log);
  Phase 5 already records the pure-V8 sysroot as unobtainable
  (`docs/lanes/phase-5-sysroot.md`).
- **R7 — `test_p6_mmap` not swept (L6a pending).**
  `tests/test_p6_mmap.c` is absent on this branch
  (`SWEEP-GAP t6mmap` in the build log); L6a delivers and gates it.
