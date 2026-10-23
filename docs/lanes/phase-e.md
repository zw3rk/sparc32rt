# Phase E Task Cards — Empirical Pre-Implementation Experiments (`sparc32rt`)

Spawn **concurrent `subagent` worker lanes** for `E01..E06` in isolated worktrees (`../sparc32rt-e01` .. `../sparc32rt-e06`), merge each into `master`, and verify `RC-E`.

---

### Lane `E01` — `SAVE`/`RESTORE` 64-Byte Stack Spill/Fill & `_start` (`%sp + 64`)
- **Worktree**: `../sparc32rt-e01` on branch `lane/pe-e01`
- **Exclusive Files**: `experiments/E01/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E01/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `SPARC V8 (`EM_SPARC`, Gaisler LEON3 / LEON4)` and run under `qemu-sparc (with -cpu LEON3)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E01/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E01/FINDINGS.md
  ```

### Lane `E02` — Dual-PC `(pc, npc)` & `Bicc,a` / `BA,a` Annulled Delay Slots
- **Worktree**: `../sparc32rt-e02` on branch `lane/pe-e02`
- **Exclusive Files**: `experiments/E02/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E02/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `SPARC V8 (`EM_SPARC`, Gaisler LEON3 / LEON4)` and run under `qemu-sparc (with -cpu LEON3)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E02/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E02/FINDINGS.md
  ```

### Lane `E03` — LEON3/4 `UMUL`/`SDIV`/`Y` Register & `CASA` (`ASI 0x0a` vs `0x0b`)
- **Worktree**: `../sparc32rt-e03` on branch `lane/pe-e03`
- **Exclusive Files**: `experiments/E03/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E03/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `SPARC V8 (`EM_SPARC`, Gaisler LEON3 / LEON4)` and run under `qemu-sparc (with -cpu LEON3)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E03/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E03/FINDINGS.md
  ```

### Lane `E04` — SPARC32 `ta 0x10` Syscall (`PSR.icc.C`), `pipe`, `clone` (`%o1=0/1`)
- **Worktree**: `../sparc32rt-e04` on branch `lane/pe-e04`
- **Exclusive Files**: `experiments/E04/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E04/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `SPARC V8 (`EM_SPARC`, Gaisler LEON3 / LEON4)` and run under `qemu-sparc (with -cpu LEON3)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E04/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E04/FINDINGS.md
  ```

### Lane `E05` — SPARC32 `rt_signal_frame32` (348 B, `sparc_stackf` 96 B)
- **Worktree**: `../sparc32rt-e05` on branch `lane/pe-e05`
- **Exclusive Files**: `experiments/E05/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E05/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `SPARC V8 (`EM_SPARC`, Gaisler LEON3 / LEON4)` and run under `qemu-sparc (with -cpu LEON3)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E05/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E05/FINDINGS.md
  ```

### Lane `E06` — SPARC V8 FPU (`%f0..%f31`, Even-Pair Doubles, `FSR.fcc`)
- **Worktree**: `../sparc32rt-e06` on branch `lane/pe-e06`
- **Exclusive Files**: `experiments/E06/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E06/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `SPARC V8 (`EM_SPARC`, Gaisler LEON3 / LEON4)` and run under `qemu-sparc (with -cpu LEON3)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E06/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E06/FINDINGS.md
  ```

