# `sparc32rt` — Technical Specification & Execution Plan

**Target Architecture**: SPARC V8 (`EM_SPARC`, Gaisler LEON3 / LEON4)
**Target Host**: AArch64 Linux (`aarch64-unknown-linux-musl` static-PIE) & macOS on Apple Silicon via `hyper-linux` (`hl`)
**Series Tier**: Tier 1 (Wave 3 — Class-A 32-Bit 4 GiB Window)

---

## 0. Execution Protocol (Muse Spark Coordinator + Parallel Worker-Lane DAG)

1. **Coordinator + Parallel Worker-Lane Split**:
   - The **Coordinator** (`muse` on `master`) owns frozen headers (`src/sparc32rt.h`, `include/a32host.h`, `src/os/syscall_nr.h`), `Makefile`, `flake.nix`, `docs/lanes/phase-*.md`, git worktree creation/cleanup, `--no-ff` merges, and phase-level Review Checkpoints (`RC-E`, `RC0..RC6`, `RC-H`).
   - **Concurrent Subagents & Workflows**:
     - For every phase (`Phase E`, `Phase 0` .. `Phase 7`), spawn **multiple concurrent `subagent` worker lanes in parallel** using isolated git worktrees (`../sparc32rt-<lane>` on branch `lane/<phase>-<lane>`) and use `run_workflow` / `list_workflows` where helpful.
     - Each worker lane has **exclusive file ownership**, codes against **frozen headers**, and runs **one bounded acceptance check** (`timeout --kill-after=30s ...`).
2. **Dual-Oracle Verification**:
   - Every phase validates `src/interp/` against the independent **`qemu-sparc (with -cpu LEON3)` ground-truth oracle** first, and then validates `src/dbt/` against `src/interp/` via `--difftest` (`0` register/PC mismatches).

---

## 1. Target Profile, ELF Admission & Substrate Architecture

### 1.1 Target CPUs & ELF Admission
- **Target CPUs**: Cobham Gaisler LEON3 (`GR712RC`) and LEON4 (`GR740`) radiation-hardened SPARC V8 processors
- **ELF Admission**: `ELFCLASS32`, `ELFDATA2MSB` (big-endian), **`e_machine == EM_SPARC (2)` with `e_flags == 0` ONLY** (explicitly rejects `EM_SPARC32PLUS (18)` and `EF_SPARC_32PLUS` with `ENOEXEC`)
- **Guest `TASK_SIZE`**: `0xf0000000 (stack top 0xefff0000, sigtramp 0xefffe000)`
- **Ground-Truth Oracle**: `qemu-sparc (with -cpu LEON3)`
- **Cross Toolchains**: `pkgsCross.sparc-linux-gnu (sparc-unknown-linux-gnu glibc + nolibc; upstream musl has no SPARC port)`

### 1.2 Class-A 4 GiB Window (`[G, G + 4 GiB)`) & `src/rt32/` Copy-First Substrate
- `sparc32rt` allocates a contiguous 4 GiB + 64 KiB guard region `[G, G + 4 GiB + 64 KiB)` (`PROT_NONE` reservation via `src/rt32/vm.c`).
- Under standalone AArch64 Linux, `G` is chosen dynamically by the host kernel (`mmap(NULL, 0x100010000ULL, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0)`).
- Under `hyper-linux` (`hl`), `/dev/a32host` (`include/a32host.h`, `A32H_ABI 1.0/1.1`) provides `G = 0x100000000ULL` (`A32H_CAP_FIXED_OFFSET_4G`).
- **Phase 0 Lane `L0a`** copies the proven `rt32` substrate from `../i686rt/src/` (or `../a32rt/src/`) into `src/rt32/`:
  - `src/rt32/vm.c`, `src/rt32/elf32.c`, `src/rt32/stack32.c`, `src/rt32/host.c`, `src/rt32/a64_emit.[ch]`, `src/rt32/safe_syscall_a64.S` (with `D18` signal-window race-free commit point and `D19` `CLONE_VM` page-table mutex locking).
  - Parameterize `elf32.c` on `sparc32rt`'s `e_machine`, endianness, and `e_flags` admission rules.

---

## 2. CPU Context, ISA Semantics & Linux ABI

### 2.1 `sparc32_ctx_t` Context, Register Windows, Dual-PC & LEON `CASA` (`src/sparc32rt.h`)
- **Strict SPARC V8 ELF Admission Policy**:
  - Admits `ELFCLASS32`, `ELFDATA2MSB` (big-endian), **`e_machine == EM_SPARC (2)` with `e_flags == 0` ONLY**.
  - **Explicitly rejects `EM_SPARC32PLUS (18)` and `EF_SPARC_32PLUS` (`ENOEXEC`)**, because V8+ permits 64-bit `%g`/`%o` registers and V9 instructions that a 32-bit V8 context cannot represent.
- **Target Sysroot (`glibc` + `nolibc`)**:
  - Upstream `musl` has no SPARC port. `sparc32rt` qualifies freestanding/`nolibc` static binaries in Phases 1–2 and **`sparc-unknown-linux-gnu` (`glibc` static and dynamic `ld-linux.so.2`)** in Phases 2–7.
- **CPU State (`sparc32_ctx_t`)**:
  - Active 32-register view `uint32_t r[32]` (`%g0..%g7` = `r[0..7]` with `r[0]=0`, `%o0..%o7` = `r[8..15]` with `%o6 = %sp`, `%l0..%l7` = `r[16..23]`, `%i0..%i7` = `r[24..31]` with `%i6 = %fp`), `uint32_t pc`, `uint32_t npc`, `uint32_t y`, `uint32_t psr` (`icc` bits `23:20`: `N, Z, V, C`), `uint32_t fsr` (`fcc` bits `11:10`), `uint32_t f[32]` (`%f0..%f31`).
- **Register Window Spill/Fill (`SAVE` / `RESTORE`)**:
  - `SAVE %rs1, src2, %rd`: computes `new_sp = r[rs1] + src2`, spills caller's current `%l0..%l7` (`r[16..23]`) and `%i0..%i7` (`r[24..31]`) as 16 big-endian 32-bit words (`struct rwindow_32`, 64 bytes) to guest stack `[%sp + 0 .. %sp + 60]`, shifts `%i0..%i7 <- %o0..%o7`, zeros `%l0..%l7`, and writes `r[rd] = new_sp`.
  - `RESTORE %rs1, src2, %rd`: computes `res = r[rs1] + src2`, moves `%o0..%o7 <- %i0..%i7`, reloads caller's `%l0..%l7` and `%i0..%i7` (64 bytes) from `[%sp + 0 .. %sp + 60]`, and writes `r[rd] = res`.
  - Before any `fork`, `clone`, or signal delivery, `flush_user_windows(ctx)` writes active `%l0..%l7`/`%i0..%i7` to `[%sp]`.
- **Dual-PC (`pc`, `npc`), Annul Bit (`,a`), & Page-Boundary Rule**:
  - Conditional `Bicc,a` / `FBfcc,a` annuls the delay slot (`pc = npc + 4; npc = npc + 8`) when **not taken**; unconditional `BA,a` / `FBA,a` **always** annuls the delay slot (`pc = target; npc = target + 4`). An annulled delay slot is never fetched, so an unmapped page immediately after a not-taken `Bicc,a` or taken `BA,a` at `0xffc` never faults.
  - Page-final non-annulled branches at `(pc & 0xfff) == 0xffc` use `EXIT_SINGLE_STEP` (`interp_step`) when a DBT block starts at `0xffc`.
- **LEON3/4 Hardware Multiply/Divide & `CASA` Privilege Policy**:
  - Implements `UMUL[cc]`, `SMUL[cc]`, `UDIV[cc]`, `SDIV[cc]`, `RDY`/`WRY`, `LDSTUB`, `SWAP`.
  - For LEON `CASA [%rs1] imm_asi, %rs2, %rd` (`op=3, op3=0x3c`): in Linux `arch/sparc/include/uapi/asm/asi.h`, `ASI_USERDATA = 0x0a` is user space whereas `ASI_KERNELDATA = 0x0b` is supervisor space. `sparc32rt` accepts `ASI == 0x0a` unconditionally in user mode and faults `SIGILL` (`ILL_PRVOPC`) on `ASI == 0x0b` by default unless `--leon-allow-asi-0b` (`SPARC32RT_LEON_SUPERVISOR_ASI=1`) is explicitly enabled.

### 2.2 SPARC32 Linux Syscall & Complete Signal Frame ABI (`src/os/`)
- **SPARC32 Syscall Convention (`ta 0x10` = `0x91d02010`)**:
  - Syscall number in `%g1` (`r[1]`); arguments 1..6 in `%o0..%o5` (`r[8..13]`).
  - Success: **`PSR.icc.C = 0`**, `%o0 = (uint32_t)ret`. Error: **`PSR.icc.C = 1`**, **`%o0 = sparc_errno_from_host(-ret)`** (positive SPARC errno). Always advances `pc = npc; npc = npc + 4`.
  - `pipe (42)` returns `fd[0]` in `%o0`, `fd[1]` in `%o1`; `fork (2)` / `vfork (66)` / `clone (217)` returns `%o1 = 0` in parent and **`%o0 = parent_pid, %o1 = 1`** in child.
- **Complete SPARC32 `rt_signal_frame32` Layout (`src/os/sigframe_sparc32.h`, Verified in `tests/check_abi_invariants.c`)**:
  - Per Linux `arch/sparc/include/uapi/asm/ptrace.h` and `arch/sparc/kernel/signal_32.c`, `rt_signal_frame32` (**348 bytes** fixed structure before optional FPU/rwin tail) has exact offsets:
    - `0x000..0x05f`: **`struct sparc_stackf ss` (96 bytes)**: `uint32_t locals[8]` (32 B) + `uint32_t ins[6]` (24 B) + `uint32_t fp` (4 B) + `uint32_t callers_pc` (4 B) + `uint32_t structptr` (4 B) + `uint32_t xargs[6]` (24 B) + `uint32_t xxargs[1]` (4 B),
    - `0x060..0x0df`: `siginfo_t info` (128 B),
    - `0x0e0..0x12f`: `struct pt_regs32 regs` (80 B: `uint32_t psr, pc, npc, y, u_regs[16]`),
    - `0x130..0x137`: `uint32_t mask[2]` (8 B `sigset_t`),
    - `0x138..0x13b`: `uint32_t fpu_save` (4 B guest pointer to inline `sigfpu32` tail or `0`),
    - `0x13c..0x143`: `uint32_t insns[2]` (8 B: `set __NR_rt_sigreturn, %g1; ta 0x10`),
    - `0x144..0x147`: `uint32_t extramask[1]` (4 B),
    - `0x148..0x14b`: `uint32_t extra_size` (4 B),
    - `0x14c..0x14f`: `uint32_t rwin_save` (4 B guest pointer to saved windows or `0`),
    - `0x150..0x15b`: `sparc32_stack_t stack` (12 B: `{uint32_t ss_sp; int32_t ss_flags; uint32_t ss_size;}`),
    - `0x15c..`: optional inline `sigfpu32` and `rwin_save` tails.
  - At initial `_start`, `argc` sits at `%sp + 64` immediately after the 64-byte `rwindow_32` save area.

---

## 3. Dual-Engine Design (`src/interp/` + `src/dbt/`)

1. **Reference Interpreter (`src/interp/`)**:
   - Pure Curated C11 step-by-step and chunked interpreter (`interp_step(sparc32_ctx_t *ctx)` and `interp_run(sparc32_ctx_t *ctx)`).
   - Serves as:
     - Ground-truth reference engine (`SPARC32RT_ENGINE=interp` or `--interp`),
     - Instruction-by-instruction differential oracle (`--difftest`),
     - Single-instruction fallback (`EXIT_UNDEF` / `EXIT_SINGLE_STEP` -> `interp_step(ctx)` -> resume DBT) for rare system/unaligned/cross-page delay-slot instructions so valid instructions never abort execution.
2. **AArch64 Dynamic Binary Translator (`src/dbt/`)**:
   - Translates guest basic blocks (up to 64 guest instructions, terminating at control transfers or page boundaries) into AArch64 machine code using `a64_emit.[ch]`.
   - Direct block chaining + 4096-entry per-thread Indirect Branch Target Cache (`IBTC`) + Return Address Stack (`RAS`).
   - Enforces W^X (`PROT_READ | PROT_WRITE` during emission -> `PROT_READ | PROT_EXEC` before execution + `__builtin___clear_cache` / `A32H_CAP_ICACHE_TRAP_IALLU`) and self-modifying code (`SMC`) page-version invalidation on `mprotect` / `munmap` / `clear_cache` / guest writes to translated pages.
   - **Never touches `x18`**.

---

## 4. Nine-Phase Implementation Pipeline & Review Checkpoints (`RC`)

| Phase / Gate | Lanes (Run in Parallel Worktrees) | Required Independent Oracle & Acceptance Gate |
|---|---|---|
| **Phase E (`RC-E`)** | `E01` .. `E06` (`experiments/E01..E06/FINDINGS.md`) | All 6 empirical probes compiled with target cross-CC, executed under `qemu-sparc (with -cpu LEON3)`, and committed with `FINDINGS.md` (`sizeof`/`offsetof` verified). |
| **Phase 0 (`RC0`)** | `L0a` (Substrate copy + build), `L0b` (`tests/check_abi_invariants.c` + CLI smoke) | `aarch64-unknown-linux-musl-gcc -static-pie` builds `_build/sparc32rt`; `make check-line-limits` (`<= 900 LOC`) and `check_abi_invariants` pass; `--version` / `--help` pass in AArch64 Docker container. |
| **Phase 1 (`RC1`)** | `L1a` (Decoder), `L1b` (Integer `src/interp/`), `L1c` (Minimal syscalls `exit`, `write`, `brk`, `mmap`), `L1d` (`test_p1_isa`) | `test_p1_isa` (covering ALU, shifts, branches, delay slots/annul at `page_end - 4` before `PROT_NONE` page, atomics, unaligned accesses) matches `qemu-sparc (with -cpu LEON3)` exit code and stdout bit-for-bit under `SPARC32RT_ENGINE=interp`. |
| **Phase 2 (`RC2`)** | `L2a` (`src/os/` static libc syscalls + struct translation), `L2b` (`src/dbt/` dispatcher + block cache + IBTC), `L2c` (`src/dbt/emit_int.c`), `L2d` (`difftest` + static libc tests) | `--difftest` reports `0` register/PC mismatches between `interp` and `dbt` on `test_p1_isa`; static `hello`, `printf`, `qsort`, `malloc`, and file I/O match `qemu-sparc (with -cpu LEON3)` on both `interp` and `dbt`. |
| **Phase 3 (`RC3`)** | `L3a` (`src/interp/fp.c` FPU/SIMD), `L3b` (`src/dbt/emit_fp.c` NEON/FP lowering), `L3c` (`test_p3_fp_simd`) | `test_p3_fp_simd` (NaN modes, rounding, FPU/SIMD corner cases) matches `qemu-sparc (with -cpu LEON3)` bit-for-bit on both `interp` and `dbt` with `0` difftest divergences. |
| **Phase 4 (`RC4`)** | `L4a` (`rt_sigframe` + `rt_sigaction`/`rt_sigreturn`/altstack), `L4b` (`clone`/TLS/`futex`/reservation invalidation), `L4c` (`fork`/`vfork`/`execve`/`wait4` + `test_p4_threads_signals`) | `test_p4_threads_signals` (signal frame inspection/modification/restoration, `SIGSEGV` recovery, pthreads + futex + atomics, `fork`+`execve`+`wait4`) matches `qemu-sparc (with -cpu LEON3)` on both `interp` and `dbt`. |
| **Phase 5 (`RC5`)** | `L5a` (`PT_INTERP` dynamic linker loading + auxv + `/proc/self/*`), `L5b` (Dynamic `glibc`/`musl` + `BusyBox` suite) | Dynamic `test_p5_dyn` and `BusyBox` (`sh -c 'ls / && echo ok | wc -c'`) match `qemu-sparc (with -cpu LEON3)` on both `interp` and `dbt`. |
| **Phase 6 (`RC6`)** | `L6a` (`hyper-linux` host contract & packaging), `L6b` (Both-host parity test suite) | `test_p1_isa`, `test_p3_fp_simd`, `test_p4_threads_signals`, `test_p5_dyn`, and `BusyBox` pass on both AArch64 Linux container and `hl` (`hyper-linux`). |
| **Phase 7 (`RC-H`)** | `H1` (`test_h1_smc`), `H2` (`libc-test` + LTP syscall subset -> `docs/h2-report.md`), `H3` (6-step instrumented CoreMark -> `docs/h3-coremark.md`), `H4` (C++17 exceptions/RTTI/TLS smoke) | All 4 hardening gates committed with machine-verified pass counts (`0` unexpected failures) and measured `dbt > interp` speedup in `docs/h3-coremark.md`. |
