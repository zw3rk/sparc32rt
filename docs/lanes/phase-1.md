# Phase 1 Task Cards — Base Integer Decoder, Reference Interpreter & Minimal Syscalls (`sparc32rt`)

Run after `RC0` is merged to `master`. All lanes code against SPEC §2 and the
Phase-0 frozen headers (`src/sparc32rt.h`, `src/os/syscall_nr.h`,
`src/os/sigframe_sparc32rt.h`); no lane may edit frozen files (escalate).

Guest-memory access in `interp` goes through the `src/rt32` VM helpers
(`G`-based `[x20, wAddr, uxtw]` window); faults set `ctx->exit_reason =
SPARC32_EXIT_FAULT` with `ctx->fault_addr`. Oracles: `experiments/E01..E06`
findings (windows, annul, MUL/DIV/Y, atomics, `ta 0x10` carry, CASA trap 0x24
not executable on oracle, FDTOI-RD oracle gap).

---

### Lane `L1a` — Instruction Decoder (`src/interp/decode.c`, `src/interp/decode.h`)
- **Worktree**: `../sparc32rt-l1a` on branch `lane/p1-l1a`
- **Exclusive Files**: `src/interp/decode.h`, `src/interp/decode.c`
- **Task**:
  1. Define the decoded-instruction representation for all SPEC §2 base
     integer instructions (ALU, shifts, MUL/DIV, branches, calls, JMPL, SAVE/
     RESTORE, loads/stores incl. alternate-space, LDSTUB/SWAP/CASA, RD/WR
     ASR/Y, FPU pass-through marker for Phase 3, illegal-encoding class).
  2. Implement the decoder (big-endian fetch, `op`/`op2`/`op3` dispatch,
     `i`/ASI handling, delay-slot/annul flags on branches). CASA decodes to
     its semantic form (`rs1, rs2, rd, asi`) — execution is L1b; the oracle
     cannot execute it (E03 casa.S trap 0x24), so decode-correctness is by
     construction + L1d coverage of the encoding word.
  3. Odd-`rd` double FP encodings decode as illegal (E06 oracle leniency
     delta: translator is manual-strict).
- **Acceptance Command**:
  ```sh
  cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Iinclude -Isrc -c src/interp/decode.c -o /tmp/decode.o
  ```

---

### Lane `L1b` — Base Integer Reference Interpreter (`src/interp/interp.c`)
- **Worktree**: `../sparc32rt-l1b` on branch `lane/p1-l1b`
- **Exclusive Files**: `src/interp/interp.c`
- **Task**:
  1. Implement `interp_step(sparc32_ctx_t *ctx)` + `interp_run` for every
     SPEC §2 base integer instruction: full `(pc, npc)` dual-PC stepping,
     annulled-delay semantics (E02), 8-window SAVE/RESTORE spill/fill with
     `WIM` traps (E01), `Y` threading through MUL/DIV (E03 #8), `icc`
     N/Z/V/C incl. UMULcc/SMULcc V and SDIV truncation (E03 table), LDSTUB/
     SWAP/CASA semantics (match → swap + rd=old; mismatch → rd=old,
     ASR-masked supervisor ASIs trap), `ta 0x10` → `EXIT_SYSCALL` with
     carry convention (E04), unaligned `LDA/STA` (trap or emulate per SPEC),
     page-final non-annulled branch at `0xffc` → `EXIT_SINGLE_STEP`.
  2. FPU instructions: return `EXIT_UNDEF` (Phase 3 owns them); `interp`
     must never silently execute them.
- **Acceptance Command**:
  ```sh
  cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Iinclude -Isrc -c src/interp/interp.c -o /tmp/interp.o
  ```

---

### Lane `L1c` — Minimal Linux Syscall Layer (`src/os/syscalls_min.c`)
- **Worktree**: `../sparc32rt-l1c` on branch `lane/p1-l1c`
- **Exclusive Files**: `src/os/syscalls_min.c`
- **Task**:
  1. Implement the Phase-1 syscall subset against the frozen
     `src/os/syscall_nr.h`: `exit`, `exit_group`, `write`, `read`, `brk`,
     `mmap`, `munmap`, `mprotect`, `uname`, `set_tid_address`.
  2. SPARC carry convention on return (`C=0` + `%o0=ret`; `C=1` +
     `%o0=sparc_errno_from_host(-ret)`), `pc = npc; npc += 4` advance,
     guest-pointer translation through the `G` window (no host-pointer
     leaks), `pipe`-less (Phase 4 owns `pipe`/`fork` full semantics; E04
     convention recorded for reuse).
  3. Wire into `src/main.c` `--interp` path (minimal: run loop calling
     `interp_run`, dispatch `EXIT_SYSCALL` here, `exit_group` terminates).
- **Acceptance Command**:
  ```sh
  cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Iinclude -Isrc -c src/os/syscalls_min.c -o /tmp/syscalls_min.o
  ```

---

### Lane `L1d` — Freestanding ISA Test Suite (`tests/test_p1_isa.c`)
- **Worktree**: `../sparc32rt-l1d` on branch `lane/p1-l1d`
- **Exclusive Files**: `tests/test_p1_isa.c`
- **Task**:
  1. Freestanding SPARC V8 test guest (build with the E-phase discipline:
     `-m32 -fno-pie -no-pie -nostdlib -static`) covering ALU, shifts,
     branches (taken/not-taken, annulled both ways), page-final branch
     before a `PROT_NONE` page, LDSTUB/SWAP, unaligned loads/stores, SAVE/
     RESTORE depth, `ta 0x10` write/exit. CASA covered as an encoding word
     + pre-state assertion only (oracle cannot execute it).
  2. Deterministic stdout record + `exit(0)`; must also pass under
     `qemu-sparc -cpu LEON3` bit-for-bit (RC1 compares the two).
- **Acceptance Command**:
  ```sh
  sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static -o /tmp/test_p1_isa tests/test_p1_isa.c && qemu-sparc -cpu LEON3 /tmp/test_p1_isa
  ```
