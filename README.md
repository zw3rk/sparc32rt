# `sparc32rt` — SPARC V8 (`EM_SPARC`, Gaisler LEON3 / LEON4) User-Mode Binary Translator for AArch64

`sparc32rt` is a zero-dependency, static-PIE (`aarch64-unknown-linux-musl`) user-mode binary translator for **SPARC V8 (`EM_SPARC`, Gaisler LEON3 / LEON4)** Linux ELF binaries on AArch64 Linux and macOS on Apple Silicon (via [`hyper-linux`](../hyper-linux)).

- **Series Tier**: Tier 1 (Wave 3 — Class-A 32-Bit 4 GiB Window)
- **Target CPUs**: Cobham Gaisler LEON3 (`GR712RC`) and LEON4 (`GR740`) radiation-hardened SPARC V8 processors
- **ELF Admission**: `ELFCLASS32`, `ELFDATA2MSB` (big-endian), **`e_machine == EM_SPARC (2)` with `e_flags == 0` ONLY** (explicitly rejects `EM_SPARC32PLUS (18)` and `EF_SPARC_32PLUS` with `ENOEXEC`)
- **Guest `TASK_SIZE`**: `0xf0000000 (stack top 0xefff0000, sigtramp 0xefffe000)`
- **Dual Execution Engines**:
  1. `src/interp/` — Portable Curated C11 reference interpreter and differential oracle (`SPARC32RT_ENGINE=interp`)
  2. `src/dbt/` — Direct-mapped + IBTC AArch64 dynamic binary translator (`SPARC32RT_ENGINE=dbt`, default) with single-instruction interpreter fallback (`EXIT_UNDEF` / `EXIT_SINGLE_STEP`)

---

## Key Documents

| Document | Purpose |
|---|---|
| [`AGENTS.md`](AGENTS.md) | Repository ground rules, Curated C11 & AArch64 ABI invariants, Muse Spark Coordinator + Parallel Worker-Lane worktree protocol, and host environment notes. |
| [`SPEC.md`](SPEC.md) | Complete technical specification for `sparc32rt` (CPU context, ISA semantics, syscall/signal/thread ABI, host contract, and 9-phase verification pipeline). |
| [`GOAL.md`](GOAL.md) | Executable `/goal` specification for autonomous Muse Spark implementation (`Phase E` -> `Phase 0..Phase 7`). |
| [`docs/lanes/`](docs/lanes/) | Phase task cards (`phase-e.md`, `phase-0.md`, and subsequent phase lane cards). |
| [`../rt-series/`](../rt-series/) | Series-wide architecture (`../rt-series/SPEC.md`), master plan (`../rt-series/PLAN.md`), and host contract (`../rt-series/docs/HOST-CONTRACT.md`). |
