/*
 * src/dbt/dbt.h — AArch64 DBT core: dispatcher, block cache, IBTC, RAS
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 2 lane L2b owns this file (SPEC sections 2-3, docs/lanes/phase-2.md
 * lane card L2b). Integer lowering lives in L2c's src/dbt/emit_int.h; L2b
 * owns the code buffer, the dispatcher, block chaining, and the trampoline.
 *
 * L2c contract (src/dbt/emit_int.h, frozen for L2b): before each
 * sparc32_emit_insn call L2b fills sparc32_emit_ctx_t (buf/pc/fault_pc and,
 * for CTI classes, delay). Every exit sequence carries the resume/fault
 * guest PC in w15 and the SPARC32_EXIT_* reason in w16; the trampoline
 * stores those to ctx->exit_dest/ctx->exit_reason and L2b commits pc/npc
 * from them on block exit. A page-final non-annulled branch at
 * (pc & 0xfff) == 0xffc is pre-empted with sparc32_emit_exit_singlestep.
 * Emitted BLR helpers are L2c's emit_priv.h runtime helpers, which run the
 * shared interp window/memory model (interp_priv.h); there is exactly one
 * window/memory model for interp/dbt difftest parity.
 *
 * Exit protocol: dbt_run/dbt_step return ctx->exit_reason with the same
 * SPARC32_EXIT_* values, fault_addr, and exit_dest convention as
 * interp_run/interp_step (src/interp/interp.h). EXIT_UNDEF and
 * EXIT_SINGLE_STEP from emitted code replay one interp_step at the exit
 * PC (genuine stops return to the caller); valid instructions never abort
 * execution. dbt_step translates and executes exactly one guest
 * instruction (CTI + delay slot counts as one step, as in interp_step)
 * with all chaining disabled, for --difftest lockstep.
 */

#ifndef SPARC32RT_DBT_DBT_H
#define SPARC32RT_DBT_DBT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sparc32rt.h"

/* Translation limits (lane card: up to 64 guest insns per block, stopping
 * at control transfers or guest page boundaries). */
#define DBT_MAX_INSNS_PER_BLOCK 64U
#define DBT_CACHE_SIZE          1024U
#define DBT_CODE_ARENA_SIZE     (4U * 1024U * 1024U)

/* Words of RW staging reserved per translation. Single-insn step
 * fragments need headroom for the worst two-path branch expansion;
 * block fragments scale with DBT_MAX_INSNS_PER_BLOCK. */
#define DBT_STEP_RESERVE_WORDS  1024U
#define DBT_BLOCK_RESERVE_WORDS (DBT_MAX_INSNS_PER_BLOCK * 128U)

/* Cached block descriptor (dispatcher metadata; host_code is staging
 * until dbt_code_publish flips the arena RX, NULL when needs_interp). */
typedef struct {
    uint32_t    start_pc;
    uint32_t    end_pc;      /* First guest PC past the block (covers an
                              * inline CTI delay slot). */
    uint32_t    n_insns;
    uint32_t    epoch;
    bool        valid;
    bool        needs_interp; /* No emitted code: run via interp_step. */
    bool        ends_cti;     /* Final insn is CALL/BRANCH/JMPL. */
    bool        ends_trap;    /* Final insn is a taken TA gate. */
    bool        is_link;      /* ends_cti with linkage (CALL, JMPL %o7). */
    bool        indirect;     /* ends_cti with register target. */
    const void *host_code;   /* RX entry point, NULL when needs_interp. */
} dbt_block_t;

/*
 * Run guest code until the dispatcher must stop, mirroring interp_run:
 * returns ctx->exit_reason (SPARC32_EXIT_SYSCALL, SPARC32_EXIT_FAULT,
 * SPARC32_EXIT_TRAP). EXIT_UNDEF / EXIT_SINGLE_STEP are consumed
 * internally (one interp_step at the exit PC, then resume) except when
 * the replay itself reports a stop without progress.
 */
int dbt_run(sparc32_ctx_t *ctx);

/*
 * Translate and execute exactly one guest instruction at ctx->pc with no
 * chaining: the --difftest oracle stepping stone (correctness over
 * speed). Returns ctx->exit_reason after that single instruction, using
 * the same replay rule as dbt_run for UNDEF/SINGLE_STEP.
 */
int dbt_step(sparc32_ctx_t *ctx);

/* Look up (translating on miss) the cached block starting at guest pc.
 * Returns NULL only when the start pc faults or the code arena is
 * exhausted; ctx->exit_reason/fault_addr describe the failure. */
const dbt_block_t *dbt_lookup(sparc32_ctx_t *ctx, uint32_t pc);

/* Invalidate every cached block (SMC on mprotect/munmap/clear_cache and
 * guest writes to translated pages call this; coarse whole-cache flush
 * is the Phase 2 policy). The code arena is recycled to RW staging. */
void dbt_flush(sparc32_ctx_t *ctx);

/* Reserve n_words of RW staging in the code arena (NULL when full; the
 * caller then treats the block as needs_interp). Reopens the arena RW
 * after a publish so translation continues across executions. */
uint32_t *dbt_code_reserve(sparc32_ctx_t *ctx, size_t n_words);

/*
 * Publish staged code: flip the arena to PROT_READ|PROT_EXEC and flush
 * the I-cache. Must precede the first host_code execution; guest data
 * pages are never mapped PROT_EXEC (the arena is anonymous memory outside
 * the [G, G + 4 GiB) window). Returns 0 on success, -1 on failure (the
 * block stays needs_interp).
 */
int dbt_code_publish(sparc32_ctx_t *ctx);

/*
 * Enter translated host code (implemented in trampoline_a64.S):
 *   x0 = ctx, x1 = entry (host RX address in the DBT code arena),
 *   x2 = chain entry for x27 (slots provisioned by dbt.c, NULL bails),
 *   x3 = epoch word for x28 (&g_cache_epoch to allow chaining).
 * On return, ctx->exit_reason/ctx->exit_dest carry w16/w15 and pc/npc are
 * committed from them (see dbt.c). Never touches x18.
 */
void dbt_enter_block(sparc32_ctx_t *ctx, const void *entry,
    const void *chain_entry, const uint32_t *epoch_ptr);

/*
 * Enter translated code with all chaining disabled for dbt_step
 * lockstep: x28 points at a zero epoch word so every RAS/IBTC/epoch
 * probe bails, and step fragments are emitted with guest_start_pc == 0
 * so the self-loop fast path is never taken. Exactly one guest
 * instruction executes before returning to C.
 */
void dbt_enter_step(sparc32_ctx_t *ctx, const void *entry,
    const void *chain_entry);

/* Chaining hook: record the pairing of block `from` to block `to` for
 * stats. Slot back-patching stays disabled in Phase 2 (slots are NULL so
 * every in-fragment chain probe bails to the C dispatcher, which chains
 * in software); this only records the pairing. */
void dbt_patch_chain(sparc32_ctx_t *ctx, const dbt_block_t *from,
    const dbt_block_t *to);

/* Introspection for tests/difftest. */
uint32_t dbt_cached_count(void);

#endif /* SPARC32RT_DBT_DBT_H */
