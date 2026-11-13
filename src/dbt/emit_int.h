/*
 * src/dbt/emit_int.h — AArch64 integer instruction emitter interface (Phase 2, L2c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L2c owns this file (Phase 2 card, SPEC sections 2-3). L2b consumes
 * it; L2b owns the code buffer, the dispatcher, block chaining, and the
 * trampoline. This unit never emits direct jumps to host addresses outside
 * the buffer: every control transfer out of a fragment goes through the
 * a64_emit exit sequences (owned by src/rt32/), which L2b chains. The only
 * out-of-buffer transfers this unit emits are BLR calls to its own
 * translator-local runtime helpers (declared in emit_priv.h and resolved at
 * emit time from the translator process address space) for ops whose guest
 * state lives outside ctx memory or needs region/ASI checks: SAVE/RESTORE
 * (shared interp window file), MUL/DIV/MULScc/TADD/TSUB (Y + traps), and
 * all loads/stores/atomics (alignment + region + big-endian + CASA).
 *
 * Contract with L2b (dispatcher / block builder):
 * - x19 holds sparc32_ctx_t *, x20 holds the G-window base (never x18).
 * - Guest registers live in ctx memory (r[32] at offset 0); the emitter
 *   performs no host register allocation for guest state, so emitted code
 *   is safe across helper calls (helpers preserve x19-x28 per AAPCS64).
 * - ctx->pc/npc are NOT advanced instruction by instruction. Every exit
 *   sequence carries the resume/fault guest PC in w15 and the reason in
 *   w16 (SPARC32_EXIT_*); L2b commits pc/npc from those on block exit.
 * - Before each sparc32_emit_insn call L2b sets ec->pc (insn address),
 *   ec->fault_pc (PC reported on fault exits; normally == pc), and, for
 *   CTI classes (CALL/BRANCH/JMPL), ec->delay to the decoded delay-slot
 *   instruction (or NULL when absent/unfetchable -> SINGLE_STEP fallback).
 * - A page-final non-annulled branch at (pc & 0xfff) == 0xffc must not be
 *   emitted normally; L2b emits sparc32_emit_exit_singlestep instead.
 * - CALL sets buf->is_call; JMPL with rd == %o7 sets buf->is_call for the
 *   RAS push path (L2b may override when it links the block).
 */

#ifndef SPARC32RT_DBT_EMIT_INT_H
#define SPARC32RT_DBT_EMIT_INT_H

#include <stdint.h>

#include "interp/decode.h"
#include "rt32/a64_emit.h"
#include "sparc32rt.h"

/* Per-instruction emit context (filled by L2b, consumed by this unit). */
typedef struct sparc32_emit_ctx {
    a64_buf_t *buf;              /* Code buffer; owned and managed by L2b. */
    uint32_t pc;                 /* Guest address of the insn being emitted. */
    uint32_t fault_pc;           /* Guest PC reported in w15 on fault exits. */
    const sparc32_decoded_t *delay; /* CTI delay-slot insn, or NULL. */
    bool fp_arith_more;          /* Another inline FP arith op follows in
                                  * this block before any FSR observer. */
} sparc32_emit_ctx_t;

/* Emit one decoded instruction. Returns 0 on success, -1 when the buffer
 * overflows (ec->buf->overflow is set; L2b terminates the block). */
int sparc32_emit_insn(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);
int sparc32_emit_one(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);

/* Commit pending batched FPSR flags to guest FSR (P5b). No-op unless
 * buf->fpsr_dirty; defined in emit_fp.c, called at every point that
 * observes FSR or clobbers host FPSR (CTI, traps, exits, helpers). */
void sparc32_emit_fp_flush(a64_buf_t *b);

/* Per-class translate functions (L2b may call these directly instead of
 * sparc32_emit_insn when it structures blocks itself). Same contract. */
int sparc32_emit_sethi(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);
int sparc32_emit_alu(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);
int sparc32_emit_shift(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);
int sparc32_emit_rdasr(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);
int sparc32_emit_wrasr(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);
int sparc32_emit_branch(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);
int sparc32_emit_call(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);
int sparc32_emit_jmpl(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);
int sparc32_emit_save(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);
int sparc32_emit_restore(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);
int sparc32_emit_trap(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);
int sparc32_emit_load(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);
int sparc32_emit_store(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);
int sparc32_emit_swap(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);
int sparc32_emit_casa(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);
int sparc32_emit_flush(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);
int sparc32_emit_stbar(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);
int sparc32_emit_priv(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);
int sparc32_emit_fallback(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);

/* SINGLE_STEP exit for L2b's page-final rule (and CTI delay fallback).
 * Carries pc in w15, SPARC32_EXIT_SINGLE_STEP in w16, then returns. */
int sparc32_emit_exit_singlestep(sparc32_emit_ctx_t *ec, uint32_t pc);

/* Delay-slot emitter for the shared page-final branch skeleton below:
 * emits the delay instruction addressed at npc (ec->pc/->fault_pc
 * already name it), like e_emit_delay / fp_emit_delay. */
typedef int (*sparc32_cti_delay_fn)(sparc32_emit_ctx_t *ec, uint32_t npc);

/* Shared page-final conditional-branch body (S32-R13-6): the not-taken
 * delay/exit runs under the caller's taken-test placeholder, which is
 * patched here (b_cond for Bicc, cbz for FBfcc); the taken delay runs
 * with jmpl record/disarm gated on e_delay_needs_jmpl_record(ec->delay)
 * so a taken delay fault commits npc = target. Both exits leave via
 * SINGLE_STEP. Implemented in emit_cti.c; called by sparc32_emit_branch
 * (Bicc) and sparc32_emit_fbranch (FBfcc). */
int sparc32_emit_branch_page_final(sparc32_emit_ctx_t *ec, uint32_t npc,
    uint32_t target, int not_taken_runs, int taken_runs,
    size_t taken_patch, int taken_is_cbz,
    sparc32_cti_delay_fn emit_delay);

#endif /* SPARC32RT_DBT_EMIT_INT_H */
