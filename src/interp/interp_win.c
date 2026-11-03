/*
 * src/interp/interp_win.c — Register-window file (Phase 1, RC1 split)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
V8 window backing store + WIM + SAVE/RESTORE executor (E01 model).
 */

#include "sparc32rt.h"

#include "interp/decode.h"
#include "interp/interp_priv.h"

#include <stdio.h>
#include <string.h>

#define SPARC32_WIN_MAXSAVE 7U

/* Window backing file (E01): flat r[] holds the live window; the other
 * seven l/i images survive here, so nesting round-trips with guest stack
 * traffic ONLY on WIM overflow/underflow traps (never on plain SAVE).
 * Single global file = one guest thread (Phase 4 needs a side table). */
static _Thread_local uint32_t interp_winfile[SPARC32_NWINDOWS][16];
/* Outgoing registers per window (S32-R7-1): %o of window N overlaps %i
 * of window N-1, so plain l/i caching loses the popped window's %o.
 * Each window's %o image survives here across rotations. */
static _Thread_local uint32_t interp_win_o[SPARC32_NWINDOWS][8];
/* Home stack address of each cached window (its %sp at cache time) and
 * liveness: only valid slots hold outstanding frames whose home is still
 * theirs. Dead slots' homes are live stack space by now (reused by
 * descendant frames, unwound longjmp levels, or post-flush reuse), so
 * spills/fills must consult validity, never a bare nonzero slot. */
static _Thread_local uint32_t interp_winsp[SPARC32_NWINDOWS];
static _Thread_local uint32_t interp_win_valid[SPARC32_NWINDOWS];

void interp_window_clone_save(uint32_t wf[SPARC32_NWINDOWS][16],
    uint32_t wsp[SPARC32_NWINDOWS], uint32_t wv[SPARC32_NWINDOWS],
    uint32_t wo[SPARC32_NWINDOWS][8])
{
    memcpy(wf, interp_winfile, sizeof(interp_winfile));
    memcpy(wsp, interp_winsp, sizeof(interp_winsp));
    memcpy(wv, interp_win_valid, sizeof(interp_win_valid));
    memcpy(wo, interp_win_o, sizeof(interp_win_o));
}

void interp_window_clone_restore(const uint32_t wf[SPARC32_NWINDOWS][16],
    const uint32_t wsp[SPARC32_NWINDOWS],
    const uint32_t wv[SPARC32_NWINDOWS],
    const uint32_t wo[SPARC32_NWINDOWS][8])
{
    memcpy(interp_winfile, wf, sizeof(interp_winfile));
    memcpy(interp_winsp, wsp, sizeof(interp_winsp));
    memcpy(interp_win_valid, wv, sizeof(interp_win_valid));
    memcpy(interp_win_o, wo, sizeof(interp_win_o));
}
/* V8 window count tracker: ctx->canrestore counts valid caller windows
 * currently cached in interp_winfile[1..SPARC32_WIN_MAXSAVE]. SAVE spills
 * the oldest cached caller window (tgt) to its own %sp (stored in
 * winfile[(tgt - 1) mod 8][I6]) iff canrestore == SPARC32_WIN_MAXSAVE;
 * RESTORE fills tgt from post-restore %sp (old_i[6]) iff canrestore == 0. */

/* Reset window state for a fresh guest (main calls this once per run). */
void interp_window_reset(void)
{
    uint32_t w;
    uint32_t i;
    for (w = 0; w < (uint32_t)SPARC32_NWINDOWS; w++) {
        for (i = 0; i < 16U; i++) {
            interp_winfile[w][i] = 0U;
        }
        for (i = 0; i < 8U; i++) {
            interp_win_o[w][i] = 0U;
        }
        interp_winsp[w] = 0U;
        interp_win_valid[w] = 0U;
    }
}

/* JIT-visible base of the window backing file (P13-4): the inline
 * SAVE/RESTORE fast path rotates ctx->r[8..31] against this array
 * with 64-bit LDP/STP instead of calling interp_window. */
uint32_t *interp_winfile_base(void)
{
    return &interp_winfile[0][0];
}

/* JIT-visible home-address and liveness arrays (DBT validity gates):
 * slot w is spillable/fillable only while interp_win_valid[w] is set,
 * and then only at interp_winsp[w]. */
uint32_t *interp_winsp_base(void)
{
    return &interp_winsp[0];
}

uint32_t *interp_win_valid_base(void)
{
    return &interp_win_valid[0];
}

/* JIT-visible base of the outgoing-register images (S32-R7-1). */
uint32_t *interp_wino_base(void)
{
    return &interp_win_o[0][0];
}

/* Spill winfile[w] (16 l/i words) to guest [va, va + 64). */
bool interp_spill_to(sparc32_ctx_t *ctx, uint32_t w, uint32_t va)
{
    uint8_t buf[SPARC32_RWINDOW_SIZE];
    uint32_t i;
    for (i = 0; i < 16U; i++) {
        uint32_t be = __builtin_bswap32(interp_winfile[w][i]);
        memcpy(&buf[4U * i], &be, 4U);
    }
    return interp_mem_wr(ctx, va, buf, SPARC32_RWINDOW_SIZE);
}

/* Fill winfile[w] from guest [va, va + 64). Outs are never filled (E01:
 * o0/o1 survive restore because fill skips them). */
bool interp_fill_from(sparc32_ctx_t *ctx, uint32_t w, uint32_t va)
{
    uint8_t buf[SPARC32_RWINDOW_SIZE];
    uint32_t i;
    if (!interp_mem_rd(ctx, va, buf, SPARC32_RWINDOW_SIZE)) {
        return false;
    }
    for (i = 0; i < 16U; i++) {
        uint32_t be;
        memcpy(&be, &buf[4U * i], 4U);
        interp_winfile[w][i] = __builtin_bswap32(be);
    }
    return true;
}
bool interp_window(sparc32_ctx_t *ctx, const sparc32_decoded_t *d,
    bool is_save)
{
    uint32_t a = ctx->r[d->rs1];
    uint32_t b = (d->is_imm != 0U) ? (uint32_t)d->simm
                                   : ctx->r[d->rs2];
    uint32_t i;
    /* Trap rule (E01): SAVE/RESTORE trap iff WIM[target] is set. Fresh
     * (CWP=0, WIM=0x01): first SAVE 0->7 is free, first RESTORE 7->0
     * fills l/i from [post-restore sp]. Stack I/O only in these traps. */
    if (is_save) {
        uint32_t old_o[8];
        uint32_t new_sp = a + b;
        uint32_t tgt =
            (ctx->cwp + SPARC32_NWINDOWS - 1U) % SPARC32_NWINDOWS;
        if (interp_win_valid[tgt] != 0U) {
            /* Evict the outgoing slot back to its own recorded home:
             * the stack copy must precede reuse so a later underflow
             * fill sees the evicted image. The home is only trusted
             * for a valid (outstanding) image; spilling a dead slot
             * would clobber the live frame reusing that stack space. */
            if (!interp_spill_to(ctx, tgt, interp_winsp[tgt])) {
                return false;
            }
        }
        for (i = 0; i < 8U; i++) {
            old_o[i] = ctx->r[SPARC32_O0 + i];
        }
        for (i = 0; i < 8U; i++) {
            interp_winfile[ctx->cwp][i] = ctx->r[SPARC32_L0 + i];
            interp_winfile[ctx->cwp][8U + i] = ctx->r[SPARC32_I0 + i];
            interp_win_o[ctx->cwp][i] = old_o[i];
        }
        interp_winsp[ctx->cwp] = ctx->r[SPARC32_SP];
        interp_win_valid[ctx->cwp] = 1U;
        for (i = 0; i < 8U; i++) {
            ctx->r[SPARC32_I0 + i] = old_o[i];
            ctx->r[SPARC32_L0 + i] = interp_winfile[tgt][i];
        }
        /* S32-R7-1: RESTORE saves the popped window's %o into
         * interp_win_o before clearing validity, so the image survives
         * for the next SAVE to this level; always restore it here. */
        for (i = 0; i < 8U; i++) {
            ctx->r[SPARC32_O0 + i] = interp_win_o[tgt][i];
        }
        ctx->cwp = tgt;
        /* The reused slot keeps its recorded (valid, home) image: the
         * stack copy spilled above stays pristine, and a later restore
         * of that level must see the evicted image, not the incoming
         * frame (which lives in registers until it saves). */
        /* Mirror CWP into PSR bits 4..0 (P13-4: the inline fast path
         * commits the same word, so both engines agree exactly). */
        ctx->psr = (ctx->psr & ~0x1FU) | tgt;
        if (ctx->cansave > 0U) {
            ctx->cansave--;
        }
        if (ctx->canrestore < SPARC32_WIN_MAXSAVE) {
            ctx->canrestore++;
        }
        interp_wreg(ctx, d->rd, new_sp);
        return true;
    }
    /* RESTORE */
    {
        uint32_t old_i[8];
        uint32_t res = a + b;
        uint32_t tgt = (ctx->cwp + 1U) % SPARC32_NWINDOWS;
        uint32_t post_sp;
        for (i = 0; i < 8U; i++) {
            old_i[i] = ctx->r[SPARC32_I0 + i];
        }
        post_sp = old_i[6];
        for (i = 0; i < 8U; i++) {
            interp_winfile[ctx->cwp][i] = ctx->r[SPARC32_L0 + i];
            interp_winfile[ctx->cwp][8U + i] = ctx->r[SPARC32_I0 + i];
            interp_win_o[ctx->cwp][i] = ctx->r[SPARC32_O0 + i];
        }
        /* The switched-out frame dies with this pop: its cached copy
         * must not be mistaken for an outstanding image by a later
         * reuse or flush. */
        interp_winsp[ctx->cwp] = ctx->r[SPARC32_SP];
        interp_win_valid[ctx->cwp] = 0U;
        if (interp_win_valid[tgt] == 0U) {
            /* The target holds nothing usable (fresh, evicted, or
             * longjmp-invalidated): refill it from its home slot
             * instead of rotating stale data into the live window. */
            if (ctx->trace_enabled) {
                fprintf(stderr, "T underfill tgt=%u post_sp=%08x\n",
                        tgt, post_sp);
            }
            if (!interp_fill_from(ctx, tgt, post_sp)) {
                return false;
            }
            interp_winsp[tgt] = post_sp;
            interp_win_valid[tgt] = 1U;
        }
        for (i = 0; i < 8U; i++) {
            ctx->r[SPARC32_O0 + i] = old_i[i];
            ctx->r[SPARC32_L0 + i] = interp_winfile[tgt][i];
            ctx->r[SPARC32_I0 + i] = interp_winfile[tgt][8U + i];
        }
        ctx->cwp = tgt;
        /* Mirror CWP into PSR bits 4..0 (P13-4: the inline fast path
         * commits the same word, so both engines agree exactly). */
        ctx->psr = (ctx->psr & ~0x1FU) | tgt;
        if (ctx->canrestore > 0U) {
            ctx->canrestore--;
        }
        if (ctx->cansave < SPARC32_WIN_MAXSAVE) {
            ctx->cansave++;
        }
        interp_wreg(ctx, d->rd, res);
        return true;
    }
}

/* Flush-windows trap (ta 3): publish the live window chain to the
 * guest stack (E03 model keeps windows cached; the trap makes the stack
 * authoritative for setjmp/longjmp and signal-frame spills). Only slots
 * holding outstanding (valid) images are written, each to its recorded
 * home frame: a dead image's home slot is live stack space by now, and
 * touching it would clobber descendant frames. The live window stays in
 * registers. */
bool interp_flush_windows(sparc32_ctx_t *ctx)
{
    uint32_t w;
    if (ctx == NULL) {
        return false;
    }
    for (w = 0U; w < (uint32_t)SPARC32_NWINDOWS; w++) {
        if (w == ctx->cwp) {
            interp_win_valid[w] = 0U;
            continue;
        }
        if (interp_win_valid[w] == 0U) {
            continue;
        }
        if (!interp_spill_to(ctx, w, interp_winsp[w])) {
            return false;
        }
        interp_win_valid[w] = 0U;
    }
    ctx->canrestore = 0U;
    ctx->cansave = SPARC32_WIN_MAXSAVE;
    return true;
}

