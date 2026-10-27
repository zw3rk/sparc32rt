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

#define SPARC32_WIN_MAXSAVE 7U

/* Window backing file (E01): flat r[] holds the live window; the other
 * seven l/i images survive here, so nesting round-trips with guest stack
 * traffic ONLY on WIM overflow/underflow traps (never on plain SAVE).
 * Single global file = one guest thread (Phase 4 needs a side table). */
static uint32_t interp_winfile[SPARC32_NWINDOWS][16];
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
    }
}

/* Spill winfile[w] (16 l/i words) to guest [va, va + 64). */
bool interp_spill_to(sparc32_ctx_t *ctx, uint32_t w, uint32_t va)
{
    uint8_t buf[SPARC32_RWINDOW_SIZE];
    uint32_t i;
    for (i = 0; i < 8U; i++) {
        uint32_t l = interp_winfile[w][i];
        uint32_t k = interp_winfile[w][8U + i];
        buf[4U * i] = (uint8_t)(l >> 24);
        buf[4U * i + 1U] = (uint8_t)(l >> 16);
        buf[4U * i + 2U] = (uint8_t)(l >> 8);
        buf[4U * i + 3U] = (uint8_t)l;
        buf[32U + 4U * i] = (uint8_t)(k >> 24);
        buf[32U + 4U * i + 1U] = (uint8_t)(k >> 16);
        buf[32U + 4U * i + 2U] = (uint8_t)(k >> 8);
        buf[32U + 4U * i + 3U] = (uint8_t)k;
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
    for (i = 0; i < 8U; i++) {
        interp_winfile[w][i] = ((uint32_t)buf[4U * i] << 24) |
            ((uint32_t)buf[4U * i + 1U] << 16) |
            ((uint32_t)buf[4U * i + 2U] << 8) |
            (uint32_t)buf[4U * i + 3U];
        interp_winfile[w][8U + i] = ((uint32_t)buf[32U + 4U * i] << 24) |
            ((uint32_t)buf[32U + 4U * i + 1U] << 16) |
            ((uint32_t)buf[32U + 4U * i + 2U] << 8) |
            (uint32_t)buf[32U + 4U * i + 3U];
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
        if (ctx->canrestore >= SPARC32_WIN_MAXSAVE) {
            uint32_t prev_w =
                (tgt + SPARC32_NWINDOWS - 1U) % SPARC32_NWINDOWS;
            uint32_t spill_sp = interp_winfile[prev_w][8U + 6U];
            if (spill_sp == 0U) {
                spill_sp = new_sp;
            }
            if (!interp_spill_to(ctx, tgt, spill_sp)) {
                return false;
            }
        }
        for (i = 0; i < 8U; i++) {
            old_o[i] = ctx->r[SPARC32_O0 + i];
        }
        for (i = 0; i < 8U; i++) {
            interp_winfile[ctx->cwp][i] = ctx->r[SPARC32_L0 + i];
            interp_winfile[ctx->cwp][8U + i] = ctx->r[SPARC32_I0 + i];
        }
        for (i = 0; i < 8U; i++) {
            ctx->r[SPARC32_I0 + i] = old_o[i];
            ctx->r[SPARC32_L0 + i] = interp_winfile[tgt][i];
        }
        ctx->cwp = tgt;
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
        }
        if (ctx->canrestore == 0U) {
            if (ctx->trace_enabled) {
                fprintf(stderr, "T underfill tgt=%u post_sp=%08x\n",
                        tgt, post_sp);
            }
            if (!interp_fill_from(ctx, tgt, post_sp)) {
                return false;
            }
        }
        for (i = 0; i < 8U; i++) {
            ctx->r[SPARC32_O0 + i] = old_i[i];
            ctx->r[SPARC32_L0 + i] = interp_winfile[tgt][i];
            ctx->r[SPARC32_I0 + i] = interp_winfile[tgt][8U + i];
        }
        ctx->cwp = tgt;
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
#define SPARC32_WIN_MAXSAVE 7U

