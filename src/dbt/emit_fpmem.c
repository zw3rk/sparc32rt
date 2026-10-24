/*
 * src/dbt/emit_fpmem.c — AArch64 FP load/store emitter (Phase 3, L3b).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from emit_fp.c for the 900-line file discipline. Lowers
 * LDF/LDDF/STF/STDF/LDFSR/STFSR through one faultable BLR helper
 * (sparc32_rt_fpmem) that reuses the shared interp accessors, so
 * alignment faults, region checks, and byte order match interp
 * exactly; LDQF/STQF and odd-rd LDDF/STDF exit EXIT_UNDEF.
 */

#include <stddef.h>
#include <stdint.h>

#include "interp/decode.h"
#include "interp/interp_priv.h"
#include "rt32/a64_emit.h"
#include "sparc32rt.h"

#include "dbt/emit_fp.h"
#include "dbt/emit_int.h"

/* Scratch allocation inside one emitted FPMEM instruction. */
#define FPMS0 15u /* w15/x15: exit guest PC / EA */
#define FPMS1 16u /* w16: exit reason */
#define FPMS2 17u /* w17: helper call target */

/* EXIT_UNDEF at ec->pc (quad / odd-rd double: manual-strict). */
static int fp_undef_here(sparc32_emit_ctx_t *ec)
{
    a64_emit_exit_undef(ec->buf, ec->pc);
    return ec->buf->overflow ? -1 : 0;
}

/* FPMEM lowering. The BLR-called helper checks alignment + region
 * through the shared interp accessors (doubleword pairs need
 * 8-alignment, which interp_mem does not enforce for len 8). */
static uint32_t sparc32_rt_fpmem(sparc32_ctx_t *ctx, uint32_t va,
    uint32_t op3, uint32_t rd)
{
    uint32_t v;

    ctx->exit_reason = SPARC32_EXIT_NONE;
    switch (op3) {
    case 0x20U: /* LDF */
        if (!interp_ld_be(ctx, va, 4U, &v)) {
            return ctx->exit_reason;
        }
        ctx->f[rd & 31U] = v;
        return SPARC32_EXIT_NONE;
    case 0x23U: /* LDDF: even rd only (emitter guarantees) */
        if ((va & 7U) != 0U) {
            ctx->exit_reason = SPARC32_EXIT_FAULT;
            ctx->fault_addr = va;
            return SPARC32_EXIT_FAULT;
        }
        if (!interp_ld_be(ctx, va, 4U, &v)) {
            return ctx->exit_reason;
        }
        ctx->f[rd & 31U] = v;
        if (!interp_ld_be(ctx, va + 4U, 4U, &v)) {
            return ctx->exit_reason;
        }
        ctx->f[(rd + 1U) & 31U] = v;
        return SPARC32_EXIT_NONE;
    case 0x24U: /* STF */
        if (!interp_st_be(ctx, va, 4U, ctx->f[rd & 31U])) {
            return ctx->exit_reason;
        }
        return SPARC32_EXIT_NONE;
    case 0x27U: /* STDF: even rd only (emitter guarantees) */
        if ((va & 7U) != 0U) {
            ctx->exit_reason = SPARC32_EXIT_FAULT;
            ctx->fault_addr = va;
            return SPARC32_EXIT_FAULT;
        }
        if (!interp_st_be(ctx, va, 4U, ctx->f[rd & 31U])) {
            return ctx->exit_reason;
        }
        if (!interp_st_be(ctx, va + 4U, 4U,
            ctx->f[(rd + 1U) & 31U])) {
            return ctx->exit_reason;
        }
        return SPARC32_EXIT_NONE;
    case 0x21U: /* LDFSR: full 32-bit round-trip (frozen contract 1) */
        if (!interp_ld_be(ctx, va, 4U, &v)) {
            return ctx->exit_reason;
        }
        ctx->fsr = v;
        return SPARC32_EXIT_NONE;
    case 0x25U: /* STFSR */
        if (!interp_st_be(ctx, va, 4U, ctx->fsr)) {
            return ctx->exit_reason;
        }
        return SPARC32_EXIT_NONE;
    default:
        break;
    }
    ctx->exit_reason = SPARC32_EXIT_UNDEF;
    return SPARC32_EXIT_UNDEF;
}

/* Effective address rs1 + (is_imm ? simm : rs2) into FPMS0. */
static void fp_ea_into(a64_buf_t *b, const sparc32_decoded_t *d)
{
    a64_emit_ldr_imm_w(b, FPMS2, A64_XCTX, (d->rs1 & 31U) * 4U);
    if (d->is_imm != 0U) {
        a64_emit_mov_imm32(b, FPMS0, (uint32_t)d->simm);
    } else {
        a64_emit_ldr_imm_w(b, FPMS0, A64_XCTX, (d->rs2 & 31U) * 4U);
    }
    a64_emit_add_reg_w(b, false, FPMS0, FPMS2, FPMS0, A64_SHIFT_LSL, 0U);
}

int sparc32_emit_fpmem(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    a64_buf_t *b;
    size_t p_fault;
    size_t p_cont;

    if (ec == NULL || ec->buf == NULL || d == NULL) {
        return -1;
    }
    b = ec->buf;
    if (d->op3 == (uint32_t)SPARC32_OP3_LDQF ||
        d->op3 == (uint32_t)SPARC32_OP3_STQF) {
        return fp_undef_here(ec);
    }
    if ((d->op3 == (uint32_t)SPARC32_OP3_LDDF ||
        d->op3 == (uint32_t)SPARC32_OP3_STDF) &&
        ((d->rd & 1U) != 0U)) {
        return fp_undef_here(ec);
    }
    fp_ea_into(b, d);
    /* w0 = ctx, w1 = EA, w2 = op3, w3 = rd. Same faultable-call shape
     * as the integer memory emitter (preserves x19-x28 per AAPCS64;
     * the fault block carries ec->fault_pc in w15 and the helper's
     * exit reason in w16, then returns to the dispatcher). */
    a64_emit_add_uxtw_x(b, 0U, A64_XCTX, A64_ZR);
    a64_emit_mov_w(b, 1U, FPMS0);
    a64_emit_mov_imm32(b, 2U, d->op3);
    a64_emit_mov_imm32(b, 3U, d->rd);
    a64_emit(b, 0xF81F0FFEU);
    fp_mov64x(b, FPMS2, (uint64_t)(uintptr_t)&sparc32_rt_fpmem);
    a64_emit(b, 0xD63F0000U | ((FPMS2 & 31U) << 5));
    a64_emit(b, 0xF84107FEU);
    p_fault = a64_emit_cbz_w_placeholder(b, true, 0U);
    p_cont = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    a64_patch_cbz_w(b, p_fault, b->count);
    a64_emit_mov_w(b, FPMS1, 0U);
    a64_emit_mov_pc32(b, FPMS0, ec->fault_pc);
    a64_emit_ret(b);
    a64_patch_b_cond(b, p_cont, b->count);
    return b->overflow ? -1 : 0;
}
