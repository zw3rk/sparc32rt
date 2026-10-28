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
#define FPMS3 21u /* w21: fast-path table base */

const uint8_t *sparc32_vm_prot_base(void);
const uint8_t *sparc32_vm_state_base(void);

/* Guest F register file word offset. */
#define FP_F_OFF ((uint32_t)offsetof(sparc32_ctx_t, f))

static uint32_t fp_f_off(uint32_t r)
{
    return FP_F_OFF + ((r & 31U) * 4U);
}

/* Same checks as Lane P5 sparc32_emit_mem_fast (emit_fast.c): per-4K
 * prot bit (0=READ, 1=WRITE); miss jumps to slow. */
static size_t f_check_prot(a64_buf_t *b, unsigned va_w, unsigned bit,
    const uint8_t *base)
{
    size_t p_slow;
    a64_emit_ubfm_w(b, FPMS2, va_w, 12u, 31u);
    if (base == NULL) {
        p_slow = a64_emit_cbz_w_placeholder(b, false, 31u);
        return p_slow;
    }
    fp_mov64x(b, FPMS3, (uint64_t)(uintptr_t)base);
    a64_emit_add_uxtw_x(b, FPMS3, FPMS3, FPMS2);
    a64_emit_ldrb_imm_w(b, FPMS2, FPMS3, 0u);
    a64_emit_ubfm_w(b, FPMS2, FPMS2, bit, bit);
    p_slow = a64_emit_cbz_w_placeholder(b, false, FPMS2);
    return p_slow;
}

static size_t f_check_align(a64_buf_t *b, unsigned va_w, unsigned hi_bit)
{
    size_t p_slow;
    a64_emit_ubfm_w(b, FPMS2, va_w, 0u, hi_bit);
    p_slow = a64_emit_cbz_w_placeholder(b, true, FPMS2);
    return p_slow;
}

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

/* w0 = ctx, w1 = EA, w2 = op3, w3 = rd. Same faultable-call shape
 * as the integer memory emitter (preserves x19-x28 per AAPCS64;
 * the fault block carries fault_pc in w15 and the helper's exit
 * reason in w16, then returns to the dispatcher). */
static void fp_slowcall(a64_buf_t *b, uint32_t op3, uint32_t rd,
    uint32_t fault_pc)
{
    size_t p_fault;
    size_t p_cont;
    sparc32_emit_fp_flush(b);
    b->fp_fast_checked = false;
    b->gpr_cache_valid = 0;
    a64_emit_add_uxtw_x(b, 0U, A64_XCTX, A64_ZR);
    a64_emit_mov_w(b, 1U, FPMS0);
    a64_emit_mov_imm32(b, 2U, op3);
    a64_emit_mov_imm32(b, 3U, rd);
    a64_emit(b, 0xF81F0FFEU);
    fp_mov64x(b, FPMS2, (uint64_t)(uintptr_t)&sparc32_rt_fpmem);
    a64_emit(b, 0xD63F0000U | ((FPMS2 & 31U) << 5));
    a64_emit(b, 0xF84107FEU);
    p_fault = a64_emit_cbz_w_placeholder(b, true, 0U);
    p_cont = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    a64_patch_cbz_w(b, p_fault, b->count);
    a64_emit_mov_w(b, FPMS1, 0U);
    a64_emit_mov_pc32(b, FPMS0, fault_pc);
    a64_emit_ret(b);
    a64_patch_b_cond(b, p_cont, b->count);
}

/* Inline fast path for LDF/STF (word) and LDDF/STDF (pair): align +
 * per-4K prot (+ code-page for stores), same as sparc32_emit_mem_fast.
 * 8-alignment keeps both double words in one 4K page, so one prot
 * lookup covers the pair. Any miss falls through to the
 * sparc32_rt_fpmem slow call. */
static int fp_emit_fast(a64_buf_t *b, const sparc32_decoded_t *d,
    uint32_t fault_pc, uint32_t op3)
{
    int is_store = (op3 == 0x24U || op3 == 0x27U) ? 1 : 0;
    int is_double = (op3 == 0x23U || op3 == 0x27U) ? 1 : 0;
    size_t p_a;
    size_t p_p;
    size_t p_c = (size_t)-1;
    size_t p_end;
    const uint8_t *prot = sparc32_vm_prot_base();
    const uint8_t *state = sparc32_vm_state_base();

    if (is_double != 0) {
        p_a = f_check_align(b, FPMS0, 2u);
    } else {
        p_a = f_check_align(b, FPMS0, 1u);
    }
    p_p = f_check_prot(b, FPMS0, (is_store != 0) ? 1u : 0u, prot);
    if (is_store != 0 && state != NULL) {
        a64_emit_ubfm_w(b, FPMS2, FPMS0, 12u, 31u);
        fp_mov64x(b, FPMS3, (uint64_t)(uintptr_t)state);
        a64_emit_add_uxtw_x(b, FPMS3, FPMS3, FPMS2);
        a64_emit_ldrb_imm_w(b, FPMS2, FPMS3, 0u);
        a64_emit_ubfm_w(b, FPMS2, FPMS2, 2u, 2u);
        p_c = a64_emit_cbz_w_placeholder(b, true, FPMS2);
    }
    if (is_store == 0) {
        a64_emit_guest_ldr_w(b, FPMS1, FPMS0);
        a64_emit_rev_w(b, FPMS1, FPMS1);
        a64_emit_str_imm_w(b, FPMS1, A64_XCTX, fp_f_off(d->rd));
        if (is_double != 0) {
            a64_emit_add_imm_w(b, false, FPMS2, FPMS0, 4u, 0u);
            a64_emit_guest_ldr_w(b, FPMS1, FPMS2);
            a64_emit_rev_w(b, FPMS1, FPMS1);
            a64_emit_str_imm_w(b, FPMS1, A64_XCTX,
                fp_f_off(d->rd + 1U));
        }
    } else {
        a64_emit_ldr_imm_w(b, FPMS1, A64_XCTX, fp_f_off(d->rd));
        a64_emit_rev_w(b, FPMS1, FPMS1);
        a64_emit_guest_str_w(b, FPMS1, FPMS0);
        if (is_double != 0) {
            a64_emit_ldr_imm_w(b, FPMS1, A64_XCTX,
                fp_f_off(d->rd + 1U));
            a64_emit_rev_w(b, FPMS1, FPMS1);
            a64_emit_add_imm_w(b, false, FPMS2, FPMS0, 4u, 0u);
            a64_emit_guest_str_w(b, FPMS1, FPMS2);
        }
    }
    p_end = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    {
        size_t slow = b->count;
        a64_patch_cbz_w(b, p_a, slow);
        a64_patch_cbz_w(b, p_p, slow);
        if (p_c != (size_t)-1) {
            a64_patch_cbz_w(b, p_c, slow);
        }
        fp_slowcall(b, op3, d->rd, fault_pc);
        a64_patch_b_cond(b, p_end, b->count);
    }
    return b->overflow ? -1 : 0;
}

int sparc32_emit_fpmem(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    a64_buf_t *b;

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
    if (d->op3 == 0x20U || d->op3 == 0x24U || d->op3 == 0x23U ||
        d->op3 == 0x27U) {
        return fp_emit_fast(b, d, ec->fault_pc, d->op3);
    }
    if (d->op3 == 0x21U) {
        b->fp_fast_checked = false;
    }
    fp_slowcall(b, d->op3, d->rd, ec->fault_pc);
    return b->overflow ? -1 : 0;
}
