/*
 * src/interp/fp.c — FPU/SIMD reference interpreter (Phase 3, lane L3a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Executes every FPop1/FPop2 opf the L1a decoder yields (singles and
 * even-pair doubles, conversions with all four FSR.RD modes per the V8
 * manual, FCMP/FCMPE with fcc, LDF/LDDF/STF/STDF, LDFSR/STFSR). Quad
 * (FqTOd, FDMULq, LDQF/STQF), 64-bit integer forms (FiTOx, FxTOx,
 * FSTOX), odd-rd double destinations and unlisted opf trap EXIT_UNDEF
 * loudly, per
 * the manual-strict translator contract (the oracle executes several of
 * these leniently; difftest covers interp-vs-dbt parity instead).
 *
 * Oracle rules implemented here (qemu-sparc 7.2 -cpu LEON3, probed):
 * - NaN propagation preserves the larger payload (rs1 wins ties);
 *   invalid operations yield 0x7FFFFFFF_FFFFFFFF / 0x7FFFFFFF.
 * - Every FPop clears FSR cexc (bits 4:0), ORs the op's IEEE flags
 *   (invalid->NVC, overflow->OFC, underflow->UFC, divzero->DZC,
 *   inexact->NXC) and accumulates them into aexc (<< 5). FCMP rewrites
 *   fcc; unordered sets NVA, plus NVC when signaling or SNaN. All other
 *   FPop classes preserve fcc.
 * - Arithmetic always rounds to nearest (qemu/L3b parity); only the
 *   int<->float conversions honor FSR.RD, per the manual.
 */

#include "interp/fp.h"

#include "interp/decode.h"
#include "interp/interp_priv.h"

#include <math.h>
#include <stdint.h>
#include <string.h>
static uint32_t fp_fcc(const sparc32_ctx_t *ctx)
{
    return (ctx->fsr >> SPARC32_FSR_FCC_SHIFT) & 3U;
}
static bool fp_undef(sparc32_ctx_t *ctx, uint32_t pc)
{
    ctx->exit_reason = SPARC32_EXIT_UNDEF;
    ctx->exit_dest = pc;
    return false;
}

/* Double-dest opfs (even-pair rd required; the decoder already rejects
 * most odd-rd forms, this covers the remainder such as FiTOd/FsMULd). */
static bool fp_double_dest(uint32_t opf)
{
    switch (opf) {
    case FP_OPF_FMOVD:
    case FP_OPF_FNEGD:
    case FP_OPF_FABSD:
    case FP_OPF_FADDD:
    case FP_OPF_FSUBD:
    case FP_OPF_FMULD:
    case FP_OPF_FDIVD:
    case FP_OPF_FITOD:
    case FP_OPF_FSTOD:
    case FP_OPF_FSMULD:
        return true;
    default:
        return false;
    }
}

bool sparc32_fp_step(sparc32_ctx_t *ctx, uint32_t pc,
    const sparc32_decoded_t *d)
{
    uint32_t opf = d->opf;
    uint32_t rs1 = d->rs1;
    uint32_t rs2 = d->rs2;
    uint32_t rd = d->rd;
    if (fp_double_dest(opf) && ((rd & 1U) != 0U)) {
        return fp_undef(ctx, pc);
    }
    switch (opf) {
    case FP_OPF_FMOVS:
        fp_clear_cexc(ctx);
        fp_put_s(ctx, rd, fp_get_s(ctx, rs2));
        return true;
    case FP_OPF_FMOVD:
        fp_clear_cexc(ctx);
        fp_put_d(ctx, rd, fp_get_d(ctx, rs2));
        return true;
    case FP_OPF_FNEGS:
        fp_clear_cexc(ctx);
        fp_put_s(ctx, rd, fp_get_s(ctx, rs2) ^ 0x80000000U);
        return true;
    case FP_OPF_FNEGD:
        fp_clear_cexc(ctx);
        fp_put_d(ctx, rd, fp_get_d(ctx, rs2) ^ 0x8000000000000000ULL);
        return true;
    case FP_OPF_FABSS:
        fp_clear_cexc(ctx);
        fp_put_s(ctx, rd, fp_get_s(ctx, rs2) & 0x7FFFFFFFU);
        return true;
    case FP_OPF_FABSD:
        fp_clear_cexc(ctx);
        fp_put_d(ctx, rd, fp_get_d(ctx, rs2) & 0x7FFFFFFFFFFFFFFFULL);
        return true;
    case FP_OPF_FADDS:
        fp_put_s(ctx, rd,
            fp_add_f32(ctx, fp_get_s(ctx, rs1), fp_get_s(ctx, rs2)));
        return true;
    case FP_OPF_FADDD:
        fp_put_d(ctx, rd,
            fp_add_f64(ctx, fp_get_d(ctx, rs1), fp_get_d(ctx, rs2)));
        return true;
    case FP_OPF_FSUBS:
        fp_put_s(ctx, rd,
            fp_sub_f32(ctx, fp_get_s(ctx, rs1), fp_get_s(ctx, rs2)));
        return true;
    case FP_OPF_FSUBD:
        fp_put_d(ctx, rd,
            fp_sub_f64(ctx, fp_get_d(ctx, rs1), fp_get_d(ctx, rs2)));
        return true;
    case FP_OPF_FMULS:
        fp_put_s(ctx, rd,
            fp_mul_f32(ctx, fp_get_s(ctx, rs1), fp_get_s(ctx, rs2)));
        return true;
    case FP_OPF_FMULD:
        fp_put_d(ctx, rd,
            fp_mul_f64(ctx, fp_get_d(ctx, rs1), fp_get_d(ctx, rs2)));
        return true;
    case FP_OPF_FDIVS:
        fp_put_s(ctx, rd,
            fp_div_f32(ctx, fp_get_s(ctx, rs1), fp_get_s(ctx, rs2)));
        return true;
    case FP_OPF_FDIVD:
        fp_put_d(ctx, rd,
            fp_div_f64(ctx, fp_get_d(ctx, rs1), fp_get_d(ctx, rs2)));
        return true;
    case FP_OPF_FSQRTS:
        fp_put_s(ctx, rd, fp_sqrt_f32(ctx, fp_get_s(ctx, rs2)));
        return true;
    case FP_OPF_FSQRTD:
        fp_put_d(ctx, rd, fp_sqrt_f64(ctx, fp_get_d(ctx, rs2)));
        return true;
    case FP_OPF_FCMPS:
        fp_cmp_f32(ctx, fp_get_s(ctx, rs1), fp_get_s(ctx, rs2), false);
        return true;
    case FP_OPF_FCMPD:
        fp_cmp_f64(ctx, fp_get_d(ctx, rs1), fp_get_d(ctx, rs2), false);
        return true;
    case FP_OPF_FCMPES:
        fp_cmp_f32(ctx, fp_get_s(ctx, rs1), fp_get_s(ctx, rs2), true);
        return true;
    case FP_OPF_FCMPED:
        fp_cmp_f64(ctx, fp_get_d(ctx, rs1), fp_get_d(ctx, rs2), true);
        return true;
    case FP_OPF_FSMULD: {
        uint64_t w;
        uint32_t a = fp_get_s(ctx, rs1);
        uint32_t b = fp_get_s(ctx, rs2);
        fp_clear_cexc(ctx);
        if (fp_f32_issnan(a) || fp_f32_issnan(b)) {
            uint32_t s = fp_f32_issnan(a) ? fp_f32_quiet(a)
                                          : fp_f32_quiet(b);
            fp_raise(ctx, FP_FSR_NVC_BIT);
            fp_put_d(ctx, rd, fp_f64_to_u64((double)fp_u32_to_f32(s)));
            return true;
        }
        if (fp_f32_isnan(a) || fp_f32_isnan(b)) {
            uint32_t n = fp_f32_pick_nan(a, b);
            fp_put_d(ctx, rd, fp_f32_to_f64(ctx, n));
            return true;
        }
        w = fp_f64_to_u64(
            (double)fp_u32_to_f32(a) * (double)fp_u32_to_f32(b));
        fp_put_d(ctx, rd, w);
        return true;
    }
    case FP_OPF_FITOS:
        fp_put_s(ctx, rd, fp_to_f32(ctx,
            (double)(int32_t)fp_get_s(ctx, rs2), fp_rd(ctx)));
        return true;
    case FP_OPF_FITOD:
        fp_clear_cexc(ctx);
        fp_put_d(ctx, rd,
            fp_f64_to_u64((double)(int32_t)fp_get_s(ctx, rs2)));
        return true;
    case FP_OPF_FSTOI:
        /* The converted integer lands in the FP register file (the V8
         * FPop format names %f registers on both sides); V8 B.28 fixes
         * rounding toward zero (FP_RD_RZ), ignoring FSR.RD. */
        fp_put_s(ctx, rd, fp_to_i32(ctx,
            (double)fp_u32_to_f32(fp_get_s(ctx, rs2)), FP_RD_RZ));
        return true;
    case FP_OPF_FDTOI:
        fp_put_s(ctx, rd, fp_to_i32(ctx,
            fp_u64_to_f64(fp_get_d(ctx, rs2)), FP_RD_RZ));
        return true;
    case FP_OPF_FSTOD:
        fp_put_d(ctx, rd, fp_f32_to_f64(ctx, fp_get_s(ctx, rs2)));
        return true;
    case FP_OPF_FDTOS:
        fp_put_s(ctx, rd, fp_to_f32(ctx,
            fp_u64_to_f64(fp_get_d(ctx, rs2)), fp_rd(ctx)));
        return true;
    default:
        break;
    }
    /* Quad, 64-bit integer and unlisted opf: loud UNDEF. */
    return fp_undef(ctx, pc);
}

bool sparc32_fp_mem(sparc32_ctx_t *ctx, uint32_t pc,
    const sparc32_decoded_t *d)
{
    uint32_t addr = ctx->r[d->rs1] +
        ((d->is_imm != 0U) ? (uint32_t)d->simm : ctx->r[d->rs2]);
    uint32_t v;
    uint32_t hi;
    uint32_t lo;
    switch (d->op3) {
    case SPARC32_OP3_LDF:
        if (!interp_ld_be(ctx, addr, 4U, &v)) {
            return false;
        }
        fp_put_s(ctx, d->rd, v);
        return true;
    case SPARC32_OP3_LDFSR:
        if (!interp_ld_be(ctx, addr, 4U, &v)) {
            return false;
        }
        ctx->fsr = v;
        return true;
    case SPARC32_OP3_LDDF:
        if ((d->rd & 1U) != 0U) {
            return fp_undef(ctx, pc);
        }
        /* V8 LDDF needs 8-byte alignment (S32-R5-1): fault like the DBT
         * helper instead of succeeding as two 4-byte halves. */
        if ((addr & 7U) != 0U) {
            ctx->exit_reason = SPARC32_EXIT_FAULT;
            ctx->fault_addr = addr;
            return false;
        }
        if (!interp_ld_be(ctx, addr, 4U, &hi)) {
            return false;
        }
        if (!interp_ld_be(ctx, addr + 4U, 4U, &lo)) {
            return false;
        }
        fp_put_s(ctx, d->rd, hi);
        fp_put_s(ctx, d->rd + 1U, lo);
        return true;
    case SPARC32_OP3_STF:
        return interp_st_be(ctx, addr, 4U, fp_get_s(ctx, d->rd));
    case SPARC32_OP3_STFSR:
        return interp_st_be(ctx, addr, 4U, ctx->fsr);
    case SPARC32_OP3_STDF:
        if ((d->rd & 1U) != 0U) {
            return fp_undef(ctx, pc);
        }
        /* V8 STDF needs 8-byte alignment (S32-R5-1): fault like the DBT
         * helper instead of succeeding as two 4-byte halves. */
        if ((addr & 7U) != 0U) {
            ctx->exit_reason = SPARC32_EXIT_FAULT;
            ctx->fault_addr = addr;
            return false;
        }
        if (!interp_st_be(ctx, addr, 4U, fp_get_s(ctx, d->rd))) {
            return false;
        }
        return interp_st_be(ctx, addr + 4U, 4U,
            fp_get_s(ctx, d->rd + 1U));
    default:
        break;
    }
    /* LDQF/STQF (quad) and anything else FP-memory: loud UNDEF. */
    return fp_undef(ctx, pc);
}

/* FBfcc taken-set per fcc value (oracle-verified, see fp.h). Bit k of
 * the entry for cond c is set when fcc == k takes the branch. */
static const uint8_t fp_fcc_taken[16] = {
    0x00U, /* FBN: never */
    0x0EU, /* FBNE: unordered, less, greater */
    0x06U, /* FBLG: less, greater */
    0x0AU, /* FBUL: unordered, less */
    0x02U, /* FBL: less */
    0x0CU, /* FBUG: unordered, greater */
    0x04U, /* FBG: greater */
    0x08U, /* FBU: unordered */
    0x0FU, /* FBA: always */
    0x01U, /* FBE: equal */
    0x09U, /* FBUE: unordered, equal */
    0x05U, /* FBGE: greater, equal */
    0x0DU, /* FBUGE: unordered, greater, equal */
    0x03U, /* FBLE: less, equal */
    0x0BU, /* FBULE: unordered, less, equal */
    0x07U, /* FBO: ordered (equal, less, greater) */
};

bool sparc32_fp_branch_taken(const sparc32_ctx_t *ctx, uint32_t cond)
{
    if ((cond & ~0xFU) != 0U) {
        return false;
    }
    return ((uint32_t)fp_fcc_taken[cond] & (1U << fp_fcc(ctx))) != 0U;
}
