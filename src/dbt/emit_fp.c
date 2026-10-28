/*
 * src/dbt/emit_fp.c — AArch64 FPU/FBfcc/FPMEM emitter (Phase 3, L3b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lowers every FPop/FPMEM op to AArch64 scalar FP/NEON (guest state
 * in ctx memory, v0-v7 scratch, never x18; raw encodings verified
 * against clang-assembled AArch64 reference bytes). NaN discipline
 * (E06): payload-preserving propagation; Invalid-Operation results
 * with no NaN input canonicalize to the oracle default. Converts
 * honor FSR.RD via FPCR.RMode (saved/restored around convert ops).
 */

#include "dbt/emit_fp.h"

#include <stddef.h>
#include <stdint.h>

#include "interp/decode.h"
#include "interp/interp_priv.h"
#include "rt32/a64_emit.h"
#include "sparc32rt.h"

/* Scratch allocation inside one emitted FPU instruction. */
#define FS0 15u /* w15/x15: scratch / exit guest PC */
#define FS1 16u /* w16/x16: scratch / exit reason / saved FPCR */
#define FS2 17u /* w17: scratch / helper call target */
#define FS3 21u /* w21: scratch */

/* Scratch FP/SIMD registers (v0..v7 are the FPU-lowering set). */
#define FVA 0u /* first source */
#define FVB 1u /* second source */
#define FVD 2u /* result */
#define FVT 3u /* temp (FsMULd second convert) */

/* ctx field offsets used by this emitter. */
#define FP_FSR_OFF ((uint32_t)offsetof(sparc32_ctx_t, fsr))
#define FP_F_OFF ((uint32_t)offsetof(sparc32_ctx_t, f))

/* FPSR helpers (defined below, used by the convert path). */
static void fp_fpsr_clear(a64_buf_t *b);
static void fp_cexc_clear(a64_buf_t *b);
static void fp_flags_commit(a64_buf_t *b);

/* Lane P5: fast-path FSR status. The inline FP sequence is valid only
 * when FSR.TEM == 0 (bits 27:23, no trapped exception) and FSR.RD == 0
 * (bits 31:30, round-to-nearest matches the host FPCR default);
 * otherwise exit UNDEF so the dispatcher replays via interp. */
static int fp_guard_fast(sparc32_emit_ctx_t *ec)
{
    a64_buf_t *b = ec->buf;
    size_t p_rd;
    size_t p_tem;
    a64_emit_ldr_imm_w(b, FS0, A64_XCTX, FP_FSR_OFF);
    a64_emit_ubfm_w(b, FS1, FS0, 30U, 31U);
    p_rd = a64_emit_cbz_w_placeholder(b, true, FS1);
    a64_emit_exit_undef(b, ec->fault_pc);
    if (b->overflow) {
        return -1;
    }
    a64_patch_cbz_w(b, p_rd, b->count);
    a64_emit_ubfm_w(b, FS1, FS0, 23U, 27U);
    p_tem = a64_emit_cbz_w_placeholder(b, true, FS1);
    a64_emit_exit_undef(b, ec->fault_pc);
    if (b->overflow) {
        return -1;
    }
    a64_patch_cbz_w(b, p_tem, b->count);
    return b->overflow ? -1 : 0;
}

/* Raw encodings verified against clang on AArch64 (lane notes). */
#define FP_DBIT 0x00400000U /* S->D selector in FP encodings */

static void fp3(a64_buf_t *b, uint32_t base, int is_d, unsigned vd,
    unsigned vn, unsigned vm)
{
    uint32_t w = base | (is_d ? FP_DBIT : 0U);

    a64_emit(b, w | ((vm & 31U) << 16) | ((vn & 31U) << 5) | (vd & 31U));
}

static void fp2(a64_buf_t *b, uint32_t base, int is_d, unsigned vd,
    unsigned vn)
{
    uint32_t w = base | (is_d ? FP_DBIT : 0U);

    a64_emit(b, w | ((vn & 31U) << 5) | (vd & 31U));
}

static void fp_cmp(a64_buf_t *b, int is_d, unsigned vn, unsigned vm)
{
    uint32_t w = 0x1E202000U | (is_d ? FP_DBIT : 0U);

    a64_emit(b, w | ((vm & 31U) << 16) | ((vn & 31U) << 5));
}

static void fp_mov_d_from_x(a64_buf_t *b, unsigned vd, unsigned rn_x)
{
    a64_emit(b, 0x9E670000U | ((rn_x & 31U) << 5) | (vd & 31U));
}

static void fp_mov_x_from_d(a64_buf_t *b, unsigned rd_x, unsigned vn)
{
    a64_emit(b, 0x9E660000U | ((vn & 31U) << 5) | (rd_x & 31U));
}

static void fp_mrs_fpcr(a64_buf_t *b, unsigned rt_x)
{
    a64_emit(b, 0xD53B4400U | (rt_x & 31U));
}

static void fp_msr_fpcr(a64_buf_t *b, unsigned rt_x)
{
    a64_emit(b, 0xD51B4400U | (rt_x & 31U));
}

/* 64-bit shift/or used to pack/unpack guest doubles (hi << 32 | lo). */
static void fp_lsl_x32(a64_buf_t *b, unsigned rd_x, unsigned rn_x)
{
    a64_emit(b, 0xD3607C00U | ((rn_x & 31U) << 5) | (rd_x & 31U));
}

static void fp_lsr_x32(a64_buf_t *b, unsigned rd_x, unsigned rn_x)
{
    a64_emit(b, 0xD360FC00U | ((rn_x & 31U) << 5) | (rd_x & 31U));
}

static void fp_orr_x(a64_buf_t *b, unsigned rd_x, unsigned rn_x,
    unsigned rm_x)
{
    a64_emit(b, 0xAA000000U | ((rm_x & 31U) << 16) |
        ((rn_x & 31U) << 5) | (rd_x & 31U));
}

/* Guest FP traffic: singles one word; doubles f[2k]=hi,f[2k+1]=lo. */

static uint32_t fp_s_off(uint32_t r)
{
    return FP_F_OFF + ((r & 31U) * 4U);
}

static uint32_t fp_d_off(uint32_t r)
{
    return FP_F_OFF + ((r & 30U) * 4U);
}

static void fp_ld_s(a64_buf_t *b, unsigned vt, uint32_t r)
{
    a64_emit_ldr_imm_w(b, FS0, A64_XCTX, fp_s_off(r));
    a64_emit_fmov_w_to_s(b, vt, FS0);
}

static void fp_st_s(a64_buf_t *b, uint32_t r, unsigned vn)
{
    a64_emit_fmov_s_to_w(b, FS0, vn);
    a64_emit_str_imm_w(b, FS0, A64_XCTX, fp_s_off(r));
}

static void fp_ld_d(a64_buf_t *b, unsigned vt, uint32_t r)
{
    uint32_t off = fp_d_off(r);

    a64_emit_ldr_imm_w(b, FS0, A64_XCTX, off);
    a64_emit_ldr_imm_w(b, FS1, A64_XCTX, off + 4U);
    fp_lsl_x32(b, FS0, FS0);
    fp_orr_x(b, FS0, FS0, FS1);
    fp_mov_d_from_x(b, vt, FS0);
}

static void fp_st_d(a64_buf_t *b, uint32_t r, unsigned vn)
{
    uint32_t off = fp_d_off(r);

    fp_mov_x_from_d(b, FS0, vn);
    fp_lsr_x32(b, FS1, FS0);
    a64_emit_str_imm_w(b, FS1, A64_XCTX, off);
    a64_emit_str_imm_w(b, FS0, A64_XCTX, off + 4U);
}

/* FSR.RD -> FPCR.RMode (SPARC 0=RN,1=RZ,2=RP,3=RM; AArch64
 * 0=RN,1=RP,2=RM,3=RZ; map 0->0,1->3,2->1,3->2). Convert ops only. */

static void fp_rd_to_rmode(a64_buf_t *b, unsigned w_rd, unsigned w_rm)
{
    a64_emit_mov_w(b, w_rm, w_rd);
    /* RD == 1 (RZ) -> 3 */
    a64_emit_mov_imm32(b, FS2, 1U);
    a64_emit_mov_imm32(b, FS3, 3U);
    a64_emit_sub_imm_w(b, true, A64_ZR, w_rd, 1U, 0U);
    a64_emit_csel_w(b, w_rm, FS3, w_rm, A64_COND_EQ);
    /* RD == 2 (RP) -> 1 */
    a64_emit_sub_imm_w(b, true, A64_ZR, w_rd, 2U, 0U);
    a64_emit_csel_w(b, w_rm, FS2, w_rm, A64_COND_EQ);
    /* RD == 3 (RM) -> 2 */
    a64_emit_mov_imm32(b, FS2, 2U);
    a64_emit_sub_imm_w(b, true, A64_ZR, w_rd, 3U, 0U);
    a64_emit_csel_w(b, w_rm, FS2, w_rm, A64_COND_EQ);
}

/* Load RD into FPCR.RMode; the previous FPCR is kept in xFS2. */
static void fp_fpcr_set_rmode(a64_buf_t *b, unsigned w_rd, unsigned w_rm)
{
    /* Save to xFS2 (xFS1 holds the rmode; w_rd is dead by now). */
    fp_rd_to_rmode(b, w_rd, w_rm);
    fp_mrs_fpcr(b, FS2);
    fp_mrs_fpcr(b, FS3);
    a64_emit_bfi_x(b, FS3, A64_ZR, 22U, 2U);
    a64_emit_mov_w(b, FS0, w_rm);
    a64_emit_bfi_x(b, FS3, FS0, 22U, 2U);
    fp_msr_fpcr(b, FS3);
}

static void fp_fpcr_restore(a64_buf_t *b)
{
    fp_msr_fpcr(b, FS2);
    /* Converts are the only FPCR clients; commit their FPSR flags
     * here (the GPR store that follows cannot disturb FPSR). */
    fp_flags_commit(b);
}

/* NaN canonicalization (E06): a result NaN with no NaN input takes
 * the oracle default (0x7FFFFFFF / 0x7FFFFFFFFFFFFFFF); NaN inputs
 * keep the propagated result. */

static void fp_canon(a64_buf_t *b, int is_d, unsigned vd, unsigned va,
    int has_b, unsigned vb)
{
    size_t p_done;
    size_t p_keep;
    size_t p_keep2 = (size_t)-1;

    /* Fast path first (result not NaN -> done); every exit lands
     * past the canonicalize block. */
    /* MRS leaves NZCV in bits 31:28, so the V flag is bit 28. */
    fp_cmp(b, is_d, vd, vd);
    a64_emit_mrs_nzcv(b, FS0);
    a64_emit_ubfm_w(b, FS0, FS0, 28U, 28U);
    p_done = a64_emit_cbz_w_placeholder(b, false, FS0);
    fp_cmp(b, is_d, va, va);
    a64_emit_mrs_nzcv(b, FS0);
    a64_emit_ubfm_w(b, FS0, FS0, 28U, 28U);
    p_keep = a64_emit_cbz_w_placeholder(b, true, FS0);
    if (has_b != 0) {
        fp_cmp(b, is_d, vb, vb);
        a64_emit_mrs_nzcv(b, FS0);
        a64_emit_ubfm_w(b, FS0, FS0, 28U, 28U);
        p_keep2 = a64_emit_cbz_w_placeholder(b, true, FS0);
    }
    if (is_d == 0) {
        a64_emit_mov_imm32(b, FS0, 0x7FFFFFFFU);
        a64_emit_fmov_w_to_s(b, vd, FS0);
    } else {
        fp_mov64x(b, FS0, 0x7FFFFFFFFFFFFFFFULL);
        fp_mov_d_from_x(b, vd, FS0);
    }
    a64_patch_cbz_w(b, p_keep, b->count);
    if (has_b != 0) {
        a64_patch_cbz_w(b, p_keep2, b->count);
    }
    a64_patch_cbz_w(b, p_done, b->count);
}

/* FPSR cumulative flags (AArch64): IXC=bit4, UFC=bit3, OFC=bit2,
 * DZC=bit1, IOC=bit0. Guest cexc: NXC=bit0, DZC=bit1, UFC=bit2,
 * OFC=bit3, NVC=bit4 (fp.h); every FPop clears cexc and accrues
 * aexc (cexc<<5). MRS NZCV reads the same FPSR (bits 31:28). */

/* Drop stale host cumulative flags before a guest FP op. */
static void fp_fpsr_clear(a64_buf_t *b)
{
    a64_emit(b, 0xD51B4420U | 31U); /* MSR FPSR, xzr */
}

/* Clear guest cexc (moves: no flags, matching fp_clear_cexc). */
static void fp_cexc_clear(a64_buf_t *b)
{
    a64_emit_ldr_imm_w(b, FS0, A64_XCTX, FP_FSR_OFF);
    a64_emit_mov_imm32(b, FS1, 0xFFFFFFE0U);
    a64_emit_and_reg_w(b, false, FS0, FS0, FS1, A64_SHIFT_LSL, 0U);
    a64_emit_str_imm_w(b, FS0, A64_XCTX, FP_FSR_OFF);
}

/* Merge fresh FPSR cumulative flags into guest FSR (NZCV already
 * consumed): cexc = permuted fresh bits (h4->b0, h1->b1, h3->b2,
 * h2->b3, h0->b4), aexc accrues. Uses w22 as the MRS target so the
 * convert result in FS0 stays live (header scratch contract). */
static void fp_flags_commit(a64_buf_t *b)
{
    a64_emit(b, 0xD53B4420U | 22U); /* MRS w22, FPSR */
    a64_emit_ubfm_w(b, FS1, 22U, 4U, 4U);
    a64_emit_ubfm_w(b, FS2, 22U, 1U, 1U);
    a64_emit_orr_reg_w(b, FS1, FS1, FS2, A64_SHIFT_LSL, 1U);
    a64_emit_ubfm_w(b, FS2, 22U, 3U, 3U);
    a64_emit_orr_reg_w(b, FS1, FS1, FS2, A64_SHIFT_LSL, 2U);
    a64_emit_ubfm_w(b, FS2, 22U, 2U, 2U);
    a64_emit_orr_reg_w(b, FS1, FS1, FS2, A64_SHIFT_LSL, 3U);
    a64_emit_ubfm_w(b, FS2, 22U, 0U, 0U);
    a64_emit_orr_reg_w(b, FS1, FS1, FS2, A64_SHIFT_LSL, 4U);
    /* fsr = (fsr & ~0x1F) | cexc | (cexc << 5). */
    a64_emit_ldr_imm_w(b, FS2, A64_XCTX, FP_FSR_OFF);
    a64_emit_mov_imm32(b, FS3, 0xFFFFFFE0U);
    a64_emit_and_reg_w(b, false, FS2, FS2, FS3, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, FS2, FS2, FS1, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, FS2, FS2, FS1, A64_SHIFT_LSL, 5U);
    a64_emit_str_imm_w(b, FS2, A64_XCTX, FP_FSR_OFF);
}

/* fcc commit (FCMP/FCMPE): map NZCV to fcc (V->3, Z->0, N^V->1,
 * else 2); replace the fcc field, set FSR bit 9 when unordered.
 * NVC (cexc bit4 + accrue) fires on IOC, or on FCMPE-unordered
 * (matching fp_cmp_f32/f64: signal || SNaN). */

static void fp_fcc_commit(a64_buf_t *b, int signal)
{
    /* FS0 = NZCV nibble; FS1 = V (unordered flag); FS0 = fcc. */
    a64_emit_mrs_nzcv(b, FS0);
    a64_emit_ubfm_w(b, FS0, FS0, 28U, 31U);
    a64_emit_ubfm_w(b, FS1, FS0, 0U, 0U);
    a64_emit_ubfm_w(b, FS2, FS0, 2U, 2U);
    a64_emit_ubfm_w(b, FS3, FS0, 3U, 3U);
    a64_emit_eor_reg_w(b, FS3, FS3, FS1, A64_SHIFT_LSL, 0U);
    a64_emit_mov_imm32(b, FS0, 2U);
    a64_emit_sub_imm_w(b, true, A64_ZR, FS3, 1U, 0U);
    a64_emit_csel_w(b, FS0, FS3, FS0, A64_COND_EQ);
    a64_emit_sub_imm_w(b, true, A64_ZR, FS2, 1U, 0U);
    a64_emit_csel_w(b, FS0, A64_ZR, FS0, A64_COND_EQ);
    a64_emit_sub_imm_w(b, true, A64_ZR, FS1, 1U, 0U);
    a64_emit_mov_imm32(b, FS3, 3U);
    a64_emit_csel_w(b, FS0, FS3, FS0, A64_COND_EQ);
    /* Merge: clear fcc + cexc, OR fcc << 10 and unordered << 9. */
    a64_emit_ldr_imm_w(b, FS2, A64_XCTX, FP_FSR_OFF);
    a64_emit_mov_imm32(b, FS3, 0xFFFFF3E0U);
    a64_emit_and_reg_w(b, false, FS2, FS2, FS3, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, FS2, FS2, FS0, A64_SHIFT_LSL, 10U);
    a64_emit_orr_reg_w(b, FS2, FS2, FS1, A64_SHIFT_LSL, 9U);
    /* NVC: IOC from a fresh FPSR read (NZCV consumed above; FS0 is
     * spent holding fcc). V is still in FS1. */
    a64_emit(b, 0xD53B4420U | (uint32_t)FS0); /* MRS FS0, FPSR */
    a64_emit_ubfm_w(b, FS0, FS0, 0U, 0U);     /* FS0 = IOC */
    if (signal != 0) {
        a64_emit_orr_reg_w(b, FS0, FS0, FS1, A64_SHIFT_LSL, 0U);
    }
    a64_emit_orr_reg_w(b, FS2, FS2, FS0, A64_SHIFT_LSL, 4U);
    a64_emit_orr_reg_w(b, FS2, FS2, FS0, A64_SHIFT_LSL, 9U);
    a64_emit_str_imm_w(b, FS2, A64_XCTX, FP_FSR_OFF);
}

/* ---- FPop1/FPop2 lowering -------------------------------------------- */

static int fp_undef(sparc32_emit_ctx_t *ec)
{
    a64_emit_exit_undef(ec->buf, ec->pc);
    return ec->buf->overflow ? -1 : 0;
}

/* Bitwise moves: FMOV/FNEG/FABS touch one word (or the pair high
 * word), so the other lane keeps paired-single independence. */
static int fp_emit_bitwise(sparc32_emit_ctx_t *ec, uint32_t opf,
    uint32_t rd, uint32_t rs2)
{
    a64_buf_t *b = ec->buf;
    uint32_t off;

    /* V8 FPop parity: odd opf = single, even opf = double. */
    if ((opf & 1U) != 0U) {
        off = fp_s_off(rs2);
    } else {
        off = fp_d_off(rs2 & 30U);
    }
    a64_emit_ldr_imm_w(b, FS0, A64_XCTX, off);
    if (opf == 0x005U || opf == 0x006U) {
        a64_emit_mov_imm32(b, FS1, 0x80000000U);
        a64_emit_eor_reg_w(b, FS0, FS0, FS1, A64_SHIFT_LSL, 0U);
    } else if (opf == 0x009U || opf == 0x00AU) {
        a64_emit_mov_imm32(b, FS1, 0x80000000U);
        a64_emit_bic_reg_w(b, false, FS0, FS0, FS1, A64_SHIFT_LSL, 0U);
    }
    if ((opf & 1U) != 0U) {
        a64_emit_str_imm_w(b, FS0, A64_XCTX, fp_s_off(rd));
    } else {
        a64_emit_str_imm_w(b, FS0, A64_XCTX, fp_d_off(rd));
    }
    /* Moves never raise (matching fp.c); clear stale cexc. */
    fp_cexc_clear(b);
    return b->overflow ? -1 : 0;
}

/* Arithmetic: FADD/FSUB/FMUL/FDIV s+d, FSQRT s+d, FsMULd. */
static int fp_emit_arith(sparc32_emit_ctx_t *ec, uint32_t opf,
    uint32_t rd, uint32_t rs1, uint32_t rs2)
{
    a64_buf_t *b = ec->buf;
    int is_d = (opf == 0x042U || opf == 0x046U || opf == 0x04AU ||
        opf == 0x04EU || opf == 0x02AU || opf == 0x069U) ? 1 : 0;
    uint32_t base = 0U;
    if (fp_guard_fast(ec) != 0) {
        return -1;
    }
    fp_fpsr_clear(b);

    switch (opf) {
    case 0x041U: case 0x042U: base = 0x1E202800U; break;
    case 0x045U: case 0x046U: base = 0x1E203800U; break;
    case 0x049U: case 0x04AU: base = 0x1E200800U; break;
    case 0x04DU: case 0x04EU: base = 0x1E201800U; break;
    case 0x029U: case 0x02AU: base = 0x1E21C000U; break;
    default: break;
    }
    if (opf == 0x069U) {
        /* FsMULd: exact widening multiply (NaN-ness preserved). */
        fp_ld_s(b, FVA, rs1);
        fp_ld_s(b, FVB, rs2);
        a64_emit_fcvt_s_to_d(b, FVA, FVA);
        a64_emit_fcvt_s_to_d(b, FVB, FVB);
        fp3(b, 0x1E200800U, 1, FVD, FVA, FVB);
        fp_canon(b, 1, FVD, FVA, 1, FVB);
        fp_st_d(b, rd, FVD);
        fp_flags_commit(b);
        return b->overflow ? -1 : 0;
    }
    /* FSQRT is unary (source in rs2); the rest are binary. */
    if (opf == 0x029U || opf == 0x02AU) {
        if (is_d != 0) {
            fp_ld_d(b, FVA, rs2);
        } else {
            fp_ld_s(b, FVA, rs2);
        }
        fp2(b, base, is_d, FVD, FVA);
        fp_canon(b, is_d, FVD, FVA, 0, 0U);
    } else {
        if (is_d != 0) {
            fp_ld_d(b, FVA, rs1);
            fp_ld_d(b, FVB, rs2);
        } else {
            fp_ld_s(b, FVA, rs1);
            fp_ld_s(b, FVB, rs2);
        }
        fp3(b, base, is_d, FVD, FVA, FVB);
        fp_canon(b, is_d, FVD, FVA, 1, FVB);
    }
    if (is_d != 0) {
        fp_st_d(b, rd, FVD);
    } else {
        fp_st_s(b, rd, FVD);
    }
    fp_flags_commit(b);
    return b->overflow ? -1 : 0;
}

/* Conversions (integer operands live in the F file as raw
 * patterns). FRINT32X rounds per FPCR.RMode (FRINTI never signals
 * inexact, so it cannot drive the NXC commit); the rest converts
 * exactly, so the sequence honors FSR.RD. */
static void fp_rd_load(a64_buf_t *b)
{
    a64_emit_ldr_imm_w(b, FS0, A64_XCTX, FP_FSR_OFF);
    a64_emit_ubfm_w(b, FS0, FS0, 30U, 31U);
}

static int fp_emit_convert(sparc32_emit_ctx_t *ec, uint32_t opf,
    uint32_t rd, uint32_t rs2)
{
    a64_buf_t *b = ec->buf;

    fp_fpsr_clear(b);
    /* FP operands first (double loads use xFS1), then RD/FPCR. */
    switch (opf) {
    case 0x0C4U: /* FiTOs: int bits -> single */
        fp_rd_load(b);
        fp_fpcr_set_rmode(b, FS0, FS1);
        a64_emit_ldr_imm_w(b, FS0, A64_XCTX, fp_s_off(rs2));
        a64_emit_scvtf_w_to_s(b, FVD, FS0);
        fp_fpcr_restore(b);
        fp_st_s(b, rd, FVD);
        return b->overflow ? -1 : 0;
    case 0x0C8U: /* FiTOd: int bits -> double */
        fp_rd_load(b);
        fp_fpcr_set_rmode(b, FS0, FS1);
        a64_emit_ldr_imm_w(b, FS0, A64_XCTX, fp_s_off(rs2));
        a64_emit_scvtf_w_to_d(b, FVD, FS0);
        fp_fpcr_restore(b);
        fp_st_d(b, rd, FVD);
        return b->overflow ? -1 : 0;
    case 0x0D1U: /* FsTOi: single -> int bits (always RZ per V8 B.28) */
        fp_ld_s(b, FVA, rs2);
        a64_emit_fcvtzs_s_to_w(b, FS0, FVA);
        fp_flags_commit(b);
        a64_emit_str_imm_w(b, FS0, A64_XCTX, fp_s_off(rd));
        return b->overflow ? -1 : 0;
    case 0x0D2U: /* FdTOi: double -> int bits (always RZ per V8 B.28) */
        fp_ld_d(b, FVA, rs2);
        a64_emit_fcvtzs_d_to_w(b, FS0, FVA);
        fp_flags_commit(b);
        a64_emit_str_imm_w(b, FS0, A64_XCTX, fp_s_off(rd));
        return b->overflow ? -1 : 0;
    case 0x0C9U: /* FsTOd: single -> double */
        fp_ld_s(b, FVA, rs2);
        fp_rd_load(b);
        fp_fpcr_set_rmode(b, FS0, FS1);
        a64_emit_fcvt_s_to_d(b, FVD, FVA);
        fp_fpcr_restore(b);
        fp_st_d(b, rd, FVD);
        return b->overflow ? -1 : 0;
    case 0x0C6U: /* FdTOs: double -> single */
        fp_ld_d(b, FVA, rs2);
        fp_rd_load(b);
        fp_fpcr_set_rmode(b, FS0, FS1);
        a64_emit_fcvt_d_to_s(b, FVD, FVA);
        fp_fpcr_restore(b);
        fp_st_s(b, rd, FVD);
        return b->overflow ? -1 : 0;
    default:
        break;
    }
    return fp_undef(ec);
}

/* FCMP/FCMPE s+d (FCMPE never traps: qemu-compatible). */
static int fp_emit_cmp(sparc32_emit_ctx_t *ec, uint32_t opf,
    uint32_t rs1, uint32_t rs2)
{
    a64_buf_t *b = ec->buf;
    int is_d = (opf == 0x052U || opf == 0x056U) ? 1 : 0;

    if (fp_guard_fast(ec) != 0) {
        return -1;
    }
    if (is_d != 0) {
        fp_ld_d(b, FVA, rs1);
        fp_ld_d(b, FVB, rs2);
    } else {
        fp_ld_s(b, FVA, rs1);
        fp_ld_s(b, FVB, rs2);
    }
    fp_fpsr_clear(b);
    fp_cmp(b, is_d, FVA, FVB);
    fp_fcc_commit(b, (opf == 0x055U || opf == 0x056U) ? 1 : 0);
    return b->overflow ? -1 : 0;
}

/* FPop dispatcher: double-dest needs even rd, double sources need
 * even rs1/rs2 (manual-strict; covers decoder gaps FSQRTd, FiTOd,
 * FsMULd, so no decode.c change is needed). */

static int fp_double_dest(uint32_t op3, uint32_t opf)
{
    if (op3 == (uint32_t)SPARC32_OP3_FPOP1) {
        switch (opf) {
        case 0x002U: case 0x006U: case 0x00AU:
        case 0x042U: case 0x046U: case 0x04AU: case 0x04EU:
        case 0x02AU: case 0x069U:
        case 0x0C8U: case 0x0C9U: case 0x0CBU:
            return 1;
        default:
            return 0;
        }
    }
    if (op3 == (uint32_t)SPARC32_OP3_FPOP2) {
        return opf == 0x069U ? 1 : 0;
    }
    return 0;
}

/* which: 1 = rs1, 2 = rs2. Arithmetic-d and FCMPd/FCMPEd take
 * double rs1+rs2; FSQRTd/FdTOi/FdTOs take double rs2 only. */
static int fp_double_source(uint32_t op3, uint32_t opf, int which)
{
    if (op3 == (uint32_t)SPARC32_OP3_FPOP1) {
        switch (opf) {
        case 0x042U: case 0x046U: case 0x04AU: case 0x04EU:
            return 1;
        case 0x02AU:
            return which == 2 ? 1 : 0;
        case 0x0D2U: case 0x0C6U:
            return which == 2 ? 1 : 0;
        default:
            return 0;
        }
    }
    if (op3 == (uint32_t)SPARC32_OP3_FPOP2) {
        if (opf == 0x052U || opf == 0x056U) {
            return 1;
        }
    }
    return 0;
}

int sparc32_emit_fpu(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    uint32_t op3;
    uint32_t opf;
    uint32_t rd;
    uint32_t rs1;
    uint32_t rs2;
    int rc;

    if (ec == NULL || ec->buf == NULL || d == NULL) {
        return -1;
    }
    op3 = d->op3;
    opf = d->opf;
    rd = d->rd;
    rs1 = d->rs1;
    rs2 = d->rs2;
    if (fp_double_dest(op3, opf) != 0 && ((rd & 1U) != 0U)) {
        return fp_undef(ec);
    }
    if (fp_double_source(op3, opf, 1) != 0 && ((rs1 & 1U) != 0U)) {
        return fp_undef(ec);
    }
    if (fp_double_source(op3, opf, 2) != 0 && ((rs2 & 1U) != 0U)) {
        return fp_undef(ec);
    }
    /* Straight-line FPop lowers inline like FPMEM: it falls through and
     * L2b emits the single fallthrough exit at the end of the block. */
    if (op3 == (uint32_t)SPARC32_OP3_FPOP1) {
        switch (opf) {
        case 0x001U: case 0x002U:
        case 0x005U: case 0x006U:
        case 0x009U: case 0x00AU:
            if ((opf & 1U) == 0U && ((rs2 & 1U) != 0U)) {
                return fp_undef(ec); /* double source must be even */
            }
            rc = fp_emit_bitwise(ec, opf, rd, rs2);
            break;
        case 0x041U: case 0x042U:
        case 0x045U: case 0x046U:
        case 0x049U: case 0x04AU:
        case 0x04DU: case 0x04EU:
        case 0x029U: case 0x02AU:
        case 0x069U:
            rc = fp_emit_arith(ec, opf, rd, rs1, rs2);
            break;
        case 0x0C4U: case 0x0C8U:
        case 0x0D1U: case 0x0D2U:
        case 0x0C9U: case 0x0C6U:
            if (opf == 0x0C9U && ((rs2 & 1U) != 0U)) {
                return fp_undef(ec); /* FsTOd double source odd */
            }
            rc = fp_emit_convert(ec, opf, rd, rs2);
            break;
        default:
            return fp_undef(ec);
        }
    } else if (op3 == (uint32_t)SPARC32_OP3_FPOP2) {
        switch (opf) {
        case 0x051U: case 0x052U:
        case 0x055U: case 0x056U:
            rc = fp_emit_cmp(ec, opf, rs1, rs2);
            break;
        case 0x069U:
            rc = fp_emit_arith(ec, opf, rd, rs1, rs2);
            break;
        default:
            return fp_undef(ec);
        }
    } else {
        return fp_undef(ec);
    }
    if (rc != 0) {
        return rc;
    }
    return 0;
}

/* FBfcc transfer (mirrors Bicc on FSR.fcc: 0 equal, 1 less,
 * 2 greater, 3 unordered; cond numbering mirrors Bicc). */

/* Taken predicate: 4-bit mask over fcc (GAS-verified numbering). */
static const uint32_t fp_taken_mask[16] = {
    0x0U, 0xEU, 0x6U, 0xAU, 0x2U, 0xCU, 0x4U, 0x8U,
    0xFU, 0x1U, 0x9U, 0x5U, 0xDU, 0x3U, 0xBU, 0x8U
};

static void fp_taken_compute(a64_buf_t *b, uint32_t cond)
{
    a64_emit_ldr_imm_w(b, FS0, A64_XCTX, FP_FSR_OFF);
    a64_emit_ubfm_w(b, FS0, FS0, 10U, 11U);
    a64_emit_mov_imm32(b, FS1, fp_taken_mask[cond & 15U]);
    a64_emit_shift_reg_w(b, FS1, FS1, FS0, A64_SHIFT_LSR);
    a64_emit_ubfm_w(b, FS1, FS1, 0U, 0U);
}

/* Delay policy (E02 annul): taken BA/FBA skips the delay;
 * annulled not-taken never fetches. */
static int fp_emit_delay(sparc32_emit_ctx_t *ec, uint32_t npc);
static int fp_delay_runs(uint32_t cond, int taken, int annul)
{
    if (taken != 0) {
        return (cond == 0x8U && annul != 0) ? 0 : 1;
    }
    return annul != 0 ? 0 : 1;
}

/* Emit the delay slot when it runs, then leave the fragment. A
 * page-final delay that ran exits via SINGLE_STEP (interp_cti tail);
 * every other path exits plainly to post. */
static int fp_delay_tail(sparc32_emit_ctx_t *ec, uint32_t npc,
    uint32_t post, int runs, int page_final)
{
    int rc;

    if (runs != 0) {
        rc = fp_emit_delay(ec, npc);
        if (rc != 0) {
            return rc;
        }
        if (page_final != 0) {
            return sparc32_emit_exit_singlestep(ec, post);
        }
    }
    a64_emit_exit_branch(ec->buf, post);
    return ec->buf->overflow ? -1 : 0;
}

/* Integer delay-slot classes route to the public L2c emitters (the
 * delay address is in ec->pc, the CTI address stays in ec->fault_pc,
 * exactly like the integer e_emit_delay). One case per line to hold
 * the 900-line file budget. */
static int fp_emit_int_delay(sparc32_emit_ctx_t *ec,
    const sparc32_decoded_t *d)
{
    switch (d->cls) {
    case SPARC32_OP_SETHI: return sparc32_emit_sethi(ec, d);
    case SPARC32_OP_ALU: return sparc32_emit_alu(ec, d);
    case SPARC32_OP_SHIFT: return sparc32_emit_shift(ec, d);
    case SPARC32_OP_RDASR: return sparc32_emit_rdasr(ec, d);
    case SPARC32_OP_WRASR: return sparc32_emit_wrasr(ec, d);
    case SPARC32_OP_PRIV: return sparc32_emit_priv(ec, d);
    case SPARC32_OP_SAVE: return sparc32_emit_save(ec, d);
    case SPARC32_OP_RESTORE: return sparc32_emit_restore(ec, d);
    case SPARC32_OP_FLUSH: return sparc32_emit_flush(ec, d);
    case SPARC32_OP_STBAR: return sparc32_emit_stbar(ec, d);
    case SPARC32_OP_LOAD: return sparc32_emit_load(ec, d);
    case SPARC32_OP_STORE: return sparc32_emit_store(ec, d);
    case SPARC32_OP_SWAP: return sparc32_emit_swap(ec, d);
    case SPARC32_OP_CASA: return sparc32_emit_casa(ec, d);
    default: break;
    }
    return sparc32_emit_fallback(ec, d);
}

static int fp_emit_delay(sparc32_emit_ctx_t *ec, uint32_t npc)
{
    const sparc32_decoded_t *d = ec->delay;
    uint32_t saved_pc = ec->pc;
    int rc;

    if (d == NULL) {
        return sparc32_emit_exit_singlestep(ec, ec->fault_pc);
    }
    switch (d->cls) {
    case SPARC32_OP_CALL:
    case SPARC32_OP_BRANCH:
    case SPARC32_OP_JMPL:
    case SPARC32_OP_TRAP:
    case SPARC32_OP_FBRANCH:
        /* CTI/TRAP in the delay slot: pristine SINGLE_STEP so the
         * dispatcher replays the outer transfer via interp_step. */
        return sparc32_emit_exit_singlestep(ec, ec->fault_pc);
    case SPARC32_OP_FPU:
        ec->pc = npc;
        rc = sparc32_emit_fpu(ec, d);
        ec->pc = saved_pc;
        return rc;
    case SPARC32_OP_FPMEM:
        ec->pc = npc;
        rc = sparc32_emit_fpmem(ec, d);
        ec->pc = saved_pc;
        return rc;
    case SPARC32_OP_ILLEGAL:
        a64_emit_exit_undef(ec->buf, npc);
        return ec->buf->overflow ? -1 : 0;
    default:
        break;
    }
    ec->pc = npc;
    rc = fp_emit_int_delay(ec, d);
    ec->pc = saved_pc;
    return rc;
}

int sparc32_emit_fbranch(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    a64_buf_t *b;
    uint32_t pc;
    uint32_t npc;
    uint32_t target;
    uint32_t cond;
    int annul;
    int page_final;
    size_t p_taken;
    size_t p_end;
    int rc;

    if (ec == NULL || ec->buf == NULL || d == NULL) {
        return -1;
    }
    b = ec->buf;
    pc = ec->pc;
    npc = pc + 4U;
    target = pc + (uint32_t)d->disp;
    cond = d->cond;
    annul = d->annul != 0U;
    page_final = ((pc & 0xFFFU) == 0xFFCU) ? 1 : 0;
    ec->fault_pc = pc;
    if (cond == 0x0U) { /* FBN: never branches. */
        return fp_delay_tail(ec, npc, npc + 4U,
            fp_delay_runs(cond, 0, annul), page_final);
    }
    if (cond == 0x8U) { /* FBA: always branches. */
        return fp_delay_tail(ec, npc, target,
            fp_delay_runs(cond, 1, annul), page_final);
    }
    if (page_final != 0) {
        fp_taken_compute(b, cond);
        p_taken = a64_emit_cbz_w_placeholder(b, true, FS1);
        rc = fp_delay_tail(ec, npc, npc + 4U,
            fp_delay_runs(cond, 0, annul), page_final);
        if (rc != 0) {
            return rc;
        }
        a64_patch_cbz_w(b, p_taken, b->count);
        /* Taken page-final always SINGLE_STEPs (emit_branch shape),
         * even when the delay was annulled away. */
        if (fp_delay_runs(cond, 1, annul) != 0) {
            rc = fp_emit_delay(ec, npc);
            if (rc != 0) {
                return rc;
            }
        }
        return sparc32_emit_exit_singlestep(ec, target);
    }
    fp_taken_compute(b, cond);
    p_taken = a64_emit_cbz_w_placeholder(b, true, FS1);
    if (fp_delay_runs(cond, 0, annul) != 0) {
        rc = fp_emit_delay(ec, npc);
        if (rc != 0) {
            return rc;
        }
    }
    p_end = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    a64_patch_cbz_w(b, p_taken, b->count);
    if (fp_delay_runs(cond, 1, annul) != 0) {
        rc = fp_emit_delay(ec, npc);
        if (rc != 0) {
            return rc;
        }
    }
    a64_emit_exit_branch(b, target);
    if (b->overflow) {
        return -1;
    }
    a64_patch_b_cond(b, p_end, b->count);
    a64_emit_exit_branch(b, npc + 4U);
    return b->overflow ? -1 : 0;
}
