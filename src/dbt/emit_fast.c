/*
 * src/dbt/emit_fast.c — Lane P5 inline fast paths (loads/stores, SMUL/UMUL)
 * plus Lane P13-4 (x25 prot probe, SAVE/RESTORE window fast path)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Inline aligned LD/ST/LDUB/STB/LDUH/STH, LDSW/LDSB/LDSH, LDD/STD
 * plus SMUL/UMUL. Loads/stores
 * check alignment and the x25-cached per-4K prot byte (bit 0 READ,
 * bit 3 writable-and-code-free); any miss funnels to the canonical
 * helper with a precise EXIT_FAULT or a slow SMC store, never a host
 * SIGSEGV.
 */

#include "dbt/emit_fast.h"

#include <stdint.h>

#include "interp/decode.h"
#include "interp/interp_priv.h"
#include "rt32/a64_emit.h"
#include "sparc32rt.h"

const uint8_t *sparc32_vm_prot_base(void);
extern uint32_t sparc32_rt_window(sparc32_ctx_t *ctx, uint32_t rs1,
    uint32_t src2, uint32_t rd, uint32_t ctl, uint32_t pc);
uint32_t *interp_winfile_base(void);
extern void vm_invalidate_jit(sparc32_ctx_t *ctx, uint32_t start,
    uint32_t end);

#define F_ES0 15u
#define F_ES1 16u
#define F_ES2 17u
#define F_ES3 21u
/* x25: trampoline-cached g_vm32_prot base (callee-saved, hence live
 * across helper calls); never x18. */
#define F_PROT 25u

/* Call-sequence words (mirror emit_int.c). */
#define F_STR_X30_PRE 0xF81F0FFEu
#define F_LDR_X30_POST 0xF84107FEu
#define F_BLR_BASE 0xD63F0000u

static void f_mov64(a64_buf_t *b, unsigned rd, uint64_t v)
{
    a64_emit(b, 0xD2800000u | (((uint32_t)v & 0xFFFFu) << 5) |
        (rd & 31u));
    a64_emit(b, 0xF2800000u | (1u << 21) |
        (((uint32_t)(v >> 16) & 0xFFFFu) << 5) | (rd & 31u));
    a64_emit(b, 0xF2800000u | (2u << 21) |
        (((uint32_t)(v >> 32) & 0xFFFFu) << 5) | (rd & 31u));
    a64_emit(b, 0xF2800000u | (3u << 21) |
        (((uint32_t)(v >> 48) & 0xFFFFu) << 5) | (rd & 31u));
}

static void f_ldgreg(a64_buf_t *b, unsigned wd, uint32_t rs)
{
    a64_gpr_load(b, wd, rs);
}

static void f_stgreg(a64_buf_t *b, uint32_t rd, unsigned ws)
{
    a64_gpr_store(b, rd, ws);
}

static void f_src2(a64_buf_t *b, unsigned wd, const sparc32_decoded_t *d)
{
    if (d->is_imm != 0u) {
        a64_emit_mov_imm32(b, wd, (uint32_t)d->simm);
    } else {
        f_ldgreg(b, wd, d->rs2);
    }
}

static void f_ea_into(a64_buf_t *b, unsigned wd, const sparc32_decoded_t *d)
{
    f_ldgreg(b, F_ES2, d->rs1);
    f_src2(b, wd, d);
    a64_emit_add_reg_w(b, false, wd, F_ES2, wd, A64_SHIFT_LSL, 0u);
}

/* Slow path: the vm32 prot/state tables only cover published pages, so
 * any miss (misaligned, unpublished, unreadable/unwritable) funnels
 * through the canonical helper, which owns region checks and precise
 * faults. Args: x0=ctx, w1=va, w2=op3, w3=rd, w4=rs2, w5=asi. */
extern uint32_t sparc32_rt_mem(sparc32_ctx_t *ctx, uint32_t va,
    uint32_t op3, uint32_t rd, uint32_t rs2, uint32_t asi);

static void f_emit_slowcall(a64_buf_t *b, const sparc32_decoded_t *d,
    uint32_t fault_pc)
{
    size_t p_fault;
    size_t p_cont;
    uint32_t op3 = d->op3 & 0x3Fu;
    bool is_store = (op3 == 0x04u || op3 == 0x05u || op3 == 0x06u ||
        op3 == 0x07u);
    a64_emit_add_uxtw_x(b, 0u, A64_XCTX, A64_ZR);
    a64_emit_mov_w(b, 1u, F_ES0);
    a64_emit_mov_imm32(b, 2u, d->op3);
    a64_emit_mov_imm32(b, 3u, d->rd);
    a64_emit_mov_imm32(b, 4u, d->rs2);
    a64_emit_mov_imm32(b, 5u, d->asi);
    f_mov64(b, F_ES2, (uint64_t)(uintptr_t)&sparc32_rt_mem);
    a64_emit(b, 0xA9BF1FE6u);
    a64_emit(b, 0xA9BF27E8u);
    a64_emit(b, 0xA9BF2FEAu);
    a64_emit(b, 0xA9BF37ECu);
    a64_emit(b, F_STR_X30_PRE);
    a64_emit(b, F_BLR_BASE | ((F_ES2 & 31u) << 5));
    a64_emit(b, F_LDR_X30_POST);
    a64_emit(b, 0xA8C137ECu);
    a64_emit(b, 0xA8C12FEAu);
    a64_emit(b, 0xA8C127E8u);
    a64_emit(b, 0xA8C11FE6u);
    if (!is_store) {
        uint32_t rd = d->rd & 31u;
        if (rd != 0u) {
            a64_emit_ldr_imm_w(b, 6u + (rd & 7u), A64_XCTX, rd * 4u);
        }
        if (op3 == 0x03u) {
            uint32_t rd2 = (d->rd + 1u) & 31u;
            a64_emit_ldr_imm_w(b, 6u + (rd2 & 7u), A64_XCTX, rd2 * 4u);
        }
    }
    p_fault = a64_emit_cbz_w_placeholder(b, true, 0u);
    p_cont = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    a64_patch_cbz_w(b, p_fault, b->count);
    a64_emit_mov_w(b, F_ES1, 0u);
    a64_emit_mov_pc32(b, F_ES0, fault_pc);
    a64_emit_ret(b);
    a64_patch_b_cond(b, p_cont, b->count);
    /* The helper call clobbers host NZCV for the rest of the block. */
    b->nzcv_valid = 0;
}

/* Note: stores to code-bearing pages funnel to the canonical helper
 * below without cache invalidation. Flushing the arena from inside
 * emitted code could clobber the running block; guest-store SMC keeps
 * the pre-existing (approximate) semantics. */

/* P13-4 single-lookup prot check against the x25-cached table (3
 * insns): lsr vpn; ldrb [x25, vpn]; tbz bit,slow. Loads test bit 0
 * (READ); stores test bit 3 (VM32_PROT_FAST_WRITE = writable and
 * code-free), folding the old code-page bitmap check into the same
 * byte. On miss jumps to slow. */
static size_t f_check_prot(a64_buf_t *b, unsigned va_w, unsigned bit)
{
    a64_emit_ubfm_w(b, F_ES2, va_w, 12u, 31u);
    a64_emit_ldrb_reg(b, F_ES3, F_PROT, F_ES2);
    return a64_emit_tbz_w_placeholder(b, F_ES3, bit);
}

static size_t f_check_align(a64_buf_t *b, unsigned va_w, unsigned hi_bit)
{
    size_t p_slow;
    a64_emit_ubfm_w(b, F_ES2, va_w, 0u, hi_bit);
    p_slow = a64_emit_cbz_w_placeholder(b, true, F_ES2);
    return p_slow;
}

int sparc32_emit_mem_fast(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    a64_buf_t *b;
    uint32_t op3;
    bool is_store;
    bool is_signed = false;
    unsigned width;
    size_t p_a = (size_t)-1;
    size_t p_p = (size_t)-1;
    size_t p_end;
    if (ec == NULL || ec->buf == NULL || d == NULL) {
        return 0;
    }
    if (sparc32_vm_prot_base() == NULL) {
        return 0;
    }
    b = ec->buf;
    op3 = d->op3 & 0x3Fu;
    if ((op3 & 0x10u) != 0u) {
        return 0;
    }
    switch (op3) {
    case 0x00u:
    case 0x08u: /* LDSW: sign extension is identity on words. */
        is_store = false;
        width = 4u;
        break;
    case 0x01u:
        is_store = false;
        width = 1u;
        break;
    case 0x02u:
        is_store = false;
        width = 2u;
        break;
    case 0x09u: /* LDSB */
        is_store = false;
        width = 1u;
        is_signed = true;
        break;
    case 0x0Au: /* LDSH */
        is_store = false;
        width = 2u;
        is_signed = true;
        break;
    case 0x03u: /* LDD: even rd only (decoder guarantees). */
        is_store = false;
        width = 8u;
        break;
    case 0x04u:
        is_store = true;
        width = 4u;
        break;
    case 0x05u:
        is_store = true;
        width = 1u;
        break;
    case 0x06u:
        is_store = true;
        width = 2u;
        break;
    case 0x07u: /* STD: even rd only (decoder guarantees). */
        is_store = true;
        width = 8u;
        break;
    default:
        return 0;
    }
    f_ea_into(b, F_ES0, d);
    if (width == 8u) {
        p_a = f_check_align(b, F_ES0, 2u);
    } else if (width == 4u) {
        p_a = f_check_align(b, F_ES0, 1u);
    } else if (width == 2u) {
        p_a = f_check_align(b, F_ES0, 0u);
    }
    p_p = f_check_prot(b, F_ES0, is_store ? 3u : 0u);
    if (!is_store) {
        if (width == 8u) {
            /* LDD: 8-alignment keeps both words in one 4K page, so
             * one prot check covers the pair. */
            a64_emit_guest_ldr_w(b, F_ES1, F_ES0);
            a64_emit_rev_w(b, F_ES1, F_ES1);
            f_stgreg(b, d->rd, F_ES1);
            a64_emit_add_imm_w(b, false, F_ES2, F_ES0, 4u, 0u);
            a64_emit_guest_ldr_w(b, F_ES1, F_ES2);
            a64_emit_rev_w(b, F_ES1, F_ES1);
            f_stgreg(b, d->rd + 1u, F_ES1);
        } else if (width == 4u) {
            a64_emit_guest_ldr_w(b, F_ES1, F_ES0);
            a64_emit_rev_w(b, F_ES1, F_ES1);
            f_stgreg(b, d->rd, F_ES1);
        } else if (width == 2u) {
            a64_emit_guest_ldrh_w(b, F_ES1, F_ES0);
            a64_emit_rev16_w(b, F_ES1, F_ES1);
            if (is_signed) {
                a64_emit_sbfm_w(b, F_ES1, F_ES1, 0u, 15u);
            }
            f_stgreg(b, d->rd, F_ES1);
        } else {
            a64_emit_guest_ldrb_w(b, F_ES1, F_ES0);
            if (is_signed) {
                a64_emit_sbfm_w(b, F_ES1, F_ES1, 0u, 7u);
            }
            f_stgreg(b, d->rd, F_ES1);
        }
    } else {
        f_ldgreg(b, F_ES1, d->rd);
        if (width == 8u) {
            /* STD: same single-page guarantee as LDD. */
            a64_emit_rev_w(b, F_ES1, F_ES1);
            a64_emit_guest_str_w(b, F_ES1, F_ES0);
            f_ldgreg(b, F_ES1, d->rd + 1u);
            a64_emit_rev_w(b, F_ES1, F_ES1);
            a64_emit_add_imm_w(b, false, F_ES2, F_ES0, 4u, 0u);
            a64_emit_guest_str_w(b, F_ES1, F_ES2);
        } else if (width == 4u) {
            a64_emit_rev_w(b, F_ES1, F_ES1);
            a64_emit_guest_str_w(b, F_ES1, F_ES0);
        } else if (width == 2u) {
            a64_emit_rev16_w(b, F_ES1, F_ES1);
            a64_emit_guest_strh_w(b, F_ES1, F_ES0);
        } else {
            a64_emit_guest_strb_w(b, F_ES1, F_ES0);
        }
    }
    p_end = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    {
        size_t slow = b->count;
        if (p_a != (size_t)-1) {
            a64_patch_cbz_w(b, p_a, slow);
        }
        a64_patch_tbz_w(b, p_p, slow);
        f_emit_slowcall(b, d, ec->fault_pc);
        a64_patch_b_cond(b, p_end, b->count);
    }
    return b->overflow ? -1 : 1;
}

int sparc32_emit_mul_fast(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    a64_buf_t *b;
    uint32_t op3;
    if (ec == NULL || ec->buf == NULL || d == NULL) {
        return 0;
    }
    op3 = d->op3 & 0x3Fu;
    if (op3 != 0x0Au && op3 != 0x0Bu) {
        return 0;
    }
    b = ec->buf;
    f_ldgreg(b, F_ES0, d->rs1);
    f_src2(b, F_ES1, d);
    if (op3 == 0x0Au) {
        a64_emit_umaddl_x(b, F_ES2, F_ES0, F_ES1, A64_ZR);
    } else {
        a64_emit_smaddl_x(b, F_ES2, F_ES0, F_ES1, A64_ZR);
    }
    a64_emit_ubfx_x_to_w(b, F_ES3, F_ES2, 32u, 32u);
    a64_emit_str_imm_w(b, F_ES3, A64_XCTX,
        (uint32_t)__builtin_offsetof(sparc32_ctx_t, y));
    f_stgreg(b, d->rd, F_ES2);
    return b->overflow ? -1 : 1;
}

/* ---- P13-4 inline SAVE/RESTORE fast path ----------------------------- */

/* Write-through GPR-cache flush point: the w6..w13 cache commits every
 * store to ctx memory, so emitted reads are always coherent and there
 * is nothing to flush; the call documents the ordering requirement
 * (operands are read in the old window, before rotation). */
static inline void sparc32_flush_gpr_cache(a64_buf_t *b)
{
    (void)b;
}

/* Cold spill/fill funnel: the window-helper call shape from emit_int.c
 * (w0 = ctx, w1 = rs1 idx, w2 = src2, w3 = rd, w4 = ctl, w5 = pc). */
static void f_win_slowcall(a64_buf_t *b, const sparc32_decoded_t *d,
    int is_save, uint32_t fault_pc)
{
    size_t p_fault;
    size_t p_cont;
    sparc32_emit_fp_flush(b);
    b->fp_fast_checked = false;
    b->gpr_cache_valid = 0;
    b->nzcv_valid = 0;
    a64_emit_add_uxtw_x(b, 0u, A64_XCTX, A64_ZR);
    a64_emit_mov_imm32(b, 1u, d->rs1);
    if (d->is_imm != 0u) {
        a64_emit_mov_imm32(b, 2u, (uint32_t)d->simm);
    } else {
        a64_emit_mov_imm32(b, 2u, d->rs2);
    }
    a64_emit_mov_imm32(b, 3u, d->rd);
    a64_emit_mov_imm32(b, 4u, ((is_save != 0) ? 1u : 0u) |
        ((d->is_imm != 0u) ? 2u : 0u));
    a64_emit_mov_pc32(b, 5u, fault_pc);
    f_mov64(b, F_ES2, (uint64_t)(uintptr_t)&sparc32_rt_window);
    a64_emit(b, 0xA9BF1FE6u);
    a64_emit(b, 0xA9BF27E8u);
    a64_emit(b, 0xA9BF2FEAu);
    a64_emit(b, 0xA9BF37ECu);
    a64_emit(b, F_STR_X30_PRE);
    a64_emit(b, F_BLR_BASE | ((F_ES2 & 31u) << 5));
    a64_emit(b, F_LDR_X30_POST);
    a64_emit(b, 0xA8C137ECu);
    a64_emit(b, 0xA8C12FEAu);
    a64_emit(b, 0xA8C127E8u);
    a64_emit(b, 0xA8C11FE6u);
    p_fault = a64_emit_cbz_w_placeholder(b, true, 0u);
    p_cont = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    a64_patch_cbz_w(b, p_fault, b->count);
    a64_emit_mov_w(b, F_ES1, 0u);
    a64_emit_mov_pc32(b, F_ES0, fault_pc);
    a64_emit_ret(b);
    a64_patch_b_cond(b, p_cont, b->count);
}

int sparc32_emit_win_fast(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d,
    int is_save)
{
    a64_buf_t *b;
    uint32_t rd;
    uint32_t cwp_off = (uint32_t)offsetof(sparc32_ctx_t, cwp);
    uint32_t cansave_off = (uint32_t)offsetof(sparc32_ctx_t, cansave);
    uint32_t canrestore_off =
        (uint32_t)offsetof(sparc32_ctx_t, canrestore);
    uint32_t psr_off = (uint32_t)offsetof(sparc32_ctx_t, psr);
    size_t p_slow;
    size_t p_skip;
    size_t p_end;
    uint8_t keep = 0u;
    unsigned sl;
    if (ec == NULL || ec->buf == NULL || d == NULL) {
        return -1;
    }
    if (sparc32_vm_prot_base() == NULL) {
        return 0;
    }
    b = ec->buf;
    rd = d->rd & 31u;
    /* 1. w15 = rs1 + op2 in the OLD window (write-through reads are
     * coherent; the flush point below is a no-op by construction). */
    sparc32_flush_gpr_cache(b);
    f_ldgreg(b, F_ES0, d->rs1);
    f_src2(b, F_ES1, d);
    a64_emit_add_reg_w(b, false, F_ES0, F_ES0, F_ES1, A64_SHIFT_LSL, 0u);
    /* Rotation probes canrestore with CMP, so live NZCV dies here. */
    b->nzcv_valid = 0;
    /* 2. Eligibility: SAVE needs canrestore < 7 (no spill), RESTORE
     * needs canrestore > 0 (no fill). WIM is unmodeled in this tree
     * (RDWIM/WRWIM trap as PRIV), so no WIM-bit gate is needed. */
    a64_emit_ldr_imm_w(b, F_ES1, A64_XCTX, canrestore_off);
    if (is_save != 0) {
        a64_emit_sub_imm_w(b, true, A64_ZR, F_ES1, 7u, 0u);
        p_slow = a64_emit_b_cond_placeholder(b, A64_COND_CS);
    } else {
        p_slow = a64_emit_cbz_w_placeholder(b, false, F_ES1);
    }
    /* 3. x1 = winfile + cwp*64, x2 = winfile + tgt*64. */
    f_mov64(b, 0u, (uint64_t)(uintptr_t)interp_winfile_base());
    a64_emit_ldr_imm_w(b, F_ES1, A64_XCTX, cwp_off);
    if (is_save != 0) {
        a64_emit_sub_imm_w(b, false, F_ES2, F_ES1, 1u, 0u);
    } else {
        a64_emit_add_imm_w(b, false, F_ES2, F_ES1, 1u, 0u);
    }
    a64_emit_ubfm_w(b, F_ES2, F_ES2, 0u, 2u);
    a64_emit_lsl_x(b, 16u, F_ES1, 6u);
    a64_emit_add_reg_x(b, 1u, 0u, 16u);
    a64_emit_lsl_x(b, 16u, F_ES2, 6u);
    a64_emit_add_reg_x(b, 2u, 0u, 16u);
    /* TGT outlives the rotation in w5 (x17 joins the old-value set). */
    a64_emit_mov_w(b, 5u, F_ES2);
    /* 4. Rotate: stash the outgoing half, spill l/i to winfile[cwp],
     * fill l/i from winfile[tgt], publish the outgoing half. */
    if (is_save != 0) {
        a64_emit_ldp_x(b, 3u, 4u, A64_XCTX, 32u);
        a64_emit_ldp_x(b, 16u, 17u, A64_XCTX, 48u);
    } else {
        a64_emit_ldp_x(b, 3u, 4u, A64_XCTX, 96u);
        a64_emit_ldp_x(b, 16u, 17u, A64_XCTX, 112u);
    }
    a64_emit_ldp_x(b, 0u, 21u, A64_XCTX, 64u);
    a64_emit_stp_x(b, 0u, 21u, 1u, 0u);
    a64_emit_ldp_x(b, 0u, 21u, A64_XCTX, 80u);
    a64_emit_stp_x(b, 0u, 21u, 1u, 16u);
    a64_emit_ldp_x(b, 0u, 21u, A64_XCTX, 96u);
    a64_emit_stp_x(b, 0u, 21u, 1u, 32u);
    a64_emit_ldp_x(b, 0u, 21u, A64_XCTX, 112u);
    a64_emit_stp_x(b, 0u, 21u, 1u, 48u);
    a64_emit_ldp_x(b, 0u, 21u, 2u, 0u);
    a64_emit_stp_x(b, 0u, 21u, A64_XCTX, 64u);
    a64_emit_ldp_x(b, 0u, 21u, 2u, 16u);
    a64_emit_stp_x(b, 0u, 21u, A64_XCTX, 80u);
    a64_emit_ldp_x(b, 0u, 21u, 2u, 32u);
    a64_emit_stp_x(b, 0u, 21u, A64_XCTX, 96u);
    a64_emit_ldp_x(b, 0u, 21u, 2u, 48u);
    a64_emit_stp_x(b, 0u, 21u, A64_XCTX, 112u);
    if (is_save != 0) {
        /* X-reg pairs advance 16 bytes: r24..r27 then r28..r31. */
        a64_emit_stp_x(b, 3u, 4u, A64_XCTX, 96u);
        a64_emit_stp_x(b, 16u, 17u, A64_XCTX, 112u);
    } else {
        /* X-reg pairs advance 16 bytes: r8..r11 then r12..r15. */
        a64_emit_stp_x(b, 3u, 4u, A64_XCTX, 32u);
        a64_emit_stp_x(b, 16u, 17u, A64_XCTX, 48u);
    }
    /* 5. Commit cwp/tgt, cansave/canrestore, and psr CWP bits. */
    a64_emit_str_imm_w(b, 5u, A64_XCTX, cwp_off);
    if (is_save != 0) {
        a64_emit_ldr_imm_w(b, 16u, A64_XCTX, cansave_off);
        p_skip = a64_emit_cbz_w_placeholder(b, false, 16u);
        a64_emit_sub_imm_w(b, false, 16u, 16u, 1u, 0u);
        a64_emit_str_imm_w(b, 16u, A64_XCTX, cansave_off);
        a64_patch_cbz_w(b, p_skip, b->count);
        a64_emit_ldr_imm_w(b, 16u, A64_XCTX, canrestore_off);
        a64_emit_add_imm_w(b, false, 16u, 16u, 1u, 0u);
        a64_emit_str_imm_w(b, 16u, A64_XCTX, canrestore_off);
    } else {
        a64_emit_ldr_imm_w(b, 16u, A64_XCTX, canrestore_off);
        a64_emit_sub_imm_w(b, false, 16u, 16u, 1u, 0u);
        a64_emit_str_imm_w(b, 16u, A64_XCTX, canrestore_off);
        a64_emit_ldr_imm_w(b, 16u, A64_XCTX, cansave_off);
        a64_emit_sub_imm_w(b, true, A64_ZR, 16u, 7u, 0u);
        p_skip = a64_emit_b_cond_placeholder(b, A64_COND_CS);
        a64_emit_add_imm_w(b, false, 16u, 16u, 1u, 0u);
        a64_emit_str_imm_w(b, 16u, A64_XCTX, cansave_off);
        a64_patch_b_cond(b, p_skip, b->count);
    }
    a64_emit_ldr_imm_w(b, 16u, A64_XCTX, psr_off);
    a64_emit_mov_imm32(b, 0u, 0xFFFFFFE0u);
    a64_emit_and_reg_w(b, false, 16u, 16u, 0u, A64_SHIFT_LSL, 0u);
    a64_emit_orr_reg_w(b, 16u, 16u, 5u, A64_SHIFT_LSL, 0u);
    a64_emit_str_imm_w(b, 16u, A64_XCTX, psr_off);
    /* 6. Write rd in the NEW window (nop for rd == 0); every cached
     * slot holding a windowed register is stale after rotation. */
    for (sl = 0u; sl < 8u; sl++) {
        if ((((b->gpr_cache_valid >> sl) & 1u) != 0u) &&
            b->gpr_cache_reg[sl] < 8u) {
            keep |= (uint8_t)(1u << sl);
        }
    }
    b->gpr_cache_valid = keep;
    f_stgreg(b, rd, F_ES0);
    /* 7. Slow spill/fill funnel. */
    p_end = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    {
        size_t slow = b->count;
        if (is_save != 0) {
            a64_patch_b_cond(b, p_slow, slow);
        } else {
            a64_patch_cbz_w(b, p_slow, slow);
        }
        f_win_slowcall(b, d, is_save, ec->fault_pc);
        a64_patch_b_cond(b, p_end, b->count);
    }
    return b->overflow ? -1 : 1;
}
