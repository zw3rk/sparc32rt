/*
 * src/dbt/emit_fast.c — Lane P5 inline fast paths (loads/stores, SMUL/UMUL)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Inline aligned LD/ST/LDUB/STB/LDUH/STH, LDSW/LDSB/LDSH, LDD/STD
 * plus SMUL/UMUL. Loads/stores
 * check alignment, per-4K prot (READ/WRITE) and, for stores, the
 * code-page bitmap (RT_PAGE_HAS_CODE); any miss emits a precise
 * EXIT_FAULT or a slow SMC store, never a host SIGSEGV.
 */

#include "dbt/emit_fast.h"

#include <stdint.h>

#include "interp/decode.h"
#include "interp/interp_priv.h"
#include "rt32/a64_emit.h"
#include "sparc32rt.h"

const uint8_t *sparc32_vm_prot_base(void);
const uint8_t *sparc32_vm_state_base(void);
extern void vm_invalidate_jit(sparc32_ctx_t *ctx, uint32_t start,
    uint32_t end);

#define F_ES0 15u
#define F_ES1 16u
#define F_ES2 17u
#define F_ES3 21u

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
    a64_emit_ldr_imm_w(b, wd, A64_XCTX, (rs & 31u) * 4u);
}

static void f_stgreg(a64_buf_t *b, uint32_t rd, unsigned ws)
{
    if (rd != 0u) {
        a64_emit_str_imm_w(b, ws, A64_XCTX, (rd & 31u) * 4u);
    }
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
    a64_emit_add_uxtw_x(b, 0u, A64_XCTX, A64_ZR);
    a64_emit_mov_w(b, 1u, F_ES0);
    a64_emit_mov_imm32(b, 2u, d->op3);
    a64_emit_mov_imm32(b, 3u, d->rd);
    a64_emit_mov_imm32(b, 4u, d->rs2);
    a64_emit_mov_imm32(b, 5u, d->asi);
    f_mov64(b, F_ES2, (uint64_t)(uintptr_t)&sparc32_rt_mem);
    a64_emit(b, F_STR_X30_PRE);
    a64_emit(b, F_BLR_BASE | ((F_ES2 & 31u) << 5));
    a64_emit(b, F_LDR_X30_POST);
    p_fault = a64_emit_cbz_w_placeholder(b, true, 0u);
    p_cont = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    a64_patch_cbz_w(b, p_fault, b->count);
    a64_emit_mov_w(b, F_ES1, 0u);
    a64_emit_mov_pc32(b, F_ES0, fault_pc);
    a64_emit_ret(b);
    a64_patch_b_cond(b, p_cont, b->count);
}

/* Note: stores to code-bearing pages funnel to the canonical helper
 * below without cache invalidation. Flushing the arena from inside
 * emitted code could clobber the running block; guest-store SMC keeps
 * the pre-existing (approximate) semantics. */

/* Check per-4K prot bit (bit 0=READ, 1=WRITE). On miss jumps to slow. */
static size_t f_check_prot(a64_buf_t *b, unsigned va_w, unsigned bit,
    const uint8_t *base)
{
    size_t p_slow;
    a64_emit_ubfm_w(b, F_ES2, va_w, 12u, 31u);
    if (base == NULL) {
        p_slow = a64_emit_cbz_w_placeholder(b, false, 31u);
        return p_slow;
    }
    f_mov64(b, F_ES3, (uint64_t)(uintptr_t)base);
    a64_emit_add_uxtw_x(b, F_ES3, F_ES3, F_ES2);
    a64_emit_ldrb_imm_w(b, F_ES2, F_ES3, 0u);
    a64_emit_ubfm_w(b, F_ES2, F_ES2, bit, bit);
    p_slow = a64_emit_cbz_w_placeholder(b, false, F_ES2);
    return p_slow;
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
    size_t p_c = (size_t)-1;
    size_t p_end;
    const uint8_t *prot;
    const uint8_t *state;
    if (ec == NULL || ec->buf == NULL || d == NULL) {
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
    prot = sparc32_vm_prot_base();
    state = sparc32_vm_state_base();
    f_ea_into(b, F_ES0, d);
    if (width == 8u) {
        p_a = f_check_align(b, F_ES0, 2u);
    } else if (width == 4u) {
        p_a = f_check_align(b, F_ES0, 1u);
    } else if (width == 2u) {
        p_a = f_check_align(b, F_ES0, 0u);
    }
    p_p = f_check_prot(b, F_ES0, is_store ? 1u : 0u, prot);
    if (is_store && state != NULL) {
        a64_emit_ubfm_w(b, F_ES2, F_ES0, 12u, 31u);
        f_mov64(b, F_ES3, (uint64_t)(uintptr_t)state);
        a64_emit_add_uxtw_x(b, F_ES3, F_ES3, F_ES2);
        a64_emit_ldrb_imm_w(b, F_ES2, F_ES3, 0u);
        a64_emit_ubfm_w(b, F_ES2, F_ES2, 2u, 2u);
        p_c = a64_emit_cbz_w_placeholder(b, true, F_ES2);
    }
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
        a64_patch_cbz_w(b, p_p, slow);
        if (p_c != (size_t)-1) {
            a64_patch_cbz_w(b, p_c, slow);
        }
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
