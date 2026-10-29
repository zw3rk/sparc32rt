/*
 * src/rt32/a64_emit.h — Direct 32-bit AArch64 instruction encoder (integer + FP/SIMD)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Vendored from i686rt/src/rt32/rt32_a64_emit.h: renamed onto
 * sparc32_ctx_t; the encoder is guest-agnostic AArch64 machine code.
 * SPARC V8 integer/FPU lowering (delay slots, icc setters, SAVE/RESTORE,
 * LDSTUB/SWAP/CASA) arrives with the Phase 2 DBT and consumes these
 * primitives. Guest memory always via [x20, wAddr, uxtw] (xG in x20).
 */

#ifndef A64_EMIT_H
#define A64_EMIT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sparc32rt.h"

/*
 * Host AArch64 register allocation inside translated fragments (SPARC DBT):
 *   w6..w13    : Direct-mapped write-through GPR cache (slot (r&31)&7);
 *                caller-saved, dead across helper BLRs (tracked in a64_buf_t)
 *   w-regs     : Guest r[] window-view slots when live in registers;
 *                callee-saved w19..w26 hold them across the trampoline
 *   w15/x15    : Scratch 0 / exit guest PC
 *   w16/x16    : Scratch 1 / exit reason (SPARC32_EXIT_*)
 *   w17/x17    : Scratch 2
 *   x19        : Pointer to `sparc32_ctx_t` (xCtx)
 *   x20        : Guest window base `G` (xG)
 *   w21/x21    : Scratch 3 / epoch & key scratch
 *   w22/x22    : Guest effective address scratch
 *   x23        : Chaining / IBTC / RAS target entry scratch
 *   x24        : Accumulated in-trampoline chain_hits delta
 *   x27        : Current block cache entry pointer (cur_entry)
 *   x28        : Pointer to `g_cache_epoch` (&g_cache_epoch)
 *   x30        : Host link register (points back to the block runner)
 *   v0..v7     : Scratch FP/SIMD registers for FPU lowering
 */
#define A64_TMP0 15U
#define A64_TMP1 16U
#define A64_TMP2 17U
#define A64_XCTX 19U
#define A64_XG   20U
#define A64_TMP3 21U
#define A64_ADDR 22U
#define A64_ZR   31U

/* Shift types */
#define A64_SHIFT_LSL 0U
#define A64_SHIFT_LSR 1U
#define A64_SHIFT_ASR 2U
#define A64_SHIFT_ROR 3U

/* Condition codes */
#define A64_COND_EQ 0U
#define A64_COND_NE 1U
#define A64_COND_CS 2U
#define A64_COND_CC 3U
#define A64_COND_MI 4U
#define A64_COND_PL 5U
#define A64_COND_VS 6U
#define A64_COND_VC 7U
#define A64_COND_HI 8U
#define A64_COND_LS 9U
#define A64_COND_GE 10U
#define A64_COND_LT 11U
#define A64_COND_GT 12U
#define A64_COND_LE 13U
#define A64_COND_AL 14U

#define A64_MAX_EXIT_SLOTS  8U

typedef struct a64_buf {
    uint32_t *words;
    size_t    count;
    size_t    cap;
    bool      overflow;
    unsigned  cond_branch_depth;
    uint32_t  guest_start_pc;
    uint32_t  guest_end_pc;
    uint8_t   gpr_cache_valid;
    uint8_t   gpr_cache_reg[8];
    bool      is_call;
    bool      lr_written_from_pc;
    bool      has_self_loop;
    size_t    loop_body_offset;
    uint32_t  exit_slot_pcs[A64_MAX_EXIT_SLOTS];
    unsigned  exit_slot_count;
    bool      fp_fast_checked;
    bool      fpsr_dirty;
    /* P13-4 live-NZCV tracking: 0 = invalid, 1 = ADDcc, 2 = SUBcc,
     * 3 = Logic cc. a64_buf_init zeroes it at block entry; every
     * emitter that touches host NZCV (TST/CMP/ADDS/SUBS/FCMP/MSR
     * NZCV, helper BLR) clears it, cc setters record their kind. */
    uint8_t   nzcv_valid;
    /* P13-4 write-through FPR cache in callee-saved d8..d15: bit s
     * of fpr_valid means D(8+s) holds guest double pair fpr_tag[s]
     * (pair = (freg >> 1) & 15, slot = pair & 7). ctx->f[] in memory
     * stays coherent (every cached write goes through), so eviction
     * and single-precision aliasing only clear valid bits. */
    uint8_t   fpr_valid;
    uint8_t   fpr_tag[8];
} a64_buf_t;

static inline void a64_buf_init(a64_buf_t *b, uint32_t *storage, size_t cap)
{
    memset(b, 0, sizeof(*b));
    b->words = storage;
    b->cap   = cap;
    b->gpr_cache_valid = 0;
    b->fp_fast_checked = false;
    b->fpsr_dirty = false;
}

static inline void a64_emit(a64_buf_t *b, uint32_t insn)
{
    if (b->count < b->cap) {
        b->words[b->count++] = insn;
    } else {
        b->overflow = true;
    }
}

/* Move immediate & register moves */
void a64_emit_movz_w(a64_buf_t *b, unsigned rd, uint16_t imm16, unsigned hw);
void a64_emit_movk_w(a64_buf_t *b, unsigned rd, uint16_t imm16, unsigned hw);
void a64_emit_mov_imm32(a64_buf_t *b, unsigned rd, uint32_t val);
void a64_emit_mov_pc32(a64_buf_t *b, unsigned rd, uint32_t pc_val);
void a64_emit_mov_w(a64_buf_t *b, unsigned rd, unsigned rm);
void a64_emit_mvn_reg_w(a64_buf_t *b, unsigned rd, unsigned rm, unsigned shift, unsigned amount);

static inline uint32_t rt32_ror32(uint32_t val, unsigned rot)
{
    rot &= 31U;
    if (rot == 0U) {
        return val;
    }
    return (val >> rot) | (val << (32U - rot));
}

static inline unsigned rt32_load_reg(a64_buf_t *b, unsigned reg, uint32_t pc_val, unsigned scratch)
{
    if (reg == 15U) {
        a64_emit_mov_pc32(b, scratch, pc_val);
        return scratch;
    }
    return reg;
}

/* Arithmetic (32-bit W) */
void a64_emit_add_imm_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, uint16_t imm12, unsigned sh);
void a64_emit_sub_imm_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, uint16_t imm12, unsigned sh);
void a64_emit_add_reg_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, unsigned rm, unsigned shift, unsigned amount);
void a64_emit_sub_reg_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, unsigned rm, unsigned shift, unsigned amount);
void a64_emit_adc_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, unsigned rm);
void a64_emit_sbc_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, unsigned rm);
void a64_emit_add_uxtw_x(a64_buf_t *b, unsigned rd_x, unsigned rn_x, unsigned rm_w);

/* Logical (32-bit W) */
void a64_emit_and_reg_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, unsigned rm, unsigned shift, unsigned amount);
void a64_emit_bic_reg_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, unsigned rm, unsigned shift, unsigned amount);
void a64_emit_orr_reg_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned shift, unsigned amount);
void a64_emit_orn_reg_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned shift, unsigned amount);
void a64_emit_eor_reg_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned shift, unsigned amount);

/* Shifts, bitfields, multiply/divide */
void a64_emit_shift_reg_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned shift_type);
void a64_emit_arm_shift_reg_w(a64_buf_t *b, unsigned dst_w, unsigned src_m, unsigned src_s,
                              unsigned shift_type, bool want_carry);
void a64_emit_shift_imm_w(a64_buf_t *b, unsigned dst_w, unsigned src_m, unsigned shift_type,
                          unsigned imm5, bool want_carry, unsigned *out_carry_reg);
void a64_emit_ubfm_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned immr, unsigned imms);
void a64_emit_sbfm_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned immr, unsigned imms);
void a64_emit_bfm_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned immr, unsigned imms);
void a64_emit_ubfx_x_to_w(a64_buf_t *b, unsigned rd_w, unsigned rn_x, unsigned lsb, unsigned width);
void a64_emit_bfi_x(a64_buf_t *b, unsigned rd_x, unsigned rn_x, unsigned lsb, unsigned width);
void a64_emit_clz_w(a64_buf_t *b, unsigned rd, unsigned rn);
void a64_emit_rbit_w(a64_buf_t *b, unsigned rd, unsigned rn);
void a64_emit_rev_w(a64_buf_t *b, unsigned rd, unsigned rn);
void a64_emit_rev16_w(a64_buf_t *b, unsigned rd, unsigned rn);
void a64_emit_madd_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned ra);
void a64_emit_msub_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned ra);
void a64_emit_umaddl_x(a64_buf_t *b, unsigned rd_x, unsigned rn_w, unsigned rm_w, unsigned ra_x);
void a64_emit_smaddl_x(a64_buf_t *b, unsigned rd_x, unsigned rn_w, unsigned rm_w, unsigned ra_x);
void a64_emit_smsubl_x(a64_buf_t *b, unsigned rd_x, unsigned rn_w, unsigned rm_w, unsigned ra_x);
void a64_emit_udiv_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm);
void a64_emit_sdiv_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm);
void a64_emit_crc32_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned sz, unsigned c_bit);

/* Conditional select & flags */
void a64_emit_csel_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned cond);
void a64_emit_csneg_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned cond);
void a64_emit_mrs_nzcv(a64_buf_t *b, unsigned rt);
void a64_emit_msr_nzcv(a64_buf_t *b, unsigned rt);

/*
 * Flag helpers for ALU operations with flag update (SPARC *cc setters
 * derive N/Z/V/C from the 32-bit result; V is preserved by the logical
 * helpers, carry comes from the shifter or an immediate bit).
 */
void a64_emit_update_nz_keep_cv(a64_buf_t *b, unsigned res_reg);
void a64_emit_update_nzc_keep_v_imm(a64_buf_t *b, unsigned res_reg, unsigned carry_bit);
void a64_emit_update_nzc_keep_v_reg(a64_buf_t *b, unsigned res_reg, unsigned carry_reg);
void a64_emit_logical_flags(a64_buf_t *b, unsigned res_reg, bool has_imm_carry,
                            unsigned imm_carry, unsigned shift_carry_reg);

/* DSP/bitfield helpers without CPSR entanglement (kept from the donor) */
void a64_emit_xt_add(a64_buf_t *b, bool is_signed, bool is_16, bool is_dual8,
                     unsigned rd, unsigned rn, unsigned rm, unsigned rot);
void a64_emit_pkh(a64_buf_t *b, bool is_tb, unsigned rd, unsigned rn, unsigned rm, unsigned shift_imm);
void a64_emit_usad8(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned ra);
void a64_emit_smlal_xy(a64_buf_t *b, unsigned rd_lo, unsigned rd_hi, unsigned rn, unsigned rm,
                       bool n_top, bool m_top);
void a64_emit_smlald(a64_buf_t *b, unsigned rd_lo, unsigned rd_hi, unsigned rn, unsigned rm,
                     bool is_sub, bool m_swap);
void a64_emit_smmla(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned ra,
                    bool is_sub, bool round);
void a64_emit_umaal(a64_buf_t *b, unsigned rd_lo, unsigned rd_hi, unsigned rn, unsigned rm);
void a64_emit_mull(a64_buf_t *b, bool is_signed, bool accumulate, bool set_flags,
                   unsigned rd_lo, unsigned rd_hi, unsigned rn, unsigned rm);

/* Guest memory loads/stores via [xG, wAddr, uxtw] */
void a64_emit_guest_ldr_w(a64_buf_t *b, unsigned rt, unsigned addr_w);
void a64_emit_guest_str_w(a64_buf_t *b, unsigned rt, unsigned addr_w);
void a64_emit_guest_ldrd_w(a64_buf_t *b, unsigned rt, unsigned rt2, unsigned addr_w);
void a64_emit_guest_strd_w(a64_buf_t *b, unsigned rt, unsigned rt2, unsigned addr_w);
void a64_emit_guest_ldrb_w(a64_buf_t *b, unsigned rt, unsigned addr_w);
void a64_emit_guest_ldrsb_w(a64_buf_t *b, unsigned rt, unsigned addr_w);
void a64_emit_guest_strb_w(a64_buf_t *b, unsigned rt, unsigned addr_w);
void a64_emit_guest_ldrh_w(a64_buf_t *b, unsigned rt, unsigned addr_w);
void a64_emit_guest_ldrsh_w(a64_buf_t *b, unsigned rt, unsigned addr_w);
void a64_emit_guest_strh_w(a64_buf_t *b, unsigned rt, unsigned addr_w);

/* Host context loads/stores via [Xn, #byte_offset] */
void a64_emit_ldrb_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset);
void a64_emit_strb_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset);
void a64_emit_ldrh_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset);
void a64_emit_strh_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset);
void a64_emit_ldr_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset);
void a64_emit_str_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset);

/* Direct-mapped write-through GPR cache in w6..w13 (slot (r&31)&7).
 * r==0 reads zero / writes nop; stores write ctx first so faults see
 * exact r[]; callers invalidate valid on helper BLRs and forked delays. */
static inline void a64_gpr_load(a64_buf_t *b, unsigned wd, uint32_t rs)
{
    uint32_t r = rs & 31u;
    unsigned sl = r & 7u;
    unsigned cg = 6u + sl;
    if (r == 0u) {
        a64_emit_mov_imm32(b, wd, 0u);
        return;
    }
    if ((((b->gpr_cache_valid >> sl) & 1u) != 0u) &&
        b->gpr_cache_reg[sl] == (uint8_t)r) {
        if (wd != cg) {
            a64_emit_mov_w(b, wd, cg);
        }
        return;
    }
    a64_emit_ldr_imm_w(b, cg, A64_XCTX, r * 4u);
    b->gpr_cache_valid |= (uint8_t)(1u << sl);
    b->gpr_cache_reg[sl] = (uint8_t)r;
    if (wd != cg) {
        a64_emit_mov_w(b, wd, cg);
    }
}

static inline void a64_gpr_store(a64_buf_t *b, uint32_t rd, unsigned ws)
{
    uint32_t r = rd & 31u;
    unsigned sl = r & 7u;
    unsigned cg = 6u + sl;
    if (r == 0u) {
        return;
    }
    a64_emit_str_imm_w(b, ws, A64_XCTX, r * 4u);
    if (ws != cg) {
        a64_emit_mov_w(b, cg, ws);
    }
    b->gpr_cache_valid |= (uint8_t)(1u << sl);
    b->gpr_cache_reg[sl] = (uint8_t)r;
}

/* Inline JMPL target record (no helper BLR): STR ctx->jmpl_target + STRB
 * ctx->jmpl_delay_armed=1. Far tail offsets use ADD+STR via tmp_x. */
static inline void a64_jmpl_record(a64_buf_t *b, unsigned src_w,
    unsigned tmp_x, unsigned val_w)
{
    uint32_t off_t = (uint32_t)offsetof(sparc32_ctx_t, jmpl_target);
    uint32_t off_a = (uint32_t)offsetof(sparc32_ctx_t, jmpl_delay_armed);
    uint32_t hi_t = off_t & ~0xFFFu;
    uint32_t lo_t = off_t & 0xFFFu;
    uint32_t hi_a = off_a & ~0xFFFu;
    uint32_t lo_a = off_a & 0xFFFu;
    if (hi_t == 0u) {
        a64_emit_str_imm_w(b, src_w, A64_XCTX, off_t);
    } else {
        a64_emit(b, 0x91400000u | ((hi_t >> 12) << 10) |
            ((A64_XCTX & 31u) << 5) | (tmp_x & 31u));
        a64_emit_str_imm_w(b, src_w, tmp_x, lo_t);
    }
    a64_emit_mov_imm32(b, val_w, 1u);
    if (hi_a == hi_t) {
        if (hi_t == 0u) {
            a64_emit_strb_imm_w(b, val_w, A64_XCTX, off_a);
        } else {
            a64_emit_strb_imm_w(b, val_w, tmp_x, lo_a);
        }
    } else if (hi_a == 0u) {
        a64_emit_strb_imm_w(b, val_w, A64_XCTX, off_a);
    } else {
        a64_emit(b, 0x91400000u | ((hi_a >> 12) << 10) |
            ((A64_XCTX & 31u) << 5) | (tmp_x & 31u));
        a64_emit_strb_imm_w(b, val_w, tmp_x, lo_a);
    }
}

/* P13-4 shared inline primitives (raw forms verified against clang on
 * AArch64): x25-cached prot probe, TBZ miss branch, 64-bit LDP/STP for
 * window rotation, D-register moves for the d8..d15 FPR cache. */

/* LDRB Wt,[Xn,Wm,uxtw]: single probe into the x25-cached prot table. */
static inline void a64_emit_ldrb_reg(a64_buf_t *b, unsigned rt_w,
    unsigned rn_x, unsigned rm_w)
{
    a64_emit(b, 0x38604800U | ((rm_w & 31U) << 16) |
        ((rn_x & 31U) << 5) | (rt_w & 31U));
}

/* TBZ Wt,#bit,label placeholder (prot fast-path miss branch). The
 * 14-bit word displacement covers +/-32 KiB; slow labels sit a few
 * instructions past the probe. */
static inline size_t a64_emit_tbz_w_placeholder(a64_buf_t *b, unsigned rt,
    unsigned bit)
{
    size_t idx;
    b->cond_branch_depth++;
    idx = b->count;
    a64_emit(b, 0x36000000U | ((bit & 31U) << 19) | (rt & 31U));
    return idx;
}

static inline void a64_patch_tbz_w(a64_buf_t *b, size_t patch_idx,
    size_t target_idx)
{
    uint32_t keep;
    int32_t disp;
    if (b->cond_branch_depth > 0U) {
        b->cond_branch_depth--;
    }
    if (patch_idx >= b->count) {
        return;
    }
    disp = (int32_t)target_idx - (int32_t)patch_idx;
    keep = b->words[patch_idx] & 0xFFF8001FU;
    b->words[patch_idx] = keep | (((uint32_t)disp & 0x3FFFU) << 5);
}

/* LSL Xd,Xn,#sh (UBFM alias): row-offset scaling for window rotation. */
static inline void a64_emit_lsl_x(a64_buf_t *b, unsigned rd_x,
    unsigned rn_x, unsigned sh)
{
    a64_emit(b, 0xD3400000U | (((64U - sh) & 63U) << 16) |
        (((63U - sh) & 63U) << 10) | ((rn_x & 31U) << 5) |
        (rd_x & 31U));
}

/* LSR Xd,Xn,#sh (UBFM alias): double high-half extraction. */
static inline void a64_emit_lsr_x(a64_buf_t *b, unsigned rd_x,
    unsigned rn_x, unsigned sh)
{
    a64_emit(b, 0xD3400000U | ((sh & 63U) << 16) | (63U << 10) |
        ((rn_x & 31U) << 5) | (rd_x & 31U));
}

/* ADD Xd,Xn,Xm (shifted register, LSL #0). */
static inline void a64_emit_add_reg_x(a64_buf_t *b, unsigned rd_x,
    unsigned rn_x, unsigned rm_x)
{
    a64_emit(b, 0x8B000000U | ((rm_x & 31U) << 16) |
        ((rn_x & 31U) << 5) | (rd_x & 31U));
}

/* LDP/STP Xt1,Xt2,[Xn,#off]: off must be a multiple of 8. */
static inline void a64_emit_ldp_x(a64_buf_t *b, unsigned rt1_x,
    unsigned rt2_x, unsigned rn_x, uint32_t off)
{
    a64_emit(b, 0xA9400000U | (((off >> 3) & 0x7FU) << 15) |
        ((rt2_x & 31U) << 10) | ((rn_x & 31U) << 5) | (rt1_x & 31U));
}

static inline void a64_emit_stp_x(a64_buf_t *b, unsigned rt1_x,
    unsigned rt2_x, unsigned rn_x, uint32_t off)
{
    a64_emit(b, 0xA9000000U | (((off >> 3) & 0x7FU) << 15) |
        ((rt2_x & 31U) << 10) | ((rn_x & 31U) << 5) | (rt1_x & 31U));
}

/* FMOV Dd,Dn / FMOV Dd,Xn / FMOV Xn,Dd (d8..d15 cache traffic).
 * FMOV (register, double) is 0x1E604000U; 0x1E602000U is unallocated
 * for nonzero destinations (clang-verified: fmov d8, d0 = 0x1E604008). */
static inline void a64_emit_fmov_d_d(a64_buf_t *b, unsigned vd,
    unsigned vn)
{
    a64_emit(b, 0x1E604000U | ((vn & 31U) << 5) | (vd & 31U));
}

static inline void a64_emit_fmov_d_x(a64_buf_t *b, unsigned vd,
    unsigned rn_x)
{
    a64_emit(b, 0x9E670000U | ((rn_x & 31U) << 5) | (vd & 31U));
}

static inline void a64_emit_fmov_x_d(a64_buf_t *b, unsigned rd_x,
    unsigned vn)
{
    a64_emit(b, 0x9E660000U | ((vn & 31U) << 5) | (rd_x & 31U));
}

/* INS Vd.S[1],Vn.S[0]: assemble the high half of a cached double. */
static inline void a64_emit_ins_s10(a64_buf_t *b, unsigned vd,
    unsigned vn)
{
    a64_emit(b, 0x6E0C0400U | ((vn & 31U) << 5) | (vd & 31U));
}

/* Emit-time FPR-cache invalidation for a guest single/double freg
 * write: clears the slot bit, so later reads miss and refill from
 * the (coherent) ctx memory. No runtime instructions. */
static inline void a64_fpr_invalidate(a64_buf_t *b, unsigned freg)
{
    unsigned slot = (((freg >> 1) & 15U) & 7U);
    b->fpr_valid &= (uint8_t)~(uint8_t)(1U << slot);
}

/* Guest memory FP loads/stores via [xG, wAddr, uxtw] (SPARC is big-endian:
 * the Phase 2 DBT byte-swaps guest FP payloads around these primitives) */
void a64_emit_guest_ldr_s(a64_buf_t *b, unsigned vt, unsigned addr_w);
void a64_emit_guest_str_s(a64_buf_t *b, unsigned vt, unsigned addr_w);
void a64_emit_guest_ldr_d(a64_buf_t *b, unsigned vt, unsigned addr_w);
void a64_emit_guest_str_d(a64_buf_t *b, unsigned vt, unsigned addr_w);

/* Scalar FP instructions */
void a64_emit_fmov_w_to_s(a64_buf_t *b, unsigned vd, unsigned rn_w);
void a64_emit_fmov_s_to_w(a64_buf_t *b, unsigned rd_w, unsigned vn);
void a64_emit_fcvt_s_to_d(a64_buf_t *b, unsigned vd, unsigned vn);
void a64_emit_fcvt_d_to_s(a64_buf_t *b, unsigned vd, unsigned vn);
void a64_emit_fcvtzs_s_to_w(a64_buf_t *b, unsigned rd_w, unsigned vn);
void a64_emit_fcvtzu_s_to_w(a64_buf_t *b, unsigned rd_w, unsigned vn);
void a64_emit_fcvtzs_d_to_w(a64_buf_t *b, unsigned rd_w, unsigned vn);
void a64_emit_fcvtzu_d_to_w(a64_buf_t *b, unsigned rd_w, unsigned vn);
void a64_emit_scvtf_w_to_s(a64_buf_t *b, unsigned vd, unsigned rn_w);
void a64_emit_ucvtf_w_to_s(a64_buf_t *b, unsigned vd, unsigned rn_w);
void a64_emit_scvtf_w_to_d(a64_buf_t *b, unsigned vd, unsigned rn_w);
void a64_emit_ucvtf_w_to_d(a64_buf_t *b, unsigned vd, unsigned rn_w);

/* ARMv8-A Crypto extensions (AES, PMULL, SHA1, SHA256) */
void a64_emit_aese(a64_buf_t *b, unsigned vd, unsigned vn);
void a64_emit_aesd(a64_buf_t *b, unsigned vd, unsigned vn);
void a64_emit_aesmc(a64_buf_t *b, unsigned vd, unsigned vn);
void a64_emit_aesimc(a64_buf_t *b, unsigned vd, unsigned vn);
void a64_emit_pmull_1q(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm);
void a64_emit_sha1c(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm);
void a64_emit_sha1p(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm);
void a64_emit_sha1m(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm);
void a64_emit_sha1su0(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm);
void a64_emit_sha1h(a64_buf_t *b, unsigned vd, unsigned vn);
void a64_emit_sha1su1(a64_buf_t *b, unsigned vd, unsigned vn);
void a64_emit_sha256h(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm);
void a64_emit_sha256h2(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm);
void a64_emit_sha256su0(a64_buf_t *b, unsigned vd, unsigned vn);
void a64_emit_sha256su1(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm);

/* Exclusives & barriers (LDSTUB/SWAP/CASA lowerings use the W forms) */
void a64_emit_ldxr_b(a64_buf_t *b, unsigned rt_w, unsigned rn_x);
void a64_emit_stxr_b(a64_buf_t *b, unsigned rs_w, unsigned rt_w, unsigned rn_x);
void a64_emit_ldxr_h(a64_buf_t *b, unsigned rt_w, unsigned rn_x);
void a64_emit_stxr_h(a64_buf_t *b, unsigned rs_w, unsigned rt_w, unsigned rn_x);
void a64_emit_ldxr_w(a64_buf_t *b, unsigned rt_w, unsigned rn_x);
void a64_emit_stxr_w(a64_buf_t *b, unsigned rs_w, unsigned rt_w, unsigned rn_x);
void a64_emit_ldxr_x(a64_buf_t *b, unsigned rt_x, unsigned rn_x);
void a64_emit_stxr_x(a64_buf_t *b, unsigned rs_w, unsigned rt_x, unsigned rn_x);
void a64_emit_clrex(a64_buf_t *b);
void a64_emit_dmb_ish(a64_buf_t *b);
void a64_emit_dsb_ish(a64_buf_t *b);
void a64_emit_isb(a64_buf_t *b);

/* Branches & block exits */
size_t a64_emit_b_cond_placeholder(a64_buf_t *b, unsigned cond);
void   a64_patch_b_cond(a64_buf_t *b, size_t patch_idx, size_t target_idx);
size_t a64_emit_cbz_w_placeholder(a64_buf_t *b, bool is_cbnz, unsigned rt);
void   a64_patch_cbz_w(a64_buf_t *b, size_t patch_idx, size_t target_idx);
void   a64_emit_ret(a64_buf_t *b);

/* Standard fragment exit sequences */
void a64_emit_exit_branch(a64_buf_t *b, uint32_t target_pc);
/* SPARC has a single instruction set (no Thumb bit); every indirect branch
 * goes through a64_emit_exit_branch_reg()'s RAS/IBTC dispatch. */
void a64_emit_exit_branch_reg(a64_buf_t *b, unsigned target_reg);
void a64_emit_exit_syscall(a64_buf_t *b, uint32_t next_pc, uint32_t syscall_nr);
void a64_emit_exit_undef(a64_buf_t *b, uint32_t fault_pc);
void a64_emit_exit_trap(a64_buf_t *b, uint32_t trap_pc);

#endif /* A64_EMIT_H */
