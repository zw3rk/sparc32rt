/*
 * src/dbt/emit_cc.c — SPARC icc <-> AArch64 NZCV translation (DBT).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from emit_int.c for the 900-line file discipline (same pattern
 * as emit_fpmem.c). R1 oracle truth (LEON3): SUBcc C is the borrow out
 * of bit 31 (C = 1 iff a < b); ADDcc C stays the carry-out. BCS/BCC
 * read the stored borrow directly via host CS/CC; BLEU/BGU map to host
 * LS/HI and need the complemented sense.
 *
 * Scratch contract (same physical regs as the integer emitter, which
 * owns w15/w16/w17/w21 inside one emitted instruction and reloads
 * operands after seeding): CS0 = w15, CS1 = w16, CS2 = w17, CS3 = w21.
 * Contract: x19 = ctx, x20 = G, never x18.
 */

#include "dbt/emit_cc.h"

#include <stddef.h>
#include <stdint.h>

#include "rt32/a64_emit.h"
#include "sparc32rt.h"

#define CS0 15u /* w15: scratch / NZCV nibble */
#define CS1 16u /* w16: scratch / psr accumulator */
#define CS2 17u /* w17: scratch */
#define CS3 21u /* w21: scratch */

/* SPARC cond -> AArch64 cond against stored icc (icc bit order differs
 * from NZCV, so C/V need the complement treatment in cond_setup). */
static const uint32_t s_cc_icc[16] = {
    14u, /* BN  -> never (folded statically; AL unused) */
    0u, /* BE   -> EQ */
    13u, /* BLE  -> LE */
    11u, /* BL   -> LT */
    9u, /* BLEU -> LS */
    2u, /* BCS  -> CS */
    4u, /* BNEG -> MI */
    6u, /* BVS  -> VS */
    14u, /* BA   -> AL */
    1u, /* BNE  -> NE */
    12u, /* BG   -> GT */
    10u, /* BGE  -> GE */
    8u, /* BGU  -> HI */
    3u, /* BCC  -> CC */
    5u, /* BPOS -> PL */
    7u /* BVC  -> VC */
};

/* SPARC cond -> AArch64 cond against live SUBcc NZCV: host C is
 * !borrow there, so BCS/BCC swap senses versus the stored-icc table
 * (BLEU/BGU already read the complement via LS/HI and stay put). */
static const uint32_t s_cc_subcc[16] = {
    14u, /* BN  -> never (folded statically; AL unused) */
    0u, /* BE   -> EQ */
    13u, /* BLE  -> LE */
    11u, /* BL   -> LT */
    9u, /* BLEU -> LS */
    3u, /* BCS  -> CC (!borrow) */
    4u, /* BNEG -> MI */
    6u, /* BVS  -> VS */
    14u, /* BA   -> AL */
    1u, /* BNE  -> NE */
    12u, /* BG   -> GT */
    10u, /* BGE  -> GE */
    8u, /* BGU  -> HI */
    2u, /* BCC  -> CS (no borrow) */
    5u, /* BPOS -> PL */
    7u /* BVC  -> VC */
};

unsigned sparc32_emit_icc_cond(uint32_t cond)
{
    return s_cc_icc[cond & 15u];
}

/* Record the live-NZCV kind for a cc-setting ALU op (P13-4): 1 for
 * ADDcc, 2 for SUBcc, 3 for the AND/OR/XOR/BIC logic cc ops (their
 * TST/ANDS forms leave guest C=V=0 in host NZCV), 0 otherwise. */
void sparc32_emit_track_cc(a64_buf_t *b, uint32_t op3)
{
    uint8_t kind = 0u;

    if (op3 == 0x10U) {
        kind = 1u;
    } else if (op3 == 0x14U) {
        kind = 2u;
    } else if (op3 >= 0x11U && op3 <= 0x17U) {
        kind = 3u;
    }
    b->nzcv_valid = kind;
}

/* Resolve a Bicc condition against live host NZCV (P13-4): returns 1
 * with the direct AArch64 condition when the recorded cc kind already
 * evaluates cond (0 setup instructions); 0 when the caller must run
 * sparc32_emit_cond_setup first. ADDcc (kind 1) only covers the 10
 * non-carry conds; Logic cc (kind 3, guest C=V=0) maps BLEU->EQ and
 * BGU->NE and covers the 8 signed/zero conds; SUBcc (kind 2) covers
 * all 16 via the complemented table above. */
int sparc32_emit_live_cond(const a64_buf_t *b, uint32_t cond,
    unsigned *a64_out)
{
    unsigned kind;
    unsigned c;
    if (b == NULL || a64_out == NULL) {
        return 0;
    }
    kind = b->nzcv_valid;
    c = cond & 15u;
    if (kind == 2u) {
        *a64_out = s_cc_subcc[c];
        return 1;
    }
    if (kind == 1u) {
        if (c == 5u || c == 13u || c == 4u || c == 12u) {
            return 0;
        }
        *a64_out = s_cc_icc[c];
        return 1;
    }
    if (kind == 3u) {
        if (c == 5u || c == 13u || c == 7u || c == 15u) {
            return 0;
        }
        if (c == 4u) {
            *a64_out = 0u;
            return 1;
        }
        if (c == 12u) {
            *a64_out = 1u;
            return 1;
        }
        *a64_out = s_cc_icc[c];
        return 1;
    }
    return 0;
}

/* Commit host NZCV (set by the preceding ADDS/SUBS/ANDS/ADCS/SBCS) into
 * ctx->psr icc bits N=23,Z=22,V=21,C=20. Host N/Z/V match SPARC; host C
 * matches SPARC C for ADD (carry-out) and logical ops (zeroed), but
 * SUBcc/SUBXcc C is the borrow, i.e. the complement of the host
 * SUBS/SBCS carry — sub_ops flips that bit before the split, exactly
 * what interp_icc_sub computes. */
void sparc32_emit_commit_flags(a64_buf_t *b, bool sub_ops)
{
    uint32_t psr_off = (uint32_t)offsetof(sparc32_ctx_t, psr);

    a64_emit_mrs_nzcv(b, CS2);
    a64_emit_ubfm_w(b, CS0, CS2, 28u, 31u); /* w15 = NZCV nibble */
    if (sub_ops) {
        a64_emit_mov_imm32(b, CS3, 2u); /* C(2): borrow, not carry */
        a64_emit_eor_reg_w(b, CS0, CS0, CS3, A64_SHIFT_LSL, 0u);
    }
    a64_emit_ldr_imm_w(b, CS1, A64_XCTX, psr_off);
    a64_emit_mov_imm32(b, CS3, 0xFF0FFFFFu);
    a64_emit_and_reg_w(b, false, CS1, CS1, CS3, A64_SHIFT_LSL, 0u);
    a64_emit_mov_imm32(b, CS3, 8u); /* N(8) -> bit 23 */
    a64_emit_and_reg_w(b, false, CS2, CS0, CS3, A64_SHIFT_LSL, 0u);
    a64_emit_orr_reg_w(b, CS1, CS1, CS2, A64_SHIFT_LSL, 20u);
    a64_emit_mov_imm32(b, CS3, 4u); /* Z(4) -> bit 22 */
    a64_emit_and_reg_w(b, false, CS2, CS0, CS3, A64_SHIFT_LSL, 0u);
    a64_emit_orr_reg_w(b, CS1, CS1, CS2, A64_SHIFT_LSL, 20u);
    a64_emit_mov_imm32(b, CS3, 2u); /* C(2) -> bit 20 */
    a64_emit_and_reg_w(b, false, CS2, CS0, CS3, A64_SHIFT_LSL, 0u);
    a64_emit_orr_reg_w(b, CS1, CS1, CS2, A64_SHIFT_LSL, 19u);
    a64_emit_mov_imm32(b, CS3, 1u); /* V(1) -> bit 21 */
    a64_emit_and_reg_w(b, false, CS2, CS0, CS3, A64_SHIFT_LSL, 0u);
    a64_emit_orr_reg_w(b, CS1, CS1, CS2, A64_SHIFT_LSL, 21u);
    a64_emit_str_imm_w(b, CS1, A64_XCTX, psr_off);
}

/* Seed the host carry flag from PSR.icc.C for ADDX/SUBX (ADC/SBC).
 * ADDX adds the C bit, so ADC seeds it directly; SUBX subtracts the
 * borrow bit, while AArch64 SBC subtracts (1 - C), so SBC seeds the
 * complement. */
void sparc32_emit_seed_carry(a64_buf_t *b, bool sbc)
{
    uint32_t psr_off = (uint32_t)offsetof(sparc32_ctx_t, psr);

    a64_emit_ldr_imm_w(b, CS0, A64_XCTX, psr_off);
    a64_emit_ubfm_w(b, CS0, CS0, 20u, 20u); /* C bit */
    if (sbc) {
        a64_emit_mov_imm32(b, CS3, 1u);
        a64_emit_eor_reg_w(b, CS0, CS0, CS3, A64_SHIFT_LSL, 0u);
    }
    a64_emit_orr_reg_w(b, CS0, A64_ZR, CS0, A64_SHIFT_LSL, 29u);
    a64_emit_msr_nzcv(b, CS0);
    /* The seeded carry is consumed by the ADC/SBC that follows; it is
     * not a live cc result for any later Bicc. */
    b->nzcv_valid = 0;
}

/* Build host NZCV from ctx->psr icc for Bicc/Ticc evaluation.
 * BCS/BCC map to host CS/CC and read the stored borrow directly, but
 * BLEU/BGU map to host LS/HI, whose C sense is the complement
 * (no-borrow): for those two conds the reconstructed host C is flipped
 * so the canonical cond table evaluates the oracle-verified predicates.
 * Conds that never consult C are unaffected either way. */
void sparc32_emit_cond_setup(a64_buf_t *b, uint32_t cond)
{
    uint32_t psr_off = (uint32_t)offsetof(sparc32_ctx_t, psr);

    a64_emit_ldr_imm_w(b, CS3, A64_XCTX, psr_off);
    a64_emit_mov_imm32(b, CS0, 0x800000u); /* N(23) -> 31 */
    a64_emit_and_reg_w(b, false, CS2, CS3, CS0, A64_SHIFT_LSL, 0u);
    a64_emit_orr_reg_w(b, CS1, A64_ZR, CS2, A64_SHIFT_LSL, 8u);
    a64_emit_mov_imm32(b, CS0, 0x400000u); /* Z(22) -> 30 */
    a64_emit_and_reg_w(b, false, CS2, CS3, CS0, A64_SHIFT_LSL, 0u);
    a64_emit_orr_reg_w(b, CS1, CS1, CS2, A64_SHIFT_LSL, 8u);
    a64_emit_mov_imm32(b, CS0, 0x100000u); /* C(20) -> 29 */
    a64_emit_and_reg_w(b, false, CS2, CS3, CS0, A64_SHIFT_LSL, 0u);
    a64_emit_orr_reg_w(b, CS1, CS1, CS2, A64_SHIFT_LSL, 9u);
    if (cond == 0x4U || cond == 0xCU) {
        a64_emit_mov_imm32(b, CS0, 0x20000000u); /* flip host C for LS/HI */
        a64_emit_eor_reg_w(b, CS1, CS1, CS0, A64_SHIFT_LSL, 0u);
    }
    a64_emit_mov_imm32(b, CS0, 0x200000u); /* V(21) -> 28 */
    a64_emit_and_reg_w(b, false, CS2, CS3, CS0, A64_SHIFT_LSL, 0u);
    a64_emit_orr_reg_w(b, CS1, CS1, CS2, A64_SHIFT_LSL, 7u);
    a64_emit_msr_nzcv(b, CS1);
    /* Reconstructed flags are consumed by the branch that follows;
     * they are not a live cc result for any later Bicc. */
    b->nzcv_valid = 0;
}
