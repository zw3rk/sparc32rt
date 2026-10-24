/*
 * src/dbt/emit_int.c — AArch64 integer instruction emitter (Phase 2, L2c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Integer emitter with interpreter-identical semantics (--difftest).
 * Inline: SETHI, ALU + cc, ADDX/SUBX + cc, shifts, RDY/WRY, Bicc/CALL/
 * JMPL with delay slots + annul, STBAR/FLUSH nops. Helpers (emit_priv.h):
 * MUL/DIV/MULScc/TADD/TSUB, SAVE/RESTORE via the shared interp window
 * file, all loads/stores/LDSTUB/SWAP/CASA. Misaligned multi-byte access
 * faults, never emulates; FPU/odd encodings exit to dispatcher fallback.
 * Contract: x19 = ctx, x20 = G, never x18; scratch w15/w16/w17/w21 (w22
 * keeps the JMPL target); helper calls save x30 on the host stack; guest
 * state lives in ctx memory; pc/npc advance only via exits (PC in w15,
 * reason in w16).
 */

#include "dbt/emit_int.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dbt/emit_cc.h"
#include "dbt/emit_fp.h"
#include "dbt/emit_priv.h"
#include "interp/decode.h"
#include "interp/interp_priv.h"
#include "rt32/a64_emit.h"
#include "sparc32rt.h"

/* Scratch allocation inside one emitted instruction. */
#define ES0 15u /* w15: scratch / exit guest PC */
#define ES1 16u /* w16: scratch / exit reason */
#define ES2 17u /* w17: scratch / helper call target */
#define ES3 21u /* w21: scratch */
#define EKEEP 22u /* w22: value keeper across delay slots (JMPL target) */

/* Verified host encodings (cross-checked with clang on AArch64):
 * str x30,[sp,#-16]! = 0xF81F0FFE, ldr x30,[sp],#16 = 0xF84107FE,
 * movz/movk Xd,imm,hw = 0xD2800000/0xF2800000|(hw<<21)|(imm<<5)|rd,
 * blr Xn = 0xD63F0000|(n<<5). */
#define A64_STR_X30_PRE 0xF81F0FFEu
#define A64_LDR_X30_POST 0xF84107FEu
#define A64_MOVZ_X_BASE 0xD2800000u
#define A64_MOVK_X_BASE 0xF2800000u
#define A64_BLR_BASE 0xD63F0000u

static void e_trap_priv(a64_buf_t *b, uint32_t pc);

/* SPARC cond -> AArch64 cond (icc bit order differs, predicates match). */
static const uint32_t s_a64_cond[16] = {
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

/* ---- tiny emit utilities ---------------------------------------------- */

static uint32_t e_reg_off(uint32_t r)
{
    return (r & 31u) * 4u;
}

static void e_ldgreg(a64_buf_t *b, unsigned wd, uint32_t rs)
{
    a64_emit_ldr_imm_w(b, wd, A64_XCTX, e_reg_off(rs));
}

static void e_stgreg(a64_buf_t *b, uint32_t rd, unsigned ws)
{
    if (rd != 0u) {
        a64_emit_str_imm_w(b, ws, A64_XCTX, e_reg_off(rd));
    }
}

/* Materialize the ALU second operand (register value or sign-extended
 * simm13) into wd. */
static void e_src2(a64_buf_t *b, unsigned wd, const sparc32_decoded_t *d)
{
    if (d->is_imm != 0u) {
        a64_emit_mov_imm32(b, wd, (uint32_t)d->simm);
    } else {
        e_ldgreg(b, wd, d->rs2);
    }
}

/* Effective address rs1 + (is_imm ? simm : rs2) into wd (wd != ES2). */
static void e_ea_into(a64_buf_t *b, unsigned wd, const sparc32_decoded_t *d)
{
    e_ldgreg(b, ES2, d->rs1);
    e_src2(b, wd, d);
    a64_emit_add_reg_w(b, false, wd, ES2, wd, A64_SHIFT_LSL, 0u);
}

/* icc <-> NZCV translation lives in src/dbt/emit_cc.c (split for the
 * 900-line discipline): sparc32_emit_commit_flags, sparc32_emit_seed_carry,
 * sparc32_emit_cond_setup. */

/* Privileged-state access trap (RDPSR/RDWIM/RDTBR, WRPSR/WRWIM/WRTBR,
 * RETT, numbered ASR, supervisor ASI): EXIT_TRAP with exit_arg 3. */
static void e_trap_priv(a64_buf_t *b, uint32_t pc)
{
    a64_emit_mov_imm32(b, ES0, 3u);
    a64_emit_str_imm_w(b, ES0, A64_XCTX,
        (uint32_t)offsetof(sparc32_ctx_t, exit_arg));
    a64_emit_exit_trap(b, pc);
}

/* Materialize a 64-bit translator-local address into a register. */
static void e_mov64(a64_buf_t *b, unsigned rd, uint64_t v)
{
    a64_emit(b, A64_MOVZ_X_BASE | (((uint32_t)v & 0xFFFFu) << 5) |
        (rd & 31u));
    a64_emit(b, A64_MOVK_X_BASE | (1u << 21) |
        (((uint32_t)(v >> 16) & 0xFFFFu) << 5) | (rd & 31u));
    a64_emit(b, A64_MOVK_X_BASE | (2u << 21) |
        (((uint32_t)(v >> 32) & 0xFFFFu) << 5) | (rd & 31u));
    a64_emit(b, A64_MOVK_X_BASE | (3u << 21) |
        (((uint32_t)(v >> 48) & 0xFFFFu) << 5) | (rd & 31u));
}

/* BLR to a translator-local helper; x0 must already hold ctx. The helper
 * returns exit_reason in w0. On nonzero, leave the fragment carrying the
 * fault/trap PC (ec->fault_pc) in w15 and the reason in w16. */
static void e_call_prologue(a64_buf_t *b, uint64_t addr)
{
    a64_emit(b, A64_STR_X30_PRE);
    e_mov64(b, ES2, addr);
}

static void e_call_invoke_faultable(sparc32_emit_ctx_t *ec)
{
    a64_buf_t *b = ec->buf;
    size_t p_fault;
    size_t p_cont;

    a64_emit(b, A64_BLR_BASE | ((ES2 & 31u) << 5));
    a64_emit(b, A64_LDR_X30_POST);
    p_fault = a64_emit_cbz_w_placeholder(b, true, 0u);
    p_cont = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    a64_patch_cbz_w(b, p_fault, b->count);
    a64_emit_mov_w(b, ES1, 0u);
    a64_emit_mov_pc32(b, ES0, ec->fault_pc);
    a64_emit_ret(b);
    a64_patch_b_cond(b, p_cont, b->count);
}

/* w0 = ctx (x19), preserving x20. */
static void e_arg_ctx(a64_buf_t *b)
{
    a64_emit_add_uxtw_x(b, 0u, A64_XCTX, A64_ZR);
}

int sparc32_emit_exit_singlestep(sparc32_emit_ctx_t *ec, uint32_t pc)
{
    a64_buf_t *b;

    if (ec == NULL || ec->buf == NULL) {
        return -1;
    }
    b = ec->buf;
    a64_emit_mov_pc32(b, ES0, pc);
    a64_emit_movz_w(b, ES1, (uint16_t)SPARC32_EXIT_SINGLE_STEP, 0u);
    a64_emit_ret(b);
    return b->overflow ? -1 : 0;
}

/* ---- delay slots (E02) ------------------------------------------------
 * The delay instruction executes unless annulled away; its faults preempt
 * the transfer (interp_cti). A CTI or TRAP in the delay slot cannot be
 * inlined (the outer transfer is cancelled / UNDEF per interp_single), so
 * the whole CTI falls back to SINGLE_STEP and interp_step replays it.
 * FPU/FBfcc/ILLEGAL delays become EXIT_UNDEF at the delay address, exactly
 * like interp_single. ec->fault_pc must already hold the CTI address so a
 * faulting delay reports the CTI as the fault site. */

static int e_emit_one(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);

static int e_emit_delay(sparc32_emit_ctx_t *ec, uint32_t npc)
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
        /* CTI (or trap) in the delay slot: pristine SINGLE_STEP so the
         * dispatcher replays the outer CTI with interp_step. */
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
    case SPARC32_OP_FBRANCH:
    case SPARC32_OP_ILLEGAL:
        a64_emit_exit_undef(ec->buf, npc);
        return ec->buf->overflow ? -1 : 0;
    default:
        break;
    }
    ec->pc = npc;
    rc = e_emit_one(ec, d);
    ec->pc = saved_pc;
    return rc;
}

/* True when the delay slot must run on this path (E02 annul rules). */
static int e_delay_runs(uint32_t cls, uint32_t cond, int taken, int annul)
{
    (void)cls;
    if (taken != 0) {
        return (cond == 0x8u && annul != 0) ? 0 : 1;
    }
    return annul != 0 ? 0 : 1;
}

/* ---- per-class emitters ------------------------------------------------ */

int sparc32_emit_sethi(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    a64_buf_t *b = ec->buf;

    a64_emit_mov_imm32(b, ES0, d->uimm << 10);
    e_stgreg(b, d->rd, ES0);
    return b->overflow ? -1 : 0;
}

int sparc32_emit_alu(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    a64_buf_t *b = ec->buf;
    uint32_t op3 = d->op3;

    switch (op3) {
    case 0x0AU:
    case 0x0BU:
    case 0x1AU:
    case 0x1BU:
    case 0x0EU:
    case 0x0FU:
    case 0x1EU:
    case 0x1FU:
    case 0x20U:
    case 0x21U:
    case 0x22U:
    case 0x23U:
    case 0x24U: {
        /* MUL/DIV/MULScc/tagged: runtime helper (Y, icc.V, traps). */
        e_ldgreg(b, ES0, d->rs1);
        e_src2(b, ES1, d);
        e_arg_ctx(b);
        a64_emit_mov_imm32(b, 1u, op3);
        a64_emit_mov_w(b, 2u, ES0);
        a64_emit_mov_w(b, 3u, ES1);
        a64_emit_mov_imm32(b, 4u, d->rd);
        a64_emit_mov_pc32(b, 5u, ec->fault_pc);
        e_call_prologue(b, (uint64_t)(uintptr_t)&sparc32_rt_muldiv);
        e_call_invoke_faultable(ec);
        return b->overflow ? -1 : 0;
    }
    default:
        break;
    }

    e_ldgreg(b, ES0, d->rs1);
    e_src2(b, ES1, d);
    switch (op3) {
    case 0x00U:
        a64_emit_add_reg_w(b, false, ES0, ES0, ES1, A64_SHIFT_LSL, 0u);
        break;
    case 0x01U:
        a64_emit_and_reg_w(b, false, ES0, ES0, ES1, A64_SHIFT_LSL, 0u);
        break;
    case 0x02U:
        a64_emit_orr_reg_w(b, ES0, ES0, ES1, A64_SHIFT_LSL, 0u);
        break;
    case 0x03U:
        a64_emit_eor_reg_w(b, ES0, ES0, ES1, A64_SHIFT_LSL, 0u);
        break;
    case 0x04U:
        a64_emit_sub_reg_w(b, false, ES0, ES0, ES1, A64_SHIFT_LSL, 0u);
        break;
    case 0x05U:
        a64_emit_bic_reg_w(b, false, ES0, ES0, ES1, A64_SHIFT_LSL, 0u);
        break;
    case 0x06U:
        a64_emit_orn_reg_w(b, ES0, ES0, ES1, A64_SHIFT_LSL, 0u);
        break;
    case 0x07U:
        a64_emit_mvn_reg_w(b, ES2, ES1, A64_SHIFT_LSL, 0u);
        a64_emit_eor_reg_w(b, ES0, ES0, ES2, A64_SHIFT_LSL, 0u);
        break;
    case 0x08U:
        sparc32_emit_seed_carry(b, false);
        e_ldgreg(b, ES0, d->rs1);
        e_src2(b, ES1, d);
        a64_emit_adc_w(b, false, ES0, ES0, ES1);
        break;
    case 0x0CU:
        sparc32_emit_seed_carry(b, true);
        e_ldgreg(b, ES0, d->rs1);
        e_src2(b, ES1, d);
        a64_emit_sbc_w(b, false, ES0, ES0, ES1);
        break;
    case 0x10U:
        a64_emit_add_reg_w(b, true, ES0, ES0, ES1, A64_SHIFT_LSL, 0u);
        break;
    case 0x11U:
        a64_emit_and_reg_w(b, true, ES0, ES0, ES1, A64_SHIFT_LSL, 0u);
        break;
    case 0x12U:
        a64_emit_orr_reg_w(b, ES0, ES0, ES1, A64_SHIFT_LSL, 0u);
        a64_emit_and_reg_w(b, true, A64_ZR, ES0, ES0, A64_SHIFT_LSL, 0u);
        break;
    case 0x13U:
        a64_emit_eor_reg_w(b, ES0, ES0, ES1, A64_SHIFT_LSL, 0u);
        a64_emit_and_reg_w(b, true, A64_ZR, ES0, ES0, A64_SHIFT_LSL, 0u);
        break;
    case 0x14U:
        a64_emit_sub_reg_w(b, true, ES0, ES0, ES1, A64_SHIFT_LSL, 0u);
        break;
    case 0x15U:
        a64_emit_bic_reg_w(b, true, ES0, ES0, ES1, A64_SHIFT_LSL, 0u);
        break;
    case 0x16U:
        a64_emit_orn_reg_w(b, ES0, ES0, ES1, A64_SHIFT_LSL, 0u);
        a64_emit_and_reg_w(b, true, A64_ZR, ES0, ES0, A64_SHIFT_LSL, 0u);
        break;
    case 0x17U:
        a64_emit_mvn_reg_w(b, ES2, ES1, A64_SHIFT_LSL, 0u);
        a64_emit_eor_reg_w(b, ES0, ES0, ES2, A64_SHIFT_LSL, 0u);
        a64_emit_and_reg_w(b, true, A64_ZR, ES0, ES0, A64_SHIFT_LSL, 0u);
        break;
    case 0x18U:
        sparc32_emit_seed_carry(b, false);
        e_ldgreg(b, ES0, d->rs1);
        e_src2(b, ES1, d);
        a64_emit_adc_w(b, true, ES0, ES0, ES1);
        break;
    case 0x1CU:
        sparc32_emit_seed_carry(b, true);
        e_ldgreg(b, ES0, d->rs1);
        e_src2(b, ES1, d);
        a64_emit_sbc_w(b, true, ES0, ES0, ES1);
        break;
    default:
        /* Reserved op3: decoder marks ILLEGAL; interp treats as UNDEF. */
        a64_emit_exit_undef(b, ec->pc);
        return b->overflow ? -1 : 0;
    }
    e_stgreg(b, d->rd, ES0);
    if (d->cc != 0u) {
        sparc32_emit_commit_flags(b, d->op3 == 0x14U || d->op3 == 0x1CU);
    }
    return b->overflow ? -1 : 0;
}

int sparc32_emit_shift(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    a64_buf_t *b = ec->buf;
    unsigned type;

    if (d->op3 == 0x25u) {
        type = A64_SHIFT_LSL;
    } else if (d->op3 == 0x26u) {
        type = A64_SHIFT_LSR;
    } else if (d->op3 == 0x27u) {
        type = A64_SHIFT_ASR;
    } else {
        a64_emit_exit_undef(b, ec->pc);
        return b->overflow ? -1 : 0;
    }
    /* AArch64 LSLV/LSRV/ASRV mask the count to 5 bits, matching the
     * interpreter's (b & 31). */
    e_ldgreg(b, ES0, d->rs1);
    e_src2(b, ES1, d);
    a64_emit_shift_reg_w(b, ES0, ES0, ES1, type);
    e_stgreg(b, d->rd, ES0);
    return b->overflow ? -1 : 0;
}

int sparc32_emit_rdasr(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    a64_buf_t *b = ec->buf;

    if (d->asr != 0u) {
        /* Numbered ASR reads trap (only %y exists on this target). */
        e_trap_priv(b, ec->pc);
        return b->overflow ? -1 : 0;
    }
    a64_emit_ldr_imm_w(b, ES0, A64_XCTX,
        (uint32_t)offsetof(sparc32_ctx_t, y));
    e_stgreg(b, d->rd, ES0);
    return b->overflow ? -1 : 0;
}

int sparc32_emit_wrasr(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    a64_buf_t *b = ec->buf;

    if (d->asr != 0u) {
        e_trap_priv(b, ec->pc);
        return b->overflow ? -1 : 0;
    }
    e_ldgreg(b, ES0, d->rs1);
    e_src2(b, ES1, d);
    a64_emit_eor_reg_w(b, ES0, ES0, ES1, A64_SHIFT_LSL, 0u);
    a64_emit_str_imm_w(b, ES0, A64_XCTX,
        (uint32_t)offsetof(sparc32_ctx_t, y));
    return b->overflow ? -1 : 0;
}

/* Page-final rule: a CTI at (pc & 0xfff) == 0xffc leaves the fragment via
 * SINGLE_STEP carrying the post-CTI PC, exactly like interp_cti's
 * EXIT_SINGLE_STEP (the dispatcher replays the transfer). The delay slot
 * is emitted inline first so its effects and faults precede the exit. */
static int e_page_final(sparc32_emit_ctx_t *ec, uint32_t npc,
    uint32_t post_pc)
{
    int rc = e_emit_delay(ec, npc);

    if (rc != 0) {
        return rc;
    }
    return sparc32_emit_exit_singlestep(ec, post_pc);
}

int sparc32_emit_branch(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    a64_buf_t *b = ec->buf;
    uint32_t pc = ec->pc;
    uint32_t npc = pc + 4u;
    uint32_t target = pc + (uint32_t)d->disp;
    uint32_t cond = d->cond;
    int annul = d->annul != 0u;
    int page_final = ((pc & 0xFFFu) == 0xFFCu);
    size_t p_taken;
    size_t p_end;
    int rc;

    ec->fault_pc = pc;
    if (cond == 0x0u) { /* BN: never branches; falls through past delay. */
        if (e_delay_runs(d->cls, cond, 0, annul) != 0) {
            if (page_final) {
                return e_page_final(ec, npc, npc + 4u);
            }
            if (e_emit_delay(ec, npc) != 0) {
                return -1;
            }
        }
        a64_emit_exit_branch(b, npc + 4u);
        return b->overflow ? -1 : 0;
    }
    if (cond == 0x8u) { /* BA: always branches. */
        if (e_delay_runs(d->cls, cond, 1, annul) != 0) {
            if (page_final) {
                return e_page_final(ec, npc, target);
            }
            rc = e_emit_delay(ec, npc);
            if (rc != 0) {
                return rc;
            }
        }
        a64_emit_exit_branch(b, target);
        return b->overflow ? -1 : 0;
    }
    if (page_final) {
        /* Runtime condition at the page end, mirroring interp_cti: the
         * delay runs unless annulled away, and SINGLE_STEP fires only
         * when the delay ran (interp_cti's tail). An annulled not-taken
         * path completes the transfer inline with a plain BRANCH exit
         * (NONE after commit), never SINGLE_STEP. */
        sparc32_emit_cond_setup(b, cond);
        p_taken = a64_emit_b_cond_placeholder(b, s_a64_cond[cond & 15u]);
        if (e_delay_runs(d->cls, cond, 0, annul) != 0) {
            rc = e_emit_delay(ec, npc);
            if (rc != 0) {
                return rc;
            }
            rc = sparc32_emit_exit_singlestep(ec, npc + 4u);
        } else {
            a64_emit_exit_branch(b, npc + 4u);
            rc = b->overflow ? -1 : 0;
        }
        if (rc != 0) {
            return rc;
        }
        a64_patch_b_cond(b, p_taken, b->count);
        if (e_delay_runs(d->cls, cond, 1, annul) != 0) {
            rc = e_emit_delay(ec, npc);
            if (rc != 0) {
                return rc;
            }
        }
        return sparc32_emit_exit_singlestep(ec, target);
    }
    sparc32_emit_cond_setup(b, cond);
    p_taken = a64_emit_b_cond_placeholder(b, s_a64_cond[cond & 15u]);
    if (e_delay_runs(d->cls, cond, 0, annul) != 0) {
        rc = e_emit_delay(ec, npc);
        if (rc != 0) {
            return rc;
        }
    }
    p_end = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    a64_patch_b_cond(b, p_taken, b->count);
    if (e_delay_runs(d->cls, cond, 1, annul) != 0) {
        rc = e_emit_delay(ec, npc);
        if (rc != 0) {
            return rc;
        }
    }
    a64_emit_exit_branch(b, target);
    if (b->overflow) {
        return -1;
    }
    a64_patch_b_cond(b, p_end, b->count);
    /* Not-taken fallthrough needs its own exit: without it the B.AL above
     * lands one word past the fragment (host SIGILL in the arena tail). */
    a64_emit_exit_branch(b, npc + 4u);
    return b->overflow ? -1 : 0;
}

int sparc32_emit_call(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    a64_buf_t *b = ec->buf;
    uint32_t pc = ec->pc;
    uint32_t npc = pc + 4u;
    uint32_t target = pc + (uint32_t)d->disp;
    int rc;

    ec->fault_pc = pc;
    if ((pc & 0xFFFu) == 0xFFCu) {
        a64_emit_mov_pc32(b, ES0, pc);
        a64_emit_str_imm_w(b, ES0, A64_XCTX, e_reg_off(SPARC32_O7));
        b->is_call = true;
        return e_page_final(ec, npc, target);
    }
    /* Pristine-fallback check first: %o7 must still hold the old value
     * when the dispatcher replays via interp_step. */
    if (ec->delay == NULL || ec->delay->cls == (uint32_t)SPARC32_OP_CALL ||
        ec->delay->cls == (uint32_t)SPARC32_OP_BRANCH ||
        ec->delay->cls == (uint32_t)SPARC32_OP_JMPL ||
        ec->delay->cls == (uint32_t)SPARC32_OP_TRAP) {
        return sparc32_emit_exit_singlestep(ec, pc);
    }
    a64_emit_mov_pc32(b, ES0, pc);
    a64_emit_str_imm_w(b, ES0, A64_XCTX, e_reg_off(SPARC32_O7));
    b->is_call = true;
    rc = e_emit_delay(ec, npc);
    if (rc != 0) {
        return rc;
    }
    a64_emit_exit_branch(b, target);
    return b->overflow ? -1 : 0;
}

int sparc32_emit_jmpl(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    a64_buf_t *b = ec->buf;
    uint32_t pc = ec->pc;
    uint32_t npc = pc + 4u;
    int rc;

    ec->fault_pc = pc;
    if ((pc & 0xFFFu) == 0xFFCu) {
        /* The resume target is a runtime value, so nothing may be
         * committed: pristine SINGLE_STEP and the dispatcher replays the
         * whole JMPL (link write, delay, transfer) via interp_step. */
        return sparc32_emit_exit_singlestep(ec, pc);
    }
    if (ec->delay == NULL || ec->delay->cls == (uint32_t)SPARC32_OP_CALL ||
        ec->delay->cls == (uint32_t)SPARC32_OP_BRANCH ||
        ec->delay->cls == (uint32_t)SPARC32_OP_JMPL ||
        ec->delay->cls == (uint32_t)SPARC32_OP_TRAP) {
        return sparc32_emit_exit_singlestep(ec, pc);
    }
    /* Target into the callee-saved keeper: delay-slot code (including
     * helper calls) cannot clobber it. */
    e_ea_into(b, EKEEP, d);
    if (d->rd != 0u) {
        a64_emit_mov_pc32(b, ES0, pc);
        e_stgreg(b, d->rd, ES0);
    }
    if (d->rd == SPARC32_O7) {
        b->is_call = true;
    }
    rc = e_emit_delay(ec, npc);
    if (rc != 0) {
        return rc;
    }
    a64_emit_exit_branch_reg(b, EKEEP);
    return b->overflow ? -1 : 0;
}

int sparc32_emit_trap(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    a64_buf_t *b = ec->buf;
    uint32_t pc = ec->pc;
    uint32_t npc = pc + 4u;
    size_t p_taken;
    size_t p_syscall;
    size_t p_end;

    /* trapnum = (rs1 + src2) & 0x7F, kept across cond setup in EKEEP. */
    e_ldgreg(b, ES0, d->rs1);
    e_src2(b, ES1, d);
    a64_emit_add_reg_w(b, false, ES0, ES0, ES1, A64_SHIFT_LSL, 0u);
    a64_emit_mov_imm32(b, ES1, 0x7Fu);
    a64_emit_and_reg_w(b, false, EKEEP, ES0, ES1, A64_SHIFT_LSL, 0u);
    if (d->cond == 0x0u) { /* TN: never traps; falls through to npc. */
        a64_emit_exit_branch(b, npc);
        return b->overflow ? -1 : 0;
    }
    if (d->cond != 0x8u) {
        sparc32_emit_cond_setup(b, d->cond);
        p_taken = a64_emit_b_cond_placeholder(b, s_a64_cond[d->cond & 15u]);
    } else {
        p_taken = (size_t)-1;
    }
    /* True path: TA 0x10 exits to the dispatcher syscall gate with the
     * dynamic %g1 number; any other true trap number is EXIT_TRAP. */
    a64_emit_mov_imm32(b, ES0, (uint32_t)SPARC32_TRAP_SYSCALL_NUM);
    a64_emit_sub_reg_w(b, true, A64_ZR, EKEEP, ES0, A64_SHIFT_LSL, 0u);
    p_syscall = a64_emit_b_cond_placeholder(b, A64_COND_EQ);
    p_end = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    a64_patch_b_cond(b, p_syscall, b->count);
    e_ldgreg(b, ES0, SPARC32_G1);
    a64_emit_str_imm_w(b, ES0, A64_XCTX,
        (uint32_t)offsetof(sparc32_ctx_t, exit_arg));
    a64_emit_mov_pc32(b, ES0, npc);
    a64_emit_movz_w(b, ES1, (uint16_t)SPARC32_EXIT_SYSCALL, 0u);
    a64_emit_ret(b);
    a64_patch_b_cond(b, p_end, b->count);
    a64_emit_str_imm_w(b, EKEEP, A64_XCTX,
        (uint32_t)offsetof(sparc32_ctx_t, exit_arg));
    a64_emit_exit_trap(b, pc);
    if (b->overflow) {
        return -1;
    }
    if (d->cond != 0x8u) {
        a64_patch_b_cond(b, p_taken, b->count);
        /* Not-taken Ticc falls through to npc (no delay slot on traps). */
        a64_emit_exit_branch(b, npc);
        return b->overflow ? -1 : 0;
    }
    return 0;
}

/* Memory and window ops funnel through one helper-call shape:
 * w0 = ctx, w1 = effective address, w2 = op3, w3 = rd, w4 = rs2/ctl,
 * w5 = asi/pc. The helper returns exit_reason. */
static int e_emit_memcall(sparc32_emit_ctx_t *ec,
    const sparc32_decoded_t *d, uint64_t helper, int is_window)
{
    a64_buf_t *b = ec->buf;

    if (is_window == 0) {
        e_ea_into(b, ES0, d);
        e_arg_ctx(b);
        a64_emit_mov_w(b, 1u, ES0);
        a64_emit_mov_imm32(b, 2u, d->op3);
        a64_emit_mov_imm32(b, 3u, d->rd);
        a64_emit_mov_imm32(b, 4u, d->rs2);
        a64_emit_mov_imm32(b, 5u, d->asi);
    } else {
        e_arg_ctx(b);
        a64_emit_mov_imm32(b, 1u, d->rs1);
        if (d->is_imm != 0u) {
            a64_emit_mov_imm32(b, 2u, (uint32_t)d->simm);
        } else {
            a64_emit_mov_imm32(b, 2u, d->rs2);
        }
        a64_emit_mov_imm32(b, 3u, d->rd);
        a64_emit_mov_imm32(b, 4u,
            ((d->cls == (uint32_t)SPARC32_OP_SAVE) ? 1u : 0u) |
            ((d->is_imm != 0u) ? 2u : 0u));
        a64_emit_mov_pc32(b, 5u, ec->fault_pc);
    }
    e_call_prologue(b, helper);
    e_call_invoke_faultable(ec);
    return b->overflow ? -1 : 0;
}

int sparc32_emit_load(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    return e_emit_memcall(ec, d, (uint64_t)(uintptr_t)&sparc32_rt_mem, 0);
}

int sparc32_emit_store(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    return e_emit_memcall(ec, d, (uint64_t)(uintptr_t)&sparc32_rt_mem, 0);
}

int sparc32_emit_swap(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    return e_emit_memcall(ec, d, (uint64_t)(uintptr_t)&sparc32_rt_mem, 0);
}

int sparc32_emit_casa(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    return e_emit_memcall(ec, d, (uint64_t)(uintptr_t)&sparc32_rt_mem, 0);
}

int sparc32_emit_save(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    return e_emit_memcall(ec, d, (uint64_t)(uintptr_t)&sparc32_rt_window, 1);
}

int sparc32_emit_restore(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    return e_emit_memcall(ec, d, (uint64_t)(uintptr_t)&sparc32_rt_window, 1);
}

int sparc32_emit_flush(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    (void)ec;
    (void)d;
    /* Host memory model needs no barrier (interp returns true). */
    return 0;
}

int sparc32_emit_stbar(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    (void)ec;
    (void)d;
    /* Store barrier is a host-model nop (TSO). */
    return 0;
}

int sparc32_emit_priv(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    (void)d;
    e_trap_priv(ec->buf, ec->pc);
    return ec->buf->overflow ? -1 : 0;
}

int sparc32_emit_fallback(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    (void)d;
    /* FPU/FBfcc/odd encodings: dispatcher single-steps via interp_step. */
    a64_emit_exit_undef(ec->buf, ec->pc);
    return ec->buf->overflow ? -1 : 0;
}

static int e_emit_one(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    switch (d->cls) {
    case SPARC32_OP_SETHI:
        return sparc32_emit_sethi(ec, d);
    case SPARC32_OP_ALU:
        return sparc32_emit_alu(ec, d);
    case SPARC32_OP_SHIFT:
        return sparc32_emit_shift(ec, d);
    case SPARC32_OP_RDASR:
        return sparc32_emit_rdasr(ec, d);
    case SPARC32_OP_WRASR:
        return sparc32_emit_wrasr(ec, d);
    case SPARC32_OP_PRIV:
        return sparc32_emit_priv(ec, d);
    case SPARC32_OP_CALL:
        return sparc32_emit_call(ec, d);
    case SPARC32_OP_BRANCH:
        return sparc32_emit_branch(ec, d);
    case SPARC32_OP_JMPL:
        return sparc32_emit_jmpl(ec, d);
    case SPARC32_OP_SAVE:
        return sparc32_emit_save(ec, d);
    case SPARC32_OP_RESTORE:
        return sparc32_emit_restore(ec, d);
    case SPARC32_OP_TRAP:
        return sparc32_emit_trap(ec, d);
    case SPARC32_OP_FLUSH:
        return sparc32_emit_flush(ec, d);
    case SPARC32_OP_STBAR:
        return sparc32_emit_stbar(ec, d);
    case SPARC32_OP_LOAD:
        return sparc32_emit_load(ec, d);
    case SPARC32_OP_STORE:
        return sparc32_emit_store(ec, d);
    case SPARC32_OP_SWAP:
        return sparc32_emit_swap(ec, d);
    case SPARC32_OP_CASA:
        return sparc32_emit_casa(ec, d);
    case SPARC32_OP_FPU:
        return sparc32_emit_fpu(ec, d);
    case SPARC32_OP_FBRANCH:
        return sparc32_emit_fbranch(ec, d);
    case SPARC32_OP_FPMEM:
        return sparc32_emit_fpmem(ec, d);
    case SPARC32_OP_ILLEGAL:
    default:
        break;
    }
    return sparc32_emit_fallback(ec, d);
}

int sparc32_emit_insn(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    int rc;

    if (ec == NULL || ec->buf == NULL || d == NULL) {
        return -1;
    }
    ec->fault_pc = ec->pc;
    rc = e_emit_one(ec, d);
    if (rc != 0 || ec->buf->overflow) {
        return -1;
    }
    return 0;
}

