/*
 * src/dbt/emit_cti.c — AArch64 CTI and delay-slot emitter (Phase 2, L2c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from src/dbt/emit_int.c for the 900-line per-file discipline.
 * Implements Bicc, CALL, JMPL, page-final SINGLE_STEP exits, and delay-slot
 * emission with annulment and fault-PC preservation.
 */

#include "dbt/emit_int.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "dbt/emit_cc.h"
#include "dbt/emit_fp.h"
#include "interp/decode.h"
#include "rt32/a64_emit.h"
#include "sparc32rt.h"

#define ES0   15u /* w15: scratch / exit guest PC */
#define ES1   16u /* w16: scratch / exit reason */
#define ES2   17u /* w17: scratch */
#define EKEEP 22u /* w22: value keeper across delay slots (JMPL target) */

static void cti_ldgreg(a64_buf_t *b, unsigned wd, uint32_t rs)
{
    a64_gpr_load(b, wd, rs);
}

static void cti_stgreg(a64_buf_t *b, uint32_t rd, unsigned ws)
{
    a64_gpr_store(b, rd, ws);
}

static void cti_src2(a64_buf_t *b, unsigned wd, const sparc32_decoded_t *d)
{
    if (d->is_imm != 0u) {
        a64_emit_mov_imm32(b, wd, (uint32_t)d->simm);
    } else {
        cti_ldgreg(b, wd, d->rs2);
    }
}

static void cti_ea_into(a64_buf_t *b, unsigned wd, const sparc32_decoded_t *d)
{
    cti_ldgreg(b, ES2, d->rs1);
    cti_src2(b, wd, d);
    a64_emit_add_reg_w(b, false, wd, ES2, wd, A64_SHIFT_LSL, 0u);
}

static unsigned cti_branch_cond(a64_buf_t *b, uint32_t cond)
{
    unsigned ac;
    if (sparc32_emit_live_cond(b, cond, &ac) != 0) {
        return ac;
    }
    sparc32_emit_cond_setup(b, cond);
    return sparc32_emit_icc_cond(cond);
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
 * like interp_single. ec->fault_pc must already hold the delay address
 * (npc) so a faulting delay reports the delay as the fault site
 * (S32-R8-3, matching interp_cti); the taken copy additionally arms
 * jmpl_target with the static target so a delay fault commits
 * npc = target (S32-R8-4). */

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
        return sparc32_emit_exit_singlestep(ec, ec->fault_pc);
    case SPARC32_OP_FPU:
        ec->pc = npc;
        rc = sparc32_emit_fpu(ec, d);
        ec->pc = saved_pc;
        sparc32_emit_fp_flush(ec->buf);
        return rc;
    case SPARC32_OP_FPMEM:
        ec->pc = npc;
        rc = sparc32_emit_fpmem(ec, d);
        ec->pc = saved_pc;
        sparc32_emit_fp_flush(ec->buf);
        return rc;
    case SPARC32_OP_FBRANCH:
    case SPARC32_OP_ILLEGAL:
        a64_emit_exit_undef(ec->buf, npc);
        return ec->buf->overflow ? -1 : 0;
    default:
        break;
    }
    ec->pc = npc;
    rc = sparc32_emit_one(ec, d);
    ec->pc = saved_pc;
    return rc;
}

static int e_delay_runs(uint32_t cls, uint32_t cond, int taken, int annul)
{
    (void)cls;
    if (taken != 0) {
        return (cond == 0x8u && annul != 0) ? 0 : 1;
    }
    return annul != 0 ? 0 : 1;
}

static int e_delay_needs_jmpl_record(const sparc32_decoded_t *dl)
{
    if (dl == NULL) {
        return 1;
    }
    switch (dl->cls) {
    case SPARC32_OP_SETHI:
    case SPARC32_OP_SHIFT:
    case SPARC32_OP_FLUSH:
    case SPARC32_OP_STBAR:
        return 0;
    case SPARC32_OP_ALU:
        return ((dl->op3 & 0x3Fu) < 0x0Eu) ? 0 : 1;
    default:
        break;
    }
    return 1;
}

static void e_jmpl_disarm(a64_buf_t *b)
{
    uint32_t off_a = (uint32_t)offsetof(sparc32_ctx_t, jmpl_delay_armed);
    uint32_t hi_a = off_a & ~0xFFFu;
    uint32_t lo_a = off_a & 0xFFFu;
    if (hi_a == 0u) {
        a64_emit_strb_imm_w(b, A64_ZR, A64_XCTX, off_a);
    } else {
        a64_emit(b, 0x91400000u | ((hi_a >> 12) << 10) |
            ((A64_XCTX & 31u) << 5) | (ES2 & 31u));
        a64_emit_strb_imm_w(b, A64_ZR, ES2, lo_a);
    }
}

/* Shared page-final conditional-branch body (S32-R13-6, declared in
 * emit_int.h): the caller emits its taken test (icc Bicc or fcc FBfcc)
 * and passes the pending placeholder; not-taken delay/exit, the patch,
 * and the taken delay/exit with jmpl record/disarm are identical
 * (w15/w16/w17 scratch on both sides). */
int sparc32_emit_branch_page_final(sparc32_emit_ctx_t *ec, uint32_t npc,
    uint32_t target, int not_taken_runs, int taken_runs,
    size_t taken_patch, int taken_is_cbz,
    sparc32_cti_delay_fn emit_delay)
{
    a64_buf_t *b;
    uint8_t sg_valid;
    uint8_t sg_reg[8];
    uint8_t sf_valid;
    uint8_t sf_tag[8];
    bool s_fp_chk;
    bool s_fp_dirty;
    int rc;
    if (ec == NULL || emit_delay == NULL) {
        return -1;
    }
    b = ec->buf;
    if (b == NULL) {
        return -1;
    }
    sg_valid = b->gpr_cache_valid;
    sf_valid = b->fpr_valid;
    s_fp_chk = b->fp_fast_checked;
    s_fp_dirty = b->fpsr_dirty;
    memcpy(sg_reg, b->gpr_cache_reg, sizeof(sg_reg));
    memcpy(sf_tag, b->fpr_tag, sizeof(sf_tag));
    if (not_taken_runs != 0) {
        rc = emit_delay(ec, npc);
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
    if (taken_is_cbz != 0) {
        a64_patch_cbz_w(b, taken_patch, b->count);
    } else {
        a64_patch_b_cond(b, taken_patch, b->count);
    }
    b->gpr_cache_valid = sg_valid;
    memcpy(b->gpr_cache_reg, sg_reg, sizeof(sg_reg));
    b->fpr_valid = sf_valid;
    memcpy(b->fpr_tag, sf_tag, sizeof(sf_tag));
    b->fp_fast_checked = s_fp_chk;
    b->fpsr_dirty = s_fp_dirty;
    if (taken_runs != 0) {
        /* S32-R8-4: taken delay faults commit npc = target. */
        if (e_delay_needs_jmpl_record(ec->delay) != 0) {
            a64_emit_mov_pc32(b, ES0, target);
            a64_jmpl_record(b, ES0, ES2, ES1);
        }
        rc = emit_delay(ec, npc);
        if (rc != 0) {
            return rc;
        }
        if (e_delay_needs_jmpl_record(ec->delay) != 0) {
            e_jmpl_disarm(b);
        }
    }
    return sparc32_emit_exit_singlestep(ec, target);
}

static int e_page_final(sparc32_emit_ctx_t *ec, uint32_t npc,
    uint32_t post_pc)
{
    int rc = e_emit_delay(ec, npc);

    if (rc != 0) {
        return rc;
    }
    if (e_delay_needs_jmpl_record(ec->delay) != 0) {
        e_jmpl_disarm(ec->buf);
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
    int need_rec = e_delay_needs_jmpl_record(ec->delay);
    size_t p_taken;
    size_t p_end;
    int rc;

    /* S32-R8-3: the delay slot runs at npc, so helper fault exits must
     * carry npc (matching interp_cti, like JMPL below). */
    ec->fault_pc = npc;
    /* S32-R14-2: a missing, CALL/BRANCH/JMPL, or TRAP delay cannot be
     * inlined (the outer transfer is cancelled); exit SINGLE_STEP at
     * the branch pc so interp_step replays the pair atomically instead
     * of losing the outer pc at npc. */
    if (ec->delay == NULL ||
        ec->delay->cls == (uint32_t)SPARC32_OP_CALL ||
        ec->delay->cls == (uint32_t)SPARC32_OP_BRANCH ||
        ec->delay->cls == (uint32_t)SPARC32_OP_JMPL ||
        ec->delay->cls == (uint32_t)SPARC32_OP_TRAP) {
        return sparc32_emit_exit_singlestep(ec, pc);
    }
    if (cond == 0x0u) {
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
    if (cond == 0x8u) {
        if (e_delay_runs(d->cls, cond, 1, annul) != 0) {
            /* S32-R8-4: taken delay faults commit npc = target. */
            if (need_rec != 0) {
                a64_emit_mov_pc32(b, ES0, target);
                a64_jmpl_record(b, ES0, ES2, ES1);
            }
            if (page_final) {
                return e_page_final(ec, npc, target);
            }
            rc = e_emit_delay(ec, npc);
            if (rc != 0) {
                return rc;
            }
            if (need_rec != 0) {
                e_jmpl_disarm(b);
            }
        }
        a64_emit_exit_branch(b, target);
        return b->overflow ? -1 : 0;
    }
    if (page_final) {
        p_taken = a64_emit_b_cond_placeholder(b, cti_branch_cond(b, cond));
        return sparc32_emit_branch_page_final(ec, npc, target,
            e_delay_runs(d->cls, cond, 0, annul),
            e_delay_runs(d->cls, cond, 1, annul),
            p_taken, 0, e_emit_delay);
    }
    {
        uint8_t sg_valid = b->gpr_cache_valid;
        uint8_t sg_reg[8];
        uint8_t sf_valid = b->fpr_valid;
        uint8_t sf_tag[8];
        bool s_fp_chk = b->fp_fast_checked;
        bool s_fp_dirty = b->fpsr_dirty;
        memcpy(sg_reg, b->gpr_cache_reg, sizeof(sg_reg));
        memcpy(sf_tag, b->fpr_tag, sizeof(sf_tag));
        p_taken = a64_emit_b_cond_placeholder(b, cti_branch_cond(b, cond));
        if (e_delay_runs(d->cls, cond, 0, annul) != 0) {
            rc = e_emit_delay(ec, npc);
            if (rc != 0) {
                return rc;
            }
        }
        p_end = a64_emit_b_cond_placeholder(b, A64_COND_AL);
        a64_patch_b_cond(b, p_taken, b->count);
        b->gpr_cache_valid = sg_valid;
        memcpy(b->gpr_cache_reg, sg_reg, sizeof(sg_reg));
        b->fpr_valid = sf_valid;
        memcpy(b->fpr_tag, sf_tag, sizeof(sf_tag));
        b->fp_fast_checked = s_fp_chk;
        b->fpsr_dirty = s_fp_dirty;
    }
    if (e_delay_runs(d->cls, cond, 1, annul) != 0) {
        /* S32-R8-4: taken delay faults commit npc = target. */
        if (need_rec != 0) {
            a64_emit_mov_pc32(b, ES0, target);
            a64_jmpl_record(b, ES0, ES2, ES1);
        }
        rc = e_emit_delay(ec, npc);
        if (rc != 0) {
            return rc;
        }
        if (need_rec != 0) {
            e_jmpl_disarm(b);
        }
    }
    a64_emit_exit_branch(b, target);
    if (b->overflow) {
        return -1;
    }
    a64_patch_b_cond(b, p_end, b->count);
    a64_emit_exit_branch(b, npc + 4u);
    return b->overflow ? -1 : 0;
}

int sparc32_emit_call(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    a64_buf_t *b = ec->buf;
    uint32_t pc = ec->pc;
    uint32_t npc = pc + 4u;
    uint32_t target = pc + (uint32_t)d->disp;
    int need_rec = e_delay_needs_jmpl_record(ec->delay);
    int rc;

    /* S32-R8-3: the delay slot runs at npc, so helper fault exits must
     * carry npc (matching interp_cti, like JMPL below). */
    ec->fault_pc = npc;
    if ((pc & 0xFFFu) == 0xFFCu) {
        a64_emit_mov_pc32(b, ES0, pc);
        cti_stgreg(b, SPARC32_O7, ES0);
        b->is_call = true;
        /* S32-R8-4: taken delay faults commit npc = target. */
        if (need_rec != 0) {
            a64_emit_mov_pc32(b, ES0, target);
            a64_jmpl_record(b, ES0, ES2, ES1);
        }
        return e_page_final(ec, npc, target);
    }
    if (ec->delay == NULL || ec->delay->cls == (uint32_t)SPARC32_OP_CALL ||
        ec->delay->cls == (uint32_t)SPARC32_OP_BRANCH ||
        ec->delay->cls == (uint32_t)SPARC32_OP_JMPL ||
        ec->delay->cls == (uint32_t)SPARC32_OP_TRAP ||
        ec->delay->cls == (uint32_t)SPARC32_OP_FBRANCH ||
        ec->delay->cls == (uint32_t)SPARC32_OP_PRIV ||
        ec->delay->cls == (uint32_t)SPARC32_OP_ILLEGAL ||
        ec->delay->cls == (uint32_t)SPARC32_OP_FPU) {
        return sparc32_emit_exit_singlestep(ec, pc);
    }
    a64_emit_mov_pc32(b, ES0, pc);
    cti_stgreg(b, SPARC32_O7, ES0);
    b->nzcv_valid = 0;
    b->is_call = true;
    /* S32-R8-4: taken delay faults commit npc = target. */
    if (need_rec != 0) {
        a64_emit_mov_pc32(b, ES0, target);
        a64_jmpl_record(b, ES0, ES2, ES1);
    }
    rc = e_emit_delay(ec, npc);
    if (rc != 0) {
        return rc;
    }
    if (need_rec != 0) {
        e_jmpl_disarm(b);
    }
    a64_emit_exit_branch(b, target);
    return b->overflow ? -1 : 0;
}

int sparc32_emit_jmpl(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d)
{
    a64_buf_t *b = ec->buf;
    uint32_t pc = ec->pc;
    uint32_t npc = pc + 4u;
    int need_rec = e_delay_needs_jmpl_record(ec->delay);
    size_t p_aligned;
    int rc;

    ec->fault_pc = pc;
    if ((pc & 0xFFFu) == 0xFFCu) {
        return sparc32_emit_exit_singlestep(ec, pc);
    }
    if (ec->delay == NULL || ec->delay->cls == (uint32_t)SPARC32_OP_CALL ||
        ec->delay->cls == (uint32_t)SPARC32_OP_BRANCH ||
        ec->delay->cls == (uint32_t)SPARC32_OP_JMPL ||
        ec->delay->cls == (uint32_t)SPARC32_OP_TRAP ||
        ec->delay->cls == (uint32_t)SPARC32_OP_FBRANCH ||
        ec->delay->cls == (uint32_t)SPARC32_OP_PRIV ||
        ec->delay->cls == (uint32_t)SPARC32_OP_ILLEGAL ||
        ec->delay->cls == (uint32_t)SPARC32_OP_FPU) {
        return sparc32_emit_exit_singlestep(ec, pc);
    }
    cti_ea_into(b, EKEEP, d);
    /* Validate 4-byte alignment of target before committing rd or running
     * the delay slot; misaligned targets exit via SINGLE_STEP at pc so the
     * interpreter raises the precise alignment fault at JMPL. */
    a64_emit_mov_imm32(b, ES0, 3u);
    a64_emit_and_reg_w(b, false, ES0, EKEEP, ES0, A64_SHIFT_LSL, 0u);
    p_aligned = a64_emit_cbz_w_placeholder(b, false, ES0);
    if (sparc32_emit_exit_singlestep(ec, pc) != 0) {
        return -1;
    }
    a64_patch_cbz_w(b, p_aligned, b->count);
    if (d->rd != 0u) {
        a64_emit_mov_pc32(b, ES0, pc);
        cti_stgreg(b, d->rd, ES0);
    }
    if (need_rec != 0) {
        a64_jmpl_record(b, EKEEP, ES2, ES0);
    }
    if (d->rd == SPARC32_O7) {
        b->is_call = true;
    }
    ec->fault_pc = npc;
    rc = e_emit_delay(ec, npc);
    if (rc != 0) {
        return rc;
    }
    if (need_rec != 0) {
        e_jmpl_disarm(b);
    }
    a64_emit_exit_branch_reg(b, EKEEP);
    return b->overflow ? -1 : 0;
}
