/*
 * src/dbt/emit_fpbranch.c — AArch64 FBfcc transfer emitter (Phase 3, L3b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from emit_fp.c for the 900-line file discipline (same pattern
 * as emit_fpmem.c). Lowers FBfcc transfers: the taken predicate is a
 * 4-bit mask over FSR.fcc (0 equal, 1 less, 2 greater, 3 unordered),
 * mirroring Bicc delay/annul/page-final policy exactly.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "interp/decode.h"
#include "rt32/a64_emit.h"
#include "sparc32rt.h"

#include "dbt/emit_fp.h"
#include "dbt/emit_int.h"

/* Scratch allocation (same FP set as emit_fp.c; v-regions untouched). */
#define FS0 15u /* w15/x15: scratch / exit guest PC */
#define FS1 16u /* w16: scratch / taken bit */
#define FS2 17u /* w17/x17: scratch / jmpl-record tmp */

/* ctx field offsets used by this emitter. */
#define FP_FSR_OFF ((uint32_t)offsetof(sparc32_ctx_t, fsr))

/* FBfcc transfer (mirrors Bicc on FSR.fcc: 0 equal, 1 less,
 * 2 greater, 3 unordered; cond numbering mirrors Bicc). */

/* Taken predicate: 4-bit mask over fcc (GAS-verified numbering). */
static const uint32_t fp_taken_mask[16] = {
    0x0U, 0xEU, 0x6U, 0xAU, 0x2U, 0xCU, 0x4U, 0x8U,
    0xFU, 0x1U, 0x9U, 0x5U, 0xDU, 0x3U, 0xBU, 0x7U
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

static void fp_jmpl_disarm(a64_buf_t *b)
{
    uint32_t off_a = (uint32_t)offsetof(sparc32_ctx_t, jmpl_delay_armed);
    uint32_t hi_a = off_a & ~0xFFFu;
    uint32_t lo_a = off_a & 0xFFFu;
    if (hi_a == 0U) {
        a64_emit_strb_imm_w(b, A64_ZR, A64_XCTX, off_a);
    } else {
        a64_emit(b, 0x91400000U | ((hi_a >> 12) << 10) |
            ((A64_XCTX & 31U) << 5) | (FS2 & 31U));
        a64_emit_strb_imm_w(b, A64_ZR, FS2, lo_a);
    }
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
        fp_jmpl_disarm(ec->buf);
        if (page_final != 0) {
            return sparc32_emit_exit_singlestep(ec, post);
        }
    }
    a64_emit_exit_branch(ec->buf, post);
    return ec->buf->overflow ? -1 : 0;
}

/* Integer delay-slot classes route to the public L2c emitters (the
 * delay address is in ec->pc, and ec->fault_pc already holds the delay
 * address too so a faulting delay reports the delay, exactly like the
 * integer e_emit_delay, S32-R8-3). One case per line to hold
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
        sparc32_emit_fp_flush(ec->buf);
        return rc;
    case SPARC32_OP_FPMEM:
        ec->pc = npc;
        rc = sparc32_emit_fpmem(ec, d);
        ec->pc = saved_pc;
        sparc32_emit_fp_flush(ec->buf);
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
    /* S32-R8-3: the delay slot runs at npc, so helper fault exits must
     * carry npc (matching interp_cti, like JMPL). */
    ec->fault_pc = npc;
    if (cond == 0x0U) { /* FBN: never branches. */
        return fp_delay_tail(ec, npc, npc + 4U,
            fp_delay_runs(cond, 0, annul), page_final);
    }
    if (cond == 0x8U) { /* FBA: always branches. */
        int runs = fp_delay_runs(cond, 1, annul);
        if (runs != 0) {
            /* S32-R8-4: taken delay faults commit npc = target. */
            a64_emit_mov_pc32(b, FS0, target);
            a64_jmpl_record(b, FS0, FS2, FS1);
        }
        return fp_delay_tail(ec, npc, target, runs, page_final);
    }
    if (page_final != 0) {
        uint8_t sg_valid = b->gpr_cache_valid;
        uint8_t sg_reg[8];
        uint8_t sf_valid = b->fpr_valid;
        uint8_t sf_tag[8];
        bool s_fp_chk = b->fp_fast_checked;
        bool s_fp_dirty = b->fpsr_dirty;
        memcpy(sg_reg, b->gpr_cache_reg, sizeof(sg_reg));
        memcpy(sf_tag, b->fpr_tag, sizeof(sf_tag));
        fp_taken_compute(b, cond);
        p_taken = a64_emit_cbz_w_placeholder(b, true, FS1);
        rc = fp_delay_tail(ec, npc, npc + 4U,
            fp_delay_runs(cond, 0, annul), page_final);
        if (rc != 0) {
            return rc;
        }
        a64_patch_cbz_w(b, p_taken, b->count);
        b->gpr_cache_valid = sg_valid;
        memcpy(b->gpr_cache_reg, sg_reg, sizeof(sg_reg));
        b->fpr_valid = sf_valid;
        memcpy(b->fpr_tag, sf_tag, sizeof(sf_tag));
        b->fp_fast_checked = s_fp_chk;
        b->fpsr_dirty = s_fp_dirty;
        /* Taken page-final always SINGLE_STEPs (emit_branch shape),
         * even when the delay was annulled away. */
        if (fp_delay_runs(cond, 1, annul) != 0) {
            /* S32-R8-4: taken delay faults commit npc = target. */
            a64_emit_mov_pc32(b, FS0, target);
            a64_jmpl_record(b, FS0, FS2, FS1);
            rc = fp_emit_delay(ec, npc);
            if (rc != 0) {
                return rc;
            }
            fp_jmpl_disarm(b);
        }
        return sparc32_emit_exit_singlestep(ec, target);
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
        b->gpr_cache_valid = sg_valid;
        memcpy(b->gpr_cache_reg, sg_reg, sizeof(sg_reg));
        b->fpr_valid = sf_valid;
        memcpy(b->fpr_tag, sf_tag, sizeof(sf_tag));
        b->fp_fast_checked = s_fp_chk;
        b->fpsr_dirty = s_fp_dirty;
    }
    if (fp_delay_runs(cond, 1, annul) != 0) {
        /* S32-R8-4: taken delay faults commit npc = target. */
        a64_emit_mov_pc32(b, FS0, target);
        a64_jmpl_record(b, FS0, FS2, FS1);
        rc = fp_emit_delay(ec, npc);
        if (rc != 0) {
            return rc;
        }
        fp_jmpl_disarm(b);
    }
    a64_emit_exit_branch(b, target);
    if (b->overflow) {
        return -1;
    }
    a64_patch_b_cond(b, p_end, b->count);
    a64_emit_exit_branch(b, npc + 4U);
    return b->overflow ? -1 : 0;
}
