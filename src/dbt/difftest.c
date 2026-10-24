/*
 * src/dbt/difftest.c — Lockstep interp-vs-dbt differential harness (Phase 2)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L2d owns this file (Phase 2, SPEC sections 2-3). See difftest.h
 * for the compared-state contract and the dbt_step granularity assumption.
 *
 * Method: two sparc32_ctx_t copies (interp side / dbt side) share the one
 * [G, G + 4 GiB) guest mapping via the same guest_base. Each iteration
 * clears both exit reasons (interp_step only sets them, like interp_run
 * does once), steps both engines once, and compares. EXIT_SYSCALL runs
 * the shared sparc32_handle_syscall() exactly once on the interp copy and
 * mirrors the result into the dbt copy. Guest memory is touched only via
 * sparc32_guest_ptr; the backtrace walker reads only guest ranges covered
 * by a readable tracked region (unrestricted direct reads while
 * region_count == 0, matching sparc32_fetch_decode early bring-up).
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sparc32rt.h"

#include "dbt/difftest.h"
#include "interp/decode.h"
#include "interp/interp.h"
#include "interp/interp_priv.h"
#include "os/syscalls_min.h"

/* Hang guard: the P2 guests terminate in well under a million steps. */
#define DIFFTEST_MAX_STEPS 100000000UL

/* Backtrace depth bound (fp-chain walk). */
#define DIFFTEST_BT_DEPTH 8U

static const char *const difftest_rnames[32] = {
    "g0", "g1", "g2", "g3", "g4", "g5", "g6", "g7",
    "o0", "o1", "o2", "o3", "o4", "o5", "o6/sp", "o7",
    "l0", "l1", "l2", "l3", "l4", "l5", "l6", "l7",
    "i0", "i1", "i2", "i3", "i4", "i5", "i6/fp", "i7",
};

/* True when [va, va + len) is safe to touch via sparc32_guest_ptr:
 * no 32-bit wrap, above the low guard, and — once regions are tracked —
 * covered by a readable region. */
static bool difftest_covered(const sparc32_ctx_t *ctx, uint32_t va, uint32_t len)
{
    size_t i;
    if (len == 0U) {
        return true;
    }
    if ((uint64_t)va + (uint64_t)len > 0x100000000ULL) {
        return false;
    }
    if (va < SPARC32_LOW_GUARD_SIZE) {
        return false;
    }
    if (ctx->region_count == 0U) {
        return true;
    }
    for (i = 0U; i < ctx->region_count; i++) {
        if (ctx->regions[i].start <= va &&
            ctx->regions[i].end >= va + len &&
            (ctx->regions[i].prot & 0x1U) != 0U) {
            return true;
        }
    }
    return false;
}

/* Big-endian guest word load; caller must have checked difftest_covered. */
static uint32_t difftest_ld_be32(const sparc32_ctx_t *ctx, uint32_t va)
{
    const uint8_t *p = (const uint8_t *)sparc32_guest_ptr(ctx, va);
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int difftest_cmp_u32(const char *name, uint32_t a, uint32_t b,
    uint32_t step_pc, int *count)
{
    if (a != b) {
        printf("difftest: divergence at pc=0x%08x: %s interp=0x%08x dbt=0x%08x\n",
            step_pc, name, a, b);
        (*count)++;
        return 1;
    }
    return 0;
}

/*
 * Guest backtrace: fp-anchored register dump plus an fp-chain walk.
 * Each frame's save area holds l0..l7 at [+0, +32) and i0..i7 at
 * [+32, +64) (interp_spill_to layout), so the caller's fp is the word at
 * [fp + 56] and its return address the word at [fp + 60]. Every read is
 * coverage-checked; the walk stops at the first unreadable,
 * misaligned, or non-progressing frame.
 */
static void difftest_backtrace(const sparc32_ctx_t *ctx)
{
    uint32_t fp = ctx->r[SPARC32_FP];
    uint32_t depth;
    printf("difftest: backtrace: pc=0x%08x npc=0x%08x sp=0x%08x fp=0x%08x o7=0x%08x\n",
        ctx->pc, ctx->npc, ctx->r[SPARC32_SP], fp, ctx->r[15]);
    for (depth = 0U; depth < DIFFTEST_BT_DEPTH; depth++) {
        uint32_t next_fp;
        uint32_t ret;
        if ((fp & 3U) != 0U || fp == 0U) {
            break;
        }
        if (!difftest_covered(ctx, fp, 64U)) {
            printf("difftest: frame %u: fp=0x%08x (unreadable, stop)\n",
                depth, fp);
            break;
        }
        next_fp = difftest_ld_be32(ctx, fp + 56U);
        ret = difftest_ld_be32(ctx, fp + 60U);
        printf("difftest: frame %u: fp=0x%08x ret=0x%08x\n", depth, fp, ret);
        if (next_fp == 0U || next_fp == fp) {
            break;
        }
        fp = next_fp;
    }
}

/* Compare the full user-visible state after one lockstep step.
 * Returns the number of differing fields (0 = agreement). */
static int difftest_cmp_state(const sparc32_ctx_t *a, const sparc32_ctx_t *b,
    uint32_t step_pc)
{
    int n = 0;
    uint32_t i;
    for (i = 0U; i < 32U; i++) {
        difftest_cmp_u32(difftest_rnames[i], a->r[i], b->r[i], step_pc, &n);
    }
    for (i = 0U; i < 32U; i++) {
        char fname[8];
        snprintf(fname, sizeof(fname), "f%u", i);
        difftest_cmp_u32(fname, a->f[i], b->f[i], step_pc, &n);
    }
    difftest_cmp_u32("pc", a->pc, b->pc, step_pc, &n);
    difftest_cmp_u32("npc", a->npc, b->npc, step_pc, &n);
    difftest_cmp_u32("psr.icc", a->psr & SPARC32_PSR_ICC_MASK,
        b->psr & SPARC32_PSR_ICC_MASK, step_pc, &n);
    difftest_cmp_u32("y", a->y, b->y, step_pc, &n);
    difftest_cmp_u32("fsr", a->fsr, b->fsr, step_pc, &n);
    difftest_cmp_u32("cwp", a->cwp, b->cwp, step_pc, &n);
    difftest_cmp_u32("cansave", a->cansave, b->cansave, step_pc, &n);
    difftest_cmp_u32("canrestore", a->canrestore, b->canrestore, step_pc, &n);
    difftest_cmp_u32("otherwin", a->otherwin, b->otherwin, step_pc, &n);
    difftest_cmp_u32("cleanwin", a->cleanwin, b->cleanwin, step_pc, &n);
    difftest_cmp_u32("nwindows", a->nwindows, b->nwindows, step_pc, &n);
    return n;
}

static const char *difftest_reason_name(uint32_t reason)
{
    switch (reason) {
    case SPARC32_EXIT_NONE:
        return "NONE";
    case SPARC32_EXIT_BRANCH:
        return "BRANCH";
    case SPARC32_EXIT_SYSCALL:
        return "SYSCALL";
    case SPARC32_EXIT_UNDEF:
        return "UNDEF";
    case SPARC32_EXIT_FAULT:
        return "FAULT";
    case SPARC32_EXIT_TRAP:
        return "TRAP";
    case SPARC32_EXIT_SINGLE_STEP:
        return "SINGLE_STEP";
    default:
        return "?";
    }
}

/* Mismatched stop reasons are a divergence; prints both sides. */
static int difftest_reason_div(const sparc32_ctx_t *a, const sparc32_ctx_t *b,
    uint32_t step_pc)
{
    printf("difftest: divergence at pc=0x%08x: stop-reason interp=%s(%u) dbt=%s(%u)\n",
        step_pc, difftest_reason_name(a->exit_reason), a->exit_reason,
        difftest_reason_name(b->exit_reason), b->exit_reason);
    printf("difftest: interp dest=0x%08x fault=0x%08x | dbt dest=0x%08x fault=0x%08x\n",
        a->exit_dest, a->fault_addr, b->exit_dest, b->fault_addr);
    difftest_backtrace(a);
    return 1;
}

/* Atomic RMW sandwich (LDSTUB/SWAP/CASA): both engines share the one
 * guest mapping, so interp stepping first would let its write be visible
 * to dbt's subsequent read (observed: dbt g4=0xff vs interp g4=0x5a).
 * Snapshot the touched bytes, run interp, restore them, then run dbt, so
 * both engines read identical pre-state. Plain loads/stores need no
 * sandwich (idempotent second write). Only entered when the range is
 * mapped+readable; otherwise both engines fault identically. */
typedef struct {
    bool armed;
    uint32_t va;
    uint32_t len;
    uint8_t bytes[4];
} difftest_rmw_t;

static difftest_rmw_t difftest_rmw_snap(const sparc32_ctx_t *ctx,
    uint32_t pc)
{
    difftest_rmw_t s;
    sparc32_decoded_t d;
    const uint8_t *ip;
    uint32_t word;
    uint32_t va;
    uint32_t len;
    s.armed = false;
    s.va = 0U;
    s.len = 0U;
    if (!interp_range_ok(ctx, pc, 4U, 1U)) {
        return s;
    }
    ip = (const uint8_t *)sparc32_guest_ptr(ctx, pc);
    word = ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) |
        ((uint32_t)ip[2] << 8) | (uint32_t)ip[3];
    sparc32_decode_word(word, &d);
    switch (d.op3) {
    case SPARC32_OP3_LDSTUB:
    case SPARC32_OP3_LDSTUBA:
        len = 1U;
        break;
    case SPARC32_OP3_SWAP:
    case SPARC32_OP3_SWAPA:
    case SPARC32_OP3_CASA:
        len = 4U;
        break;
    default:
        return s;
    }
    va = ctx->r[d.rs1 & 31U] +
        (d.is_imm != 0U ? (uint32_t)d.simm : ctx->r[d.rs2 & 31U]);
    if (!interp_range_ok(ctx, va, len, 3U)) {
        return s;
    }
    memcpy(s.bytes, sparc32_guest_ptr(ctx, va), len);
    s.armed = true;
    s.va = va;
    s.len = len;
    return s;
}

static void difftest_rmw_restore(const sparc32_ctx_t *ctx, difftest_rmw_t *s)
{
    if (s->armed) {
        memcpy(sparc32_guest_ptr(ctx, s->va), s->bytes, (size_t)s->len);
        s->armed = false;
    }
}

int difftest_run(sparc32_ctx_t *ctx)
{
    sparc32_ctx_t a;
    sparc32_ctx_t b;
    unsigned long steps = 0UL;
    if (ctx == NULL) {
        printf("difftest: null context\n");
        return 2;
    }
    a = *ctx;
    b = *ctx;
    for (;;) {
        uint32_t step_pc;
        long nr;
        long status;
        int n;
        difftest_rmw_t rmw;
        if (steps >= DIFFTEST_MAX_STEPS) {
            printf("difftest: step budget exhausted (%lu steps, pc=0x%08x)\n",
                steps, a.pc);
            return 2;
        }
        /* interp_step/dbt_step only set exit_reason (interp_run clears it
         * once); the lockstep loop must clear it before every step. */
        a.exit_reason = SPARC32_EXIT_NONE;
        b.exit_reason = SPARC32_EXIT_NONE;
        step_pc = a.pc;
        steps++;
        rmw = difftest_rmw_snap(&a, step_pc);
        interp_step(&a);
        difftest_rmw_restore(&a, &rmw);
        dbt_step(&b);
        if (a.exit_reason != b.exit_reason) {
            return difftest_reason_div(&a, &b, step_pc);
        }
        switch (a.exit_reason) {
        case SPARC32_EXIT_NONE:
            /* Clean step: exit_dest carries no meaning (dbt leaves the
             * fallthrough pc there; interp leaves it stale). */
            n = difftest_cmp_state(&a, &b, step_pc);
            if (n != 0) {
                difftest_backtrace(&a);
                return 1;
            }
            break;
        case SPARC32_EXIT_SINGLE_STEP:
            /* SINGLE_STEP (page-final branch whose delay ran) already
             * advanced pc/npc on both sides; stepping simply resumes.
             * exit_dest IS the resume point here, so it must agree.
             * A page-final branch whose delay was annulled away reports
             * NONE on both sides (interp_cti early return; dbt replays
             * to the same NONE), never SINGLE_STEP. */
            n = difftest_cmp_state(&a, &b, step_pc);
            if (a.exit_dest != b.exit_dest) {
                printf("difftest: divergence at pc=0x%08x: exit_dest interp=0x%08x dbt=0x%08x\n",
                    step_pc, a.exit_dest, b.exit_dest);
                n++;
            }
            if (n != 0) {
                difftest_backtrace(&a);
                return 1;
            }
            break;
        case SPARC32_EXIT_SYSCALL:
            /* Both engines trapped on the same instruction: state must
             * match first, then the syscall runs exactly once. */
            n = difftest_cmp_state(&a, &b, step_pc);
            if (n != 0) {
                difftest_backtrace(&a);
                return 1;
            }
            nr = (long)(int32_t)a.r[SPARC32_G1];
            status = sparc32_handle_syscall(&a);
            if (sparc32_syscall_is_exit(nr)) {
                *ctx = a;
                printf("difftest: 0 divergences (%lu steps, guest exit %ld)\n",
                    steps, status & 0xFFL);
                return (int)(status & 0xFFL);
            }
            /* One shared handler call: mirror the post-syscall state
             * (advanced pc/npc, carry result) into both engines. */
            b = a;
            break;
        case SPARC32_EXIT_FAULT:
            /* Matching fault: state and fault address must agree first,
             * then attempt synchronous delivery on both copies (same
             * signo rule as main.c: misaligned VA -> SIGBUS, else
             * SIGSEGV). Delivery is deterministic, so identical
             * pre-states stay identical. */
            n = difftest_cmp_state(&a, &b, step_pc);
            if (a.fault_addr != b.fault_addr) {
                printf("difftest: divergence at pc=0x%08x: fault_addr interp=0x%08x dbt=0x%08x\n",
                    step_pc, a.fault_addr, b.fault_addr);
                n++;
            }
            if (n != 0) {
                difftest_backtrace(&a);
                return 1;
            }
            {
                int signo = (a.fault_addr & 3U) != 0U ? 10 : 11;
                bool da = interp_try_deliver_sync(&a, signo);
                bool db = interp_try_deliver_sync(&b, signo);
                if (da && db) {
                    break;
                }
                if (da != db) {
                    printf("difftest: divergence at pc=0x%08x: delivery interp=%d dbt=%d\n",
                        step_pc, (int)da, (int)db);
                    difftest_backtrace(&a);
                    return 1;
                }
            }
            /* Neither copy has a handler: agreement, guest would die. */
            *ctx = a;
            printf("difftest: both engines faulted with no handler at pc=0x%08x (agreement, guest did not exit)\n",
                step_pc);
            return 2;
        default:
            /* Matching non-continuable stop (TRAP/UNDEF/...):
             * agreement, but the guest did not exit cleanly. */
            n = difftest_cmp_state(&a, &b, step_pc);
            if (a.fault_addr != b.fault_addr) {
                printf("difftest: divergence at pc=0x%08x: fault_addr interp=0x%08x dbt=0x%08x\n",
                    step_pc, a.fault_addr, b.fault_addr);
                n++;
            }
            if (n != 0) {
                difftest_backtrace(&a);
                return 1;
            }
            *ctx = a;
            printf("difftest: both engines stopped with %s(%u) at pc=0x%08x (agreement, guest did not exit)\n",
                difftest_reason_name(a.exit_reason), a.exit_reason, step_pc);
            return 2;
        }
    }
}
