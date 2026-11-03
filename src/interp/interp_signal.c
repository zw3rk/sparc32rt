/*
 * src/interp/interp_signal.c — Sync fault delivery (Phase 1, RC1)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
RC1 subset of Phase-4 signals: rt_signal_frame32 construction for
 * installed old-style handlers; async delivery stays Phase 4.
 */

#include "sparc32rt.h"

#include "interp/interp.h"
#include "interp/interp_priv.h"
#include "os/sigframe_sparc32rt.h"
#include "os/syscalls_min.h"
#include "os/threads.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

/* Synchronous fault delivery. Builds the frozen kernel-order
 * rt_signal_frame32 (344 B) + inline sigfpu32 tail (136 B) on the guest
 * stack (16-aligned) and redirects to an installed handler:
 *   %sp = frame, %o0 = signo, %o1 = &siginfo, %o2 = &pt_regs,
 *   %o7 = restorer, pc = handler, npc = handler + 4.
 * Generic word/halfword alignment checks in interp_mem.c and explicit
 * doubleword alignment checks in interp.c / emit_int.c raise EXIT_FAULT
 * with ctx->fault_addr; sparc32_classify_fault selects SIGBUS (10,
 * BUS_ADRALN) vs SIGSEGV (11, SEGV_MAPERR/SEGV_ACCERR). */
/* C2-3 delivery stack: an SA_ONSTACK handler runs on the installed
 * alternate stack (top, frame built under it 16-aligned) unless a
 * handler already runs there. Returns the sp to build under. */
static uint32_t interp_delivery_sp(sparc32_ctx_t *ctx, uint32_t flags)
{
    uint32_t sp = ctx->r[SPARC32_SP];
    /* Flush all cached caller windows and the interrupted live window to
     * the interrupted stack before overwriting %sp with the signal frame,
     * so setjmp/longjmp or stack unwinding out of a signal handler finds
     * the interrupted window's L0..I7 at its true home sp. */
    (void)interp_flush_windows(ctx);
    if (interp_range_ok(ctx, sp, SPARC32_RWINDOW_SIZE, 2U)) {
        int i;
        for (i = 0; i < 8; i++) {
            uint32_t base = sp + (uint32_t)i * 4U;
            (void)interp_st_be(ctx, base, 4U,
                ctx->r[SPARC32_L0 + (uint32_t)i]);
            (void)interp_st_be(ctx, base + 32U, 4U,
                ctx->r[SPARC32_I0 + (uint32_t)i]);
        }
    }
    if ((flags & SPARC32_SA_ONSTACK) != 0U) {
        uint32_t asp;
        uint32_t asize;
        int onstack;
        /* Per-thread alternate stack (S32-R3-5): the owning context's
         * stack only; another thread's stack is never borrowed. */
        if (sparc32_sigaltstack_state_ctx(ctx, &asp, &asize, &onstack) == 0 &&
            !onstack) {
            sparc32_sigaltstack_set_onstack_ctx(ctx, 1);
            sp = asp + asize;
        }
    }
    return sp;
}

static bool interp_frame_fpu(sparc32_ctx_t *ctx, uint32_t fpu_va)
{
    uint32_t i;
    for (i = 0U; i < 32U; i++) {
        if (!interp_st_be(ctx, fpu_va + i * 4U, 4U, ctx->f[i])) {
            return false;
        }
    }
    if (!interp_st_be(ctx, fpu_va + 128U, 4U, ctx->fsr)) {
        return false;
    }
    if (!interp_st_be(ctx, fpu_va + 132U, 4U, 0U)) {
        return false;
    }
    return true;
}

static void interp_apply_delivery_mask(sparc32_ctx_t *ctx, int signo,
    uint32_t flags, uint64_t sa_mask)
{
    /* Per-thread mask only (S32-R3-5): no process-global merge. */
    uint64_t next = ctx->sig_mask | sa_mask;
    if ((flags & (SPARC32_SA_NODEFER | 0x40000000U)) == 0U &&
        signo >= 1 && signo <= 64) {
        uint64_t bit = 1ULL << (uint64_t)((uint32_t)(signo - 1) % 32U);
        if ((uint32_t)signo <= 32U) {
            bit <<= 32U;
        }
        next |= bit;
    }
    sparc32_l2a_set_blocked_mask(ctx, next);
}

/* C2-3 frame stack field (0x144, 12 B stack_t): the installed alternate
 * stack, SS_ONSTACK while a handler runs on it, SS_DISABLE when none is
 * installed; extra_size words stay zero. */
static bool interp_frame_stack(sparc32_ctx_t *ctx, uint32_t frame)
{
    uint32_t asp = 0U;
    uint32_t asize = 0U;
    uint32_t aflags = SPARC32_SS_DISABLE;
    uint32_t qsp;
    uint32_t qsize;
    int onstack;
    if (sparc32_sigaltstack_state_ctx(ctx, &qsp, &qsize, &onstack) == 0) {
        asp = qsp;
        asize = qsize;
        aflags = (onstack != 0) ? SPARC32_SS_ONSTACK : 0U;
    }
    if (!interp_st_be(ctx, frame + 0x144U, 4U, asp)) {
        return false;
    }
    if (!interp_st_be(ctx, frame + 0x148U, 4U, aflags)) {
        return false;
    }
    if (!interp_st_be(ctx, frame + 0x14cU, 4U, asize)) {
        return false;
    }
    if (!interp_st_be(ctx, frame + 0x150U, 4U, 0U)) {
        return false;
    }
    if (!interp_st_be(ctx, frame + 0x154U, 4U, 0U)) {
        return false;
    }
    return true;
}

bool interp_try_deliver_sync(sparc32_ctx_t *ctx, int signo)
{
    uint32_t handler;
    uint32_t restorer;
    uint32_t flags = 0U;
    uint64_t sa_mask = 0ULL;
    uint64_t old_mask;
    uint32_t addr;
    uint32_t frame;
    uint32_t fpu_va;
    uint32_t code = 1U;
    size_t k;
    int i;
    if (ctx == NULL || (signo != 10 && signo != 11)) {
        return false;
    }
    if (sparc32_signal_get_action(signo, &handler, &restorer, &flags,
            &sa_mask) != 0) {
        return false;
    }
    addr = ctx->fault_addr;
    if (signo == 10) {
        /* BUS_ADRALN: an alignment fault reports code 1 even when the
         * address is mapped; ADRERR (2) is a SIGSEGV-class code. */
        code = 1U;
    } else {
        for (k = 0; k < ctx->region_count; k++) {
            if (addr >= ctx->regions[k].start && addr < ctx->regions[k].end) {
                code = 2U;
                break;
            }
        }
    }
    frame = (interp_delivery_sp(ctx, flags) -
        (SPARC32_RT_SIGFRAME_SIZE + SPARC32_SIGFPU_SIZE)) & ~15U;
    fpu_va = frame + SPARC32_RT_SIGFRAME_SIZE;
    if (!interp_range_ok(ctx, frame,
            SPARC32_RT_SIGFRAME_SIZE + SPARC32_SIGFPU_SIZE, 2U)) {
        return false;
    }
    /* Per-thread mask only (S32-R3-5): no process-global merge. */
    old_mask = ctx->sig_mask;
    for (i = 0; i < 8; i++) {
        uint32_t base = frame + (uint32_t)i * 4U;
        if (!interp_st_be(ctx, base, 4U, ctx->r[SPARC32_L0 + (uint32_t)i])) {
            return false;
        }
        if (!interp_st_be(ctx, base + 32U, 4U,
                           ctx->r[SPARC32_I0 + (uint32_t)i])) {
            return false;
        }
    }
    for (i = 0; i < 6; i++) {
        if (!interp_st_be(ctx, frame + 0x44U + (uint32_t)i * 4U, 4U, 0U)) {
            return false;
        }
    }
    if (!interp_st_be(ctx, frame + 0x5cU, 4U, 0U)) {
        return false;
    }
    if (!interp_st_be(ctx, frame + 0x60U, 4U, (uint32_t)signo)) {
        return false;
    }
    if (!interp_st_be(ctx, frame + 0x64U, 4U, 0U)) {
        return false;
    }
    if (!interp_st_be(ctx, frame + 0x68U, 4U, code)) {
        return false;
    }
    for (i = 0; i < 5; i++) {
        if (!interp_st_be(ctx, frame + 0x6cU + (uint32_t)i * 4U, 4U, 0U)) {
            return false;
        }
    }
    if (!interp_st_be(ctx, frame + 0x40U, 4U, 0U)) {
        return false;
    }
    /* si_addr is _sifields+0 (siginfo+12): the handler reads info+8
     * (si_code) and info+12 (si_addr) per the uClibc/Linux sparc layout. */
    if (!interp_st_be(ctx, frame + 0x6cU, 4U, addr)) {
        return false;
    }
    for (i = 7; i < 32; i++) {
        if (!interp_st_be(ctx, frame + 0x60U + (uint32_t)i * 4U, 4U, 0U)) {
            return false;
        }
    }
    if (!interp_st_be(ctx, frame + 0xe0U, 4U, ctx->psr)) {
        return false;
    }
    if (!interp_st_be(ctx, frame + 0xe4U, 4U, ctx->pc)) {
        return false;
    }
    if (!interp_st_be(ctx, frame + 0xe8U, 4U, ctx->npc)) {
        return false;
    }
    if (!interp_st_be(ctx, frame + 0xecU, 4U, ctx->y)) {
        return false;
    }
    for (i = 0; i < 16; i++) {
        uint32_t v = (i < 8) ? ctx->r[(uint32_t)i]
                             : ctx->r[SPARC32_O0 + (uint32_t)(i - 8)];
        if (!interp_st_be(ctx, frame + 0xf0U + (uint32_t)i * 4U, 4U, v)) {
            return false;
        }
    }
    if (!interp_st_be(ctx, frame + 0x130U, 4U, (uint32_t)(old_mask >> 32U))) {
        return false;
    }
    if (!interp_st_be(ctx, frame + 0x134U, 4U, (uint32_t)old_mask)) {
        return false;
    }
    if (!interp_st_be(ctx, frame + 0x138U, 4U, fpu_va)) {
        return false;
    }
    if (!interp_frame_fpu(ctx, fpu_va)) {
        return false;
    }
    if (!interp_st_be(ctx, frame + 0x13cU, 4U, SPARC32_RESTORER_MOV_G1)) {
        return false;
    }
    if (!interp_st_be(ctx, frame + 0x140U, 4U, SPARC32_RESTORER_TA_10)) {
        return false;
    }
    if (!interp_frame_stack(ctx, frame)) {
        return false;
    }
    interp_apply_delivery_mask(ctx, signo, flags, sa_mask);
    ctx->r[SPARC32_SP] = frame;
    ctx->r[SPARC32_O0] = (uint32_t)signo;
    ctx->r[SPARC32_O1] = frame + 0x60U;
    ctx->r[SPARC32_O2] = frame + 0xe0U;
    ctx->r[SPARC32_O7] = restorer;
    ctx->pc = handler;
    ctx->npc = handler + 4U;
    ctx->sync_sig_delivered = true;
    ctx->sig_last_frame_va = frame;
    ctx->exit_reason = SPARC32_EXIT_NONE;
    return true;
}

/* ---- Phase 4 async delivery (lane L4a). Host handlers only set the
 * pending bit (threads.c); delivery happens at safe points via
 * interp_poll_async (interp step / syscall boundary), consulting the
 * merged per-thread + process-global mask. */

/* Validated one-time snapshot of a caught signal's action (S32-R5-6): taken
 * once before frame construction and shared by the build and the commit, so
 * a concurrent sigaction change cannot mix handler/restorer/flags/sa_mask
 * from two dispositions, and the commit never re-fetches unchecked. */
struct interp_sig_action {
    uint32_t handler;
    uint32_t restorer;
    uint32_t flags;
    uint64_t sa_mask;
};

static bool interp_sig_snapshot(int signo, struct interp_sig_action *out)
{
    if (out == NULL || signo < 1 || signo > 64) {
        return false;
    }
    return sparc32_signal_get_action(signo, &out->handler, &out->restorer,
        &out->flags, &out->sa_mask) == 0;
}

/* Async frame build: same frozen 344 B + 136 B FPU layout as the sync path;
 * only si_code/si_addr differ (SI_USER(0)/0: sent, not faulted). Uses the
 * validated snapshot (S32-R5-6) instead of fetching the action again. */
static bool interp_async_build(sparc32_ctx_t *ctx, int signo,
    const struct interp_sig_action *act, uint32_t *frame)
{
    uint32_t flags;
    uint64_t old_mask;
    uint32_t fr;
    uint32_t fpu_va;
    int i;
    if (ctx == NULL || act == NULL || signo < 1 || signo > 64) {
        return false;
    }
    flags = act->flags;
    fr = (interp_delivery_sp(ctx, flags) -
        (SPARC32_RT_SIGFRAME_SIZE + SPARC32_SIGFPU_SIZE)) & ~15U;
    fpu_va = fr + SPARC32_RT_SIGFRAME_SIZE;
    if (!interp_range_ok(ctx, fr,
            SPARC32_RT_SIGFRAME_SIZE + SPARC32_SIGFPU_SIZE, 2U)) {
        return false;
    }
    /* Per-thread mask only (S32-R3-5): no process-global merge. */
    old_mask = ctx->sig_mask;
    for (i = 0; i < 8; i++) {
        uint32_t base = fr + (uint32_t)i * 4U;
        if (!interp_st_be(ctx, base, 4U, ctx->r[SPARC32_L0 + (uint32_t)i])) {
            return false;
        }
        if (!interp_st_be(ctx, base + 32U, 4U,
                           ctx->r[SPARC32_I0 + (uint32_t)i])) {
            return false;
        }
    }
    for (i = 0; i < 6; i++) {
        if (!interp_st_be(ctx, fr + 0x44U + (uint32_t)i * 4U, 4U, 0U)) {
            return false;
        }
    }
    if (!interp_st_be(ctx, fr + 0x5cU, 4U, 0U)) {
        return false;
    }
    if (!interp_st_be(ctx, fr + 0x60U, 4U, (uint32_t)signo)) {
        return false;
    }
    if (!interp_st_be(ctx, fr + 0x64U, 4U, 0U)) {
        return false;
    }
    if (!interp_st_be(ctx, fr + 0x68U, 4U, 0U)) {
        return false;
    }
    for (i = 0; i < 5; i++) {
        if (!interp_st_be(ctx, fr + 0x6cU + (uint32_t)i * 4U, 4U, 0U)) {
            return false;
        }
    }
    if (!interp_st_be(ctx, fr + 0x40U, 4U, 0U)) {
        return false;
    }
    if (!interp_st_be(ctx, fr + 0x78U, 4U, 0U)) {
        return false;
    }
    for (i = 7; i < 32; i++) {
        if (!interp_st_be(ctx, fr + 0x60U + (uint32_t)i * 4U, 4U, 0U)) {
            return false;
        }
    }
    if (!interp_st_be(ctx, fr + 0xe0U, 4U, ctx->psr)) {
        return false;
    }
    if (!interp_st_be(ctx, fr + 0xe4U, 4U, ctx->pc)) {
        return false;
    }
    if (!interp_st_be(ctx, fr + 0xe8U, 4U, ctx->npc)) {
        return false;
    }
    /* Compat mirror: sigreturn(216) resumes from frame+100/+104 (which
     * alias si_errno/si_code). Async handlers return without patching
     * (qemu style), so the mirror must carry pc/npc at delivery; the
     * sync path keeps oracle-visible si_errno/si_code and relies on
     * the L1d/E05 patch-before-sigreturn pattern instead. */
    if ((flags & SPARC32_SA_SIGINFO) == 0U) {
        if (!interp_st_be(ctx, fr + 100U, 4U, ctx->pc)) {
            return false;
        }
        if (!interp_st_be(ctx, fr + 104U, 4U, ctx->npc)) {
            return false;
        }
    }
    if (!interp_st_be(ctx, fr + 0xecU, 4U, ctx->y)) {
        return false;
    }
    for (i = 0; i < 16; i++) {
        uint32_t v = (i < 8) ? ctx->r[(uint32_t)i]
                             : ctx->r[SPARC32_O0 + (uint32_t)(i - 8)];
        if (!interp_st_be(ctx, fr + 0xf0U + (uint32_t)i * 4U, 4U, v)) {
            return false;
        }
    }
    if (!interp_st_be(ctx, fr + 0x130U, 4U, (uint32_t)(old_mask >> 32U))) {
        return false;
    }
    if (!interp_st_be(ctx, fr + 0x134U, 4U, (uint32_t)old_mask)) {
        return false;
    }
    if (!interp_st_be(ctx, fr + 0x138U, 4U, fpu_va)) {
        return false;
    }
    if (!interp_frame_fpu(ctx, fpu_va)) {
        return false;
    }
    if (!interp_st_be(ctx, fr + 0x13cU, 4U, SPARC32_RESTORER_MOV_G1)) {
        return false;
    }
    if (!interp_st_be(ctx, fr + 0x140U, 4U, SPARC32_RESTORER_TA_10)) {
        return false;
    }
    if (!interp_frame_stack(ctx, fr)) {
        return false;
    }
    *frame = fr;
    return true;
}

/* Commit a built async frame with the validated snapshot (S32-R5-6).
 * from_process (S32-R5-4) records which queue the signal was dequeued from:
 * a thread-directed delivery consumes only the thread pending bit, while a
 * process-directed delivery (already single-winner-claimed by the caller)
 * leaves the thread bit alone so a same-numbered thread signal survives. */
static void interp_async_commit(sparc32_ctx_t *ctx, int signo, uint32_t frame,
    const struct interp_sig_action *act, bool from_process)
{
    uint64_t bit = 1ULL << (uint64_t)((uint32_t)(signo - 1) % 32U);
    if ((uint32_t)signo <= 32U) {
        bit <<= 32U;
    }
    if (!from_process) {
        __atomic_fetch_and(&ctx->pending_signals, ~bit, __ATOMIC_ACQ_REL);
    }
    interp_apply_delivery_mask(ctx, signo, act->flags, act->sa_mask);
    ctx->r[SPARC32_SP] = frame;
    ctx->r[SPARC32_O0] = (uint32_t)signo;
    ctx->r[SPARC32_O1] = frame + 0x60U;
    ctx->r[SPARC32_O2] = frame + 0xe0U;
    ctx->r[SPARC32_O7] = act->restorer;
    ctx->pc = act->handler;
    ctx->npc = act->handler + 4U;
    ctx->sig_last_frame_va = frame;
    ctx->exit_reason = SPARC32_EXIT_NONE;
}

bool interp_try_deliver_async(sparc32_ctx_t *ctx, int signo)
{
    struct interp_sig_action act;
    uint32_t frame;
    if (!interp_sig_snapshot(signo, &act)) {
        return false;
    }
    if (!interp_async_build(ctx, signo, &act, &frame)) {
        return false;
    }
    interp_async_commit(ctx, signo, frame, &act, false);
    return true;
}

bool interp_try_deliver_async_process(sparc32_ctx_t *ctx, int signo)
{
    struct interp_sig_action act;
    uint32_t frame;
    if (!interp_sig_snapshot(signo, &act)) {
        return false;
    }
    if (!interp_async_build(ctx, signo, &act, &frame)) {
        return false;
    }
    interp_async_commit(ctx, signo, frame, &act, true);
    return true;
}

/* In-dispatch delivery for sigsuspend(107) ONLY. The interrupted trap
 * already completed, so the frame records the post-syscall resume point
 * (npc/npc+4) together with %o0=EINTR (4) and PSR.C=1 for sigreturn
 * restore, while live ctx enters the handler directly with %o0=signo,
 * pc=handler, and npc=handler+4 (S32-R2-11). */
static bool interp_deliver_syscall_source(sparc32_ctx_t *ctx, int signo,
    bool carry, bool from_process)
{
    struct interp_sig_action act;
    uint32_t frame;
    uint32_t resume;
    if (ctx == NULL) {
        return false;
    }
    /* Snapshot once up front (S32-R5-6): a failed snapshot means the
     * disposition raced away, so there is nothing to deliver. */
    if (!interp_sig_snapshot(signo, &act)) {
        return false;
    }
    resume = ctx->npc;
    if (!interp_async_build(ctx, signo, &act, &frame)) {
        return false;
    }
    if (!interp_st_be(ctx, frame + 0xe4U, 4U, resume)) {
        return false;
    }
    if (!interp_st_be(ctx, frame + 0xe8U, 4U, resume + 4U)) {
        return false;
    }
    /* Mirror the resume point into the sigreturn compat slots too, but only
     * for old-style handlers (S32-R5-7): under SA_SIGINFO offsets 100/104
     * carry si_errno/si_code and must not be clobbered. */
    if ((act.flags & SPARC32_SA_SIGINFO) == 0U) {
        if (!interp_st_be(ctx, frame + 100U, 4U, resume)) {
            return false;
        }
        if (!interp_st_be(ctx, frame + 104U, 4U, resume + 4U)) {
            return false;
        }
    }
    {
        uint32_t psr = ctx->psr & ~SPARC32_PSR_C;
        if (carry) {
            psr |= SPARC32_PSR_C;
            if (!interp_st_be(ctx, frame + 0xf0U + 8U * 4U, 4U, 4U)) {
                return false;
            }
        }
        if (!interp_st_be(ctx, frame + 0xe0U, 4U, psr)) {
            return false;
        }
    }
    interp_async_commit(ctx, signo, frame, &act, from_process);
    return true;
}

bool interp_deliver_async_for_syscall(sparc32_ctx_t *ctx, int signo,
    bool carry)
{
    return interp_deliver_syscall_source(ctx, signo, carry, false);
}

bool interp_deliver_async_for_syscall_process(sparc32_ctx_t *ctx, int signo,
    bool carry)
{
    return interp_deliver_syscall_source(ctx, signo, carry, true);
}

/* Default-terminate set (S32-R4-5): SPARC signals whose Linux default
 * action terminates the process, i.e. every default-disposition signal
 * except the ignore-default (16/URG, 20/CHLD, 28/WINCH), stop-default
 * (17/STOP, 18/TSTP, 21/TTIN, 22/TTOU), and continue-default (19/CONT)
 * ones. */
static bool interp_dfl_terminates(int sig)
{
    switch (sig) {
    case 16:
    case 17:
    case 18:
    case 19:
    case 20:
    case 21:
    case 22:
    case 28:
        return false;
    default:
        return true;
    }
}

/* Safe-point poll (S32-R3-7): thread-directed bits first, then one
 * process-directed claim per signal. Each queue delivers independently:
 * a thread delivery leaves the process word alone, and a claimed
 * process bit delivers even when another context holds the same thread
 * bit (no cross-queue consume or discard). Same-number signals in the
 * same queue merge, matching kernel semantics. Ignored signals (S32-R3-6)
 * are discarded. A default-disposition signal queued while blocked
 * (S32-R4-5) terminates here at unmask time when its default action is
 * fatal: the host disposition mirrors DFL, so the kernel applies it.
 * Blocked signals stay queued. */
bool interp_poll_async(sparc32_ctx_t *ctx)
{
    uint64_t blocked;
    uint64_t p;
    int s;
    if (ctx == NULL) {
        return false;
    }
    /* Per-thread mask only (S32-R3-5): no process-global merge. */
    blocked = ctx->sig_mask;
    p = __atomic_load_n(&ctx->pending_signals, __ATOMIC_ACQUIRE);
    for (s = 1; s <= 64; s++) {
        uint64_t bit = 1ULL << (uint64_t)((uint32_t)(s - 1) % 32U);
        uint32_t w;
        if ((uint32_t)s <= 32U) {
            bit <<= 32U;
        }
        if ((p & bit) == 0U) {
            continue;
        }
        w = ((uint32_t)s <= 32U) ? (uint32_t)(blocked >> 32U)
                                 : (uint32_t)blocked;
        if (((w >> ((uint32_t)(s - 1) % 32U)) & 1U) != 0U) {
            continue;
        }
        {
            uint32_t handler;
            uint32_t restorer;
            if (sparc32_signal_get(s, &handler, &restorer) != 0) {
                __atomic_fetch_and(&ctx->pending_signals, ~bit,
                    __ATOMIC_ACQ_REL);
                if (sparc32_signal_disposition(s) ==
                        SPARC32_SIG_DISP_DFL &&
                    interp_dfl_terminates(s)) {
                    /* Default termination at delivery time: the
                     * signal was queued while blocked and is now
                     * unblocked with no handler installed. */
                    (void)kill(getpid(),
                        sparc32_sig_to_host(s));
                }
                continue;
            }
        }
        /* Thread-directed delivery leaves the process queue alone
         * (S32-R4-6): no consume of the process-pending bit here. */
        return interp_try_deliver_async(ctx, s);
    }
    for (s = 1; s <= 64; s++) {
        uint32_t w;
        uint32_t handler;
        uint32_t restorer;
        w = ((uint32_t)s <= 32U) ? (uint32_t)(blocked >> 32U)
                                 : (uint32_t)blocked;
        if (((w >> ((uint32_t)(s - 1) % 32U)) & 1U) != 0U) {
            continue;
        }
        /* Single-winner claim: exactly one polling thread delivers
         * each process-directed signal. */
        if (!sparc32_thr_claim_global(s)) {
            continue;
        }
        if (sparc32_signal_get(s, &handler, &restorer) != 0) {
            if (sparc32_signal_disposition(s) ==
                    SPARC32_SIG_DISP_DFL &&
                interp_dfl_terminates(s)) {
                /* Process-directed default termination at unmask
                 * time (S32-R4-5), mirroring the thread queue above. */
                (void)kill(getpid(), sparc32_sig_to_host(s));
            }
            continue;
        }
        /* Process-directed delivery is independent of thread queues
         * (S32-R4-6, S32-R5-4): never discard a claimed bit just because
         * another thread holds the same signal pending, and never clear
         * the thread bit for a process-queued signal. */
        return interp_try_deliver_async_process(ctx, s);
    }
    return false;
}

/* Safe guest instruction-word fetch for fault classification: reads
 * through the [G, G + 4 GiB) window only when [va, va + 4) is covered by
 * a readable tracked region, and never touches exit state (unlike
 * sparc32_fetch_decode, which would clobber the live fault record). */
static bool sparc32_fault_insn_word(const sparc32_ctx_t *ctx, uint32_t va,
    uint32_t *out)
{
    const uint8_t *p;
    uint32_t word;
    bool ok;
    if (out == NULL) {
        return false;
    }
    /* Hold the VM gate across the cover check and the word load (S32-R5-3):
     * a concurrent munmap/mprotect must not retire the code page between
     * validation and dereference. */
    sparc32_vm_access_enter();
    ok = interp_range_ok(ctx, va, 4U, 1U);
    if (ok) {
        p = (const uint8_t *)sparc32_guest_ptr(ctx, va);
        word = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
            ((uint32_t)p[2] << 8) | (uint32_t)p[3];
        *out = word;
    }
    sparc32_vm_access_leave();
    return ok;
}

/* Required access width of a faulting load/store (S32-R5-2, V8 widths):
 * 1 for byte ops, 2 for halfword ops, 4 for word/single-FP/RMW ops, 8 for
 * doubleword ops (integer LDD/STD/LDDA/STDA and FP LDDF/STDF, which both
 * engines fault on (addr & 7) per S32-R5-1). Raw V8 op3 values are used so
 * byte/halfword alternates need no new decoder symbols. */
static uint32_t sparc32_fault_req_align(uint32_t op, uint32_t op3)
{
    if (op != 3U) {
        return 4U;
    }
    switch (op3) {
    case 0x01U: /* LDUB */
    case 0x09U: /* LDSB */
    case 0x05U: /* STB */
    case 0x0DU: /* LDSTUB */
    case 0x11U: /* LDUBA */
    case 0x19U: /* LDSBA */
    case 0x15U: /* STBA */
    case 0x1DU: /* LDSTUBA */
        return 1U;
    case 0x02U: /* LDUH */
    case 0x0AU: /* LDSH */
    case 0x06U: /* STH */
    case 0x12U: /* LDUHA */
    case 0x1AU: /* LDSHA */
    case 0x16U: /* STHA */
        return 2U;
    case 0x03U: /* LDD */
    case 0x07U: /* STD */
    case 0x13U: /* LDDA */
    case 0x17U: /* STDA */
    case 0x23U: /* LDDF */
    case 0x27U: /* STDF */
        return 8U;
    default:
        return 4U;
    }
}

/*
 * Fault -> signal classification (RC-U3-r2 #2, S32-11, S32-R5-1, S32-R5-2).
 * Both engines report alignment violations as EXIT_FAULT with
 * fault_addr = VA. Decode the faulting instruction FIRST (resolving one CTI
 * delay slot, since a faulting delay reports pc at the transfer for
 * JMPL but at the CTI for the other CTI classes) to learn its required
 * access width, then report SIGBUS (10, BUS_ADRALN) only when
 * (va & (width - 1)) != 0; otherwise the fault is a mapping fault and
 * delivers SIGSEGV (11). In particular a 4-byte-aligned, 8-byte-misaligned
 * LDD/STD/LDDA/STDA/LDDF/STDF fault delivers SIGBUS, while an unmapped
 * byte access (LDSB/LDUB/STB) at an odd address or an aligned halfword
 * fault delivers SIGSEGV. Undecodable PCs report SIGSEGV.
 */
int sparc32_classify_fault(const sparc32_ctx_t *ctx)
{
    uint32_t va = ctx->fault_addr;
    uint32_t pc = ctx->pc;
    uint32_t word;
    sparc32_decoded_t d;
    unsigned depth;
    for (depth = 0U; depth < 2U; depth++) {
        uint32_t width;
        if (!sparc32_fault_insn_word(ctx, pc, &word)) {
            return 11;
        }
        sparc32_decode_word(word, &d);
        if (d.cls == (uint32_t)SPARC32_OP_CALL ||
            d.cls == (uint32_t)SPARC32_OP_BRANCH ||
            d.cls == (uint32_t)SPARC32_OP_FBRANCH ||
            d.cls == (uint32_t)SPARC32_OP_JMPL ||
            d.cls == (uint32_t)SPARC32_OP_TRAP) {
            pc += 4U;
            continue;
        }
        width = sparc32_fault_req_align(d.op, d.op3);
        return ((va & (width - 1U)) != 0U) ? 10 : 11;
    }
    return 11;
}
