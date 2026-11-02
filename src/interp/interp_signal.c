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

#include <stddef.h>
#include <stdint.h>

/* Process-global mask owned by src/os/syscalls_time.c. */
extern uint64_t sparc32_l2a_blocked_mask(void);

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
        if (sparc32_sigaltstack_state(&asp, &asize, &onstack) == 0 &&
            !onstack) {
            sparc32_sigaltstack_set_onstack(1);
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
    uint64_t cur = ctx->sig_mask | sparc32_l2a_blocked_mask();
    uint64_t next = cur | sa_mask;
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
    if (sparc32_sigaltstack_state(&qsp, &qsize, &onstack) == 0) {
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
    old_mask = ctx->sig_mask | sparc32_l2a_blocked_mask();
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

/* Async frame build: same frozen 344 B + 136 B FPU layout as the sync path;
 * only si_code/si_addr differ (SI_USER(0)/0: sent, not faulted). */
static bool interp_async_build(sparc32_ctx_t *ctx, int signo, uint32_t *frame)
{
    uint32_t handler;
    uint32_t restorer;
    uint32_t flags = 0U;
    uint64_t old_mask;
    uint32_t fr;
    uint32_t fpu_va;
    int i;
    if (ctx == NULL || signo < 1 || signo > 64) {
        return false;
    }
    if (sparc32_signal_get_full(signo, &handler, &restorer, &flags) != 0) {
        return false;
    }
    fr = (interp_delivery_sp(ctx, flags) -
        (SPARC32_RT_SIGFRAME_SIZE + SPARC32_SIGFPU_SIZE)) & ~15U;
    fpu_va = fr + SPARC32_RT_SIGFRAME_SIZE;
    if (!interp_range_ok(ctx, fr,
            SPARC32_RT_SIGFRAME_SIZE + SPARC32_SIGFPU_SIZE, 2U)) {
        return false;
    }
    old_mask = ctx->sig_mask | sparc32_l2a_blocked_mask();
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

static void interp_async_commit(sparc32_ctx_t *ctx, int signo, uint32_t frame)
{
    uint32_t handler;
    uint32_t restorer;
    uint32_t flags = 0U;
    uint64_t sa_mask = 0ULL;
    uint64_t bit = 1ULL << (uint64_t)((uint32_t)(signo - 1) % 32U);
    if ((uint32_t)signo <= 32U) {
        bit <<= 32U;
    }
    __atomic_fetch_and(&ctx->pending_signals, ~bit, __ATOMIC_ACQ_REL);
    (void)sparc32_signal_get_action(signo, &handler, &restorer, &flags,
        &sa_mask);
    interp_apply_delivery_mask(ctx, signo, flags, sa_mask);
    ctx->r[SPARC32_SP] = frame;
    ctx->r[SPARC32_O0] = (uint32_t)signo;
    ctx->r[SPARC32_O1] = frame + 0x60U;
    ctx->r[SPARC32_O2] = frame + 0xe0U;
    ctx->r[SPARC32_O7] = restorer;
    ctx->pc = handler;
    ctx->npc = handler + 4U;
    ctx->sig_last_frame_va = frame;
    ctx->exit_reason = SPARC32_EXIT_NONE;
}

bool interp_try_deliver_async(sparc32_ctx_t *ctx, int signo)
{
    uint32_t frame;
    if (!interp_async_build(ctx, signo, &frame)) {
        return false;
    }
    interp_async_commit(ctx, signo, frame);
    return true;
}

/* In-dispatch delivery for sigsuspend(107) ONLY. The interrupted trap
 * already completed, so the frame records the post-syscall resume point
 * (npc/npc+4) together with %o0=EINTR (4) and PSR.C=1 for sigreturn
 * restore, while live ctx enters the handler directly with %o0=signo,
 * pc=handler, and npc=handler+4 (S32-R2-11). */
bool interp_deliver_async_for_syscall(sparc32_ctx_t *ctx, int signo,
    bool carry)
{
    uint32_t frame;
    uint32_t handler;
    uint32_t restorer;
    uint32_t flags = 0U;
    uint64_t sa_mask = 0ULL;
    uint32_t resume;
    uint64_t bit = 1ULL << (uint64_t)((uint32_t)(signo - 1) % 32U);
    if ((uint32_t)signo <= 32U) {
        bit <<= 32U;
    }
    resume = ctx->npc;
    if (!interp_async_build(ctx, signo, &frame)) {
        return false;
    }
    if (!interp_st_be(ctx, frame + 0xe4U, 4U, resume)) {
        return false;
    }
    if (!interp_st_be(ctx, frame + 0xe8U, 4U, resume + 4U)) {
        return false;
    }
    /* Mirror the resume point into the sigreturn compat slots too. */
    if (!interp_st_be(ctx, frame + 100U, 4U, resume)) {
        return false;
    }
    if (!interp_st_be(ctx, frame + 104U, 4U, resume + 4U)) {
        return false;
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
    __atomic_fetch_and(&ctx->pending_signals, ~bit, __ATOMIC_ACQ_REL);
    (void)sparc32_signal_get_action(signo, &handler, &restorer, &flags,
        &sa_mask);
    interp_apply_delivery_mask(ctx, signo, flags, sa_mask);
    ctx->r[SPARC32_SP] = frame;
    ctx->r[SPARC32_O0] = (uint32_t)signo;
    ctx->r[SPARC32_O1] = frame + 0x60U;
    ctx->r[SPARC32_O2] = frame + 0xe0U;
    ctx->r[SPARC32_O7] = restorer;
    ctx->pc = handler;
    ctx->npc = handler + 4U;
    ctx->sig_last_frame_va = frame;
    ctx->exit_reason = SPARC32_EXIT_NONE;
    return true;
}

/* Safe-point poll: deliver the lowest unblocked pending signal with an
 * installed handler. Sticky bits for handler-less signals are cleared
 * (default dispositions were already applied on the host). */
bool interp_poll_async(sparc32_ctx_t *ctx)
{
    uint64_t blocked;
    uint64_t p;
    int s;
    if (ctx == NULL) {
        return false;
    }
    blocked = ctx->sig_mask | sparc32_l2a_blocked_mask();
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
                continue;
            }
        }
        return interp_try_deliver_async(ctx, s);
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
    if (out == NULL || !interp_range_ok(ctx, va, 4U, 1U)) {
        return false;
    }
    p = (const uint8_t *)sparc32_guest_ptr(ctx, va);
    *out = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    return true;
}

/*
 * Fault -> signal classification (RC-U3-r2 #2, S32-11). Both engines report
 * alignment violations as EXIT_FAULT with fault_addr = VA, but
 * (fault_addr & 3) alone cannot see a 4-byte-aligned, 8-byte-misaligned
 * LDD/STD: that fault MUST deliver SIGBUS (10, BUS_ADRALN), never
 * SIGSEGV (11). Decode the faulting instruction (resolving one CTI
 * delay slot, since a faulting delay reports pc at the transfer for
 * JMPL but at the CTI for the other CTI classes) and report SIGBUS
 * only when a doubleword access (LDD/STD/LDDA/STDA) faulted on
 * (va & 7). FP LDDF/STDF are excluded on purpose: the interpreter
 * faults those only as 4-byte halves, so their 4-mod-8 faults are
 * mapping faults (SIGSEGV). Undecodable PCs keep the old heuristic.
 */
int sparc32_classify_fault(const sparc32_ctx_t *ctx)
{
    uint32_t va = ctx->fault_addr;
    uint32_t pc = ctx->pc;
    uint32_t word;
    sparc32_decoded_t d;
    unsigned depth;
    if ((va & 3U) != 0U) {
        return 10;
    }
    if ((va & 7U) == 0U) {
        return 11;
    }
    for (depth = 0U; depth < 2U; depth++) {
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
        if (d.op == 3U &&
            (d.op3 == SPARC32_OP3_LDD || d.op3 == SPARC32_OP3_STD ||
             d.op3 == SPARC32_OP3_LDDA || d.op3 == SPARC32_OP3_STDA)) {
            return 10;
        }
        return 11;
    }
    return 11;
}
