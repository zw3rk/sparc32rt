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

#include "interp/interp_priv.h"
#include "os/sigframe_sparc32rt.h"
#include "os/syscalls_min.h"

#include <stddef.h>
#include <stdint.h>

/* Synchronous fault delivery (RC1 subset of Phase-4 signals). Builds the
 * frozen kernel-order rt_signal_frame32 (344 B, 16-aligned) on the guest
 * stack and redirects to an installed old-style handler:
 *   %sp = frame, %o0 = signo, %o1 = &siginfo, %o2 = &pt_regs,
 *   %o7 = restorer, pc = handler, npc = handler + 4.
 * si_addr = ctx->fault_addr; si_code = SEGV_ACCERR(2) when the fault
 * address lies inside a mapped region, else SEGV_MAPERR(1). The test
 * handler patches pc/npc at frame+100/+104 (non-RT signal_frame regs
 * slots aliasing the RT info words on this kernel/qemu layout) and
 * resumes via sigreturn(216), which reads exactly those slots — the
 * kernel-layout regs at +0xE4/+0xE8 are saved faithfully but ignored by
 * that path, matching qemu-sparc do_sigreturn. Returns false when no
 * handler is installed or the frame does not fit (caller keeps EXIT_FAULT).
 * Misaligned DATA accesses never reach here (emulated byte-wise, E06). */
bool interp_try_deliver_sync(sparc32_ctx_t *ctx, int signo)
{
    uint32_t handler;
    uint32_t restorer;
    uint32_t addr;
    uint32_t frame;
    uint32_t code = 1U;
    size_t k;
    int i;
    if (ctx == NULL || (signo != 10 && signo != 11)) {
        return false;
    }
    if (sparc32_signal_get(signo, &handler, &restorer) != 0) {
        return false;
    }
    addr = ctx->fault_addr;
    for (k = 0; k < ctx->region_count; k++) {
        if (addr >= ctx->regions[k].start && addr < ctx->regions[k].end) {
            code = 2U;
            break;
        }
    }
    frame = (ctx->r[SPARC32_SP] - SPARC32_RT_SIGFRAME_SIZE) & ~15U;
    if (!interp_range_ok(ctx, frame, SPARC32_RT_SIGFRAME_SIZE, 2U)) {
        return false;
    }
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
    if (!interp_st_be(ctx, frame + 0x78U, 4U, addr)) {
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
                             : ctx->r[SPARC32_I0 + (uint32_t)(i - 8)];
        if (!interp_st_be(ctx, frame + 0xf0U + (uint32_t)i * 4U, 4U, v)) {
            return false;
        }
    }
    if (!interp_st_be(ctx, frame + 0x130U, 4U, 0U)) {
        return false;
    }
    if (!interp_st_be(ctx, frame + 0x134U, 4U, 0U)) {
        return false;
    }
    if (!interp_st_be(ctx, frame + 0x138U, 4U, 0U)) {
        return false;
    }
    if (!interp_st_be(ctx, frame + 0x13cU, 4U, SPARC32_RESTORER_MOV_G1)) {
        return false;
    }
    if (!interp_st_be(ctx, frame + 0x140U, 4U, SPARC32_RESTORER_TA_10)) {
        return false;
    }
    for (i = 0; i < 5; i++) {
        if (!interp_st_be(ctx, frame + 0x144U + (uint32_t)i * 4U, 4U, 0U)) {
            return false;
        }
    }
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

/* ---- Phase 4 async delivery (lane L4a). The sync function above is
 * untouched (E05 byte-identical); this path duplicates its frame
 * construction with async si_code/si_addr. Host handlers only set the
 * pending bit (threads.c); delivery happens at safe points via
 * interp_poll_async (interp step / syscall boundary), consulting the
 * merged per-thread + process-global mask. */

/* Process-global mask owned by src/os/syscalls.c (non-static there). */
extern uint64_t sparc32_l2a_blocked_mask(void);

/* Async frame build: same frozen 344 B layout as the sync path; only
 * si_code/si_addr differ (SI_USER(0)/0: sent, not faulted). */
static bool interp_async_build(sparc32_ctx_t *ctx, int signo, uint32_t *frame)
{
    uint32_t handler;
    uint32_t restorer;
    uint32_t fr;
    int i;
    if (ctx == NULL || signo < 1 || signo > 31) {
        return false;
    }
    if (sparc32_signal_get(signo, &handler, &restorer) != 0) {
        return false;
    }
    fr = (ctx->r[SPARC32_SP] - SPARC32_RT_SIGFRAME_SIZE) & ~15U;
    if (!interp_range_ok(ctx, fr, SPARC32_RT_SIGFRAME_SIZE, 2U)) {
        return false;
    }
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
    if (!interp_st_be(ctx, fr + 100U, 4U, ctx->pc)) {
        return false;
    }
    if (!interp_st_be(ctx, fr + 104U, 4U, ctx->npc)) {
        return false;
    }
    if (!interp_st_be(ctx, fr + 0xecU, 4U, ctx->y)) {
        return false;
    }
    for (i = 0; i < 16; i++) {
        uint32_t v = (i < 8) ? ctx->r[(uint32_t)i]
                             : ctx->r[SPARC32_I0 + (uint32_t)(i - 8)];
        if (!interp_st_be(ctx, fr + 0xf0U + (uint32_t)i * 4U, 4U, v)) {
            return false;
        }
    }
    if (!interp_st_be(ctx, fr + 0x130U, 4U, 0U)) {
        return false;
    }
    if (!interp_st_be(ctx, fr + 0x134U, 4U, 0U)) {
        return false;
    }
    if (!interp_st_be(ctx, fr + 0x138U, 4U, 0U)) {
        return false;
    }
    if (!interp_st_be(ctx, fr + 0x13cU, 4U, SPARC32_RESTORER_MOV_G1)) {
        return false;
    }
    if (!interp_st_be(ctx, fr + 0x140U, 4U, SPARC32_RESTORER_TA_10)) {
        return false;
    }
    for (i = 0; i < 5; i++) {
        if (!interp_st_be(ctx, fr + 0x144U + (uint32_t)i * 4U, 4U, 0U)) {
            return false;
        }
    }
    *frame = fr;
    return true;
}

static void interp_async_commit(sparc32_ctx_t *ctx, int signo, uint32_t frame)
{
    uint32_t handler;
    uint32_t restorer;
    uint64_t bit = 1ULL << (uint64_t)((uint32_t)(signo - 1) % 32U);
    if ((uint32_t)signo <= 32U) {
        bit <<= 32U;
    }
    ctx->pending_signals &= ~bit;
    (void)sparc32_signal_get(signo, &handler, &restorer);
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

/* In-dispatch delivery for sigsuspend(107) ONLY (kill and friends use
 * late delivery: the tail would clobber handler %o0 with the syscall
 * return). The interrupted trap already completed, so the frame records
 * the post-syscall resume point (npc/npc+4, what the tail will commit),
 * not the trap — the handler sigreturns past the syscall, matching
 * Linux. The dispatch tail commits pc = npc; npc += 4, so pre-point npc
 * at the handler (pc one slot behind is dead state). The tail then
 * overwrites %o0 with EINTR and sets C — exactly the post-handler
 * state the test asserts — while the frame psr carries C for the
 * sigreturn restore. */
bool interp_deliver_async_for_syscall(sparc32_ctx_t *ctx, int signo,
    bool carry)
{
    uint32_t frame;
    uint32_t handler;
    uint32_t restorer;
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
        }
        if (!interp_st_be(ctx, frame + 0xe0U, 4U, psr)) {
            return false;
        }
    }
    ctx->pending_signals &= ~bit;
    (void)sparc32_signal_get(signo, &handler, &restorer);
    ctx->r[SPARC32_SP] = frame;
    ctx->r[SPARC32_O0] = (uint32_t)signo;
    ctx->r[SPARC32_O1] = frame + 0x60U;
    ctx->r[SPARC32_O2] = frame + 0xe0U;
    ctx->r[SPARC32_O7] = restorer;
    ctx->npc = handler;
    ctx->pc = handler - 4U;
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
    p = ctx->pending_signals;
    for (s = 1; s <= 31; s++) {
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
                ctx->pending_signals &= ~bit;
                continue;
            }
        }
        return interp_try_deliver_async(ctx, s);
    }
    return false;
}
