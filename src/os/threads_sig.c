/*
 * src/os/threads_sig.c — Signal syscalls: pending-signal, sigsuspend,
 * itimer, and the per-thread blocked-mask helpers
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from src/os/threads.c for the 900-line file discipline (S32-18).
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "sparc32rt.h"
#include "interp/interp_priv.h"
#include "os/l2a_access.h"
#include "os/syscalls_min.h"
#include "os/threads.h"

/* Process-queue variant of the sigsuspend delivery helper (defined in
 * src/interp/interp_signal.c alongside interp_deliver_async_for_syscall):
 * declared here so the frozen threads.h need not change. */
bool interp_deliver_async_for_syscall_process(sparc32_ctx_t *ctx, int signo,
    bool carry);

/* rt_sigpending(104): kernel-layout BE quad (signals 1..32 in the high
 * word). sigsetsize must be 8 (E05 rule). Reports the thread bits plus
 * the unclaimed process queue (S32-R3-7): anything neither delivered
 * nor discarded yet. */
long sparc32_thr_rt_sigpending(sparc32_ctx_t *ctx, uint32_t set_va,
    uint32_t sigsetsize)
{
    uint8_t out[8];
    uint64_t p;
    sparc32_threads_ensure_init(ctx);
    if (ctx == NULL) {
        return -EFAULT;
    }
    if (sigsetsize != 8U) {
        return -EINVAL;
    }
    p = __atomic_load_n(&ctx->pending_signals, __ATOMIC_ACQUIRE) |
        sparc32_thr_process_pending();
    put_be64(out, p);
    if (set_va != 0U) {
        return (long)l2a_store(ctx, set_va, out, sizeof(out));
    }
    return 0;
}

/* Default-action sets for DFL disposition routing in rt_sigsuspend
 * (S32-R5-5): fatal-default signals terminate, ignore-default signals
 * (URG/CHLD/WINCH/CONT) are discarded, and stop-default signals stay
 * queued for normal polling. Mirrors interp_dfl_terminates. */
static bool thr_sig_dfl_terminates(int sig)
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

static bool thr_sig_dfl_ignores(int sig)
{
    switch (sig) {
    case 16:
    case 19:
    case 20:
    case 28:
        return true;
    default:
        return false;
    }
}

/* rt_sigsuspend(107): replace mask, sleep for an unblocked pending
 * signal, deliver synchronously, fail EINTR; both masks restored first. */
long sparc32_thr_rt_sigsuspend(sparc32_ctx_t *ctx, uint32_t set_va,
    uint32_t sigsetsize)
{
    uint64_t n;
    uint64_t old;
    uint8_t buf[8];
    sigset_t block_set;
    sigset_t old_host_set;
    sigset_t wait_host_set;
    int s;
    sparc32_threads_ensure_init(ctx);
    if (ctx == NULL) {
        return -EFAULT;
    }
    if (sigsetsize != 8U) {
        return -EINVAL;
    }
    if (set_va == 0U || l2a_load(ctx, set_va, buf, sizeof(buf)) != 0) {
        return -EFAULT;
    }
    n = ((uint64_t)get_be32(buf) << 32U) | (uint64_t)get_be32(buf + 4);
    /* Per-thread mask only (S32-R3-5): no process-global merge. */
    old = ctx->sig_mask;
    sparc32_l2a_set_blocked_mask(ctx, n);
    sigfillset(&block_set);
    sigdelset(&block_set, SIGBUS);
    sigdelset(&block_set, SIGSEGV);
    sigdelset(&block_set, SIGILL);
    sigdelset(&block_set, SIGFPE);
    sigemptyset(&wait_host_set);
    (void)sigprocmask(SIG_SETMASK, &block_set, &old_host_set);
    for (;;) {
        /* Phase 1: own thread bits (S32-R3-7). Thread-directed delivery
         * consumes only the thread bit (S32-R5-4): the process word is
         * never claimed or cleared here. */
        for (s = 1; s <= 64; s++) {
            uint64_t bit = 1ULL << (uint64_t)((uint32_t)(s - 1) % 32U);
            uint32_t handler;
            uint32_t restorer;
            if ((uint32_t)s <= 32U) {
                bit <<= 32U;
            }
            if ((__atomic_load_n(&ctx->pending_signals,
                    __ATOMIC_ACQUIRE) & bit) == 0ULL) {
                continue;
            }
            if (sparc32_thr_sig_blocked(ctx, s) != 0) {
                continue;
            }
            if (sparc32_signal_get(s, &handler, &restorer) != 0) {
                /* No handler installed (S32-R5-5): only SIG_IGN and
                 * ignore-default DFL are discarded. Fatal-default DFL
                 * terminates like the kernel would; stop-default DFL
                 * stays queued for normal polling. */
                if (sparc32_signal_disposition(s) ==
                        SPARC32_SIG_DISP_DFL &&
                    thr_sig_dfl_terminates(s)) {
                    sparc32_l2a_set_blocked_mask(ctx, old);
                    (void)sigprocmask(SIG_SETMASK, &old_host_set, NULL);
                    (void)kill(getpid(), sparc32_sig_to_host(s));
                    return -EINTR;
                }
                if (sparc32_signal_disposition(s) ==
                        SPARC32_SIG_DISP_DFL &&
                    !thr_sig_dfl_ignores(s)) {
                    sparc32_l2a_set_blocked_mask(ctx, old);
                    (void)sigprocmask(SIG_SETMASK, &old_host_set, NULL);
                    return -EINTR;
                }
                __atomic_fetch_and(&ctx->pending_signals, ~bit,
                    __ATOMIC_ACQ_REL);
                continue;
            }
            sparc32_l2a_set_blocked_mask(ctx, old);
            (void)sigprocmask(SIG_SETMASK, &old_host_set, NULL);
            if (!interp_deliver_async_for_syscall(ctx, s, true)) {
                __atomic_fetch_and(&ctx->pending_signals, ~bit,
                    __ATOMIC_ACQ_REL);
                return -EINTR;
            }
            return 0;
        }
        /* Phase 2: single-winner process claims (S32-R3-7), matching
         * interp_poll_async (S32-R5-4): a process-pending signal is not
         * skipped just because another thread holds a blocked
         * thread-directed pending bit of the same number. Unhandled
         * signals route like Phase 1 (S32-R5-5) instead of being
         * silently dropped. */
        for (s = 1; s <= 64; s++) {
            uint32_t handler;
            uint32_t restorer;
            if (sparc32_thr_sig_blocked(ctx, s) != 0) {
                continue;
            }
            if (sparc32_signal_get(s, &handler, &restorer) != 0) {
                if (sparc32_signal_disposition(s) ==
                        SPARC32_SIG_DISP_DFL &&
                    thr_sig_dfl_terminates(s)) {
                    if (!sparc32_thr_claim_global(s)) {
                        continue;
                    }
                    sparc32_l2a_set_blocked_mask(ctx, old);
                    (void)sigprocmask(SIG_SETMASK, &old_host_set, NULL);
                    (void)kill(getpid(), sparc32_sig_to_host(s));
                    return -EINTR;
                }
                if (sparc32_signal_disposition(s) ==
                        SPARC32_SIG_DISP_DFL &&
                    !thr_sig_dfl_ignores(s)) {
                    sparc32_l2a_set_blocked_mask(ctx, old);
                    (void)sigprocmask(SIG_SETMASK, &old_host_set, NULL);
                    return -EINTR;
                }
                if (!sparc32_thr_claim_global(s)) {
                    continue;
                }
                continue;
            }
            if (!sparc32_thr_claim_global(s)) {
                continue;
            }
            sparc32_l2a_set_blocked_mask(ctx, old);
            (void)sigprocmask(SIG_SETMASK, &old_host_set, NULL);
            if (!interp_deliver_async_for_syscall_process(ctx, s, true)) {
                return -EINTR;
            }
            return 0;
        }
        (void)sigsuspend(&wait_host_set);
    }
}

/* setitimer(83): ITIMER_REAL one-shot/periodic via the host timer.
 * Guest itimerval is 16 bytes big-endian (interval, value; each a
 * 4-byte sec + 4-byte usec pair). VIRTUAL/PROF timers return -EINVAL
 * (RC4 scope: the oracle test uses REAL only). SIGALRM lands through
 * the installed host handler and the pending-bit safe-point path. */
long sparc32_thr_setitimer(sparc32_ctx_t *ctx, uint32_t which,
    uint32_t new_va, uint32_t old_va)
{
    uint8_t np[16];
    uint8_t op[16];
    struct itimerval ntv;
    struct itimerval otv;
    struct itimerval *oldp;
    if (which != 0U) {
        return -EINVAL;
    }
    if (new_va == 0U || l2a_load(ctx, new_va, np, sizeof(np)) != 0) {
        return -EFAULT;
    }
    if (old_va != 0U && l2a_range_ok_prot(old_va, 16U, 2U) != 0) {
        return -EFAULT;
    }
    ntv.it_interval.tv_sec = (time_t)(int32_t)get_be32(np);
    ntv.it_interval.tv_usec = (suseconds_t)(int32_t)get_be32(np + 4);
    ntv.it_value.tv_sec = (time_t)(int32_t)get_be32(np + 8);
    ntv.it_value.tv_usec = (suseconds_t)(int32_t)get_be32(np + 12);
    if (ntv.it_interval.tv_sec < 0 || ntv.it_interval.tv_usec < 0 ||
        ntv.it_interval.tv_usec >= 1000000 ||
        ntv.it_value.tv_sec < 0 || ntv.it_value.tv_usec < 0 ||
        ntv.it_value.tv_usec >= 1000000) {
        return -EINVAL;
    }
    oldp = (old_va != 0U) ? &otv : NULL;
    if (setitimer(ITIMER_REAL, &ntv, oldp) != 0) {
        return -(long)errno;
    }
    if (old_va != 0U) {
        put_be32(op, (uint32_t)otv.it_interval.tv_sec);
        put_be32(op + 4, (uint32_t)otv.it_interval.tv_usec);
        put_be32(op + 8, (uint32_t)otv.it_value.tv_sec);
        put_be32(op + 12, (uint32_t)otv.it_value.tv_usec);
        return (long)l2a_store(ctx, old_va, op, sizeof(op));
    }
    return 0;
}

/* Per-thread blocked-mask helpers over ctx->sig_mask (kernel layout;
 * moved from threads.c for the 900-line discipline). */
uint64_t sparc32_thr_mask_sanitize(uint64_t mask)
{
    /* SIGKILL (9) and SIGSTOP (17) are unblockable SPARC signals. */
    mask &= ~sparc32_thr_sigbit(9);
    mask &= ~sparc32_thr_sigbit(17);
    return mask;
}

int sparc32_thr_sig_blocked(const sparc32_ctx_t *ctx, int sig)
{
    uint64_t m;
    uint32_t w;
    if (ctx == NULL || sig < 1 || sig > 64) {
        return 0;
    }
    m = ctx->sig_mask;
    w = ((uint32_t)sig <= 32U) ? (uint32_t)(m >> 32U) : (uint32_t)m;
    return (int)((w >> ((uint32_t)(sig - 1) % 32U)) & 1U);
}

void sparc32_thr_sig_set(sparc32_ctx_t *ctx, int sig, bool blocked)
{
    uint64_t bit;
    if (ctx == NULL || sig < 1 || sig > 64) {
        return;
    }
    bit = sparc32_thr_sigbit(sig);
    if (blocked) {
        ctx->sig_mask |= bit;
    } else {
        ctx->sig_mask &= ~bit;
    }
}
