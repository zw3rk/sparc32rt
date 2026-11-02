/*
 * src/os/threads_sig.c — Pending-signal, sigsuspend, and itimer syscalls
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

#include "sparc32rt.h"
#include "interp/interp_priv.h"
#include "os/l2a_access.h"
#include "os/syscalls_min.h"
#include "os/threads.h"

extern uint64_t sparc32_l2a_blocked_mask(void);

/* rt_sigpending(104): kernel-layout BE quad (signals 1..32 in the high
 * word). sigsetsize must be 8 (E05 rule). */
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
    p = __atomic_load_n(&ctx->pending_signals, __ATOMIC_ACQUIRE);
    put_be64(out, p);
    if (set_va != 0U) {
        return (long)l2a_store(ctx, set_va, out, sizeof(out));
    }
    return 0;
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
    old = ctx->sig_mask | sparc32_l2a_blocked_mask();
    sparc32_l2a_set_blocked_mask(ctx, n);
    sigfillset(&block_set);
    sigdelset(&block_set, SIGBUS);
    sigdelset(&block_set, SIGSEGV);
    sigdelset(&block_set, SIGILL);
    sigdelset(&block_set, SIGFPE);
    sigemptyset(&wait_host_set);
    (void)sigprocmask(SIG_SETMASK, &block_set, &old_host_set);
    for (;;) {
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
