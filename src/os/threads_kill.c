/*
 * src/os/threads_kill.c — kill/tkill/tgkill + TID helpers (Phase 4, L4a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from src/os/threads.c for the 900-line file discipline. Shares
 * the live registry in threads.c through thr_live_enter/leave/
 * find_locked (see threads.h): a pointer from the lookup is valid only
 * while the lock is held, so the wakeup TID is copied under the lock
 * and nothing dereferences the target after unlock (S32-R3-1
 * follow-up #2). Default-disposition signals to a live guest thread go
 * through the real host call so the kernel applies the default action
 * (S32-R3-7 follow-up #1: raise(SIGTERM) and abort() work again).
 */

/* sched_yield/pthread + syscall() under strict -std=c11 with musl. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "sparc32rt.h"
#include "os/syscalls_min.h"
#include "os/threads.h"

/* Self-directed process signal (S32-R3-7): the signal is
 * process-directed, so it joins the process queue for single-winner
 * claiming at the next safe point (late delivery: the dispatch tail
 * already committed this syscall's return). Ignored signals are
 * discarded; default dispositions were already applied by the host
 * (kill() above ran with the mirrored host disposition). */
static long thr_kill_self(sparc32_ctx_t *ctx, int sig)
{
    if (sparc32_signal_disposition(sig) == SPARC32_SIG_DISP_IGN) {
        sparc32_thr_discard_signal(ctx, sig);
        return 0;
    }
    sparc32_thr_note_signal(sig);
    return 0;
}

static bool thr_is_self(uint32_t pid)
{
    pid_t self = getpid();
    return pid == 0U || pid == (uint32_t)self || pid == 0xFFFFFFFFU;
}

long sparc32_thr_kill(sparc32_ctx_t *ctx, uint32_t pid, uint32_t sig)
{
    sparc32_threads_ensure_init(ctx);
    if (ctx == NULL) {
        return -EFAULT;
    }
    if (sig > 64U) {
        return -EINVAL;
    }
    if (sig != 0U && thr_is_self(pid)) {
        int s = (int)sig;
        if (s != 9 && s != 17 &&
            sparc32_signal_disposition(s) == SPARC32_SIG_DISP_DFL &&
            sparc32_thr_sig_blocked(ctx, s) != 0) {
            /* Blocked + default (S32-R4-5): queue only and skip the
             * host call, so kernel SIG_DFL cannot terminate while
             * the guest holds the signal blocked. The safe-point
             * poll applies default termination at unmask time. */
            return thr_kill_self(ctx, s);
        }
    }
    if (sig != 0U &&
        kill((pid_t)(int32_t)pid,
            sparc32_sig_to_host((int)sig)) != 0) {
        return -(long)errno;
    }
    if (sig != 0U && thr_is_self(pid)) {
        return thr_kill_self(ctx, (int)sig);
    }
    return 0;
}

/* Thread-directed delivery (S32-R3-7): the bit lands on the target
 * context only. A host wakeup follows (same signal number) so a
 * target parked in sigsuspend observes it; the safe-point poll
 * dedups the wakeup's process bit against the thread bit and still
 * delivers exactly once. Ignored signals never wake; default
 * dispositions go through the real host call so the kernel applies
 * the default action (fatal signals terminate; raise/abort work). */
static long thr_host_tgkill(uint32_t tgid, int host_tid, uint32_t sig)
{
    /* Host numbering (S32-R4-4): the caller passes SPARC numbers. */
    int hsig = sparc32_sig_to_host((int)sig);
#if defined(__linux__) && defined(SYS_tgkill)
    long rc = syscall(SYS_tgkill, (pid_t)(int32_t)tgid, (pid_t)host_tid,
        hsig);
    return (rc == 0) ? 0 : -(long)errno;
#elif defined(__linux__) && defined(SYS_tkill)
    long rc;
    (void)tgid;
    rc = syscall(SYS_tkill, (pid_t)host_tid, hsig);
    return (rc == 0) ? 0 : -(long)errno;
#else /* #ifndef __linux__: pthread delivery (S32-R4-8) */
    pthread_t pt;
    long rc;
    (void)tgid;
    if (thr_live_pt_for_tid(host_tid, &pt)) {
        int prc = pthread_kill(pt, hsig);
        return (prc == 0) ? 0 : -(long)prc;
    }
    rc = kill((pid_t)host_tid, hsig);
    return (rc == 0) ? 0 : -(long)errno;
#endif
}

static long thr_kill_tid(sparc32_ctx_t *ctx, uint32_t tgid,
    uint32_t tid, uint32_t sig)
{
    long rc = 0;
    bool found = false;
    bool is_self_target = false;
    bool dfl_blocked_queued = false;
    int target_host_tid = 0;
    int disp = SPARC32_SIG_DISP_DFL;
    int self_tid = 0;
    sparc32_ctx_t *target = NULL;
    if (sig > 64U) {
        return -EINVAL;
    }
    if ((int32_t)tgid <= 0) {
        return -EINVAL;
    }
    self_tid = thr_gettid();
    if ((int32_t)tgid != (int32_t)getpid()) {
        /* Foreign thread group (S32-R4-7): never queue locally. A local
         * TID under a mismatched TGID is ESRCH; otherwise delegate to
         * the host. */
        bool local = false;
        thr_live_enter();
        local = thr_live_find_locked((int32_t)tid, self_tid, ctx) != NULL;
        thr_live_leave();
        if (local) {
            return -ESRCH;
        }
        if (sig == 0U) {
#if defined(__linux__) && defined(SYS_tgkill)
            rc = syscall(SYS_tgkill, (pid_t)(int32_t)tgid,
                (pid_t)(int32_t)tid, 0);
            return (rc == 0) ? 0 : -(long)errno;
#else
            return -ESRCH;
#endif
        }
        return thr_host_tgkill(tgid, (int32_t)tid, sig);
    }
    if (sig == 0U) {
        /* Existence check only. */
        thr_live_enter();
        found = thr_live_find_locked((int32_t)tid, self_tid, ctx) != NULL;
        thr_live_leave();
        if (found) {
            return 0;
        }
#if defined(__linux__) && defined(SYS_tgkill)
        rc = syscall(SYS_tgkill, (pid_t)(int32_t)tgid, (pid_t)(int32_t)tid,
            0);
        return (rc == 0) ? 0 : -(long)errno;
#else
        return -ESRCH;
#endif
    }
    thr_live_enter();
    target = thr_live_find_locked((int32_t)tid, self_tid, ctx);
    if (target != NULL) {
        /* Copy the wakeup TID while the lock is held: the target may
         * reach thr_thread_finish and free its context as soon as the
         * lock is released (S32-R3-1 follow-up), so nothing
         * dereferences the pointer after unlock. Lock order here is
         * thr_live_lock then sigact_lock; no reverse path exists
         * (S32-R3-8). The bit updates run while the lock is still
         * held, so the pointer is live. */
        found = true;
        is_self_target = (target == ctx);
        target_host_tid = target->host_tid;
        disp = sparc32_signal_disposition((int)sig);
        if (disp == SPARC32_SIG_DISP_IGN) {
            uint64_t bit = sparc32_thr_sigbit((int)sig);
            __atomic_fetch_and(&target->pending_signals, ~bit,
                __ATOMIC_ACQ_REL);
            thr_live_leave();
            return 0;
        }
        if (disp == SPARC32_SIG_DISP_DFL && (int)sig != 9 &&
            (int)sig != 17 &&
            sparc32_thr_sig_blocked(target, (int)sig) != 0) {
            /* Blocked + default (S32-R4-5): queue the thread bit and
             * skip the host call below, so kernel SIG_DFL cannot fire
             * while the guest holds the signal blocked. Default
             * termination applies at unmask time in the poll. */
            __atomic_fetch_or(&target->pending_signals,
                sparc32_thr_sigbit((int)sig), __ATOMIC_RELEASE);
            dfl_blocked_queued = true;
        } else if (disp == SPARC32_SIG_DISP_CAUGHT) {
            __atomic_fetch_or(&target->pending_signals,
                sparc32_thr_sigbit((int)sig), __ATOMIC_RELEASE);
        }
    }
    thr_live_leave();
    if (!found) {
        rc = thr_host_tgkill(tgid, (int32_t)tid, sig);
        if (rc != 0) {
            return rc;
        }
        return 0;
    }
    if (disp == SPARC32_SIG_DISP_DFL && dfl_blocked_queued) {
        /* Queued while blocked above: no host call. A self target
         * also joins the process queue; the poll terminates at
         * unmask time when the default action is fatal. */
        if ((int32_t)tid == self_tid) {
            return thr_kill_self(ctx, (int)sig);
        }
        return 0;
    }
    if (disp == SPARC32_SIG_DISP_DFL) {
        /* Default disposition to a live guest thread: the kernel must
         * apply it (raise(SIGTERM)/abort()/tkill SIGKILL were silently
         * dropped before this fix). Prefer the real kernel TID for a
         * self target whose stored host_tid may be stale. */
        int wake_tid = target_host_tid;
        if (is_self_target || (int32_t)tid == self_tid || wake_tid <= 0) {
            wake_tid = self_tid;
        }
        rc = thr_host_tgkill(tgid, wake_tid, sig);
        if (rc != 0) {
            return rc;
        }
        if ((int32_t)tid == self_tid) {
            return thr_kill_self(ctx, (int)sig);
        }
        return 0;
    }
    if (disp == SPARC32_SIG_DISP_CAUGHT && !is_self_target) {
        /* Wakeup for a target that may park in sigsuspend. The handler
         * only sets the process bit; the poll dedups it against the
         * thread bit above. Uses the copied TID, never the
         * possibly-freed target pointer. */
        thr_host_tgkill(tgid, target_host_tid, sig);
        if ((int32_t)tid == self_tid) {
            return thr_kill_self(ctx, (int)sig);
        }
    } else if ((int32_t)tid == self_tid) {
        return thr_kill_self(ctx, (int)sig);
    }
    return 0;
}

long sparc32_thr_gettid(sparc32_ctx_t *ctx)
{
    sparc32_threads_ensure_init(ctx);
    if (ctx == NULL) {
        return -EFAULT;
    }
    if (ctx->host_tid <= 0) {
        ctx->host_tid = thr_gettid();
    }
    return (long)ctx->host_tid;
}

long sparc32_thr_tkill(sparc32_ctx_t *ctx, uint32_t tid, uint32_t sig)
{
    sparc32_threads_ensure_init(ctx);
    if (ctx == NULL) {
        return -EFAULT;
    }
    return thr_kill_tid(ctx, (uint32_t)getpid(), tid, sig);
}

long sparc32_thr_tgkill(sparc32_ctx_t *ctx, uint32_t tgid, uint32_t tid,
    uint32_t sig)
{
    sparc32_threads_ensure_init(ctx);
    if (ctx == NULL) {
        return -EFAULT;
    }
    if ((int32_t)tgid <= 0) {
        return -EINVAL;
    }
    return thr_kill_tid(ctx, tgid, tid, sig);
}

/* set_tid_address(166) completion: record + real tid + one-time async
 * init, so plain static binaries get async coverage without any other
 * L4a syscall. */
long sparc32_thr_set_tid_address(sparc32_ctx_t *ctx, uint32_t tidptr_va)
{
    sparc32_threads_ensure_init(ctx);
    if (ctx == NULL) {
        return -EFAULT;
    }
    ctx->clear_child_tid = tidptr_va;
    if (ctx->host_tid <= 0) {
        ctx->host_tid = thr_gettid();
    }
    return (long)ctx->host_tid;
}
