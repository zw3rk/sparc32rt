/*
 * src/os/threads.c — Phase-4 process/thread machinery (lane L4a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * pipe/pipe2, fork/vfork, wait4/waitpid, clone via host pthreads,
 * kill family with synchronous self-delivery,
 * rt_sigpending/rt_sigsuspend. execve lives in threads_exec.c (split
 * for the 900-line discipline). Oracle evidence in the commit message.
 * vfork is fork + document. Async (#5): host handlers only set the
 * pending bit; delivery at safe points. RC4 hookups for threaded proof
 * are listed in threads.h. */
/* sched_yield/pthread + syscall() under strict -std=c11 with musl. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sparc32rt.h"
#include "os/syscalls_min.h"
#include "os/threads.h"
#include "interp/interp.h"
#include "rt32/rt32.h"

/* syscalls.c owns these (non-static): the rt_sigprocmask writer keeps
 * the process-global mask coherent, the reader merges into poll. */
extern long sparc32_l2a_rt_sigprocmask(sparc32_ctx_t *ctx, uint32_t how,
    uint32_t set_va, uint32_t oset_va, uint32_t sigsetsize);
extern uint64_t sparc32_l2a_blocked_mask(void);

#define THR_MAX_LIVE 64U

/* Live contexts for host-signal notes (lock-free reads in handler). */
static sparc32_ctx_t *thr_live[THR_MAX_LIVE];
static pthread_mutex_t thr_live_lock = PTHREAD_MUTEX_INITIALIZER;
static bool thr_init_done = false;

static void thr_register(sparc32_ctx_t *ctx)
{
    size_t i;
    if (ctx == NULL) {
        return;
    }
    pthread_mutex_lock(&thr_live_lock);
    for (i = 0U; i < THR_MAX_LIVE; i++) {
        if (thr_live[i] == ctx) {
            pthread_mutex_unlock(&thr_live_lock);
            return;
        }
    }
    for (i = 0U; i < THR_MAX_LIVE; i++) {
        if (thr_live[i] == NULL) {
            thr_live[i] = ctx;
            break;
        }
    }
    pthread_mutex_unlock(&thr_live_lock);
}

static void thr_deregister(sparc32_ctx_t *ctx)
{
    size_t i;
    pthread_mutex_lock(&thr_live_lock);
    for (i = 0U; i < THR_MAX_LIVE; i++) {
        if (thr_live[i] == ctx) {
            thr_live[i] = NULL;
        }
    }
    pthread_mutex_unlock(&thr_live_lock);
}

/* Host async note: set the kernel-layout pending bit on every live ctx.
 * Plain loads/stores only; signals without a guest handler are left for
 * the default path in thr_host_handler. */
void sparc32_thr_note_signal(int sig)
{
    uint64_t bit;
    size_t i;
    if (sig < 1 || sig > 64) {
        return;
    }
    bit = 1ULL << (uint64_t)((uint32_t)(sig - 1) % 32U);
    for (i = 0U; i < THR_MAX_LIVE; i++) {
        sparc32_ctx_t *c = thr_live[i];
        if (c == NULL) {
            continue;
        }
        if ((uint32_t)sig <= 32U) {
            c->pending_signals |= bit << 32U;
        } else {
            c->pending_signals |= bit;
        }
    }
}

static void thr_host_handler(int sig)
{
    uint32_t handler;
    uint32_t restorer;
    if (sig < 1 || sig > 31) {
        return;
    }
    if (sparc32_signal_get(sig, &handler, &restorer) == 0) {
        sparc32_thr_note_signal(sig);
        return;
    }
    /* No guest handler: restore default and re-raise so the process
     * keeps stock disposition instead of swallowing the signal. */
    signal(sig, SIG_DFL);
    raise(sig);
}

void sparc32_threads_ensure_init(sparc32_ctx_t *ctx)
{
    /* Catchable signals except the sync-fault pair (SIGBUS=7/SIGSEGV=11
     * stay on EXIT_FAULT) and the uncatchable SIGKILL=9/SIGSTOP=19.
     * Timer signals included for setitimer-style guests. */
    static const int sigs[] = {
        1, 2, 3, 4, 5, 6, 8, 10, 12, 13, 14, 15,
        16, 17, 18, 20, 21, 22, 23, 24, 25, 26,
        27, 28, 29, 30, 31,
    };
    size_t i;
    thr_register(ctx);
    if (thr_init_done) {
        return;
    }
    thr_init_done = true;
    for (i = 0U; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = thr_host_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        if (sigs[i] == 9 || sigs[i] == 19) {
            continue;
        }
        (void)sigaction(sigs[i], &sa, NULL);
    }
}

int sparc32_thr_sig_blocked(const sparc32_ctx_t *ctx, int sig)
{
    uint64_t m;
    uint32_t w;
    if (ctx == NULL || sig < 1 || sig > 64) {
        return 0;
    }
    m = ctx->sig_mask | sparc32_l2a_blocked_mask();
    w = ((uint32_t)sig <= 32U) ? (uint32_t)(m >> 32U) : (uint32_t)m;
    return (int)((w >> ((uint32_t)(sig - 1) % 32U)) & 1U);
}

void sparc32_thr_sig_set(sparc32_ctx_t *ctx, int sig, bool blocked)
{
    uint64_t bit;
    if (ctx == NULL || sig < 1 || sig > 64) {
        return;
    }
    bit = 1ULL << (uint64_t)((uint32_t)(sig - 1) % 32U);
    if ((uint32_t)sig <= 32U) {
        bit <<= 32U;
    }
    if (blocked) {
        ctx->sig_mask |= bit;
    } else {
        ctx->sig_mask &= ~bit;
    }
}

/* Guest BE word access through the G window (32-bit wrap + low-guard
 * check; the 4 GiB window is PROT_NONE with mapped regions inside). */
int sparc32_thr_range_ok(uint32_t va, uint32_t len)
{
    if (len == 0U) {
        return 0;
    }
    if ((uint64_t)va + (uint64_t)len > 0x100000000ULL) {
        return -EFAULT;
    }
    if (va < SPARC32_LOW_GUARD_SIZE) {
        return -EFAULT;
    }
    return 0;
}

static int thr_st(sparc32_ctx_t *ctx, uint32_t va, uint32_t v)
{
    uint8_t *p;
    if (sparc32_thr_range_ok(va, 4U) != 0) {
        return -EFAULT;
    }
    p = (uint8_t *)sparc32_guest_ptr(ctx, va);
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
    return 0;
}

/* pipe(42): SPARC dual-return (E04). The tail commits %o0 from the
 * return value, so return the read end and stash the write end in %o1.
 * The pointer-arg form is invalid on LEON Linux (oracle: EFAULT). */
long sparc32_thr_pipe(sparc32_ctx_t *ctx)
{
    int fds[2];
    sparc32_threads_ensure_init(ctx);
    if (ctx == NULL) {
        return -EFAULT;
    }
    if (pipe(fds) != 0) {
        return -(long)errno;
    }
    ctx->r[SPARC32_O1] = (uint32_t)fds[1];
    return (long)fds[0];
}

/* pipe2(321): generic pointer form (oracle: dual faults EFAULT, pointer
 * succeeds). Only CLOEXEC/NONBLOCK map; else EINVAL. */
long sparc32_thr_pipe2(sparc32_ctx_t *ctx, uint32_t fds_va, uint32_t flags)
{
    int fds[2];
    int oflags = 0;
    sparc32_threads_ensure_init(ctx);
    if (ctx == NULL || sparc32_thr_range_ok(fds_va, 8U) != 0) {
        return -EFAULT;
    }
    if ((flags & ~0x404000U) != 0U) {
        return -EINVAL;
    }
    if ((flags & 0x400000U) != 0U) {
        oflags |= O_CLOEXEC;
    }
    if ((flags & 0x4000U) != 0U) {
        oflags |= O_NONBLOCK;
    }
    if (pipe2(fds, oflags) != 0) {
        return -(long)errno;
    }
    if (thr_st(ctx, fds_va, (uint32_t)fds[0]) != 0 ||
        thr_st(ctx, fds_va + 4U, (uint32_t)fds[1]) != 0) {
        close(fds[0]);
        close(fds[1]);
        return -EFAULT;
    }
    return 0;
}

/* fork(2): E04 dual-return (parent o0=pid/o1=0, child o0=0/o1=1). DBT
 * cache survives as shared COW mappings; pending signals do not. */
long sparc32_thr_fork(sparc32_ctx_t *ctx)
{
    pid_t pid;
    sparc32_threads_ensure_init(ctx);
    if (ctx == NULL) {
        return -EFAULT;
    }
    pid = fork();
    if (pid < 0) {
        return -(long)errno;
    }
    if (pid == 0) {
        ctx->pending_signals = 0U;
        ctx->sig_last_frame_va = 0U;
        ctx->r[SPARC32_O1] = 1U;
        return 0;
    }
    ctx->r[SPARC32_O1] = 0U;
    return (long)pid;
}

long sparc32_thr_vfork(sparc32_ctx_t *ctx)
{
    return sparc32_thr_fork(ctx);
}

static long thr_wait_common(sparc32_ctx_t *ctx, uint32_t pid,
    uint32_t wstat_va, uint32_t options, uint32_t rusage_va, bool has_rusage)
{
    pid_t got;
    int status = 0;
    sparc32_threads_ensure_init(ctx);
    if (ctx == NULL) {
        return -EFAULT;
    }
    if (wstat_va != 0U && sparc32_thr_range_ok(wstat_va, 4U) != 0) {
        return -EFAULT;
    }
    if (has_rusage && rusage_va != 0U && sparc32_thr_range_ok(rusage_va, 72U) != 0) {
        return -EFAULT;
    }
    if (has_rusage && rusage_va != 0U) {
        got = wait4((pid_t)(int32_t)pid, &status, (int)options, NULL);
    } else {
        got = waitpid((pid_t)(int32_t)pid, &status, (int)options);
    }
    if (got < 0) {
        return -(long)errno;
    }
    /* Status is host-endian; the guest observes the BE word
     * (E04: exit(7) -> 0x0700). rusage is zero-filled (RC-H). */
    if (wstat_va != 0U && thr_st(ctx, wstat_va, (uint32_t)status) != 0) {
        return -EFAULT;
    }
    if (has_rusage && rusage_va != 0U) {
        memset(sparc32_guest_ptr(ctx, rusage_va), 0, 72);
    }
    return (long)got;
}

long sparc32_thr_wait4(sparc32_ctx_t *ctx, uint32_t pid, uint32_t wstat_va,
    uint32_t options, uint32_t rusage_va)
{
    return thr_wait_common(ctx, pid, wstat_va, options, rusage_va, true);
}

long sparc32_thr_waitpid(sparc32_ctx_t *ctx, uint32_t pid,
    uint32_t wstat_va, uint32_t options)
{
    return thr_wait_common(ctx, pid, wstat_va, options, 0U, false);
}

/* clone(217) order from qemu -strace: flags, child_stack,
 * parent_tidptr, tls, child_tidptr (tls in o3 on SPARC). CLONE_VM
 * mandatory; PARENT_SETTID/CHILD_CLEARTID(+wake)/SETTLS(-> %g7)
 * implemented; FS/FILES/SIGHAND/THREAD/VFORK/UNTRACED accepted. */

static void thr_thread_finish(struct thr_start *st, long status)
{
    sparc32_ctx_t *ctx = st->ctx;
    if (st->clear_tid_va != 0U && sparc32_thr_range_ok(st->clear_tid_va, 4U) == 0) {
        uint8_t *p = (uint8_t *)sparc32_guest_ptr(ctx, st->clear_tid_va);
        p[0] = 0; p[1] = 0; p[2] = 0; p[3] = 0;
#if defined(__linux__) && defined(SYS_futex)
        (void)syscall(SYS_futex, (uint32_t *)p, 1, 1, NULL, NULL, 0);
#endif
    }
    thr_deregister(ctx);
    free(ctx);
    free(st);
    pthread_exit((void *)(uintptr_t)(status & 0xFFL));
}

/* Clone-thread entry: interp stepping with per-step async polling.
 * DBT for threads is RC4/L4b; threads run the reference engine. */
static void *thr_thread_entry(void *arg)
{
    struct thr_start *st = (struct thr_start *)arg;
    sparc32_ctx_t *ctx = st->ctx;
    /* Publish the real kernel TID first (parent blocks on it). No
     * window reset: the global winfile/WIM is shared until RC4
     * per-thread state lands; the child continues the quiescent
     * parent's window images, so the parent must not execute guest
     * code concurrently (futex rendezvous before it resumes). */
    ctx->host_tid = (int)gettid();
    pthread_mutex_lock(&st->lock);
    st->child_tid = (long)ctx->host_tid;
    st->tid_ready = true;
    pthread_cond_signal(&st->ready);
    pthread_mutex_unlock(&st->lock);
    if (st->flags_cleartid && st->child_tid_va != 0U) {
        (void)thr_st(ctx, st->child_tid_va, (uint32_t)ctx->host_tid);
    }
    rt32_vm_sync_ctx(ctx);
    for (;;) {
        while (ctx->exit_reason == SPARC32_EXIT_NONE) {
            interp_step(ctx);
            if (ctx->exit_reason != SPARC32_EXIT_NONE) {
                break;
            }
            if (interp_poll_async(ctx)) {
                continue;
            }
        }
        if (ctx->exit_reason == SPARC32_EXIT_FAULT ||
            ctx->exit_reason == SPARC32_EXIT_SINGLE_STEP) {
            int signo;
            if (ctx->exit_reason == SPARC32_EXIT_SINGLE_STEP) {
                ctx->fault_addr = ctx->exit_dest;
            }
            signo = (ctx->fault_addr & 3U) != 0U ? 10 : 11;
            if (interp_try_deliver_sync(ctx, signo)) {
                continue;
            }
            if (interp_poll_async(ctx)) {
                continue;
            }
            thr_thread_finish(st, 128L + (long)signo);
            return NULL;
        }
        if (ctx->exit_reason != SPARC32_EXIT_SYSCALL) {
            thr_thread_finish(st, 1L);
            return NULL;
        }
        {
            long nr = (long)(int32_t)ctx->r[SPARC32_G1];
            long status = sparc32_handle_syscall(ctx);
            if (sparc32_syscall_is_exit(nr)) {
                thr_thread_finish(st, status);
                return NULL;
            }
            while (interp_poll_async(ctx)) {
            }
            /* Re-arm for the next step (interp_run's contract: the
             * stepper never resets exit_reason itself; without this
             * the same syscall re-dispatches forever). */
            ctx->exit_reason = SPARC32_EXIT_NONE;
        }
    }
}

long sparc32_thr_clone(sparc32_ctx_t *ctx, uint32_t flags, uint32_t stack,
    uint32_t parent_tid_va, uint32_t tls, uint32_t child_tid_va)
{
    /* SYSVSEM accepted and ignored: one shared address space shares
     * all semundo state by construction (qemu requires the bit). */
    static const uint32_t known =
        THR_CLONE_VM | THR_CLONE_FS | THR_CLONE_FILES | THR_CLONE_SIGHAND |
        THR_CLONE_THREAD | THR_CLONE_PARENT_SETTID |
        THR_CLONE_CHILD_CLEARTID | THR_CLONE_SETTLS | THR_CLONE_VFORK |
        THR_CLONE_SYSVSEM | THR_CLONE_UNTRACED;
    sparc32_ctx_t *child;
    struct thr_start *st;
    pthread_t th;
    pthread_attr_t attr;
    long child_tid;
    sparc32_threads_ensure_init(ctx);
    if (ctx == NULL) {
        return -EFAULT;
    }
    if ((flags & THR_CLONE_VM) == 0U || (flags & ~known) != 0U) {
        return -EINVAL;
    }
    if (stack != 0U && sparc32_thr_range_ok(stack - 64U, 64U) != 0 &&
        sparc32_thr_range_ok(stack, 4U) != 0) {
        return -EFAULT;
    }
    child = (sparc32_ctx_t *)calloc(1, sizeof(*child));
    st = (struct thr_start *)malloc(sizeof(*st));
    if (child == NULL || st == NULL) {
        free(child);
        free(st);
        return -ENOMEM;
    }
    *child = *ctx;
    child->exit_reason = SPARC32_EXIT_NONE;
    child->exit_arg = 0U;
    child->blocks_executed = 0U;
    child->syscalls_executed = 0U;
    child->pending_signals = 0U;
    child->sync_sig_delivered = false;
    child->sig_last_frame_va = 0U;
    child->sig_last_frame_rt = 0U;
    child->host_tid = 0;
    child->is_thread_clone = true;
    child->clear_child_tid = 0U;
    child->stack_base = stack;
    /* Child resumes past the clone trap with (o0 = 0, o1 = 0). */
    child->pc = ctx->npc;
    child->npc = ctx->npc + 4U;
    child->r[SPARC32_O0] = 0U;
    child->r[SPARC32_O1] = 0U;
    if (stack != 0U) {
        child->r[SPARC32_SP] = stack & ~15U;
    }
    if ((flags & THR_CLONE_SETTLS) != 0U) {
        child->r[SPARC32_G7] = tls;
    }
    if ((flags & THR_CLONE_CHILD_CLEARTID) != 0U) {
        child->clear_child_tid = child_tid_va;
    }
    st->ctx = child;
    st->clear_tid_va = child->clear_child_tid;
    st->child_tid_va = child_tid_va;
    st->flags_cleartid = (flags & THR_CLONE_CHILD_CLEARTID) != 0U;
    st->tid_ready = false;
    st->child_tid = -1L;
    thr_register(child);
    if (pthread_mutex_init(&st->lock, NULL) != 0 ||
        pthread_cond_init(&st->ready, NULL) != 0 ||
        pthread_attr_init(&attr) != 0) {
        thr_deregister(child);
        free(child);
        free(st);
        return -ENOMEM;
    }
    (void)pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&th, &attr, thr_thread_entry, st) != 0) {
        int e = errno;
        pthread_attr_destroy(&attr);
        pthread_mutex_destroy(&st->lock);
        pthread_cond_destroy(&st->ready);
        thr_deregister(child);
        free(child);
        free(st);
        return -(long)e;
    }
    pthread_attr_destroy(&attr);
    /* Rendezvous on the real kernel TID (reported as the clone return
     * value and stored to parent_tidptr). The child frees st at exit;
     * lock/cond die here (child never touches them after signalling). */
    pthread_mutex_lock(&st->lock);
    while (!st->tid_ready) {
        pthread_cond_wait(&st->ready, &st->lock);
    }
    child_tid = st->child_tid;
    pthread_mutex_unlock(&st->lock);
    pthread_mutex_destroy(&st->lock);
    pthread_cond_destroy(&st->ready);
    if ((flags & THR_CLONE_PARENT_SETTID) != 0U && parent_tid_va != 0U) {
        (void)thr_st(ctx, parent_tid_va, (uint32_t)child_tid);
    }
    ctx->r[SPARC32_O1] = 0U;
    return child_tid;
}

/* kill(37)/tkill(187)/tgkill(211): host pass-through, identity-mapped
 * 1..31. Self-directed signals with an installed, unblocked handler
 * deliver synchronously at this boundary (pre-compensated pc/npc),
 * matching Linux user-visible order; anything else just sets the
 * pending bit for the next safe point. */
static long thr_kill_self(sparc32_ctx_t *ctx, int sig)
{
    uint32_t handler;
    uint32_t restorer;
    sparc32_thr_note_signal(sig);
    if (sparc32_thr_sig_blocked(ctx, sig) != 0) {
        return 0;
    }
    if (sparc32_signal_get(sig, &handler, &restorer) != 0) {
        return 0;
    }
    /* Late delivery (RC4): the dispatch tail commits O0=0/C=0 first and
     * the next safe point (interp_step top / dbt block entry) delivers
     * with handler %o0=signo. In-dispatch delivery would let the tail
     * clobber %o0 with the syscall return. */
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
    if (sig > 31U) {
        return -EINVAL;
    }
    if (sig != 0U && kill((pid_t)(int32_t)pid, (int)sig) != 0) {
        return -(long)errno;
    }
    if (sig != 0U && thr_is_self(pid)) {
        return thr_kill_self(ctx, (int)sig);
    }
    return 0;
}

static long thr_kill_tid(sparc32_ctx_t *ctx, uint32_t tgid,
    uint32_t tid, uint32_t sig)
{
    long rc;
    if (sig > 31U) {
        return -EINVAL;
    }
#if defined(__linux__) && defined(SYS_tgkill)
    rc = syscall(SYS_tgkill, (pid_t)(int32_t)tgid, (pid_t)(int32_t)tid,
        (int)sig);
#else
    (void)tgid;
    rc = syscall(SYS_tkill, (pid_t)(int32_t)tid, (int)sig);
#endif
    if (sig != 0U && rc == 0 && (int32_t)tid == gettid()) {
        return thr_kill_self(ctx, (int)sig);
    }
    return (rc == 0) ? 0 : -(long)errno;
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
        ctx->host_tid = (int)gettid();
    }
    return (long)ctx->host_tid;
}

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
    if (set_va != 0U && sparc32_thr_range_ok(set_va, 8U) != 0) {
        return -EFAULT;
    }
    p = ctx->pending_signals;
    out[0] = (uint8_t)(p >> 56);
    out[1] = (uint8_t)(p >> 48);
    out[2] = (uint8_t)(p >> 40);
    out[3] = (uint8_t)(p >> 32);
    out[4] = (uint8_t)(p >> 24);
    out[5] = (uint8_t)(p >> 16);
    out[6] = (uint8_t)(p >> 8);
    out[7] = (uint8_t)p;
    if (set_va != 0U) {
        memcpy(sparc32_guest_ptr(ctx, set_va), out, sizeof(out));
    }
    return 0;
}

/* rt_sigsuspend(107): replace mask, sleep for an unblocked pending
 * signal, deliver synchronously, fail EINTR; both masks restored first.
 * set_va doubles as restore scratch (guest memory ends unchanged). */
long sparc32_thr_rt_sigsuspend(sparc32_ctx_t *ctx, uint32_t set_va,
    uint32_t sigsetsize)
{
    uint64_t n;
    uint64_t old;
    uint64_t old_ctx;
    uint8_t *buf;
    uint8_t tmp[8];
    sigset_t host_set;
    int s;
    sparc32_threads_ensure_init(ctx);
    if (ctx == NULL) {
        return -EFAULT;
    }
    if (sigsetsize != 8U) {
        return -EINVAL;
    }
    if (set_va == 0U || sparc32_thr_range_ok(set_va, 8U) != 0) {
        return -EFAULT;
    }
    buf = (uint8_t *)sparc32_guest_ptr(ctx, set_va);
    n = ((uint64_t)buf[0] << 56) | ((uint64_t)buf[1] << 48) |
        ((uint64_t)buf[2] << 40) | ((uint64_t)buf[3] << 32) |
        ((uint64_t)buf[4] << 24) | ((uint64_t)buf[5] << 16) |
        ((uint64_t)buf[6] << 8) | (uint64_t)buf[7];
    memcpy(tmp, buf, sizeof(tmp));
    old = sparc32_l2a_blocked_mask();
    old_ctx = ctx->sig_mask;
    if (sparc32_l2a_rt_sigprocmask(ctx, SPARC_SIG_SETMASK, set_va, 0U, 8U) != 0) {
        return -EFAULT;
    }
    ctx->sig_mask = n;
    sigemptyset(&host_set);
    for (;;) {
        bool woke = false;
        for (s = 1; s <= 31; s++) {
            uint64_t bit = 1ULL << (uint64_t)((uint32_t)(s - 1) % 32U);
            uint32_t handler;
            uint32_t restorer;
            if ((uint32_t)s <= 32U) {
                bit <<= 32U;
            }
            if ((ctx->pending_signals & bit) == 0U) {
                continue;
            }
            if (sparc32_thr_sig_blocked(ctx, s) != 0) {
                continue;
            }
            if (sparc32_signal_get(s, &handler, &restorer) != 0) {
                ctx->pending_signals &= ~bit;
                continue;
            }
            for (int k = 0; k < 8; k++) {
                buf[k] = (uint8_t)(old >> (56 - 8 * k));
            }
            (void)sparc32_l2a_rt_sigprocmask(ctx, SPARC_SIG_SETMASK, set_va, 0U, 8U);
            memcpy(buf, tmp, sizeof(tmp));
            ctx->sig_mask = old_ctx;
            /* In-dispatch delivery (sigsuspend asserts the handler ran
             * before return). The tail then commits O0=EINTR/C=1 over
             * %o0 — exactly the post-handler state — while the frame
             * psr carries C for the sigreturn restore. */
            if (!interp_deliver_async_for_syscall(ctx, s, true)) {
                ctx->pending_signals &= ~bit;
            }
            woke = true;
            break;
        }
        if (woke) {
            return -EINTR;
        }
        (void)sigsuspend(&host_set);
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
    const uint8_t *np;
    uint8_t *op;
    struct itimerval ntv;
    struct itimerval otv;
    struct itimerval *oldp;
    if (which != 0U) {
        return -EINVAL;
    }
    if (new_va == 0U || sparc32_thr_range_ok(new_va, 16U) != 0) {
        return -EFAULT;
    }
    if (old_va != 0U && sparc32_thr_range_ok(old_va, 16U) != 0) {
        return -EFAULT;
    }
    np = (const uint8_t *)sparc32_guest_ptr(ctx, new_va);
    ntv.it_interval.tv_sec = (time_t)(int32_t)(((uint32_t)np[0] << 24) |
        ((uint32_t)np[1] << 16) | ((uint32_t)np[2] << 8) |
        (uint32_t)np[3]);
    ntv.it_interval.tv_usec = (suseconds_t)(int32_t)(((uint32_t)np[4] << 24) |
        ((uint32_t)np[5] << 16) | ((uint32_t)np[6] << 8) |
        (uint32_t)np[7]);
    ntv.it_value.tv_sec = (time_t)(int32_t)(((uint32_t)np[8] << 24) |
        ((uint32_t)np[9] << 16) | ((uint32_t)np[10] << 8) |
        (uint32_t)np[11]);
    ntv.it_value.tv_usec = (suseconds_t)(int32_t)(((uint32_t)np[12] << 24) |
        ((uint32_t)np[13] << 16) | ((uint32_t)np[14] << 8) |
        (uint32_t)np[15]);
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
        uint32_t osec;
        uint32_t ousec;
        uint32_t vsec;
        uint32_t vusec;
        op = (uint8_t *)sparc32_guest_ptr(ctx, old_va);
        osec = (uint32_t)otv.it_interval.tv_sec;
        ousec = (uint32_t)otv.it_interval.tv_usec;
        vsec = (uint32_t)otv.it_value.tv_sec;
        vusec = (uint32_t)otv.it_value.tv_usec;
        op[0] = (uint8_t)(osec >> 24);
        op[1] = (uint8_t)(osec >> 16);
        op[2] = (uint8_t)(osec >> 8);
        op[3] = (uint8_t)osec;
        op[4] = (uint8_t)(ousec >> 24);
        op[5] = (uint8_t)(ousec >> 16);
        op[6] = (uint8_t)(ousec >> 8);
        op[7] = (uint8_t)ousec;
        op[8] = (uint8_t)(vsec >> 24);
        op[9] = (uint8_t)(vsec >> 16);
        op[10] = (uint8_t)(vsec >> 8);
        op[11] = (uint8_t)vsec;
        op[12] = (uint8_t)(vusec >> 24);
        op[13] = (uint8_t)(vusec >> 16);
        op[14] = (uint8_t)(vusec >> 8);
        op[15] = (uint8_t)vusec;
    }
    return 0;
}
