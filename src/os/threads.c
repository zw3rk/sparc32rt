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
#include "os/l2a_access.h"
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

static int thr_gettid(void)
{
#if defined(__APPLE__)
    uint64_t tid = 0;
    (void)pthread_threadid_np(NULL, &tid);
    return (tid != 0ULL) ? (int)(tid & 0x7FFFFFFFULL) : (int)getpid();
#else
    return (int)gettid();
#endif
}

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
        if (__atomic_load_n(&thr_live[i], __ATOMIC_RELAXED) == ctx) {
            pthread_mutex_unlock(&thr_live_lock);
            return;
        }
    }
    for (i = 0U; i < THR_MAX_LIVE; i++) {
        if (__atomic_load_n(&thr_live[i], __ATOMIC_RELAXED) == NULL) {
            __atomic_store_n(&thr_live[i], ctx, __ATOMIC_RELEASE);
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
        if (__atomic_load_n(&thr_live[i], __ATOMIC_RELAXED) == ctx) {
            __atomic_store_n(&thr_live[i], NULL, __ATOMIC_RELEASE);
        }
    }
    pthread_mutex_unlock(&thr_live_lock);
}

/* Drop a live context without racing an async host-signal note (Section
 * 3 #3): sparc32_thr_note_signal runs in signal context on any thread and
 * dereferences every thr_live[] entry, so the deregister+free sequence
 * must be uninterruptible on this thread. sigfillset covers every handled
 * signal; the mask is restored before return, at which point the slot is
 * already NULL and a handler can no longer observe the freed pointer. */
static void thr_drop_context(sparc32_ctx_t *ctx)
{
    sigset_t block;
    sigset_t old;
    bool have_old = false;
    if (ctx == NULL) {
        return;
    }
    sigfillset(&block);
    if (sigprocmask(SIG_SETMASK, &block, &old) == 0) {
        have_old = true;
    }
    thr_deregister(ctx);
    free(ctx);
    if (have_old) {
        (void)sigprocmask(SIG_SETMASK, &old, NULL);
    }
}

/* Host async note: set the kernel-layout pending bit on every live ctx.
 * Atomic loads/stores only; signals without a guest handler are left for
 * the default path in thr_host_handler. */
void sparc32_thr_note_signal(int sig)
{
    uint64_t bit;
    uint64_t mask;
    size_t i;
    if (sig < 1 || sig > 64) {
        return;
    }
    bit = 1ULL << (uint64_t)((uint32_t)(sig - 1) % 32U);
    mask = ((uint32_t)sig <= 32U) ? (bit << 32U) : bit;
    for (i = 0U; i < THR_MAX_LIVE; i++) {
        sparc32_ctx_t *c = __atomic_load_n(&thr_live[i], __ATOMIC_ACQUIRE);
        if (c == NULL) {
            continue;
        }
        __atomic_fetch_or(&c->pending_signals, mask, __ATOMIC_RELEASE);
    }
}

static void thr_host_handler(int sig)
{
    uint32_t handler;
    uint32_t restorer;
    if (sig < 1 || sig > 64) {
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
    if (__atomic_load_n(&thr_init_done, __ATOMIC_ACQUIRE)) {
        return;
    }
    pthread_mutex_lock(&thr_live_lock);
    if (!__atomic_load_n(&thr_init_done, __ATOMIC_RELAXED)) {
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
        __atomic_store_n(&thr_init_done, true, __ATOMIC_RELEASE);
    }
    pthread_mutex_unlock(&thr_live_lock);
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

/* Guest BE word access through the G window with page-permission checks. */
int sparc32_thr_range_ok(uint32_t va, uint32_t len)
{
    return l2a_range_ok_prot(va, len, 1U);
}

static int thr_st(sparc32_ctx_t *ctx, uint32_t va, uint32_t v)
{
    uint8_t b[4];
    put_be32(b, v);
    return l2a_store(ctx, va, b, sizeof(b));
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
    if (ctx == NULL || l2a_range_ok_prot(fds_va, 8U, 2U) != 0) {
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
#if defined(__linux__)
    if (pipe2(fds, oflags) != 0) {
        return -(long)errno;
    }
#else
    if (pipe(fds) != 0) {
        return -(long)errno;
    }
    if ((oflags & O_CLOEXEC) != 0) {
        (void)fcntl(fds[0], F_SETFD, FD_CLOEXEC);
        (void)fcntl(fds[1], F_SETFD, FD_CLOEXEC);
    }
    if ((oflags & O_NONBLOCK) != 0) {
        int fl0 = fcntl(fds[0], F_GETFL);
        int fl1 = fcntl(fds[1], F_GETFL);
        if (fl0 >= 0) {
            (void)fcntl(fds[0], F_SETFL, fl0 | O_NONBLOCK);
        }
        if (fl1 >= 0) {
            (void)fcntl(fds[1], F_SETFL, fl1 | O_NONBLOCK);
        }
    }
#endif
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
        sparc32_vm_fork_child_reset();
        __atomic_store_n(&ctx->pending_signals, 0ULL, __ATOMIC_RELAXED);
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
    if (wstat_va != 0U && l2a_range_ok_prot(wstat_va, 4U, 2U) != 0) {
        return -EFAULT;
    }
    if (has_rusage && rusage_va != 0U &&
        l2a_range_ok_prot(rusage_va, 72U, 2U) != 0) {
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
        uint8_t z[72];
        memset(z, 0, sizeof(z));
        if (l2a_store(ctx, rusage_va, z, sizeof(z)) != 0) {
            return -EFAULT;
        }
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
    if (st->clear_tid_va != 0U &&
        l2a_range_ok_prot(st->clear_tid_va, 4U, 2U) == 0) {
        (void)thr_st(ctx, st->clear_tid_va, 0U);
#if defined(__linux__) && defined(SYS_futex)
        (void)syscall(SYS_futex,
            (uint32_t *)sparc32_guest_ptr(ctx, st->clear_tid_va),
            1, 1, NULL, NULL, 0);
#else
        {
            extern long sparc32_futex_wake_emu(sparc32_ctx_t *c,
                uint32_t uaddr, uint32_t n);
            (void)sparc32_futex_wake_emu(ctx, st->clear_tid_va, 1U);
        }
#endif
    }
    thr_drop_context(ctx);
    free(st);
    pthread_exit((void *)(uintptr_t)(status & 0xFFL));
}

/* Clone-thread entry: interp stepping with per-step async polling.
 * DBT for threads is RC4/L4b; threads run the reference engine. */
static void *thr_thread_entry(void *arg)
{
    struct thr_start *st = (struct thr_start *)arg;
    sparc32_ctx_t *ctx = st->ctx;
    interp_window_clone_restore(st->winfile, st->winsp, st->win_valid);
    ctx->host_tid = thr_gettid();
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
            signo = sparc32_classify_fault(ctx);
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
    /* Child resumes past the clone trap with (o0 = 0, o1 = 1). */
    child->pc = ctx->npc;
    child->npc = ctx->npc + 4U;
    child->r[SPARC32_O0] = 0U;
    child->r[SPARC32_O1] = 1U;
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
    interp_window_clone_save(st->winfile, st->winsp, st->win_valid);
    thr_register(child);
    if (pthread_mutex_init(&st->lock, NULL) != 0 ||
        pthread_cond_init(&st->ready, NULL) != 0 ||
        pthread_attr_init(&attr) != 0) {
        thr_drop_context(child);
        free(st);
        return -ENOMEM;
    }
    (void)pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&th, &attr, thr_thread_entry, st) != 0) {
        int e = errno;
        pthread_attr_destroy(&attr);
        pthread_mutex_destroy(&st->lock);
        pthread_cond_destroy(&st->ready);
        thr_drop_context(child);
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
    if (sig > 64U) {
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
    if (sig > 64U) {
        return -EINVAL;
    }
#if defined(__linux__) && defined(SYS_tgkill)
    rc = syscall(SYS_tgkill, (pid_t)(int32_t)tgid, (pid_t)(int32_t)tid,
        (int)sig);
#elif defined(__linux__) && defined(SYS_tkill)
    (void)tgid;
    rc = syscall(SYS_tkill, (pid_t)(int32_t)tid, (int)sig);
#else
    (void)tgid;
    {
        size_t i;
        bool found = ((int32_t)tid == thr_gettid() ||
            (pid_t)(int32_t)tid == getpid());
        for (i = 0U; i < THR_MAX_LIVE; i++) {
            sparc32_ctx_t *c = __atomic_load_n(&thr_live[i], __ATOMIC_ACQUIRE);
            if (c != NULL && c->host_tid == (int32_t)tid) {
                found = true;
                if (sig >= 1U && sig <= 64U) {
                    uint64_t bit = 1ULL << (uint64_t)((sig - 1U) % 32U);
                    uint64_t mask = (sig <= 32U) ? (bit << 32U) : bit;
                    __atomic_fetch_or(&c->pending_signals, mask,
                        __ATOMIC_RELEASE);
                }
            }
        }
        rc = found ? 0 : (long)kill((pid_t)(int32_t)tid, (int)sig);
    }
#endif
    if (sig != 0U && rc == 0 && (int32_t)tid == thr_gettid()) {
        return thr_kill_self(ctx, (int)sig);
    }
    return (rc == 0) ? 0 : -(long)errno;
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
