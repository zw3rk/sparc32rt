/*
 * src/os/threads.c — Phase-4 process/thread machinery (lane L4a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * fork/vfork, wait4/waitpid, clone via host pthreads,
 * rt_sigpending/rt_sigsuspend. The kill family (kill/tkill/tgkill,
 * gettid, set_tid_address) lives in threads_kill.c; pipe/pipe2 and
 * the guest FD table live in threads_fd.c; execve lives in
 * threads_exec.c (splits for the 900-line discipline). Oracle
 * evidence in the commit message.
 * vfork is fork + document. Async (#5): host handlers only set the
 * process-pending word; delivery at safe points. RC4 hookups for
 * threaded proof are listed in threads.h.
 *
 * Lock order (S32-R3-2, S32-R3-3): thr_live_lock -> sigact_lock ->
 * thr_fd_lock -> g_dbt_lock -> VM spinlock. vm_lock_acquire()
 * performs the DBT quiescence step itself; fork prepare takes the
 * five in order and holds them across fork() so the child inherits
 * no partial mutation and no lock owned by a vanished thread.
 */
/* sched_yield/pthread + syscall() under strict -std=c11 with musl. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "sparc32rt.h"
#include "os/l2a_access.h"
#include "os/syscalls_min.h"
#include "os/threads.h"
#include "interp/interp.h"
#include "rt32/rt32.h"

#define THR_MAX_LIVE 512U

/* VM / DBT fork + quiescence hooks (defined in rt32/vm.c, dbt/dbt_cache.c). */
extern void vm_lock_acquire_noquiesce(void);
extern void vm_lock_release_noquiesce(void);
extern void dbt_fork_prepare(void);
extern void dbt_fork_parent(void);
extern void dbt_fork_child_reset(void);
extern void sparc32_vm_fork_child_reset(void);

int thr_gettid(void)
{
#if defined(__APPLE__)
    uint64_t tid = 0;
    (void)pthread_threadid_np(NULL, &tid);
    return (tid != 0ULL) ? (int)(tid & 0x7FFFFFFFULL) : (int)getpid();
#else
    return (int)gettid();
#endif
}

/* Live contexts (normal thread context only; the async handler never
 * reads this table) + the stable process-pending word + exec retire.
 * Each slot also stores the host pthread for non-Linux wakeup
 * (S32-R4-8): pthread_kill(pt) instead of kill(host_tid). */
typedef struct {
    sparc32_ctx_t *ctx;
    pthread_t pt;
    int pt_valid;
} thr_slot_t;
static thr_slot_t thr_live[THR_MAX_LIVE];
static pthread_mutex_t thr_live_lock = PTHREAD_MUTEX_INITIALIZER;
static bool thr_init_done = false;
static _Atomic uint64_t g_process_pending = 0ULL;
static _Atomic bool g_exec_retiring = false;

/* Sticky per-context retirement marks (S32-R3-4 follow-up #4): every
 * context ever marked retired stays marked until its own storage is
 * freed, so a slow sibling that missed the wait still observes the
 * flag after the globals stop changing. Guarded by thr_live_lock;
 * readers use acquire loads so the hot poll stays lock-free. */
static sparc32_ctx_t *thr_retired[THR_MAX_LIVE];

static void thr_retired_add_locked(sparc32_ctx_t *ctx)
{
    size_t i;
    for (i = 0U; i < THR_MAX_LIVE; i++) {
        if (__atomic_load_n(&thr_retired[i], __ATOMIC_RELAXED) == ctx) {
            return;
        }
    }
    for (i = 0U; i < THR_MAX_LIVE; i++) {
        if (__atomic_load_n(&thr_retired[i], __ATOMIC_RELAXED) == NULL) {
            __atomic_store_n(&thr_retired[i], ctx, __ATOMIC_RELEASE);
            return;
        }
    }
}

static void thr_retired_remove_locked(sparc32_ctx_t *ctx)
{
    size_t i;
    for (i = 0U; i < THR_MAX_LIVE; i++) {
        if (__atomic_load_n(&thr_retired[i], __ATOMIC_RELAXED) == ctx) {
            __atomic_store_n(&thr_retired[i], NULL, __ATOMIC_RELEASE);
        }
    }
}

static bool thr_retired_contains(const sparc32_ctx_t *ctx)
{
    size_t i;
    if (ctx == NULL) {
        return false;
    }
    for (i = 0U; i < THR_MAX_LIVE; i++) {
        if (__atomic_load_n(&thr_retired[i], __ATOMIC_ACQUIRE) == ctx) {
            return true;
        }
    }
    return false;
}

/* Live-registry lock + lookup shared by the threads_*.c splits (see
 * threads.h). The pointer is only valid while the lock is held. */
void thr_live_enter(void)
{
    pthread_mutex_lock(&thr_live_lock);
}

void thr_live_leave(void)
{
    pthread_mutex_unlock(&thr_live_lock);
}

sparc32_ctx_t *thr_live_find_locked(int32_t want_tid, int32_t self_tid,
    const sparc32_ctx_t *self)
{
    size_t i;
    for (i = 0U; i < THR_MAX_LIVE; i++) {
        sparc32_ctx_t *c = __atomic_load_n(&thr_live[i].ctx,
            __ATOMIC_ACQUIRE);
        if (c != NULL && (c->host_tid == want_tid ||
                (want_tid == self_tid && c == self))) {
            return c;
        }
    }
    return NULL;
}

/* Slot pthread lookup for non-Linux wakeup (S32-R4-8). Own locking. */
bool thr_live_pt_for_tid(int32_t tid, pthread_t *out)
{
    size_t i;
    bool ok = false;
    pthread_mutex_lock(&thr_live_lock);
    for (i = 0U; i < THR_MAX_LIVE; i++) {
        sparc32_ctx_t *c = __atomic_load_n(&thr_live[i].ctx,
            __ATOMIC_ACQUIRE);
        if (c != NULL && c->host_tid == tid && thr_live[i].pt_valid) {
            if (out != NULL) {
                *out = thr_live[i].pt;
            }
            ok = true;
            break;
        }
    }
    pthread_mutex_unlock(&thr_live_lock);
    return ok;
}

static void thr_live_set_pt_locked(sparc32_ctx_t *ctx, pthread_t pt)
{
    size_t i;
    for (i = 0U; i < THR_MAX_LIVE; i++) {
        if (__atomic_load_n(&thr_live[i].ctx, __ATOMIC_RELAXED) == ctx) {
            thr_live[i].pt = pt;
            thr_live[i].pt_valid = 1;
            break;
        }
    }
}

static void thr_register(sparc32_ctx_t *ctx)
{
    size_t i;
    pthread_t self;
    if (ctx == NULL) {
        return;
    }
    self = pthread_self();
    pthread_mutex_lock(&thr_live_lock);
    for (i = 0U; i < THR_MAX_LIVE; i++) {
        if (__atomic_load_n(&thr_live[i].ctx, __ATOMIC_RELAXED) == ctx) {
            if (!thr_live[i].pt_valid) {
                thr_live[i].pt = self;
                thr_live[i].pt_valid = 1;
            }
            pthread_mutex_unlock(&thr_live_lock);
            return;
        }
    }
    for (i = 0U; i < THR_MAX_LIVE; i++) {
        if (__atomic_load_n(&thr_live[i].ctx, __ATOMIC_RELAXED) == NULL) {
            __atomic_store_n(&thr_live[i].ctx, ctx, __ATOMIC_RELEASE);
            thr_live[i].pt = self;
            thr_live[i].pt_valid = 1;
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
        if (__atomic_load_n(&thr_live[i].ctx, __ATOMIC_RELAXED) == ctx) {
            __atomic_store_n(&thr_live[i].ctx, NULL, __ATOMIC_RELEASE);
            thr_live[i].pt_valid = 0;
        }
    }
    /* A context that frees its own storage drops its retirement mark
     * with it, so a later allocation that reuses the address is never
     * mistaken for a retired sibling (S32-R3-4 follow-up #4). */
    thr_retired_remove_locked(ctx);
    pthread_mutex_unlock(&thr_live_lock);
}

/* Context teardown (S32-R3-1): the async handler never dereferences a
 * live context (it only sets g_process_pending), so freeing after
 * deregistering under thr_live_lock is safe. Normal-context readers
 * (tkill scans) hold the same lock across load + pending-bit update,
 * so no thread observes the freed pointer. */
static void thr_drop_context(sparc32_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    thr_deregister(ctx);
    free(ctx);
}

/* Host async note (S32-R3-1, S32-R3-7): set the stable process-pending
 * bit only. Atomic fetch_or; no context access, no table read. */
void sparc32_thr_note_signal(int sig)
{
    if (sig < 1 || sig > 64) {
        return;
    }
    atomic_fetch_or_explicit(&g_process_pending, sparc32_thr_sigbit(sig),
        memory_order_release);
}

void sparc32_thr_host_handler(int sig)
{
    /* Host numbering (S32-R4-4): map back to SPARC before noting. */
    sig = sparc32_sig_from_host(sig);
    if (sig < 1 || sig > 64) {
        return;
    }
    sparc32_thr_note_signal(sig);
}

/* Thread-directed note: set one context's own pending bit. The caller
 * either holds thr_live_lock (tkill scan) or owns the context
 * exclusively (self delivery, no registry access). */
void sparc32_thr_note_thread(sparc32_ctx_t *ctx, int sig)
{
    if (ctx == NULL || sig < 1 || sig > 64) {
        return;
    }
    __atomic_fetch_or(&ctx->pending_signals, sparc32_thr_sigbit(sig), __ATOMIC_RELEASE);
}

/* Single-winner claim of one process-pending bit (S32-R3-7): exactly
 * one polling thread delivers each process-directed signal. */
bool sparc32_thr_claim_global(int sig)
{
    uint64_t old;
    uint64_t bit;
    if (sig < 1 || sig > 64) {
        return false;
    }
    bit = sparc32_thr_sigbit(sig);
    old = atomic_load_explicit(&g_process_pending, memory_order_acquire);
    for (;;) {
        uint64_t want;
        if ((old & bit) == 0U) {
            return false;
        }
        want = old & ~bit;
        if (atomic_compare_exchange_weak_explicit(&g_process_pending, &old,
                want, memory_order_acq_rel, memory_order_acquire)) {
            return true;
        }
    }
}

/* True when any live context holds thread bit sig (S32-R3-7 echo
 * attribution): a claimed process bit with a surviving thread owner
 * elsewhere is a host-wakeup echo, not a second signal. */
bool sparc32_thr_thread_has_pending(int sig)
{
    uint64_t bit;
    size_t i;
    if (sig < 1 || sig > 64) {
        return false;
    }
    bit = sparc32_thr_sigbit(sig);
    pthread_mutex_lock(&thr_live_lock);
    for (i = 0U; i < THR_MAX_LIVE; i++) {
        sparc32_ctx_t *c = __atomic_load_n(&thr_live[i].ctx,
            __ATOMIC_ACQUIRE);
        if (c != NULL && (__atomic_load_n(&c->pending_signals,
                __ATOMIC_ACQUIRE) & bit) != 0ULL) {
            pthread_mutex_unlock(&thr_live_lock);
            return true;
        }
    }
    pthread_mutex_unlock(&thr_live_lock);
    return false;
}

void sparc32_thr_discard_signal(sparc32_ctx_t *ctx, int sig)
{
    uint64_t bit;
    if (sig < 1 || sig > 64) {
        return;
    }
    bit = sparc32_thr_sigbit(sig);
    if (ctx != NULL) {
        __atomic_fetch_and(&ctx->pending_signals, ~bit, __ATOMIC_ACQ_REL);
    }
    atomic_fetch_and_explicit(&g_process_pending, ~bit,
        memory_order_acq_rel);
}

/* True when this context or the process queue holds an undelivered
 * signal (fast-path guard for the safe-point poll). */
bool sparc32_thr_has_pending(const sparc32_ctx_t *ctx)
{
    if (ctx != NULL && __atomic_load_n(&ctx->pending_signals,
            __ATOMIC_ACQUIRE) != 0ULL) {
        return true;
    }
    return atomic_load_explicit(&g_process_pending,
        memory_order_acquire) != 0ULL;
}

uint64_t sparc32_thr_process_pending(void)
{
    return atomic_load_explicit(&g_process_pending, memory_order_acquire);
}

void sparc32_thr_clear_process_pending(void)
{
    atomic_store_explicit(&g_process_pending, 0ULL, memory_order_release);
}

/* Retired-context exit (S32-R3-4): a guest thread that observes the
 * exec-retire flag deregisters and frees only its own context, then
 * leaves the process (which survives while the exec survivor runs). */
void sparc32_thr_self_retire(sparc32_ctx_t *ctx)
{
    if (ctx == NULL) {
        pthread_exit(NULL);
    }
    thr_deregister(ctx);
    free(ctx);
    pthread_exit(NULL);
}

void sparc32_threads_ensure_init(sparc32_ctx_t *ctx)
{
    thr_register(ctx);
    /* Inherited descriptors 0..2 join the guest FD table once, so a
     * later F_SETFD on them is honoured at exec (follow-up #6). */
    sparc32_fd_ensure_init();
    if (__atomic_load_n(&thr_init_done, __ATOMIC_ACQUIRE)) {
        return;
    }
    pthread_mutex_lock(&thr_live_lock);
    if (!__atomic_load_n(&thr_init_done, __ATOMIC_RELAXED)) {
        /* Host dispositions install lazily from rt_sigaction; every
         * signal starts at SIG_DFL, which is already the host state. */
        __atomic_store_n(&thr_init_done, true, __ATOMIC_RELEASE);
    }
    pthread_mutex_unlock(&thr_live_lock);
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

/* Coordinated fork (S32-R3-2): quiesce admission and execution in the
 * documented lock order (thr_live_lock -> sigact_lock -> thr_fd_lock
 * -> g_dbt_lock -> VM spinlock), fork, then rebuild single-threaded
 * state. The child inherits all five locks held by the surviving
 * (forking) thread, so it owns and then reinitializes them; no lock
 * is ever owned by a vanished thread, and no reader/runner survives
 * to observe a torn VM table. A sibling inside rt_sigaction or an
 * open-family call at fork time no longer leaves the child with a
 * permanently locked mutex (S32-R3-2 follow-up #3). */
void sparc32_thr_fork_prepare(void)
{
    pthread_mutex_lock(&thr_live_lock);
    sparc32_signal_fork_prepare();
    sparc32_fd_fork_prepare();
    dbt_fork_prepare();
    vm_lock_acquire_noquiesce();
}

void sparc32_thr_fork_parent(void)
{
    vm_lock_release_noquiesce();
    dbt_fork_parent();
    sparc32_fd_fork_parent();
    sparc32_signal_fork_parent();
    pthread_mutex_unlock(&thr_live_lock);
}

void sparc32_thr_fork_child(sparc32_ctx_t *ctx)
{
    size_t i;
    sparc32_vm_fork_child_reset();
    dbt_fork_child_reset();
    /* The forking thread owns every process-wide mutex in the child:
     * release each one, then rebuild it so vanished threads leave no
     * slots or marks behind, then re-register the sole survivor. */
    sparc32_fd_fork_child();
    sparc32_signal_fork_child();
    pthread_mutex_unlock(&thr_live_lock);
    pthread_mutex_destroy(&thr_live_lock);
    pthread_mutex_init(&thr_live_lock, NULL);
    for (i = 0U; i < THR_MAX_LIVE; i++) {
        __atomic_store_n(&thr_live[i].ctx, NULL, __ATOMIC_RELAXED);
        thr_live[i].pt_valid = 0;
        __atomic_store_n(&thr_retired[i], NULL, __ATOMIC_RELAXED);
    }
    atomic_store_explicit(&g_process_pending, 0ULL, memory_order_relaxed);
    atomic_store_explicit(&g_exec_retiring, false, memory_order_relaxed);
    if (ctx != NULL) {
        __atomic_store_n(&ctx->pending_signals, 0ULL, __ATOMIC_RELAXED);
        ctx->sig_last_frame_va = 0U;
        ctx->sig_last_frame_rt = 0U;
        thr_register(ctx);
    }
}

/* fork(2): E04 dual-return (parent o0=pid/o1=0, child o0=0/o1=1). DBT
 * cache survives as shared COW mappings; pending queues restart empty
 * in the child (fresh process, no inherited pendings). */
long sparc32_thr_fork(sparc32_ctx_t *ctx)
{
    pid_t pid;
    sparc32_threads_ensure_init(ctx);
    if (ctx == NULL) {
        return -EFAULT;
    }
    sparc32_thr_fork_prepare();
    pid = fork();
    if (pid < 0) {
        int e = errno;
        sparc32_thr_fork_parent();
        return -(long)e;
    }
    if (pid == 0) {
        sparc32_thr_fork_child(ctx);
        ctx->r[SPARC32_O1] = 1U;
        return 0;
    }
    sparc32_thr_fork_parent();
    ctx->r[SPARC32_O1] = 0U;
    return (long)pid;
}

long sparc32_thr_vfork(sparc32_ctx_t *ctx)
{
    return sparc32_thr_fork(ctx);
}

/* execve sibling retirement (S32-R3-4, follow-up #4): old guest
 * threads must not survive the image replacement. The survivor marks
 * every other live context retired; every clone-thread loop polls
 * sparc32_thr_is_retired() — including inside the inner interp_step
 * loop, so compute-bound siblings observe it — and exits through the
 * normal thread-finish path (which deregisters and frees its own
 * context, so no cross-thread free ever runs). */
void sparc32_thr_exec_retire_begin(sparc32_ctx_t *survivor)
{
    size_t i;
    atomic_store_explicit(&g_exec_retiring, true, memory_order_release);
    /* Mark every other live context retired under the lock. The marks
     * are sticky per context (see thr_retired): the wait below never
     * clears them, so a slow sibling still observes its own mark after
     * the registry slot is gone instead of resuming against the new
     * image. Contexts cloned after the exec are never marked. */
    pthread_mutex_lock(&thr_live_lock);
    for (i = 0U; i < THR_MAX_LIVE; i++) {
        sparc32_ctx_t *c = __atomic_load_n(&thr_live[i].ctx,
            __ATOMIC_ACQUIRE);
        if (c != NULL && c != survivor) {
            thr_retired_add_locked(c);
        }
    }
    pthread_mutex_unlock(&thr_live_lock);
}

bool sparc32_thr_is_retired(const sparc32_ctx_t *ctx)
{
    if (ctx == NULL) {
        return false;
    }
    return thr_retired_contains(ctx);
}

void sparc32_thr_exec_retire_done(void)
{
    atomic_store_explicit(&g_exec_retiring, false, memory_order_release);
}

void sparc32_thr_exec_retire_wait(sparc32_ctx_t *survivor)
{
    /* Bounded wait (~2 s): siblings poll out on their own; a thread
     * stuck in a host blocking call cannot observe the flag, so the
     * transaction must still commit. Leftovers are deregistered (never
     * freed here) so the new image owns a clean registry — but their
     * sticky retirement marks are kept, so a late sibling still exits
     * through the retire path instead of running its old PC against
     * the new image. Only fork_child (a fresh process) resets the
     * marks and the retiring flag. */
    struct timespec ts;
    int tries;
    size_t n;
    ts.tv_sec = 0;
    ts.tv_nsec = 1000000L;
    for (tries = 0; tries < 2000; tries++) {
        size_t live = 0U;
        size_t k;
        pthread_mutex_lock(&thr_live_lock);
        for (k = 0U; k < THR_MAX_LIVE; k++) {
            if (__atomic_load_n(&thr_live[k].ctx, __ATOMIC_ACQUIRE) !=
                NULL) {
                live++;
            }
        }
        pthread_mutex_unlock(&thr_live_lock);
        if (live <= 1U) {
            break;
        }
        (void)nanosleep(&ts, NULL);
    }
    pthread_mutex_lock(&thr_live_lock);
    for (n = 0U; n < THR_MAX_LIVE; n++) {
        sparc32_ctx_t *c = __atomic_load_n(&thr_live[n].ctx,
            __ATOMIC_ACQUIRE);
        if (c != NULL && c != survivor) {
            __atomic_store_n(&thr_live[n].ctx, NULL, __ATOMIC_RELEASE);
            thr_live[n].pt_valid = 0;
        }
    }
    pthread_mutex_unlock(&thr_live_lock);
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

static void thr_start_release(struct thr_start *st)
{
    bool last = false;
    pthread_mutex_lock(&st->lock);
    if (--st->refs == 0) {
        last = true;
    }
    pthread_mutex_unlock(&st->lock);
    if (last) {
        pthread_mutex_destroy(&st->lock);
        pthread_cond_destroy(&st->ready);
        free(st);
    }
}

static void thr_thread_finish(struct thr_start *st, long status)
{
    sparc32_ctx_t *ctx = st->ctx;
    bool retired = thr_retired_contains(ctx);
    if (!retired && st->clear_tid_va != 0U &&
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
    thr_start_release(st);
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
    pthread_mutex_lock(&thr_live_lock);
    thr_live_set_pt_locked(ctx, pthread_self());
    pthread_mutex_unlock(&thr_live_lock);
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
        if (sparc32_thr_is_retired(ctx)) {
            thr_thread_finish(st, 0L);
            return NULL;
        }
        while (ctx->exit_reason == SPARC32_EXIT_NONE) {
            /* Inner-loop retire poll (S32-R3-4 follow-up #4): a
             * compute-bound sibling never reaches a syscall, so the
             * outer-loop check alone would never fire. */
            if (sparc32_thr_is_retired(ctx)) {
                thr_thread_finish(st, 0L);
                return NULL;
            }
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
    if (atomic_load_explicit(&g_exec_retiring, memory_order_acquire)) {
        return -EAGAIN;
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
    /* A fresh clone thread owns no alternate stack (explicit clone
     * inheritance rule); it inherits the blocked mask. */
    child->altstack_flags = 0U;
    child->altstack_sp = 0U;
    child->altstack_size = 0U;
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
    st->refs = 2;
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
    /* Record the child's pthread for non-Linux wakeup (S32-R4-8); the
     * child entry refreshes the same slot via pthread_self(). */
    pthread_mutex_lock(&thr_live_lock);
    thr_live_set_pt_locked(child, th);
    pthread_mutex_unlock(&thr_live_lock);
    /* Rendezvous on the real kernel TID (reported as the clone return
     * value and stored to parent_tidptr). Refcounted (S32-R4-1): the
     * parent drops one ref here, the child drops the other at finish;
     * only the last to reach zero destroys lock/cond and frees st. */
    pthread_mutex_lock(&st->lock);
    while (!st->tid_ready) {
        pthread_cond_wait(&st->ready, &st->lock);
    }
    child_tid = st->child_tid;
    pthread_mutex_unlock(&st->lock);
    thr_start_release(st);
    if ((flags & THR_CLONE_PARENT_SETTID) != 0U && parent_tid_va != 0U) {
        (void)thr_st(ctx, parent_tid_va, (uint32_t)child_tid);
    }
    ctx->r[SPARC32_O1] = 0U;
    return child_tid;
}

/* The kill family (kill/tkill/tgkill, gettid, set_tid_address)
 * lives in threads_kill.c (split for the 900-line file discipline);
 * it shares the registry above through thr_live_enter/leave/find. */
