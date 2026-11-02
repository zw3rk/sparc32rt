/*
 * src/os/threads.h — Phase-4 process/thread machinery (lane L4a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Helpers behind the new syscalls_min.c case arms (fork/pipe/pipe2/
 * wait4/waitpid/clone/vfork/execve/set_tid_address/kill/tkill/tgkill/
 * rt_sigpending/rt_sigsuspend) plus the async-signal note path and the
 * interp safe-point poll (defined in interp/interp_signal.c).
 *
 * Return convention: host-style (>= 0 value, negative host errno); the
 * syscalls_min.c carry commit translates. Dual-return syscalls (pipe,
 * fork) also fill ctx->r[SPARC32_O1] directly; the shared tail commits
 * %o0 from the return value and advances pc = npc; npc += 4.
 *
 * Pending-signal routing (S32-R3-1, S32-R3-7): the async host handler
 * only sets the process-pending word (stable storage, never a live
 * context pointer). Thread-directed signals set the target context's
 * own pending bit. The safe-point poll delivers thread bits first and
 * then atomically claims one process bit, so each host signal invokes
 * the guest handler exactly once.
 *
 * Signal bit layout: kernel sigset order. Signal s (1..64) lives in bit
 * ((s - 1) % 32) of word (s <= 32 ? high : low) of the u64 mask, the
 * exact blocked-mask format, so per-thread ctx->sig_mask is the whole
 * mask (S32-R3-5: no process-global merge).
 */
static inline uint64_t sparc32_thr_sigbit(int sig)
{
    uint64_t bit = 1ULL << (uint64_t)((uint32_t)(sig - 1) % 32U);
    if ((uint32_t)sig <= 32U) {
        bit <<= 32U;
    }
    return bit;
}

#ifndef SPARC32RT_OS_THREADS_H
#define SPARC32RT_OS_THREADS_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "sparc32rt.h"

/* clone(217) flags (Linux arch-independent values; tls arrives in o3). */
#define THR_CLONE_VM 0x00000100U
#define THR_CLONE_FS 0x00000200U
#define THR_CLONE_FILES 0x00000400U
#define THR_CLONE_SIGHAND 0x00000800U
#define THR_CLONE_THREAD 0x00010000U
#define THR_CLONE_PARENT_SETTID 0x00100000U
#define THR_CLONE_CHILD_CLEARTID 0x00200000U
#define THR_CLONE_SETTLS 0x00080000U
#define THR_CLONE_VFORK 0x00004000U
#define THR_CLONE_SYSVSEM 0x00040000U
#define THR_CLONE_UNTRACED 0x00800000U

/* Clone rendezvous between the returning parent and the started child. */
struct thr_start {
    sparc32_ctx_t *ctx;
    uint32_t clear_tid_va;
    uint32_t child_tid_va;
    bool flags_cleartid;
    pthread_mutex_t lock;
    pthread_cond_t ready;
    bool tid_ready;
    long child_tid;
    uint32_t winfile[SPARC32_NWINDOWS][16];
    uint32_t winsp[SPARC32_NWINDOWS];
    uint32_t win_valid[SPARC32_NWINDOWS];
};

void interp_window_clone_save(uint32_t wf[SPARC32_NWINDOWS][16],
    uint32_t wsp[SPARC32_NWINDOWS], uint32_t wv[SPARC32_NWINDOWS]);
void interp_window_clone_restore(const uint32_t wf[SPARC32_NWINDOWS][16],
    const uint32_t wsp[SPARC32_NWINDOWS],
    const uint32_t wv[SPARC32_NWINDOWS]);
long sparc32_thr_gettid(sparc32_ctx_t *ctx);

/* Live-context registry + async host-signal install. Idempotent; called
 * from every helper (notably the completed set_tid_address arm, which
 * musl startup always issues, so plain static binaries get async
 * coverage without issuing any other L4a syscall). Host dispositions
 * are installed lazily by rt_sigaction; ensure_init only registers. */
void sparc32_threads_ensure_init(sparc32_ctx_t *ctx);

/* Async host handler (installed per caught signal by rt_sigaction):
 * sets the process-pending bit. Never touches live contexts. */
void sparc32_thr_host_handler(int sig);

/* Process-directed note (async-signal-safe): set the stable
 * process-pending bit. Never dereferences a live context. */
void sparc32_thr_note_signal(int sig);

/* Thread-directed note: set one context's own pending bit. Takes the
 * live lock unless the caller already holds it. */
void sparc32_thr_note_thread(sparc32_ctx_t *ctx, int sig);

/* Atomically claim one process-pending bit for delivery; true when
 * this caller won it (exactly one claimant per host signal). */
bool sparc32_thr_claim_global(int sig);

/* True when any live context holds the thread bit for sig (echo
 * attribution for claimed process bits). */
bool sparc32_thr_thread_has_pending(int sig);

/* Discard a signal from both queues (SIG_IGN installs, exec reset). */
void sparc32_thr_discard_signal(sparc32_ctx_t *ctx, int sig);

/* True when the context or the process queue holds a signal (poll guard). */
bool sparc32_thr_has_pending(const sparc32_ctx_t *ctx);

/* Snapshot the process-pending word (sigpending union, no consume). */
uint64_t sparc32_thr_process_pending(void);

/* Drop every process-pending bit (exec reset). */
void sparc32_thr_clear_process_pending(void);

/* Strip unblockable signals (SIGKILL/SIGSTOP) from a mask value. */
uint64_t sparc32_thr_mask_sanitize(uint64_t mask);

/* Fork/exec coordination: the lock order is thr_live_lock ->
 * g_dbt_lock -> VM spinlock everywhere. */
void sparc32_thr_fork_prepare(void);
void sparc32_thr_fork_parent(void);
void sparc32_thr_fork_child(sparc32_ctx_t *ctx);

/* execve sibling retirement: mark every context except the survivor,
 * then wait (bounded) for the marked threads to deregister. */
void sparc32_thr_exec_retire_begin(sparc32_ctx_t *survivor);
void sparc32_thr_exec_retire_wait(sparc32_ctx_t *survivor);
bool sparc32_thr_is_retired(const sparc32_ctx_t *ctx);

/* Retired-context self exit: deregister + free own context, leave the
 * process (interp_run/dbt_run retire polls; never returns). */
void sparc32_thr_self_retire(sparc32_ctx_t *ctx);

/* Per-thread blocked-mask helpers over ctx->sig_mask (kernel layout). */
int sparc32_thr_sig_blocked(const sparc32_ctx_t *ctx, int sig);
void sparc32_thr_sig_set(sparc32_ctx_t *ctx, int sig, bool blocked);

/* Guest FD close-on-exec tracking (execve sweep). */
void sparc32_fd_note_open(int fd, bool cloexec);
void sparc32_fd_note_close(int fd);
void sparc32_fd_note_dup2(int oldfd, int newfd);
void sparc32_fd_note_set_cloexec(int fd, bool cloexec);
void sparc32_fd_cloexec_sweep(void);

/* setitimer(83): ITIMER_REAL one-shot via host setitimer; VIRTUAL/PROF
 * return -EINVAL (RC4 scope). SIGALRM lands via the host handler. */
long sparc32_thr_setitimer(sparc32_ctx_t *ctx, uint32_t which,
    uint32_t new_va, uint32_t old_va);

/* Guest range check (low-guard + 4 GiB wrap), shared with exec. */
int sparc32_thr_range_ok(uint32_t va, uint32_t len);

/* Process syscalls. */
long sparc32_thr_pipe(sparc32_ctx_t *ctx);
long sparc32_thr_pipe2(sparc32_ctx_t *ctx, uint32_t fds_va, uint32_t flags);
long sparc32_thr_fork(sparc32_ctx_t *ctx);
long sparc32_thr_vfork(sparc32_ctx_t *ctx);
long sparc32_thr_wait4(sparc32_ctx_t *ctx, uint32_t pid, uint32_t wstat_va,
    uint32_t options, uint32_t rusage_va);
long sparc32_thr_waitpid(sparc32_ctx_t *ctx, uint32_t pid,
    uint32_t wstat_va, uint32_t options);
long sparc32_thr_clone(sparc32_ctx_t *ctx, uint32_t flags, uint32_t stack,
    uint32_t parent_tid_va, uint32_t tls, uint32_t child_tid_va);
long sparc32_thr_execve(sparc32_ctx_t *ctx, uint32_t path_va,
    uint32_t argv_va, uint32_t envp_va);
long sparc32_thr_kill(sparc32_ctx_t *ctx, uint32_t pid, uint32_t sig);
long sparc32_thr_tkill(sparc32_ctx_t *ctx, uint32_t tid, uint32_t sig);
long sparc32_thr_tgkill(sparc32_ctx_t *ctx, uint32_t tgid, uint32_t tid,
    uint32_t sig);
long sparc32_thr_set_tid_address(sparc32_ctx_t *ctx, uint32_t tidptr_va);
long sparc32_thr_rt_sigpending(sparc32_ctx_t *ctx, uint32_t set_va,
    uint32_t sigsetsize);
long sparc32_thr_rt_sigsuspend(sparc32_ctx_t *ctx, uint32_t set_va,
    uint32_t sigsetsize);

/* Async safe-point poll (interp/interp_signal.c): deliver the lowest
 * unblocked pending signal whose handler is installed. Returns true
 * when a delivery redirected pc (caller keeps running); false when
 * nothing was deliverable. Pure interp path; the sync fault path is
 * untouched. The coordinator wires one call at the top of interp_step
 * (RC4); clone threads already poll every step in their entry loop. */
bool interp_poll_async(sparc32_ctx_t *ctx);

/* Deliver signo now (frame built, pc redirected). Async variant carries
 * si_code SI_USER(0) / si_addr 0. Kill and friends use late delivery
 * (the tail commits the return first); sigsuspend(107) uses the
 * in-dispatch form below because its test asserts the handler ran
 * before return (count==5 immediately after). */
bool interp_try_deliver_async(sparc32_ctx_t *ctx, int signo);
bool interp_deliver_async_for_syscall(sparc32_ctx_t *ctx, int signo,
    bool carry);

#endif /* SPARC32RT_OS_THREADS_H */
