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
 * Signal bit layout: kernel sigset order. Signal s (1..64) lives in bit
 * ((s - 1) % 32) of word (s <= 32 ? high : low) of the u64 mask, i.e. the
 * exact sparc32_l2a_blocked_mask() format, so per-thread ctx->sig_mask
 * merges with the process-global mask by OR.
 */

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
};

/* Live-context registry + host async-handler install. Idempotent; called
 * from every helper (notably the completed set_tid_address arm, which
 * musl startup always issues, so plain static binaries get async
 * coverage without issuing any other L4a syscall). */
void sparc32_threads_ensure_init(sparc32_ctx_t *ctx);

/* Host-side async note (from the installed host handlers): set the
 * pending bit on every live unmasked context. Async-signal-safe. */
void sparc32_thr_note_signal(int sig);

/* Per-thread blocked-mask helpers over ctx->sig_mask (kernel layout). */
int sparc32_thr_sig_blocked(const sparc32_ctx_t *ctx, int sig);
void sparc32_thr_sig_set(sparc32_ctx_t *ctx, int sig, bool blocked);

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
long sparc32_thr_waitpid(sparc32_ctx_t *ctx, uint32_t pid, uint32_t wstat_va,
    uint32_t options);
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
