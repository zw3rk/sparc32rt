/*
 * src/os/threads_fd.c — Guest descriptor lifecycle (Phase 4, L4a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Guest-owned host descriptors with close-on-exec tracking (S32-R3-9):
 * every guest syscall that allocates a descriptor records it here with
 * its CLOEXEC flag (pipe/pipe2 live here; open/openat/creat/dup/dup2/
 * fcntl call in from syscalls.c; dup/dup2/pipe/pipe2 live here).
 * execve sweeps the table and closes
 * the marked entries when the replacement image commits. Translator-
 * owned descriptors (ELF plan fds, region backing fds, control pipes)
 * never enter this table, so the sweep cannot close them. The table
 * is process-global (guest threads share descriptors under CLONE_FILES)
 * and fork-inherited through COW, matching Linux semantics.
 *
 * Split from src/os/threads.c for the 900-line file discipline.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "sparc32rt.h"
#include "os/l2a_access.h"
#include "os/syscalls_min.h"
#include "os/threads.h"

/* Fixed tracking table: hosts cap guest fds far below this in practice;
 * an fd past the cap stays untracked (it leaks across exec rather than
 * risking a wrong close). */
#define THR_FD_TRACK_MAX 8192

static uint8_t thr_fd_used[THR_FD_TRACK_MAX];
static uint8_t thr_fd_cloexec[THR_FD_TRACK_MAX];
static pthread_mutex_t thr_fd_lock = PTHREAD_MUTEX_INITIALIZER;

void sparc32_fd_note_open(int fd, bool cloexec)
{
    if (fd < 0 || fd >= THR_FD_TRACK_MAX) {
        return;
    }
    pthread_mutex_lock(&thr_fd_lock);
    thr_fd_used[fd] = 1U;
    thr_fd_cloexec[fd] = cloexec ? 1U : 0U;
    pthread_mutex_unlock(&thr_fd_lock);
}

void sparc32_fd_note_close(int fd)
{
    if (fd < 0 || fd >= THR_FD_TRACK_MAX) {
        return;
    }
    pthread_mutex_lock(&thr_fd_lock);
    thr_fd_used[fd] = 0U;
    thr_fd_cloexec[fd] = 0U;
    pthread_mutex_unlock(&thr_fd_lock);
}

void sparc32_fd_note_dup2(int oldfd, int newfd)
{
    if (newfd < 0 || newfd >= THR_FD_TRACK_MAX) {
        return;
    }
    pthread_mutex_lock(&thr_fd_lock);
    if (oldfd == newfd) {
        /* dup2(fd, fd) is a no-op that keeps CLOEXEC (Linux): leave a
         * tracked flag alone, and adopt the host flag when the
         * descriptor was never tracked (S32-R3-9 follow-up #6). */
        if (thr_fd_used[newfd] == 0U) {
            int flags = fcntl(newfd, F_GETFD);
            if (flags >= 0) {
                thr_fd_used[newfd] = 1U;
                thr_fd_cloexec[newfd] =
                    ((flags & FD_CLOEXEC) != 0) ? 1U : 0U;
            }
        }
        pthread_mutex_unlock(&thr_fd_lock);
        return;
    }
    /* dup2/dup3 clear CLOEXEC on the target (Linux): the target stays
     * tracked (it is guest-owned) but no longer close-on-exec. */
    thr_fd_used[newfd] = 1U;
    thr_fd_cloexec[newfd] = 0U;
    pthread_mutex_unlock(&thr_fd_lock);
}

void sparc32_fd_note_set_cloexec(int fd, bool cloexec)
{
    /* fcntl F_SETFD: update the flag of a tracked descriptor only;
     * untracked (translator-owned) descriptors are left alone. */
    if (fd < 0 || fd >= THR_FD_TRACK_MAX) {
        return;
    }
    pthread_mutex_lock(&thr_fd_lock);
    if (thr_fd_used[fd] != 0U) {
        thr_fd_cloexec[fd] = cloexec ? 1U : 0U;
    }
    pthread_mutex_unlock(&thr_fd_lock);
}

/* Register inherited descriptors 0..2 as guest-owned (once), so a
 * later F_SETFD on stdio is honoured at exec (S32-R3-9 follow-up #6).
 * Runs at translator startup through sparc32_threads_ensure_init;
 * descriptors already closed stay untracked. */
void sparc32_fd_ensure_init(void)
{
    static bool done = false;
    int fd;
    pthread_mutex_lock(&thr_fd_lock);
    if (done) {
        pthread_mutex_unlock(&thr_fd_lock);
        return;
    }
    for (fd = 0; fd <= 2; fd++) {
        if (thr_fd_used[fd] == 0U) {
            int flags = fcntl(fd, F_GETFD);
            if (flags >= 0) {
                thr_fd_used[fd] = 1U;
                thr_fd_cloexec[fd] =
                    ((flags & FD_CLOEXEC) != 0) ? 1U : 0U;
            }
        }
    }
    done = true;
    pthread_mutex_unlock(&thr_fd_lock);
}

/* Fork coordination (S32-R3-2 follow-up #3): the child inherits this
 * mutex held across fork(), so the survivor owns and then rebuilds
 * it. The table itself survives through COW, matching Linux. */
void sparc32_fd_fork_prepare(void)
{
    pthread_mutex_lock(&thr_fd_lock);
}

void sparc32_fd_fork_parent(void)
{
    pthread_mutex_unlock(&thr_fd_lock);
}

void sparc32_fd_fork_child(void)
{
    pthread_mutex_unlock(&thr_fd_lock);
    pthread_mutex_destroy(&thr_fd_lock);
    pthread_mutex_init(&thr_fd_lock, NULL);
}

void sparc32_fd_cloexec_sweep(void)
{
    /* Close every tracked close-on-exec descriptor. Untracked fds
     * (stdio, translator backing fds) and non-CLOEXEC guest fds
     * survive, matching kernel exec semantics. A close failure
     * (raced guest close) just untracks the entry. */
    int fd;
    for (fd = 0; fd < THR_FD_TRACK_MAX; fd++) {
        bool sweep = false;
        pthread_mutex_lock(&thr_fd_lock);
        if (thr_fd_used[fd] != 0U && thr_fd_cloexec[fd] != 0U) {
            thr_fd_used[fd] = 0U;
            thr_fd_cloexec[fd] = 0U;
            sweep = true;
        }
        pthread_mutex_unlock(&thr_fd_lock);
        if (sweep) {
            (void)close(fd);
        }
    }
}

/* Guest BE word store through the G window (local copy: threads.c keeps
 * its own for the clone/tid paths). */
static int fd_st(sparc32_ctx_t *ctx, uint32_t va, uint32_t v)
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
    sparc32_fd_note_open(fds[0], false);
    sparc32_fd_note_open(fds[1], false);
    ctx->r[SPARC32_O1] = (uint32_t)fds[1];
    return (long)fds[0];
}

/* pipe2(321): generic pointer form (oracle: dual faults EFAULT, pointer
 * succeeds). Only CLOEXEC/NONBLOCK map; else EINVAL. */
long sparc32_thr_pipe2(sparc32_ctx_t *ctx, uint32_t fds_va, uint32_t flags)
{
    int fds[2];
    int oflags = 0;
    bool cloexec = false;
    sparc32_threads_ensure_init(ctx);
    if (ctx == NULL || l2a_range_ok_prot(fds_va, 8U, 2U) != 0) {
        return -EFAULT;
    }
    if ((flags & ~0x404000U) != 0U) {
        return -EINVAL;
    }
    if ((flags & 0x400000U) != 0U) {
        oflags |= O_CLOEXEC;
        cloexec = true;
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
    if (fd_st(ctx, fds_va, (uint32_t)fds[0]) != 0 ||
        fd_st(ctx, fds_va + 4U, (uint32_t)fds[1]) != 0) {
        close(fds[0]);
        close(fds[1]);
        return -EFAULT;
    }
    sparc32_fd_note_open(fds[0], cloexec);
    sparc32_fd_note_open(fds[1], cloexec);
    return 0;
}

/* R2: dup/dup2 over host fds (the oracle implements both; both engines
 * returned ENOSYS before dispatch existed). Moved from syscalls.c: the
 * descriptors join the close-on-exec table like every other guest-
 * allocated fd (S32-R3-9). */
long sparc32_l2a_dup(uint32_t fd)
{
    int rc = dup((int)(int32_t)fd);
    if (rc < 0) {
        return -(long)errno;
    }
    /* dup clears CLOEXEC on the new descriptor. */
    sparc32_fd_note_open(rc, false);
    return (long)rc;
}

long sparc32_l2a_dup2(uint32_t oldfd, uint32_t newfd)
{
    int rc = dup2((int)(int32_t)oldfd, (int)(int32_t)newfd);
    if (rc < 0) {
        return -(long)errno;
    }
    sparc32_fd_note_dup2((int)(int32_t)oldfd, (int)(int32_t)newfd);
    return (long)rc;
}
