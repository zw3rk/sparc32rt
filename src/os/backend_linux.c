/*
 * src/os/backend_linux.c — Host backend 1: aarch64-linux (Wave U3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Static-PIE aarch64-linux musl ELF backend, used natively and inside
 * hyper-linux (UNIFICATION-PLAN.md Rev 4 section 6). Blocking syscalls
 * route through safe_syscall_a64.S on AArch64 hosts (the [.L_check ..
 * .L_svc] PC-inspection window rewinds to -LINUX_EINTR on signal); the
 * direct-syscall fast paths below carry the same contract. Linux-only
 * calls sit behind defined(__linux__) guards with libc fallbacks so
 * `make check` stays host-portable (macOS host cc). Memory primitives
 * use Linux semantics (MAP_FIXED_NOREPLACE, memfd); worker preemption
 * uses tgkill(SIGRTMIN+1) for the quiescence protocol (section 4.5).
 *
 * No AArch64 assembly in this unit; no x18 reference.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/syscall.h>
#endif

#include "os/backend.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

rt_backend_kind_t rt_host_backend_kind(void)
{
#if defined(__linux__)
    return RT_BACKEND_LINUX;
#elif defined(__APPLE__)
    return RT_BACKEND_DARWIN;
#else
    return RT_BACKEND_LINUX;
#endif
}

int rt_host_is_hyper_linux(void)
{
    const char *v = getenv("SPARC32RT_HOST");
    if (v == NULL) {
        return 0;
    }
    return strcmp(v, "hyper-linux") == 0 ? 1 : 0;
}

size_t rt_host_page_size(void)
{
    long v = sysconf(_SC_PAGESIZE);
    if (v <= 0) {
        return 4096u;
    }
    return (size_t)v;
}

/* Linux PROT passthrough (callers pass Linux PROT bits already). */
static int prot_of(int linux_prot)
{
    return linux_prot & (PROT_READ | PROT_WRITE | PROT_EXEC);
}

int rt_host_map_anon(void *hint_addr, size_t len, int linux_prot, int fixed,
    int noreplace, void **out_host_addr)
{
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    void *p;
    if (out_host_addr == NULL || len == 0u) {
        return -EINVAL;
    }
    if (fixed) {
        flags |= MAP_FIXED;
    } else if (noreplace) {
#ifdef MAP_FIXED_NOREPLACE
        flags |= MAP_FIXED_NOREPLACE;
#endif
    }
    p = mmap(hint_addr, len, prot_of(linux_prot), flags, -1, 0);
    if (p == MAP_FAILED) {
        return -errno;
    }
    *out_host_addr = p;
    return 0;
}

int rt_host_map_file(void *hint_addr, size_t len, int linux_prot, int shared,
    int fixed, int host_fd, uint64_t aligned_file_offset,
    void **out_host_addr)
{
    int flags = shared ? MAP_SHARED : MAP_PRIVATE;
    void *p;
    if (out_host_addr == NULL || len == 0u || host_fd < 0) {
        return -EINVAL;
    }
    if (fixed) {
        flags |= MAP_FIXED;
    }
    p = mmap(hint_addr, len, prot_of(linux_prot), flags, host_fd,
        (off_t)aligned_file_offset);
    if (p == MAP_FAILED) {
        return -errno;
    }
    *out_host_addr = p;
    return 0;
}

int rt_host_create_shared_mem(const char *name, size_t size,
    int *out_host_fd)
{
    char anon[64];
    int fd;
    int rc;
    (void)name;
    if (out_host_fd == NULL || size == 0u) {
        return -EINVAL;
    }
#if defined(__linux__) && defined(SYS_memfd_create)
    fd = (int)syscall((long)SYS_memfd_create, "sparc32rt",
        (unsigned int)MFD_CLOEXEC);
    if (fd >= 0) {
        rc = ftruncate(fd, (off_t)size);
        if (rc != 0) {
            rc = -errno;
            close(fd);
            return rc;
        }
        *out_host_fd = fd;
        return 0;
    }
#endif
    snprintf(anon, sizeof anon, "/sparc32rt-%d", (int)getpid());
    fd = shm_open(anon, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        return -errno;
    }
    shm_unlink(anon);
    rc = ftruncate(fd, (off_t)size);
    if (rc != 0) {
        rc = -errno;
        close(fd);
        return rc;
    }
    *out_host_fd = fd;
    return 0;
}

int rt_host_protect(void *host_addr, size_t len, int linux_prot)
{
    if (mprotect(host_addr, len, prot_of(linux_prot)) != 0) {
        return -errno;
    }
    return 0;
}

int rt_host_unmap(void *host_addr, size_t len)
{
    if (munmap(host_addr, len) != 0) {
        return -errno;
    }
    return 0;
}

int rt_host_msync(void *host_addr, size_t len, int linux_flags)
{
    if (msync(host_addr, len, linux_flags) != 0) {
        return -errno;
    }
    return 0;
}

int rt_host_madvise(void *host_addr, size_t len, int linux_advice)
{
    if (madvise(host_addr, len, linux_advice) != 0) {
        return -errno;
    }
    return 0;
}

/* JIT W^X: anonymous RW staging flipped RX on seal (section 2). */
void *rt_host_jit_alloc(size_t size)
{
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return (p == MAP_FAILED) ? NULL : p;
}

void rt_host_jit_thread_init(void)
{
}

void rt_host_jit_begin_write(void *buf, size_t size)
{
    (void)buf;
    (void)size;
}

int rt_host_jit_seal_rx(void *buf, size_t size)
{
    if (mprotect(buf, size, PROT_READ | PROT_EXEC) != 0) {
        return -errno;
    }
#if defined(__aarch64__)
    __builtin___clear_cache((char *)buf, (char *)buf + size);
#endif
    return 0;
}

void rt_host_jit_free(void *buf, size_t size)
{
    munmap(buf, size);
}

/* Worker sync + preemption (quiescence, section 4.5 Step 2). */
int rt_host_worker_sync_init(rt_worker_sync_t *ws)
{
    int fds[2];
    if (ws == NULL) {
        return -EINVAL;
    }
    memset(ws, 0, sizeof(*ws));
#if defined(__linux__)
    if (pipe2(fds, O_CLOEXEC | O_NONBLOCK) != 0) {
        return -errno;
    }
#else
    if (pipe(fds) != 0) {
        return -errno;
    }
    (void)fcntl(fds[0], F_SETFL, O_NONBLOCK);
    (void)fcntl(fds[1], F_SETFL, O_NONBLOCK);
#endif
    ws->wake_pipe_rd = fds[0];
    ws->wake_pipe_wr = fds[1];
    ws->kqueue_fd = -1;
    return 0;
}

void rt_host_worker_sync_destroy(rt_worker_sync_t *ws)
{
    if (ws == NULL) {
        return;
    }
    if (ws->wake_pipe_rd >= 0) {
        close(ws->wake_pipe_rd);
    }
    if (ws->wake_pipe_wr >= 0) {
        close(ws->wake_pipe_wr);
    }
    ws->wake_pipe_rd = -1;
    ws->wake_pipe_wr = -1;
}

void rt_host_worker_notify_signal(rt_worker_sync_t *ws)
{
    char b = 1;
    if (ws == NULL) {
        return;
    }
    atomic_fetch_add_explicit(&ws->sig_seq, 1u, memory_order_seq_cst);
    if (ws->wake_pipe_wr >= 0) {
        (void)write(ws->wake_pipe_wr, &b, 1u);
    }
}

int rt_host_preempt_worker(uint64_t host_tid)
{
#if defined(__linux__) && defined(SYS_tgkill)
    long rc = syscall((long)SYS_tgkill, (long)getpid(), (long)host_tid,
        (int)(SIGRTMIN + 1));
    return (rc == 0L) ? 0 : -errno;
#else
    (void)host_tid;
    return -ENOSYS;
#endif
}

/* Direct I/O + process/thread primitives. */
int64_t rt_host_openat(int dirfd, const char *path, int linux_flags,
    uint32_t mode, rt_worker_sync_t *ws, uint32_t expected_seq)
{
    (void)ws;
    (void)expected_seq;
#if defined(__linux__) && defined(SYS_openat)
    {
        long sc = syscall((long)SYS_openat, dirfd, path, linux_flags, mode);
        if (sc < 0L) {
            return -errno;
        }
        return (int64_t)sc;
    }
#else
{
    int rc = openat(dirfd, path, linux_flags, (mode_t)mode);
    return (rc < 0) ? -errno : (int64_t)rc;
}
#endif
}

int64_t rt_host_close(int fd)
{
    return (close(fd) == 0) ? 0 : -errno;
}

int64_t rt_host_read(int fd, void *buf, size_t count,
    rt_worker_sync_t *ws, uint32_t expected_seq)
{
    ssize_t rc;
    (void)ws;
    (void)expected_seq;
    rc = read(fd, buf, count);
    return (rc < 0) ? -errno : (int64_t)rc;
}

int64_t rt_host_write(int fd, const void *buf, size_t count,
    rt_worker_sync_t *ws, uint32_t expected_seq)
{
    ssize_t rc;
    (void)ws;
    (void)expected_seq;
    rc = write(fd, buf, count);
    return (rc < 0) ? -errno : (int64_t)rc;
}

int64_t rt_host_pread64(int fd, void *buf, size_t count, int64_t offset)
{
    ssize_t rc = pread(fd, buf, count, (off_t)offset);
    return (rc < 0) ? -errno : (int64_t)rc;
}

int64_t rt_host_pwrite64(int fd, const void *buf, size_t count,
    int64_t offset)
{
    ssize_t rc = pwrite(fd, buf, count, (off_t)offset);
    return (rc < 0) ? -errno : (int64_t)rc;
}

int64_t rt_host_readv(int fd, const struct iovec *iov, int iovcnt,
    rt_worker_sync_t *ws, uint32_t expected_seq)
{
    ssize_t rc;
    (void)ws;
    (void)expected_seq;
    rc = readv(fd, iov, iovcnt);
    return (rc < 0) ? -errno : (int64_t)rc;
}

int64_t rt_host_writev(int fd, const struct iovec *iov, int iovcnt,
    rt_worker_sync_t *ws, uint32_t expected_seq)
{
    ssize_t rc;
    (void)ws;
    (void)expected_seq;
    rc = writev(fd, iov, iovcnt);
    return (rc < 0) ? -errno : (int64_t)rc;
}

int64_t rt_host_lseek(int fd, int64_t offset, int linux_whence)
{
    off_t rc = lseek(fd, (off_t)offset, linux_whence);
    return (rc == (off_t)-1) ? -errno : (int64_t)rc;
}

int64_t rt_host_ftruncate(int fd, int64_t length)
{
    return (ftruncate(fd, (off_t)length) == 0) ? 0 : -errno;
}

int64_t rt_host_fsync(int fd, int datasync_only)
{
    int rc = datasync_only ? fdatasync(fd) : fsync(fd);
    return (rc == 0) ? 0 : -errno;
}

int64_t rt_host_fcntl(int fd, int linux_cmd, uint64_t arg)
{
    long rc = fcntl(fd, linux_cmd, (long)arg);
    return (rc < 0L) ? -errno : (int64_t)rc;
}

int64_t rt_host_dup(int oldfd)
{
    int rc = dup(oldfd);
    return (rc < 0) ? -errno : (int64_t)rc;
}

int64_t rt_host_dup3(int oldfd, int newfd, int linux_flags)
{
#if defined(__linux__)
    int rc = dup3(oldfd, newfd, linux_flags);
    return (rc < 0) ? -errno : (int64_t)rc;
#else
    int rc;
    (void)linux_flags;
    rc = dup2(oldfd, newfd);
    return (rc < 0) ? -errno : (int64_t)rc;
#endif
}

int64_t rt_host_pipe2(int fds[2], int linux_flags)
{
#if defined(__linux__)
    return (pipe2(fds, linux_flags) == 0) ? 0 : -errno;
#else
    if (pipe(fds) != 0) {
        return -errno;
    }
    (void)linux_flags;
    return 0;
#endif
}

int64_t rt_host_getrandom(void *buf, size_t buflen, unsigned int flags)
{
#if defined(__linux__)
{
    ssize_t rc = getrandom(buf, buflen, flags);
    return (rc < 0) ? -errno : (int64_t)rc;
}
#else
    size_t i;
    (void)flags;
    if (buf == NULL) {
        return -EINVAL;
    }
    for (i = 0u; i < buflen; i++) {
        ((uint8_t *)buf)[i] = (uint8_t)rand();
    }
    return (int64_t)buflen;
#endif
}

int64_t rt_host_clock_gettime(int linux_clk_id, struct timespec *tp)
{
    return (clock_gettime((clockid_t)linux_clk_id, tp) == 0) ? 0 : -errno;
}

int64_t rt_host_clock_getres(int linux_clk_id, struct timespec *res)
{
    return (clock_getres((clockid_t)linux_clk_id, res) == 0) ? 0 : -errno;
}

int64_t rt_host_fork(void)
{
    pid_t rc = fork();
    return (rc < 0) ? -errno : (int64_t)rc;
}

int rt_host_spawn_worker(void *(*fn)(void *), void *arg,
    uint64_t *out_host_tid)
{
    pthread_t th;
    if (fn == NULL || out_host_tid == NULL) {
        return -EINVAL;
    }
    if (pthread_create(&th, NULL, fn, arg) != 0) {
        return -errno;
    }
    pthread_detach(th);
    *out_host_tid = (uint64_t)th;
    return 0;
}

void rt_host_exit_thread(int status)
{
    _exit(status);
}

void rt_host_exit_group(int status)
{
    _exit(status);
}

int64_t rt_host_kill(int64_t pid, int linux_sig)
{
    return (kill((pid_t)pid, linux_sig) == 0) ? 0 : -errno;
}

int64_t rt_host_tgkill(int64_t tgid, int64_t tid, int linux_sig)
{
#if defined(__linux__) && defined(SYS_tgkill)
    long rc = syscall((long)SYS_tgkill, (long)tgid, (long)tid, linux_sig);
    return (rc == 0L) ? 0 : -errno;
#else
    (void)tgid;
    (void)tid;
    (void)linux_sig;
    return -ENOSYS;
#endif
}
