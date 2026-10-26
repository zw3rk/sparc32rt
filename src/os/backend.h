/*
 * src/os/backend.h — Complete Host OS Backend Interface (Rev 4, Wave U3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * UNIFICATION-PLAN.md Rev 4 section 6 (Wave U3 lane U3-sparc32):
 * Backend 1 (backend_linux.c): static-PIE aarch64-linux musl ELF run
 * inside hyper-linux or natively; blocking syscalls route through
 * safe_syscall_a64.S ([.L_check .. .L_svc] rewind to -LINUX_EINTR).
 * Backend 2 (backend_darwin.c): native macOS arm64 Mach-O via libSystem,
 * MAP_JIT (pthread_jit_write_protect_np), per-syscall-class
 * kqueue/wake-pipe signal-atomic blocking, 4 KiB Soft-TLB sub-page
 * protection. No Hypervisor.framework dependency.
 *
 * Resolves astra#xhigh #11 (futex pinning + Rank-1 -> Rank-7 ordering),
 * #13 and fable M10 (race-free Darwin blocking incl. rt_host_openat),
 * and fable C3 (rt_host_preempt_worker for quiescence).
 */
#ifndef SPARC32RT_OS_BACKEND_H
#define SPARC32RT_OS_BACKEND_H

#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/uio.h>

typedef enum {
    RT_BACKEND_LINUX = 1, /* Static-PIE aarch64-linux (native or hl) */
    RT_BACKEND_DARWIN = 2 /* Standalone macOS arm64 Mach-O (MAP_JIT) */
} rt_backend_kind_t;

/* 1. Backend identity & dynamic host page size (via sysconf). */
rt_backend_kind_t rt_host_backend_kind(void);
int rt_host_is_hyper_linux(void);
size_t rt_host_page_size(void); /* 4096, 16384, or 65536, never hardcoded */

/* 2. Low-level host memory primitives consumed by src/vm/vm32.c. */
int rt_host_map_anon(void *hint_addr, size_t len, int linux_prot, int fixed,
    int noreplace, void **out_host_addr);
int rt_host_map_file(void *hint_addr, size_t len, int linux_prot, int shared,
    int fixed, int host_fd, uint64_t aligned_file_offset,
    void **out_host_addr);
int rt_host_create_shared_mem(const char *name, size_t size,
    int *out_host_fd);
int rt_host_protect(void *host_addr, size_t len, int linux_prot);
int rt_host_unmap(void *host_addr, size_t len);
int rt_host_msync(void *host_addr, size_t len, int linux_flags);
int rt_host_madvise(void *host_addr, size_t len, int linux_advice);

/* 3. JIT W^X code cache allocation & thread-local APRR publication. */
void *rt_host_jit_alloc(size_t size);
void rt_host_jit_thread_init(void);
void rt_host_jit_begin_write(void *buf, size_t size);
int rt_host_jit_seal_rx(void *buf, size_t size);
void rt_host_jit_free(void *buf, size_t size);

/* 4. Per-syscall-class race-free signal-atomic blocking & preemption. */
typedef struct {
    _Atomic uint32_t sig_seq;
    _Atomic uint32_t in_commit_window;
    _Atomic uintptr_t ulock_wait_addr;
    int kqueue_fd;
    int wake_pipe_rd;
    int wake_pipe_wr;
    uint64_t host_tid;
} rt_worker_sync_t;

int rt_host_worker_sync_init(rt_worker_sync_t *ws);
void rt_host_worker_sync_destroy(rt_worker_sync_t *ws);
void rt_host_worker_notify_signal(rt_worker_sync_t *ws);
int rt_host_preempt_worker(uint64_t host_tid);

/* 5. Filesystem & descriptor operations (blocking calls take ws+seq). */
int64_t rt_host_openat(int dirfd, const char *path, int linux_flags,
    uint32_t mode, rt_worker_sync_t *ws, uint32_t expected_seq);
int64_t rt_host_close(int fd);
int64_t rt_host_read(int fd, void *buf, size_t count,
    rt_worker_sync_t *ws, uint32_t expected_seq);
int64_t rt_host_write(int fd, const void *buf, size_t count,
    rt_worker_sync_t *ws, uint32_t expected_seq);
int64_t rt_host_pread64(int fd, void *buf, size_t count, int64_t offset);
int64_t rt_host_pwrite64(int fd, const void *buf, size_t count,
    int64_t offset);
int64_t rt_host_readv(int fd, const struct iovec *iov, int iovcnt,
    rt_worker_sync_t *ws, uint32_t expected_seq);
int64_t rt_host_writev(int fd, const struct iovec *iov, int iovcnt,
    rt_worker_sync_t *ws, uint32_t expected_seq);
int64_t rt_host_lseek(int fd, int64_t offset, int linux_whence);
int64_t rt_host_fstatat(int dirfd, const char *path, void *statx_out,
    int linux_flags);
int64_t rt_host_ftruncate(int fd, int64_t length);
int64_t rt_host_fallocate(int fd, int mode, int64_t offset, int64_t len);
int64_t rt_host_sendfile(int out_fd, int in_fd, int64_t *offset,
    size_t count);
int64_t rt_host_copy_file_range(int fd_in, int64_t *off_in, int fd_out,
    int64_t *off_out, size_t len, unsigned int flags);
int64_t rt_host_fsync(int fd, int datasync_only);
int64_t rt_host_getdents64(int fd, void *dirent_buf, size_t buf_size);
int64_t rt_host_fcntl(int fd, int linux_cmd, uint64_t arg);
int64_t rt_host_ioctl(int fd, uint64_t linux_req, void *arg);
int64_t rt_host_dup(int oldfd);
int64_t rt_host_dup3(int oldfd, int newfd, int linux_flags);
int64_t rt_host_pipe2(int fds[2], int linux_flags);
int64_t rt_host_readlinkat(int dirfd, const char *path, char *buf,
    size_t bufsiz);
int64_t rt_host_unlinkat(int dirfd, const char *path, int linux_flags);
int64_t rt_host_mkdirat(int dirfd, const char *path, uint32_t mode);
int64_t rt_host_renameat2(int olddirfd, const char *oldpath, int newdirfd,
    const char *newpath, unsigned int flags);
int64_t rt_host_symlinkat(const char *target, int newdirfd,
    const char *linkpath);
int64_t rt_host_linkat(int olddirfd, const char *oldpath, int newdirfd,
    const char *newpath, int flags);
int64_t rt_host_faccessat2(int dirfd, const char *path, int mode, int flags);
int64_t rt_host_fchmodat(int dirfd, const char *path, uint32_t mode,
    int flags);
int64_t rt_host_fchownat(int dirfd, const char *path, uint32_t uid,
    uint32_t gid, int flags);
int64_t rt_host_utimensat(int dirfd, const char *path,
    const struct timespec times[2], int flags);
int64_t rt_host_getcwd(char *buf, size_t size);
int64_t rt_host_chdir(const char *path);
int64_t rt_host_fchdir(int fd);

/* 6. Networking & I/O multiplexing. */
int64_t rt_host_socket(int linux_domain, int linux_type, int protocol);
int64_t rt_host_socketpair(int linux_domain, int linux_type, int protocol,
    int sv[2]);
int64_t rt_host_bind(int fd, const void *linux_addr, uint32_t addrlen);
int64_t rt_host_connect(int fd, const void *linux_addr, uint32_t addrlen,
    rt_worker_sync_t *ws, uint32_t expected_seq);
int64_t rt_host_listen(int fd, int backlog);
int64_t rt_host_accept4(int fd, void *addr_out, uint32_t *addrlen_inout,
    int linux_flags, rt_worker_sync_t *ws, uint32_t expected_seq);
int64_t rt_host_sendto(int fd, const void *buf, size_t len, int linux_flags,
    const void *dest_addr, uint32_t addrlen, rt_worker_sync_t *ws,
    uint32_t expected_seq);
int64_t rt_host_recvfrom(int fd, void *buf, size_t len, int linux_flags,
    void *src_out, uint32_t *addrlen_inout, rt_worker_sync_t *ws,
    uint32_t expected_seq);
int64_t rt_host_getsockname(int fd, void *addr_out, uint32_t *addrlen_inout);
int64_t rt_host_getpeername(int fd, void *addr_out, uint32_t *addrlen_inout);
int64_t rt_host_setsockopt(int fd, int linux_level, int linux_optname,
    const void *optval, uint32_t optlen);
int64_t rt_host_getsockopt(int fd, int linux_level, int linux_optname,
    void *optval, uint32_t *optlen_inout);
int64_t rt_host_shutdown(int fd, int how);
int64_t rt_host_ppoll(void *pollfds, size_t nfds,
    const struct timespec *rel_timeout, const uint64_t *linux_sigmask,
    rt_worker_sync_t *ws, uint32_t expected_seq);
int64_t rt_host_epoll_create1(int linux_flags);
int64_t rt_host_epoll_ctl(int epfd, int op, int fd, const void *epoll_event);
int64_t rt_host_epoll_pwait(int epfd, void *events_out, int maxevents,
    int timeout_ms, const uint64_t *linux_sigmask, rt_worker_sync_t *ws,
    uint32_t expected_seq);

/* 7. Canonical futex key, backing pinning & lock-order-safe admission. */
typedef enum {
    RT_FUTEX_KEY_PRIVATE = 1,
    RT_FUTEX_KEY_SHARED_ANON = 2,
    RT_FUTEX_KEY_SHARED_FILE = 3
} rt_futex_key_kind_t;

typedef struct {
    uint32_t kind;
    uint32_t reserved;
    uint64_t owner_id; /* mm_id (renewed in child on fork) / shm/inode id */
    uint64_t mount_id; /* 0 for private/anon; st_dev or APFS FSID */
    uint64_t offset; /* guest VA (private) or backing offset (shared) */
} rt_futex_key_t;

int64_t rt_host_futex_wait_bitset(_Atomic uint32_t *pinned_uaddr,
    const rt_futex_key_t *key, uint32_t host_endian_val,
    const struct timespec *timeout, int is_abs_timeout, int clock_realtime,
    uint32_t bitset, rt_worker_sync_t *ws, uint32_t expected_seq);
int64_t rt_host_futex_wake_bitset(_Atomic uint32_t *pinned_uaddr,
    const rt_futex_key_t *key, int count, uint32_t bitset);
int64_t rt_host_futex_requeue(_Atomic uint32_t *pinned_uaddr1,
    const rt_futex_key_t *key1, int wake_count, const rt_futex_key_t *key2,
    int requeue_count, const uint32_t *host_endian_cmp_val);
int64_t rt_host_clock_gettime(int linux_clk_id, struct timespec *tp);
int64_t rt_host_clock_getres(int linux_clk_id, struct timespec *res);
int64_t rt_host_clock_nanosleep(int linux_clk_id, int linux_flags,
    const struct timespec *req, struct timespec *rem,
    rt_worker_sync_t *ws, uint32_t expected_seq);
int64_t rt_host_getrandom(void *buf, size_t buflen, unsigned int flags);

/* 8. Process, thread, per-worker sigaltstack, sync/async delivery. */
int rt_host_worker_altstack_init(void **out_stack_mem, size_t *out_size);
void rt_host_worker_altstack_destroy(void *stack_mem, size_t stack_size);
int rt_host_spawn_worker(void *(*fn)(void *), void *arg,
    uint64_t *out_host_tid);
int64_t rt_host_fork(void);
int64_t rt_host_execve(const char *path, char *const argv[],
    char *const envp[]);
int64_t rt_host_wait4(int64_t pid, int *status_out, int linux_options,
    void *rusage_out, rt_worker_sync_t *ws, uint32_t expected_seq);
int64_t rt_host_waitid(int idtype, int64_t id, void *siginfo_out,
    int linux_options, void *rusage_out, rt_worker_sync_t *ws,
    uint32_t expected_seq);
int64_t rt_host_kill(int64_t pid, int linux_sig);
int64_t rt_host_tgkill(int64_t tgid, int64_t tid, int linux_sig);
int rt_host_sigprocmask(int linux_how, const uint64_t *new_set,
    uint64_t *old_set);
void rt_host_exit_thread(int status) __attribute__((noreturn));
void rt_host_exit_group(int status) __attribute__((noreturn));

typedef struct {
    int linux_si_signo;
    int linux_si_code;
    uintptr_t fault_addr;
    uintptr_t host_pc;
    int is_write;
    void *host_ucontext;
} rt_host_sync_fault_t;

typedef struct {
    int linux_si_signo;
    int linux_si_code;
    int32_t sender_pid;
    uint32_t sender_uid;
    int32_t exit_status_or_sig;
    int32_t timer_overrun;
    uint64_t sigval_u64;
} rt_host_async_siginfo_t;

typedef void (*rt_host_sync_fault_fn)(const rt_host_sync_fault_t *fault);
typedef void (*rt_host_async_sig_fn)(const rt_host_async_siginfo_t *sig);
typedef void (*rt_host_preempt_fn)(void *host_ucontext);

int rt_host_install_signal_handlers(rt_host_sync_fault_fn on_sync_fault,
    rt_host_async_sig_fn on_async_sig, rt_host_preempt_fn on_preempt);

#endif /* SPARC32RT_OS_BACKEND_H */
