/*
 * src/os/syscalls.c — Phase-2 static-libc syscalls (lane L2a).
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 * Frozen numbers, L1c carry convention; guest structs via the G window
 * (BE stores); host-style returns. Mask is file-static (single-thread).
 * Needs _GNU_SOURCE: musl hides syscall(2)/clock_gettime under -std=c11.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

/* macOS <sys/stat.h> #defines st_atime/mtime/ctime over the frozen
 * sigframe header field names; drop them here (this TU only). */
#ifdef st_atime
#undef st_atime
#endif
#ifdef st_mtime
#undef st_mtime
#endif
#ifdef st_ctime
#undef st_ctime
#endif

#include "sparc32rt.h"
#include "os/sigframe_sparc32rt.h"
#include "os/syscall_nr.h"

/* SPARC open flags (arch/sparc fcntl.h); low 2 access bits match hosts. */
#define SP_O_APPEND 0x0008U
#define SP_O_CREAT 0x0200U
#define SP_O_TRUNC 0x0400U
#define SP_O_EXCL 0x0800U
#define SP_O_DSYNC 0x2000U
#define SP_O_SYNC 0x802000U
#define SP_O_NONBLOCK 0x4000U
#define SP_O_NDELAY 0x4004U
#define SP_O_NOCTTY 0x8000U
#define SP_O_LARGEFILE 0x40000U
#define SP_O_DIRECTORY 0x10000U
#define SP_O_NOFOLLOW 0x20000U
#define SP_O_DIRECT 0x100000U
#define SP_O_NOATIME 0x200000U
#define SP_O_CLOEXEC 0x400000U
#define SP_O_PATH 0x1000000U
#define SP_O_TMPFILE 0x2010000U

#define SP_F_DUPFD 0U
#define SP_F_GETFD 1U
#define SP_F_SETFD 2U
#define SP_F_GETFL 3U
#define SP_F_SETFL 4U

#define SP_FIONREAD 0x4004667fU
#define SP_TCGETS 0x80245408U

#define SP_CLOCK_REALTIME 0U
#define SP_CLOCK_MONOTONIC 1U

#define SP_FUTEX_WAIT 0U
#define SP_FUTEX_WAKE 1U

#define SP_SIG_BLOCK 0U
#define SP_SIG_UNBLOCK 1U
#define SP_SIG_SETMASK 2U

#define SP_GRND_NONBLOCK 0x0001U
#define SP_GRND_RANDOM 0x0002U
#define SP_GRND_INSECURE 0x0004U

#define SP_AT_FDCWD ((int32_t)-100)
#define SP_AT_SYMLINK_NOFOLLOW 0x100U
#define SP_AT_NO_AUTOMOUNT 0x800U
#define SP_AT_EMPTY_PATH 0x1000U
#define SP_AT_STATX_SYNC_TYPE 0x6000U

#define L2A_PATH_MAX 4096U
#define L2A_IOV_MAX 1024U
#define L2A_IOV_BATCH 32U

static uint32_t l2a_blocked[2] = { 0U, 0U };

uint64_t sparc32_l2a_blocked_mask(void)
{
    return ((uint64_t)l2a_blocked[0] << 32) | (uint64_t)l2a_blocked[1];
}

static void put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void put_be64(uint8_t *p, uint64_t v)
{
    put_be32(p, (uint32_t)(v >> 32));
    put_be32(p + 4, (uint32_t)v);
}

static uint32_t get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* Bounds check for [va, va+len): reject 32-bit wrap + low guard (L1c model). */
static int l2a_range_ok(uint32_t va, uint64_t len)
{
    if (len == 0U) {
        return 0;
    }
    if (len > 0x100000000ULL || (uint64_t)va + len > 0x100000000ULL) {
        return -EFAULT;
    }
    return (va < SPARC32_LOW_GUARD_SIZE) ? -EFAULT : 0;
}

/* NUL-terminated guest string -> out (0 ok, -EFAULT/-ENAMETOOLONG). */
static long l2a_copy_cstring(sparc32_ctx_t *ctx, uint32_t va, char *out,
    uint32_t cap)
{
    uint32_t i;
    if (cap == 0U || l2a_range_ok(va, 1U) != 0) {
        return (cap == 0U) ? -ENAMETOOLONG : -EFAULT;
    }
    for (i = 0U; i < cap; i++) {
        uint32_t a = va + i;
        const uint8_t *p;
        if (a < va || a < SPARC32_LOW_GUARD_SIZE) {
            return (a < va) ? -ENAMETOOLONG : -EFAULT;
        }
        p = (const uint8_t *)sparc32_guest_ptr(ctx, a);
        out[i] = (char)*p;
        if (*p == 0U) {
            return 0;
        }
    }
    out[cap - 1U] = '\0';
    return -ENAMETOOLONG;
}

static int l2a_st_be32(sparc32_ctx_t *ctx, uint32_t va, uint32_t v)
{
    if (l2a_range_ok(va, 4U) != 0) {
        return -EFAULT;
    }
    put_be32((uint8_t *)sparc32_guest_ptr(ctx, va), v);
    return 0;
}

static int l2a_store(sparc32_ctx_t *ctx, uint32_t va, const void *src,
    uint64_t len)
{
    if (l2a_range_ok(va, len) != 0) {
        return -EFAULT;
    }
    if (len != 0U) {
        memcpy(sparc32_guest_ptr(ctx, va), src, (size_t)len);
    }
    return 0;
}

/* Narrowing checks with EOVERFLOW fallback (old-stat semantics). */
static long narrow_u16(uint64_t v)
{
    return (v <= 0xFFFFULL) ? (long)v : -EOVERFLOW;
}

static long narrow_s16(int64_t v)
{
    return (v >= -32768LL && v <= 32767LL) ? (long)v : -EOVERFLOW;
}

static long narrow_u32(uint64_t v)
{
    return (v <= 0xFFFFFFFFULL) ? (long)(uint32_t)v : -EOVERFLOW;
}

static long narrow_s32(int64_t v)
{
    return (v >= -2147483648LL && v <= 2147483647LL) ? (long)(int32_t)v
                                                    : -EOVERFLOW;
}

/* Host stat times: macOS uses st_*timespec, Linux st_*tim. */
static void l2a_host_times(const struct stat *h, int which, int64_t *sec,
    int64_t *nsec)
{
#if defined(__APPLE__)
    const struct timespec *t = (which == 0) ? &h->st_atimespec
        : ((which == 1) ? &h->st_mtimespec : &h->st_ctimespec);
#else
    const struct timespec *t = (which == 0) ? &h->st_atim
        : ((which == 1) ? &h->st_mtim : &h->st_ctim);
#endif
    *sec = (int64_t)t->tv_sec;
    *nsec = (int64_t)t->tv_nsec;
}

/* SPARC O_* -> host O_*. Unknown bits are EINVAL; O_DSYNC maps to O_SYNC. */
static long open_flags_to_host(uint32_t guest, int *host_out)
{
    uint32_t rest = guest & ~3U;
    size_t i;
    int h = (int)(guest & 3U);
    static const struct {
        uint32_t guest;
        int host;
    } map[] = {
        { SP_O_APPEND, O_APPEND }, { SP_O_CREAT, O_CREAT },
        { SP_O_TRUNC, O_TRUNC }, { SP_O_EXCL, O_EXCL },
        { SP_O_NONBLOCK, O_NONBLOCK }, { SP_O_NDELAY, O_NONBLOCK },
        { SP_O_NOCTTY, O_NOCTTY }, { SP_O_DIRECTORY, O_DIRECTORY },
        { SP_O_NOFOLLOW, O_NOFOLLOW }, { SP_O_CLOEXEC, O_CLOEXEC },
#ifdef O_LARGEFILE
        { SP_O_LARGEFILE, O_LARGEFILE },
#endif
#ifdef O_DIRECT
        { SP_O_DIRECT, O_DIRECT },
#endif
#ifdef O_NOATIME
        { SP_O_NOATIME, O_NOATIME },
#endif
#ifdef O_PATH
        { SP_O_PATH, O_PATH },
#endif
#ifdef O_TMPFILE
        { SP_O_TMPFILE, O_TMPFILE },
#endif
    };
    if ((rest & (SP_O_SYNC | SP_O_DSYNC)) != 0U) {
#ifdef O_SYNC
        h |= O_SYNC;
        rest &= ~(SP_O_SYNC | SP_O_DSYNC);
#else
        return -EINVAL;
#endif
    }
    for (i = 0U; i < sizeof(map) / sizeof(map[0]); i++) {
        if ((rest & map[i].guest) != 0U) {
            h |= map[i].host;
            rest &= ~map[i].guest;
        }
    }
#ifndef O_LARGEFILE
    rest &= ~SP_O_LARGEFILE; /* 64-bit hosts: largefile is the default */
#endif
    if (rest != 0U) {
        return -EINVAL;
    }
    *host_out = h;
    return 0;
}

static long sys_openat(sparc32_ctx_t *ctx, int32_t dirfd, uint32_t path_va,
    uint32_t flags, uint32_t mode)
{
    char path[L2A_PATH_MAX];
    long rc = l2a_copy_cstring(ctx, path_va, path, L2A_PATH_MAX);
    int host_flags;
    int fd;
    if (rc != 0) {
        return rc;
    }
    rc = open_flags_to_host(flags, &host_flags);
    if (rc != 0) {
        return rc;
    }
    fd = openat((dirfd == SP_AT_FDCWD) ? AT_FDCWD : (int)dirfd, path,
        host_flags, (mode_t)(mode & 0777U));
    return (fd < 0) ? -(long)errno : (long)fd;
}

long sparc32_l2a_openat(sparc32_ctx_t *ctx, uint32_t dirfd, uint32_t path_va,
    uint32_t flags, uint32_t mode)
{
    return sys_openat(ctx, (int32_t)dirfd, path_va, flags, mode);
}

long sparc32_l2a_open(sparc32_ctx_t *ctx, uint32_t path_va, uint32_t flags,
    uint32_t mode)
{
    return sys_openat(ctx, SP_AT_FDCWD, path_va, flags, mode);
}

long sparc32_l2a_creat(sparc32_ctx_t *ctx, uint32_t path_va, uint32_t mode)
{
    char path[L2A_PATH_MAX];
    long rc = l2a_copy_cstring(ctx, path_va, path, L2A_PATH_MAX);
    int fd;
    if (rc != 0) {
        return rc;
    }
    fd = openat(AT_FDCWD, path, O_CREAT | O_WRONLY | O_TRUNC,
        (mode_t)(mode & 0777U));
    return (fd < 0) ? -(long)errno : (long)fd;
}

long sparc32_l2a_close(int fd)
{
    return (close(fd) != 0) ? -(long)errno : 0;
}

long sparc32_l2a_unlink(sparc32_ctx_t *ctx, uint32_t path_va)
{
    char path[L2A_PATH_MAX];
    long rc = l2a_copy_cstring(ctx, path_va, path, L2A_PATH_MAX);
    if (rc != 0) {
        return rc;
    }
    return (unlink(path) != 0) ? -(long)errno : 0;
}

long sparc32_l2a_lseek(uint32_t fd, int32_t offset, uint32_t whence)
{
    off_t rc;
    int host_whence;
    switch (whence) {
    case 0U: host_whence = SEEK_SET; break;
    case 1U: host_whence = SEEK_CUR; break;
    case 2U: host_whence = SEEK_END; break;
    default: return -EINVAL;
    }
    rc = lseek((int)fd, (off_t)offset, host_whence);
    if (rc == (off_t)-1) {
        return -(long)errno;
    }
    return (rc > (off_t)2147483647L || rc < (off_t)-2147483648L) ? -EOVERFLOW
                                                                : (long)rc;
}

long sparc32_l2a_getpid(void)
{
    return (long)getpid();
}

long sparc32_l2a_getuid(void)
{
    return (long)getuid();
}

long sparc32_l2a_geteuid(void)
{
    return (long)geteuid();
}

long sparc32_l2a_getgid(void)
{
    return (long)getgid();
}

long sparc32_l2a_getegid(void)
{
    return (long)getegid();
}

/* readv/writev over guest iovec chains ({BE base, BE len} x iovcnt). */
static long sys_rwvec(sparc32_ctx_t *ctx, uint32_t fd, uint32_t iov_va,
    uint32_t iovcnt, int is_write)
{
    uint64_t total = 0ULL;
    uint32_t i = 0U;
    if (iovcnt > L2A_IOV_MAX) {
        return -EINVAL;
    }
    if (iovcnt == 0U) {
        return 0;
    }
    if (l2a_range_ok(iov_va, (uint64_t)iovcnt * 8U) != 0) {
        return -EFAULT;
    }
    while (i < iovcnt) {
        struct iovec host[L2A_IOV_BATCH];
        uint64_t want = 0ULL;
        uint32_t n = 0U;
        uint32_t j;
        ssize_t rc;
        for (j = 0U; j < L2A_IOV_BATCH && i + j < iovcnt; j++) {
            const uint8_t *e = (const uint8_t *)sparc32_guest_ptr(ctx,
                iov_va + (uint64_t)(i + j) * 8U);
            uint32_t base = get_be32(e);
            uint32_t len = get_be32(e + 4);
            if (l2a_range_ok(base, len) != 0) {
                return (total != 0ULL) ? (long)total : -EFAULT;
            }
            if (len == 0U) {
                continue;
            }
            host[n].iov_base = sparc32_guest_ptr(ctx, base);
            host[n].iov_len = (size_t)len;
            n++; want += (uint64_t)len;
        }
        if (n == 0U) {
            i += L2A_IOV_BATCH;
            continue;
        }
        rc = is_write ? writev((int)fd, host, (int)n)
                      : readv((int)fd, host, (int)n);
        if (rc < 0) {
            return (total != 0ULL) ? (long)total : -(long)errno;
        }
        total += (uint64_t)rc;
        i += L2A_IOV_BATCH;
        if ((uint64_t)rc < want) {
            break; /* short count terminates the vector walk */
        }
    }
    return (long)total;
}

long sparc32_l2a_readv(sparc32_ctx_t *ctx, uint32_t fd, uint32_t iov_va,
    uint32_t iovcnt)
{
    return sys_rwvec(ctx, fd, iov_va, iovcnt, 0);
}

long sparc32_l2a_writev(sparc32_ctx_t *ctx, uint32_t fd, uint32_t iov_va,
    uint32_t iovcnt)
{
    return sys_rwvec(ctx, fd, iov_va, iovcnt, 1);
}

/* stat family: host fstatat/fstat converted into the frozen BE layouts. */
#define PUT16(off, expr) do { long _v = (expr); \
    if (_v < 0) { return _v; } put_be16(b + (off), (uint16_t)_v); } while (0)
#define PUT32(off, expr) do { long _v = (expr); \
    if (_v < 0) { return _v; } put_be32(b + (off), (uint32_t)_v); } while (0)

static long store_stat32(sparc32_ctx_t *ctx, uint32_t va, const struct stat *h)
{
    uint8_t b[sizeof(sparc32_stat_t)];
    int64_t sec;
    int64_t nsec;
    memset(b, 0, sizeof(b));
    PUT16(offsetof(sparc32_stat_t, st_dev), narrow_u16((uint64_t)h->st_dev));
    PUT32(offsetof(sparc32_stat_t, st_ino), narrow_u32((uint64_t)h->st_ino));
    put_be32(b + offsetof(sparc32_stat_t, st_mode), (uint32_t)h->st_mode);
    PUT16(offsetof(sparc32_stat_t, st_nlink), narrow_s16((int64_t)h->st_nlink));
    PUT16(offsetof(sparc32_stat_t, st_uid), narrow_u16((uint64_t)h->st_uid));
    PUT16(offsetof(sparc32_stat_t, st_gid), narrow_u16((uint64_t)h->st_gid));
    PUT16(offsetof(sparc32_stat_t, st_rdev), narrow_u16((uint64_t)h->st_rdev));
    PUT32(offsetof(sparc32_stat_t, st_size), narrow_s32((int64_t)h->st_size));
    l2a_host_times(h, 0, &sec, &nsec);
    PUT32(offsetof(sparc32_stat_t, st_atime), narrow_s32(sec));
    put_be32(b + offsetof(sparc32_stat_t, st_atime_nsec), (uint32_t)nsec);
    l2a_host_times(h, 1, &sec, &nsec);
    PUT32(offsetof(sparc32_stat_t, st_mtime), narrow_s32(sec));
    put_be32(b + offsetof(sparc32_stat_t, st_mtime_nsec), (uint32_t)nsec);
    l2a_host_times(h, 2, &sec, &nsec);
    PUT32(offsetof(sparc32_stat_t, st_ctime), narrow_s32(sec));
    put_be32(b + offsetof(sparc32_stat_t, st_ctime_nsec), (uint32_t)nsec);
    PUT32(offsetof(sparc32_stat_t, st_blksize),
        narrow_s32((int64_t)h->st_blksize));
    PUT32(offsetof(sparc32_stat_t, st_blocks),
        narrow_s32((int64_t)h->st_blocks));
    return l2a_store(ctx, va, b, sizeof(b));
}

static long store_stat64(sparc32_ctx_t *ctx, uint32_t va, const struct stat *h)
{
    uint8_t b[sizeof(sparc32_stat64_t)];
    int64_t sec;
    int64_t nsec;
    memset(b, 0, sizeof(b));
    put_be64(b + offsetof(sparc32_stat64_t, st_dev), (uint64_t)h->st_dev);
    put_be64(b + offsetof(sparc32_stat64_t, st_ino), (uint64_t)h->st_ino);
    put_be32(b + offsetof(sparc32_stat64_t, st_mode), (uint32_t)h->st_mode);
    PUT32(offsetof(sparc32_stat64_t, st_nlink),
        narrow_u32((uint64_t)h->st_nlink));
    put_be32(b + offsetof(sparc32_stat64_t, st_uid), (uint32_t)h->st_uid);
    put_be32(b + offsetof(sparc32_stat64_t, st_gid), (uint32_t)h->st_gid);
    put_be64(b + offsetof(sparc32_stat64_t, st_rdev), (uint64_t)h->st_rdev);
    put_be64(b + offsetof(sparc32_stat64_t, st_size), (uint64_t)h->st_size);
    PUT32(offsetof(sparc32_stat64_t, st_blksize),
        narrow_u32((uint64_t)h->st_blksize));
    /* NOTE the kernel quirk: st_blocks stays 32-bit on 32-bit sparc. */
    PUT32(offsetof(sparc32_stat64_t, st_blocks),
        narrow_u32((uint64_t)h->st_blocks));
    l2a_host_times(h, 0, &sec, &nsec);
    PUT32(offsetof(sparc32_stat64_t, st_atime), narrow_u32((uint64_t)sec));
    put_be32(b + offsetof(sparc32_stat64_t, st_atime_nsec), (uint32_t)nsec);
    l2a_host_times(h, 1, &sec, &nsec);
    PUT32(offsetof(sparc32_stat64_t, st_mtime), narrow_u32((uint64_t)sec));
    put_be32(b + offsetof(sparc32_stat64_t, st_mtime_nsec), (uint32_t)nsec);
    l2a_host_times(h, 2, &sec, &nsec);
    PUT32(offsetof(sparc32_stat64_t, st_ctime), narrow_u32((uint64_t)sec));
    put_be32(b + offsetof(sparc32_stat64_t, st_ctime_nsec), (uint32_t)nsec);
    return l2a_store(ctx, va, b, sizeof(b));
}

static long sys_stat_path(sparc32_ctx_t *ctx, const char *path, int dirfd,
    int nofollow, uint32_t buf_va, int is64)
{
    struct stat h;
    if (fstatat(dirfd, path, &h, nofollow ? AT_SYMLINK_NOFOLLOW : 0) != 0) {
        return -(long)errno;
    }
    return is64 ? store_stat64(ctx, buf_va, &h) : store_stat32(ctx, buf_va, &h);
}

long sparc32_l2a_stat(sparc32_ctx_t *ctx, uint32_t path_va, uint32_t buf_va)
{
    char path[L2A_PATH_MAX];
    long rc = l2a_copy_cstring(ctx, path_va, path, L2A_PATH_MAX);
    return (rc != 0) ? rc : sys_stat_path(ctx, path, AT_FDCWD, 0, buf_va, 0);
}

long sparc32_l2a_lstat(sparc32_ctx_t *ctx, uint32_t path_va, uint32_t buf_va)
{
    char path[L2A_PATH_MAX];
    long rc = l2a_copy_cstring(ctx, path_va, path, L2A_PATH_MAX);
    return (rc != 0) ? rc : sys_stat_path(ctx, path, AT_FDCWD, 1, buf_va, 0);
}

long sparc32_l2a_fstat(sparc32_ctx_t *ctx, uint32_t fd, uint32_t buf_va)
{
    struct stat h;
    if (fstat((int)fd, &h) != 0) {
        return -(long)errno;
    }
    return store_stat32(ctx, buf_va, &h);
}

long sparc32_l2a_stat64(sparc32_ctx_t *ctx, uint32_t path_va, uint32_t buf_va)
{
    char path[L2A_PATH_MAX];
    long rc = l2a_copy_cstring(ctx, path_va, path, L2A_PATH_MAX);
    return (rc != 0) ? rc : sys_stat_path(ctx, path, AT_FDCWD, 0, buf_va, 1);
}

long sparc32_l2a_lstat64(sparc32_ctx_t *ctx, uint32_t path_va, uint32_t buf_va)
{
    char path[L2A_PATH_MAX];
    long rc = l2a_copy_cstring(ctx, path_va, path, L2A_PATH_MAX);
    return (rc != 0) ? rc : sys_stat_path(ctx, path, AT_FDCWD, 1, buf_va, 1);
}

long sparc32_l2a_fstat64(sparc32_ctx_t *ctx, uint32_t fd, uint32_t buf_va)
{
    struct stat h;
    if (fstat((int)fd, &h) != 0) {
        return -(long)errno;
    }
    return store_stat64(ctx, buf_va, &h);
}

long sparc32_l2a_fstatat64(sparc32_ctx_t *ctx, uint32_t dirfd,
    uint32_t path_va, uint32_t buf_va, uint32_t flags)
{
    char path[L2A_PATH_MAX];
    struct stat h;
    long rc = l2a_copy_cstring(ctx, path_va, path, L2A_PATH_MAX);
    int host_flags = 0;
    int host_dirfd;
    if (rc != 0) {
        return rc;
    }
    if ((flags & ~(SP_AT_SYMLINK_NOFOLLOW | SP_AT_NO_AUTOMOUNT |
            SP_AT_EMPTY_PATH)) != 0U) {
        return -EINVAL;
    }
    if ((flags & SP_AT_SYMLINK_NOFOLLOW) != 0U) {
        host_flags |= AT_SYMLINK_NOFOLLOW;
    }
#ifdef AT_NO_AUTOMOUNT
    if ((flags & SP_AT_NO_AUTOMOUNT) != 0U) {
        host_flags |= AT_NO_AUTOMOUNT;
    }
#endif
#ifdef AT_EMPTY_PATH
    if ((flags & SP_AT_EMPTY_PATH) != 0U) {
        host_flags |= AT_EMPTY_PATH;
    }
#endif
    host_dirfd = ((int32_t)dirfd == SP_AT_FDCWD) ? AT_FDCWD : (int)(int32_t)dirfd;
    if (fstatat(host_dirfd, path, &h, host_flags) != 0) {
        return -(long)errno;
    }
    return store_stat64(ctx, buf_va, &h);
}

/* statx: guest is the asm-generic 256 B layout; host via raw SYS_statx. */
enum {
    STX_OFF_MASK = 0, STX_OFF_BLKSIZE = 4, STX_OFF_ATTR = 8,
    STX_OFF_NLINK = 16, STX_OFF_UID = 20, STX_OFF_GID = 24, STX_OFF_MODE = 28,
    STX_OFF_INO = 32, STX_OFF_SIZE = 40, STX_OFF_BLOCKS = 48,
    STX_OFF_ATTRMASK = 56, STX_OFF_ATIME = 64, STX_OFF_BTIME = 80,
    STX_OFF_CTIME = 96, STX_OFF_MTIME = 112, STX_OFF_RDEVMAJ = 128,
    STX_OFF_RDEVMIN = 132, STX_OFF_DEVMAJ = 136, STX_OFF_DEVMIN = 140,
    STX_OFF_MNTID = 144, STX_SIZE = 256
};

#if defined(__linux__) && defined(SYS_statx)
struct l2a_host_statx_ts {
    int64_t tv_sec; uint32_t tv_nsec; int32_t __reserved;
};

struct l2a_host_statx {
    uint32_t stx_mask, stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink, stx_uid, stx_gid;
    uint16_t stx_mode, __spare0[1];
    uint64_t stx_ino, stx_size, stx_blocks, stx_attributes_mask;
    struct l2a_host_statx_ts stx_atime, stx_btime, stx_ctime, stx_mtime;
    uint32_t stx_rdev_major, stx_rdev_minor, stx_dev_major, stx_dev_minor;
    uint64_t stx_mnt_id, __spare2, __spare3[12];
};

static void put_statx_ts(uint8_t *b, uint32_t off, int64_t sec, uint64_t nsec)
{
    put_be64(b + off, (sec < 0) ? 0U : (uint64_t)sec);
    put_be32(b + off + 8, (uint32_t)nsec);
    put_be32(b + off + 12, 0U);
}
#endif

long sparc32_l2a_statx(sparc32_ctx_t *ctx, uint32_t dirfd, uint32_t path_va,
    uint32_t flags, uint32_t mask, uint32_t buf_va)
{
#if defined(__linux__) && defined(SYS_statx)
    char path[L2A_PATH_MAX];
    struct l2a_host_statx h;
    uint8_t b[STX_SIZE];
    long rc = l2a_copy_cstring(ctx, path_va, path, L2A_PATH_MAX);
    int host_flags = 0;
    int host_dirfd;
    if (rc != 0) {
        return rc;
    }
    if ((flags & ~(SP_AT_SYMLINK_NOFOLLOW | SP_AT_NO_AUTOMOUNT |
            SP_AT_EMPTY_PATH | SP_AT_STATX_SYNC_TYPE)) != 0U) {
        return -EINVAL;
    }
    if ((flags & SP_AT_SYMLINK_NOFOLLOW) != 0U) {
        host_flags |= AT_SYMLINK_NOFOLLOW;
    }
#ifdef AT_NO_AUTOMOUNT
    if ((flags & SP_AT_NO_AUTOMOUNT) != 0U) {
        host_flags |= AT_NO_AUTOMOUNT;
    }
#endif
#ifdef AT_EMPTY_PATH
    if ((flags & SP_AT_EMPTY_PATH) != 0U) {
        host_flags |= AT_EMPTY_PATH;
    }
#endif
    host_flags |= (int)(flags & SP_AT_STATX_SYNC_TYPE);
    host_dirfd = ((int32_t)dirfd == SP_AT_FDCWD) ? AT_FDCWD : (int)(int32_t)dirfd;
    memset(&h, 0, sizeof(h));
    if (syscall(SYS_statx, host_dirfd, path, host_flags, (unsigned int)mask,
            &h) != 0) {
        return ((long)errno == 0) ? -ENOSYS : -(long)errno;
    }
    memset(b, 0, sizeof(b));
    put_be32(b + STX_OFF_MASK, h.stx_mask);
    put_be32(b + STX_OFF_BLKSIZE, h.stx_blksize);
    put_be64(b + STX_OFF_ATTR, h.stx_attributes);
    put_be32(b + STX_OFF_NLINK, h.stx_nlink);
    put_be32(b + STX_OFF_UID, h.stx_uid);
    put_be32(b + STX_OFF_GID, h.stx_gid);
    put_be16(b + STX_OFF_MODE, h.stx_mode);
    put_be64(b + STX_OFF_INO, h.stx_ino);
    put_be64(b + STX_OFF_SIZE, h.stx_size);
    put_be64(b + STX_OFF_BLOCKS, h.stx_blocks);
    put_be64(b + STX_OFF_ATTRMASK, h.stx_attributes_mask);
    put_statx_ts(b, STX_OFF_ATIME, h.stx_atime.tv_sec, h.stx_atime.tv_nsec);
    put_statx_ts(b, STX_OFF_BTIME, h.stx_btime.tv_sec, h.stx_btime.tv_nsec);
    put_statx_ts(b, STX_OFF_CTIME, h.stx_ctime.tv_sec, h.stx_ctime.tv_nsec);
    put_statx_ts(b, STX_OFF_MTIME, h.stx_mtime.tv_sec, h.stx_mtime.tv_nsec);
    put_be32(b + STX_OFF_RDEVMAJ, h.stx_rdev_major);
    put_be32(b + STX_OFF_RDEVMIN, h.stx_rdev_minor);
    put_be32(b + STX_OFF_DEVMAJ, h.stx_dev_major);
    put_be32(b + STX_OFF_DEVMIN, h.stx_dev_minor);
    put_be64(b + STX_OFF_MNTID, h.stx_mnt_id);
    return l2a_store(ctx, buf_va, b, sizeof(b));
#else
    (void)ctx; (void)dirfd; (void)path_va;
    (void)flags; (void)mask; (void)buf_va;
    return -ENOSYS;
#endif
}

static long flags_host_to_guest(int host)
{
    uint32_t g = (uint32_t)(host & 3);
    if ((host & O_APPEND) != 0) {
        g |= SP_O_APPEND;
    }
    if ((host & O_NONBLOCK) != 0) {
        g |= SP_O_NONBLOCK;
    }
#ifdef O_SYNC
    if ((host & O_SYNC) != 0) {
        g |= SP_O_SYNC;
    }
#endif
    return (long)g;
}

long sparc32_l2a_fcntl(uint32_t fd, uint32_t cmd, uint32_t arg)
{
    int rc;
    switch (cmd) {
    case SP_F_DUPFD:
        rc = fcntl((int)fd, F_DUPFD, (int)arg);
        return (rc < 0) ? -(long)errno : (long)rc;
    case SP_F_GETFD:
        rc = fcntl((int)fd, F_GETFD);
        return (rc < 0) ? -(long)errno : (long)rc;
    case SP_F_SETFD:
        return (fcntl((int)fd, F_SETFD, (int)arg) != 0) ? -(long)errno : 0;
    case SP_F_GETFL:
        rc = fcntl((int)fd, F_GETFL);
        return (rc < 0) ? -(long)errno : flags_host_to_guest(rc);
    case SP_F_SETFL: {
        int host = 0;
        if ((arg & ~(SP_O_NONBLOCK | SP_O_APPEND)) != 0U) {
            return -EINVAL; /* only O_NONBLOCK|O_APPEND are settable */
        }
        if ((arg & SP_O_APPEND) != 0U) {
            host |= O_APPEND;
        }
        if ((arg & SP_O_NONBLOCK) != 0U) {
            host |= O_NONBLOCK;
        }
        return (fcntl((int)fd, F_SETFL, host) != 0) ? -(long)errno : 0;
    }
    default:
        return -EINVAL;
    }
}

/* Guest buffer is __kernel_timespec: BE u64 tv_sec, BE u32 tv_nsec, 4 B pad. */
long sparc32_l2a_clock_gettime(sparc32_ctx_t *ctx, uint32_t clk_id,
    uint32_t tp_va)
{
    struct timespec ts;
    uint8_t b[16];
    clockid_t host_clk;
    switch (clk_id) {
    case SP_CLOCK_REALTIME: host_clk = CLOCK_REALTIME; break;
    case SP_CLOCK_MONOTONIC: host_clk = CLOCK_MONOTONIC; break;
    default: return -EINVAL;
    }
    if (l2a_range_ok(tp_va, sizeof(b)) != 0) {
        return -EFAULT;
    }
    if (clock_gettime(host_clk, &ts) != 0) {
        return -(long)errno;
    }
    if (ts.tv_sec < 0) {
        return -EOVERFLOW;
    }
    memset(b, 0, sizeof(b));
    put_be64(b, (uint64_t)ts.tv_sec);
    put_be32(b + 8, (uint32_t)ts.tv_nsec);
    return l2a_store(ctx, tp_va, b, sizeof(b));
}

long sparc32_l2a_getrandom(sparc32_ctx_t *ctx, uint32_t buf_va, uint32_t len,
    uint32_t flags)
{
#if defined(__linux__) && defined(SYS_getrandom)
    long rc;
    if ((flags & ~(SP_GRND_NONBLOCK | SP_GRND_RANDOM | SP_GRND_INSECURE)) !=
        0U) {
        return -EINVAL;
    }
    if (l2a_range_ok(buf_va, len) != 0) {
        return -EFAULT;
    }
    if (len == 0U) {
        return 0;
    }
    rc = syscall(SYS_getrandom, sparc32_guest_ptr(ctx, buf_va), (size_t)len,
        (unsigned int)flags);
    return (rc < 0) ? -(long)errno : rc;
#else
    (void)ctx; (void)buf_va; (void)len; (void)flags;
    return -ENOSYS;
#endif
}

/* futex WAIT/WAKE via host futex. BE guest words: WAIT expectation is
 * swapped once for the LE host compare; WAKE counts pass through. */
long sparc32_l2a_futex(sparc32_ctx_t *ctx, uint32_t uaddr, uint32_t op,
    uint32_t val, uint32_t timeout_va)
{
#if defined(__linux__) && defined(SYS_futex)
    uint32_t *host_ptr;
    long rc;
    if ((op & 127U) != SP_FUTEX_WAIT && (op & 127U) != SP_FUTEX_WAKE) {
        return -ENOSYS;
    }
    if (l2a_range_ok(uaddr, 4U) != 0) {
        return -EFAULT;
    }
    host_ptr = (uint32_t *)sparc32_guest_ptr(ctx, uaddr);
    if ((op & 127U) == SP_FUTEX_WAKE) {
        rc = syscall(SYS_futex, host_ptr, (int)op, (int)val, NULL, NULL, 0);
        return (rc < 0) ? -(long)errno : rc;
    } {
        uint32_t swapped = ((val & 0xFFU) << 24) | ((val & 0xFF00U) << 8) |
            ((val & 0xFF0000U) >> 8) | ((val & 0xFF000000U) >> 24);
        struct timespec ts;
        struct timespec *tsp = NULL;
        if (timeout_va != 0U) {
            const uint8_t *tp;
            int64_t sec;
            int64_t nsec;
            if (l2a_range_ok(timeout_va, 8U) != 0) {
                return -EFAULT;
            }
            tp = (const uint8_t *)sparc32_guest_ptr(ctx, timeout_va);
            sec = (int64_t)(int32_t)get_be32(tp);
            nsec = (int64_t)(int32_t)get_be32(tp + 4);
            if (sec < 0 || nsec < 0 || nsec >= 1000000000LL) {
                return -EINVAL;
            }
            ts.tv_sec = (time_t)sec;
            ts.tv_nsec = (long)nsec;
            tsp = &ts;
        }
        rc = syscall(SYS_futex, host_ptr, (int)op, (int)swapped, tsp, NULL, 0);
        return (rc < 0) ? -(long)errno : rc;
    }
#else
    (void)ctx; (void)uaddr; (void)op; (void)val; (void)timeout_va;
    return -ENOSYS;
#endif
}

/* rt_sigprocmask bookkeeping only; delivery stays Phase 1/4 machinery. */
long sparc32_l2a_rt_sigprocmask(sparc32_ctx_t *ctx, uint32_t how,
    uint32_t set_va, uint32_t oset_va, uint32_t sigsetsize)
{
    uint8_t old[8];
    if (sigsetsize != 8U) {
        return -EINVAL;
    }
    put_be32(old, l2a_blocked[0]);
    put_be32(old + 4, l2a_blocked[1]);
    if (set_va != 0U) {
        const uint8_t *p;
        uint32_t n0;
        uint32_t n1;
        if (l2a_range_ok(set_va, 8U) != 0) {
            return -EFAULT;
        }
        p = (const uint8_t *)sparc32_guest_ptr(ctx, set_va);
        n0 = get_be32(p);
        n1 = get_be32(p + 4);
        switch (how) {
        case SP_SIG_BLOCK: l2a_blocked[0] |= n0; l2a_blocked[1] |= n1; break;
        case SP_SIG_UNBLOCK:
            l2a_blocked[0] &= ~n0; l2a_blocked[1] &= ~n1; break;
        case SP_SIG_SETMASK: l2a_blocked[0] = n0; l2a_blocked[1] = n1; break;
        default: return -EINVAL;
        }
    } else if (how > SP_SIG_SETMASK) {
        return -EINVAL;
    }
    return (oset_va != 0U) ? l2a_store(ctx, oset_va, old, sizeof(old)) : 0;
}

/* FIONREAD via the host; TCGETS answers as an isatty query; else ENOTTY. */
long sparc32_l2a_ioctl(sparc32_ctx_t *ctx, uint32_t fd, uint32_t request,
    uint32_t arg_va)
{
    if (request == SP_FIONREAD) {
        int n = 0;
        if (l2a_range_ok(arg_va, 4U) != 0) {
            return -EFAULT;
        }
        if (ioctl((int)fd, FIONREAD, &n) != 0) {
            return -(long)errno;
        }
        return l2a_st_be32(ctx, arg_va, (uint32_t)n);
    }
    return (request == SP_TCGETS) ? (isatty((int)fd) ? 0 : -ENOTTY) : -ENOTTY;
}
