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
#include <stdlib.h>
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
#include "os/l2a_access.h"
#include "os/sigframe_sparc32rt.h"
#include "os/syscall_nr.h"
#include "os/syscalls_min.h"
#include "os/threads.h"
#include "rt32/procfs.h"

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

#define SP_AT_FDCWD ((int32_t)-100)
#define SP_AT_SYMLINK_NOFOLLOW 0x100U
#define SP_AT_NO_AUTOMOUNT 0x800U
#define SP_AT_EMPTY_PATH 0x1000U
#define SP_AT_STATX_SYNC_TYPE 0x6000U

#define L2A_PATH_MAX 4096U
#define L2A_IOV_MAX 1024U
#define L2A_IOV_BATCH 32U

/* BE words, range model, guest stores, and l2a_copy_cstring live in os/l2a_access.h. */

/* Sysroot fallback (C2-3): absolute guest paths that miss on the host
 * retry under ctx->sysroot (dynamic loader DT_NEEDED + PT_INTERP
 * dependencies live there; guest /tmp and relative paths stay on the
 * host). Mirrors the ppc64rt "fallback on miss" contract. Returns 0 and
 * fills out on success, -1 when no sysroot applies. /proc stays with
 * the procfs layer (never remapped). */
static int sys_path_sysroot(const sparc32_ctx_t *ctx, const char *path,
    char *out, size_t cap)
{
    size_t rn;
    size_t pn;
    if (ctx == NULL || ctx->sysroot == NULL || ctx->sysroot[0] == '\0' ||
        path == NULL || path[0] != '/' || out == NULL || cap == 0U) {
        return -1;
    }
    if (strncmp(path, "/proc/", 6U) == 0) {
        return -1;
    }
    rn = strlen(ctx->sysroot);
    pn = strlen(path);
    if (rn == 0U || rn + pn + 1U > cap) {
        return -1;
    }
    memcpy(out, ctx->sysroot, rn);
    memcpy(out + rn, path, pn + 1U);
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

/* Identity fold (C2-3): host dev_t/ino_t routinely exceed the SPARC
 * old-ABI 16/32-bit identity fields (Darwin reports dev 0x100000e),
 * which strict narrowing turns into EOVERFLOW on every library stat.
 * Folding keeps a stable per-file identity instead of failing the
 * lookup; semantic fields (uid/gid/mode/size/times) keep strict
 * narrowing above. The 104 B stat64 layout carries full-width
 * identities and is unaffected. */
static uint16_t fold_dev16(uint64_t v)
{
    return (uint16_t)((v ^ (v >> 16U) ^ (v >> 32U)) & 0xFFFFULL);
}

static uint32_t fold_ino32(uint64_t v)
{
    return (uint32_t)((v ^ (v >> 32U)) & 0xFFFFFFFFULL);
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
    if (rc != 0) {
        return rc;
    }
    rc = open_flags_to_host(flags, &host_flags);
    if (rc != 0) {
        return rc;
    }
    /* L5a hook: /proc/self/<name> served from translator state, all else host. */
    rc = rt32_procfs_openat(ctx, (dirfd == SP_AT_FDCWD) ? AT_FDCWD : (int)dirfd,
        path, host_flags, (mode_t)(mode & 0777U));
    if (rc == -(long)ENOENT && dirfd == SP_AT_FDCWD) {
        /* C2-3 sysroot fallback: absolute loader/library paths that
         * miss on the host retry under --sysroot. */
        char alt[L2A_PATH_MAX];
        if (sys_path_sysroot(ctx, path, alt, sizeof(alt)) == 0) {
            int fd = openat(AT_FDCWD, alt, host_flags,
                (mode_t)(mode & 0777U));
            if (fd >= 0) {
                return (long)fd;
            }
            if (errno != ENOENT) {
                return -(long)errno;
            }
        }
    }
    return rc;
}

long sparc32_l2a_openat(sparc32_ctx_t *ctx, uint32_t dirfd, uint32_t path_va,
    uint32_t flags, uint32_t mode)
{
    /* Successful guest opens join the close-on-exec table (S32-R3-9). */
    long rc = sys_openat(ctx, (int32_t)dirfd, path_va, flags, mode);
    if (rc >= 0) {
        sparc32_fd_note_open((int)rc, (flags & SP_O_CLOEXEC) != 0U);
    }
    return rc;
}

long sparc32_l2a_open(sparc32_ctx_t *ctx, uint32_t path_va, uint32_t flags,
    uint32_t mode)
{
    long rc = sys_openat(ctx, SP_AT_FDCWD, path_va, flags, mode);
    if (rc >= 0) {
        sparc32_fd_note_open((int)rc, (flags & SP_O_CLOEXEC) != 0U);
    }
    return rc;
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
    if (fd < 0) {
        return -(long)errno;
    }
    sparc32_fd_note_open(fd, false);
    return (long)fd;
}

long sparc32_fd_close_tracked(int fd);

long sparc32_l2a_close(int fd)
{
    return sparc32_fd_close_tracked(fd);
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

long sparc32_l2a_getppid(void)
{
    return (long)getppid();
}

/* readv/writev over guest iovec chains ({BE base, BE len} x iovcnt). */
static long sys_rwvec(sparc32_ctx_t *ctx, uint32_t fd, uint32_t iov_va,
    uint32_t iovcnt, int is_write)
{
    uint64_t total = 0ULL;
    uint32_t i = 0U;
    uint32_t buf_prot = is_write ? 1U : 2U;
    if (iovcnt > L2A_IOV_MAX) {
        return -EINVAL;
    }
    if (iovcnt == 0U) {
        return 0;
    }
    if (l2a_range_ok_prot(iov_va, (uint64_t)iovcnt * 8U, 1U) != 0) {
        return -EFAULT;
    }
    while (i < iovcnt) {
        struct iovec host[L2A_IOV_BATCH];
        uint32_t gbase[L2A_IOV_BATCH];
        uint32_t glen[L2A_IOV_BATCH];
        uint8_t sbuf[4096];
        uint8_t *stage = sbuf;
        uint64_t want = 0ULL;
        uint64_t off = 0ULL;
        uint32_t n = 0U;
        uint32_t j;
        ssize_t rc;
        for (j = 0U; j < L2A_IOV_BATCH && i + j < iovcnt; j++) {
            uint8_t e[8];
            uint32_t base;
            uint32_t len;
            if (l2a_load(ctx, iov_va + (uint32_t)((i + j) * 8U), e, 8U) != 0) {
                return (total != 0ULL) ? (long)total : -EFAULT;
            }
            base = get_be32(e);
            len = get_be32(e + 4);
            if (l2a_range_ok_prot(base, len, buf_prot) != 0) {
                return (total != 0ULL) ? (long)total : -EFAULT;
            }
            if (len == 0U) {
                continue;
            }
            gbase[n] = base;
            glen[n] = len;
            n++; want += (uint64_t)len;
        }
        if (n == 0U) {
            i += L2A_IOV_BATCH;
            continue;
        }
        if (want > sizeof(sbuf)) {
            stage = (uint8_t *)malloc((size_t)want);
            if (stage == NULL) {
                return (total != 0ULL) ? (long)total : -ENOMEM;
            }
        }
        for (j = 0U; j < n; j++) {
            host[j].iov_base = stage + off;
            host[j].iov_len = (size_t)glen[j];
            if (is_write && l2a_load(ctx, gbase[j], stage + off, glen[j]) != 0) {
                if (stage != sbuf) { free(stage); }
                return (total != 0ULL) ? (long)total : -EFAULT;
            }
            off += (uint64_t)glen[j];
        }
        rc = is_write ? writev((int)fd, host, (int)n)
                      : readv((int)fd, host, (int)n);
        if (rc < 0) {
            int err = errno;
            if (stage != sbuf) { free(stage); }
            return (total != 0ULL) ? (long)total : -(long)err;
        }
        if (!is_write && rc > 0) {
            uint64_t rem = (uint64_t)rc;
            off = 0ULL;
            for (j = 0U; j < n && rem > 0ULL; j++) {
                uint64_t chunk = (rem < (uint64_t)glen[j]) ? rem : (uint64_t)glen[j];
                if (l2a_store(ctx, gbase[j], stage + off, chunk) != 0) {
                    if (stage != sbuf) { free(stage); }
                    return (total != 0ULL) ? (long)total : -EFAULT;
                }
                off += (uint64_t)glen[j];
                rem -= chunk;
            }
        }
        if (stage != sbuf) { free(stage); }
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
    /* Identity fields fold (C2-3); semantic fields narrow strictly. */
    put_be16(b + offsetof(sparc32_stat_t, st_dev),
        fold_dev16((uint64_t)h->st_dev));
    put_be32(b + offsetof(sparc32_stat_t, st_ino),
        fold_ino32((uint64_t)h->st_ino));
    put_be32(b + offsetof(sparc32_stat_t, st_mode), (uint32_t)h->st_mode);
    PUT16(offsetof(sparc32_stat_t, st_nlink), narrow_s16((int64_t)h->st_nlink));
    PUT16(offsetof(sparc32_stat_t, st_uid), narrow_u16((uint64_t)h->st_uid));
    PUT16(offsetof(sparc32_stat_t, st_gid), narrow_u16((uint64_t)h->st_gid));
    put_be16(b + offsetof(sparc32_stat_t, st_rdev),
        fold_dev16((uint64_t)h->st_rdev));
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
        /* C2-3 sysroot fallback (absolute paths only). */
        char alt[L2A_PATH_MAX];
        if (errno != ENOENT || dirfd != AT_FDCWD ||
            sys_path_sysroot(ctx, path, alt, sizeof(alt)) != 0 ||
            fstatat(AT_FDCWD, alt, &h,
                nofollow ? AT_SYMLINK_NOFOLLOW : 0) != 0) {
            return -(long)errno;
        }
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
        /* C2-3 sysroot fallback (absolute paths only). */
        char alt[L2A_PATH_MAX];
        if (errno != ENOENT || host_dirfd != AT_FDCWD ||
            sys_path_sysroot(ctx, path, alt, sizeof(alt)) != 0 ||
            fstatat(AT_FDCWD, alt, &h, host_flags) != 0) {
            return -(long)errno;
        }
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
        /* C2-3 sysroot fallback (absolute paths only). */
        char alt[L2A_PATH_MAX];
        if (((long)errno == 0) || host_dirfd != AT_FDCWD ||
            sys_path_sysroot(ctx, path, alt, sizeof(alt)) != 0 ||
            syscall(SYS_statx, AT_FDCWD, alt, host_flags, (unsigned int)mask,
                &h) != 0) {
            return ((long)errno == 0) ? -ENOSYS : -(long)errno;
        }
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
    /* Portable statx via host fstatat (C2-3): hosts without SYS_statx
     * (macOS) serve STATX_BASIC_STATS from a host fstatat. uClibc
     * fstat/stat call statx with no fallback, so ENOSYS here breaks
     * every libc guest on such hosts. Birth time, device numbers, and
     * mount id are zero (regular-file guests never read them). */
    {
        enum {
            SP_STX_BASIC_STATS = 0x7FFU
        };
        char ppath[L2A_PATH_MAX];
        struct stat h;
        uint8_t b[STX_SIZE];
        int host_flags = 0;
        int host_dirfd;
        int64_t sec;
        int64_t nsec;
        long rc = l2a_copy_cstring(ctx, path_va, ppath, L2A_PATH_MAX);
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
        host_dirfd =
            ((int32_t)dirfd == SP_AT_FDCWD) ? AT_FDCWD : (int)(int32_t)dirfd;
        /* AT_EMPTY_PATH with an empty path operates on dirfd itself
         * (uClibc fstat/stat); hosts without AT_EMPTY_PATH (macOS)
         * serve that via fstat on the file descriptor. */
        if (ppath[0] == '\0' && host_dirfd != AT_FDCWD &&
            (flags & SP_AT_EMPTY_PATH) != 0U) {
            if (fstat(host_dirfd, &h) != 0) {
                return -(long)errno;
            }
        } else if (fstatat(host_dirfd, ppath, &h, host_flags) != 0) {
            /* C2-3 sysroot fallback (absolute paths only). */
            char alt[L2A_PATH_MAX];
            if (errno != ENOENT || host_dirfd != AT_FDCWD ||
                sys_path_sysroot(ctx, ppath, alt, sizeof(alt)) != 0 ||
                fstatat(AT_FDCWD, alt, &h, host_flags) != 0) {
                return -(long)errno;
            }
        }
        memset(b, 0, sizeof(b));
        put_be32(b + STX_OFF_MASK, mask & SP_STX_BASIC_STATS);
        put_be32(b + STX_OFF_BLKSIZE, (uint32_t)h.st_blksize);
        put_be64(b + STX_OFF_ATTR, 0U);
        put_be32(b + STX_OFF_NLINK, (uint32_t)h.st_nlink);
        put_be32(b + STX_OFF_UID, (uint32_t)h.st_uid);
        put_be32(b + STX_OFF_GID, (uint32_t)h.st_gid);
        put_be16(b + STX_OFF_MODE, (uint16_t)h.st_mode);
        put_be64(b + STX_OFF_INO, (uint64_t)h.st_ino);
        put_be64(b + STX_OFF_SIZE, (uint64_t)(int64_t)h.st_size);
        put_be64(b + STX_OFF_BLOCKS, (uint64_t)h.st_blocks);
        put_be64(b + STX_OFF_ATTRMASK, 0U);
        l2a_host_times(&h, 0, &sec, &nsec);
        put_be64(b + STX_OFF_ATIME, (sec < 0) ? 0U : (uint64_t)sec);
        put_be32(b + STX_OFF_ATIME + 8, (uint32_t)nsec);
        l2a_host_times(&h, 1, &sec, &nsec);
        put_be64(b + STX_OFF_MTIME, (sec < 0) ? 0U : (uint64_t)sec);
        put_be32(b + STX_OFF_MTIME + 8, (uint32_t)nsec);
        l2a_host_times(&h, 2, &sec, &nsec);
        put_be64(b + STX_OFF_CTIME, (sec < 0) ? 0U : (uint64_t)sec);
        put_be32(b + STX_OFF_CTIME + 8, (uint32_t)nsec);
        return l2a_store(ctx, buf_va, b, sizeof(b));
    }
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
        if (rc < 0) {
            return -(long)errno;
        }
        sparc32_fd_note_open(rc, false);
        return (long)rc;
    case SP_F_GETFD:
        rc = fcntl((int)fd, F_GETFD);
        return (rc < 0) ? -(long)errno : (long)rc;
    case SP_F_SETFD:
        /* Guest FD_CLOEXEC is bit 0, matching the host (S32-R3-9). */
        if (fcntl((int)fd, F_SETFD, (int)arg) != 0) {
            return -(long)errno;
        }
        sparc32_fd_note_set_cloexec((int)fd, ((int)arg & FD_CLOEXEC) != 0);
        return 0;
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
