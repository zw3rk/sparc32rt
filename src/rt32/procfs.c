/*
 * src/rt32/procfs.c — /proc/self served from translator state (lane L5a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Absolute /proc/self/{exe,maps,cmdline,stat,auxv} paths are served
 * from translator state (guest region table, argv, auxv snapshot, exec
 * path) — never the host's. Everything else (including other
 * /proc/self/<name> entries such as oom_score_adj) falls through to the
 * host untouched. Synthetic files are presented through a pipe whose
 * read end is handed to the guest; reads are sequential.
 */

#define _GNU_SOURCE
#include "rt32/procfs.h"

#include "rt32/rt32.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PROCFS_SELF "/proc/self/"
#define PROCFS_SELF_LEN 11U
#define PROCFS_PATH_MAX 4096U

/* Bounds check for [va, va+len): reject 32-bit wrap + low guard. */
static int procfs_range_ok(uint32_t va, uint64_t len)
{
    if (len == 0U) {
        return 0;
    }
    if (len > 0x100000000ULL || (uint64_t)va + len > 0x100000000ULL) {
        return -EFAULT;
    }
    return (va < SPARC32_LOW_GUARD_SIZE) ? -EFAULT : 0;
}

/* NUL-terminated guest string -> host out (0 ok, -EFAULT/-ENAMETOOLONG). */
static long procfs_copy_in(sparc32_ctx_t *ctx, uint32_t va, char *out,
                           uint32_t cap)
{
    uint32_t i;
    if (cap == 0U || procfs_range_ok(va, 1U) != 0) {
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

static long procfs_copy_out(sparc32_ctx_t *ctx, uint32_t va, const void *src,
                            uint64_t len)
{
    if (procfs_range_ok(va, len) != 0) {
        return -EFAULT;
    }
    if (len != 0U) {
        memcpy(sparc32_guest_ptr(ctx, va), src, (size_t)len);
    }
    return 0;
}

/* Split an absolute /proc/self/<rel> path; false for anything else. */
static bool procfs_is_self(const char *path, const char **rel_out)
{
    if (strncmp(path, PROCFS_SELF, PROCFS_SELF_LEN) != 0) {
        return false;
    }
    *rel_out = path + PROCFS_SELF_LEN;
    return true;
}

/* The guest executable path: exec_path, else guest argv[0]. */
static const char *procfs_exe_path(const sparc32_ctx_t *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    if (ctx->exec_path != NULL && ctx->exec_path[0] != '\0') {
        return ctx->exec_path;
    }
    if (ctx->guest_argc > 0 && ctx->guest_argv != NULL &&
        ctx->guest_argv[0] != NULL) {
        return ctx->guest_argv[0];
    }
    return NULL;
}

/* Hand the guest the read end of a pipe pre-filled with [data, len). */
static long procfs_serve_bytes(const void *data, size_t len, int host_flags)
{
    int fds[2];
    size_t done = 0;
    int rw_flags;
#if defined(__linux__)
    if (pipe2(fds, (host_flags & O_CLOEXEC) != 0 ? O_CLOEXEC : 0) != 0) {
        return -(long)errno;
    }
#else
    if (pipe(fds) != 0) {
        return -(long)errno;
    }
    if ((host_flags & O_CLOEXEC) != 0) {
        (void)fcntl(fds[0], F_SETFD, FD_CLOEXEC);
        (void)fcntl(fds[1], F_SETFD, FD_CLOEXEC);
    }
#endif
    rw_flags = fcntl(fds[0], F_GETFL);
    if (rw_flags >= 0 && (host_flags & O_NONBLOCK) != 0) {
        (void)fcntl(fds[0], F_SETFL, rw_flags | O_NONBLOCK);
    }
    while (done < len) {
        ssize_t n = write(fds[1], (const uint8_t *)data + done, len - done);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fds[0]);
            close(fds[1]);
            return -(long)errno;
        }
        done += (size_t)n;
    }
    close(fds[1]);
    return (long)fds[0];
}

static long procfs_open_exe(sparc32_ctx_t *ctx, int host_flags)
{
    const char *ep = procfs_exe_path(ctx);
    int fd;
    if (ep == NULL) {
        return -ENOENT;
    }
    if ((host_flags & O_ACCMODE) != O_RDONLY) {
        return -EACCES;
    }
    fd = rt32_open_guest_ro(ctx, ep);
    if (fd < 0) {
        return -(long)errno;
    }
    if ((host_flags & O_CLOEXEC) == 0) {
        (void)fcntl(fd, F_SETFD, 0);
    }
    return (long)fd;
}

static long procfs_open_maps(sparc32_ctx_t *ctx)
{
    size_t total = 0;
    size_t i;
    char *buf;
    size_t pos = 0;
    if (ctx == NULL) {
        return -ENOENT;
    }
    for (i = 0; i < ctx->region_count; i++) {
        const sparc32_region_t *r = &ctx->regions[i];
        int n = snprintf(NULL, 0, "%08x-%08x %c%c%c%c %08x 00:00 0%s%s\n",
            r->start, r->end, (r->prot & 1U) ? 'r' : '-',
            (r->prot & 2U) ? 'w' : '-', (r->prot & 4U) ? 'x' : '-', 'p',
            0U, r->name[0] != '\0' ? " " : "", r->name);
        if (n < 0) {
            return -EIO;
        }
        total += (size_t)n;
    }
    buf = (char *)malloc(total + 1U);
    if (buf == NULL) {
        return -ENOMEM;
    }
    for (i = 0; i < ctx->region_count; i++) {
        const sparc32_region_t *r = &ctx->regions[i];
        int n = snprintf(buf + pos, total + 1U - pos,
            "%08x-%08x %c%c%c%c %08x 00:00 0%s%s\n",
            r->start, r->end, (r->prot & 1U) ? 'r' : '-',
            (r->prot & 2U) ? 'w' : '-', (r->prot & 4U) ? 'x' : '-', 'p',
            0U, r->name[0] != '\0' ? " " : "", r->name);
        if (n < 0 || (size_t)n >= total + 1U - pos) {
            free(buf);
            return -EIO;
        }
        pos += (size_t)n;
    }
    {
        long fd = procfs_serve_bytes(buf, total, O_RDONLY);
        free(buf);
        return fd;
    }
}

static long procfs_open_cmdline(sparc32_ctx_t *ctx)
{
    size_t total = 0;
    int i;
    char *buf;
    size_t pos = 0;
    long fd;
    if (ctx == NULL || ctx->guest_argv == NULL || ctx->guest_argc < 1) {
        return -ENOENT;
    }
    if (ctx->guest_argc > 512) {
        return -E2BIG;
    }
    for (i = 0; i < ctx->guest_argc; i++) {
        if (ctx->guest_argv[i] == NULL) {
            return -EFAULT;
        }
        total += strlen(ctx->guest_argv[i]) + 1U;
    }
    buf = (char *)malloc(total + 1U);
    if (buf == NULL) {
        return -ENOMEM;
    }
    for (i = 0; i < ctx->guest_argc; i++) {
        size_t n = strlen(ctx->guest_argv[i]) + 1U;
        memcpy(buf + pos, ctx->guest_argv[i], n);
        pos += n;
    }
    fd = procfs_serve_bytes(buf, total, O_RDONLY);
    free(buf);
    return fd;
}

static long procfs_open_stat(sparc32_ctx_t *ctx)
{
    char buf[192];
    const char *ep = procfs_exe_path(ctx);
    const char *base;
    char comm[16];
    size_t i = 0;
    int n;
    if (ep == NULL) {
        return -ENOENT;
    }
    base = strrchr(ep, '/');
    base = (base != NULL) ? base + 1 : ep;
    while (i < sizeof(comm) - 1U && base[i] != '\0') {
        comm[i] = base[i];
        i++;
    }
    comm[i] = '\0';
    n = snprintf(buf, sizeof(buf),
        "%d (%s) R 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 "
        "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        (int)getpid(), comm);
    if (n < 0 || (size_t)n >= sizeof(buf)) {
        return -EIO;
    }
    return procfs_serve_bytes(buf, (size_t)n, O_RDONLY);
}

static long procfs_open_auxv(sparc32_ctx_t *ctx)
{
    uint8_t out[256];
    size_t words;
    size_t i;
    if (ctx == NULL || ctx->auxv_bytes == 0U ||
        ctx->auxv_bytes > sizeof(out) ||
        ctx->auxv_bytes > sizeof(ctx->auxv_data)) {
        return -ENOENT;
    }
    words = ctx->auxv_bytes / sizeof(uint32_t);
    for (i = 0; i < words; i++) {
        uint32_t v = ctx->auxv_data[i];
        out[4U * i] = (uint8_t)(v >> 24);
        out[4U * i + 1U] = (uint8_t)(v >> 16);
        out[4U * i + 2U] = (uint8_t)(v >> 8);
        out[4U * i + 3U] = (uint8_t)v;
    }
    return procfs_serve_bytes(out, words * sizeof(uint32_t), O_RDONLY);
}

long rt32_procfs_openat(sparc32_ctx_t *ctx, int dirfd, const char *path,
                        int host_flags, unsigned host_mode)
{
    const char *rel;
    if (procfs_is_self(path, &rel)) {
        if (strcmp(rel, "exe") == 0) {
            return procfs_open_exe(ctx, host_flags);
        }
        if ((host_flags & O_ACCMODE) != O_RDONLY) {
            return -EACCES;
        }
        if (strcmp(rel, "maps") == 0) {
            return procfs_open_maps(ctx);
        }
        if (strcmp(rel, "cmdline") == 0) {
            return procfs_open_cmdline(ctx);
        }
        if (strcmp(rel, "stat") == 0) {
            return procfs_open_stat(ctx);
        }
        if (strcmp(rel, "auxv") == 0) {
            return procfs_open_auxv(ctx);
        }
    }
    {
        int fd = openat(dirfd, path, host_flags, (mode_t)host_mode);
        return (fd < 0) ? -(long)errno : (long)fd;
    }
}

static long procfs_readlink_at(sparc32_ctx_t *ctx, int dirfd, uint32_t path_va,
                               uint32_t buf_va, uint32_t len)
{
    char path[PROCFS_PATH_MAX];
    const char *rel;
    long rc = procfs_copy_in(ctx, path_va, path, PROCFS_PATH_MAX);
    if (rc != 0) {
        return rc;
    }
    if (procfs_is_self(path, &rel) && strcmp(rel, "exe") == 0) {
        const char *ep = procfs_exe_path(ctx);
        size_t n;
        if (ep == NULL) {
            return -ENOENT;
        }
        if (len == 0U) {
            return -EINVAL;
        }
        n = strlen(ep);
        if (n > len) {
            n = len;
        }
        rc = procfs_copy_out(ctx, buf_va, ep, n);
        return (rc != 0) ? rc : (long)n;
    }
    if (len == 0U) {
        return -EINVAL;
    }
    {
        char hostbuf[PROCFS_PATH_MAX];
        size_t want = (len < PROCFS_PATH_MAX) ? len : PROCFS_PATH_MAX;
        ssize_t n = readlinkat(dirfd, path, hostbuf, want);
        if (n < 0) {
            return -(long)errno;
        }
        rc = procfs_copy_out(ctx, buf_va, hostbuf, (uint64_t)n);
        return (rc != 0) ? rc : (long)n;
    }
}

long rt32_procfs_readlink(sparc32_ctx_t *ctx, uint32_t path_va,
                          uint32_t buf_va, uint32_t len)
{
    return procfs_readlink_at(ctx, AT_FDCWD, path_va, buf_va, len);
}

long rt32_procfs_readlinkat(sparc32_ctx_t *ctx, uint32_t dirfd,
                            uint32_t path_va, uint32_t buf_va, uint32_t len)
{
    int host_dir = ((int32_t)dirfd == (int32_t)-100) ? AT_FDCWD
                                                    : (int)(int32_t)dirfd;
    return procfs_readlink_at(ctx, host_dir, path_va, buf_va, len);
}
