/*
 * src/rt32/host.c — Optional /dev/a32host handshake & capability detection
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Vendored from i686rt/src/rt32/rt32_host.c: renamed rt32_ untouched,
 * retyped on sparc32_ctx_t; env prefix I686RT_ -> SPARC32RT_. Uses libc
 * ioctl(2) (not raw syscall(2)) so the probe compiles on the host cc too.
 */

#define _POSIX_C_SOURCE 200809L
#include "rt32.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

void rt32_host_probe(sparc32_ctx_t *ctx)
{
    int fd;
    a32h_info_t info;

    if (!ctx) {
        return;
    }
    memset(&ctx->host_info, 0, sizeof(ctx->host_info));
    ctx->has_host_info = false;

    {
        const char *host_env = getenv("SPARC32RT_HOST");
        if (host_env && strcmp(host_env, "none") == 0) {
            return;
        }
    }

    fd = open(A32H_DEV_PATH, O_RDWR | O_CLOEXEC);
    if (fd < 0 && (errno == EACCES || errno == EPERM || errno == EROFS)) {
        fd = open(A32H_DEV_PATH, O_RDONLY | O_CLOEXEC);
    }
    if (fd < 0) {
        return;
    }

    memset(&info, 0, sizeof(info));
    if (ioctl(fd, (int)A32H_GET_INFO, &info) == 0 &&
        info.abi_major == A32H_ABI_MAJOR) {
        ctx->host_info = info;
        ctx->has_host_info = true;
    }

    close(fd);
}
