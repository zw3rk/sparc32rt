/*
 * src/os/syscalls_time.c — Clocks and entropy (Phase 2 L2a + Phase 7 R2).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from syscalls.c for the 900-line file discipline:
 * clock_gettime, gettimeofday, clock_nanosleep, getrandom.
 * Needs _GNU_SOURCE: musl hides syscall(2)/clock_gettime under -std=c11.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "sparc32rt.h"
#include "os/backend.h"
#include "os/l2a_access.h"

#define SP_CLOCK_REALTIME 0U
#define SP_CLOCK_MONOTONIC 1U

#define SP_GRND_NONBLOCK 0x0001U
#define SP_GRND_RANDOM 0x0002U
#define SP_GRND_INSECURE 0x0004U

/* R2: gettimeofday. The guest struct timeval is BE u32 tv_sec + BE u32
 * tv_usec; the obsolete tz pointer is accepted and ignored like Linux
 * (a NULL tv is a successful no-op, also like Linux). */
long sparc32_l2a_gettimeofday(sparc32_ctx_t *ctx, uint32_t tv_va,
    uint32_t tz_va)
{
    struct timeval tv;
    uint8_t b[8];
    (void)tz_va;
    if (tv_va == 0U) {
        return 0;
    }
    if (l2a_range_ok(tv_va, sizeof(b)) != 0) {
        return -EFAULT;
    }
    if (gettimeofday(&tv, NULL) != 0) {
        return -(long)errno;
    }
    if (tv.tv_sec < 0 || tv.tv_usec < 0) {
        return -EOVERFLOW;
    }
    put_be32(b, (uint32_t)tv.tv_sec);
    put_be32(b + 4, (uint32_t)tv.tv_usec);
    return (long)l2a_store(ctx, tv_va, b, sizeof(b));
}

/* R2: clock_nanosleep (4-arg SPARC form). The guest timespec layout is
 * the same __kernel_timespec as clock_gettime above. Only REALTIME /
 * MONOTONIC with flags 0 / TIMER_ABSTIME(1) are supported; EINTR stores
 * the remainder when rem_va is nonzero, matching Linux. */
long sparc32_l2a_clock_nanosleep(sparc32_ctx_t *ctx, uint32_t clk_id,
    uint32_t flags, uint32_t req_va, uint32_t rem_va)
{
    clockid_t host_clk;
    struct timespec req;
    struct timespec rem;
    const uint8_t *rp;
    uint64_t sec;
    uint32_t nsec;
    uint8_t b[16];
    int rc;
    switch (clk_id) {
    case SP_CLOCK_REALTIME: host_clk = CLOCK_REALTIME; break;
    case SP_CLOCK_MONOTONIC: host_clk = CLOCK_MONOTONIC; break;
    default: return -EINVAL;
    }
    if (flags != 0U && flags != 1U) {
        return -EINVAL;
    }
    if (l2a_range_ok(req_va, sizeof(b)) != 0) {
        return -EFAULT;
    }
    rp = (const uint8_t *)sparc32_guest_ptr(ctx, req_va);
    sec = ((uint64_t)get_be32(rp) << 32) | (uint64_t)get_be32(rp + 4);
    nsec = get_be32(rp + 8);
    if (nsec >= 1000000000U) {
        return -EINVAL;
    }
    if (sec > (uint64_t)9223372036854775807ULL) {
        return -EOVERFLOW;
    }
    req.tv_sec = (time_t)sec;
    req.tv_nsec = (long)nsec;
#if defined(__APPLE__)
    if (flags == 1U) {
        struct timespec now;
        if (clock_gettime(host_clk, &now) != 0) {
            return -(long)errno;
        }
        if (req.tv_sec < now.tv_sec ||
            (req.tv_sec == now.tv_sec && req.tv_nsec <= now.tv_nsec)) {
            return 0;
        }
        req.tv_sec -= now.tv_sec;
        if (req.tv_nsec < now.tv_nsec) {
            req.tv_sec -= 1;
            req.tv_nsec += 1000000000L - now.tv_nsec;
        } else {
            req.tv_nsec -= now.tv_nsec;
        }
    }
    rc = (nanosleep(&req, (rem_va != 0U) ? &rem : NULL) == 0) ? 0 : errno;
#else
    rc = clock_nanosleep(host_clk, (int)flags, &req,
        (rem_va != 0U) ? &rem : NULL);
#endif
    if (rc != 0) {
        long erc = -(long)rc;
        if (rc == EINTR && rem_va != 0U) {
            long wrc;
            if (rem.tv_sec < 0) {
                return -EOVERFLOW;
            }
            memset(b, 0, sizeof(b));
            put_be64(b, (uint64_t)rem.tv_sec);
            put_be32(b + 8, (uint32_t)rem.tv_nsec);
            wrc = (long)l2a_store(ctx, rem_va, b, sizeof(b));
            if (wrc != 0) {
                return wrc;
            }
        }
        return erc;
    }
    return 0;
}

/* Guest buffer for clock_gettime (257) is 32-bit old_timespec32:
 * BE u32 tv_sec, BE u32 tv_nsec (8 bytes). */
long sparc32_l2a_clock_gettime(sparc32_ctx_t *ctx, uint32_t clk_id,
    uint32_t tp_va)
{
    struct timespec ts;
    uint8_t b[8];
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
    put_be32(b, (uint32_t)ts.tv_sec);
    put_be32(b + 4, (uint32_t)ts.tv_nsec);
    return l2a_store(ctx, tp_va, b, sizeof(b));
}

/* Guest buffer for clock_gettime64 (403) is __kernel_timespec:
 * BE u64 tv_sec, BE u64 tv_nsec (16 bytes). */
long sparc32_l2a_clock_gettime64(sparc32_ctx_t *ctx, uint32_t clk_id,
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
    put_be64(b + 8, (uint64_t)ts.tv_nsec);
    return l2a_store(ctx, tp_va, b, sizeof(b));
}

long sparc32_l2a_getrandom(sparc32_ctx_t *ctx, uint32_t buf_va, uint32_t len,
    uint32_t flags)
{
    int64_t rc;
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
    /* Host entropy through the backend hook (Rev 4 section 6): Linux
     * forwards flags to getrandom(2); Darwin drains getentropy(2). The
     * hook returns -errno on failure, bytes filled on success. */
    rc = rt_host_getrandom(sparc32_guest_ptr(ctx, buf_va), (size_t)len,
        (unsigned int)flags);
    return (long)rc;
}
