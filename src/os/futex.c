/*
 * src/os/futex.c — futex(142)/futex_time64(422) WAIT/WAKE backend.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * uClibc issues futex_time64 for every pthread/mutex/guard operation,
 * so both numbers must work. On a Linux host the call passes through
 * to the host futex (BE/LE conversion as in sparc32_l2a_futex). Where
 * the host has no futex (Darwin) a small pthread condvar emulation
 * serves WAIT/WAKE with relative or CLOCK_REALTIME-absolute timeouts;
 * every other op is -ENOSYS (SPARC 38). Returned errnos are SPARC
 * numbers (EAGAIN 11, ETIMEDOUT 110, EINTR 4, EINVAL 22, EFAULT 14),
 * never host values.
 */

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>

#include "sparc32rt.h"

#include "os/l2a_access.h"

#define FUTEX_SP_WAIT 0U
#define FUTEX_SP_WAKE 1U
#define FUTEX_SP_CMD_MASK 15U
#define FUTEX_SP_PRIVATE_FLAG 128U
#define FUTEX_SP_CLOCK_REALTIME 256U

/* SPARC (asm-generic) errnos, independent of the build host. */
#define SP_EAGAIN 11L
#define SP_EINTR 4L
#define SP_EINVAL 22L
#define SP_EFAULT 14L
#define SP_ENOSYS 38L
#define SP_ETIMEDOUT 110L

/* Emulation: one global mutex guards a small table mapping guest futex
 * addresses to condvars. WAIT checks the BE word under the lock, sleeps
 * until WAKE or the deadline, and re-checks after every wakeup so slot
 * sharing and spurious wakeups stay correct. Over-wake on WAKE(n>1) is
 * benign: waiters re-test the word before returning. */
#define FUTEX_EMU_SLOTS 64U

struct futex_emu_slot {
    int in_use;
    int cond_init;
    uint32_t uaddr;
    int waiters;
    pthread_cond_t cond;
};

static pthread_mutex_t futex_emu_lock = PTHREAD_MUTEX_INITIALIZER;
static struct futex_emu_slot futex_emu_slots[FUTEX_EMU_SLOTS];

static struct futex_emu_slot *futex_emu_find(uint32_t uaddr, int create)
{
    unsigned i;
    struct futex_emu_slot *free_slot = 0;
    struct futex_emu_slot *idle_slot = 0;
    for (i = 0U; i < FUTEX_EMU_SLOTS; i++) {
        if (futex_emu_slots[i].in_use) {
            if (futex_emu_slots[i].uaddr == uaddr) {
                return &futex_emu_slots[i];
            }
            /* A live slot with no waiters holds no state worth keeping
             * (S32-R5-10): it is recyclable once the free list runs out. */
            if (futex_emu_slots[i].waiters == 0 && idle_slot == 0) {
                idle_slot = &futex_emu_slots[i];
            }
            continue;
        }
        if (free_slot == 0) {
            free_slot = &futex_emu_slots[i];
        }
    }
    if (create && free_slot != 0) {
        if (!free_slot->cond_init) {
            pthread_cond_init(&free_slot->cond, 0);
            free_slot->cond_init = 1;
        }
        free_slot->in_use = 1;
        free_slot->uaddr = uaddr;
        free_slot->waiters = 0;
        return free_slot;
    }
    /* Table full but an idle slot exists: recycle it for the new address
     * instead of permanently exhausting the table after 64 distinct
     * addresses. The condvar stays valid; nobody waits on it. */
    if (create && idle_slot != 0) {
        idle_slot->uaddr = uaddr;
        idle_slot->waiters = 0;
        return idle_slot;
    }
    return 0;
}

/* Current CLOCK_REALTIME in nanoseconds (Darwin has no clock_gettime
 * MONOTONIC condvar clocks; REALTIME suffices for relative waits). */
static int64_t futex_emu_now_ns(void)
{
    struct timeval tv;
    gettimeofday(&tv, 0);
    return (int64_t)tv.tv_sec * 1000000000LL +
        (int64_t)tv.tv_usec * 1000LL;
}

static uint32_t futex_emu_read(sparc32_ctx_t *ctx, uint32_t uaddr, int *ok)
{
    uint8_t p[4];
    if (l2a_load(ctx, uaddr, p, sizeof(p)) != 0) {
        *ok = 0;
        return 0U;
    }
    *ok = 1;
    return get_be32(p);
}

long sparc32_futex_wait_emu(sparc32_ctx_t *ctx, uint32_t uaddr,
    uint32_t val, int64_t sec, int64_t nsec, int has_timeout, int absolute)
{
    int64_t deadline;
    int ok;
    if (has_timeout) {
        if (sec < 0 || nsec < 0 || nsec >= 1000000000LL) {
            return -SP_EINVAL;
        }
        if (absolute) {
            deadline = (sec > 9000000000LL) ? 9000000000LL * 1000000000LL :
                sec * 1000000000LL + nsec;
        } else {
            int64_t rel = (sec > 9000000000LL) ? 9000000000LL * 1000000000LL :
                sec * 1000000000LL + nsec;
            int64_t now = futex_emu_now_ns();
            deadline = (now > INT64_MAX - rel) ? INT64_MAX : (now + rel);
        }
    } else {
        deadline = 0LL;
    }
    pthread_mutex_lock(&futex_emu_lock);
    {
        uint32_t cur = futex_emu_read(ctx, uaddr, &ok);
        struct futex_emu_slot *slot;
        int rc;
        struct timespec ts;
        if (!ok) {
            pthread_mutex_unlock(&futex_emu_lock);
            return -SP_EFAULT;
        }
        if (cur != val) {
            pthread_mutex_unlock(&futex_emu_lock);
            return -SP_EAGAIN;
        }
        if (has_timeout && futex_emu_now_ns() >= deadline) {
            pthread_mutex_unlock(&futex_emu_lock);
            return -SP_ETIMEDOUT;
        }
        slot = futex_emu_find(uaddr, 1);
        if (slot == 0) {
            pthread_mutex_unlock(&futex_emu_lock);
            return -SP_EAGAIN;
        }
        slot->waiters++;
        if (!has_timeout) {
            rc = pthread_cond_wait(&slot->cond, &futex_emu_lock);
        } else {
            ts.tv_sec = (time_t)(deadline / 1000000000LL);
            ts.tv_nsec = (long)(deadline % 1000000000LL);
            rc = pthread_cond_timedwait(&slot->cond, &futex_emu_lock, &ts);
        }
        slot->waiters--;
        pthread_mutex_unlock(&futex_emu_lock);
        if (rc == 0) {
            return 0L;
        }
        if (rc == ETIMEDOUT) {
            return -SP_ETIMEDOUT;
        }
        return (rc == EINTR) ? -SP_EINTR : -SP_EINVAL;
    }
}

long sparc32_futex_wake_emu(sparc32_ctx_t *ctx, uint32_t uaddr, uint32_t n)
{
    struct futex_emu_slot *slot;
    long woken;
    (void)ctx;
    if (n == 0U) {
        return 0L;
    }
    pthread_mutex_lock(&futex_emu_lock);
    slot = futex_emu_find(uaddr, 0);
    if (slot == 0 || slot->waiters <= 0) {
        pthread_mutex_unlock(&futex_emu_lock);
        return 0L;
    }
    woken = (long)slot->waiters;
    if (woken > (long)n) {
        woken = (long)n;
    }
    if (woken <= 1L) {
        pthread_cond_signal(&slot->cond);
    } else {
        pthread_cond_broadcast(&slot->cond);
    }
    pthread_mutex_unlock(&futex_emu_lock);
    return woken;
}

/* Shared parse-and-dispatch for futex(142): 8-byte BE32 timeout.
 * Serves the non-Linux host path of sparc32_l2a_futex. */
long sparc32_l2a_futex_emu32(sparc32_ctx_t *ctx, uint32_t uaddr,
    uint32_t op, uint32_t val, uint32_t timeout_va)
{
    uint32_t cmd = op & FUTEX_SP_CMD_MASK;
    int absolute = (op & FUTEX_SP_CLOCK_REALTIME) != 0U;
    if (cmd != FUTEX_SP_WAIT && cmd != FUTEX_SP_WAKE) {
        return -SP_ENOSYS;
    }
    if (l2a_range_ok(uaddr, 4U) != 0) {
        return -SP_EFAULT;
    }
    if (cmd == FUTEX_SP_WAKE) {
        return sparc32_futex_wake_emu(ctx, uaddr, val);
    }
    if (timeout_va == 0U) {
        return sparc32_futex_wait_emu(ctx, uaddr, val, 0LL, 0LL, 0, 0);
    }
    {
        uint8_t tp[8];
        int64_t sec;
        int64_t nsec;
        if (l2a_load(ctx, timeout_va, tp, sizeof(tp)) != 0) {
            return -SP_EFAULT;
        }
        sec = (int64_t)(int32_t)get_be32(tp);
        nsec = (int64_t)(int32_t)get_be32(tp + 4);
        return sparc32_futex_wait_emu(ctx, uaddr, val, sec, nsec, 1,
            absolute);
    }
}

/* Shared parse-and-dispatch for futex_time64(422): 16-byte BE64 timeout.
 * On Linux with SYS_futex_time64 the host serves it; otherwise (Darwin,
 * old headers) the emulation serves WAIT/WAKE. */
long sparc32_l2a_futex_time64(sparc32_ctx_t *ctx, uint32_t uaddr,
    uint32_t op, uint32_t val, uint32_t timeout_va)
{
    uint32_t cmd = op & FUTEX_SP_CMD_MASK;
    int absolute = (op & FUTEX_SP_CLOCK_REALTIME) != 0U;
    if (cmd != FUTEX_SP_WAIT && cmd != FUTEX_SP_WAKE) {
        return -SP_ENOSYS;
    }
    if (l2a_range_ok(uaddr, 4U) != 0) {
        return -SP_EFAULT;
    }
    if (cmd == FUTEX_SP_WAKE) {
#if defined(__linux__) && defined(SYS_futex)
        uint32_t *host_ptr = (uint32_t *)sparc32_guest_ptr(ctx, uaddr);
        long rc = syscall(SYS_futex, host_ptr, (int)(op & 15U), (int)val,
            0, 0, 0);
        return (rc < 0) ? -(long)errno : rc;
#else
        return sparc32_futex_wake_emu(ctx, uaddr, val);
#endif
    }
    if (timeout_va == 0U) {
#if defined(__linux__) && defined(SYS_futex)
        uint32_t *host_ptr = (uint32_t *)sparc32_guest_ptr(ctx, uaddr);
        uint32_t swapped = ((val & 0xFFU) << 24) | ((val & 0xFF00U) << 8) |
            ((val & 0xFF0000U) >> 8) | ((val & 0xFF000000U) >> 24);
        long rc = syscall(SYS_futex, host_ptr, (int)(op & 15U),
            (int)swapped, 0, 0, 0);
        return (rc < 0) ? -(long)errno : rc;
#else
        return sparc32_futex_wait_emu(ctx, uaddr, val, 0LL, 0LL, 0, 0);
#endif
    }
    {
        uint8_t tp[16];
        uint64_t sec;
        uint64_t nsec;
        if (l2a_load(ctx, timeout_va, tp, sizeof(tp)) != 0) {
            return -SP_EFAULT;
        }
        sec = ((uint64_t)get_be32(tp) << 32) | (uint64_t)get_be32(tp + 4);
        nsec = ((uint64_t)get_be32(tp + 8) << 32) | (uint64_t)get_be32(tp + 12);
        if ((sec >> 63) != 0U || (nsec >> 63) != 0U) {
            return -SP_EINVAL;
        }
#if defined(__linux__) && defined(SYS_futex_time64)
        {
            uint32_t *host_ptr = (uint32_t *)sparc32_guest_ptr(ctx, uaddr);
            uint32_t swapped = ((val & 0xFFU) << 24) |
                ((val & 0xFF00U) << 8) | ((val & 0xFF0000U) >> 8) |
                ((val & 0xFF000000U) >> 24);
            long long hts[2];
            long rc;
            hts[0] = (long long)sec;
            hts[1] = (long long)nsec;
            rc = syscall(SYS_futex_time64, host_ptr, (int)(op & 15U),
                (int)swapped, hts, 0, 0);
            return (rc < 0) ? -(long)errno : rc;
        }
#elif defined(__linux__) && defined(SYS_futex)
        {
            uint32_t *host_ptr = (uint32_t *)sparc32_guest_ptr(ctx, uaddr);
            uint32_t swapped = ((val & 0xFFU) << 24) |
                ((val & 0xFF00U) << 8) | ((val & 0xFF0000U) >> 8) |
                ((val & 0xFF000000U) >> 24);
            struct timespec hts;
            long rc;
            if (nsec >= 1000000000ULL) {
                return -SP_EINVAL;
            }
            hts.tv_sec = (time_t)sec;
            hts.tv_nsec = (long)nsec;
            rc = syscall(SYS_futex, host_ptr, (int)(op & 15U),
                (int)swapped, &hts, 0, 0);
            return (rc < 0) ? -(long)errno : rc;
        }
#else
        if (nsec >= 1000000000ULL) {
            return -SP_EINVAL;
        }
        return sparc32_futex_wait_emu(ctx, uaddr, val, (int64_t)sec,
            (int64_t)nsec, 1, absolute);
#endif
    }
}
