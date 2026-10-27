/*
 * src/os/l2a_access.h — Guest memory accessors for the syscall layer.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from syscalls.c for the 900-line file discipline: big-endian
 * word helpers plus the L1c guest-range model ([va, va+len) rejects
 * 32-bit wrap and the low guard page) shared by src/os/syscalls*.c.
 * Private to the syscall layer; included by syscalls.c (which keeps
 * the historic unprefixed be-helper names) and syscalls_time.c.
 */

#ifndef SPARC32RT_OS_L2A_ACCESS_H
#define SPARC32RT_OS_L2A_ACCESS_H

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "sparc32rt.h"

static inline void put_be16(uint8_t *p, uint16_t v)
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

#endif /* SPARC32RT_OS_L2A_ACCESS_H */
