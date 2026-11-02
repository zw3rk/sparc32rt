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

static inline void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline void put_be64(uint8_t *p, uint64_t v)
{
    put_be32(p, (uint32_t)(v >> 32));
    put_be32(p + 4, (uint32_t)v);
}

static inline uint32_t get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* Validate that every guest page in [va, va + len) lies within
 * [SPARC32_LOW_GUARD_SIZE, SPARC32_TASK_SIZE_TOP) and carries req_prot
 * (1 = READ, 2 = WRITE, 4 = EXEC) in the published g_vm32_prot table. */
static inline int l2a_range_ok_prot(uint32_t va, uint64_t len,
    uint32_t req_prot)
{
    uint64_t end;
    const uint8_t *prot;
    uint32_t pg;
    uint32_t end_pg;
    if (len == 0U) {
        return 0;
    }
    if (len > (uint64_t)SPARC32_TASK_SIZE_TOP) {
        return -EFAULT;
    }
    end = (uint64_t)va + len;
    if (va < SPARC32_LOW_GUARD_SIZE || end > (uint64_t)SPARC32_TASK_SIZE_TOP) {
        return -EFAULT;
    }
    prot = sparc32_vm_prot_base();
    if (prot == NULL) {
        return 0;
    }
    pg = va >> 12;
    end_pg = (uint32_t)((end - 1ULL) >> 12);
    for (;;) {
        uint8_t p = __atomic_load_n(&prot[pg], __ATOMIC_ACQUIRE);
        if (((uint32_t)p & req_prot) != req_prot) {
            return -EFAULT;
        }
        if (pg == end_pg) {
            break;
        }
        pg++;
    }
    return 0;
}

static inline int l2a_range_ok(uint32_t va, uint64_t len)
{
    return l2a_range_ok_prot(va, len, 1U);
}

static inline int l2a_load(const sparc32_ctx_t *ctx, uint32_t va, void *dst,
    uint64_t len)
{
    sparc32_vm_access_enter();
    if (l2a_range_ok_prot(va, len, 1U) != 0) {
        sparc32_vm_access_leave();
        return -EFAULT;
    }
    if (len != 0U) {
        memcpy(dst, sparc32_guest_ptr(ctx, va), (size_t)len);
    }
    sparc32_vm_access_leave();
    return 0;
}

static inline int l2a_store(sparc32_ctx_t *ctx, uint32_t va, const void *src,
    uint64_t len)
{
    bool has_code = false;
    sparc32_vm_access_enter();
    if (l2a_range_ok_prot(va, len, 2U) != 0) {
        sparc32_vm_access_leave();
        return -EFAULT;
    }
    if (len != 0U) {
        memcpy(sparc32_guest_ptr(ctx, va), src, (size_t)len);
        vm32_note_page_write(va, (size_t)len);
        has_code = vm32_range_has_code(va, (size_t)len);
    }
    sparc32_vm_access_leave();
    if (has_code) {
        uint64_t end = (uint64_t)va + len;
        vm_invalidate_jit(ctx, va,
            (end > 0xFFFFFFFFULL) ? 0xFFFFFFFFU : (uint32_t)end);
    }
    return 0;
}

static inline long l2a_copy_cstring(sparc32_ctx_t *ctx, uint32_t va, char *out,
    uint32_t cap)
{
    uint32_t i;
    if (cap == 0U) {
        return -ENAMETOOLONG;
    }
    sparc32_vm_access_enter();
    if (l2a_range_ok_prot(va, 1U, 1U) != 0) {
        sparc32_vm_access_leave();
        return -EFAULT;
    }
    for (i = 0U; i < cap; i++) {
        uint32_t a = va + i;
        const uint8_t *p;
        if (a < va) {
            sparc32_vm_access_leave();
            return -ENAMETOOLONG;
        }
        if (l2a_range_ok_prot(a, 1U, 1U) != 0) {
            sparc32_vm_access_leave();
            return -EFAULT;
        }
        p = (const uint8_t *)sparc32_guest_ptr(ctx, a);
        out[i] = (char)*p;
        if (*p == 0U) {
            sparc32_vm_access_leave();
            return 0;
        }
    }
    sparc32_vm_access_leave();
    out[cap - 1U] = '\0';
    return -ENAMETOOLONG;
}

#endif /* SPARC32RT_OS_L2A_ACCESS_H */
