/*
 * src/interp/interp_mem.c — Guest memory accessors (Phase 1, RC1 split)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
G-window loads/stores with region coverage checks, shared by the
 * executor (interp.c), windows (interp_win.c) and delivery (interp_signal.c).
 */

#include "sparc32rt.h"

#include "interp/interp_priv.h"

#include <string.h>

sparc32_ldstub_lock_t g_sparc32_ldstub_lock;

void interp_wreg(sparc32_ctx_t *ctx, uint32_t rd, uint32_t v)
{
    if (rd != 0U) {
        ctx->r[rd & 31U] = v;
    }
}

const uint8_t *sparc32_vm_prot_base(void);

/* Region coverage: every byte of [va, va+len) must be mapped with the
 * needed PROT bits. PROT_NONE/unmapped areas carry no record and fail. */
bool interp_range_ok(const sparc32_ctx_t *ctx, uint32_t va,
    uint32_t len, uint32_t need)
{
    uint64_t end = (uint64_t)va + (uint64_t)len;
    /* O(1) fast path: a short span inside one 4K page consults the
     * published per-page prot table (kept in sync with regions[] by
     * every vm_mmap commit/unmap/mprotect). A miss falls through to
     * the region walk below. */
    if (len != 0U && len <= 64U &&
        (((va ^ (va + len - 1U)) >> 12) == 0U)) {
        const uint8_t *prot = sparc32_vm_prot_base();
        if (prot != NULL &&
            (((uint32_t)prot[va >> 12] & need) == need)) {
            return true;
        }
    }
    uint32_t cur = va;
    size_t i;
    if (len == 0U || end > (uint64_t)SPARC32_TASK_SIZE_TOP) {
        return false;
    }
    for (i = 0; i < ctx->region_count && (uint64_t)cur < end; i++) {
        const sparc32_region_t *r = &ctx->regions[i];
        if ((uint64_t)cur >= (uint64_t)r->end) {
            continue;
        }
        if (cur < r->start) {
            return false;
        }
        if ((((uint32_t)r->prot) & need) != need) {
            return false;
        }
        cur = r->end;
    }
    return (uint64_t)cur >= end;
}

/* SPARC alignment: word accesses need 4-alignment, halfwords 2-alignment;
 * the oracle raises SIGBUS otherwise (L1d misaligned word load traps).
 * Single bytes never fault. Window spill/fill (64 B of words) needs only
 * word alignment. (Residual RC1 gap: 8-byte LDD/STD at 4-but-unaligned-8
 * emulates instead of faulting; no RC1 test covers it — Phase 3 owns
 * doubleword alignment with the FPU.) */
static bool interp_aligned(uint32_t va, uint32_t len)
{
    uint32_t need = (len <= 1U) ? 1U : ((len == 2U) ? 2U : 4U);
    return (va & (need - 1U)) == 0U;
}

bool interp_mem_rd(sparc32_ctx_t *ctx, uint32_t va, void *dst,
    uint32_t len)
{
    if (!interp_aligned(va, len)) {
        ctx->exit_reason = SPARC32_EXIT_FAULT;
        ctx->fault_addr = va;
        return false;
    }
    if (!interp_range_ok(ctx, va, len, 1U)) {
        ctx->exit_reason = SPARC32_EXIT_FAULT;
        ctx->fault_addr = va;
        return false;
    }
    memcpy(dst, sparc32_guest_ptr(ctx, va), (size_t)len);
    return true;
}

bool interp_mem_wr(sparc32_ctx_t *ctx, uint32_t va, const void *src,
    uint32_t len)
{
    if (!interp_aligned(va, len)) {
        ctx->exit_reason = SPARC32_EXIT_FAULT;
        ctx->fault_addr = va;
        return false;
    }
    if (!interp_range_ok(ctx, va, len, 2U)) {
        ctx->exit_reason = SPARC32_EXIT_FAULT;
        ctx->fault_addr = va;
        return false;
    }
    memcpy(sparc32_guest_ptr(ctx, va), src, (size_t)len);
    if (__atomic_load_n(&g_sparc32_ldstub_lock.va, __ATOMIC_RELAXED) == va &&
        __atomic_load_n(&g_sparc32_ldstub_lock.owner, __ATOMIC_RELAXED) ==
            (uintptr_t)ctx) {
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        __atomic_store_n(&g_sparc32_ldstub_lock.va, 0U, __ATOMIC_RELEASE);
        __atomic_store_n(&g_sparc32_ldstub_lock.owner, 0U, __ATOMIC_RELEASE);
    }
    return true;
}

bool interp_ld_be(sparc32_ctx_t *ctx, uint32_t va, uint32_t len,
    uint32_t *out)
{
    uint8_t b[4];
    uint32_t v = 0U;
    uint32_t i;
    if (!interp_mem_rd(ctx, va, b, len)) {
        return false;
    }
    for (i = 0; i < len; i++) {
        v = (v << 8) | (uint32_t)b[i];
    }
    *out = v;
    return true;
}

bool interp_st_be(sparc32_ctx_t *ctx, uint32_t va, uint32_t len,
    uint32_t v)
{
    uint8_t b[4];
    uint32_t i;
    for (i = 0; i < len; i++) {
        b[len - 1U - i] = (uint8_t)(v & 0xFFU);
        v >>= 8;
    }
    return interp_mem_wr(ctx, va, b, len);
}
