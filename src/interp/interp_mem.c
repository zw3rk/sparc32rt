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

#include <sched.h>
#include <string.h>

uint8_t sparc32_ldstub_exchange(uint8_t *cell)
{
    static uint32_t gate = 0U;
    static uint8_t *active_cell = NULL;
    unsigned spins = 0U;
    for (;;) {
        uint8_t *act;
        while (__atomic_exchange_n(&gate, 1U, __ATOMIC_ACQUIRE) != 0U) {
            sched_yield();
        }
        act = __atomic_load_n(&active_cell, __ATOMIC_ACQUIRE);
        if (act == NULL || act == cell ||
            __atomic_load_n(act, __ATOMIC_SEQ_CST) != 0xFFU ||
            spins >= 1024U) {
            uint8_t old = __atomic_exchange_n(cell, (uint8_t)0xFFU,
                __ATOMIC_SEQ_CST);
            if (old == 0U) {
                __atomic_store_n(&active_cell, cell, __ATOMIC_RELEASE);
            }
            __atomic_store_n(&gate, 0U, __ATOMIC_RELEASE);
            if (old != 0U) {
                sched_yield();
            }
            return old;
        }
        __atomic_store_n(&gate, 0U, __ATOMIC_RELEASE);
        spins++;
        sched_yield();
    }
}

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
    const uint8_t *prot;
    uint32_t cur = va;
    size_t i;
    if (len == 0U || end > (uint64_t)SPARC32_TASK_SIZE_TOP) {
        return false;
    }
    prot = sparc32_vm_prot_base();
    if (prot != NULL) {
        uint32_t pg = va >> 12;
        uint32_t end_pg = (uint32_t)((end - 1ULL) >> 12);
        for (;;) {
            uint8_t p = __atomic_load_n(&prot[pg], __ATOMIC_ACQUIRE);
            if (((uint32_t)p & need) != need) {
                return false;
            }
            if (pg == end_pg) {
                return true;
            }
            pg++;
        }
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
 * word alignment; integer LDD/STD/LDDA/STDA enforce 8-byte alignment
 * directly in interp.c / emit_int.c before calling these word helpers. */
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
    sparc32_vm_access_enter();
    if (!interp_range_ok(ctx, va, len, 1U)) {
        sparc32_vm_access_leave();
        ctx->exit_reason = SPARC32_EXIT_FAULT;
        ctx->fault_addr = va;
        return false;
    }
    memcpy(dst, sparc32_guest_ptr(ctx, va), (size_t)len);
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    sparc32_vm_access_leave();
    return true;
}

bool interp_mem_wr(sparc32_ctx_t *ctx, uint32_t va, const void *src,
    uint32_t len)
{
    bool has_code;
    if (!interp_aligned(va, len)) {
        ctx->exit_reason = SPARC32_EXIT_FAULT;
        ctx->fault_addr = va;
        return false;
    }
    sparc32_vm_access_enter();
    if (!interp_range_ok(ctx, va, len, 2U)) {
        sparc32_vm_access_leave();
        ctx->exit_reason = SPARC32_EXIT_FAULT;
        ctx->fault_addr = va;
        return false;
    }
    __atomic_thread_fence(__ATOMIC_RELEASE);
    memcpy(sparc32_guest_ptr(ctx, va), src, (size_t)len);
    vm32_note_page_write(va, (size_t)len);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    has_code = vm32_range_has_code(va, (size_t)len);
    sparc32_vm_access_leave();
    if (has_code) {
        vm_invalidate_jit(ctx, va, va + len);
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
