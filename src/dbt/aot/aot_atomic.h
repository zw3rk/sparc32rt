/*
 * src/dbt/aot/aot_atomic.h — Shared SEQ_CST atomic RMW primitives
 * (Wave U3, lane U3-sparc32)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Canonical LDSTUB / SWAP / CASA implementations for sparc32rt.
 * UNIFICATION-PLAN.md Rev 4 section 4.4 requires every interpreter and
 * DBT atomic handler to execute C11 __atomic_* builtins with
 * __ATOMIC_SEQ_CST on the resolved canonical host address (HVA) — never
 * a plain load + store pair, which loses a concurrent writer racing
 * between the two accesses.
 *
 * Guest memory holds big-endian bytes. The 4-byte SWAP/CASA exchange the
 * whole 32-bit cell atomically; the BE encode/decode helpers below only
 * change the value interpretation, never the in-memory byte image, so the
 * exchange is representation-safe on any host endianness.
 *
 * Both engines must call these (Wave U3 parity):
 *   - src/interp/interp.c (interp_casa / interp_swap / LDSTUB case 0x0D)
 *   - src/dbt/emit_priv.h (sparc32_rt_mem CASA / SWAP / LDSTUB arms;
 *     L2c-owned, pending a one-line call swap by the Coordinator)
 *
 * No AArch64 assembly in this header (x18 discipline is vacuous here).
 */

#ifndef SPARC32RT_DBT_AOT_ATOMIC_H
#define SPARC32RT_DBT_AOT_ATOMIC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sparc32rt.h"
#include "interp/interp_priv.h"

/* Encode a guest word to the 32-bit cell image stored at HVA (BE bytes). */
static inline uint32_t sparc32_be_cell_encode(uint32_t v)
{
    uint8_t b[4];
    uint32_t w = 0U;
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)v;
    memcpy(&w, b, sizeof w);
    return w;
}

/* Decode a 32-bit HVA cell image back to a guest word (BE bytes). */
static inline uint32_t sparc32_be_cell_decode(uint32_t w)
{
    uint8_t b[4];
    memcpy(b, &w, sizeof w);
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
        ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

/*
 * Resolve the canonical host address for [va, va+len) with the required
 * guest PROT bits (1 = read, 2 = write; atomics need 3). Mirrors the
 * fault contract of interp_mem_rd/interp_mem_wr: misalignment of a
 * multi-byte access and missing coverage both report EXIT_FAULT with
 * fault_addr set, and no guest byte is touched. Returns NULL on fault.
 */
static inline void *sparc32_atomic_hva(sparc32_ctx_t *ctx, uint32_t va,
    uint32_t len, uint32_t need)
{
    uint32_t need_align = (len <= 1U) ? 1U : ((len == 2U) ? 2U : 4U);
    if ((va & (need_align - 1U)) != 0U) {
        ctx->exit_reason = SPARC32_EXIT_FAULT;
        ctx->fault_addr = va;
        return NULL;
    }
    if (!interp_range_ok(ctx, va, len, need)) {
        ctx->exit_reason = SPARC32_EXIT_FAULT;
        ctx->fault_addr = va;
        return NULL;
    }
    return sparc32_guest_ptr(ctx, va);
}

/*
 * LDSTUB [%rs1 + src2], %rd: atomically read the old byte into rd and
 * force the cell to 0xFF. Single-byte access: never an alignment fault.
 */
static inline bool sparc32_atomic_ldstub(sparc32_ctx_t *ctx, uint32_t va,
    uint32_t rd)
{
    uint8_t *cell;
    uint8_t old;
    void *hva = sparc32_atomic_hva(ctx, va, 1U, 3U);
    if (hva == NULL) {
        return false;
    }
    cell = (uint8_t *)hva;
    old = __atomic_exchange_n(cell, (uint8_t)0xFF, __ATOMIC_SEQ_CST);
    interp_wreg(ctx, rd, (uint32_t)old);
    return true;
}

/*
 * SWAP [%rs1 + src2], %rd: atomically exchange the 4-byte BE cell with
 * the old rd value; rd always receives the old memory contents.
 */
static inline bool sparc32_atomic_swap(sparc32_ctx_t *ctx, uint32_t va,
    uint32_t rd)
{
    uint32_t old_rd = ctx->r[rd & 31U];
    uint32_t new_cell = sparc32_be_cell_encode(old_rd);
    uint32_t old_cell;
    uint32_t *cell;
    void *hva = sparc32_atomic_hva(ctx, va, 4U, 3U);
    if (hva == NULL) {
        return false;
    }
    cell = (uint32_t *)hva;
    old_cell = __atomic_exchange_n(cell, new_cell, __ATOMIC_SEQ_CST);
    interp_wreg(ctx, rd, sparc32_be_cell_decode(old_cell));
    return true;
}

/*
 * CASA [%rs1] %asi, %rs2, %rd: compare the 4-byte BE cell against rs2;
 * on equality atomically store old rd. rd always receives the old memory
 * contents (match swaps, LEON semantics).
 */
static inline bool sparc32_atomic_casa(sparc32_ctx_t *ctx, uint32_t va,
    uint32_t rs2, uint32_t rd)
{
    uint32_t cmp = ctx->r[rs2 & 31U];
    uint32_t old_rd = ctx->r[rd & 31U];
    uint32_t expected = sparc32_be_cell_encode(cmp);
    uint32_t desired = sparc32_be_cell_encode(old_rd);
    uint32_t *cell;
    void *hva = sparc32_atomic_hva(ctx, va, 4U, 3U);
    if (hva == NULL) {
        return false;
    }
    cell = (uint32_t *)hva;
    __atomic_compare_exchange_n(cell, &expected, desired, false,
        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    interp_wreg(ctx, rd, sparc32_be_cell_decode(expected));
    return true;
}

#endif /* SPARC32RT_DBT_AOT_ATOMIC_H */
