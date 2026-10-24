/*
 * src/dbt/emit_priv.h — Translator-local runtime helpers (Phase 2, L2c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L2c owns this file. These helpers run in the translator process
 * and are invoked from JIT-emitted code via BLR (see emit_int.c). They
 * implement exactly the operations whose state or checks cannot be
 * expressed inline without duplicating engine-hidden state:
 *
 * - sparc32_rt_window: SAVE/RESTORE through the shared interp window file
 *   (interp_win.c WIM model) so interp and dbt engines observe one window
 *   history even when blocks fall back to interp_step mid-run.
 * - sparc32_rt_mem: loads/stores/LDSTUB/SWAP/CASA with interp-identical
 *   alignment faults (misaligned multi-byte access faults, never
 *   emulates), region checks via ctx->regions, big-endian assembly, and
 *   the LEON ASI privilege policy (0x0a user ok, 0x0b supervisor traps).
 * - sparc32_rt_muldiv: MUL/DIV/MULScc/TADD/TSUB arithmetic with Y
 *   threading, icc N/Z/V/C, and divide-by-zero/tag traps, mirroring the
 *   reference interpreter expression for expression.
 *
 * All helpers return ctx->exit_reason (SPARC32_EXIT_NONE on success)
 * after recording fault/trap state (exit_reason, exit_arg, fault_addr,
 * exit_dest) exactly as the interpreter does. Emitted code tests the
 * return value and leaves the fragment with the fault PC in w15 and the
 * reason in w16. Guest memory is touched only through the [G, G + 4 GiB)
 * window (sparc32_guest_ptr + ctx->regions); faults use
 * ctx->exit_reason/ctx->fault_addr.
 *
 * Implementation note: the helpers live here as static functions so the
 * whole integer emitter (emit_int.c + this file) stays within the 900-line
 * per-file discipline. They compile into emit_int.o (the sole includer);
 * JIT-emitted code resolves their addresses at emit time from the
 * translator process. No other unit may call them or take their address.
 */

#ifndef SPARC32RT_DBT_EMIT_PRIV_H
#define SPARC32RT_DBT_EMIT_PRIV_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sparc32rt.h"
#include "interp/decode.h"
#include "interp/interp_priv.h"

static void rt_icc_nz(sparc32_ctx_t *ctx, uint32_t res)
{
    if ((res & 0x80000000u) != 0u) {
        ctx->psr |= SPARC32_PSR_N;
    }
    if (res == 0u) {
        ctx->psr |= SPARC32_PSR_Z;
    }
}

static void rt_icc_add(sparc32_ctx_t *ctx, uint32_t res, uint32_t a,
    uint32_t b, uint32_t cin)
{
    uint64_t full = (uint64_t)a + (uint64_t)b + (uint64_t)cin;
    int64_t s = (int64_t)(int32_t)a + (int64_t)(int32_t)b + (int64_t)cin;

    ctx->psr &= ~SPARC32_PSR_ICC_MASK;
    rt_icc_nz(ctx, res);
    if (s != (int64_t)(int32_t)res) {
        ctx->psr |= SPARC32_PSR_V;
    }
    if ((full >> 32) != 0u) {
        ctx->psr |= SPARC32_PSR_C;
    }
}

static void rt_icc_sub(sparc32_ctx_t *ctx, uint32_t res, uint32_t a,
    uint32_t b, uint32_t bin)
{
    uint64_t bb = (uint64_t)b + (uint64_t)bin;
    int64_t s = (int64_t)(int32_t)a - (int64_t)(int32_t)b - (int64_t)bin;

    ctx->psr &= ~SPARC32_PSR_ICC_MASK;
    rt_icc_nz(ctx, res);
    if (s != (int64_t)(int32_t)res) {
        ctx->psr |= SPARC32_PSR_V;
    }
    if ((uint64_t)a >= bb) {
        ctx->psr |= SPARC32_PSR_C;
    }
}

static uint32_t rt_trap(sparc32_ctx_t *ctx, uint32_t num, uint32_t pc)
{
    ctx->exit_reason = SPARC32_EXIT_TRAP;
    ctx->exit_arg = num;
    ctx->exit_dest = pc;
    return SPARC32_EXIT_TRAP;
}

static int rt_asi_ok(uint32_t asi)
{
    const char *e;

    if (asi == (uint32_t)SPARC32_ASI_USERDATA) {
        return 1;
    }
    if (asi != (uint32_t)SPARC32_ASI_KERNELDATA) {
        return 0;
    }
    e = getenv("SPARC32RT_LEON_SUPERVISOR_ASI");
    return e != NULL && e[0] == '1' && e[1] == '\0';
}

/* Multiply/divide/tagged op: op3 selects the operation, a/b operand
 * values, rd destination index, pc faulting address for trap exit_dest. */
static uint32_t sparc32_rt_muldiv(sparc32_ctx_t *ctx, uint32_t op3,
    uint32_t a, uint32_t b, uint32_t rd, uint32_t pc)
{
    uint32_t res;

    ctx->exit_reason = SPARC32_EXIT_NONE;
    switch (op3) {
    case 0x0AU: { /* UMUL */
        uint64_t p = (uint64_t)a * (uint64_t)b;

        ctx->y = (uint32_t)(p >> 32);
        interp_wreg(ctx, rd, (uint32_t)p);
        return SPARC32_EXIT_NONE;
    }
    case 0x0BU: { /* SMUL */
        int64_t p = (int64_t)(int32_t)a * (int64_t)(int32_t)b;

        ctx->y = (uint32_t)((uint64_t)p >> 32);
        interp_wreg(ctx, rd, (uint32_t)(uint64_t)p);
        return SPARC32_EXIT_NONE;
    }
    case 0x1AU: { /* UMULcc: V is the signed overflow (E03). */
        uint64_t p = (uint64_t)a * (uint64_t)b;
        int64_t sp = (int64_t)(int32_t)a * (int64_t)(int32_t)b;

        ctx->y = (uint32_t)(p >> 32);
        ctx->psr &= ~SPARC32_PSR_ICC_MASK;
        rt_icc_nz(ctx, (uint32_t)p);
        if (sp != (int64_t)(int32_t)(uint32_t)p) {
            ctx->psr |= SPARC32_PSR_V;
        }
        interp_wreg(ctx, rd, (uint32_t)p);
        return SPARC32_EXIT_NONE;
    }
    case 0x1BU: { /* SMULcc */
        int64_t p = (int64_t)(int32_t)a * (int64_t)(int32_t)b;

        ctx->y = (uint32_t)((uint64_t)p >> 32);
        ctx->psr &= ~SPARC32_PSR_ICC_MASK;
        rt_icc_nz(ctx, (uint32_t)(uint64_t)p);
        if (p != (int64_t)(int32_t)(uint32_t)(uint64_t)p) {
            ctx->psr |= SPARC32_PSR_V;
        }
        interp_wreg(ctx, rd, (uint32_t)(uint64_t)p);
        return SPARC32_EXIT_NONE;
    }
    case 0x0EU: { /* UDIV: (Y:rs1) dividend, div-by-zero traps. */
        uint64_t dvd = ((uint64_t)ctx->y << 32) | (uint64_t)a;

        if (b == 0u) {
            return rt_trap(ctx, 0x2Au, pc);
        }
        interp_wreg(ctx, rd, (uint32_t)(dvd / (uint64_t)b));
        return SPARC32_EXIT_NONE;
    }
    case 0x0FU: { /* SDIV: truncates toward zero. */
        int64_t dvd = ((int64_t)(int32_t)ctx->y << 32) | (int64_t)a;
        int32_t dvs = (int32_t)b;

        if (dvs == 0) {
            return rt_trap(ctx, 0x2Au, pc);
        }
        if (dvd == (int64_t)0x8000000000000000LL && dvs == -1) {
            interp_wreg(ctx, rd, 0x80000000u);
            return SPARC32_EXIT_NONE;
        }
        interp_wreg(ctx, rd, (uint32_t)(uint64_t)(dvd / (int64_t)dvs));
        return SPARC32_EXIT_NONE;
    }
    case 0x1EU: { /* UDIVcc: V iff the quotient exceeds 32 bits (E03). */
        uint64_t dvd = ((uint64_t)ctx->y << 32) | (uint64_t)a;
        uint64_t q;

        if (b == 0u) {
            return rt_trap(ctx, 0x2Au, pc);
        }
        q = dvd / (uint64_t)b;
        res = (uint32_t)q;
        ctx->psr &= ~SPARC32_PSR_ICC_MASK;
        rt_icc_nz(ctx, res);
        if (q > (uint64_t)0xFFFFFFFFu) {
            ctx->psr |= SPARC32_PSR_V;
        }
        interp_wreg(ctx, rd, res);
        return SPARC32_EXIT_NONE;
    }
    case 0x1FU: { /* SDIVcc */
        int64_t dvd = ((int64_t)(int32_t)ctx->y << 32) | (int64_t)a;
        int32_t dvs = (int32_t)b;
        int64_t q;

        if (dvs == 0) {
            return rt_trap(ctx, 0x2Au, pc);
        }
        ctx->psr &= ~SPARC32_PSR_ICC_MASK;
        if (dvd == (int64_t)0x8000000000000000LL && dvs == -1) {
            ctx->psr |= SPARC32_PSR_V | SPARC32_PSR_N;
            interp_wreg(ctx, rd, 0x80000000u);
            return SPARC32_EXIT_NONE;
        }
        q = dvd / (int64_t)dvs;
        res = (uint32_t)(uint64_t)q;
        rt_icc_nz(ctx, res);
        if (q != (int64_t)(int32_t)res) {
            ctx->psr |= SPARC32_PSR_V;
        }
        interp_wreg(ctx, rd, res);
        return SPARC32_EXIT_NONE;
    }
    case 0x20U: /* TADDcc */
        res = a + b;
        rt_icc_add(ctx, res, a, b, 0u);
        if (((a & 3u) | (b & 3u)) != 0u) {
            ctx->psr |= SPARC32_PSR_V;
        }
        interp_wreg(ctx, rd, res);
        return SPARC32_EXIT_NONE;
    case 0x21U: /* TSUBcc */
        res = a - b;
        rt_icc_sub(ctx, res, a, b, 0u);
        if (((a & 3u) | (b & 3u)) != 0u) {
            ctx->psr |= SPARC32_PSR_V;
        }
        interp_wreg(ctx, rd, res);
        return SPARC32_EXIT_NONE;
    case 0x22U: /* TADDccTV */
        res = a + b;
        rt_icc_add(ctx, res, a, b, 0u);
        if (((a & 3u) | (b & 3u)) != 0u) {
            ctx->psr |= SPARC32_PSR_V;
        }
        if ((ctx->psr & SPARC32_PSR_V) != 0u) {
            return rt_trap(ctx, 0x01u, pc);
        }
        interp_wreg(ctx, rd, res);
        return SPARC32_EXIT_NONE;
    case 0x23U: /* TSUBccTV */
        res = a - b;
        rt_icc_sub(ctx, res, a, b, 0u);
        if (((a & 3u) | (b & 3u)) != 0u) {
            ctx->psr |= SPARC32_PSR_V;
        }
        if ((ctx->psr & SPARC32_PSR_V) != 0u) {
            return rt_trap(ctx, 0x01u, pc);
        }
        interp_wreg(ctx, rd, res);
        return SPARC32_EXIT_NONE;
    case 0x24U: { /* MULSCC */
        int nv = (((ctx->psr & SPARC32_PSR_N) != 0u) !=
            ((ctx->psr & SPARC32_PSR_V) != 0u));
        uint32_t opnd = (nv != 0) ? b : 0u;
        uint64_t full = (uint64_t)a + (uint64_t)opnd;
        uint32_t sum = (uint32_t)full;
        int64_t s = (int64_t)(int32_t)a + (int64_t)(int32_t)opnd;
        uint32_t yold = ctx->y;

        ctx->y = ((a & 1u) << 31) | (yold >> 1);
        ctx->psr &= ~SPARC32_PSR_ICC_MASK;
        rt_icc_nz(ctx, sum);
        if (s != (int64_t)(int32_t)sum) {
            ctx->psr |= SPARC32_PSR_V;
        }
        if ((full >> 32) != 0u) {
            ctx->psr |= SPARC32_PSR_C;
        }
        interp_wreg(ctx, rd,
            ((yold & 1u) != 0u ? 0x80000000u : 0u) | (sum >> 1));
        return SPARC32_EXIT_NONE;
    }
    default:
        break;
    }
    ctx->exit_reason = SPARC32_EXIT_UNDEF;
    ctx->exit_dest = pc;
    return SPARC32_EXIT_UNDEF;
}

/* Window op: rs1 register index, src2 second-operand selector (simm13
 * value when ctl bit1 is set, rs2 index otherwise), rd destination index,
 * ctl bit0 = is_save, bit1 = is_imm, pc spill/fill fault address. */
static uint32_t sparc32_rt_window(sparc32_ctx_t *ctx, uint32_t rs1,
    uint32_t src2, uint32_t rd, uint32_t ctl, uint32_t pc)
{
    sparc32_decoded_t d;
    int is_save = ((ctl & 1u) != 0u) ? 1 : 0;

    (void)pc;
    memset(&d, 0, sizeof d);
    d.rs1 = rs1 & 31u;
    d.rd = rd & 31u;
    if ((ctl & 2u) != 0u) {
        d.is_imm = 1u;
        d.simm = (int32_t)src2;
    } else {
        d.rs2 = src2 & 31u;
    }
    ctx->exit_reason = SPARC32_EXIT_NONE;
    if (!interp_window(ctx, &d, is_save != 0)) {
        return ctx->exit_reason;
    }
    return SPARC32_EXIT_NONE;
}

/* Memory op: va effective address, op3 raw decoder op3 (alternate-space
 * bit 0x10 included), rd destination/source index, rs2 compare-register
 * index for CASA, asi alternate address-space id. */
static uint32_t sparc32_rt_mem(sparc32_ctx_t *ctx, uint32_t va, uint32_t op3,
    uint32_t rd, uint32_t rs2, uint32_t asi)
{
    uint32_t v;
    uint32_t base = op3;

    ctx->exit_reason = SPARC32_EXIT_NONE;
    if (op3 == 0x3Cu) { /* CASA: match swaps, rd always gets old mem. */
        uint32_t cmp = ctx->r[rs2 & 31u];
        uint32_t old_rd = ctx->r[rd & 31u];
        uint32_t mem;

        if (rt_asi_ok(asi) == 0) {
            return rt_trap(ctx, 0x03u, va);
        }
        if (!interp_ld_be(ctx, va, 4u, &mem)) {
            return ctx->exit_reason;
        }
        interp_wreg(ctx, rd, mem);
        if (mem == cmp && !interp_st_be(ctx, va, 4u, old_rd)) {
            return ctx->exit_reason;
        }
        return SPARC32_EXIT_NONE;
    }
    if (op3 == 0x0Fu || op3 == 0x1Fu) { /* SWAP/SWAPA */
        uint32_t old_rd = ctx->r[rd & 31u];

        if (((op3 & 0x10u) != 0u) && rt_asi_ok(asi) == 0) {
            return rt_trap(ctx, 0x03u, va);
        }
        if (!interp_ld_be(ctx, va, 4u, &v)) {
            return ctx->exit_reason;
        }
        if (!interp_st_be(ctx, va, 4u, old_rd)) {
            return ctx->exit_reason;
        }
        interp_wreg(ctx, rd, v);
        return SPARC32_EXIT_NONE;
    }
    if ((base & 0x10u) != 0u) {
        if (rt_asi_ok(asi) == 0) {
            return rt_trap(ctx, 0x03u, va);
        }
        base &= 0x0Fu;
    }
    switch (base) {
    case 0x00U:
    case 0x08U: /* LDUW / LDSW (sign extension is identity on words). */
        if (!interp_ld_be(ctx, va, 4u, &v)) {
            return ctx->exit_reason;
        }
        interp_wreg(ctx, rd, v);
        return SPARC32_EXIT_NONE;
    case 0x01U: /* LDUB */
        if (!interp_ld_be(ctx, va, 1u, &v)) {
            return ctx->exit_reason;
        }
        interp_wreg(ctx, rd, v);
        return SPARC32_EXIT_NONE;
    case 0x02U: /* LDUH */
        if (!interp_ld_be(ctx, va, 2u, &v)) {
            return ctx->exit_reason;
        }
        interp_wreg(ctx, rd, v);
        return SPARC32_EXIT_NONE;
    case 0x03U: /* LDD: even rd only (decoder guarantees). */
        if (!interp_ld_be(ctx, va, 4u, &v)) {
            return ctx->exit_reason;
        }
        interp_wreg(ctx, rd, v);
        if (!interp_ld_be(ctx, va + 4u, 4u, &v)) {
            return ctx->exit_reason;
        }
        interp_wreg(ctx, rd + 1u, v);
        return SPARC32_EXIT_NONE;
    case 0x04U: /* STW */
        if (!interp_st_be(ctx, va, 4u, ctx->r[rd & 31u])) {
            return ctx->exit_reason;
        }
        return SPARC32_EXIT_NONE;
    case 0x05U: /* STB */
        if (!interp_st_be(ctx, va, 1u, ctx->r[rd & 31u])) {
            return ctx->exit_reason;
        }
        return SPARC32_EXIT_NONE;
    case 0x06U: /* STH */
        if (!interp_st_be(ctx, va, 2u, ctx->r[rd & 31u])) {
            return ctx->exit_reason;
        }
        return SPARC32_EXIT_NONE;
    case 0x07U: /* STD: even rd only (decoder guarantees). */
        if (!interp_st_be(ctx, va, 4u, ctx->r[rd & 31u])) {
            return ctx->exit_reason;
        }
        if (!interp_st_be(ctx, va + 4u, 4u, ctx->r[(rd + 1u) & 31u])) {
            return ctx->exit_reason;
        }
        return SPARC32_EXIT_NONE;
    case 0x09U: /* LDSB */
        if (!interp_ld_be(ctx, va, 1u, &v)) {
            return ctx->exit_reason;
        }
        v &= 0xFFu;
        interp_wreg(ctx, rd, ((v & 0x80u) != 0u) ? v | 0xFFFFFF00u : v);
        return SPARC32_EXIT_NONE;
    case 0x0AU: /* LDSH */
        if (!interp_ld_be(ctx, va, 2u, &v)) {
            return ctx->exit_reason;
        }
        v &= 0xFFFFu;
        interp_wreg(ctx, rd, ((v & 0x8000u) != 0u) ? v | 0xFFFF0000u : v);
        return SPARC32_EXIT_NONE;
    case 0x0DU: /* LDSTUB: old byte to rd, 0xFF to memory. */
        if (!interp_ld_be(ctx, va, 1u, &v)) {
            return ctx->exit_reason;
        }
        if (!interp_st_be(ctx, va, 1u, 0xFFu)) {
            return ctx->exit_reason;
        }
        interp_wreg(ctx, rd, v);
        return SPARC32_EXIT_NONE;
    default:
        break;
    }
    /* Unreachable: the decoder only produces the op3 values above. */
    ctx->exit_reason = SPARC32_EXIT_UNDEF;
    ctx->exit_dest = va;
    return SPARC32_EXIT_UNDEF;
}

#endif /* SPARC32RT_DBT_EMIT_PRIV_H */
