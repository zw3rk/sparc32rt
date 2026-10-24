/*
 * src/interp/interp.c — Base integer reference interpreter (Phase 1, L1b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * interp_step() + interp_run() for every SPEC section 2 base integer
 * instruction: dual-PC stepping, annulled-delay semantics (E02), 8-window
 * SAVE/RESTORE via interp_win.c (E01 WIM model),
 * Y threading through MUL/DIV (E03), icc N/Z/V/C (E03: MULcc V is the
 * SIGNED overflow, SDIV truncates toward zero), LDSTUB/SWAP/CASA per the
 * LEON manual (match swaps, rd always gets old mem; ASI 0x0a ok, 0x0b
 * traps unless SPARC32RT_LEON_SUPERVISOR_ASI=1), ta 0x10 -> EXIT_SYSCALL
 * with the carry convention (E04), misaligned multi-byte accesses fault
 * (SIGBUS via sync delivery, oracle-compatible), single bytes never do
 * (qemu-oracle compatible), page-final non-annulled branch at 0xffc ->
 * EXIT_SINGLE_STEP. FPU/FPMEM route to fp.c (Phase 3, lane L3a);
 * quad, 64-bit and odd-rd double-dest FPop trap EXIT_UNDEF.
 *
 * Classification comes from the frozen L1a decoder (interp/decode.h):
 * interp_step() fetches via sparc32_fetch_decode() and dispatches on
 * sparc32_decoded_t (cls/op3/rd/rs1/rs2/is_imm/simm/asi/cond/annul/disp).
 * Engine policy on decoder classes (Coordinator-blessed): STBAR
 * (SPARC32_OP_STBAR) executes as a host-model nop; LDSW/LDSWA execute as
 * word loads (sign extension is the identity on words).
 * SAVE/RESTORE/CASA dispatch follows the L1a classes (SAVE is op == 2 /
 * op3 == 0x3c, RESTORE 0x3d, CASA op == 3 / op3 == 0x3c with i == 1).
 *
 * Guest memory uses only the [G, G + 4GiB) window via sparc32_guest_ptr()
 * after a ctx->regions coverage check; data gaps or missing R/W permission
 * set EXIT_FAULT with fault_addr. Instruction fetch faults come from
 * sparc32_fetch_decode(). Shared engine internals live behind
 * interp/interp_priv.h (interp_mem.c, interp_win.c, interp_signal.c).
 */

#include "sparc32rt.h"

#include "interp/decode.h"
#include "interp/fp.h"
#include "interp/interp_priv.h"
#include "os/sigframe_sparc32rt.h"
#include "os/syscalls_min.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SPARC32_TRAP_TAG_OVERFLOW 0x01U
#define SPARC32_TRAP_PRIV_INSN 0x03U
#define SPARC32_TRAP_DIV_ZERO 0x2AU
#define SPARC32_TRAP_SYSCALL 0x10U

static void interp_icc_logic(sparc32_ctx_t *ctx, uint32_t res)
{
    ctx->psr &= ~SPARC32_PSR_ICC_MASK;
    if ((res & 0x80000000U) != 0U) {
        ctx->psr |= SPARC32_PSR_N;
    }
    if (res == 0U) {
        ctx->psr |= SPARC32_PSR_Z;
    }
}

static void interp_icc_nz(sparc32_ctx_t *ctx, uint32_t res)
{
    if ((res & 0x80000000U) != 0U) {
        ctx->psr |= SPARC32_PSR_N;
    }
    if (res == 0U) {
        ctx->psr |= SPARC32_PSR_Z;
    }
}

static void interp_icc_add(sparc32_ctx_t *ctx, uint32_t res, uint32_t a,
    uint32_t b, uint32_t cin)
{
    uint64_t full = (uint64_t)a + (uint64_t)b + (uint64_t)cin;
    int64_t s = (int64_t)(int32_t)a + (int64_t)(int32_t)b + (int64_t)cin;
    ctx->psr &= ~SPARC32_PSR_ICC_MASK;
    interp_icc_nz(ctx, res);
    if (s != (int64_t)(int32_t)res) {
        ctx->psr |= SPARC32_PSR_V;
    }
    if ((full >> 32) != 0U) {
        ctx->psr |= SPARC32_PSR_C;
    }
}

/* SUBcc C is the borrow out of bit 31 (R1: oracle-verified LEON3
 * truth: C = 1 iff a < b + bin). BCS/BCC/BLEU/BGU read it directly,
 * and SUBX subtracts the outstanding borrow (cin below). */
static void interp_icc_sub(sparc32_ctx_t *ctx, uint32_t res, uint32_t a,
    uint32_t b, uint32_t bin)
{
    uint64_t bb = (uint64_t)b + (uint64_t)bin;
    int64_t s = (int64_t)(int32_t)a - (int64_t)(int32_t)b - (int64_t)bin;
    ctx->psr &= ~SPARC32_PSR_ICC_MASK;
    interp_icc_nz(ctx, res);
    if (s != (int64_t)(int32_t)res) {
        ctx->psr |= SPARC32_PSR_V;
    }
    if ((uint64_t)a < bb) {
        ctx->psr |= SPARC32_PSR_C;
    }
}

/* V8 Bicc/Ticc conditions. */
static bool interp_eval_cond(uint32_t cond, uint32_t psr)
{
    bool n = (psr & SPARC32_PSR_N) != 0U;
    bool z = (psr & SPARC32_PSR_Z) != 0U;
    bool v = (psr & SPARC32_PSR_V) != 0U;
    bool c = (psr & SPARC32_PSR_C) != 0U;
    switch (cond) {
    case 0x0U: return false;
    case 0x1U: return z;
    case 0x2U: return z || (n != v);
    case 0x3U: return n != v;
    case 0x4U: return c || z;
    case 0x5U: return c;
    case 0x6U: return n;
    case 0x7U: return v;
    case 0x8U: return true;
    case 0x9U: return !z;
    case 0xAU: return !(z || (n != v));
    case 0xBU: return n == v;
    case 0xCU: return !(c || z);
    case 0xDU: return !c;
    case 0xEU: return !n;
    default: return !v;
    }
}

static bool interp_asi_ok(uint32_t asi)
{
    const char *e;
    if (asi == (uint32_t)SPARC32_ASI_USERDATA) {
        return true;
    }
    if (asi != (uint32_t)SPARC32_ASI_KERNELDATA) {
        return false;
    }
    e = getenv("SPARC32RT_LEON_SUPERVISOR_ASI");
    return e != NULL && e[0] == '1' && e[1] == '\0';
}


/* Forward declaration: single-insn executor (no CTI). Leaves pc/npc alone
 * on clean completion; sets exit state (and trap pc advance) on stops. */
static bool interp_single(sparc32_ctx_t *ctx, uint32_t pc,
    const sparc32_decoded_t *d);

static bool interp_trap_taken(sparc32_ctx_t *ctx, uint32_t num)
{
    /* No pc advance here: the owner (sparc32_handle_syscall, SPEC 2.2)
     * commits pc = npc; npc += 4 exactly once per trap. Advancing here too
     * skipped the instruction after every syscall (observed: retl skipped,
     * guest ran off the end of .text). */
    if (num == SPARC32_TRAP_SYSCALL) {
        ctx->exit_reason = SPARC32_EXIT_SYSCALL;
        ctx->exit_arg = SPARC32_TRAP_SYSCALL;
    } else {
        ctx->exit_reason = SPARC32_EXIT_TRAP;
        ctx->exit_arg = num;
        ctx->exit_dest = ctx->pc;
    }
    return false;
}

static bool interp_undef(sparc32_ctx_t *ctx, uint32_t pc)
{
    ctx->exit_reason = SPARC32_EXIT_UNDEF;
    ctx->exit_dest = pc;
    return false;
}

/* MULcc shared tail: N/Z from lo, V = signed overflow (E03 #5), C = 0. */
static bool interp_mulcc(sparc32_ctx_t *ctx, uint32_t rd, uint32_t lo,
    int64_t sprod, uint64_t umag)
{
    ctx->y = (uint32_t)(umag >> 32);
    ctx->psr &= ~SPARC32_PSR_ICC_MASK;
    interp_icc_nz(ctx, lo);
    if (sprod != (int64_t)(int32_t)lo) {
        ctx->psr |= SPARC32_PSR_V;
    }
    interp_wreg(ctx, rd, lo);
    return true;
}

static bool interp_alu(sparc32_ctx_t *ctx, uint32_t pc,
    const sparc32_decoded_t *d)
{
    uint32_t op3 = d->op3;
    uint32_t rd = d->rd;
    uint32_t a = ctx->r[d->rs1];
    uint32_t b = (d->is_imm != 0U) ? (uint32_t)d->simm
                                   : ctx->r[d->rs2];
    uint32_t res;
    uint32_t cin;
    switch (op3) {
    case 0x00U: interp_wreg(ctx, rd, a + b); return true;
    case 0x01U: interp_wreg(ctx, rd, a & b); return true;
    case 0x02U: interp_wreg(ctx, rd, a | b); return true;
    case 0x03U: interp_wreg(ctx, rd, a ^ b); return true;
    case 0x04U: interp_wreg(ctx, rd, a - b); return true;
    case 0x05U: interp_wreg(ctx, rd, a & ~b); return true;
    case 0x06U: interp_wreg(ctx, rd, a | ~b); return true;
    case 0x07U: interp_wreg(ctx, rd, a ^ ~b); return true;
    case 0x08U:
        cin = (ctx->psr & SPARC32_PSR_C) != 0U ? 1U : 0U;
        interp_wreg(ctx, rd, a + b + cin);
        return true;
    case 0x0CU:
        cin = (ctx->psr & SPARC32_PSR_C) != 0U ? 1U : 0U;
        interp_wreg(ctx, rd, a - b - cin);
        return true;
    case 0x10U: res = a + b; interp_icc_add(ctx, res, a, b, 0U);
        interp_wreg(ctx, rd, res); return true;
    case 0x11U: res = a & b; interp_icc_logic(ctx, res);
        interp_wreg(ctx, rd, res); return true;
    case 0x12U: res = a | b; interp_icc_logic(ctx, res);
        interp_wreg(ctx, rd, res); return true;
    case 0x13U: res = a ^ b; interp_icc_logic(ctx, res);
        interp_wreg(ctx, rd, res); return true;
    case 0x14U: res = a - b; interp_icc_sub(ctx, res, a, b, 0U);
        interp_wreg(ctx, rd, res); return true;
    case 0x15U: res = a & ~b; interp_icc_logic(ctx, res);
        interp_wreg(ctx, rd, res); return true;
    case 0x16U: res = a | ~b; interp_icc_logic(ctx, res);
        interp_wreg(ctx, rd, res); return true;
    case 0x17U: res = a ^ ~b; interp_icc_logic(ctx, res);
        interp_wreg(ctx, rd, res); return true;
    case 0x18U: cin = (ctx->psr & SPARC32_PSR_C) != 0U ? 1U : 0U;
        res = a + b + cin; interp_icc_add(ctx, res, a, b, cin);
        interp_wreg(ctx, rd, res); return true;
    case 0x1CU: cin = (ctx->psr & SPARC32_PSR_C) != 0U ? 1U : 0U;
        res = a - b - cin; interp_icc_sub(ctx, res, a, b, cin);
        interp_wreg(ctx, rd, res); return true;
    case 0x0AU: { /* UMUL */
        uint64_t p = (uint64_t)a * (uint64_t)b;
        ctx->y = (uint32_t)(p >> 32);
        interp_wreg(ctx, rd, (uint32_t)p);
        return true;
    }
    case 0x0BU: { /* SMUL */
        int64_t p = (int64_t)(int32_t)a * (int64_t)(int32_t)b;
        ctx->y = (uint32_t)((uint64_t)p >> 32);
        interp_wreg(ctx, rd, (uint32_t)(uint64_t)p);
        return true;
    }
    case 0x1AU: { /* UMULcc */
        uint64_t p = (uint64_t)a * (uint64_t)b;
        int64_t sp = (int64_t)(int32_t)a * (int64_t)(int32_t)b;
        return interp_mulcc(ctx, rd, (uint32_t)p, sp, p);
    }
    case 0x1BU: { /* SMULcc */
        int64_t p = (int64_t)(int32_t)a * (int64_t)(int32_t)b;
        return interp_mulcc(ctx, rd, (uint32_t)(uint64_t)p, p,
            (uint64_t)p);
    }
    case 0x0EU: { /* UDIV */
        uint64_t dvd = ((uint64_t)ctx->y << 32) | (uint64_t)a;
        if (b == 0U) {
            return interp_trap_taken(ctx, SPARC32_TRAP_DIV_ZERO);
        }
        interp_wreg(ctx, rd, (uint32_t)(dvd / (uint64_t)b));
        return true;
    }
    case 0x0FU: { /* SDIV */
        int64_t dvd = ((int64_t)(int32_t)ctx->y << 32) | (int64_t)a;
        int32_t dvs = (int32_t)b;
        if (dvs == 0) {
            return interp_trap_taken(ctx, SPARC32_TRAP_DIV_ZERO);
        }
        if (dvd == (int64_t)0x8000000000000000LL && dvs == -1) {
            interp_wreg(ctx, rd, 0x80000000U);
            return true;
        }
        interp_wreg(ctx, rd, (uint32_t)(uint64_t)(dvd / (int64_t)dvs));
        return true;
    }
    case 0x1EU: { /* UDIVcc: V iff quotient exceeds 32 bits (E03 #10). */
        uint64_t dvd = ((uint64_t)ctx->y << 32) | (uint64_t)a;
        uint64_t q;
        if (b == 0U) {
            return interp_trap_taken(ctx, SPARC32_TRAP_DIV_ZERO);
        }
        q = dvd / (uint64_t)b;
        res = (uint32_t)q;
        ctx->psr &= ~SPARC32_PSR_ICC_MASK;
        interp_icc_nz(ctx, res);
        if (q > (uint64_t)0xFFFFFFFFU) {
            ctx->psr |= SPARC32_PSR_V;
        }
        interp_wreg(ctx, rd, res);
        return true;
    }
    case 0x1FU: { /* SDIVcc */
        int64_t dvd = ((int64_t)(int32_t)ctx->y << 32) | (int64_t)a;
        int32_t dvs = (int32_t)b;
        int64_t q;
        if (dvs == 0) {
            return interp_trap_taken(ctx, SPARC32_TRAP_DIV_ZERO);
        }
        ctx->psr &= ~SPARC32_PSR_ICC_MASK;
        if (dvd == (int64_t)0x8000000000000000LL && dvs == -1) {
            ctx->psr |= SPARC32_PSR_V | SPARC32_PSR_N;
            interp_wreg(ctx, rd, 0x80000000U);
            return true;
        }
        q = dvd / (int64_t)dvs;
        res = (uint32_t)(uint64_t)q;
        interp_icc_nz(ctx, res);
        if (q != (int64_t)(int32_t)res) {
            ctx->psr |= SPARC32_PSR_V;
        }
        interp_wreg(ctx, rd, res);
        return true;
    }
    case 0x20U: res = a + b; interp_icc_add(ctx, res, a, b, 0U);
        if (((a & 3U) | (b & 3U)) != 0U) ctx->psr |= SPARC32_PSR_V;
        interp_wreg(ctx, rd, res); return true;
    case 0x21U: res = a - b; interp_icc_sub(ctx, res, a, b, 0U);
        if (((a & 3U) | (b & 3U)) != 0U) ctx->psr |= SPARC32_PSR_V;
        interp_wreg(ctx, rd, res); return true;
    case 0x22U: res = a + b; interp_icc_add(ctx, res, a, b, 0U);
        if (((a & 3U) | (b & 3U)) != 0U) ctx->psr |= SPARC32_PSR_V;
        if ((ctx->psr & SPARC32_PSR_V) != 0U)
            return interp_trap_taken(ctx, SPARC32_TRAP_TAG_OVERFLOW);
        interp_wreg(ctx, rd, res); return true;
    case 0x23U: res = a - b; interp_icc_sub(ctx, res, a, b, 0U);
        if (((a & 3U) | (b & 3U)) != 0U) ctx->psr |= SPARC32_PSR_V;
        if ((ctx->psr & SPARC32_PSR_V) != 0U)
            return interp_trap_taken(ctx, SPARC32_TRAP_TAG_OVERFLOW);
        interp_wreg(ctx, rd, res); return true;
    case 0x24U: { /* MULSCC */
        bool nv = ((ctx->psr & SPARC32_PSR_N) != 0U) !=
            ((ctx->psr & SPARC32_PSR_V) != 0U);
        uint32_t opnd = nv ? b : 0U;
        uint64_t full = (uint64_t)a + (uint64_t)opnd;
        uint32_t sum = (uint32_t)full;
        int64_t s = (int64_t)(int32_t)a + (int64_t)(int32_t)opnd;
        uint32_t yold = ctx->y;
        ctx->y = ((a & 1U) << 31) | (yold >> 1);
        ctx->psr &= ~SPARC32_PSR_ICC_MASK;
        interp_icc_nz(ctx, sum);
        if (s != (int64_t)(int32_t)sum) {
            ctx->psr |= SPARC32_PSR_V;
        }
        if ((full >> 32) != 0U) {
            ctx->psr |= SPARC32_PSR_C;
        }
        interp_wreg(ctx, rd,
            ((yold & 1U) != 0U ? 0x80000000U : 0U) | (sum >> 1));
        return true;
    }
    case 0x25U: interp_wreg(ctx, rd, a << (b & 31U)); return true;
    case 0x26U: interp_wreg(ctx, rd, a >> (b & 31U)); return true;
    case 0x27U:
        interp_wreg(ctx, rd, (uint32_t)((int32_t)a >> (b & 31U)));
        return true;
    default: break;
    }
    /* Reserved op3: illegal here (STBAR never reaches this switch; the
     * decoder reports it ILLEGAL and interp_single turns it into a nop). */
    return interp_undef(ctx, pc);
}

static bool interp_rdwr(sparc32_ctx_t *ctx, const sparc32_decoded_t *d)
{
    uint32_t a = ctx->r[d->rs1];
    uint32_t b = (d->is_imm != 0U) ? (uint32_t)d->simm
                                   : ctx->r[d->rs2];
    if (d->cls == (uint32_t)SPARC32_OP_RDASR) {
        /* RDY reads %y; numbered-ASR reads trap (E03: only %y exists). */
        if (d->asr != 0U) {
            return interp_trap_taken(ctx, SPARC32_TRAP_PRIV_INSN);
        }
        interp_wreg(ctx, d->rd, ctx->y);
        return true;
    }
    /* WRASR: rd == 0 writes %y, else the numbered ASR traps. */
    if (d->asr != 0U) {
        return interp_trap_taken(ctx, SPARC32_TRAP_PRIV_INSN);
    }
    ctx->y = a ^ b;
    return true;
}

static bool interp_casa(sparc32_ctx_t *ctx, const sparc32_decoded_t *d)
{
    uint32_t cmp = ctx->r[d->rs2];
    uint32_t addr = ctx->r[d->rs1];
    uint32_t old_rd = ctx->r[d->rd];
    uint32_t mem;
    if (!interp_asi_ok(d->asi)) {
        return interp_trap_taken(ctx, SPARC32_TRAP_PRIV_INSN);
    }
    if (!interp_ld_be(ctx, addr, 4U, &mem)) {
        return false;
    }
    interp_wreg(ctx, d->rd, mem);
    if (mem == cmp && !interp_st_be(ctx, addr, 4U, old_rd)) {
        return false;
    }
    return true;
}

static bool interp_swap(sparc32_ctx_t *ctx, const sparc32_decoded_t *d)
{
    uint32_t addr = ctx->r[d->rs1] +
        ((d->is_imm != 0U) ? (uint32_t)d->simm : ctx->r[d->rs2]);
    uint32_t old_rd = ctx->r[d->rd];
    uint32_t v;
    if (((d->op3 & 0x10U) != 0U) && !interp_asi_ok(d->asi)) {
        return interp_trap_taken(ctx, SPARC32_TRAP_PRIV_INSN);
    }
    if (!interp_ld_be(ctx, addr, 4U, &v)) {
        return false;
    }
    if (!interp_st_be(ctx, addr, 4U, old_rd)) {
        return false;
    }
    interp_wreg(ctx, d->rd, v);
    return true;
}

/* Loads/stores, plain and alternate-space (asi checked first). LDSTUB is
 * the atomic byte op (read then force 0xFF); SWAP/CASA live in their own
 * handlers. LDSW/LDSWA execute as word loads (new vs the pre-merge file,
 * which returned UNDEF for op3 0x08/0x18). */
static bool interp_mem(sparc32_ctx_t *ctx, uint32_t pc,
    const sparc32_decoded_t *d)
{
    uint32_t addr = ctx->r[d->rs1] +
        ((d->is_imm != 0U) ? (uint32_t)d->simm : ctx->r[d->rs2]);
    uint32_t base = d->op3;
    uint32_t v;
    if ((base & 0x10U) != 0U) {
        if (!interp_asi_ok(d->asi)) {
            return interp_trap_taken(ctx, SPARC32_TRAP_PRIV_INSN);
        }
        base &= 0x0FU;
    }
    switch (base) {
    case 0x00U:
    case 0x08U: /* LDUW / LDSW (sign extension is the identity on words). */
        if (!interp_ld_be(ctx, addr, 4U, &v)) return false;
        interp_wreg(ctx, d->rd, v); return true;
    case 0x01U:
        if (!interp_ld_be(ctx, addr, 1U, &v)) return false;
        interp_wreg(ctx, d->rd, v); return true;
    case 0x02U:
        if (!interp_ld_be(ctx, addr, 2U, &v)) return false;
        interp_wreg(ctx, d->rd, v); return true;
    case 0x03U:
        if ((d->rd & 1U) != 0U) return interp_undef(ctx, pc);
        if (!interp_ld_be(ctx, addr, 4U, &v)) return false;
        interp_wreg(ctx, d->rd, v);
        if (!interp_ld_be(ctx, addr + 4U, 4U, &v)) return false;
        interp_wreg(ctx, d->rd + 1U, v); return true;
    case 0x04U: return interp_st_be(ctx, addr, 4U, ctx->r[d->rd]);
    case 0x05U: return interp_st_be(ctx, addr, 1U, ctx->r[d->rd]);
    case 0x06U: return interp_st_be(ctx, addr, 2U, ctx->r[d->rd]);
    case 0x07U:
        if ((d->rd & 1U) != 0U) {
            return interp_undef(ctx, pc);
        }
        if (!interp_st_be(ctx, addr, 4U, ctx->r[d->rd])) {
            return false;
        }
        return interp_st_be(ctx, addr + 4U, 4U, ctx->r[d->rd + 1U]);
    case 0x09U:
        if (!interp_ld_be(ctx, addr, 1U, &v)) return false;
        v &= 0xFFU;
        interp_wreg(ctx, d->rd, ((v & 0x80U) != 0U) ? v | 0xFFFFFF00U : v);
        return true;
    case 0x0AU:
        if (!interp_ld_be(ctx, addr, 2U, &v)) return false;
        v &= 0xFFFFU;
        interp_wreg(ctx, d->rd, ((v & 0x8000U) != 0U) ? v | 0xFFFF0000U : v);
        return true;
    case 0x0DU:
        if (!interp_ld_be(ctx, addr, 1U, &v)) return false;
        if (!interp_st_be(ctx, addr, 1U, 0xFFU)) return false;
        interp_wreg(ctx, d->rd, v); return true;
    default: break;
    }
    return interp_undef(ctx, pc);
}

static bool interp_single(sparc32_ctx_t *ctx, uint32_t pc,
    const sparc32_decoded_t *d)
{
    switch (d->cls) {
    case SPARC32_OP_SETHI:
        interp_wreg(ctx, d->rd, d->uimm << 10);
        return true;
    case SPARC32_OP_ALU:
    case SPARC32_OP_SHIFT:
        return interp_alu(ctx, pc, d);
    case SPARC32_OP_RDASR:
    case SPARC32_OP_WRASR:
        return interp_rdwr(ctx, d);
    case SPARC32_OP_PRIV:
        return interp_trap_taken(ctx, SPARC32_TRAP_PRIV_INSN);
    case SPARC32_OP_SAVE:
        return interp_window(ctx, d, true);
    case SPARC32_OP_RESTORE:
        return interp_window(ctx, d, false);
    case SPARC32_OP_FLUSH:
        return true; /* Host memory model needs no barrier. */
    case SPARC32_OP_LOAD:
    case SPARC32_OP_STORE:
        return interp_mem(ctx, pc, d);
    case SPARC32_OP_SWAP:
        return interp_swap(ctx, d);
    case SPARC32_OP_CASA:
        return interp_casa(ctx, d);
    case SPARC32_OP_FPU:
        return sparc32_fp_step(ctx, pc, d);
    case SPARC32_OP_FPMEM:
        return sparc32_fp_mem(ctx, pc, d);
    default:
        break;
    }
    /* CALL/BRANCH/FBRANCH/JMPL/TRAP never reach here: interp_step routes
     * CTIs through interp_cti() and traps inline. Anything else illegal
     * is UNDEF, except STBAR, which the host model executes as a nop. */
    if (d->cls == (uint32_t)SPARC32_OP_STBAR) {
        return true;
    }
    return interp_undef(ctx, pc);
}

static bool interp_is_cti(const sparc32_decoded_t *d)
{
    return d->cls == (uint32_t)SPARC32_OP_CALL ||
        d->cls == (uint32_t)SPARC32_OP_BRANCH ||
        d->cls == (uint32_t)SPARC32_OP_FBRANCH ||
        d->cls == (uint32_t)SPARC32_OP_JMPL;
}

/* CTI at pc (ctx->npc == pc + 4): delay slot, annul (E02), page-final. */
static void interp_cti(sparc32_ctx_t *ctx, uint32_t pc,
    const sparc32_decoded_t *d)
{
    uint32_t npc = ctx->npc;
    uint32_t target = 0U;
    uint32_t cond = 0x8U;
    bool taken = true;
    bool annul = false;
    bool runs;
    sparc32_decoded_t dd;
    bool page_final = (pc & 0xFFFU) == 0xFFCU;

    if (d->cls == (uint32_t)SPARC32_OP_CALL) {
        target = pc + (uint32_t)d->disp;
        interp_wreg(ctx, SPARC32_O7, pc);
    } else if (d->cls == (uint32_t)SPARC32_OP_BRANCH) {
        cond = d->cond;
        annul = d->annul != 0U;
        taken = interp_eval_cond(cond, ctx->psr);
        target = pc + (uint32_t)d->disp;
    } else if (d->cls == (uint32_t)SPARC32_OP_FBRANCH) {
        /* FBfcc mirrors Bicc exactly (dual-PC, delay, annul,
         * page-final) except the condition evaluates FSR.fcc in
         * fp.c instead of PSR.icc. */
        cond = d->cond;
        annul = d->annul != 0U;
        taken = sparc32_fp_branch_taken(ctx, d->cond);
        target = pc + (uint32_t)d->disp;
    } else { /* JMPL: RETT decodes PRIV, never reaches here. */
        uint32_t b = (d->is_imm != 0U) ? (uint32_t)d->simm
                                       : ctx->r[d->rs2];
        target = ctx->r[d->rs1] + b;
        interp_wreg(ctx, d->rd, pc);
    }

    /* Delay runs unless annulled away (E02): taken BA,a always skips;
     * not-taken Bicc,a skips without fetching (no next-page fault). */
    if (taken) {
        runs = !(cond == 0x8U && annul &&
            (d->cls == (uint32_t)SPARC32_OP_BRANCH ||
             d->cls == (uint32_t)SPARC32_OP_FBRANCH));
    } else {
        runs = !annul;
    }
    if (!runs) {
        if (taken) {
            ctx->pc = target;
            ctx->npc = target + 4U;
        } else {
            ctx->pc = npc + 4U;
            ctx->npc = npc + 8U;
        }
        return;
    }
    if (ctx->trace_enabled) {
        fprintf(stderr, "T cti pc=%08x taken=%u target=%08x npc=%08x\n", pc,
                taken ? 1U : 0U, target, npc);
    }
    if (sparc32_fetch_decode(ctx, npc, &dd) != 0) {
        return;
    }
    if (interp_is_cti(&dd)) {
        /* CTI in a delay slot is implementation-defined; run the inner
         * transfer and let it redirect pc/npc (outer is cancelled). */
        interp_cti(ctx, npc, &dd);
        return;
    }
    if (!interp_single(ctx, npc, &dd)) {
        return;
    }
    if (taken) {
        ctx->pc = target;
        ctx->npc = target + 4U;
    } else {
        ctx->pc = npc + 4U;
        ctx->npc = npc + 8U;
    }
    /* Non-annulled page-final branch: the next fetch crosses a page. */
    if (page_final) {
        ctx->exit_reason = SPARC32_EXIT_SINGLE_STEP;
        ctx->exit_dest = ctx->pc;
    }
}

void interp_step(sparc32_ctx_t *ctx)
{
    uint32_t pc;
    sparc32_decoded_t d;
    if (ctx == NULL) {
        return;
    }
    /* Async safe point (Phase 4): a redirected pc consumes this step. */
    if (interp_poll_async(ctx)) {
        ctx->r[0] = 0U;
        return;
    }
    ctx->r[0] = 0U;
    pc = ctx->pc;
    if (sparc32_fetch_decode(ctx, pc, &d) != 0) {
        return;
    }
    if (ctx->trace_enabled) {
        fprintf(stderr, "T pc=%08x npc=%08x raw=%08x cls=%u\n", pc, ctx->npc,
                d.raw, d.cls);
    }
    if (interp_is_cti(&d)) {
        interp_cti(ctx, pc, &d);
        ctx->r[0] = 0U;
        return;
    }
    if (d.cls == (uint32_t)SPARC32_OP_TRAP) {
        /* Ticc has no delay slot; 0x10 with a true condition is the
         * syscall gate (E04), any other true trap number -> EXIT_TRAP. */
        uint32_t b = (d.is_imm != 0U) ? (uint32_t)d.simm
                                      : ctx->r[d.rs2];
        if (interp_eval_cond(d.cond, ctx->psr)) {
            interp_trap_taken(ctx, (ctx->r[d.rs1] + b) & 0x7FU);
        } else {
            ctx->pc = ctx->npc;
            ctx->npc += 4U;
        }
        ctx->r[0] = 0U;
        return;
    }
    if (!interp_single(ctx, pc, &d)) {
        ctx->r[0] = 0U;
        return;
    }
    ctx->pc = ctx->npc;
    ctx->npc += 4U;
    ctx->r[0] = 0U;
}

void interp_run(sparc32_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    ctx->exit_reason = SPARC32_EXIT_NONE;
    while (ctx->exit_reason == SPARC32_EXIT_NONE) {
        interp_step(ctx);
    }
}
