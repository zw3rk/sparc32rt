/*
 * src/interp/decode.c — SPARC V8 base integer instruction decoder
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 1 lane L1a (SPEC section 2.1, experiments/E01..E06). Big-endian
 * fetch plus op/op2/op3 dispatch into sparc32_decoded_t. Execution
 * semantics belong to lane L1b; FPU execution belongs to Phase 3.
 */

#include "interp/decode.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "sparc32rt.h"

/* Sign-extend the low n bits of v (1 <= n <= 31). Branchless and fully
 * defined: the old ((v << shift) >> shift) form shifted right as UNSIGNED
 * (logical shift), discarding the sign it had just shifted into bit 31. */
static int32_t sign_extend(uint32_t v, uint32_t n)
{
    uint32_t m = 1U << (n - 1U);
    uint32_t x = v & ((1U << n) - 1U);

    return (int32_t)((x ^ m) - m);
}

/* FPop1 opf values with a double-precision destination (V8 opf table):
 * even-pair rd required, odd rd decodes illegal (E06 oracle leniency
 * delta: qemu executes it, LEON hardware traps, translator is strict). */
static int fpu_double_dest(uint32_t op3, uint32_t opf)
{
    if (op3 == SPARC32_OP3_FPOP1) {
        switch (opf) {
        case 0x002U: /* FMOVd */
        case 0x006U: /* FNEGd */
        case 0x00AU: /* FABSd */
        case 0x042U: /* FADDd */
        case 0x046U: /* FSUBd */
        case 0x04AU: /* FMULd */
        case 0x04EU: /* FDIVd */
        case 0x0C6U: /* FiTOd */
        case 0x0C9U: /* FsTOd */
        case 0x0CBU: /* FqTOd */
            return 1;
        default:
            return 0;
        }
    }
    if (op3 == SPARC32_OP3_FPOP2) {
        /* FsMULd (single x single -> double); FDMULq is quad-dest and
         * passes through for Phase 3 to trap on this LEON target. */
        return opf == 0x069U;
    }
    return 0;
}

/* op == 2 ALU membership (integer operate incl. MUL/DIV/MULScc/tagged).
 * cc outputs mirror op3 bit 4 for the whole family. */
static int is_alu_op3(uint32_t op3)
{
    switch (op3) {
    case 0x00U:
    case 0x01U:
    case 0x02U:
    case 0x03U:
    case 0x04U:
    case 0x05U:
    case 0x06U:
    case 0x07U:
    case 0x08U:
    case SPARC32_OP3_UMUL:
    case SPARC32_OP3_SMUL:
    case SPARC32_OP3_SUBX:
    case SPARC32_OP3_UDIV:
    case SPARC32_OP3_SDIV:
    case 0x10U:
    case 0x11U:
    case 0x12U:
    case 0x13U:
    case 0x14U:
    case 0x15U:
    case 0x16U:
    case 0x17U:
    case 0x18U:
    case 0x1AU:
    case 0x1BU:
    case 0x1CU:
    case 0x1EU:
    case 0x1FU:
    case 0x20U:
    case 0x21U:
    case 0x22U:
    case 0x23U:
    case SPARC32_OP3_MULSCC:
        return 1;
    default:
        return 0;
    }
}

/* Doubleword memory ops need an even rd (manual-strict, like FP odd-rd). */
static int is_double_mem_op3(uint32_t op3)
{
    return op3 == SPARC32_OP3_LDD || op3 == SPARC32_OP3_STD ||
        op3 == SPARC32_OP3_LDDA || op3 == SPARC32_OP3_STDA;
}

static int is_load_op3(uint32_t op3)
{
    switch (op3) {
    case SPARC32_OP3_LDUW:
    case SPARC32_OP3_LDUB:
    case SPARC32_OP3_LDUH:
    case SPARC32_OP3_LDD:
    case SPARC32_OP3_LDSW:
    case SPARC32_OP3_LDSB:
    case SPARC32_OP3_LDSH:
    case SPARC32_OP3_LDSTUB:
    case SPARC32_OP3_LDA:
    case SPARC32_OP3_LDUBA:
    case SPARC32_OP3_LDUHA:
    case SPARC32_OP3_LDDA:
    case SPARC32_OP3_LDSWA:
    case SPARC32_OP3_LDSBA:
    case SPARC32_OP3_LDSHA:
    case SPARC32_OP3_LDSTUBA:
        return 1;
    default:
        return 0;
    }
}

static int is_store_op3(uint32_t op3)
{
    switch (op3) {
    case SPARC32_OP3_STW:
    case SPARC32_OP3_STB:
    case SPARC32_OP3_STH:
    case SPARC32_OP3_STD:
    case SPARC32_OP3_STA:
    case SPARC32_OP3_STBA:
    case SPARC32_OP3_STHA:
    case SPARC32_OP3_STDA:
        return 1;
    default:
        return 0;
    }
}

static void decode_format2(uint32_t word, sparc32_decoded_t *out)
{
    uint32_t op3 = (word >> 19) & 0x3FU;
    uint32_t rd = (word >> 25) & 0x1FU;
    uint32_t rs1 = (word >> 14) & 0x1FU;
    uint32_t i = (word >> 13) & 0x1U;

    out->op3 = op3;
    out->rd = rd;
    out->rs1 = rs1;
    out->is_imm = i;
    if (i != 0U) {
        out->simm = sign_extend(word & 0x1FFFU, 13U);
    } else {
        out->asi = (word >> 5) & 0xFFU;
        out->rs2 = word & 0x1FU;
    }

    if (is_alu_op3(op3)) {
        out->cls = SPARC32_OP_ALU;
        out->cc = (op3 & 0x10U) != 0U ? 1U : 0U;
        return;
    }

    switch (op3) {
    case SPARC32_OP3_SLL:
    case SPARC32_OP3_SRL:
    case SPARC32_OP3_SRA:
        out->cls = SPARC32_OP_SHIFT;
        return;
    case SPARC32_OP3_RDASR:
        out->cls = SPARC32_OP_RDASR;
        out->asr = rs1;
        return;
    case SPARC32_OP3_WRASR:
        out->cls = SPARC32_OP_WRASR;
        out->asr = rd;
        return;
    case SPARC32_OP3_RDPSR:
    case SPARC32_OP3_RDWIM:
    case SPARC32_OP3_RDTBR:
    case SPARC32_OP3_WRPSR:
    case SPARC32_OP3_WRWIM:
    case SPARC32_OP3_WRTBR:
    case SPARC32_OP3_RETT:
        out->cls = SPARC32_OP_PRIV;
        return;
    case SPARC32_OP3_FPOP1:
    case SPARC32_OP3_FPOP2: {
        uint32_t opf = (word >> 5) & 0x1FFU;
        out->opf = opf;
        out->rs2 = word & 0x1FU;
        out->asi = 0U;
        if (fpu_double_dest(op3, opf) && ((rd & 0x1U) != 0U)) {
            out->cls = SPARC32_OP_ILLEGAL;
            return;
        }
        out->cls = SPARC32_OP_FPU;
        return;
    }
    case SPARC32_OP3_JMPL:
        out->cls = SPARC32_OP_JMPL;
        return;
    case SPARC32_OP3_TICC:
        out->cls = SPARC32_OP_TRAP;
        out->cond = (word >> 25) & 0x0FU;
        return;
    case SPARC32_OP3_FLUSH:
        out->cls = SPARC32_OP_FLUSH;
        return;
    case SPARC32_OP3_STBAR:
        out->cls = SPARC32_OP_STBAR;
        return;
    case SPARC32_OP3_SAVE:
        out->cls = SPARC32_OP_SAVE;
        return;
    case SPARC32_OP3_RESTORE:
        out->cls = SPARC32_OP_RESTORE;
        return;
    default:
        /* CPop1/CPop2 (no LEON coprocessor) and unassigned op3. */
        out->cls = SPARC32_OP_ILLEGAL;
        return;
    }
}

static void decode_format3_mem(uint32_t word, sparc32_decoded_t *out)
{
    uint32_t op3 = (word >> 19) & 0x3FU;
    uint32_t rd = (word >> 25) & 0x1FU;
    uint32_t rs1 = (word >> 14) & 0x1FU;
    uint32_t i = (word >> 13) & 0x1U;

    out->op3 = op3;
    out->rd = rd;
    out->rs1 = rs1;
    out->is_imm = i;
    if (i != 0U) {
        out->simm = sign_extend(word & 0x1FFFU, 13U);
    } else {
        out->asi = (word >> 5) & 0xFFU;
        out->rs2 = word & 0x1FU;
    }

    if (op3 == SPARC32_OP3_CASA) {
        /* CASA carries its ASI in bits 12:5 with i == 1 (E03: the
         * 0xD5E22149 encoding has i set and asi 0x0a in that slot). */
        if (i == 0U) {
            out->cls = SPARC32_OP_ILLEGAL;
            return;
        }
        out->asi = (word >> 5) & 0xFFU;
        out->rs2 = word & 0x1FU;
        out->simm = 0;
        out->atomic = 1U;
        out->cls = SPARC32_OP_CASA;
        return;
    }
    if (op3 == SPARC32_OP3_SWAP || op3 == SPARC32_OP3_SWAPA) {
        out->atomic = 1U;
        out->cls = SPARC32_OP_SWAP;
        return;
    }
    if (is_load_op3(op3)) {
        if (op3 == SPARC32_OP3_LDSTUB || op3 == SPARC32_OP3_LDSTUBA) {
            out->atomic = 1U;
        }
        if (is_double_mem_op3(op3) && ((rd & 0x1U) != 0U)) {
            out->cls = SPARC32_OP_ILLEGAL;
            return;
        }
        out->cls = SPARC32_OP_LOAD;
        return;
    }
    if (is_store_op3(op3)) {
        if (is_double_mem_op3(op3) && ((rd & 0x1U) != 0U)) {
            out->cls = SPARC32_OP_ILLEGAL;
            return;
        }
        out->cls = SPARC32_OP_STORE;
        return;
    }
    /* FP loads/stores (Phase 3): purely syntactic here; odd-rd and quad
     * traps live in fp.c so UNDEF-vs-execute stays in one place. */
    switch (op3) {
    case SPARC32_OP3_LDF:
    case SPARC32_OP3_LDFSR:
    case SPARC32_OP3_LDQF:
    case SPARC32_OP3_LDDF:
    case SPARC32_OP3_STF:
    case SPARC32_OP3_STFSR:
    case SPARC32_OP3_STQF:
    case SPARC32_OP3_STDF:
        out->cls = SPARC32_OP_FPMEM;
        return;
    default:
        break;
    }
    /* LDX/LDXA (V9 64-bit), PREFETCH (V9), and the remaining gaps. */
    out->cls = SPARC32_OP_ILLEGAL;
}

void sparc32_decode_word(uint32_t word, sparc32_decoded_t *out)
{
    uint32_t op;

    if (out == NULL) {
        return;
    }
    out->raw = word;
    out->cls = SPARC32_OP_ILLEGAL;
    out->op = (word >> 30) & 0x3U;
    out->op2 = 0U;
    out->op3 = 0U;
    out->rd = 0U;
    out->rs1 = 0U;
    out->rs2 = 0U;
    out->is_imm = 0U;
    out->simm = 0;
    out->asi = 0U;
    out->cond = 0U;
    out->annul = 0U;
    out->disp = 0;
    out->uimm = 0U;
    out->opf = 0U;
    out->asr = 0U;
    out->atomic = 0U;
    out->cc = 0U;

    op = out->op;
    if (op == 0x1U) {
        /* Format 1 CALL: 30-bit word displacement, delay slot executes. */
        out->cls = SPARC32_OP_CALL;
        out->disp = sign_extend(word & 0x3FFFFFFFU, 30U) << 2;
        return;
    }
    if (op == 0x0U) {
        uint32_t op2 = (word >> 22) & 0x7U;
        out->op2 = op2;
        if (op2 == 0x4U) {
            out->cls = SPARC32_OP_SETHI;
            out->rd = (word >> 25) & 0x1FU;
            out->uimm = word & 0x3FFFFFU;
            return;
        }
        if (op2 == 0x2U || op2 == 0x6U) {
            uint32_t disp22 = word & 0x3FFFFFU;
            out->cls = (op2 == 0x2U) ? SPARC32_OP_BRANCH : SPARC32_OP_FBRANCH;
            out->annul = (word >> 29) & 0x1U;
            out->cond = (word >> 25) & 0x0FU;
            out->disp = sign_extend(disp22, 22U) << 2;
            return;
        }
        /* op2 == 0 is UNIMP (const22 trap operand); 1/3/5/7 are V9-only
         * (ILLTRAP/BPr/FBP/etc.): all illegal on this V8 target. */
        out->uimm = word & 0x3FFFFFU;
        out->cls = SPARC32_OP_ILLEGAL;
        return;
    }
    if (op == 0x2U) {
        decode_format2(word, out);
        return;
    }
    /* op == 0x3U: Format 3 memory incl. CASA. */
    decode_format3_mem(word, out);
}

/* Guest PROT bit for read (Linux PROT_READ; matches the tracked region
 * encoding in src/rt32/vm_mmap.c, which stores prot & 0x7). */
#define SPARC32_DECODE_PROT_READ 0x1U

int sparc32_fetch_decode(sparc32_ctx_t *ctx, uint32_t va, sparc32_decoded_t *out)
{
    sparc32_decoded_t tmp;
    const uint8_t *base;
    size_t k;
    uint32_t word;

    if (ctx == NULL || out == NULL) {
        return -1;
    }
    sparc32_decode_word(0U, out);
    if ((va & 0x3U) != 0U) {
        ctx->exit_reason = SPARC32_EXIT_FAULT;
        ctx->fault_addr = va;
        return -1;
    }
    if (ctx->region_count > 0U) {
        int covered = 0;
        for (k = 0; k < ctx->region_count; k++) {
            uint32_t start = ctx->regions[k].start;
            uint32_t end = ctx->regions[k].end;
            /* The whole 4-byte word must sit inside one readable region;
             * end > va guards against 32-bit wrap on small regions. */
            if (va >= start && end > va && (end - va) >= 4U &&
                ((ctx->regions[k].prot & SPARC32_DECODE_PROT_READ) != 0U)) {
                covered = 1;
                break;
            }
        }
        if (covered == 0) {
            ctx->exit_reason = SPARC32_EXIT_FAULT;
            ctx->fault_addr = va;
            if (ctx->trace_enabled) {
                size_t r;
                fprintf(stderr, "T FETCHFAIL va=%08x nregions=%zu\n", va,
                        ctx->region_count);
                for (r = 0; r < ctx->region_count; r++) {
                    fprintf(stderr, "T   [%zu] %08x..%08x prot=%x\n", r,
                            ctx->regions[r].start, ctx->regions[r].end,
                            ctx->regions[r].prot);
                }
            }
            return -1;
        }
    }
    /* Big-endian fetch through the [G, G + 4 GiB) window (SPEC: guest
     * memory only via the x20/uxtw window; byte assembly keeps this unit
     * host-endian clean without <endian.h>). */
    base = (const uint8_t *)sparc32_guest_ptr(ctx, va);
    word = ((uint32_t)base[0] << 24) | ((uint32_t)base[1] << 16) |
        ((uint32_t)base[2] << 8) | (uint32_t)base[3];
    sparc32_decode_word(word, &tmp);
    *out = tmp;
    return 0;
}
