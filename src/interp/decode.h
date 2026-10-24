/*
 * src/interp/decode.h — Decoded-instruction representation + decoder API
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 1 lane L1a owns this file (SPEC section 2.1, experiments/E01..E06
 * oracle findings). It defines the decoded form of every SPEC section 2
 * base integer instruction and the big-endian fetch entry point used by
 * the reference interpreter (lane L1b) and the Phase 2 DBT frontend.
 *
 * Encoding authority: SPARC V8 manual, Format 1/2/3 field layout
 * (op/op2/op3 dispatch below). Execution semantics belong to L1b; this
 * unit only classifies words.
 */

#ifndef SPARC32RT_INTERP_DECODE_H
#define SPARC32RT_INTERP_DECODE_H

#include <stdint.h>

#include "sparc32rt.h"

/* Decoded instruction class (one per SPEC section 2 execution family). */
typedef enum {
    SPARC32_OP_ILLEGAL = 0, /* Undecodable, V9-only, unassigned op3, UNIMP,
                             * odd-rd LDD/STD(+A), odd-rd double FP dest,
                             * CASA with i == 0. L1b must never execute. */
    SPARC32_OP_CALL,    /* Format 1 CALL: disp30, writes %o7, delay executes. */
    SPARC32_OP_SETHI,   /* SETHI imm22 -> rd (rd == 0 is the classic NOP). */
    SPARC32_OP_BRANCH,  /* Bicc (op2 == 2): cond, annul bit, disp22.
                         * cond == 8 is BA (unconditional; ,a always annuls).
                         * cond == 0 is BN (never branches; delay still runs
                         * unless annulled). E02 oracle behavior. */
    SPARC32_OP_FBRANCH, /* FBfcc (op2 == 6): same shape, fcc condition.
                         * Phase 3 executes; interp returns EXIT_UNDEF. */
    SPARC32_OP_ALU,     /* Integer ALU incl. MUL/DIV/MULScc/TADD/TSUB (op3 in
                         * struct field); cc flag mirrors op3 bit 4. */
    SPARC32_OP_SHIFT,   /* SLL/SRL/SRA (op3 0x25/0x26/0x27). */
    SPARC32_OP_RDASR,   /* RDASR (op3 0x28): asr field holds rs1; asr == 0
                         * reads %y (RDY), else the numbered ASR (E03). */
    SPARC32_OP_WRASR,   /* WRASR (op3 0x30): asr field holds rd; rd == 0
                         * writes %y (WRY), else the numbered ASR. */
    SPARC32_OP_PRIV,    /* Privileged state access: RDPSR/RDWIM/RDTBR,
                         * WRPSR/WRWIM/WRTBR, RETT. op3 names the register;
                         * user-mode execution traps (L1b). */
    SPARC32_OP_FPU,     /* FPop1/FPop2 pass-through marker for Phase 3
                         * (opf/rs1/rs2/rd recorded; interp: EXIT_UNDEF). */
    SPARC32_OP_JMPL,    /* JMPL (op3 0x38): rd/rs1/src2; rd == 15 is the
                         * return/call linkage register, rd == 0 discards. */
    SPARC32_OP_SAVE,    /* SAVE (op3 0x3c): window rotate + spill (E01). */
    SPARC32_OP_RESTORE, /* RESTORE (op3 0x3d): window rotate + fill (E01). */
    SPARC32_OP_TRAP,    /* Ticc (op3 0x3a): cond + rs1/src2. TA (cond == 8)
                         * with simm13 == 0x10 is the syscall trap (E04). */
    SPARC32_OP_FLUSH,   /* FLUSH (op3 0x3b): rs1/src2 address hint. */
    SPARC32_OP_LOAD,    /* Loads incl. alternate-space (asi valid) and the
                         * LDSTUB atomic byte op (atomic flag set). */
    SPARC32_OP_STORE,   /* Stores incl. alternate-space (asi valid). */
    SPARC32_OP_SWAP,    /* SWAP/SWAPA atomic register/memory exchange (E03). */
    SPARC32_OP_CASA     /* LEON CASA (op3 0x3c on op == 3): rs1/rs2/rd/asi.
                         * Decode-only; the oracle cannot execute it
                         * (E03 casa.S trap 0x24), execution is L1b. */
} sparc32_op_t;

/* op == 2 (Format 3 ALU/misc) op3 values (SPARC V8). */
#define SPARC32_OP3_ADD     0x00U
#define SPARC32_OP3_AND     0x01U
#define SPARC32_OP3_OR      0x02U
#define SPARC32_OP3_XOR     0x03U
#define SPARC32_OP3_SUB     0x04U
#define SPARC32_OP3_ANDN    0x05U
#define SPARC32_OP3_ORN     0x06U
#define SPARC32_OP3_XORN    0x07U
#define SPARC32_OP3_ADDX    0x08U
#define SPARC32_OP3_UMUL    0x0AU
#define SPARC32_OP3_SMUL    0x0BU
#define SPARC32_OP3_SUBX    0x0CU
#define SPARC32_OP3_UDIV    0x0EU
#define SPARC32_OP3_SDIV    0x0FU
#define SPARC32_OP3_SLL     0x25U
#define SPARC32_OP3_SRL     0x26U
#define SPARC32_OP3_SRA     0x27U
#define SPARC32_OP3_RDASR   0x28U
#define SPARC32_OP3_RDPSR   0x29U
#define SPARC32_OP3_RDWIM   0x2AU
#define SPARC32_OP3_RDTBR   0x2BU
#define SPARC32_OP3_WRASR   0x30U
#define SPARC32_OP3_WRPSR   0x31U
#define SPARC32_OP3_WRWIM   0x32U
#define SPARC32_OP3_WRTBR   0x33U
#define SPARC32_OP3_FPOP1   0x34U
#define SPARC32_OP3_FPOP2   0x35U
#define SPARC32_OP3_CPOP1   0x36U
#define SPARC32_OP3_CPOP2   0x37U
#define SPARC32_OP3_JMPL    0x38U
#define SPARC32_OP3_RETT    0x39U
#define SPARC32_OP3_TICC    0x3AU
#define SPARC32_OP3_FLUSH   0x3BU
#define SPARC32_OP3_SAVE    0x3CU
#define SPARC32_OP3_RESTORE 0x3DU
#define SPARC32_OP3_MULSCC  0x24U

/* op == 3 (Format 3 memory) op3 values (SPARC V8 subset implemented). */
#define SPARC32_OP3_LDUW  0x00U
#define SPARC32_OP3_LDUB  0x01U
#define SPARC32_OP3_LDUH  0x02U
#define SPARC32_OP3_LDD   0x03U
#define SPARC32_OP3_STW   0x04U
#define SPARC32_OP3_STB   0x05U
#define SPARC32_OP3_STH   0x06U
#define SPARC32_OP3_STD   0x07U
#define SPARC32_OP3_LDSW  0x08U
#define SPARC32_OP3_LDSB  0x09U
#define SPARC32_OP3_LDSH  0x0AU
#define SPARC32_OP3_LDSTUB 0x0DU
#define SPARC32_OP3_SWAP  0x0FU
#define SPARC32_OP3_LDA   0x10U
#define SPARC32_OP3_LDUBA 0x11U
#define SPARC32_OP3_LDUHA 0x12U
#define SPARC32_OP3_LDDA  0x13U
#define SPARC32_OP3_STA   0x14U
#define SPARC32_OP3_STBA  0x15U
#define SPARC32_OP3_STHA  0x16U
#define SPARC32_OP3_STDA  0x17U
#define SPARC32_OP3_LDSWA 0x18U
#define SPARC32_OP3_LDSBA 0x19U
#define SPARC32_OP3_LDSHA 0x1AU
#define SPARC32_OP3_LDSTUBA 0x1DU
#define SPARC32_OP3_SWAPA 0x1FU
#define SPARC32_OP3_CASA  0x3CU

/* Bicc condition codes (op2 == 2, cond field). */
#define SPARC32_COND_BN 0x0U
#define SPARC32_COND_BE 0x1U
#define SPARC32_COND_BLE 0x2U
#define SPARC32_COND_BL 0x3U
#define SPARC32_COND_BLEU 0x4U
#define SPARC32_COND_BCS 0x5U
#define SPARC32_COND_BNEG 0x6U
#define SPARC32_COND_BVS 0x7U
#define SPARC32_COND_BA 0x8U
#define SPARC32_COND_BNE 0x9U
#define SPARC32_COND_BG 0xAU
#define SPARC32_COND_BGE 0xBU
#define SPARC32_COND_BGU 0xCU
#define SPARC32_COND_BCC 0xDU
#define SPARC32_COND_BPOS 0xEU
#define SPARC32_COND_BVC 0xFU

/* FBfcc condition codes (op2 == 6, cond field). */
#define SPARC32_FCOND_FBN 0x0U
#define SPARC32_FCOND_FBA 0x8U

/* Ticc condition codes share the Bicc numbering; TA == 8 is unconditional. */
#define SPARC32_TCOND_TN 0x0U
#define SPARC32_TCOND_TA 0x8U

/* The SPARC32 Linux syscall trap word (E04: ta 0x10 == 0x91d02010). */
#define SPARC32_TRAP_SYSCALL_NUM 0x10U
#define SPARC32_TRAP_SYSCALL_WORD 0x91D02010U

/* User-mode data ASI accepted unconditionally (SPEC 2.1, E03).
 * ASI_KERNELDATA (0x0b) traps ILL_PRVOPC unless the supervisor-ASI
 * escape is enabled; L1b owns that policy, the decoder just records. */
#define SPARC32_ASI_USERDATA 0x0AU
#define SPARC32_ASI_KERNELDATA 0x0BU

/* Decoded instruction: every field is filled to a defined value for every
 * class; fields unused by a class read 0. */
typedef struct {
    uint32_t raw;   /* Raw big-endian instruction word. */
    uint32_t cls;   /* sparc32_op_t class. */
    uint32_t op;    /* Top-level op field (bits 31:30). */
    uint32_t op2;   /* Format-2 op2 (op == 0 only). */
    uint32_t op3;   /* Format-3 op3 (op == 2/3 only). */
    uint32_t rd;    /* Destination register (Format 3; Ticc: trap cond). */
    uint32_t rs1;   /* First source register (Format 3). */
    uint32_t rs2;   /* Second source register (Format 3, i == 0; CASA). */
    uint32_t is_imm; /* i bit (Format 3 second-operand select). */
    int32_t  simm;  /* Sign-extended simm13 (Format 3, i == 1). */
    uint32_t asi;   /* Alternate-space ASI (Format 3 mem, i == 0; CASA). */
    uint32_t cond;  /* Branch/Ticc condition (bits 28:25). */
    uint32_t annul; /* Branch annul (a) bit. */
    int32_t  disp;  /* Scaled branch/call displacement in bytes
                     * (disp22/disp30 sign-extended, already << 2). */
    uint32_t uimm;  /* SETHI imm22 (caller shifts << 10) / UNIMP const22. */
    uint32_t opf;   /* FPU opf field (bits 13:5) for SPARC32_OP_FPU. */
    uint32_t asr;   /* ASR number for RDASR/WRASR (rs1/rd respectively). */
    uint32_t atomic; /* Set for LDSTUB/SWAP/CASA (E03 single-copy atomic). */
    uint32_t cc;    /* Set when the ALU op updates icc (op3 bit 4). */
} sparc32_decoded_t;

/* Pure word decoder: classifies one raw instruction word, no memory access.
 * Always fills *out (illegal words yield SPARC32_OP_ILLEGAL). */
void sparc32_decode_word(uint32_t word, sparc32_decoded_t *out);

/* Big-endian fetch + decode at guest VA. Returns 0 on success. On fault
 * (misaligned VA or no readable tracked region covering [va, va + 4))
 * sets ctx->exit_reason = SPARC32_EXIT_FAULT with ctx->fault_addr = va,
 * marks *out illegal, and returns -1. Guest bytes are read only through
 * the [G, G + 4 GiB) window (sparc32_guest_ptr); when no regions are
 * tracked yet (region_count == 0, early bring-up) the window read is used
 * directly without a coverage check. */
int sparc32_fetch_decode(sparc32_ctx_t *ctx, uint32_t va, sparc32_decoded_t *out);

#endif /* SPARC32RT_INTERP_DECODE_H */
