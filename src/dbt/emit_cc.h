/*
 * src/dbt/emit_cc.h — SPARC icc <-> AArch64 NZCV translation (DBT).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from emit_int.c for the 900-line file discipline (same pattern
 * as emit_fpmem.c). Lowering lives in src/dbt/emit_cc.c: committing the
 * host flags after ALU ops, seeding the host carry for ADDX/SUBX, and
 * rebuilding host NZCV from ctx->psr for Bicc/Ticc evaluation.
 */

#ifndef SPARC32RT_DBT_EMIT_CC_H
#define SPARC32RT_DBT_EMIT_CC_H

#include <stdbool.h>
#include <stdint.h>

#include "rt32/a64_emit.h"

/* Commit host NZCV (set by the preceding ADDS/SUBS/ANDS/ADCS/SBCS) into
 * ctx->psr icc bits. sub_ops flips the C bit: SUBcc/SUBXcc C is the
 * borrow (R1 oracle truth), the complement of the host carry. */
void sparc32_emit_commit_flags(a64_buf_t *b, bool sub_ops);

/* Seed the host carry flag from PSR.icc.C. sbc complements it: SUBX
 * subtracts the borrow while AArch64 SBC subtracts (1 - C). */
void sparc32_emit_seed_carry(a64_buf_t *b, bool sbc);

/* Build host NZCV from ctx->psr icc for Bicc/Ticc cond evaluation.
 * Flips the reconstructed host C for BLEU/BGU, whose host LS/HI sense
 * is the complement of the stored borrow (R1). */
void sparc32_emit_cond_setup(a64_buf_t *b, uint32_t cond);

#endif /* SPARC32RT_DBT_EMIT_CC_H */
