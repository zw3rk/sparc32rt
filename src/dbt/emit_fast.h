/*
 * src/dbt/emit_fast.h — Lane P5 inline fast paths (loads/stores, MUL)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SPARC32RT_DBT_EMIT_FAST_H
#define SPARC32RT_DBT_EMIT_FAST_H

#include "dbt/emit_int.h"
#include "interp/decode.h"

/* Emit an inline aligned load/store (LDUW/LDUB/LDUH/LDD/LDSW/LDSB/
 * LDSH/STW/STB/STH/STD) with REV and prot/code-page checks. Returns 1
 * when emitted (fast path with precise slow fallback inside), 0 when
 * the op is out of scope (caller uses the shared helper), -1 on
 * buffer overflow. */
int sparc32_emit_mem_fast(sparc32_emit_ctx_t *ec,
    const sparc32_decoded_t *d);

/* Emit inline UMUL/SMUL (Y:rd = 64-bit product). Returns 1/0/-1 with
 * the same contract. */
int sparc32_emit_mul_fast(sparc32_emit_ctx_t *ec,
    const sparc32_decoded_t *d);

#endif /* SPARC32RT_DBT_EMIT_FAST_H */
