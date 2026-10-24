/*
 * src/dbt/emit_fp.h — AArch64 FPU/FBfcc/FPMEM emitter interface (Phase 3, L3b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L3b owns this file (Phase 3 card, SPEC sections 2-3,
 * experiments/E06/FINDINGS.md). It lowers every FPop/FPMEM op the L3a
 * reference interpreter implements to AArch64 scalar FP/NEON, plus the
 * FBfcc transfer emitter that mirrors Bicc on FSR.fcc.
 *
 * V8 opf ground truth (verified with sparc64-linux-gnu-gcc -m32 GAS,
 * oracle container objdump; single/double differ only in the low opf
 * bit unless noted):
 *   FPop1 (op3 0x34): FMOV 0x01/0x02, FNEG 0x05/0x06, FABS 0x09/0x0A,
 *     FSQRT 0x29/0x2A, FADD 0x41/0x42, FSUB 0x45/0x46, FMUL 0x49/0x4A,
 *     FDIV 0x4D/0x4E, FsMULd 0x69 (double dest), FiTOs 0xC4,
 *     FiTOd 0xC8 (double dest), FsTOd 0xC9 (double dest),
 *     FdTOs 0xC6 (single dest), FsTOi 0xD1, FdTOi 0xD2.
 *   FPop2 (op3 0x35): FCMPs 0x51, FCMPd 0x52, FCMPEs 0x55, FCMPEd 0x56.
 *   Quad (FqTOd 0xCB, FDMULq 0x6E, LDQF/STQF 0x22/0x26, any other quad
 *   opf) and V9 64-bit-integer forms (FiTOx/FsTOx/FdTOx/FxTO*) are not
 *   implemented: EXIT_UNDEF (manual-strict, frozen contract 3).
 *   Any other opf: EXIT_UNDEF.
 *
 * Guest double model: SPARC %f[2k] (even) holds the HIGH word,
 * %f[2k+1] the LOW word (big-endian pair order, same as guest LDDF
 * memory layout and the integer LDD rd/rd+1 convention):
 *   ctx->f[2k] = bits 63:32, ctx->f[2k+1] = bits 31:0.
 * Integer-valued conversion operands live in the F register file as
 * raw 32-bit patterns (SPARC FPU convention: f[rd]/f[rs2]).
 *
 * fcc lives in ctx->fsr bits 11:10 (0=equal, 1=less, 2=greater,
 * 3=unordered); unordered FCMP/FCMPE additionally sets FSR bit 9
 * (qemu LEON3 reports fsr 0xe00 for NaN-vs-number, FINDINGS #2).
 *
 * Contract with L2b (inherits emit_int.h): x19 holds ctx, x20 the
 * G-window base (never x18); guest FP state lives in ctx memory
 * (f[32]/fsr); emitted code is safe across helper calls (helpers
 * preserve x19-x28 per AAPCS64); v0-v7 are scratch FP registers;
 * w15/w16/w17/w21/w22 are scratch.
 */

#ifndef SPARC32RT_DBT_EMIT_FP_H
#define SPARC32RT_DBT_EMIT_FP_H

#include <stdint.h>

#include "interp/decode.h"
#include "dbt/emit_int.h"

/* Emit one decoded FPU (FPop1/FPop2) instruction. Odd double-dest,
 * odd double-source, quad, V9-only, and unlisted opf encodings exit
 * EXIT_UNDEF at ec->pc (manual-strict, frozen contract 3). */
int sparc32_emit_fpu(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);

/* Emit one decoded FP memory op (LDF/LDDF/STF/STDF/LDFSR/STFSR).
 * LDQF/STQF and odd-rd LDDF/STDF exit EXIT_UNDEF at ec->pc.
 * Misaligned or unmapped access exits via the fault path carrying
 * ec->fault_pc (same protocol as the integer memory emitter). */
int sparc32_emit_fpmem(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);

/* Emit one FBfcc transfer. Mirrors sparc32_emit_branch exactly
 * (dual-PC, delay executes unless annulled away, annulled not-taken
 * never fetches, page-final (pc & 0xfff) == 0xffc SINGLE_STEP), except
 * the condition evaluates FSR.fcc instead of PSR.icc. */
int sparc32_emit_fbranch(sparc32_emit_ctx_t *ec, const sparc32_decoded_t *d);

#endif /* SPARC32RT_DBT_EMIT_FP_H */
