/*
 * src/interp/fp.h — FPU/SIMD reference interpreter interface (Phase 3, L3a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Declares the FPU execution interface. Lane L3a owns this header;
 * interp.c uses it only through the explicit hook hunks (FPU/FPMEM
 * routing from interp_single, FBRANCH routing through interp_is_cti /
 * interp_cti). The arithmetic core lives in fp_arith.c; the shared
 * helpers below are lane-internal (used by fp.c and fp_arith.c only).
 *
 * Oracle ground truth (experiments/E06/FINDINGS.md plus lane-local qemu
 * probes against qemu-sparc 7.2 -cpu LEON3, recorded in the lane notes):
 * - FSR fcc = bits 11:10 (0 equal, 1 less, 2 greater, 3 unordered),
 *   RD = bits 31:30 (0 RN, 1 RZ, 2 RP, 3 RM), full 32-bit LDFSR/STFSR.
 * - NaN payloads propagate; 0.0/0.0 -> 0x7FFFFFFF_FFFFFFFF; FCMP
 *   unordered -> fcc=3 with fsr bit 9 (NVA) set; SNaN or FCMPE adds the
 *   cexc-NV bit; every FPop clears cexc and accumulates into aexc.
 * - qemu converts (FiTO/FsTO/FdTO) ignore FSR.RD (round to zero). The
 *   translator implements RD faithfully per the V8 manual; oracle tests
 *   pin RN only and interp-vs-dbt difftest proves RD!=RN parity.
 * - FBfcc conditions (verified insn by insn on the oracle):
 *   0 FBN{} 1 FBNE{1,2,3} 2 FBLG{1,2} 3 FBUL{1,3} 4 FBL{1} 5 FBUG{2,3}
 *   6 FBG{2} 7 FBU{3} 8 FBA{always} 9 FBE{0} 10 FBUE{0,3} 11 FBGE{0,2}
 *   12 FBUGE{0,2,3} 13 FBLE{0,1} 14 FBULE{0,1,3} 15 FBO{0,1,2}
 *   where the set lists the fcc values that take the branch.
 */

#ifndef SPARC32RT_INTERP_FP_H
#define SPARC32RT_INTERP_FP_H

#include <stdbool.h>
#include <stdint.h>

#include "sparc32rt.h"
#include "interp/decode.h"

/* FPop opf values implemented here (GAS-verified encodings; FPop2 forms
 * such as FCMP/FSMULD arrive with op3 0x35 and are dispatched on opf). */
#define FP_OPF_FMOVS  0x001U
#define FP_OPF_FMOVD  0x002U
#define FP_OPF_FNEGS  0x005U
#define FP_OPF_FNEGD  0x006U
#define FP_OPF_FABSS  0x009U
#define FP_OPF_FABSD  0x00AU
#define FP_OPF_FSQRTS 0x029U
#define FP_OPF_FSQRTD 0x02AU
#define FP_OPF_FADDS  0x041U
#define FP_OPF_FADDD  0x042U
#define FP_OPF_FSUBS  0x045U
#define FP_OPF_FSUBD  0x046U
#define FP_OPF_FMULS  0x049U
#define FP_OPF_FMULD  0x04AU
#define FP_OPF_FDIVS  0x04DU
#define FP_OPF_FDIVD  0x04EU
#define FP_OPF_FCMPS  0x051U
#define FP_OPF_FCMPD  0x052U
#define FP_OPF_FCMPES 0x055U
#define FP_OPF_FCMPED 0x056U
#define FP_OPF_FSMULD 0x069U
#define FP_OPF_FITOS  0x0C4U
#define FP_OPF_FDTOS  0x0C6U
#define FP_OPF_FITOD  0x0C8U
#define FP_OPF_FSTOD  0x0C9U
#define FP_OPF_FSTOI  0x0D1U
#define FP_OPF_FDTOI  0x0D2U

/* FSR fields (frozen header provides FCC shift/mask). */
#define FP_FSR_RD_SHIFT 30U
#define FP_FSR_TEM_SHIFT 23U
#define FP_FSR_TEM_MASK (0x1FU << 23)
#define FP_FSR_FTT_SHIFT 14U
#define FP_FSR_FTT_MASK (0x7U << 14)
#define FP_FSR_QNE_BIT (1U << 13)
#define FP_FSR_VER_MASK (0x7U << 17)
#define FP_FSR_FTT_IEEE 1U
#define FP_FSR_WRITABLE_MASK 0xCFC00FFFU
#define FP_FSR_CEXC_MASK 0x1FU
#define FP_FSR_NVA_BIT  (1U << 9)
#define FP_FSR_NVC_BIT  (1U << 4)
#define FP_FSR_OFC_BIT  (1U << 3)
#define FP_FSR_UFC_BIT  (1U << 2)
#define FP_FSR_DZC_BIT  (1U << 1)
#define FP_FSR_NXC_BIT  (1U << 0)
#define FP_TRAP_FP_EXCEPTION 0x07U

/* Rounding directions (FSR.RD). */
#define FP_RD_RN 0U
#define FP_RD_RZ 1U
#define FP_RD_RP 2U
#define FP_RD_RM 3U

/* IEEE-754 bit layouts. */
#define FP_F32_EXP_MASK  0x7F800000U
#define FP_F32_FRAC_MASK 0x007FFFFFU
#define FP_F32_QUIET_BIT 0x00400000U
#define FP_D64_EXP_MASK  0x7FF0000000000000ULL
#define FP_D64_FRAC_MASK 0x000FFFFFFFFFFFFFULL
#define FP_D64_QUIET_BIT 0x0008000000000000ULL

/* Canonical invalid-operation results (oracle: all-ones payloads). */
#define FP_F32_CANON_NAN 0x7FFFFFFFU
#define FP_F64_CANON_NAN 0x7FFFFFFFFFFFFFFFULL

/* Execute one FPop1/FPop2 instruction (SPARC32_OP_FPU class). Returns true
 * on clean completion (pc/npc left alone); on stop conditions (quad,
 * 64-bit, odd-rd double-dest or unlisted opf) records the exit state and
 * returns false, mirroring interp_single. */
bool sparc32_fp_step(sparc32_ctx_t *ctx, uint32_t pc,
    const sparc32_decoded_t *d);

/* Execute one FP load/store (SPARC32_OP_FPMEM class): LDF/LDFSR/LDDF and
 * STF/STFSR/STDF with the integer-memory fault rules (misaligned
 * multi-byte access -> EXIT_FAULT). Odd-rd LDDF/STDF and LDQF/STQF trap
 * EXIT_UNDEF, matching the manual-strict translator contract. */
bool sparc32_fp_mem(sparc32_ctx_t *ctx, uint32_t pc,
    const sparc32_decoded_t *d);

/* Evaluate an FBfcc condition against FSR.fcc. FBN (cond 0) never takes,
 * FBA (cond 8) always takes; all other conds follow the oracle table in
 * the header comment above. */
bool sparc32_fp_branch_taken(const sparc32_ctx_t *ctx, uint32_t cond);

/*
 * Lane-internal shared helpers (defined in fp_arith.c, used by fp.c).
 * Register accessors, bit reinterpretations, FSR state, NaN utilities.
 */
uint32_t fp_get_s(const sparc32_ctx_t *ctx, uint32_t r);
void fp_put_s(sparc32_ctx_t *ctx, uint32_t r, uint32_t v);
uint64_t fp_get_d(const sparc32_ctx_t *ctx, uint32_t r);
void fp_put_d(sparc32_ctx_t *ctx, uint32_t r, uint64_t v);
float fp_u32_to_f32(uint32_t v);
uint32_t fp_f32_to_u32(float f);
double fp_u64_to_f64(uint64_t v);
uint64_t fp_f64_to_u64(double d);
uint32_t fp_rd(const sparc32_ctx_t *ctx);
void fp_clear_cexc(sparc32_ctx_t *ctx);
void fp_raise(sparc32_ctx_t *ctx, uint32_t cexc);
void fp_set_fcc(sparc32_ctx_t *ctx, uint32_t fcc);
bool fp_f32_isnan(uint32_t v);
bool fp_f32_issnan(uint32_t v);
bool fp_f64_isnan(uint64_t v);
bool fp_f64_issnan(uint64_t v);
uint32_t fp_f32_quiet(uint32_t v);
uint64_t fp_f64_quiet(uint64_t v);
uint32_t fp_f32_pick_nan(uint32_t a, uint32_t b);
uint64_t fp_f64_pick_nan(uint64_t a, uint64_t b);

/*
 * Lane-internal arithmetic core (defined in fp_arith.c, used by fp.c).
 * Each clears FSR cexc, reports its IEEE flags, and returns the result.
 */
uint32_t fp_add_f32(sparc32_ctx_t *ctx, uint32_t a, uint32_t b);
uint64_t fp_add_f64(sparc32_ctx_t *ctx, uint64_t a, uint64_t b);
uint32_t fp_sub_f32(sparc32_ctx_t *ctx, uint32_t a, uint32_t b);
uint64_t fp_sub_f64(sparc32_ctx_t *ctx, uint64_t a, uint64_t b);
uint32_t fp_mul_f32(sparc32_ctx_t *ctx, uint32_t a, uint32_t b);
uint64_t fp_mul_f64(sparc32_ctx_t *ctx, uint64_t a, uint64_t b);
uint32_t fp_div_f32(sparc32_ctx_t *ctx, uint32_t a, uint32_t b);
uint64_t fp_div_f64(sparc32_ctx_t *ctx, uint64_t a, uint64_t b);
uint32_t fp_sqrt_f32(sparc32_ctx_t *ctx, uint32_t a);
uint64_t fp_sqrt_f64(sparc32_ctx_t *ctx, uint64_t a);
uint32_t fp_to_i32(sparc32_ctx_t *ctx, double v, uint32_t rd);
uint32_t fp_to_f32(sparc32_ctx_t *ctx, double v, uint32_t rd);
uint64_t fp_f32_to_f64(sparc32_ctx_t *ctx, uint32_t v);
void fp_cmp_f32(sparc32_ctx_t *ctx, uint32_t a, uint32_t b, bool signal);
void fp_cmp_f64(sparc32_ctx_t *ctx, uint64_t a, uint64_t b, bool signal);

#endif /* SPARC32RT_INTERP_FP_H */
