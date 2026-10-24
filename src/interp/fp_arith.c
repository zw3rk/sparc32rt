/*
 * src/interp/fp_arith.c — FPU arithmetic core (Phase 3, lane L3a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements the computational half of the lane-L3a FPU interpreter:
 * register accessors, FSR state, NaN utilities, conversions with all
 * four FSR.RD modes, arithmetic (always round-to-nearest), and compares.
 * Shared helpers are declared in interp/fp.h; the dispatcher lives in
 * interp/fp.c. Split from fp.c to honor the 900-line file discipline.
 */

#include "interp/fp.h"

#include "interp/decode.h"
#include "interp/interp_priv.h"

#include <math.h>
#include <stdint.h>
#include <string.h>

uint32_t fp_get_s(const sparc32_ctx_t *ctx, uint32_t r)
{
    return ctx->f[r & 31U];
}

void fp_put_s(sparc32_ctx_t *ctx, uint32_t r, uint32_t v)
{
    ctx->f[r & 31U] = v;
}

uint64_t fp_get_d(const sparc32_ctx_t *ctx, uint32_t r)
{
    uint64_t hi = (uint64_t)ctx->f[r & 31U];
    uint64_t lo = (uint64_t)ctx->f[(r + 1U) & 31U];
    return (hi << 32) | lo;
}

void fp_put_d(sparc32_ctx_t *ctx, uint32_t r, uint64_t v)
{
    ctx->f[r & 31U] = (uint32_t)(v >> 32);
    ctx->f[(r + 1U) & 31U] = (uint32_t)v;
}

float fp_u32_to_f32(uint32_t v)
{
    float f;
    memcpy(&f, &v, sizeof(f));
    return f;
}

uint32_t fp_f32_to_u32(float f)
{
    uint32_t v;
    memcpy(&v, &f, sizeof(v));
    return v;
}

double fp_u64_to_f64(uint64_t v)
{
    double d;
    memcpy(&d, &v, sizeof(d));
    return d;
}

uint64_t fp_f64_to_u64(double d)
{
    uint64_t v;
    memcpy(&v, &d, sizeof(v));
    return v;
}
uint32_t fp_rd(const sparc32_ctx_t *ctx)
{
    return (ctx->fsr >> FP_FSR_RD_SHIFT) & 3U;
}

/* Every FPop clears cexc first (oracle: sticky aexc survives, cexc does
 * not — verified with DZ-then-op sequences). */
void fp_clear_cexc(sparc32_ctx_t *ctx)
{
    ctx->fsr &= ~(uint32_t)FP_FSR_CEXC_MASK;
}

void fp_raise(sparc32_ctx_t *ctx, uint32_t cexc)
{
    ctx->fsr |= cexc & (uint32_t)FP_FSR_CEXC_MASK;
    ctx->fsr |= (cexc & (uint32_t)FP_FSR_CEXC_MASK) << 5;
}

void fp_set_fcc(sparc32_ctx_t *ctx, uint32_t fcc)
{
    ctx->fsr &= ~(uint32_t)SPARC32_FSR_FCC_MASK;
    ctx->fsr |= (fcc & 3U) << SPARC32_FSR_FCC_SHIFT;
}

/* NaN classification. SPARC quiet bit = MSB of the fraction. */
bool fp_f32_isnan(uint32_t v)
{
    return ((v & FP_F32_EXP_MASK) == FP_F32_EXP_MASK) &&
        ((v & FP_F32_FRAC_MASK) != 0U);
}

bool fp_f32_issnan(uint32_t v)
{
    return fp_f32_isnan(v) && ((v & FP_F32_QUIET_BIT) == 0U);
}

bool fp_f64_isnan(uint64_t v)
{
    return ((v & FP_D64_EXP_MASK) == FP_D64_EXP_MASK) &&
        ((v & FP_D64_FRAC_MASK) != 0ULL);
}

bool fp_f64_issnan(uint64_t v)
{
    return fp_f64_isnan(v) && ((v & FP_D64_QUIET_BIT) == 0ULL);
}

uint32_t fp_f32_quiet(uint32_t v)
{
    return v | FP_F32_QUIET_BIT;
}

uint64_t fp_f64_quiet(uint64_t v)
{
    return v | FP_D64_QUIET_BIT;
}

/* Canonical invalid-operation results (oracle: all-ones payloads). */
#define FP_F32_CANON_NAN 0x7FFFFFFFU
#define FP_F64_CANON_NAN 0x7FFFFFFFFFFFFFFFULL

/* Two-quiet-NaN propagation: the larger payload wins (oracle); exact
 * ties keep rs1. Sign follows the winner. */
uint32_t fp_f32_pick_nan(uint32_t a, uint32_t b)
{
    uint32_t pa = a & FP_F32_FRAC_MASK;
    uint32_t pb = b & FP_F32_FRAC_MASK;
    if (pb > pa) {
        return b;
    }
    return a;
}

uint64_t fp_f64_pick_nan(uint64_t a, uint64_t b)
{
    uint64_t pa = a & FP_D64_FRAC_MASK;
    uint64_t pb = b & FP_D64_FRAC_MASK;
    if (pb > pa) {
        return b;
    }
    return a;
}

static int32_t fp_round_i32(double v, uint32_t rd, bool *inex, bool *ovf)
{
    double r;
    double t;
    double d;
    *inex = false;
    *ovf = false;
    if (rd == FP_RD_RZ) {
        t = (double)(int64_t)v;
        if (t != v) {
            *inex = true;
        }
        r = t;
    } else if (rd == FP_RD_RP) {
        t = (double)(int64_t)v;
        r = t;
        if (v != t) {
            *inex = true;
            if (v > 0.0) {
                r = t + 1.0;
            }
        }
    } else if (rd == FP_RD_RM) {
        t = (double)(int64_t)v;
        r = t;
        if (v != t) {
            *inex = true;
            if (v < 0.0) {
                r = t - 1.0;
            }
        }
    } else {
        t = (double)(int64_t)v;
        d = v - t;
        if (d < 0.0) {
            d = -d;
        }
        if (d < 0.5) {
            r = t;
        } else if (d > 0.5) {
            r = (v >= 0.0) ? t + 1.0 : t - 1.0;
        } else if (((int64_t)t & 1) == 0) {
            r = t;
        } else {
            r = (v >= 0.0) ? t + 1.0 : t - 1.0;
        }
        if (r != v) {
            *inex = true;
        }
    }
    if (r > 2147483647.0 || r < -2147483648.0) {
        *ovf = true;
        *inex = false;
    }
    return (int32_t)r;
}

/* Float/double -> int32 with RD (FsTOi/FdTOi). NaN and out-of-range map
 * to INT32_MAX / INT32_MIN with invalid, per the oracle. */
uint32_t fp_to_i32(sparc32_ctx_t *ctx, double v, uint32_t rd)
{
    bool inex;
    bool ovf;
    int32_t r;
    fp_clear_cexc(ctx);
    if (isnan(v)) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return 0x7FFFFFFFU;
    }
    if (v >= 2147483648.0) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return 0x7FFFFFFFU;
    }
    if (v < -2147483648.0) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return 0x80000000U;
    }
    r = fp_round_i32(v, rd, &inex, &ovf);
    if (ovf) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return (v >= 0.0) ? 0x7FFFFFFFU : 0x80000000U;
    }
    if (inex) {
        fp_raise(ctx, FP_FSR_NXC_BIT);
    }
    return (uint32_t)r;
}

/* Round a finite double to binary32 under RD (FiTOs/FdTOs narrowing).
 * Reports the IEEE flags for the conversion. */
uint32_t fp_to_f32(sparc32_ctx_t *ctx, double v, uint32_t rd)
{
    float frn;
    double back;
    bool ovf;
    bool tiny;
    fp_clear_cexc(ctx);
    if (isnan(v)) {
        /* Narrow the payload; never a zero fraction (that is inf). */
        uint64_t bits = fp_f64_to_u64(v);
        uint32_t pay = (uint32_t)((bits & FP_D64_FRAC_MASK) >> 29);
        uint32_t sign = (uint32_t)((bits >> 32) & 0x80000000ULL);
        if ((bits & FP_D64_QUIET_BIT) == 0ULL) {
            /* SNaN narrows to quiet with invalid (softfloat rule). */
            fp_raise(ctx, FP_FSR_NVC_BIT);
            if (pay == 0U) {
                pay = FP_F32_QUIET_BIT;
            }
            return sign | FP_F32_EXP_MASK | pay | FP_F32_QUIET_BIT;
        }
        if (pay == 0U) {
            pay = FP_F32_QUIET_BIT;
        }
        return sign | FP_F32_EXP_MASK | pay;
    }
    if (isinf(v)) {
        return (v > 0.0) ? 0x7F800000U : 0xFF800000U;
    }
    frn = (float)v;
    ovf = !isfinite(frn);
    if (ovf) {
        /* Overflow: value per RD, flags always OFC+OFA+NXC+NXA. */
        fp_raise(ctx, FP_FSR_OFC_BIT | FP_FSR_NXC_BIT);
        if (rd == FP_RD_RZ) {
            return (v > 0.0) ? 0x7F7FFFFFU : 0xFF7FFFFFU;
        }
        if (rd == FP_RD_RM && v > 0.0) {
            return 0x7F7FFFFFU;
        }
        if (rd == FP_RD_RP && v < 0.0) {
            return 0xFF7FFFFFU;
        }
        return (v > 0.0) ? 0x7F800000U : 0xFF800000U;
    }
    back = (double)frn;
    if (back == v) {
        return fp_f32_to_u32(frn);
    }
    fp_raise(ctx, FP_FSR_NXC_BIT);
    tiny = (fpclassify(frn) == FP_SUBNORMAL) || (frn == 0.0F);
    if (tiny && v != 0.0) {
        fp_raise(ctx, FP_FSR_UFC_BIT);
    }
    if (rd == FP_RD_RN) {
        return fp_f32_to_u32(frn);
    }
    if (rd == FP_RD_RZ) {
        if (fabs(back) > fabs(v)) {
            frn = nextafterf(frn, 0.0F);
        }
        return fp_f32_to_u32(frn);
    }
    if (rd == FP_RD_RP) {
        if (back < v) {
            frn = nextafterf(frn, (float)INFINITY);
        }
        return fp_f32_to_u32(frn);
    }
    if (back > v) {
        frn = nextafterf(frn, -(float)INFINITY);
    }
    return fp_f32_to_u32(frn);
}

/* Widen binary32 to binary64 (FsTOd). Exact except SNaN, which quiets
 * with invalid (softfloat rule, unprobed residual). */
uint64_t fp_f32_to_f64(sparc32_ctx_t *ctx, uint32_t v)
{
    fp_clear_cexc(ctx);
    if (fp_f32_issnan(v)) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        v = fp_f32_quiet(v);
    }
    return fp_f64_to_u64((double)fp_u32_to_f32(v));
}

/* Shared NaN pre-handling for binary ops. Returns true with *res set
 * when a NaN operand decides the result (invalid + quiet-first-SNaN, or
 * quiet propagation of the larger payload with no flags). */
static bool fp_f32_nan2(sparc32_ctx_t *ctx, uint32_t a, uint32_t b,
    uint32_t *res)
{
    if (fp_f32_issnan(a) || fp_f32_issnan(b)) {
        fp_clear_cexc(ctx);
        fp_raise(ctx, FP_FSR_NVC_BIT);
        *res = fp_f32_issnan(a) ? fp_f32_quiet(a) : fp_f32_quiet(b);
        return true;
    }
    if (fp_f32_isnan(a) || fp_f32_isnan(b)) {
        *res = fp_f32_pick_nan(a, b);
        return true;
    }
    return false;
}

static bool fp_f64_nan2(sparc32_ctx_t *ctx, uint64_t a, uint64_t b,
    uint64_t *res)
{
    if (fp_f64_issnan(a) || fp_f64_issnan(b)) {
        fp_clear_cexc(ctx);
        fp_raise(ctx, FP_FSR_NVC_BIT);
        *res = fp_f64_issnan(a) ? fp_f64_quiet(a) : fp_f64_quiet(b);
        return true;
    }
    if (fp_f64_isnan(a) || fp_f64_isnan(b)) {
        *res = fp_f64_pick_nan(a, b);
        return true;
    }
    return false;
}

/* Report overflow/underflow/inexact for a computed result r against the
 * exact long-double value q. Callers handle invalid/DZ first and exact
 * infinities (exact, no flags) before reaching here. */
static void fp_flags_f32(sparc32_ctx_t *ctx, float r, long double q)
{
    if (!isfinite(r)) {
        fp_raise(ctx, FP_FSR_OFC_BIT | FP_FSR_NXC_BIT);
        return;
    }
    if ((fpclassify(r) == FP_SUBNORMAL || r == 0.0F) && q != 0.0L) {
        fp_raise(ctx, FP_FSR_UFC_BIT | FP_FSR_NXC_BIT);
        return;
    }
    if ((long double)r != q) {
        fp_raise(ctx, FP_FSR_NXC_BIT);
    }
}

static void fp_flags_f64(sparc32_ctx_t *ctx, double r, long double q)
{
    if (!isfinite(r)) {
        fp_raise(ctx, FP_FSR_OFC_BIT | FP_FSR_NXC_BIT);
        return;
    }
    if ((fpclassify(r) == FP_SUBNORMAL || r == 0.0) && q != 0.0L) {
        fp_raise(ctx, FP_FSR_UFC_BIT | FP_FSR_NXC_BIT);
        return;
    }
    if ((long double)r != q) {
        fp_raise(ctx, FP_FSR_NXC_BIT);
    }
}

uint32_t fp_add_f32(sparc32_ctx_t *ctx, uint32_t a, uint32_t b)
{
    float fa = fp_u32_to_f32(a);
    float fb = fp_u32_to_f32(b);
    uint32_t r;
    fp_clear_cexc(ctx);
    if (fp_f32_nan2(ctx, a, b, &r)) {
        return r;
    }
    if (isinf(fa) && isinf(fb) && ((a ^ b) & 0x80000000U) != 0U) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return FP_F32_CANON_NAN;
    }
    {
        float fr = fa + fb;
        long double q = (long double)fa + (long double)fb;
        if ((long double)fr == q) {
            return fp_f32_to_u32(fr);
        }
        fp_flags_f32(ctx, fr, q);
        return fp_f32_to_u32(fr);
    }
}

uint64_t fp_add_f64(sparc32_ctx_t *ctx, uint64_t a, uint64_t b)
{
    double fa = fp_u64_to_f64(a);
    double fb = fp_u64_to_f64(b);
    uint64_t r;
    fp_clear_cexc(ctx);
    if (fp_f64_nan2(ctx, a, b, &r)) {
        return r;
    }
    if (isinf(fa) && isinf(fb) && ((a ^ b) & 0x8000000000000000ULL) != 0ULL) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return FP_F64_CANON_NAN;
    }
    {
        double fr = fa + fb;
        long double q = (long double)fa + (long double)fb;
        if ((long double)fr == q) {
            return fp_f64_to_u64(fr);
        }
        fp_flags_f64(ctx, fr, q);
        return fp_f64_to_u64(fr);
    }
}

uint32_t fp_sub_f32(sparc32_ctx_t *ctx, uint32_t a, uint32_t b)
{
    float fa = fp_u32_to_f32(a);
    float fb = fp_u32_to_f32(b);
    uint32_t r;
    fp_clear_cexc(ctx);
    if (fp_f32_nan2(ctx, a, b, &r)) {
        return r;
    }
    if (isinf(fa) && isinf(fb) && ((a ^ b) & 0x80000000U) == 0U) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return FP_F32_CANON_NAN;
    }
    {
        float fr = fa - fb;
        long double q = (long double)fa - (long double)fb;
        if ((long double)fr == q) {
            return fp_f32_to_u32(fr);
        }
        fp_flags_f32(ctx, fr, q);
        return fp_f32_to_u32(fr);
    }
}

uint64_t fp_sub_f64(sparc32_ctx_t *ctx, uint64_t a, uint64_t b)
{
    double fa = fp_u64_to_f64(a);
    double fb = fp_u64_to_f64(b);
    uint64_t r;
    fp_clear_cexc(ctx);
    if (fp_f64_nan2(ctx, a, b, &r)) {
        return r;
    }
    if (isinf(fa) && isinf(fb) &&
        ((a ^ b) & 0x8000000000000000ULL) == 0ULL) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return FP_F64_CANON_NAN;
    }
    {
        double fr = fa - fb;
        long double q = (long double)fa - (long double)fb;
        if ((long double)fr == q) {
            return fp_f64_to_u64(fr);
        }
        fp_flags_f64(ctx, fr, q);
        return fp_f64_to_u64(fr);
    }
}

uint32_t fp_mul_f32(sparc32_ctx_t *ctx, uint32_t a, uint32_t b)
{
    float fa = fp_u32_to_f32(a);
    float fb = fp_u32_to_f32(b);
    uint32_t r;
    fp_clear_cexc(ctx);
    if (fp_f32_nan2(ctx, a, b, &r)) {
        return r;
    }
    if (isinf(fa) && fb == 0.0F) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return FP_F32_CANON_NAN;
    }
    if (isinf(fb) && fa == 0.0F) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return FP_F32_CANON_NAN;
    }
    {
        float fr = fa * fb;
        long double q = (long double)fa * (long double)fb;
        if ((long double)fr == q) {
            return fp_f32_to_u32(fr);
        }
        fp_flags_f32(ctx, fr, q);
        return fp_f32_to_u32(fr);
    }
}

uint64_t fp_mul_f64(sparc32_ctx_t *ctx, uint64_t a, uint64_t b)
{
    double fa = fp_u64_to_f64(a);
    double fb = fp_u64_to_f64(b);
    uint64_t r;
    fp_clear_cexc(ctx);
    if (fp_f64_nan2(ctx, a, b, &r)) {
        return r;
    }
    if (isinf(fa) && fb == 0.0) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return FP_F64_CANON_NAN;
    }
    if (isinf(fb) && fa == 0.0) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return FP_F64_CANON_NAN;
    }
    {
        double fr = fa * fb;
        long double q = (long double)fa * (long double)fb;
        if ((long double)fr == q) {
            return fp_f64_to_u64(fr);
        }
        fp_flags_f64(ctx, fr, q);
        return fp_f64_to_u64(fr);
    }
}

uint32_t fp_div_f32(sparc32_ctx_t *ctx, uint32_t a, uint32_t b)
{
    float fa = fp_u32_to_f32(a);
    float fb = fp_u32_to_f32(b);
    uint32_t r;
    fp_clear_cexc(ctx);
    if (fp_f32_nan2(ctx, a, b, &r)) {
        return r;
    }
    if (fb == 0.0F) {
        if (fa == 0.0F) {
            fp_raise(ctx, FP_FSR_NVC_BIT);
            return FP_F32_CANON_NAN;
        }
        if (!isinf(fa)) {
            uint32_t sign = (a ^ b) & 0x80000000U;
            fp_raise(ctx, FP_FSR_DZC_BIT);
            return sign | FP_F32_EXP_MASK;
        }
        /* inf / 0 is exact infinity: no exception (IEEE 754). */
        return ((a ^ b) & 0x80000000U) | FP_F32_EXP_MASK;
    }
    if (isinf(fa) && isinf(fb)) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return FP_F32_CANON_NAN;
    }
    {
        float fr = fa / fb;
        if (fa == 0.0F) {
            return fp_f32_to_u32(fr);
        }
        if ((long double)fr * (long double)fb == (long double)fa) {
            return fp_f32_to_u32(fr);
        }
        if (!isnormal(fr)) {
            fp_raise(ctx, FP_FSR_UFC_BIT | FP_FSR_NXC_BIT);
            return fp_f32_to_u32(fr);
        }
        fp_raise(ctx, FP_FSR_NXC_BIT);
        return fp_f32_to_u32(fr);
    }
}

uint64_t fp_div_f64(sparc32_ctx_t *ctx, uint64_t a, uint64_t b)
{
    double fa = fp_u64_to_f64(a);
    double fb = fp_u64_to_f64(b);
    uint64_t r;
    fp_clear_cexc(ctx);
    if (fp_f64_nan2(ctx, a, b, &r)) {
        return r;
    }
    if (fb == 0.0) {
        if (fa == 0.0) {
            fp_raise(ctx, FP_FSR_NVC_BIT);
            return FP_F64_CANON_NAN;
        }
        if (!isinf(fa)) {
            uint64_t sign = (a ^ b) & 0x8000000000000000ULL;
            fp_raise(ctx, FP_FSR_DZC_BIT);
            return sign | FP_D64_EXP_MASK;
        }
        return ((a ^ b) & 0x8000000000000000ULL) | FP_D64_EXP_MASK;
    }
    if (isinf(fa) && isinf(fb)) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return FP_F64_CANON_NAN;
    }
    {
        double fr = fa / fb;
        if (fa == 0.0) {
            return fp_f64_to_u64(fr);
        }
        if ((long double)fr * (long double)fb == (long double)fa) {
            return fp_f64_to_u64(fr);
        }
        if (!isnormal(fr)) {
            fp_raise(ctx, FP_FSR_UFC_BIT | FP_FSR_NXC_BIT);
            return fp_f64_to_u64(fr);
        }
        fp_raise(ctx, FP_FSR_NXC_BIT);
        return fp_f64_to_u64(fr);
    }
}

uint32_t fp_sqrt_f32(sparc32_ctx_t *ctx, uint32_t a)
{
    float fa = fp_u32_to_f32(a);
    fp_clear_cexc(ctx);
    if (fp_f32_issnan(a)) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return fp_f32_quiet(a);
    }
    if (fp_f32_isnan(a)) {
        return a;
    }
    if (signbit(fa) && fa != 0.0F) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return FP_F32_CANON_NAN;
    }
    {
        float fr = sqrtf(fa);
        if ((long double)fr * (long double)fr == (long double)fa) {
            return fp_f32_to_u32(fr);
        }
        fp_flags_f32(ctx, fr, sqrtl((long double)fa));
        return fp_f32_to_u32(fr);
    }
}

uint64_t fp_sqrt_f64(sparc32_ctx_t *ctx, uint64_t a)
{
    double fa = fp_u64_to_f64(a);
    fp_clear_cexc(ctx);
    if (fp_f64_issnan(a)) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return fp_f64_quiet(a);
    }
    if (fp_f64_isnan(a)) {
        return a;
    }
    if (signbit(fa) && fa != 0.0) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return FP_F64_CANON_NAN;
    }
    {
        double fr = sqrt(fa);
        if ((long double)fr * (long double)fr == (long double)fa) {
            return fp_f64_to_u64(fr);
        }
        fp_flags_f64(ctx, fr, sqrtl((long double)fa));
        return fp_f64_to_u64(fr);
    }
}

/* FCMP/FCMPE: set fcc, clear cexc, keep aexc. Unordered sets NVA, plus
 * cexc-NV when signaling (FCMPE) or an SNaN operand is involved. */
void fp_cmp_f32(sparc32_ctx_t *ctx, uint32_t a, uint32_t b,
    bool signal)
{
    bool unordered;
    fp_clear_cexc(ctx);
    unordered = fp_f32_isnan(a) || fp_f32_isnan(b);
    if (!unordered) {
        float fa = fp_u32_to_f32(a);
        float fb = fp_u32_to_f32(b);
        fp_set_fcc(ctx, (fa < fb) ? 1U : ((fa > fb) ? 2U : 0U));
        return;
    }
    fp_set_fcc(ctx, 3U);
    ctx->fsr |= FP_FSR_NVA_BIT;
    if (signal || fp_f32_issnan(a) || fp_f32_issnan(b)) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
    }
}

void fp_cmp_f64(sparc32_ctx_t *ctx, uint64_t a, uint64_t b,
    bool signal)
{
    bool unordered;
    fp_clear_cexc(ctx);
    unordered = fp_f64_isnan(a) || fp_f64_isnan(b);
    if (!unordered) {
        double fa = fp_u64_to_f64(a);
        double fb = fp_u64_to_f64(b);
        fp_set_fcc(ctx, (fa < fb) ? 1U : ((fa > fb) ? 2U : 0U));
        return;
    }
    fp_set_fcc(ctx, 3U);
    ctx->fsr |= FP_FSR_NVA_BIT;
    if (signal || fp_f64_issnan(a) || fp_f64_issnan(b)) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
    }
}
