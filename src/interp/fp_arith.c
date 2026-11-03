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

/* Every FPop clears cexc/FTT first (S32-R7-18; aexc is sticky). */
void fp_clear_cexc(sparc32_ctx_t *ctx)
{
    ctx->fsr &= ~((uint32_t)FP_FSR_CEXC_MASK |
        (uint32_t)FP_FSR_FTT_MASK);
}

/* S32-R7-16: TEM trap check. On trap set FTT + cexc without aexc accrual;
 * the fp.c wrapper owns the PC/exit. */
void fp_raise(sparc32_ctx_t *ctx, uint32_t cexc)
{
    uint32_t masked = cexc & (uint32_t)FP_FSR_CEXC_MASK;
    uint32_t tem = (ctx->fsr >> (uint32_t)FP_FSR_TEM_SHIFT) & 0x1FU;
    if ((masked & tem) != 0U) {
        ctx->fsr &= ~(uint32_t)FP_FSR_CEXC_MASK;
        ctx->fsr |= masked;
        ctx->fsr &= ~(uint32_t)FP_FSR_FTT_MASK;
        ctx->fsr |= (uint32_t)FP_FSR_FTT_IEEE
            << (uint32_t)FP_FSR_FTT_SHIFT;
        return;
    }
    ctx->fsr |= masked;
    ctx->fsr |= masked << 5;
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
    uint32_t pa;
    uint32_t pb;
    if (!fp_f32_isnan(a)) {
        return b;
    }
    if (!fp_f32_isnan(b)) {
        return a;
    }
    pa = a & FP_F32_FRAC_MASK;
    pb = b & FP_F32_FRAC_MASK;
    if (pb > pa) {
        return b;
    }
    return a;
}

uint64_t fp_f64_pick_nan(uint64_t a, uint64_t b)
{
    uint64_t pa;
    uint64_t pb;
    if (!fp_f64_isnan(a)) {
        return b;
    }
    if (!fp_f64_isnan(b)) {
        return a;
    }
    pa = a & FP_D64_FRAC_MASK;
    pb = b & FP_D64_FRAC_MASK;
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
        return 0;
    }
    return (int32_t)r;
}

/* Float/double -> int32 with RD (FsTOi/FdTOi). NaN and out-of-range map
 * to INT32_MAX / INT32_MIN with invalid, per the oracle. S32-R7-21:
 * representability is decided after rounding (e.g. -2147483648.5
 * truncates to INT32_MIN with NX, not NV); the early guards only
 * protect the int64 intermediate. */
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
    if (v >= 9223372036854775808.0) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return 0x7FFFFFFFU;
    }
    if (v < -9223372036854775808.0) {
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
        /* S32-R7-22: directed adjustment can overflow to infinity. */
        if (!isfinite(frn)) fp_raise(ctx, FP_FSR_OFC_BIT | FP_FSR_NXC_BIT);
        return fp_f32_to_u32(frn);
    }
    if (back > v) {
        frn = nextafterf(frn, -(float)INFINITY);
    }
    if (!isfinite(frn)) fp_raise(ctx, FP_FSR_OFC_BIT | FP_FSR_NXC_BIT);
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

/* Apply FSR.RD directed rounding and raise OFC/UFC/NXC for a round-to-nearest
 * result fr given the exact error sign err (sign(exact - fr), 0 iff exact). */
static uint32_t fp_finish_f32(sparc32_ctx_t *ctx, float fr, double err,
    uint32_t zero_sign)
{
    uint32_t rd = fp_rd(ctx);
    if (!isfinite(fr)) {
        fp_raise(ctx, FP_FSR_OFC_BIT | FP_FSR_NXC_BIT);
        if (rd == FP_RD_RZ) {
            return (fr > 0.0F) ? 0x7F7FFFFFU : 0xFF7FFFFFU;
        }
        if (rd == FP_RD_RM && fr > 0.0F) {
            return 0x7F7FFFFFU;
        }
        if (rd == FP_RD_RP && fr < 0.0F) {
            return 0xFF7FFFFFU;
        }
        return (fr > 0.0F) ? 0x7F800000U : 0xFF800000U;
    }
    if (err == 0.0) {
        return (fr == 0.0F) ? zero_sign : fp_f32_to_u32(fr);
    }
    if (fr == 0.0F) {
        fr = (err < 0.0) ? -0.0F : 0.0F;
    }
    if (rd == FP_RD_RP && err > 0.0) {
        fr = nextafterf(fr, (float)INFINITY);
    } else if (rd == FP_RD_RM && err < 0.0) {
        fr = nextafterf(fr, -(float)INFINITY);
    } else if (rd == FP_RD_RZ &&
        ((fr > 0.0F && err < 0.0) || (fr < 0.0F && err > 0.0))) {
        fr = nextafterf(fr, 0.0F);
    }
    if (!isfinite(fr)) {
        fp_raise(ctx, FP_FSR_OFC_BIT | FP_FSR_NXC_BIT);
    } else if (fpclassify(fr) == FP_SUBNORMAL || fr == 0.0F) {
        fp_raise(ctx, FP_FSR_UFC_BIT | FP_FSR_NXC_BIT);
    } else {
        fp_raise(ctx, FP_FSR_NXC_BIT);
    }
    return fp_f32_to_u32(fr);
}

static uint64_t fp_finish_f64(sparc32_ctx_t *ctx, double fr, double err,
    uint64_t zero_sign)
{
    uint32_t rd = fp_rd(ctx);
    if (!isfinite(fr)) {
        fp_raise(ctx, FP_FSR_OFC_BIT | FP_FSR_NXC_BIT);
        if (rd == FP_RD_RZ) {
            return (fr > 0.0) ?
                0x7FEFFFFFFFFFFFFFULL : 0xFFEFFFFFFFFFFFFFULL;
        }
        if (rd == FP_RD_RM && fr > 0.0) {
            return 0x7FEFFFFFFFFFFFFFULL;
        }
        if (rd == FP_RD_RP && fr < 0.0) {
            return 0xFFEFFFFFFFFFFFFFULL;
        }
        return (fr > 0.0) ?
            0x7FF0000000000000ULL : 0xFFF0000000000000ULL;
    }
    if (err == 0.0) {
        return (fr == 0.0) ? zero_sign : fp_f64_to_u64(fr);
    }
    if (fr == 0.0) {
        fr = (err < 0.0) ? -0.0 : 0.0;
    }
    if (rd == FP_RD_RP && err > 0.0) {
        fr = nextafter(fr, (double)INFINITY);
    } else if (rd == FP_RD_RM && err < 0.0) {
        fr = nextafter(fr, -(double)INFINITY);
    } else if (rd == FP_RD_RZ &&
        ((fr > 0.0 && err < 0.0) || (fr < 0.0 && err > 0.0))) {
        fr = nextafter(fr, 0.0);
    }
    if (!isfinite(fr)) {
        fp_raise(ctx, FP_FSR_OFC_BIT | FP_FSR_NXC_BIT);
    } else if (fpclassify(fr) == FP_SUBNORMAL || fr == 0.0) {
        fp_raise(ctx, FP_FSR_UFC_BIT | FP_FSR_NXC_BIT);
    } else {
        fp_raise(ctx, FP_FSR_NXC_BIT);
    }
    return fp_f64_to_u64(fr);
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
    if (isinf(fa) && isinf(fb)) {
        if (((a ^ b) & 0x80000000U) != 0U) {
            fp_raise(ctx, FP_FSR_NVC_BIT);
            return FP_F32_CANON_NAN;
        }
        return a;
    }
    if (isinf(fa)) {
        return a;
    }
    if (isinf(fb)) {
        return b;
    }
    {
        float fr = fa + fb;
        double da = (double)fa;
        double db = (double)fb;
        double s = da + db;
        double v = s - da;
        double err = (s - (double)fr) + ((da - (s - v)) + (db - v));
        uint32_t zsign = (((a ^ b) & 0x80000000U) != 0U) ?
            ((fp_rd(ctx) == FP_RD_RM) ? 0x80000000U : 0U) :
            (a & 0x80000000U);
        return fp_finish_f32(ctx, fr, err, zsign);
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
    if (isinf(fa) && isinf(fb)) {
        if (((a ^ b) & 0x8000000000000000ULL) != 0ULL) {
            fp_raise(ctx, FP_FSR_NVC_BIT);
            return FP_F64_CANON_NAN;
        }
        return a;
    }
    if (isinf(fa)) {
        return a;
    }
    if (isinf(fb)) {
        return b;
    }
    {
        double fr = fa + fb;
        double v = fr - fa;
        double err = isfinite(fr) ? ((fa - (fr - v)) + (fb - v)) : 0.0;
        uint64_t zsign = (((a ^ b) & 0x8000000000000000ULL) != 0ULL) ?
            ((fp_rd(ctx) == FP_RD_RM) ? 0x8000000000000000ULL : 0ULL) :
            (a & 0x8000000000000000ULL);
        return fp_finish_f64(ctx, fr, err, zsign);
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
    if (isinf(fa) && isinf(fb)) {
        if (((a ^ b) & 0x80000000U) == 0U) {
            fp_raise(ctx, FP_FSR_NVC_BIT);
            return FP_F32_CANON_NAN;
        }
        return a;
    }
    if (isinf(fa)) {
        return a;
    }
    if (isinf(fb)) {
        return b ^ 0x80000000U;
    }
    {
        float fr = fa - fb;
        double da = (double)fa;
        double db = -(double)fb;
        double s = da + db;
        double v = s - da;
        double err = (s - (double)fr) + ((da - (s - v)) + (db - v));
        uint32_t nb = b ^ 0x80000000U;
        uint32_t zsign = (((a ^ nb) & 0x80000000U) != 0U) ?
            ((fp_rd(ctx) == FP_RD_RM) ? 0x80000000U : 0U) :
            (a & 0x80000000U);
        return fp_finish_f32(ctx, fr, err, zsign);
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
    if (isinf(fa) && isinf(fb)) {
        if (((a ^ b) & 0x8000000000000000ULL) == 0ULL) {
            fp_raise(ctx, FP_FSR_NVC_BIT);
            return FP_F64_CANON_NAN;
        }
        return a;
    }
    if (isinf(fa)) {
        return a;
    }
    if (isinf(fb)) {
        return b ^ 0x8000000000000000ULL;
    }
    {
        double fr = fa - fb;
        double nb = -fb;
        double v = fr - fa;
        double err = isfinite(fr) ? ((fa - (fr - v)) + (nb - v)) : 0.0;
        uint64_t nb_bits = b ^ 0x8000000000000000ULL;
        uint64_t zsign = (((a ^ nb_bits) & 0x8000000000000000ULL) != 0ULL) ?
            ((fp_rd(ctx) == FP_RD_RM) ? 0x8000000000000000ULL : 0ULL) :
            (a & 0x8000000000000000ULL);
        return fp_finish_f64(ctx, fr, err, zsign);
    }
}

uint32_t fp_mul_f32(sparc32_ctx_t *ctx, uint32_t a, uint32_t b)
{
    float fa = fp_u32_to_f32(a);
    float fb = fp_u32_to_f32(b);
    uint32_t r;
    uint32_t sign = (a ^ b) & 0x80000000U;
    fp_clear_cexc(ctx);
    if (fp_f32_nan2(ctx, a, b, &r)) {
        return r;
    }
    if ((isinf(fa) && fb == 0.0F) || (isinf(fb) && fa == 0.0F)) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return FP_F32_CANON_NAN;
    }
    if (isinf(fa) || isinf(fb)) {
        return sign | FP_F32_EXP_MASK;
    }
    if (fa == 0.0F || fb == 0.0F) {
        return sign;
    }
    {
        float fr = fa * fb;
        double err = ((double)fa * (double)fb) - (double)fr;
        return fp_finish_f32(ctx, fr, err, sign);
    }
}

uint64_t fp_mul_f64(sparc32_ctx_t *ctx, uint64_t a, uint64_t b)
{
    double fa = fp_u64_to_f64(a);
    double fb = fp_u64_to_f64(b);
    uint64_t r;
    uint64_t sign = (a ^ b) & 0x8000000000000000ULL;
    fp_clear_cexc(ctx);
    if (fp_f64_nan2(ctx, a, b, &r)) {
        return r;
    }
    if ((isinf(fa) && fb == 0.0) || (isinf(fb) && fa == 0.0)) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return FP_F64_CANON_NAN;
    }
    if (isinf(fa) || isinf(fb)) {
        return sign | FP_D64_EXP_MASK;
    }
    if (fa == 0.0 || fb == 0.0) {
        return sign;
    }
    {
        double fr = fa * fb;
        double err = 0.0;
        if (isfinite(fr)) {
            if (fr == 0.0) {
                err = (sign != 0ULL) ? -1.0 : 1.0;
            } else {
                int ea = 0;
                int eb = 0;
                double ma = frexp(fa, &ea);
                double mb = frexp(fb, &eb);
                double mr = ldexp(fr, -(ea + eb));
                err = fma(ma, mb, -mr);
            }
        }
        return fp_finish_f64(ctx, fr, err, sign);
    }
}

uint32_t fp_div_f32(sparc32_ctx_t *ctx, uint32_t a, uint32_t b)
{
    float fa = fp_u32_to_f32(a);
    float fb = fp_u32_to_f32(b);
    uint32_t r;
    uint32_t sign = (a ^ b) & 0x80000000U;
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
            fp_raise(ctx, FP_FSR_DZC_BIT);
        }
        return sign | FP_F32_EXP_MASK;
    }
    if (isinf(fa) && isinf(fb)) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return FP_F32_CANON_NAN;
    }
    if (isinf(fa)) {
        return sign | FP_F32_EXP_MASK;
    }
    if (fa == 0.0F || isinf(fb)) {
        return sign;
    }
    {
        float fr = fa / fb;
        double rem = (double)fa - ((double)fr * (double)fb);
        double err = (fb > 0.0F) ? rem : -rem;
        return fp_finish_f32(ctx, fr, err, sign);
    }
}

uint64_t fp_div_f64(sparc32_ctx_t *ctx, uint64_t a, uint64_t b)
{
    double fa = fp_u64_to_f64(a);
    double fb = fp_u64_to_f64(b);
    uint64_t r;
    uint64_t sign = (a ^ b) & 0x8000000000000000ULL;
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
            fp_raise(ctx, FP_FSR_DZC_BIT);
        }
        return sign | FP_D64_EXP_MASK;
    }
    if (isinf(fa) && isinf(fb)) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return FP_F64_CANON_NAN;
    }
    if (isinf(fa)) {
        return sign | FP_D64_EXP_MASK;
    }
    if (fa == 0.0 || isinf(fb)) {
        return sign;
    }
    {
        double fr = fa / fb;
        double err = 0.0;
        if (isfinite(fr)) {
            if (fr == 0.0) {
                err = (sign != 0ULL) ? -1.0 : 1.0;
            } else {
                int ea = 0;
                int eb = 0;
                double ma = frexp(fa, &ea);
                double mb = frexp(fb, &eb);
                double mr = ldexp(fr, -(ea - eb));
                double rem = fma(-mr, mb, ma);
                err = (fb > 0.0) ? rem : -rem;
            }
        }
        return fp_finish_f64(ctx, fr, err, sign);
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
    if (fa == 0.0F || isinf(fa)) {
        return a;
    }
    {
        float fr = sqrtf(fa);
        double err = (double)fa - ((double)fr * (double)fr);
        return fp_finish_f32(ctx, fr, err, a & 0x80000000U);
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
    if (fa == 0.0 || isinf(fa)) {
        return a;
    }
    {
        double fr = sqrt(fa);
        int ea = 0;
        double ma = frexp(fa, &ea);
        double mr;
        double err;
        if ((ea & 1) != 0) {
            ma *= 2.0;
            ea -= 1;
        }
        mr = ldexp(fr, -(ea / 2));
        err = fma(-mr, mr, ma);
        return fp_finish_f64(ctx, fr, err, a & 0x8000000000000000ULL);
    }
}

/* FCMP/FCMPE: set fcc, clear cexc, keep aexc. Unordered sets NVA, plus
 * cexc-NV when signaling (FCMPE) or an SNaN operand is involved. */
void fp_cmp_f32(sparc32_ctx_t *ctx, uint32_t a, uint32_t b,
    bool signal)
{
    bool u;
    fp_clear_cexc(ctx);
    u = fp_f32_isnan(a) || fp_f32_isnan(b);
    if (!u) {
        float fa = fp_u32_to_f32(a);
        float fb = fp_u32_to_f32(b);
        fp_set_fcc(ctx, (fa < fb) ? 1U : ((fa > fb) ? 2U : 0U));
        return;
    }
    /* S32-R7-19 quiet qNaN raises nothing; S32-R7-16 trap skips FCC/NVA. */
    if (!signal && !fp_f32_issnan(a) && !fp_f32_issnan(b)) {
        fp_set_fcc(ctx, 3U);
        return;
    }
    if ((((ctx->fsr >> (uint32_t)FP_FSR_TEM_SHIFT) & 0x1FU) &
            (uint32_t)FP_FSR_NVC_BIT) != 0U) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return;
    }
    fp_set_fcc(ctx, 3U);
    ctx->fsr |= FP_FSR_NVA_BIT;
    fp_raise(ctx, FP_FSR_NVC_BIT);
}

void fp_cmp_f64(sparc32_ctx_t *ctx, uint64_t a, uint64_t b,
    bool signal)
{
    bool u;
    fp_clear_cexc(ctx);
    u = fp_f64_isnan(a) || fp_f64_isnan(b);
    if (!u) {
        double fa = fp_u64_to_f64(a);
        double fb = fp_u64_to_f64(b);
        fp_set_fcc(ctx, (fa < fb) ? 1U : ((fa > fb) ? 2U : 0U));
        return;
    }
    /* S32-R7-19 quiet qNaN raises nothing; S32-R7-16 trap skips FCC/NVA. */
    if (!signal && !fp_f64_issnan(a) && !fp_f64_issnan(b)) {
        fp_set_fcc(ctx, 3U);
        return;
    }
    if ((((ctx->fsr >> (uint32_t)FP_FSR_TEM_SHIFT) & 0x1FU) &
            (uint32_t)FP_FSR_NVC_BIT) != 0U) {
        fp_raise(ctx, FP_FSR_NVC_BIT);
        return;
    }
    fp_set_fcc(ctx, 3U);
    ctx->fsr |= FP_FSR_NVA_BIT;
    fp_raise(ctx, FP_FSR_NVC_BIT);
}
