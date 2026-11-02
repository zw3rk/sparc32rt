/*
 * tests/guest-include/fenv.h — minimal SPARC V8 floating-point environment
 * for uClibc-sparcv8 guests (lane C2-3).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * The Bootlin sparcv8-uclibc sysroot ships no C <fenv.h> (uClibc on
 * SPARC implements no floating-point environment interfaces), while the
 * shared torture ../../rt-series/tests/p3_torture.c needs exactly four
 * entry points (fegetround, fesetround, feclearexcept, fetestexcept)
 * plus FE_* macros. This header implements them directly on the V8
 * %fsr (unprivileged RD/WR %fsr, pure V8 encodings):
 *
 *   FSR bits 31-30 (RD): 0 nearest, 1 toward-zero, 2 upward, 3 downward.
 *   FSR bits 9-5 (aexc, accrued): bit5 inexact, bit6 div-by-zero,
 *     bit7 underflow, bit8 overflow, bit9 invalid.
 *
 * Only what p3_torture.c uses is provided; anything else is a compile
 * error, never a silent stub. Rounding/exception semantics are verified
 * against the qemu-sparc -cpu LEON3 oracle like every other guest row
 * (the same binary runs on oracle, --interp, and --dbt).
 *
 * Used via -I for guest builds only; never on a host include path.
 */

#ifndef SPARC32RT_GUEST_FENV_H
#define SPARC32RT_GUEST_FENV_H

#include <stdint.h>

#define FE_INEXACT 0x01
#define FE_DIVBYZERO 0x02
#define FE_UNDERFLOW 0x04
#define FE_OVERFLOW 0x08
#define FE_INVALID 0x10
#define FE_ALL_EXCEPT 0x1f

#define FE_TONEAREST 0
#define FE_TOWARDZERO 1
#define FE_UPWARD 2
#define FE_DOWNWARD 3

static __inline__ int fegetround(void)
{
    uint32_t fsr = 0u;
    __asm__ volatile("st %%fsr, %0" : "=m"(fsr));
    return (int)((fsr >> 30) & 3u);
}

static __inline__ int fesetround(int round)
{
    uint32_t fsr = 0u;
    uint32_t nw;
    if ((round & ~3) != 0) {
        return 1;
    }
    __asm__ volatile("st %%fsr, %0" : "=m"(fsr));
    nw = (fsr & 0x3fffffffu) | ((uint32_t)round << 30);
    __asm__ volatile("ld %0, %%fsr" : : "m"(nw));
    return 0;
}

static __inline__ int feclearexcept(int excepts)
{
    uint32_t fsr = 0u;
    uint32_t nw;
    __asm__ volatile("st %%fsr, %0" : "=m"(fsr));
    nw = fsr & ~(((uint32_t)(excepts & FE_ALL_EXCEPT)) << 5);
    __asm__ volatile("ld %0, %%fsr" : : "m"(nw));
    return 0;
}

static __inline__ int fetestexcept(int excepts)
{
    uint32_t fsr = 0u;
    __asm__ volatile("st %%fsr, %0" : "=m"(fsr));
    return (int)((fsr >> 5) & (uint32_t)(excepts & FE_ALL_EXCEPT));
}

#endif /* SPARC32RT_GUEST_FENV_H */
