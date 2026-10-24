/*
 * tests/test_p5_dynlib.c — Phase 5 dynamic-lib guest, shared object (lane L5b).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * The shared object loaded by tests/test_p5_dyn.c via dlopen(3). It
 * exercises exactly the dynamic-loader surface the Phase-5 translator
 * must carry: a cross-DSO function call, a per-thread TLS counter
 * living in the shared object, and a string payload returned across
 * the DSO boundary.
 *
 * Build (pure-V8 dynamic sysroot; see docs/lanes/phase-5-sysroot.md):
 *   sparc-linux-gnu-gcc -mcpu=leon3 -O2 -fPIC -shared \
 *     -o libp5dyn.so tests/test_p5_dynlib.c
 *
 * This file is freestanding-clean on purpose (no libc calls): every
 * behavior under test lives in the caller, so a failure points at the
 * loader/TLS machinery, never at libc-in-lib problems.
 */

#include <stddef.h>

/* Per-thread counter owned by this DSO. The caller bumps it twice in
 * the main thread and expects exactly 1 then 2 back. */
__thread int p5_lib_tls_counter = 0;

int p5_dyn_add(int a, int b)
{
    return a + b;
}

int p5_dyn_tls_bump(void)
{
    p5_lib_tls_counter += 1;
    return p5_lib_tls_counter;
}

const char *p5_dyn_name(void)
{
    return "p5-dynlib";
}

/* A small struct-passing check across the DSO boundary (by value). */
struct p5_pair {
    int x;
    int y;
};

int p5_dyn_pair_sum(struct p5_pair p)
{
    return p.x + p.y;
}

size_t p5_dyn_strlen(const char *s)
{
    const char *p = s;
    while (*p != '\0') {
        p++;
    }
    return (size_t)(p - s);
}
