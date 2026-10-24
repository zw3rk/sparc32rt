/*
 * tests/test_p5_dyn.c — Phase 5 dynamic-libc guest, main executable (lane L5b).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Exercises exactly the dynamic-loader surface Phase 5 must carry:
 * PT_INTERP launch via the sysroot ld.so, a cross-DSO call
 * (tests/test_p5_dynlib.c), dlopen(3)/dlsym(3)/dlclose(3) by explicit
 * path, __thread TLS in both the executable and the DSO, and
 * struct-by-value passing across the DSO boundary. Deterministic
 * stdout; exit 0 means every check passed.
 *
 * Build (pure-V8 dynamic sysroot; see docs/lanes/phase-5-sysroot.md):
 *   sparc-linux-gnu-gcc -mcpu=leon3 -O2 -fPIC -shared \
 *     -o libp5dyn.so tests/test_p5_dynlib.c
 *   sparc-linux-gnu-gcc -mcpu=leon3 -O2 \
 *     -o test_p5_dyn tests/test_p5_dyn.c
 *
 * Oracle (run from the directory holding libp5dyn.so):
 *   qemu-sparc -cpu LEON3 ./test_p5_dyn
 * must match --interp/--dbt stdout bit-for-bit, with --difftest
 * reporting 0 divergences.
 */

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

/* TLS owned by the executable (distinct from the DSO's counter). */
__thread int p5_exe_tls_value = 7;

struct p5_pair {
    int x;
    int y;
};

static int p5_fail(const char *msg)
{
    printf("P5-DYN-FAIL %s\n", msg);
    fflush(stdout);
    return 1;
}

static int p5_check_add(void *h)
{
    int (*add_fn)(int, int);
    int got;

    *(void **)(&add_fn) = dlsym(h, "p5_dyn_add");
    if (add_fn == NULL) {
        return p5_fail("dlsym-add");
    }
    got = add_fn(40, 2);
    if (got != 42) {
        return p5_fail("add-value");
    }
    printf("add ok %d\n", got);
    return 0;
}

static int p5_check_name(void *h)
{
    const char *(*name_fn)(void);
    const char *got;

    *(void **)(&name_fn) = dlsym(h, "p5_dyn_name");
    if (name_fn == NULL) {
        return p5_fail("dlsym-name");
    }
    got = name_fn();
    if (got == NULL || strcmp(got, "p5-dynlib") != 0) {
        return p5_fail("name-value");
    }
    printf("name ok %s\n", got);
    return 0;
}

static int p5_check_pair(void *h)
{
    int (*sum_fn)(struct p5_pair);
    struct p5_pair p;
    int got;

    *(void **)(&sum_fn) = dlsym(h, "p5_dyn_pair_sum");
    if (sum_fn == NULL) {
        return p5_fail("dlsym-pair");
    }
    p.x = 17;
    p.y = 25;
    got = sum_fn(p);
    if (got != 42) {
        return p5_fail("pair-value");
    }
    printf("pair ok %d\n", got);
    return 0;
}

static int p5_check_tls(void *h)
{
    int (*bump_fn)(void);
    int first;
    int second;

    /* Executable-side TLS: read, write, re-read. */
    if (p5_exe_tls_value != 7) {
        return p5_fail("exe-tls-init");
    }
    p5_exe_tls_value = 8;
    if (p5_exe_tls_value != 8) {
        return p5_fail("exe-tls-write");
    }
    printf("exe-tls ok %d\n", p5_exe_tls_value);

    /* DSO-side TLS: two bumps must yield exactly 1 then 2. */
    *(void **)(&bump_fn) = dlsym(h, "p5_dyn_tls_bump");
    if (bump_fn == NULL) {
        return p5_fail("dlsym-tls");
    }
    first = bump_fn();
    second = bump_fn();
    if (first != 1 || second != 2) {
        return p5_fail("lib-tls-values");
    }
    printf("lib-tls ok %d %d\n", first, second);
    return 0;
}

static int p5_check_missing(void *h)
{
    void *sym;

    dlerror();
    sym = dlsym(h, "p5_dyn_no_such_symbol");
    if (sym != NULL || dlerror() == NULL) {
        return p5_fail("missing-symbol");
    }
    printf("missing ok\n");
    return 0;
}

int main(void)
{
    void *handle;

    dlerror();
    handle = dlopen("./libp5dyn.so", RTLD_NOW);
    if (handle == NULL) {
        printf("P5-DYN-FAIL dlopen %s\n", dlerror());
        fflush(stdout);
        return 1;
    }
    printf("dlopen ok\n");
    if (p5_check_add(handle) != 0) {
        return 1;
    }
    if (p5_check_name(handle) != 0) {
        return 1;
    }
    if (p5_check_pair(handle) != 0) {
        return 1;
    }
    if (p5_check_tls(handle) != 0) {
        return 1;
    }
    if (p5_check_missing(handle) != 0) {
        return 1;
    }
    if (dlclose(handle) != 0) {
        return p5_fail("dlclose");
    }
    printf("P5-DYN-PASS\n");
    return 0;
}
