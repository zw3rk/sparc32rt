/*
 * tests/check_r11_signals.c — host-runnable Round-11 signal invariant checks
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * S32-R11-1: SPARC SIGEMT (7) and SIGLOST (29) are pure-emulation signals
 * with no host image. Pins that to_host reports -1 for them (fail closed,
 * never the host SIGBUS/SIGIO number), that they never collide with guest
 * 10 (SIGBUS) / 23 (SIGIO), that host SIGBUS/SIGIO still map back to guest
 * 10/23, and that every other signal round-trips through both conversions.
 * Also pins the sigaltstack flag constants behind S32-R11-2..4.
 *
 * Prints PASS and returns 0 on success.
 *
 * Build (Darwin): cc -std=c11 -D_DARWIN_C_SOURCE -Werror=vla -pedantic \
 *          -Wall -Wextra -Werror -Iinclude -Isrc tests/check_r11_signals.c \
 *          -o _build/check_r11_signals
 * Build (Linux): ... -D_POSIX_C_SOURCE=200809L ... (same as above).
 */

#include <signal.h>
#include <stdio.h>

#include "interp/interp_priv.h"
#include "os/threads.h"

static int failures = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("FAIL line %d: %s\n", __LINE__, #cond);                \
            ++failures;                                                    \
        }                                                                  \
    } while (0)

int main(void)
{
    int s;
    /* S32-R11-1: pure-emulation predicate. */
    CHECK(sparc32_sig_pure_emu(7));
    CHECK(sparc32_sig_pure_emu(29));
    CHECK(!sparc32_sig_pure_emu(1));
    CHECK(!sparc32_sig_pure_emu(9));
    CHECK(!sparc32_sig_pure_emu(10));
    CHECK(!sparc32_sig_pure_emu(11));
    CHECK(!sparc32_sig_pure_emu(23));
    CHECK(!sparc32_sig_pure_emu(30));
    CHECK(!sparc32_sig_pure_emu(64));
    /* S32-R11-1: no host image, no collision with 10/23. */
    CHECK(sparc32_sig_to_host(7) == -1);
    CHECK(sparc32_sig_to_host(29) == -1);
    CHECK(sparc32_sig_to_host(7) != sparc32_sig_to_host(10));
    CHECK(sparc32_sig_to_host(29) != sparc32_sig_to_host(23));
    CHECK(sparc32_sig_to_host(10) == SIGBUS);
    CHECK(sparc32_sig_to_host(23) == SIGIO);
    CHECK(sparc32_sig_from_host(SIGBUS) == 10);
    CHECK(sparc32_sig_from_host(SIGIO) == 23);
    /* Every delegated signal round-trips; 7/29 never come from the host. */
    for (s = 1; s <= 64; s++) {
        int h;
        if (sparc32_sig_pure_emu(s)) {
            continue;
        }
        h = sparc32_sig_to_host(s);
        CHECK(h >= 1);
        CHECK(sparc32_sig_from_host(h) == s);
    }
    /* S32-R11-2..4: sigaltstack flag constants. */
    CHECK(SPARC32_SS_ONSTACK == 1U);
    CHECK(SPARC32_SS_DISABLE == 2U);
    CHECK(SPARC32_SS_AUTODISARM == 0x80000000U);
    if (failures == 0) {
        printf("PASS check_r11_signals\n");
    }
    return (failures == 0) ? 0 : 1;
}
