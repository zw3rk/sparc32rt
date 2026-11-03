/*
 * tests/test_r7_decode.c — host-native Round-7 decoder regression checks.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Covers the pure decoder fixes in S32-R7-10 (CASA i-bit), S32-R7-11
 * (STBAR special form), S32-R7-17 (FDTOS vs FITOD), and S32-R7-23
 * (FPop1/FPop2 group validation) via sparc32_decode_word only.
 *
 * Build & run (host-native):
 *   cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
 *     -Iinclude -Isrc tests/test_r7_decode.c src/interp/decode.c \
 *     -o /tmp/test_r7_decode && /tmp/test_r7_decode
 */

#include <stdint.h>
#include <stdio.h>

#include "interp/decode.h"

/* Link stubs for the fetch path (untouched by these word-level checks). */
bool interp_range_ok(const sparc32_ctx_t *ctx, uint32_t va, uint32_t len,
    uint32_t need)
{
    (void)ctx;
    (void)va;
    (void)len;
    (void)need;
    return false;
}

void sparc32_vm_access_enter(void)
{
}

void sparc32_vm_access_leave(void)
{
}

const uint8_t *sparc32_vm_prot_base(void)
{
    return NULL;
}

static int failures = 0;

static void expect_cls(uint32_t word, uint32_t want, const char *what)
{
    sparc32_decoded_t d;
    sparc32_decode_word(word, &d);
    if (d.cls != want) {
        printf("R7-DECODE FAIL: %s word=%08x got=%u want=%u\n", what,
            word, d.cls, want);
        failures++;
    }
}

int main(void)
{
    /* S32-R7-10: immediate-ASI CASA (i == 0) decodes CASA. */
    expect_cls(0xD5E60156U, (uint32_t)SPARC32_OP_CASA, "casa-imm-asi");
    /* S32-R7-10: register-ASI CASA (i == 1) is illegal. */
    expect_cls(0xD5E62156U, (uint32_t)SPARC32_OP_ILLEGAL, "casa-reg-asi");
    /* S32-R7-11: real STBAR (RDASR rs1=15 rd=0) decodes STBAR. */
    expect_cls(0x8143C000U, (uint32_t)SPARC32_OP_STBAR, "stbar-real");
    /* S32-R7-11: invented op3 0x2c form is illegal. */
    expect_cls(0x81602000U, (uint32_t)SPARC32_OP_ILLEGAL, "stbar-invented");
    /* S32-R7-17: FDTOS (0x0c6) to odd single rd is legal. */
    expect_cls(0x83A018C0U, (uint32_t)SPARC32_OP_FPU, "fdtos-odd-ok");
    /* S32-R7-17: FITOD (0x0c8) to odd double rd stays illegal. */
    expect_cls(0x83A01900U, (uint32_t)SPARC32_OP_ILLEGAL, "fitod-odd-bad");
    /* S32-R7-23: FADDS under FPop1 is legal, under FPop2 illegal. */
    expect_cls(0x81A00820U, (uint32_t)SPARC32_OP_FPU, "fadds-fpop1-ok");
    expect_cls(0x81A80820U, (uint32_t)SPARC32_OP_ILLEGAL, "fadds-fpop2-bad");
    /* S32-R7-23: FCMPS under FPop2 is legal, under FPop1 illegal. */
    expect_cls(0x81A80A20U, (uint32_t)SPARC32_OP_FPU, "fcmps-fpop2-ok");
    expect_cls(0x81A00A20U, (uint32_t)SPARC32_OP_ILLEGAL, "fcmps-fpop1-bad");
    if (failures != 0) {
        printf("R7-DECODE: %d FAILURES\n", failures);
        return 1;
    }
    printf("R7-DECODE: PASS\n");
    return 0;
}
