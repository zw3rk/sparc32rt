/*
 * tests/test_r13_r16.c — host-native regression checks for the Round 13-16
 * remediation (S32-R13-1..15, S32-R14-1..2, S32-R15-1..2, S32-R16-1).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Covers, against the real objects (not stubs of the fixed logic):
 *   R13-2  sigreturn restores the interrupted window cursor and stack
 *          chain after handler SAVEs, and aborts without mutation on a
 *          faulty frame (drives sparc32_sys_rt_sigreturn in
 *          src/os/syscalls_sig.c over a crafted rt_signal_frame32).
 *   R13-3  rt32_open_guest_ro with a sysroot never fails open onto the
 *          host filesystem and reports ENAMETOOLONG on overflow.
 *   R14-1  conditional Ticc words decode to SPARC32_OP_TRAP with the
 *          right condition (the inverted-sense fix keys on these).
 *   R14-2  CTI/TRAP words decode to their SPARC32_OP_* classes (the
 *          delay-slot singlestep fix keys on these).
 *   R15-1  fp_to_i32 maps NaN/+Inf to 0x7FFFFFFF (NVC) and -Inf to
 *          0x80000000 (NVC), matching the FsTOi/FdTOi DBT fix.
 *   R15-2  two-quiet-NaN arithmetic selects per fp_f32/f64_pick_nan
 *          (larger fraction wins, ties keep va), SNaN quiets with NVC.
 *   R13-7  sparc32_fpu_double_dest agrees on FSQRTd (double) vs FDTOS
 *          (single); R13-8 is covered by construction (single mapping).
 *
 * DBT emission itself (R14-1 invert, R14-2 singlestep, R15-1 CSEL,
 * R15-2 payload compare) is exercised end-to-end by tests/guests/r13r16
 * under --interp, --dbt, and --difftest (see tests/check_r13_r16.sh).
 *
 * Build & run (host-native):
 *   cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
 *     -Iinclude -Isrc tests/test_r13_r16.c src/os/syscalls_sig.c \
 *     src/interp/interp_win.c src/interp/interp_mem.c \
 *     src/interp/decode.c src/rt32/elf32.c src/interp/fp_arith.c \
 *     -o /tmp/test_r13_r16 && /tmp/test_r13_r16
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sparc32rt.h"
#include "interp/decode.h"
#include "interp/fp.h"
#include "os/threads.h"

/* Real entry points under test (declared locally like syscalls_min.c). */
long sparc32_sys_rt_sigreturn(sparc32_ctx_t *ctx);
int rt32_open_guest_ro(const sparc32_ctx_t *ctx, const char *guest_path);

/* ---- link stubs: controlled environment, real objects under test ---- */

/* 1 MiB page table covering the whole 4 GiB window (fake_prot[va>>12]). */
static uint8_t fake_prot[1U << 20];

const uint8_t *sparc32_vm_prot_base(void)
{
    return fake_prot;
}

void sparc32_vm_access_enter(void)
{
}

void sparc32_vm_access_leave(void)
{
}

void vm32_note_page_write(uint32_t gva, size_t len)
{
    (void)gva;
    (void)len;
}

bool vm32_range_has_code(uint32_t gva, size_t len)
{
    (void)gva;
    (void)len;
    return false;
}

void vm_invalidate_jit(sparc32_ctx_t *ctx, uint32_t start, uint32_t end)
{
    (void)ctx;
    (void)start;
    (void)end;
}

bool sparc32_thr_is_retired(const sparc32_ctx_t *ctx)
{
    (void)ctx;
    return false;
}

void sparc32_thr_host_handler(int sig)
{
    (void)sig;
}

void sparc32_thr_discard_signal(sparc32_ctx_t *ctx, int sig)
{
    (void)ctx;
    (void)sig;
}

uint64_t sparc32_thr_mask_sanitize(uint64_t mask)
{
    mask &= ~sparc32_thr_sigbit(9);
    mask &= ~sparc32_thr_sigbit(17);
    return mask;
}

/* rt32_vm_record_region is only reached on the loader commit path;
 * rt32_open_guest_ro never calls it, but the link needs the symbol. */
int rt32_vm_record_region(sparc32_ctx_t *ctx, uint32_t start, uint32_t end,
    uint32_t prot, uint32_t flags, const char *name)
{
    (void)ctx;
    (void)start;
    (void)end;
    (void)prot;
    (void)flags;
    (void)name;
    return 0;
}

static int failures = 0;

static void expect(int cond, const char *what)
{
    if (cond == 0) {
        printf("R13-R16 FAIL: %s\n", what);
        failures++;
    }
}

/* Big-endian word access into the fake guest window. */
static uint8_t guest_mem[8192];
static sparc32_ctx_t tctx;

static void w32(uint32_t va, uint32_t v)
{
    uint8_t *p = guest_mem + (va - 0x10000U);
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void guest_env_init(void)
{
    memset(&tctx, 0, sizeof(tctx));
    memset(guest_mem, 0, sizeof(guest_mem));
    memset(fake_prot, 0, sizeof(fake_prot));
    tctx.guest_base = (uint64_t)(uintptr_t)guest_mem - 0x10000ULL;
    fake_prot[0x10000U >> 12] = 3U;
    fake_prot[0x11000U >> 12] = 3U;
}

/* ---- S32-R13-3: sysroot ELF open ---- */

static void test_sysroot(void)
{
    char dir[64];
    char sub[80];
    char path[96];
    char host_probe[64];
    int fd;
    ssize_t n;
    char buf[8];
    char *longroot;
    size_t i;
    snprintf(dir, sizeof(dir), "/tmp/r13sys_%d", (int)getpid());
    snprintf(sub, sizeof(sub), "%s/empty", dir);
    snprintf(path, sizeof(path), "%s/hello", dir);
    snprintf(host_probe, sizeof(host_probe), "/tmp/r13probe_%d",
        (int)getpid());
    expect(mkdir(dir, 0700) == 0, "sysroot mkdir");
    expect(mkdir(sub, 0700) == 0, "sysroot empty mkdir");
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    expect(fd >= 0, "sysroot hello create");
    if (fd >= 0) {
        expect(write(fd, "hi", 2) == 2, "sysroot hello write");
        close(fd);
    }
    fd = open(host_probe, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    expect(fd >= 0, "host probe create");
    if (fd >= 0) {
        expect(write(fd, "HOST", 4) == 4, "host probe write");
        close(fd);
    }
    memset(&tctx, 0, sizeof(tctx));
    tctx.sysroot = dir;
    /* Present under the sysroot: opens and reads. */
    fd = rt32_open_guest_ro(&tctx, "/hello");
    expect(fd >= 0, "sysroot hit opens");
    if (fd >= 0) {
        n = read(fd, buf, sizeof(buf));
        expect(n == 2 && buf[0] == 'h' && buf[1] == 'i',
            "sysroot hit content");
        close(fd);
    }
    /* Missing under the sysroot: ENOENT, no host fallback. */
    errno = 0;
    fd = rt32_open_guest_ro(&tctx, "/no-such-file");
    expect(fd == -1 && errno == ENOENT, "sysroot miss ENOENT");
    /* Present on the host but outside the sysroot: must NOT open. */
    tctx.sysroot = sub;
    errno = 0;
    fd = rt32_open_guest_ro(&tctx, host_probe);
    expect(fd == -1 && errno == ENOENT, "sysroot no fail-open to host");
    if (fd >= 0) {
        close(fd);
    }
    /* Overlong resolution: ENAMETOOLONG. */
    longroot = (char *)malloc(2048U);
    expect(longroot != NULL, "sysroot longroot alloc");
    if (longroot != NULL) {
        for (i = 0U; i < 2047U; i++) {
            longroot[i] = 'a';
        }
        longroot[2047] = '\0';
        tctx.sysroot = longroot;
        errno = 0;
        fd = rt32_open_guest_ro(&tctx, "/x");
        expect(fd == -1 && errno == ENAMETOOLONG,
            "sysroot overflow ENAMETOOLONG");
        free(longroot);
    }
    unlink(path);
    unlink(host_probe);
    rmdir(sub);
    rmdir(dir);
}

/* ---- S32-R13-2: sigreturn window cursor and stack chain ---- */

#define T_FRAME 0x10000U

static void frame_init(void)
{
    int i;
    for (i = 0; i < 8; i++) {
        w32(T_FRAME + (uint32_t)i * 4U, 0x11111110U + (uint32_t)i);
        w32(T_FRAME + 32U + (uint32_t)i * 4U, 0x11111118U + (uint32_t)i);
    }
    for (i = 0; i < 16; i++) {
        uint32_t v = (i < 8) ? (0xA0U + (uint32_t)i)
                             : (0xA8U + (uint32_t)i);
        w32(T_FRAME + 0xF0U + (uint32_t)i * 4U, v);
    }
    w32(T_FRAME + 0xE0U, 0xC5U); /* psr: cwp 5 */
    w32(T_FRAME + 0xE4U, 0x12000U);
    w32(T_FRAME + 0xE8U, 0x12004U);
    w32(T_FRAME + 0xECU, 0x9U);
    w32(T_FRAME + 0x130U, 0xFFFFFFFFU);
    w32(T_FRAME + 0x134U, 0xFFFFFFFFU);
    w32(T_FRAME + 0x138U, 0U); /* fpu_save: none */
    w32(T_FRAME + 0x154U, 0U); /* rwin_save: none */
}

/* Handler-like context: its own SAVE chain (cwp 2, cached windows,
 * clobbered live window) over the interrupted frame. */
static void handler_ctx_init(void)
{
    int i;
    int w;
    guest_env_init();
    frame_init();
    tctx.r[SPARC32_SP] = T_FRAME;
    tctx.cwp = 2U;
    tctx.psr = 0xE2U;
    tctx.cansave = 0U;
    tctx.canrestore = 7U;
    for (w = 0; w < 8; w++) {
        tctx.win_valid[w] = 1U;
        for (i = 0; i < 16; i++) {
            tctx.winfile[w][i] = 0xEEEE0000U + (uint32_t)w;
        }
    }
    for (i = 0; i < 8; i++) {
        tctx.r[SPARC32_L0 + (uint32_t)i] = 0xDEAD0000U + (uint32_t)i;
        tctx.r[SPARC32_I0 + (uint32_t)i] = 0xDEAD0010U + (uint32_t)i;
    }
    tctx.sig_mask = 0ULL;
}

static void test_sigreturn_restore(void)
{
    uint64_t want_mask;
    int i;
    int w;
    long rc;
    handler_ctx_init();
    rc = sparc32_sys_rt_sigreturn(&tctx);
    expect(rc == 0, "sigreturn restores (rc==0)");
    expect(tctx.cwp == 5U, "sigreturn restores cwp");
    expect(tctx.psr == 0xC5U, "sigreturn restores psr+cwp");
    expect(tctx.canrestore == 0U, "sigreturn clears canrestore");
    expect(tctx.cansave == 7U, "sigreturn resets cansave");
    for (w = 0; w < 8; w++) {
        expect(tctx.win_valid[w] == 0U, "sigreturn clears win_valid");
    }
    for (i = 0; i < 8; i++) {
        expect(tctx.r[SPARC32_L0 + (uint32_t)i] ==
            0x11111110U + (uint32_t)i, "sigreturn restores L");
        expect(tctx.r[SPARC32_I0 + (uint32_t)i] ==
            0x11111118U + (uint32_t)i, "sigreturn restores I");
    }
    for (i = 1; i < 8; i++) {
        expect(tctx.r[(uint32_t)i] == 0xA0U + (uint32_t)i,
            "sigreturn restores g");
    }
    for (i = 8; i < 16; i++) {
        expect(tctx.r[SPARC32_O0 + (uint32_t)(i - 8)] ==
            0xA8U + (uint32_t)i, "sigreturn restores o");
    }
    expect(tctx.y == 0x9U, "sigreturn restores y");
    expect(tctx.pc == 0x12000U, "sigreturn restores pc");
    expect(tctx.npc == 0x12004U, "sigreturn restores npc");
    expect(tctx.r[0] == 0U, "sigreturn keeps g0 zero");
    want_mask = sparc32_thr_mask_sanitize(0xFFFFFFFFFFFFFFFFULL);
    expect(tctx.sig_mask == want_mask, "sigreturn restores mask");
}

/* A frame whose protection is revoked must abort with -EFAULT and
 * leave the context untouched (loads precede every mutation). */
static void test_sigreturn_fault(void)
{
    uint32_t save_cwp;
    uint32_t save_psr;
    uint32_t save_l0;
    long rc;
    handler_ctx_init();
    save_cwp = tctx.cwp;
    save_psr = tctx.psr;
    save_l0 = tctx.r[SPARC32_L0];
    fake_prot[T_FRAME >> 12] = 0U;
    rc = sparc32_sys_rt_sigreturn(&tctx);
    expect(rc == -EFAULT, "sigreturn faulty frame EFAULT");
    expect(tctx.cwp == save_cwp, "sigreturn fault keeps cwp");
    expect(tctx.psr == save_psr, "sigreturn fault keeps psr");
    expect(tctx.r[SPARC32_L0] == save_l0, "sigreturn fault keeps L0");
    expect(tctx.canrestore == 7U, "sigreturn fault keeps canrestore");
    fake_prot[T_FRAME >> 12] = 3U;
}

/* Misaligned frame address aborts without mutation. */
static void test_sigreturn_misaligned(void)
{
    long rc;
    handler_ctx_init();
    tctx.r[SPARC32_SP] = T_FRAME + 1U;
    rc = sparc32_sys_rt_sigreturn(&tctx);
    expect(rc == -EFAULT, "sigreturn misaligned EFAULT");
    expect(tctx.cwp == 2U, "sigreturn misaligned keeps cwp");
}

/* ---- S32-R15-1 / R15-2: FP oracle semantics ---- */

static void test_fp_to_i32(void)
{
    sparc32_ctx_t c;
    uint32_t r;
    memset(&c, 0, sizeof(c));
    r = fp_to_i32(&c, nan(""), 0U);
    expect(r == 0x7FFFFFFFU, "fstoi NaN -> INT32_MAX");
    expect(c.fsr == 0x210U, "fstoi NaN sets NVC");
    memset(&c, 0, sizeof(c));
    r = fp_to_i32(&c, INFINITY, 0U);
    expect(r == 0x7FFFFFFFU, "fstoi +Inf -> INT32_MAX");
    expect(c.fsr == 0x210U, "fstoi +Inf sets NVC");
    memset(&c, 0, sizeof(c));
    r = fp_to_i32(&c, -INFINITY, 0U);
    expect(r == 0x80000000U, "fstoi -Inf -> INT32_MIN");
    expect(c.fsr == 0x210U, "fstoi -Inf sets NVC");
}

static void test_fp_pick_nan(void)
{
    sparc32_ctx_t c;
    uint32_t r32;
    uint64_t r64;
    expect(fp_f32_pick_nan(0x7FC00001U, 0x7FC00002U) == 0x7FC00002U,
        "pick_nan32 larger frac wins");
    expect(fp_f32_pick_nan(0x7FC00005U, 0x7FC00003U) == 0x7FC00005U,
        "pick_nan32 smaller frac loses");
    expect(fp_f32_pick_nan(0x7FC00004U, 0x7FC00004U) == 0x7FC00004U,
        "pick_nan32 tie keeps va");
    expect(fp_f32_pick_nan(0xFFC00002U, 0x7FC00001U) == 0xFFC00002U,
        "pick_nan32 keeps winner sign");
    expect(fp_f64_pick_nan(0x7FF8000000000001ULL,
            0x7FF8000000000002ULL) == 0x7FF8000000000002ULL,
        "pick_nan64 larger frac wins");
    expect(fp_f64_pick_nan(0x7FFC000000000009ULL,
            0x7FF8000000000003ULL) == 0x7FFC000000000009ULL,
        "pick_nan64 smaller frac loses");
    /* End-to-end through the shared binary-op path (nan2 + pick_nan). */
    memset(&c, 0, sizeof(c));
    r32 = fp_add_f32(&c, 0x7FC00001U, 0x7FC00002U);
    expect(r32 == 0x7FC00002U, "fadds two-QNaN selects vb");
    expect(c.fsr == 0U, "fadds two-QNaN raises no flags");
    memset(&c, 0, sizeof(c));
    r32 = fp_add_f32(&c, 0x7FC00005U, 0x7FC00003U);
    expect(r32 == 0x7FC00005U, "fadds two-QNaN selects va");
    expect(c.fsr == 0U, "fadds va-win raises no flags");
    memset(&c, 0, sizeof(c));
    r64 = fp_add_f64(&c, 0x7FF8000000000001ULL,
        0x7FF8000000000002ULL);
    expect(r64 == 0x7FF8000000000002ULL, "faddd two-QNaN selects vb");
    expect(c.fsr == 0U, "faddd two-QNaN raises no flags");
    memset(&c, 0, sizeof(c));
    r32 = fp_add_f32(&c, 0x7F800001U, 0x7FC00002U);
    expect(r32 == 0x7FC00001U, "fadds SNaN quiets first input");
    expect(c.fsr == 0x210U, "fadds SNaN sets NVC");
}

/* ---- S32-R14-1 / R14-2 decode classes, S32-R13-7 double-dest ---- */

static void test_decode_classes(void)
{
    sparc32_decoded_t d;
    sparc32_decode_word(0x83D02010U, &d); /* te 0x10 */
    expect(d.cls == (uint32_t)SPARC32_OP_TRAP, "te decodes TRAP");
    expect(d.cond == 1U, "te cond is 1");
    sparc32_decode_word(0x81D02000U, &d); /* tn 0x0 */
    expect(d.cls == (uint32_t)SPARC32_OP_TRAP, "tn decodes TRAP");
    expect(d.cond == 0U, "tn cond is 0");
    sparc32_decode_word(0x91D02010U, &d); /* ta 0x10 */
    expect(d.cls == (uint32_t)SPARC32_OP_TRAP, "ta decodes TRAP");
    expect(d.cond == 8U, "ta cond is 8");
    sparc32_decode_word(0x10800000U, &d); /* ba +0 */
    expect(d.cls == (uint32_t)SPARC32_OP_BRANCH, "ba decodes BRANCH");
    expect(d.cond == 8U, "ba cond is 8");
    sparc32_decode_word(0x00800000U, &d); /* bn +0 */
    expect(d.cls == (uint32_t)SPARC32_OP_BRANCH, "bn decodes BRANCH");
    sparc32_decode_word(0x81C3E008U, &d); /* jmpl %o7+8, %g0 */
    expect(d.cls == (uint32_t)SPARC32_OP_JMPL, "jmpl decodes JMPL");
    expect(sparc32_fpu_double_dest(SPARC32_OP3_FPOP1, 0x02AU) != 0,
        "FSQRTd is double-dest");
    expect(sparc32_fpu_double_dest(SPARC32_OP3_FPOP1, 0x042U) != 0,
        "FADDd is double-dest");
    expect(sparc32_fpu_double_dest(SPARC32_OP3_FPOP1, 0x0C6U) == 0,
        "FDTOS is single-dest");
    expect(sparc32_fpu_double_dest(SPARC32_OP3_FPOP1, 0x0D1U) == 0,
        "FsTOi is single-dest");
    expect(sparc32_fpu_double_dest(SPARC32_OP3_FPOP2, 0x051U) == 0,
        "FPop2 never double-dest");
}

int main(void)
{
    test_sysroot();
    test_sigreturn_restore();
    test_sigreturn_fault();
    test_sigreturn_misaligned();
    test_fp_to_i32();
    test_fp_pick_nan();
    test_decode_classes();
    if (failures == 0) {
        printf("R13-R16-UNITS: PASS\n");
    }
    return (failures == 0) ? 0 : 1;
}
