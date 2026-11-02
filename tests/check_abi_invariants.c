/*
 * tests/check_abi_invariants.c — host-runnable ABI invariant checks
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L0b (Phase 0, RC0): compile-time _Static_assert plus runtime
 * offsetof/sizeof checks for every field offset and struct size in
 * sparc32_ctx_t (src/sparc32rt.h, frozen) and src/os/sigframe_sparc32rt.h
 * (SPEC section 2.2). Prints PASS and returns 0 on success.
 *
 * Build: cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
 *          -Iinclude -Isrc tests/check_abi_invariants.c \
 *          -o _build/check_abi_invariants
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "sparc32rt.h"
#include "interp/interp_priv.h"
#include "os/sigframe_sparc32rt.h"

static int failures = 0;

#define CHECK_OFF(type, member, expect)                                       \
    do {                                                                      \
        size_t got = offsetof(type, member);                                  \
        if (got != (size_t)(expect)) {                                        \
            printf("FAIL %s.%s: got %lu want %lu\n", #type, #member,         \
                (unsigned long)got, (unsigned long)(expect));                 \
            ++failures;                                                       \
        }                                                                     \
    } while (0)

#define CHECK_SIZE(type, expect)                                              \
    do {                                                                      \
        size_t got = sizeof(type);                                            \
        if (got != (size_t)(expect)) {                                        \
            printf("FAIL sizeof(%s): got %lu want %lu\n", #type,             \
                (unsigned long)got, (unsigned long)(expect));                 \
            ++failures;                                                       \
        }                                                                     \
    } while (0)

#define CHECK_CONST(name, got, expect)                                        \
    do {                                                                      \
        unsigned long long v = (unsigned long long)(got);                     \
        unsigned long long w = (unsigned long long)(expect);                  \
        if (v != w) {                                                         \
            printf("FAIL %s: got %llu want %llu\n", name, v, w);             \
            ++failures;                                                       \
        }                                                                     \
    } while (0)

/* Compile-time pins (duplicate the headers' asserts from the consumer side
 * so a silent header edit breaks this TU too). */
_Static_assert(offsetof(sparc32_ctx_t, r) == 0, "ctx.r");
_Static_assert(offsetof(sparc32_ctx_t, pc) == 0x080, "ctx.pc");
_Static_assert(offsetof(sparc32_ctx_t, guest_base) == 0x130, "ctx.guest_base");
_Static_assert(offsetof(sparc32_ctx_t, ras) == 0x190, "ctx.ras");
_Static_assert(offsetof(sparc32_ctx_t, ibtc) == 0x990, "ctx.ibtc");
_Static_assert(sizeof(sparc32_rt_sigframe_t) == 344, "rt frame 344");
_Static_assert(sizeof(sparc32_stat_t) == 64, "stat 64");
_Static_assert(sizeof(sparc32_stat64_t) == 104, "stat64 104");

static void check_ctx(void)
{
    CHECK_OFF(sparc32_ctx_t, r, 0x000);
    CHECK_OFF(sparc32_ctx_t, pc, 0x080);
    CHECK_OFF(sparc32_ctx_t, npc, 0x084);
    CHECK_OFF(sparc32_ctx_t, y, 0x088);
    CHECK_OFF(sparc32_ctx_t, psr, 0x08c);
    CHECK_OFF(sparc32_ctx_t, fsr, 0x090);
    CHECK_OFF(sparc32_ctx_t, f, 0x094);
    CHECK_OFF(sparc32_ctx_t, cwp, 0x114);
    CHECK_OFF(sparc32_ctx_t, cansave, 0x118);
    CHECK_OFF(sparc32_ctx_t, canrestore, 0x11c);
    CHECK_OFF(sparc32_ctx_t, otherwin, 0x120);
    CHECK_OFF(sparc32_ctx_t, cleanwin, 0x124);
    CHECK_OFF(sparc32_ctx_t, nwindows, 0x128);
    CHECK_OFF(sparc32_ctx_t, guest_base, 0x130);
    CHECK_OFF(sparc32_ctx_t, exit_reason, 0x138);
    CHECK_OFF(sparc32_ctx_t, exit_arg, 0x13c);
    CHECK_OFF(sparc32_ctx_t, fault_addr, 0x140);
    CHECK_OFF(sparc32_ctx_t, exit_dest, 0x144);
    CHECK_OFF(sparc32_ctx_t, sig_mask, 0x148);
    CHECK_OFF(sparc32_ctx_t, pending_signals, 0x150);
    CHECK_OFF(sparc32_ctx_t, trace_enabled, 0x158);
    CHECK_OFF(sparc32_ctx_t, blocks_executed, 0x160);
    CHECK_OFF(sparc32_ctx_t, chain_hits, 0x168);
    CHECK_OFF(sparc32_ctx_t, last_exec_entry, 0x170);
    CHECK_OFF(sparc32_ctx_t, ibtc_hits, 0x178);
    CHECK_OFF(sparc32_ctx_t, ras_hits, 0x180);
    CHECK_OFF(sparc32_ctx_t, ras_top, 0x188);
    CHECK_OFF(sparc32_ctx_t, ras, 0x190);
    CHECK_OFF(sparc32_ctx_t, ibtc, 0x990);

    /* ABI-locked constants (SPEC section 2.1). */
    CHECK_CONST("SPARC32_PSR_N", SPARC32_PSR_N, 1U << 23);
    CHECK_CONST("SPARC32_PSR_Z", SPARC32_PSR_Z, 1U << 22);
    CHECK_CONST("SPARC32_PSR_V", SPARC32_PSR_V, 1U << 21);
    CHECK_CONST("SPARC32_PSR_C", SPARC32_PSR_C, 1U << 20);
    CHECK_CONST("SPARC32_NWINDOWS", SPARC32_NWINDOWS, 8);
    CHECK_CONST("SPARC32_RWINDOW_SIZE", SPARC32_RWINDOW_SIZE, 64);
    CHECK_CONST("SPARC32_RAS_SIZE", SPARC32_RAS_SIZE, 64);
    CHECK_CONST("SPARC32_IBTC_SIZE", SPARC32_IBTC_SIZE, 1024);
    CHECK_CONST("SPARC32_TASK_SIZE_TOP", SPARC32_TASK_SIZE_TOP, 0xF0000000UL);
    CHECK_CONST("SPARC32_STACK_TOP", SPARC32_STACK_TOP, 0xEFFF0000UL);
    CHECK_CONST("SPARC32_SIGTRAMP_PAGE", SPARC32_SIGTRAMP_PAGE, 0xEFFFE000UL);
    CHECK_CONST("sizeof(r)", sizeof(((sparc32_ctx_t *)0)->r), 128);
    CHECK_CONST("sizeof(f)", sizeof(((sparc32_ctx_t *)0)->f), 128);
    CHECK_CONST("sizeof(ibtc_entry)", sizeof(sparc32_ibtc_entry_t), 32);
}

static void check_sigframe(void)
{
    CHECK_SIZE(sparc32_stackf_t, 96);
    CHECK_OFF(sparc32_stackf_t, locals, 0x00);
    CHECK_OFF(sparc32_stackf_t, ins, 0x20);
    CHECK_OFF(sparc32_stackf_t, fp, 0x38);
    CHECK_OFF(sparc32_stackf_t, callers_pc, 0x3c);
    CHECK_OFF(sparc32_stackf_t, structptr, 0x40);
    CHECK_OFF(sparc32_stackf_t, xargs, 0x44);
    CHECK_OFF(sparc32_stackf_t, xxargs, 0x5c);

    CHECK_SIZE(sparc32_siginfo_t, 128);
    CHECK_OFF(sparc32_siginfo_t, si_signo, 0x00);
    CHECK_OFF(sparc32_siginfo_t, si_errno, 0x04);
    CHECK_OFF(sparc32_siginfo_t, si_code, 0x08);
    CHECK_OFF(sparc32_siginfo_t, sifields, 0x0c);

    CHECK_SIZE(sparc32_pt_regs_t, 80);
    CHECK_OFF(sparc32_pt_regs_t, psr, 0x00);
    CHECK_OFF(sparc32_pt_regs_t, pc, 0x04);
    CHECK_OFF(sparc32_pt_regs_t, npc, 0x08);
    CHECK_OFF(sparc32_pt_regs_t, y, 0x0c);
    CHECK_OFF(sparc32_pt_regs_t, u_regs, 0x10);

    CHECK_SIZE(sparc32_sigmask_t, 8);
    CHECK_SIZE(sparc32_stack_t, 12);
    CHECK_OFF(sparc32_stack_t, ss_sp, 0x00);
    CHECK_OFF(sparc32_stack_t, ss_flags, 0x04);
    CHECK_OFF(sparc32_stack_t, ss_size, 0x08);

    CHECK_SIZE(sparc32_rt_sigframe_t, 344);
    CHECK_OFF(sparc32_rt_sigframe_t, ss, 0x000);
    CHECK_OFF(sparc32_rt_sigframe_t, info, 0x060);
    CHECK_OFF(sparc32_rt_sigframe_t, regs, 0x0e0);
    CHECK_OFF(sparc32_rt_sigframe_t, mask, 0x130);
    CHECK_OFF(sparc32_rt_sigframe_t, fpu_save, 0x138);
    CHECK_OFF(sparc32_rt_sigframe_t, insns, 0x13c);
    CHECK_OFF(sparc32_rt_sigframe_t, stack, 0x144);
    CHECK_OFF(sparc32_rt_sigframe_t, extra_size, 0x150);
    CHECK_OFF(sparc32_rt_sigframe_t, rwin_save, 0x154);
    CHECK_OFF(sparc32_rt_sigframe_t, regs.pc, 0x0e4);
    CHECK_OFF(sparc32_rt_sigframe_t, regs.npc, 0x0e8);
    CHECK_OFF(sparc32_rt_sigframe_t, regs.u_regs, 0x0f0);

    /* Handler ABI pins (E05 + signal_32.c). */
    CHECK_CONST("UREG_I0(signo slot)", SPARC32_UREG_I0, 8);
    CHECK_CONST("UREG_FP", SPARC32_UREG_FP, 14);
    CHECK_CONST("UREG_RETPC", SPARC32_UREG_RETPC, 15);
    CHECK_CONST("NR_rt_sigreturn", SPARC32_NR_RT_SIGRETURN, 101);
    CHECK_CONST("NR_rt_sigaction", SPARC32_NR_RT_SIGACTION, 102);
    CHECK_CONST("restorer mov", SPARC32_RESTORER_MOV_G1, 0x82102065UL);
    CHECK_CONST("restorer ta", SPARC32_RESTORER_TA_10, 0x91d02010UL);
    CHECK_CONST("SIGMASK_SIZE", SPARC32_SIGMASK_SIZE, 8);
    CHECK_CONST("RT_SIGFRAME_SIZE", SPARC32_RT_SIGFRAME_SIZE, 344);
    CHECK_CONST("SIGFPU_SIZE", SPARC32_SIGFPU_SIZE, 136);

    CHECK_SIZE(sparc32_mcontext_t, 80);
    CHECK_SIZE(sparc32_sigcontext_t, 88);
    CHECK_OFF(sparc32_sigcontext_t, regs, 0);
    CHECK_OFF(sparc32_sigcontext_t, mask, 80);
    CHECK_SIZE(sparc32_ucontext_t, 116);
    CHECK_OFF(sparc32_ucontext_t, uc_flags, 0);
    CHECK_OFF(sparc32_ucontext_t, uc_link, 4);
    CHECK_OFF(sparc32_ucontext_t, uc_stack, 8);
    CHECK_OFF(sparc32_ucontext_t, uc_mcontext, 20);
    CHECK_OFF(sparc32_ucontext_t, uc_sigmask, 108);
}

static void check_stat(void)
{
    CHECK_SIZE(sparc32_stat_t, 64);
    CHECK_OFF(sparc32_stat_t, st_dev, 0x00);
    CHECK_OFF(sparc32_stat_t, st_ino, 0x04);
    CHECK_OFF(sparc32_stat_t, st_mode, 0x08);
    CHECK_OFF(sparc32_stat_t, st_nlink, 0x0c);
    CHECK_OFF(sparc32_stat_t, st_uid, 0x0e);
    CHECK_OFF(sparc32_stat_t, st_gid, 0x10);
    CHECK_OFF(sparc32_stat_t, st_rdev, 0x12);
    CHECK_OFF(sparc32_stat_t, st_size, 0x14);
    CHECK_OFF(sparc32_stat_t, st_atime, 0x18);
    CHECK_OFF(sparc32_stat_t, st_atime_nsec, 0x1c);
    CHECK_OFF(sparc32_stat_t, st_mtime, 0x20);
    CHECK_OFF(sparc32_stat_t, st_mtime_nsec, 0x24);
    CHECK_OFF(sparc32_stat_t, st_ctime, 0x28);
    CHECK_OFF(sparc32_stat_t, st_ctime_nsec, 0x2c);
    CHECK_OFF(sparc32_stat_t, st_blksize, 0x30);
    CHECK_OFF(sparc32_stat_t, st_blocks, 0x34);
    CHECK_OFF(sparc32_stat_t, __unused4, 0x38);

    CHECK_SIZE(sparc32_stat64_t, 104);
    CHECK_OFF(sparc32_stat64_t, st_dev, 0x00);
    CHECK_OFF(sparc32_stat64_t, st_ino, 0x08);
    CHECK_OFF(sparc32_stat64_t, st_mode, 0x10);
    CHECK_OFF(sparc32_stat64_t, st_nlink, 0x14);
    CHECK_OFF(sparc32_stat64_t, st_uid, 0x18);
    CHECK_OFF(sparc32_stat64_t, st_gid, 0x1c);
    CHECK_OFF(sparc32_stat64_t, st_rdev, 0x20);
    CHECK_OFF(sparc32_stat64_t, __pad3, 0x28);
    CHECK_OFF(sparc32_stat64_t, st_size, 0x30);
    CHECK_OFF(sparc32_stat64_t, st_blksize, 0x38);
    CHECK_OFF(sparc32_stat64_t, __pad4, 0x3c);
    CHECK_OFF(sparc32_stat64_t, st_blocks, 0x44);
    CHECK_OFF(sparc32_stat64_t, st_atime, 0x48);
    CHECK_OFF(sparc32_stat64_t, st_atime_nsec, 0x4c);
    CHECK_OFF(sparc32_stat64_t, st_mtime, 0x50);
    CHECK_OFF(sparc32_stat64_t, st_mtime_nsec, 0x54);
    CHECK_OFF(sparc32_stat64_t, st_ctime, 0x58);
    CHECK_OFF(sparc32_stat64_t, st_ctime_nsec, 0x5c);
    CHECK_OFF(sparc32_stat64_t, __unused4, 0x60);
    CHECK_OFF(sparc32_stat64_t, __unused5, 0x64);
}

int main(void)
{
    check_ctx();
    check_sigframe();
    check_stat();
    if (failures != 0) {
        printf("FAILURES: %d\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
