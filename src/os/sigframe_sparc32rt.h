/*
 * src/os/sigframe_sparc32rt.h — frozen SPARC32 signal-frame + stat UAPI
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L0b owns this file (Phase 0 freeze, SPEC section 2.2,
 * experiments/E05/FINDINGS.md). Other lanes must not edit it; escalate
 * instead.
 *
 * Layout authority, in order:
 *   1. SPEC section 2.2 (frozen offsets, implemented verbatim below).
 *   2. Linux arch/sparc/include/uapi/asm/ptrace.h (sparc_stackf, pt_regs),
 *      arch/sparc/include/uapi/asm/stat.h (stat, stat64),
 *      include/uapi/asm-generic/siginfo.h (siginfo_t, 128 B).
 *   3. Oracle behavior (qemu-sparc -cpu LEON3, E05): signo in %o0,
 *      pc/npc recoverable from the frame, si_addr present, interrupted
 *      %sp present, rt_sigaction is 5-arg with sigsetsize 8.
 *
 * RESOLVED (Coordinator decision on Linux v6.6
 * arch/sparc/kernel/signal_32.c first-hand evidence): the rt frame tail is
 * kernel-order stack, extra_size, rwin_save, 344 B total, no extramask
 * (the non-RT `struct signal_frame' is the one carrying
 * extramask[_NSIG_WORDS - 1]); qemu linux-user/sparc/signal.c
 * `target_rt_signal_frame' uses the same order (ss + siginfo + pt_regs +
 * mask + fpu_save + insns[2] + stack + extra_size + rwin_save, E05
 * finding 8). This header freezes that kernel-order 344 B layout;
 * SPEC section 2.2 is to be corrected by the Coordinator.
 *
 * Handler ABI (E05 + signal_32.c setup_rt_frame/do_rt_sigreturn):
 *   - signo delivered in %o0 (regs.u_regs[UREG_I0], UREG_I0 == 8).
 *   - regs carries the interrupted psr/pc/npc/y; rt_sigreturn restores
 *     pc/npc, y, u_regs[G1..I7], mask, and altstack from the frame.
 *   - Default restorer: { 0x82102065 (`mov 101, %g1', __NR_rt_sigreturn),
 *     0x91d02010 (`ta 0x10') }.
 *   - rt_sigaction (nr 102) is 5-arg: sig, act, oact, restorer,
 *     sigsetsize (== 8, sizeof sparc32_sigmask_t); the 4-arg form is EINVAL.
 */

#ifndef SPARC32RT_OS_SIGFRAME_SPARC32RT_H
#define SPARC32RT_OS_SIGFRAME_SPARC32RT_H

#include <stddef.h>
#include <stdint.h>

/* ---- Frame geometry (SPEC section 2.2, frozen) --------------------------- */
#define SPARC32_SS_SIZE         96U
#define SPARC32_SIGINFO_SIZE    128U
#define SPARC32_PT_REGS_SIZE    80U
#define SPARC32_SIGMASK_WORDS   2U
#define SPARC32_SIGMASK_SIZE    8U
#define SPARC32_RT_SIGFRAME_SIZE 344U

#define SPARC32_RT_OFF_SS       0x000U
#define SPARC32_RT_OFF_INFO     0x060U
#define SPARC32_RT_OFF_REGS     0x0e0U
#define SPARC32_RT_OFF_MASK     0x130U
#define SPARC32_RT_OFF_FPU_SAVE 0x138U
#define SPARC32_RT_OFF_INSNS    0x13cU
#define SPARC32_RT_OFF_STACK    0x144U
#define SPARC32_RT_OFF_EXTRA_SIZE 0x150U
#define SPARC32_RT_OFF_RWIN_SAVE 0x154U

/* Syscall + restorer constants (src/os/syscall_nr.h, signal_32.c). */
#define SPARC32_NR_RT_SIGRETURN 101U
#define SPARC32_NR_RT_SIGACTION 102U
#define SPARC32_RESTORER_MOV_G1 0x82102065U /* mov __NR_rt_sigreturn, %g1 */
#define SPARC32_RESTORER_TA_10  0x91d02010U /* ta 0x10 */

/* pt_regs u_regs[] indices (uapi asm/ptrace.h UREG_*; no %o/%l snapshot:
 * register windows are flushed to the stack before delivery). */
enum {
    SPARC32_UREG_G0 = 0,
    SPARC32_UREG_G1 = 1,
    SPARC32_UREG_G2 = 2,
    SPARC32_UREG_G3 = 3,
    SPARC32_UREG_G4 = 4,
    SPARC32_UREG_G5 = 5,
    SPARC32_UREG_G6 = 6,
    SPARC32_UREG_G7 = 7,
    SPARC32_UREG_I0 = 8,  /* handler %o0 (signo) aliases this slot */
    SPARC32_UREG_I1 = 9,
    SPARC32_UREG_I2 = 10,
    SPARC32_UREG_I3 = 11,
    SPARC32_UREG_I4 = 12,
    SPARC32_UREG_I5 = 13,
    SPARC32_UREG_I6 = 14, /* UREG_FP: interrupted %sp lives here */
    SPARC32_UREG_I7 = 15  /* UREG_RETPC */
};
#define SPARC32_UREG_FP    SPARC32_UREG_I6
#define SPARC32_UREG_RETPC SPARC32_UREG_I7

/* ---- struct sparc_stackf (96 B, uapi asm/ptrace.h) ----------------------- */
typedef struct {
    uint32_t locals[8];   /* 0x00 */
    uint32_t ins[6];      /* 0x20 */
    uint32_t fp;          /* 0x38 */
    uint32_t callers_pc;  /* 0x3c */
    uint32_t structptr;   /* 0x40 */
    uint32_t xargs[6];    /* 0x44 */
    uint32_t xxargs[1];   /* 0x5c */
} sparc32_stackf_t;

_Static_assert(sizeof(sparc32_stackf_t) == 96, "sparc_stackf must be 96 bytes");
_Static_assert(offsetof(sparc32_stackf_t, locals) == 0x00, "locals at 0x00");
_Static_assert(offsetof(sparc32_stackf_t, ins) == 0x20, "ins at 0x20");
_Static_assert(offsetof(sparc32_stackf_t, fp) == 0x38, "fp at 0x38");
_Static_assert(offsetof(sparc32_stackf_t, callers_pc) == 0x3c, "callers_pc at 0x3c");
_Static_assert(offsetof(sparc32_stackf_t, structptr) == 0x40, "structptr at 0x40");
_Static_assert(offsetof(sparc32_stackf_t, xargs) == 0x44, "xargs at 0x44");
_Static_assert(offsetof(sparc32_stackf_t, xxargs) == 0x5c, "xxargs at 0x5c");

/* ---- siginfo_t (128 B, asm-generic/siginfo.h; sparc has no
 * __ARCH_SI_TRAPNO, so _sigfault is addr_lsb + bounds + addr) -------------- */
typedef struct {
    int32_t si_signo; /* 0x00 */
    int32_t si_errno; /* 0x04 */
    int32_t si_code;  /* 0x08 */
    union {
        int32_t pad[29];
        struct {
            int16_t  addr_lsb;   /* 0x0c */
            uint8_t  __pad[2];   /* 0x0e */
            uint32_t addr_bnd[2]; /* 0x10 lower/upper bound */
            uint32_t addr;       /* 0x18 faulting address */
        } fault;
        struct {
            int32_t pid;         /* 0x0c */
            uint32_t uid;        /* 0x10 */
            int32_t value;       /* 0x14 sigval int */
        } kill;
    } sifields; /* 0x0c */
} sparc32_siginfo_t;

_Static_assert(sizeof(sparc32_siginfo_t) == 128, "siginfo_t must be 128 bytes");
_Static_assert(offsetof(sparc32_siginfo_t, si_signo) == 0x00, "si_signo at 0");
_Static_assert(offsetof(sparc32_siginfo_t, si_errno) == 0x04, "si_errno at 4");
_Static_assert(offsetof(sparc32_siginfo_t, si_code) == 0x08, "si_code at 8");
_Static_assert(offsetof(sparc32_siginfo_t, sifields) == 0x0c, "sifields at 12");
_Static_assert(offsetof(sparc32_siginfo_t, sifields.fault.addr) == 0x18,
               "si_addr at siginfo+24");

/* ---- struct pt_regs (80 B, uapi asm/ptrace.h, 32-bit) -------------------- */
typedef struct {
    uint32_t psr;       /* 0x00 */
    uint32_t pc;        /* 0x04 interrupted pc */
    uint32_t npc;       /* 0x08 interrupted npc */
    uint32_t y;         /* 0x0c */
    uint32_t u_regs[16]; /* 0x10 %g0..%g7, %i0..%i7 */
} sparc32_pt_regs_t;

_Static_assert(sizeof(sparc32_pt_regs_t) == 80, "pt_regs must be 80 bytes");
_Static_assert(offsetof(sparc32_pt_regs_t, psr) == 0x00, "psr at 0");
_Static_assert(offsetof(sparc32_pt_regs_t, pc) == 0x04, "pc at 4");
_Static_assert(offsetof(sparc32_pt_regs_t, npc) == 0x08, "npc at 8");
_Static_assert(offsetof(sparc32_pt_regs_t, y) == 0x0c, "y at 12");
_Static_assert(offsetof(sparc32_pt_regs_t, u_regs) == 0x10, "u_regs at 16");
_Static_assert(SPARC32_UREG_FP == 14, "UREG_FP == UREG_I6 == 14");
_Static_assert(SPARC32_UREG_RETPC == 15, "UREG_RETPC == UREG_I7 == 15");

/* ---- sigset_t (8 B: _NSIG_WORDS == 2 on 32-bit sparc) -------------------- */
typedef struct {
    uint32_t sig[2]; /* 0x00 */
} sparc32_sigmask_t;

_Static_assert(sizeof(sparc32_sigmask_t) == 8, "sigset_t must be 8 bytes");
_Static_assert(offsetof(sparc32_sigmask_t, sig) == 0, "sig at 0");

/* ---- stack_t / sigaltstack (12 B) --------------------------------------- */
typedef struct {
    uint32_t ss_sp;    /* 0x00 */
    int32_t  ss_flags; /* 0x04 */
    uint32_t ss_size;  /* 0x08 */
} sparc32_stack_t;

_Static_assert(sizeof(sparc32_stack_t) == 12, "stack_t must be 12 bytes");
_Static_assert(offsetof(sparc32_stack_t, ss_sp) == 0x00, "ss_sp at 0");
_Static_assert(offsetof(sparc32_stack_t, ss_flags) == 0x04, "ss_flags at 4");
_Static_assert(offsetof(sparc32_stack_t, ss_size) == 0x08, "ss_size at 8");

/* ---- rt_signal_frame32 (344 B, kernel order, frozen) --------------------- */
typedef struct {
    sparc32_stackf_t  ss;         /* 0x000 */
    sparc32_siginfo_t info;       /* 0x060 */
    sparc32_pt_regs_t regs;       /* 0x0e0 */
    uint32_t          mask[2];    /* 0x130 blocked mask */
    uint32_t          fpu_save;   /* 0x138 guest ptr to sigfpu32 tail or 0 */
    uint32_t          insns[2];   /* 0x13c restorer: mov nr,%g1; ta 0x10 */
    sparc32_stack_t   stack;      /* 0x144 sigaltstack */
    uint32_t          extra_size; /* 0x150 */
    uint32_t          rwin_save;  /* 0x154 guest ptr to saved windows or 0 */
} sparc32_rt_sigframe_t;

_Static_assert(sizeof(sparc32_rt_sigframe_t) == 344, "rt frame must be 344 bytes");
_Static_assert(offsetof(sparc32_rt_sigframe_t, ss) == 0x000, "ss at 0x000");
_Static_assert(offsetof(sparc32_rt_sigframe_t, info) == 0x060, "info at 0x060");
_Static_assert(offsetof(sparc32_rt_sigframe_t, regs) == 0x0e0, "regs at 0x0e0");
_Static_assert(offsetof(sparc32_rt_sigframe_t, mask) == 0x130, "mask at 0x130");
_Static_assert(offsetof(sparc32_rt_sigframe_t, fpu_save) == 0x138, "fpu_save at 0x138");
_Static_assert(offsetof(sparc32_rt_sigframe_t, insns) == 0x13c, "insns at 0x13c");
_Static_assert(offsetof(sparc32_rt_sigframe_t, stack) == 0x144, "stack at 0x144");
_Static_assert(offsetof(sparc32_rt_sigframe_t, extra_size) == 0x150, "extra_size at 0x150");
_Static_assert(offsetof(sparc32_rt_sigframe_t, rwin_save) == 0x154, "rwin_save at 0x154");
_Static_assert(offsetof(sparc32_rt_sigframe_t, regs.pc) == 0x0e4, "frame pc at 0x0e4");
_Static_assert(offsetof(sparc32_rt_sigframe_t, regs.npc) == 0x0e8, "frame npc at 0x0e8");
_Static_assert(offsetof(sparc32_rt_sigframe_t, regs.u_regs) == 0x0f0, "frame u_regs at 0x0f0");
_Static_assert(offsetof(sparc32_rt_sigframe_t, stack.ss_sp) == 0x144, "frame ss_sp at 0x144");

/*
 * ucontext/sigcontext/mcontext views (L0b-owned translator-side views, NOT
 * kernel ABI): 32-bit SPARC Linux carries no packed ucontext in the kernel
 * frame — do_rt_sigreturn consumes regs, mask, and stack directly from
 * rt_signal_frame32. These views bind Phase 4 code to exactly those
 * frame-carried pieces; their packing is internal to the translator.
 */
typedef sparc32_pt_regs_t sparc32_mcontext_t; /* machine context == pt_regs */

typedef struct {
    sparc32_pt_regs_t regs;  /* restorable register state */
    uint32_t          mask[2]; /* restorable blocked mask */
} sparc32_sigcontext_t;

typedef struct {
    uint32_t             uc_flags;
    uint32_t             uc_link;   /* guest ptr to outer ucontext or 0 */
    sparc32_stack_t      uc_stack;  /* sigaltstack */
    sparc32_sigcontext_t uc_mcontext;
    uint32_t             uc_sigmask[2];
} sparc32_ucontext_t;

_Static_assert(sizeof(sparc32_mcontext_t) == 80, "mcontext == pt_regs, 80 bytes");
_Static_assert(sizeof(sparc32_sigcontext_t) == 88, "sigcontext must be 88 bytes");
_Static_assert(offsetof(sparc32_sigcontext_t, regs) == 0, "sc.regs at 0");
_Static_assert(offsetof(sparc32_sigcontext_t, mask) == 80, "sc.mask at 80");
_Static_assert(offsetof(sparc32_ucontext_t, uc_flags) == 0, "uc_flags at 0");
_Static_assert(offsetof(sparc32_ucontext_t, uc_link) == 4, "uc_link at 4");
_Static_assert(offsetof(sparc32_ucontext_t, uc_stack) == 8, "uc_stack at 8");
_Static_assert(offsetof(sparc32_ucontext_t, uc_mcontext) == 20, "uc_mcontext at 20");
_Static_assert(offsetof(sparc32_ucontext_t, uc_sigmask) == 108, "uc_sigmask at 108");
_Static_assert(sizeof(sparc32_ucontext_t) == 116, "ucontext must be 116 bytes");

/* ---- struct stat (64 B, uapi asm/stat.h, 32-bit sparc).
 * The 16-bit uid/gid/rdev pack tightly after st_nlink (no padding). ------- */
typedef struct {
    uint16_t st_dev;          /* 0x00 */
    uint32_t st_ino;          /* 0x04 */
    uint32_t st_mode;         /* 0x08 */
    int16_t  st_nlink;        /* 0x0c */
    uint16_t st_uid;          /* 0x0e */
    uint16_t st_gid;          /* 0x10 */
    uint16_t st_rdev;         /* 0x12 */
    int32_t  st_size;         /* 0x14 */
    int32_t  st_atime;        /* 0x18 */
    uint32_t st_atime_nsec;   /* 0x1c */
    int32_t  st_mtime;        /* 0x20 */
    uint32_t st_mtime_nsec;   /* 0x24 */
    int32_t  st_ctime;        /* 0x28 */
    uint32_t st_ctime_nsec;   /* 0x2c */
    int32_t  st_blksize;      /* 0x30 */
    int32_t  st_blocks;       /* 0x34 */
    uint32_t __unused4[2];    /* 0x38 */
} sparc32_stat_t;

_Static_assert(sizeof(sparc32_stat_t) == 64, "stat must be 64 bytes");
_Static_assert(offsetof(sparc32_stat_t, st_dev) == 0x00, "st_dev at 0");
_Static_assert(offsetof(sparc32_stat_t, st_ino) == 0x04, "st_ino at 4");
_Static_assert(offsetof(sparc32_stat_t, st_mode) == 0x08, "st_mode at 8");
_Static_assert(offsetof(sparc32_stat_t, st_nlink) == 0x0c, "st_nlink at 12");
_Static_assert(offsetof(sparc32_stat_t, st_uid) == 0x0e, "st_uid at 14");
_Static_assert(offsetof(sparc32_stat_t, st_gid) == 0x10, "st_gid at 16");
_Static_assert(offsetof(sparc32_stat_t, st_rdev) == 0x12, "st_rdev at 18");
_Static_assert(offsetof(sparc32_stat_t, st_size) == 0x14, "st_size at 20");
_Static_assert(offsetof(sparc32_stat_t, st_atime) == 0x18, "st_atime at 24");
_Static_assert(offsetof(sparc32_stat_t, st_atime_nsec) == 0x1c, "atime_nsec at 28");
_Static_assert(offsetof(sparc32_stat_t, st_mtime) == 0x20, "st_mtime at 32");
_Static_assert(offsetof(sparc32_stat_t, st_mtime_nsec) == 0x24, "mtime_nsec at 36");
_Static_assert(offsetof(sparc32_stat_t, st_ctime) == 0x28, "st_ctime at 40");
_Static_assert(offsetof(sparc32_stat_t, st_ctime_nsec) == 0x2c, "ctime_nsec at 44");
_Static_assert(offsetof(sparc32_stat_t, st_blksize) == 0x30, "st_blksize at 48");
_Static_assert(offsetof(sparc32_stat_t, st_blocks) == 0x34, "st_blocks at 52");
_Static_assert(offsetof(sparc32_stat_t, __unused4) == 0x38, "__unused4 at 56");

/* ---- struct stat64 (104 B, uapi asm/stat.h, 32-bit sparc).
 * Note the quirk: st_blocks stays 32-bit on 32-bit sparc. ------------------ */
typedef struct {
    uint64_t st_dev;          /* 0x00 */
    uint64_t st_ino;          /* 0x08 */
    uint32_t st_mode;         /* 0x10 */
    uint32_t st_nlink;        /* 0x14 */
    uint32_t st_uid;          /* 0x18 */
    uint32_t st_gid;          /* 0x1c */
    uint64_t st_rdev;         /* 0x20 */
    uint8_t  __pad3[8];       /* 0x28 */
    int64_t  st_size;         /* 0x30 */
    uint32_t st_blksize;      /* 0x38 */
    uint8_t  __pad4[8];       /* 0x3c */
    uint32_t st_blocks;       /* 0x44 32-bit by kernel definition */
    uint32_t st_atime;        /* 0x48 */
    uint32_t st_atime_nsec;   /* 0x4c */
    uint32_t st_mtime;        /* 0x50 */
    uint32_t st_mtime_nsec;   /* 0x54 */
    uint32_t st_ctime;        /* 0x58 */
    uint32_t st_ctime_nsec;   /* 0x5c */
    uint32_t __unused4;       /* 0x60 */
    uint32_t __unused5;       /* 0x64 */
} sparc32_stat64_t;

_Static_assert(sizeof(sparc32_stat64_t) == 104, "stat64 must be 104 bytes");
_Static_assert(offsetof(sparc32_stat64_t, st_dev) == 0x00, "st_dev at 0");
_Static_assert(offsetof(sparc32_stat64_t, st_ino) == 0x08, "st_ino at 8");
_Static_assert(offsetof(sparc32_stat64_t, st_mode) == 0x10, "st_mode at 16");
_Static_assert(offsetof(sparc32_stat64_t, st_nlink) == 0x14, "st_nlink at 20");
_Static_assert(offsetof(sparc32_stat64_t, st_uid) == 0x18, "st_uid at 24");
_Static_assert(offsetof(sparc32_stat64_t, st_gid) == 0x1c, "st_gid at 28");
_Static_assert(offsetof(sparc32_stat64_t, st_rdev) == 0x20, "st_rdev at 32");
_Static_assert(offsetof(sparc32_stat64_t, __pad3) == 0x28, "__pad3 at 40");
_Static_assert(offsetof(sparc32_stat64_t, st_size) == 0x30, "st_size at 48");
_Static_assert(offsetof(sparc32_stat64_t, st_blksize) == 0x38, "st_blksize at 56");
_Static_assert(offsetof(sparc32_stat64_t, __pad4) == 0x3c, "__pad4 at 60");
_Static_assert(offsetof(sparc32_stat64_t, st_blocks) == 0x44, "st_blocks at 68");
_Static_assert(offsetof(sparc32_stat64_t, st_atime) == 0x48, "st_atime at 72");
_Static_assert(offsetof(sparc32_stat64_t, st_atime_nsec) == 0x4c, "atime_nsec at 76");
_Static_assert(offsetof(sparc32_stat64_t, st_mtime) == 0x50, "st_mtime at 80");
_Static_assert(offsetof(sparc32_stat64_t, st_mtime_nsec) == 0x54, "mtime_nsec at 84");
_Static_assert(offsetof(sparc32_stat64_t, st_ctime) == 0x58, "st_ctime at 88");
_Static_assert(offsetof(sparc32_stat64_t, st_ctime_nsec) == 0x5c, "ctime_nsec at 92");
_Static_assert(offsetof(sparc32_stat64_t, __unused4) == 0x60, "__unused4 at 96");
_Static_assert(offsetof(sparc32_stat64_t, __unused5) == 0x64, "__unused5 at 100");

#endif /* SPARC32RT_OS_SIGFRAME_SPARC32RT_H */
