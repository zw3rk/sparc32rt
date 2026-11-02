/*
 * src/os/syscalls_sig.c — Signal disposition, sigaltstack, and sigreturn
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sparc32rt.h"
#include "interp/interp_priv.h"
#include "os/l2a_access.h"
#include "os/sigframe_sparc32rt.h"
#include "os/threads.h"

#define SPARC_SA_ONSTACK SPARC32_SA_ONSTACK
#define SPARC_SA_RESTART SPARC32_SA_RESTART
#define SPARC_SA_NODEFER SPARC32_SA_NODEFER
#define SPARC_SA_SIGINFO SPARC32_SA_SIGINFO
#define SPARC_SS_ONSTACK SPARC32_SS_ONSTACK
#define SPARC_SS_DISABLE SPARC32_SS_DISABLE
#define SPARC_MINSIGSTKSZ SPARC32_MINSIGSTKSZ

static int sig_range_ok_prot(uint32_t va, uint32_t len, uint32_t req_prot)
{
    return l2a_range_ok_prot(va, len, req_prot);
}

static int sig_ld_be32(sparc32_ctx_t *ctx, uint32_t va, uint32_t *out)
{
    const uint8_t *p;
    if (sig_range_ok_prot(va, 4U, 1U) != 0) {
        return -EFAULT;
    }
    p = (const uint8_t *)sparc32_guest_ptr(ctx, va);
    *out = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    return 0;
}

static int sig_st_be32(sparc32_ctx_t *ctx, uint32_t va, uint32_t v)
{
    uint8_t b[4];
    put_be32(b, v);
    return l2a_store(ctx, va, b, sizeof(b));
}

static struct {
    uint32_t handler;
    uint32_t restorer;
    uint32_t flags;
    uint64_t sa_mask;
    int installed;
} sigact[65];

static struct {
    uint32_t sp;
    uint32_t size;
    int enabled;
    int onstack;
} sigalt = { 0U, 0U, 0, 0 };

int sparc32_signal_get(int sig, uint32_t *handler_va, uint32_t *restorer_va)
{
    if (sig < 1 || sig > 64 || !sigact[sig].installed) {
        return -1;
    }
    *handler_va = sigact[sig].handler;
    *restorer_va = sigact[sig].restorer;
    return 0;
}

int sparc32_signal_get_full(int sig, uint32_t *handler_va,
    uint32_t *restorer_va, uint32_t *flags)
{
    if (sig < 1 || sig > 64 || !sigact[sig].installed) {
        return -1;
    }
    *handler_va = sigact[sig].handler;
    *restorer_va = sigact[sig].restorer;
    *flags = sigact[sig].flags;
    return 0;
}

int sparc32_signal_get_action(int sig, uint32_t *handler_va,
    uint32_t *restorer_va, uint32_t *flags, uint64_t *sa_mask)
{
    if (sig < 1 || sig > 64 || !sigact[sig].installed) {
        return -1;
    }
    *handler_va = sigact[sig].handler;
    *restorer_va = sigact[sig].restorer;
    *flags = sigact[sig].flags;
    if (sa_mask != NULL) {
        *sa_mask = sigact[sig].sa_mask;
    }
    return 0;
}

int sparc32_sigaltstack_state(uint32_t *sp, uint32_t *size, int *onstack)
{
    if (sp == NULL || size == NULL || onstack == NULL) {
        return -1;
    }
    if (!sigalt.enabled) {
        return -1;
    }
    *sp = sigalt.sp;
    *size = sigalt.size;
    *onstack = sigalt.onstack;
    return 0;
}

void sparc32_sigaltstack_set_onstack(int onstack)
{
    sigalt.onstack = (onstack != 0) ? 1 : 0;
}

void sparc32_signal_reset_all(void)
{
    int sig;
    for (sig = 1; sig <= 64; sig++) {
        sigact[sig].installed = 0;
        sigact[sig].handler = 0U;
        sigact[sig].restorer = 0U;
        sigact[sig].flags = 0U;
        sigact[sig].sa_mask = 0ULL;
    }
    sigalt.sp = 0U;
    sigalt.size = 0U;
    sigalt.enabled = 0;
    sigalt.onstack = 0;
}

long sparc32_sys_rt_sigaction(sparc32_ctx_t *ctx, uint32_t sig, uint32_t act_va,
    uint32_t oact_va, uint32_t restorer, uint32_t sigsetsize)
{
    const uint32_t valid_flags = SPARC_SA_ONSTACK | SPARC_SA_RESTART |
        SPARC_SA_NODEFER | SPARC_SA_SIGINFO | 0x0000033CU | 0x40000000U;
    if (sig < 1U || sig > 64U || sigsetsize != 8U || sig == 9U || sig == 17U) {
        return -EINVAL;
    }
    if (oact_va != 0U && sig_range_ok_prot(oact_va, 20U, 2U) != 0) {
        return -EFAULT;
    }
    if (act_va != 0U) {
        uint32_t handler;
        uint32_t w4 = 0U;
        uint32_t w8 = 0U;
        uint32_t w12 = 0U;
        uint32_t w16 = 0U;
        uint32_t flags;
        uint64_t sa_mask;
        if (sig_range_ok_prot(act_va, 20U, 1U) != 0 ||
            sig_ld_be32(ctx, act_va, &handler) != 0 ||
            sig_ld_be32(ctx, act_va + 4U, &w4) != 0 ||
            sig_ld_be32(ctx, act_va + 8U, &w8) != 0 ||
            sig_ld_be32(ctx, act_va + 12U, &w12) != 0 ||
            sig_ld_be32(ctx, act_va + 16U, &w16) != 0) {
            return -EFAULT;
        }
        if (w4 != 0U) {
            flags = w4;
            sa_mask = ((uint64_t)w12 << 32U) | (uint64_t)w16;
            if (restorer == 0U && w8 != 0U) {
                restorer = w8;
            }
        } else if (w12 != 0U && (w12 & ~valid_flags) == 0U && w16 == 0U) {
            flags = w12;
            sa_mask = (uint64_t)w8;
        } else {
            flags = 0U;
            sa_mask = ((uint64_t)w12 << 32U) | (uint64_t)w16;
            if (restorer == 0U && w8 != 0U) {
                restorer = w8;
            }
        }
        if ((flags & ~valid_flags) != 0U) {
            return -EINVAL;
        }
        if (oact_va != 0U) {
            uint32_t oh = sigact[sig].installed ? sigact[sig].handler : 0U;
            uint32_t of = sigact[sig].installed ? sigact[sig].flags : 0U;
            uint32_t or_va = sigact[sig].installed ? sigact[sig].restorer : 0U;
            uint64_t om = sigact[sig].installed ? sigact[sig].sa_mask : 0ULL;
            (void)sig_st_be32(ctx, oact_va, oh);
            (void)sig_st_be32(ctx, oact_va + 4U, of);
            (void)sig_st_be32(ctx, oact_va + 8U, or_va);
            (void)sig_st_be32(ctx, oact_va + 12U, (uint32_t)(om >> 32U));
            (void)sig_st_be32(ctx, oact_va + 16U, (uint32_t)om);
        }
        if (handler == 0U || handler == 1U) {
            sigact[sig].installed = 0;
            sigact[sig].handler = handler;
            sigact[sig].restorer = 0U;
            sigact[sig].flags = 0U;
            sigact[sig].sa_mask = 0ULL;
        } else {
            sigact[sig].handler = handler;
            sigact[sig].restorer = restorer;
            sigact[sig].flags = flags;
            sigact[sig].sa_mask = sa_mask;
            sigact[sig].installed = 1;
        }
        return 0;
    }
    if (oact_va != 0U) {
        uint32_t oh = sigact[sig].installed ? sigact[sig].handler : 0U;
        uint32_t of = sigact[sig].installed ? sigact[sig].flags : 0U;
        uint32_t or_va = sigact[sig].installed ? sigact[sig].restorer : 0U;
        uint64_t om = sigact[sig].installed ? sigact[sig].sa_mask : 0ULL;
        (void)sig_st_be32(ctx, oact_va, oh);
        (void)sig_st_be32(ctx, oact_va + 4U, of);
        (void)sig_st_be32(ctx, oact_va + 8U, or_va);
        (void)sig_st_be32(ctx, oact_va + 12U, (uint32_t)(om >> 32U));
        (void)sig_st_be32(ctx, oact_va + 16U, (uint32_t)om);
    }
    return 0;
}

long sparc32_sys_sigaltstack(sparc32_ctx_t *ctx, uint32_t uss_va,
    uint32_t uoss_va)
{
    if (uoss_va != 0U) {
        uint32_t cur_flags = !sigalt.enabled ? SPARC_SS_DISABLE
            : (sigalt.onstack ? SPARC_SS_ONSTACK : 0U);
        if (sig_range_ok_prot(uoss_va, 12U, 2U) != 0 ||
            sig_st_be32(ctx, uoss_va, sigalt.sp) != 0 ||
            sig_st_be32(ctx, uoss_va + 4U, cur_flags) != 0 ||
            sig_st_be32(ctx, uoss_va + 8U, sigalt.size) != 0) {
            return -EFAULT;
        }
    }
    if (uss_va != 0U) {
        uint32_t sp;
        uint32_t flags;
        uint32_t size;
        if (sig_range_ok_prot(uss_va, 12U, 1U) != 0 ||
            sig_ld_be32(ctx, uss_va, &sp) != 0 ||
            sig_ld_be32(ctx, uss_va + 4U, &flags) != 0 ||
            sig_ld_be32(ctx, uss_va + 8U, &size) != 0) {
            return -EFAULT;
        }
        if (flags == SPARC_SS_DISABLE) {
            sigalt.enabled = 0;
            sigalt.onstack = 0;
            sigalt.sp = 0U;
            sigalt.size = 0U;
            return 0;
        }
        if (flags != 0U && flags != SPARC_SS_ONSTACK) {
            return -EINVAL;
        }
        if (sigalt.onstack) {
            return -EPERM;
        }
        if (size < SPARC_MINSIGSTKSZ) {
            return -ENOMEM;
        }
        if (sig_range_ok_prot(sp, size, 2U) != 0) {
            return -EFAULT;
        }
        sigalt.sp = sp;
        sigalt.size = size;
        sigalt.enabled = 1;
    }
    return 0;
}

/* Shared frame validation + register/mask/FPU restoration for sigreturn(216)
 * and rt_sigreturn(101) (S32-9, S32-10, S32-14). */
static long sigreturn_restore_common(sparc32_ctx_t *ctx, uint32_t base,
    uint32_t pc, uint32_t npc)
{
    uint32_t u[16];
    uint32_t fpu_regs[32];
    uint32_t fpu_fsr = 0U;
    uint32_t y;
    uint32_t psr;
    uint32_t fs;
    uint32_t rp;
    uint32_t mask_hi;
    uint32_t mask_lo;
    int i;
    if ((pc & 3U) != 0U || (npc & 3U) != 0U ||
        sig_ld_be32(ctx, base + 0x130U, &mask_hi) != 0 ||
        sig_ld_be32(ctx, base + 0x134U, &mask_lo) != 0 ||
        sig_ld_be32(ctx, base + 0x138U, &fs) != 0 ||
        sig_ld_be32(ctx, base + 0x154U, &rp) != 0 || rp != 0U ||
        sig_ld_be32(ctx, base + 0xE0U, &psr) != 0 ||
        sig_ld_be32(ctx, base + 0xECU, &y) != 0) {
        return -EFAULT;
    }
    if (fs != 0U) {
        if ((fs & 3U) != 0U ||
            sig_range_ok_prot(fs, SPARC32_SIGFPU_SIZE, 1U) != 0) {
            return -EFAULT;
        }
        for (i = 0; i < 32; i++) {
            if (sig_ld_be32(ctx, fs + (uint32_t)i * 4U, &fpu_regs[i]) != 0) {
                return -EFAULT;
            }
        }
        if (sig_ld_be32(ctx, fs + 128U, &fpu_fsr) != 0) {
            return -EFAULT;
        }
    }
    for (i = 0; i < 16; i++) {
        if (sig_ld_be32(ctx, base + 0xF0U + (uint32_t)i * 4U, &u[i]) != 0) {
            return -EFAULT;
        }
    }
    ctx->psr = psr;
    ctx->y = y;
    for (i = 1; i < 8; i++) {
        ctx->r[(uint32_t)i] = u[i];
    }
    for (i = 8; i < 16; i++) {
        ctx->r[SPARC32_O0 + (uint32_t)(i - 8)] = u[i];
    }
    for (i = 0; i < 8; i++) {
        (void)sig_ld_be32(ctx, base + (uint32_t)i * 4U,
            &ctx->r[SPARC32_L0 + (uint32_t)i]);
        (void)sig_ld_be32(ctx, base + 32U + (uint32_t)i * 4U,
            &ctx->r[SPARC32_I0 + (uint32_t)i]);
    }
    if (fs != 0U) {
        for (i = 0; i < 32; i++) {
            ctx->f[(uint32_t)i] = fpu_regs[i];
        }
        ctx->fsr = fpu_fsr;
    }
    ctx->r[0] = 0U;
    ctx->pc = pc;
    ctx->npc = npc;
    sparc32_l2a_set_blocked_mask(ctx,
        ((uint64_t)mask_hi << 32U) | (uint64_t)mask_lo);
    sparc32_sigaltstack_set_onstack(0);
    return 0;
}

long sparc32_sys_sigreturn(sparc32_ctx_t *ctx)
{
    uint32_t base = ctx->r[SPARC32_SP];
    uint32_t pc;
    uint32_t npc;
    uint32_t fp;
    if ((base & 15U) != 0U ||
        sig_range_ok_prot(base, SPARC32_RT_SIGFRAME_SIZE, 1U) != 0) {
        return -EFAULT;
    }
    if (sig_ld_be32(ctx, base + 0xF0U + 14U * 4U, &fp) != 0 ||
        (fp & 7U) != 0U ||
        sig_ld_be32(ctx, base + 100U, &pc) != 0 ||
        sig_ld_be32(ctx, base + 104U, &npc) != 0) {
        return -EFAULT;
    }
    return sigreturn_restore_common(ctx, base, pc, npc);
}

long sparc32_sys_rt_sigreturn(sparc32_ctx_t *ctx)
{
    uint32_t base = ctx->r[SPARC32_SP];
    uint32_t pc;
    uint32_t npc;
    if ((base & 15U) != 0U ||
        sig_range_ok_prot(base, SPARC32_RT_SIGFRAME_SIZE, 1U) != 0) {
        return -EFAULT;
    }
    if (sig_ld_be32(ctx, base + 0xE4U, &pc) != 0 ||
        sig_ld_be32(ctx, base + 0xE8U, &npc) != 0) {
        return -EFAULT;
    }
    return sigreturn_restore_common(ctx, base, pc, npc);
}
