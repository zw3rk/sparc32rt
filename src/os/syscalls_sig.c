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
#include "os/threads.h"

#define SPARC_SA_ONSTACK SPARC32_SA_ONSTACK
#define SPARC_SA_RESTART SPARC32_SA_RESTART
#define SPARC_SA_SIGINFO SPARC32_SA_SIGINFO
#define SPARC_SS_ONSTACK SPARC32_SS_ONSTACK
#define SPARC_SS_DISABLE SPARC32_SS_DISABLE
#define SPARC_MINSIGSTKSZ SPARC32_MINSIGSTKSZ

static int sig_range_ok(uint32_t va, uint32_t len)
{
    if (len == 0U) {
        return 0;
    }
    if ((uint64_t)va + (uint64_t)len > 0x100000000ULL) {
        return -EFAULT;
    }
    if (va < SPARC32_LOW_GUARD_SIZE) {
        return -EFAULT;
    }
    return 0;
}

static int sig_ld_be32(sparc32_ctx_t *ctx, uint32_t va, uint32_t *out)
{
    const uint8_t *p;
    if (sig_range_ok(va, 4U) != 0) {
        return -EFAULT;
    }
    p = (const uint8_t *)sparc32_guest_ptr(ctx, va);
    *out = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    return 0;
}

static int sig_st_be32(sparc32_ctx_t *ctx, uint32_t va, uint32_t v)
{
    uint8_t *p;
    if (sig_range_ok(va, 4U) != 0) {
        return -EFAULT;
    }
    p = (uint8_t *)sparc32_guest_ptr(ctx, va);
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
    return 0;
}

static struct {
    uint32_t handler;
    uint32_t restorer;
    uint32_t flags;
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

#define SPARC32_FPU_SAVE_DEPTH 16U
static _Thread_local struct {
    const sparc32_ctx_t *ctx;
    uint32_t f[32];
    uint32_t fsr;
    int used;
} fpu_save_stack[SPARC32_FPU_SAVE_DEPTH];
static _Thread_local unsigned fpu_save_next = 0U;

void sparc32_fpu_save_push(const sparc32_ctx_t *ctx)
{
    unsigned i;
    if (ctx == NULL) {
        return;
    }
    fpu_save_stack[fpu_save_next].ctx = ctx;
    for (i = 0U; i < 32U; i++) {
        fpu_save_stack[fpu_save_next].f[i] = ctx->f[i];
    }
    fpu_save_stack[fpu_save_next].fsr = ctx->fsr;
    fpu_save_stack[fpu_save_next].used = 1;
    fpu_save_next = (fpu_save_next + 1U) % SPARC32_FPU_SAVE_DEPTH;
}

int sparc32_fpu_save_pop(sparc32_ctx_t *ctx)
{
    unsigned n;
    unsigned i;
    if (ctx == NULL) {
        return -1;
    }
    for (n = 0U; n < SPARC32_FPU_SAVE_DEPTH; n++) {
        unsigned idx = (fpu_save_next + SPARC32_FPU_SAVE_DEPTH - 1U - n) %
            SPARC32_FPU_SAVE_DEPTH;
        if (fpu_save_stack[idx].used &&
            fpu_save_stack[idx].ctx == ctx) {
            for (i = 0U; i < 32U; i++) {
                ctx->f[i] = fpu_save_stack[idx].f[i];
            }
            ctx->fsr = fpu_save_stack[idx].fsr;
            fpu_save_stack[idx].used = 0;
            return 0;
        }
    }
    return -1;
}

void sparc32_signal_reset_all(void)
{
    int sig;
    unsigned i;
    for (sig = 1; sig <= 64; sig++) {
        sigact[sig].installed = 0;
        sigact[sig].handler = 0U;
        sigact[sig].restorer = 0U;
        sigact[sig].flags = 0U;
    }
    sigalt.sp = 0U;
    sigalt.size = 0U;
    sigalt.enabled = 0;
    sigalt.onstack = 0;
    for (i = 0U; i < SPARC32_FPU_SAVE_DEPTH; i++) {
        fpu_save_stack[i].used = 0;
    }
}

long sparc32_sys_rt_sigaction(sparc32_ctx_t *ctx, uint32_t sig, uint32_t act_va,
    uint32_t oact_va, uint32_t restorer, uint32_t sigsetsize)
{
    uint32_t handler;
    uint32_t flags4 = 0U;
    uint32_t flags12 = 0U;
    uint32_t flags;
    (void)oact_va;
    if (sig < 1U || sig > 64U || sigsetsize != 8U) {
        return -EINVAL;
    }
    if (sig_range_ok(act_va, 20U) != 0 ||
        sig_ld_be32(ctx, act_va, &handler) != 0 ||
        sig_ld_be32(ctx, act_va + 4U, &flags4) != 0 ||
        sig_ld_be32(ctx, act_va + 12U, &flags12) != 0) {
        return -EFAULT;
    }
    flags = (flags4 != 0U) ? flags4 : flags12;
    if ((flags & ~(SPARC_SA_ONSTACK | SPARC_SA_RESTART |
            SPARC_SA_SIGINFO | 0x0000033CU)) != 0U) {
        return -EINVAL;
    }
    sigact[sig].handler = handler;
    sigact[sig].restorer = restorer;
    sigact[sig].flags = flags;
    sigact[sig].installed = 1;
    return 0;
}

long sparc32_sys_sigaltstack(sparc32_ctx_t *ctx, uint32_t uss_va,
    uint32_t uoss_va)
{
    if (uoss_va != 0U) {
        uint32_t cur_flags = !sigalt.enabled ? SPARC_SS_DISABLE
            : (sigalt.onstack ? SPARC_SS_ONSTACK : 0U);
        if (sig_range_ok(uoss_va, 12U) != 0 ||
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
        if (sig_range_ok(uss_va, 12U) != 0 ||
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
        if (sig_range_ok(sp, size) != 0) {
            return -EFAULT;
        }
        sigalt.sp = sp;
        sigalt.size = size;
        sigalt.enabled = 1;
    }
    return 0;
}

long sparc32_sys_sigreturn(sparc32_ctx_t *ctx)
{
    uint32_t base = ctx->r[SPARC32_SP];
    uint32_t u[16];
    uint32_t pc;
    uint32_t npc;
    uint32_t y;
    uint32_t psr;
    uint32_t fp;
    uint32_t rp;
    uint32_t fs;
    int i;
    if ((base & 15U) != 0U || sig_range_ok(base, 344U) != 0) {
        return -EFAULT;
    }
    if (sig_ld_be32(ctx, base + 0xF0U + 14U * 4U, &fp) != 0 || (fp & 7U) != 0U ||
        sig_ld_be32(ctx, base + 100U, &pc) != 0 ||
        sig_ld_be32(ctx, base + 104U, &npc) != 0 ||
        (pc & 3U) != 0U || (npc & 3U) != 0U ||
        sig_ld_be32(ctx, base + 0x138U, &fs) != 0 || fs != 0U ||
        sig_ld_be32(ctx, base + 0x154U, &rp) != 0 || rp != 0U ||
        sig_ld_be32(ctx, base + 0xE0U, &psr) != 0 ||
        sig_ld_be32(ctx, base + 0xECU, &y) != 0) {
        return -EFAULT;
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
    ctx->r[0] = 0U;
    ctx->pc = pc;
    ctx->npc = npc;
    sparc32_sigaltstack_set_onstack(0);
    (void)sparc32_fpu_save_pop(ctx);
    return 0;
}

long sparc32_sys_rt_sigreturn(sparc32_ctx_t *ctx)
{
    uint32_t base = ctx->r[SPARC32_SP];
    uint32_t u[16];
    uint32_t pc;
    uint32_t npc;
    uint32_t y;
    uint32_t psr;
    uint32_t fs;
    uint32_t rp;
    int i;
    if ((base & 15U) != 0U || sig_range_ok(base, 344U) != 0) {
        return -EFAULT;
    }
    if (sig_ld_be32(ctx, base + 0x138U, &fs) != 0 || fs != 0U ||
        sig_ld_be32(ctx, base + 0x154U, &rp) != 0 || rp != 0U ||
        sig_ld_be32(ctx, base + 0xE0U, &psr) != 0 ||
        sig_ld_be32(ctx, base + 0xE4U, &pc) != 0 ||
        sig_ld_be32(ctx, base + 0xE8U, &npc) != 0 ||
        (pc & 3U) != 0U || (npc & 3U) != 0U ||
        sig_ld_be32(ctx, base + 0xECU, &y) != 0) {
        return -EFAULT;
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
    ctx->r[0] = 0U;
    ctx->pc = pc;
    ctx->npc = npc;
    sparc32_sigaltstack_set_onstack(0);
    (void)sparc32_fpu_save_pop(ctx);
    return 0;
}
