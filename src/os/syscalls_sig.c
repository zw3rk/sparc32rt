/*
 * src/os/syscalls_sig.c — Signal disposition, sigaltstack, and sigreturn
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
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
    uint8_t p[4];
    int rc = l2a_load(ctx, va, p, sizeof(p));
    if (rc != 0) {
        return rc;
    }
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

/* Disposition kinds (S32-R3-6): default, ignored, and caught are three
 * distinct states. SIG_DFL and SIG_IGN no longer collapse into
 * "not installed": ignored signals are discarded at the safe point and
 * reported back by oldact, never re-raised as fatal defaults. A plain
 * pthread mutex serializes writers and snapshot readers (S32-R3-8);
 * the async host handler never consults this table (it only sets the
 * stable process-pending word), so no async-signal-safe access is
 * needed here. */
#define SIG_DISP_DFL 0
#define SIG_DISP_IGN 1
#define SIG_DISP_CAUGHT 2

static struct {
    uint32_t handler;
    uint32_t restorer;
    uint32_t flags;
    uint64_t sa_mask;
    int kind;
} sigact[65];

static pthread_mutex_t sigact_lock = PTHREAD_MUTEX_INITIALIZER;

int sparc32_signal_disposition(int sig)
{
    int kind;
    if (sig < 1 || sig > 64) {
        return SIG_DISP_DFL;
    }
    pthread_mutex_lock(&sigact_lock);
    kind = sigact[sig].kind;
    pthread_mutex_unlock(&sigact_lock);
    return kind;
}

/* The host disposition mirrors the guest disposition so the kernel
 * applies default actions itself (fatal signals terminate without any
 * re-raise dance) and ignored signals never reach the handler. Only
 * caught signals keep the translator's async handler installed. The
 * sync-fault pair (SIGBUS/SIGSEGV) stays on the emulated EXIT_FAULT
 * path and never takes a host handler. */
static void sig_host_sync(int sig, int kind)
{
#if defined(__linux__) || defined(__APPLE__)
    struct sigaction sa;
    if (sig < 1 || sig > 64 || sig == 9 || sig == 17) {
        return;
    }
    if (sig == 7 || sig == 11) {
        return;
    }
    memset(&sa, 0, sizeof(sa));
    if (kind == SIG_DISP_CAUGHT) {
        sa.sa_handler = sparc32_thr_host_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        (void)sigaction(sig, &sa, NULL);
    } else if (kind == SIG_DISP_IGN) {
        sa.sa_handler = SIG_IGN;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        (void)sigaction(sig, &sa, NULL);
    } else {
        sa.sa_handler = SIG_DFL;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        (void)sigaction(sig, &sa, NULL);
    }
#else
    (void)sig;
    (void)kind;
#endif
}

int sparc32_signal_get(int sig, uint32_t *handler_va, uint32_t *restorer_va)
{
    int ok = -1;
    if (sig < 1 || sig > 64) {
        return -1;
    }
    pthread_mutex_lock(&sigact_lock);
    if (sigact[sig].kind == SIG_DISP_CAUGHT) {
        *handler_va = sigact[sig].handler;
        *restorer_va = sigact[sig].restorer;
        ok = 0;
    }
    pthread_mutex_unlock(&sigact_lock);
    return ok;
}

int sparc32_signal_get_full(int sig, uint32_t *handler_va,
    uint32_t *restorer_va, uint32_t *flags)
{
    int ok = -1;
    if (sig < 1 || sig > 64) {
        return -1;
    }
    pthread_mutex_lock(&sigact_lock);
    if (sigact[sig].kind == SIG_DISP_CAUGHT) {
        *handler_va = sigact[sig].handler;
        *restorer_va = sigact[sig].restorer;
        *flags = sigact[sig].flags;
        ok = 0;
    }
    pthread_mutex_unlock(&sigact_lock);
    return ok;
}

int sparc32_signal_get_action(int sig, uint32_t *handler_va,
    uint32_t *restorer_va, uint32_t *flags, uint64_t *sa_mask)
{
    int ok = -1;
    if (sig < 1 || sig > 64) {
        return -1;
    }
    pthread_mutex_lock(&sigact_lock);
    if (sigact[sig].kind == SIG_DISP_CAUGHT) {
        *handler_va = sigact[sig].handler;
        *restorer_va = sigact[sig].restorer;
        *flags = sigact[sig].flags;
        if (sa_mask != NULL) {
            *sa_mask = sigact[sig].sa_mask;
        }
        ok = 0;
    }
    pthread_mutex_unlock(&sigact_lock);
    return ok;
}

/* Per-thread alternate stack (S32-R3-5): address, size, and the
 * enabled/onstack bits live in the owning guest context. Bit 0 of
 * altstack_flags is ENABLED, bit 1 is ONSTACK (a handler runs on it). */
#define ALT_ENABLED 1U
#define ALT_ONSTACK 2U

int sparc32_sigaltstack_state_ctx(const sparc32_ctx_t *ctx, uint32_t *sp,
    uint32_t *size, int *onstack)
{
    if (ctx == NULL || sp == NULL || size == NULL || onstack == NULL) {
        return -1;
    }
    if ((ctx->altstack_flags & ALT_ENABLED) == 0U) {
        return -1;
    }
    *sp = ctx->altstack_sp;
    *size = ctx->altstack_size;
    *onstack = ((ctx->altstack_flags & ALT_ONSTACK) != 0U) ? 1 : 0;
    return 0;
}

int sparc32_sigaltstack_state(uint32_t *sp, uint32_t *size, int *onstack)
{
    (void)sp;
    (void)size;
    (void)onstack;
    return -1;
}

void sparc32_sigaltstack_set_onstack_ctx(sparc32_ctx_t *ctx, int onstack)
{
    uint32_t f;
    if (ctx == NULL) {
        return;
    }
    f = ctx->altstack_flags & ALT_ENABLED;
    if (onstack != 0) {
        f |= ALT_ONSTACK;
    }
    ctx->altstack_flags = f;
}

void sparc32_sigaltstack_set_onstack(int onstack)
{
    (void)onstack;
}

/* execve keeps ignored dispositions (S32-R3-4 companion rule): only
 * caught signals return to default, with the host disposition synced
 * back so the new image starts from real SIG_DFL. */
void sparc32_signal_reset_for_exec(void)
{
    int sig;
    pthread_mutex_lock(&sigact_lock);
    for (sig = 1; sig <= 64; sig++) {
        if (sigact[sig].kind == SIG_DISP_CAUGHT) {
            sigact[sig].kind = SIG_DISP_DFL;
            sigact[sig].handler = 0U;
            sigact[sig].restorer = 0U;
            sigact[sig].flags = 0U;
            sigact[sig].sa_mask = 0ULL;
        }
    }
    pthread_mutex_unlock(&sigact_lock);
    for (sig = 1; sig <= 64; sig++) {
        if (sparc32_signal_disposition(sig) == SIG_DISP_DFL) {
            sig_host_sync(sig, SIG_DISP_DFL);
        }
    }
}

void sparc32_signal_reset_all(void)
{
    int sig;
    pthread_mutex_lock(&sigact_lock);
    for (sig = 1; sig <= 64; sig++) {
        sigact[sig].kind = SIG_DISP_DFL;
        sigact[sig].handler = 0U;
        sigact[sig].restorer = 0U;
        sigact[sig].flags = 0U;
        sigact[sig].sa_mask = 0ULL;
    }
    pthread_mutex_unlock(&sigact_lock);
    for (sig = 1; sig <= 64; sig++) {
        sig_host_sync(sig, SIG_DISP_DFL);
    }
}

long sparc32_sys_rt_sigaction(sparc32_ctx_t *ctx, uint32_t sig, uint32_t act_va,
    uint32_t oact_va, uint32_t restorer, uint32_t sigsetsize)
{
    const uint32_t valid_flags = SPARC_SA_ONSTACK | SPARC_SA_RESTART |
        SPARC_SA_NODEFER | SPARC_SA_SIGINFO | 0x0000033CU | 0x40000000U;
    /* Snapshot the whole input action before writing any old-action
     * output (S32-R3 cross-RT aliasing rule): act and oact may be the
     * same guest address or overlap, so every input word is loaded
     * into locals first and no store runs until parsing is done. */
    uint32_t in_handler = 0U;
    uint32_t in_w4 = 0U;
    uint32_t in_w8 = 0U;
    uint32_t in_w12 = 0U;
    uint32_t in_w16 = 0U;
    bool have_act = false;
    if (sig < 1U || sig > 64U || sigsetsize != 8U || sig == 9U || sig == 17U) {
        return -EINVAL;
    }
    if (oact_va != 0U && sig_range_ok_prot(oact_va, 20U, 2U) != 0) {
        return -EFAULT;
    }
    if (act_va != 0U) {
        if (sig_range_ok_prot(act_va, 20U, 1U) != 0 ||
            sig_ld_be32(ctx, act_va, &in_handler) != 0 ||
            sig_ld_be32(ctx, act_va + 4U, &in_w4) != 0 ||
            sig_ld_be32(ctx, act_va + 8U, &in_w8) != 0 ||
            sig_ld_be32(ctx, act_va + 12U, &in_w12) != 0 ||
            sig_ld_be32(ctx, act_va + 16U, &in_w16) != 0) {
            return -EFAULT;
        }
        have_act = true;
    }
    if (have_act) {
        uint32_t flags;
        uint64_t sa_mask;
        uint32_t use_restorer = restorer;
        if (in_w4 != 0U) {
            flags = in_w4;
            sa_mask = ((uint64_t)in_w12 << 32U) | (uint64_t)in_w16;
            if (use_restorer == 0U && in_w8 != 0U) {
                use_restorer = in_w8;
            }
        } else if (in_w12 != 0U && (in_w12 & ~valid_flags) == 0U && in_w16 == 0U) {
            flags = in_w12;
            sa_mask = (uint64_t)in_w8;
        } else {
            flags = 0U;
            sa_mask = ((uint64_t)in_w12 << 32U) | (uint64_t)in_w16;
            if (use_restorer == 0U && in_w8 != 0U) {
                use_restorer = in_w8;
            }
        }
        if ((flags & ~valid_flags) != 0U) {
            return -EINVAL;
        }
        /* Publish the old disposition first: the snapshot above is
         * complete, so oact stores cannot clobber unread input. */
        if (oact_va != 0U) {
            uint32_t oh = 0U;
            uint32_t of = 0U;
            uint32_t or_va = 0U;
            uint64_t om = 0ULL;
            pthread_mutex_lock(&sigact_lock);
            if (sigact[sig].kind == SIG_DISP_CAUGHT) {
                oh = sigact[sig].handler;
                of = sigact[sig].flags;
                or_va = sigact[sig].restorer;
                om = sigact[sig].sa_mask;
            } else if (sigact[sig].kind == SIG_DISP_IGN) {
                oh = 1U;
            }
            pthread_mutex_unlock(&sigact_lock);
            (void)sig_st_be32(ctx, oact_va, oh);
            (void)sig_st_be32(ctx, oact_va + 4U, of);
            (void)sig_st_be32(ctx, oact_va + 8U, or_va);
            (void)sig_st_be32(ctx, oact_va + 12U, (uint32_t)(om >> 32U));
            (void)sig_st_be32(ctx, oact_va + 16U, (uint32_t)om);
        }
        if (in_handler == 0U || in_handler == 1U) {
            int kind = (in_handler == 1U) ? SIG_DISP_IGN : SIG_DISP_DFL;
            uint32_t h = in_handler;
            pthread_mutex_lock(&sigact_lock);
            sigact[sig].kind = kind;
            sigact[sig].handler = h;
            sigact[sig].restorer = 0U;
            sigact[sig].flags = 0U;
            sigact[sig].sa_mask = 0ULL;
            pthread_mutex_unlock(&sigact_lock);
            sig_host_sync((int)sig, kind);
            /* Ignored signals are discarded, never re-raised: drop any
             * queued thread and process bits for this signal now. */
            if (kind == SIG_DISP_IGN && ctx != NULL) {
                sparc32_thr_discard_signal(ctx, (int)sig);
            }
        } else {
            pthread_mutex_lock(&sigact_lock);
            sigact[sig].handler = in_handler;
            sigact[sig].restorer = use_restorer;
            sigact[sig].flags = flags;
            sigact[sig].sa_mask = sa_mask;
            sigact[sig].kind = SIG_DISP_CAUGHT;
            pthread_mutex_unlock(&sigact_lock);
            sig_host_sync((int)sig, SIG_DISP_CAUGHT);
        }
        return 0;
    }
    if (oact_va != 0U) {
        uint32_t oh = 0U;
        uint32_t of = 0U;
        uint32_t or_va = 0U;
        uint64_t om = 0ULL;
        pthread_mutex_lock(&sigact_lock);
        if (sigact[sig].kind == SIG_DISP_CAUGHT) {
            oh = sigact[sig].handler;
            of = sigact[sig].flags;
            or_va = sigact[sig].restorer;
            om = sigact[sig].sa_mask;
        } else if (sigact[sig].kind == SIG_DISP_IGN) {
            oh = 1U;
        }
        pthread_mutex_unlock(&sigact_lock);
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
    /* Snapshot the whole input stack descriptor before writing any
     * old-stack output: uss and uoss may alias or overlap. */
    bool have_uss = false;
    uint32_t in_sp = 0U;
    uint32_t in_flags = 0U;
    uint32_t in_size = 0U;
    if (ctx == NULL) {
        return -EFAULT;
    }
    if (uoss_va != 0U && sig_range_ok_prot(uoss_va, 12U, 2U) != 0) {
        return -EFAULT;
    }
    if (uss_va != 0U) {
        if (sig_range_ok_prot(uss_va, 12U, 1U) != 0 ||
            sig_ld_be32(ctx, uss_va, &in_sp) != 0 ||
            sig_ld_be32(ctx, uss_va + 4U, &in_flags) != 0 ||
            sig_ld_be32(ctx, uss_va + 8U, &in_size) != 0) {
            return -EFAULT;
        }
        have_uss = true;
    }
    if (uoss_va != 0U) {
        bool en = (ctx->altstack_flags & ALT_ENABLED) != 0U;
        bool on = (ctx->altstack_flags & ALT_ONSTACK) != 0U;
        uint32_t cur_flags = !en ? SPARC_SS_DISABLE
            : (on ? SPARC_SS_ONSTACK : 0U);
        if (sig_st_be32(ctx, uoss_va, en ? ctx->altstack_sp : 0U) != 0 ||
            sig_st_be32(ctx, uoss_va + 4U, cur_flags) != 0 ||
            sig_st_be32(ctx, uoss_va + 8U, en ? ctx->altstack_size : 0U) != 0) {
            return -EFAULT;
        }
    }
    if (have_uss) {
        if (in_flags == SPARC_SS_DISABLE) {
            ctx->altstack_flags = 0U;
            ctx->altstack_sp = 0U;
            ctx->altstack_size = 0U;
            return 0;
        }
        if (in_flags != 0U && in_flags != SPARC_SS_ONSTACK) {
            return -EINVAL;
        }
        if ((ctx->altstack_flags & ALT_ONSTACK) != 0U) {
            return -EPERM;
        }
        if (in_size < SPARC_MINSIGSTKSZ) {
            return -ENOMEM;
        }
        if (sig_range_ok_prot(in_sp, in_size, 2U) != 0) {
            return -EFAULT;
        }
        ctx->altstack_sp = in_sp;
        ctx->altstack_size = in_size;
        ctx->altstack_flags = ALT_ENABLED;
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
    ctx->sig_mask = sparc32_thr_mask_sanitize(
        ((uint64_t)mask_hi << 32U) | (uint64_t)mask_lo);
    sparc32_sigaltstack_set_onstack_ctx(ctx, 0);
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
