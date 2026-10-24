/*
 * src/os/syscalls_min.c — Phase-1 minimal SPARC32 Linux syscall layer
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L1c owns this file (Phase 1, SPEC section 2.2). Implements the
 * Phase-1 syscall subset against the frozen src/os/syscall_nr.h:
 * exit(1), exit_group(188), read(3), write(4), brk(17), mmap(71),
 * mmap2(56), munmap(73), mprotect(74), uname(189), set_tid_address(166).
 *
 * SPARC32 syscall convention (SPEC section 2.2, E04 oracle):
 *   number in %g1 (r[1]), args 1..6 in %o0..%o5 (r[8..13]).
 *   Success: PSR.icc.C = 0, %o0 = (uint32_t)ret.
 *   Error:   PSR.icc.C = 1, %o0 = sparc_errno_from_host(-ret)
 *            (positive SPARC errno). Always advances pc = npc; npc += 4.
 * Guest pointers are translated through the G window via
 * sparc32_guest_ptr; no host pointer ever leaks to the guest.
 * Unmapped-guest faults inside handler copies are reported through
 * ctx->exit_reason = SPARC32_EXIT_FAULT with ctx->fault_addr.
 *
 * Engine-loop contract (for the --interp run loop in src/main.c, which
 * arrives with L1b's interp_run): sparc32_handle_syscall dispatches the
 * number in %g1 and returns the guest exit status for exit/exit_group
 * (terminal; sparc32_syscall_is_exit says so) or 0 otherwise. The loop
 * treats exit/exit_group as terminal instead of resuming at pc.
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "sparc32rt.h"
#include "os/syscall_nr.h"
#include "rt32/rt32.h"

/* SPARC Linux errnos are the asm-generic numbers. On the AArch64 Linux
 * deployment host they match the host values, but the mapping is kept
 * explicit (rather than identity) so the E04 carry convention holds on
 * any build host — e.g. macOS reports ENOSYS as 78, SPARC as 38. Only
 * errnos this layer can produce are listed; anything else falls back
 * to the raw value, which is correct on the Linux host. */
static uint32_t sparc_errno_from_host(long host_errno)
{
    switch (host_errno) {
    case EPERM: return 1U;
    case ENOENT: return 2U;
    case ESRCH: return 3U;
    case EINTR: return 4U;
    case EIO: return 5U;
    case ENXIO: return 6U;
    case E2BIG: return 7U;
    case ENOEXEC: return 8U;
    case EBADF: return 9U;
    case ECHILD: return 10U;
    case EAGAIN: return 11U;
    case ENOMEM: return 12U;
    case EACCES: return 13U;
    case EFAULT: return 14U;
    case EBUSY: return 16U;
    case EEXIST: return 17U;
    case ENODEV: return 19U;
    case ENOTDIR: return 20U;
    case EISDIR: return 21U;
    case EINVAL: return 22U;
    case ENFILE: return 23U;
    case EMFILE: return 24U;
    case ENOTTY: return 25U;
    case EFBIG: return 27U;
    case ENOSPC: return 28U;
    case ESPIPE: return 29U;
    case EROFS: return 30U;
    case EPIPE: return 32U;
    case ENOSYS: return 38U;
    case ENAMETOOLONG: return 36U;
    case ELOOP: return 40U;
    default: break;
    }
    return (uint32_t)host_errno;
}

/* Host syscall result: negative errno on failure, else the value. Short
 * (partial) read/write counts are genuine results, not errors. */
static long host_ret(ssize_t n)
{
    return (n < 0) ? -(long)errno : (long)n;
}

/* Guest u32 result as the kernel would produce it: rt32_vm_mmap2 and
 * rt32_vm_brk return addresses and (uint32_t)-errno in one u32.
 * Sign-extend so errors read as negative errno here; the carry-commit
 * step below restores the exact 32-bit pattern either way. */
static long ret_guest_u32(uint32_t v)
{
    return (long)(int32_t)v;
}

/* Bounds check for a [va, va + len) guest range: rejects 32-bit wrap
 * and the low guard page. Returns 0 when addressable, -EFAULT when not.
 * The whole 4 GiB window is reserved PROT_NONE with mapped regions
 * inside (src/rt32/vm.c), so anything passing this check is safe to
 * touch through sparc32_guest_ptr for the Phase-1 subset. */
static int guest_range_ok(uint32_t va, uint32_t len)
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

/* Big-endian guest word access (guest is BE, host may be LE). */
static int sys_ld_be32(sparc32_ctx_t *ctx, uint32_t va, uint32_t *out)
{
    const uint8_t *p;
    if (guest_range_ok(va, 4U) != 0) {
        return -EFAULT;
    }
    p = (const uint8_t *)sparc32_guest_ptr(ctx, va);
    *out = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    return 0;
}

/* Old-style (non-SA_SIGINFO) signal dispositions for sync delivery.
 * Phase-1 scope: installed by rt_sigaction, consulted by
 * interp_try_deliver_sync. Async delivery/threads arrive in Phase 4. */
static struct {
    uint32_t handler;
    uint32_t restorer;
    int installed;
} sigact[32];

int sparc32_signal_get(int sig, uint32_t *handler_va, uint32_t *restorer_va)
{
    if (sig < 1 || sig > 31 || !sigact[sig].installed) {
        return -1;
    }
    *handler_va = sigact[sig].handler;
    *restorer_va = sigact[sig].restorer;
    return 0;
}

static long sys_close(int fd)
{
    if (close(fd) != 0) {
        return -(long)errno;
    }
    return 0;
}

/* rt_sigaction(102): SPARC 5-arg form (E05: sig, act, oact, restorer,
 * sigsetsize). Phase-1 accepts old-style handlers only (flags == 0);
 * SA_SIGINFO and realtime extensions are Phase 4. */
static long sys_rt_sigaction(sparc32_ctx_t *ctx, uint32_t sig, uint32_t act_va,
    uint32_t oact_va, uint32_t restorer, uint32_t sigsetsize)
{
    uint32_t handler;
    uint32_t flags;
    (void)ctx;
    (void)oact_va;
    if (sig < 1U || sig > 31U) {
        return -EINVAL;
    }
    if (sigsetsize != 8U) {
        return -EINVAL;
    }
    if (guest_range_ok(act_va, 20U) != 0) {
        return -EFAULT;
    }
    if (sys_ld_be32(ctx, act_va, &handler) != 0) {
        return -EFAULT;
    }
    if (sys_ld_be32(ctx, act_va + 4U, &flags) != 0) {
        return -EFAULT;
    }
    if (flags != 0U) {
        return -EINVAL;
    }
    sigact[sig].handler = handler;
    sigact[sig].restorer = restorer;
    sigact[sig].installed = 1;
    return 0;
}

/* sigreturn(216): legacy non-RT restore with qemu-sparc compatible frame
 * addressing. The guest handler (L1d test) patches pc/npc at frame+100 /
 * frame+104 — the non-RT struct signal_frame regs slots, which alias the
 * RT frame's si_errno/si_code words on this kernel/qemu layout — and
 * resumes from there. u_regs (g0..g7, i0..i7), y and psr come from the
 * kernel-layout slots (+0xE0 regs); %o regs stay live (handler contract).
 * fpu_save/rwin_save must be 0 (we never set them); anything else faults
 * instead of silently mis-restoring. */
static long sys_sigreturn(sparc32_ctx_t *ctx)
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
    if ((base & 15U) != 0U) {
        return -EFAULT;
    }
    if (guest_range_ok(base, 344U) != 0) {
        return -EFAULT;
    }
    if (sys_ld_be32(ctx, base + 0xF0U + 14U * 4U, &fp) != 0) {
        return -EFAULT;
    }
    if ((fp & 7U) != 0U) {
        return -EFAULT;
    }
    if (sys_ld_be32(ctx, base + 100U, &pc) != 0) {
        return -EFAULT;
    }
    if (sys_ld_be32(ctx, base + 104U, &npc) != 0) {
        return -EFAULT;
    }
    if ((pc & 3U) != 0U || (npc & 3U) != 0U) {
        return -EFAULT;
    }
    if (sys_ld_be32(ctx, base + 0x138U, &fs) != 0) {
        return -EFAULT;
    }
    if (fs != 0U) {
        return -EFAULT;
    }
    if (sys_ld_be32(ctx, base + 0x154U, &rp) != 0) {
        return -EFAULT;
    }
    if (rp != 0U) {
        return -EFAULT;
    }
    if (sys_ld_be32(ctx, base + 0xE0U, &psr) != 0) {
        return -EFAULT;
    }
    if (sys_ld_be32(ctx, base + 0xECU, &y) != 0) {
        return -EFAULT;
    }
    for (i = 0; i < 16; i++) {
        if (sys_ld_be32(ctx, base + 0xF0U + (uint32_t)i * 4U, &u[i]) != 0) {
            return -EFAULT;
        }
    }
    ctx->psr = psr;
    ctx->y = y;
    for (i = 1; i < 8; i++) {
        ctx->r[(uint32_t)i] = u[i];
    }
    for (i = 8; i < 16; i++) {
        ctx->r[SPARC32_I0 + (uint32_t)(i - 8)] = u[i];
    }
    ctx->r[0] = 0U;
    ctx->pc = pc;
    ctx->npc = npc;
    return 0;
}

static long sys_read(sparc32_ctx_t *ctx, uint32_t fd, uint32_t buf_va, uint32_t count)
{
    if (guest_range_ok(buf_va, count) != 0) {
        return -EFAULT;
    }
    return host_ret(read((int)fd, sparc32_guest_ptr(ctx, buf_va), (size_t)count));
}

static long sys_write(sparc32_ctx_t *ctx, uint32_t fd, uint32_t buf_va, uint32_t count)
{
    if (guest_range_ok(buf_va, count) != 0) {
        return -EFAULT;
    }
    return host_ret(write((int)fd, sparc32_guest_ptr(ctx, buf_va), (size_t)count));
}

static long sys_brk(sparc32_ctx_t *ctx, uint32_t new_brk)
{
    /* rt32_vm_brk: new_brk == 0 reads out the current break; otherwise
     * it grows/shrinks the guest heap and returns the new break (the
     * old one when the request is invalid), matching Linux brk. */
    return ret_guest_u32(rt32_vm_brk(ctx, new_brk));
}

/* Common mmap core: pgoff is the page offset (mmap2 form). Guest fd
 * numbers are host fd numbers in Phase 1 (no fd virtualization yet),
 * so the fd passes straight through to the rt32 engine. */
static long sys_mmap_pgoff(sparc32_ctx_t *ctx, uint32_t addr, uint32_t len,
                            uint32_t prot, uint32_t flags, uint32_t fd,
                            uint32_t pgoff)
{
    uint32_t r = rt32_vm_mmap2(ctx, addr, len, prot, flags, (int)fd, pgoff);

    return ret_guest_u32(r);
}

static long sys_mmap(sparc32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot,
                     uint32_t flags, uint32_t fd, uint32_t offset)
{
    /* SPARC mmap(71) takes a byte offset (page-aligned); the rt32
     * engine takes a page offset like mmap2(56). */
    if ((offset & (SPARC32_PAGE_SIZE - 1U)) != 0U) {
        return -EINVAL;
    }
    return sys_mmap_pgoff(ctx, addr, len, prot, flags, fd,
                          offset / SPARC32_PAGE_SIZE);
}

static long sys_mmap2(sparc32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot,
                      uint32_t flags, uint32_t fd, uint32_t pgoff)
{
    return sys_mmap_pgoff(ctx, addr, len, prot, flags, fd, pgoff);
}

static long sys_munmap(sparc32_ctx_t *ctx, uint32_t addr, uint32_t len)
{
    return (long)rt32_vm_munmap(ctx, addr, len);
}

static long sys_mprotect(sparc32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot)
{
    return (long)rt32_vm_mprotect(ctx, addr, len, prot);
}

/* struct utsname: six NUL-padded fields of 65 bytes each (390 total),
 * matching the sparc32 new_utsname layout the oracle exposes. */
#define SPARC32_UTS_FIELD  65U
#define SPARC32_UTS_FIELDS 6U
#define SPARC32_UTS_TOTAL  (SPARC32_UTS_FIELD * SPARC32_UTS_FIELDS)

static long sys_uname(sparc32_ctx_t *ctx, uint32_t buf_va)
{
    static const char *const uts_fields[SPARC32_UTS_FIELDS] = {
        "Linux", "sparc32rt", "6.1.0", "#1 SMP sparc32rt", "sparc", "(none)",
    };
    uint8_t *buf;
    size_t i;
    size_t j;

    if (buf_va > UINT32_MAX - (SPARC32_UTS_TOTAL - 1U)) {
        return -EFAULT;
    }
    if (buf_va < SPARC32_LOW_GUARD_SIZE) {
        return -EFAULT;
    }
    buf = (uint8_t *)sparc32_guest_ptr(ctx, buf_va);
    for (i = 0U; i < SPARC32_UTS_FIELDS; i++) {
        uint8_t *field = buf + (size_t)i * SPARC32_UTS_FIELD;

        memset(field, 0, SPARC32_UTS_FIELD);
        for (j = 0U; uts_fields[i][j] != '\0' && j < SPARC32_UTS_FIELD - 1U; j++) {
            field[j] = (uint8_t)uts_fields[i][j];
        }
    }
    return 0;
}

/* set_tid_address(166): records clear_child_tid (used at thread exit
 * by Phase 4 clone/exit) and returns the caller's own tid, which musl
 * stores as the main thread's tid. The kernel writes nothing to
 * *tidptr here; the clear+wake happens at thread teardown. */
static long sys_set_tid_address(sparc32_ctx_t *ctx, uint32_t tidptr_va)
{
    ctx->clear_child_tid = tidptr_va;
    return (ctx->host_tid > 0) ? (long)ctx->host_tid : 1000L;
}

int sparc32_syscall_is_exit(long nr)
{
    return (nr == (long)SPARC32__NR_exit || nr == (long)SPARC32__NR_exit_group) ? 1 : 0;
}

const char *sparc32_syscall_name(long nr)
{
    if (nr < 0L || nr >= (long)SPARC32_NR_MAX) {
        return NULL;
    }
#ifdef SPARC32RT_SYSCALL_NAMES
    return sparc32_sysent[(size_t)nr].name;
#else
    {
        static const char *const names[SPARC32_NR_MAX] = {
#define X(nr, name) [nr] = #name,
            SPARC32_SYSCALL_LIST
#undef X
        };

        return names[(size_t)nr];
    }
#endif
}

/* Dispatch the syscall in %g1 (args %o0..%o5), commit the SPARC carry
 * convention, and advance pc = npc; npc += 4. Returns the guest exit
 * status for exit/exit_group (terminal), 0 otherwise. */
long sparc32_handle_syscall(sparc32_ctx_t *ctx)
{
    long nr;
    uint32_t o0;
    uint32_t o1;
    uint32_t o2;
    uint32_t o3;
    uint32_t o4;
    uint32_t o5;
    long ret;

    if (ctx == NULL) {
        return -EFAULT;
    }
    nr = (long)(int32_t)ctx->r[SPARC32_G1];
    o0 = ctx->r[SPARC32_O0];
    o1 = ctx->r[SPARC32_O1];
    o2 = ctx->r[SPARC32_O2];
    o3 = ctx->r[SPARC32_O3];
    o4 = ctx->r[SPARC32_O4];
    o5 = ctx->r[SPARC32_O5];

    switch (nr) {
    case (long)SPARC32__NR_exit:
    case (long)SPARC32__NR_exit_group:
        ret = (long)(int32_t)o0;
        ctx->r[SPARC32_O0] = o0;
        ctx->psr &= ~SPARC32_PSR_C;
        ctx->pc = ctx->npc;
        ctx->npc += 4U;
        ctx->syscalls_executed++;
        return ret;
    case (long)SPARC32__NR_read:
        ret = sys_read(ctx, o0, o1, o2);
        break;
    case (long)SPARC32__NR_write:
        ret = sys_write(ctx, o0, o1, o2);
        break;
    case (long)SPARC32__NR_brk:
        ret = sys_brk(ctx, o0);
        break;
    case (long)SPARC32__NR_mmap:
        ret = sys_mmap(ctx, o0, o1, o2, o3, o4, o5);
        break;
    case (long)SPARC32__NR_mmap2:
        ret = sys_mmap2(ctx, o0, o1, o2, o3, o4, o5);
        break;
    case (long)SPARC32__NR_munmap:
        ret = sys_munmap(ctx, o0, o1);
        break;
    case (long)SPARC32__NR_mprotect:
        ret = sys_mprotect(ctx, o0, o1, o2);
        break;
    case (long)SPARC32__NR_close:
        ret = sys_close((int)(int32_t)o0);
        break;
    case (long)SPARC32__NR_rt_sigaction:
        ret = sys_rt_sigaction(ctx, o0, o1, o2, o3, o4);
        break;
    case (long)SPARC32__NR_sigreturn:
        /* sigreturn sets an absolute resume pc/npc; the common tail
         * advance below must not run a second time (same double-advance
         * class as the old trap_taken bug: resume would skip +4). */
        ret = sys_sigreturn(ctx);
        if (ret == 0) {
            ctx->syscalls_executed++;
            return 0;
        }
        break;
    case (long)SPARC32__NR_uname:
        ret = sys_uname(ctx, o0);
        break;
    case (long)SPARC32__NR_set_tid_address:
        ret = sys_set_tid_address(ctx, o0);
        break;
    default:
        ret = -ENOSYS;
        break;
    }

    /* Carry commit (E04): errors are negative host errno here.
     * mmap/brk return guest u32 addresses, whose high-bit patterns
     * would misread as errors; treat only the kernel -4095..-1 window
     * (u32 0xFFFFF001..0xFFFFFFFF) as an error for those two. */
    if (nr == (long)SPARC32__NR_mmap || nr == (long)SPARC32__NR_mmap2 ||
        nr == (long)SPARC32__NR_brk) {
        uint32_t u = (uint32_t)ret;

        if (u > 0xFFFFF000U) {
            ctx->r[SPARC32_O0] = sparc_errno_from_host((long)(0U - u));
            ctx->psr |= SPARC32_PSR_C;
        } else {
            ctx->r[SPARC32_O0] = u;
            ctx->psr &= ~SPARC32_PSR_C;
        }
    } else if (ret < 0L) {
        ctx->r[SPARC32_O0] = sparc_errno_from_host(-ret);
        ctx->psr |= SPARC32_PSR_C;
    } else {
        ctx->r[SPARC32_O0] = (uint32_t)ret;
        ctx->psr &= ~SPARC32_PSR_C;
    }
    ctx->pc = ctx->npc;
    ctx->npc += 4U;
    ctx->syscalls_executed++;
    return 0;
}
