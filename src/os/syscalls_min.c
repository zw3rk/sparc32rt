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

/* Needs _GNU_SOURCE: prlimit(2) is hidden under strict -std=c11
 * (and under the Makefile's Linux-only _POSIX_C_SOURCE=200809L). */
#define _GNU_SOURCE

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>

#include "sparc32rt.h"
#include "interp/interp.h"
#include "interp/interp_priv.h"
#include "os/l2a_access.h"
#include "os/syscall_nr.h"
#include "os/threads.h"
#include "rt32/rt32.h"
#include "rt32/procfs.h"

/* Phase-2 static-libc layer (src/os/syscalls.c, lane L2a owns). Handlers
 * return host-style results (>= 0 value, negative host errno); the carry
 * commit below applies unchanged. */
long sparc32_l2a_openat(sparc32_ctx_t *ctx, uint32_t dirfd, uint32_t path_va,
    uint32_t flags, uint32_t mode);
long sparc32_l2a_open(sparc32_ctx_t *ctx, uint32_t path_va, uint32_t flags,
    uint32_t mode);
long sparc32_l2a_creat(sparc32_ctx_t *ctx, uint32_t path_va, uint32_t mode);
long sparc32_l2a_close(int fd);
long sparc32_l2a_unlink(sparc32_ctx_t *ctx, uint32_t path_va);
long sparc32_l2a_lseek(uint32_t fd, int32_t offset, uint32_t whence);
long sparc32_l2a_getpid(void);
long sparc32_l2a_getuid(void);
long sparc32_l2a_geteuid(void);
long sparc32_l2a_getgid(void);
long sparc32_l2a_getegid(void);
long sparc32_l2a_getppid(void);
long sparc32_l2a_dup(uint32_t fd);
long sparc32_l2a_dup2(uint32_t oldfd, uint32_t newfd);
long sparc32_l2a_readv(sparc32_ctx_t *ctx, uint32_t fd, uint32_t iov_va,
    uint32_t iovcnt);
long sparc32_l2a_writev(sparc32_ctx_t *ctx, uint32_t fd, uint32_t iov_va,
    uint32_t iovcnt);
long sparc32_l2a_stat(sparc32_ctx_t *ctx, uint32_t path_va, uint32_t buf_va);
long sparc32_l2a_lstat(sparc32_ctx_t *ctx, uint32_t path_va, uint32_t buf_va);
long sparc32_l2a_fstat(sparc32_ctx_t *ctx, uint32_t fd, uint32_t buf_va);
long sparc32_l2a_stat64(sparc32_ctx_t *ctx, uint32_t path_va, uint32_t buf_va);
long sparc32_l2a_lstat64(sparc32_ctx_t *ctx, uint32_t path_va, uint32_t buf_va);
long sparc32_l2a_fstat64(sparc32_ctx_t *ctx, uint32_t fd, uint32_t buf_va);
long sparc32_l2a_fstatat64(sparc32_ctx_t *ctx, uint32_t dirfd,
    uint32_t path_va, uint32_t buf_va, uint32_t flags);
long sparc32_l2a_statx(sparc32_ctx_t *ctx, uint32_t dirfd, uint32_t path_va,
    uint32_t flags, uint32_t mask, uint32_t buf_va);
long sparc32_l2a_fcntl(uint32_t fd, uint32_t cmd, uint32_t arg);
long sparc32_l2a_clock_gettime(sparc32_ctx_t *ctx, uint32_t clk_id,
    uint32_t tp_va);
long sparc32_l2a_clock_gettime64(sparc32_ctx_t *ctx, uint32_t clk_id,
    uint32_t tp_va);
long sparc32_l2a_gettimeofday(sparc32_ctx_t *ctx, uint32_t tv_va,
    uint32_t tz_va);
long sparc32_l2a_clock_nanosleep(sparc32_ctx_t *ctx, uint32_t clk_id,
    uint32_t flags, uint32_t req_va, uint32_t rem_va);
long sparc32_l2a_getrandom(sparc32_ctx_t *ctx, uint32_t buf_va, uint32_t len,
    uint32_t flags);
long sparc32_l2a_futex(sparc32_ctx_t *ctx, uint32_t uaddr, uint32_t op,
    uint32_t val, uint32_t timeout_va);
long sparc32_l2a_futex_time64(sparc32_ctx_t *ctx, uint32_t uaddr,
    uint32_t op, uint32_t val, uint32_t timeout_va);
long sparc32_l2a_rt_sigprocmask(sparc32_ctx_t *ctx, uint32_t how,
    uint32_t set_va, uint32_t oset_va, uint32_t sigsetsize);
long sparc32_l2a_ioctl(sparc32_ctx_t *ctx, uint32_t fd, uint32_t request,
    uint32_t arg_va);

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
    case ERANGE: return 34U;
    case EOVERFLOW: return 75U;
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

/* Bounds + permission check for a [va, va + len) guest range. */
static int guest_range_ok_prot(uint32_t va, uint32_t len, uint32_t req_prot)
{
    return l2a_range_ok_prot(va, len, req_prot);
}

/* Big-endian guest word access (guest is BE, host may be LE). */
static int sys_st_be32(sparc32_ctx_t *ctx, uint32_t va, uint32_t v);
#if defined(__linux__)
static int sys_ld_be32(sparc32_ctx_t *ctx, uint32_t va, uint32_t *out)
{
    const uint8_t *p;
    if (guest_range_ok_prot(va, 4U, 1U) != 0) {
        return -EFAULT;
    }
    p = (const uint8_t *)sparc32_guest_ptr(ctx, va);
    *out = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    return 0;
}
#endif

#ifndef SPARC32__NR_sigaltstack
#define SPARC32__NR_sigaltstack 28L
#endif
#ifndef SPARC32__NR_rt_sigreturn
#define SPARC32__NR_rt_sigreturn 101L
#endif

long sparc32_sys_rt_sigaction(sparc32_ctx_t *ctx, uint32_t sig, uint32_t act_va,
    uint32_t oact_va, uint32_t restorer, uint32_t sigsetsize);
long sparc32_sys_sigaltstack(sparc32_ctx_t *ctx, uint32_t uss_va,
    uint32_t uoss_va);
long sparc32_sys_sigreturn(sparc32_ctx_t *ctx);
long sparc32_sys_rt_sigreturn(sparc32_ctx_t *ctx);

static long sys_read(sparc32_ctx_t *ctx, uint32_t fd, uint32_t buf_va, uint32_t count)
{
    ssize_t n;
    if (guest_range_ok_prot(buf_va, count, 2U) != 0) {
        return -EFAULT;
    }
    n = read((int)fd, sparc32_guest_ptr(ctx, buf_va), (size_t)count);
    if (n > 0 && vm32_range_has_code(buf_va, (size_t)n)) {
        vm_invalidate_jit(ctx, buf_va, buf_va + (uint32_t)n);
    }
    return host_ret(n);
}

static long sys_write(sparc32_ctx_t *ctx, uint32_t fd, uint32_t buf_va, uint32_t count)
{
    if (guest_range_ok_prot(buf_va, count, 1U) != 0) {
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

/* mremap(250): SPARC 5-arg form (old_addr, old_len, new_len, flags,
 * new_addr). rt32_vm_mremap returns a guest u32 address or
 * (uint32_t)-errno like mmap/brk, so it shares their carry-commit
 * window below (Phase 6, host-contract section 2.1). */
static long sys_mremap(sparc32_ctx_t *ctx, uint32_t old_addr, uint32_t old_len,
                       uint32_t new_len, uint32_t flags, uint32_t new_addr)
{
    return ret_guest_u32(rt32_vm_mremap(ctx, old_addr, old_len, new_len,
                                       flags, new_addr));
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
    uint8_t buf[SPARC32_UTS_TOTAL];
    size_t i;
    size_t j;

    if (guest_range_ok_prot(buf_va, SPARC32_UTS_TOTAL, 2U) != 0) {
        return -EFAULT;
    }
    memset(buf, 0, sizeof(buf));
    for (i = 0U; i < SPARC32_UTS_FIELDS; i++) {
        uint8_t *field = buf + i * SPARC32_UTS_FIELD;
        for (j = 0U; uts_fields[i][j] != '\0' && j < SPARC32_UTS_FIELD - 1U; j++) {
            field[j] = (uint8_t)uts_fields[i][j];
        }
    }
    return (long)l2a_store(ctx, buf_va, buf, sizeof(buf));
}

/* Big-endian guest word stores (guest is BE, host may be LE). */
static int sys_st_be32(sparc32_ctx_t *ctx, uint32_t va, uint32_t v)
{
    uint8_t b[4];
    put_be32(b, v);
    return l2a_store(ctx, va, b, sizeof(b));
}

#if defined(__linux__)
/* 64-bit guest words: prlimit64-only (non-Linux builds stub that path). */
static int sys_ld_be64(sparc32_ctx_t *ctx, uint32_t va, uint64_t *out)
{
    uint32_t hi;
    uint32_t lo;
    if (sys_ld_be32(ctx, va, &hi) != 0) {
        return -EFAULT;
    }
    if (sys_ld_be32(ctx, va + 4U, &lo) != 0) {
        return -EFAULT;
    }
    *out = ((uint64_t)hi << 32) | (uint64_t)lo;
    return 0;
}

static int sys_st_be64(sparc32_ctx_t *ctx, uint32_t va, uint64_t v)
{
    if (sys_st_be32(ctx, va, (uint32_t)(v >> 32)) != 0) {
        return -EFAULT;
    }
    return sys_st_be32(ctx, va + 4U, (uint32_t)v);
}
#endif

/* L4c RLIMIT_AS + prlimit64/getrlimit mapping (oracle: qemu-sparc
 * -cpu LEON3): getrlimit(144) reports cur=max=0x7fffffff (32-bit
 * infinity); prlimit64(331) reports cur=max=0xffffffffffffffff
 * (RLIM64_INFINITY); /proc/self/oom_score_adj reads "0\n" and accepts
 * writes through the existing openat/read/write passthrough, so it
 * needs no mapping (probed: read 2 B, write 3 B, both ok).
 * Previously both traps fell into default -ENOSYS, which deviates
 * from the oracle; hence this fix (case arms below).
 * Placement note: these helpers live here as static sys_* functions
 * (this file's own sys_rt_sigaction/sys_sigreturn/sys_uname pattern),
 * not in src/os/syscalls.c — that TU sits at 899/900 lines and the
 * hard `make check-line-limits` gate forbids any growth there. */

/* 64-bit host limit -> 32-bit guest rlimit word: infinity and anything
 * above the signed-32-bit range land on 0x7FFFFFFF (oracle shape). */
static uint32_t rlim32_sat(uint64_t v)
{
    return (v >= 0x7FFFFFFFULL) ? 0x7FFFFFFFUL : (uint32_t)v;
}

static long sys_getrlimit(sparc32_ctx_t *ctx, uint32_t res, uint32_t buf_va)
{
    struct rlimit h;
    if (guest_range_ok_prot(buf_va, 8U, 2U) != 0) {
        return -EFAULT;
    }
    if (getrlimit((int)res, &h) != 0) {
        return -(long)errno;
    }
    if (sys_st_be32(ctx, buf_va, rlim32_sat((uint64_t)h.rlim_cur)) != 0) {
        return -EFAULT;
    }
    if (sys_st_be32(ctx, buf_va + 4U, rlim32_sat((uint64_t)h.rlim_max)) != 0) {
        return -EFAULT;
    }
    return 0;
}

static long sys_prlimit64(sparc32_ctx_t *ctx, uint32_t pid, uint32_t res,
    uint32_t new_va, uint32_t old_va)
{
#if defined(__linux__)
    struct rlimit newh;
    struct rlimit oldh;
    struct rlimit *newp = NULL;
    struct rlimit *oldp = NULL;
    uint64_t cur;
    uint64_t max;
    if (new_va != 0U) {
        if (guest_range_ok_prot(new_va, 16U, 1U) != 0) {
            return -EFAULT;
        }
        if (sys_ld_be64(ctx, new_va, &cur) != 0) {
            return -EFAULT;
        }
        if (sys_ld_be64(ctx, new_va + 8U, &max) != 0) {
            return -EFAULT;
        }
        newh.rlim_cur = (rlim_t)cur;
        newh.rlim_max = (rlim_t)max;
        newp = &newh;
    }
    if (old_va != 0U) {
        if (guest_range_ok_prot(old_va, 16U, 2U) != 0) {
            return -EFAULT;
        }
        oldp = &oldh;
    }
    if (prlimit((pid_t)(int32_t)pid, (int)res, newp, oldp) != 0) {
        return -(long)errno;
    }
    if (old_va != 0U) {
        if (sys_st_be64(ctx, old_va, (uint64_t)oldh.rlim_cur) != 0) {
            return -EFAULT;
        }
        if (sys_st_be64(ctx, old_va + 8U, (uint64_t)oldh.rlim_max) != 0) {
            return -EFAULT;
        }
    }
    return 0;
#else
    (void)ctx;
    (void)pid;
    (void)res;
    (void)new_va;
    (void)old_va;
    return -ENOSYS;
#endif
}

/* set_robust_list(300)/get_robust_list(301): record the NPTL robust
 * mutex list head/len per thread and report it back. The translator
 * never needs to walk the list (no fatal thread exits mid-critical
 * section in the test matrix), so recording suffices; qemu accepts
 * the call, hence 0 rather than -ENOSYS. */
static long sys_set_robust_list(sparc32_ctx_t *ctx, uint32_t head_va,
    uint32_t len)
{
    if (len != 12U && len != 24U) {
        return -EINVAL;
    }
    ctx->robust_list_head = head_va;
    ctx->robust_list_len = len;
    return 0;
}

static long sys_get_robust_list(sparc32_ctx_t *ctx, uint32_t pid,
    uint32_t head_ptr_va, uint32_t len_ptr_va)
{
    if (pid != 0U) {
        return -ESRCH;
    }
    if (guest_range_ok_prot(head_ptr_va, 4U, 2U) != 0 ||
        guest_range_ok_prot(len_ptr_va, 4U, 2U) != 0) {
        return -EFAULT;
    }
    if (sys_st_be32(ctx, head_ptr_va, ctx->robust_list_head) != 0) {
        return -EFAULT;
    }
    if (sys_st_be32(ctx, len_ptr_va, ctx->robust_list_len) != 0) {
        return -EFAULT;
    }
    return 0;
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
    case (long)SPARC32__NR_mremap:
        ret = sys_mremap(ctx, o0, o1, o2, o3, o4);
        break;
    case (long)SPARC32__NR_close:
        ret = sparc32_l2a_close((int)(int32_t)o0);
        break;
    /* R2: dup/dup2/getppid/gettimeofday/clock_nanosleep (oracle-verified;
     * both engines returned ENOSYS before these dispatch arms). */
    case (long)SPARC32__NR_dup:
        ret = sparc32_l2a_dup(o0);
        break;
    case (long)SPARC32__NR_dup2:
        ret = sparc32_l2a_dup2(o0, o1);
        break;
    case (long)SPARC32__NR_getppid:
        ret = sparc32_l2a_getppid();
        break;
    /* Lane L2a static-libc set (src/os/syscalls.c, additive cases only). */
    case (long)SPARC32__NR_open:
        ret = sparc32_l2a_open(ctx, o0, o1, o2);
        break;
    case (long)SPARC32__NR_creat:
        ret = sparc32_l2a_creat(ctx, o0, o1);
        break;
    case (long)SPARC32__NR_unlink:
        ret = sparc32_l2a_unlink(ctx, o0);
        break;
    case (long)SPARC32__NR_lseek:
        ret = sparc32_l2a_lseek(o0, (int32_t)o1, o2);
        break;
    case (long)SPARC32__NR_getpid:
        ret = sparc32_l2a_getpid();
        break;
    case (long)SPARC32__NR_gettid:
        ret = sparc32_thr_gettid(ctx);
        break;
    case (long)SPARC32__NR_getuid:
    case (long)SPARC32__NR_getuid32:
        ret = sparc32_l2a_getuid();
        break;
    case (long)SPARC32__NR_geteuid:
    case (long)SPARC32__NR_geteuid32:
        ret = sparc32_l2a_geteuid();
        break;
    case (long)SPARC32__NR_getgid:
    case (long)SPARC32__NR_getgid32:
        ret = sparc32_l2a_getgid();
        break;
    case (long)SPARC32__NR_getegid:
    case (long)SPARC32__NR_getegid32:
        ret = sparc32_l2a_getegid();
        break;
    case (long)SPARC32__NR_stat:
        ret = sparc32_l2a_stat(ctx, o0, o1);
        break;
    case (long)SPARC32__NR_lstat:
        ret = sparc32_l2a_lstat(ctx, o0, o1);
        break;
    case (long)SPARC32__NR_fstat:
        ret = sparc32_l2a_fstat(ctx, o0, o1);
        break;
    case (long)SPARC32__NR_stat64:
        ret = sparc32_l2a_stat64(ctx, o0, o1);
        break;
    case (long)SPARC32__NR_lstat64:
        ret = sparc32_l2a_lstat64(ctx, o0, o1);
        break;
    case (long)SPARC32__NR_fstat64:
        ret = sparc32_l2a_fstat64(ctx, o0, o1);
        break;
    case (long)SPARC32__NR_fstatat64:
        ret = sparc32_l2a_fstatat64(ctx, o0, o1, o2, o3);
        break;
    case (long)SPARC32__NR_statx:
        ret = sparc32_l2a_statx(ctx, o0, o1, o2, o3, o4);
        break;
    case (long)SPARC32__NR_readv:
        ret = sparc32_l2a_readv(ctx, o0, o1, o2);
        break;
    case (long)SPARC32__NR_writev:
        ret = sparc32_l2a_writev(ctx, o0, o1, o2);
        break;
    case (long)SPARC32__NR_openat:
        ret = sparc32_l2a_openat(ctx, o0, o1, o2, o3);
        break;
    /* Lane L5a /proc/self interception (src/rt32/procfs.c owns the logic). */
    case (long)SPARC32__NR_readlink:
        ret = rt32_procfs_readlink(ctx, o0, o1, o2);
        break;
    case (long)SPARC32__NR_readlinkat:
        ret = rt32_procfs_readlinkat(ctx, o0, o1, o2, o3);
        break;
    case (long)SPARC32__NR_fcntl:
    case (long)SPARC32__NR_fcntl64: /* identical F_* command set on SPARC */
        ret = sparc32_l2a_fcntl(o0, o1, o2);
        break;
    case (long)SPARC32__NR_rt_sigprocmask:
        ret = sparc32_l2a_rt_sigprocmask(ctx, o0, o1, o2, o3);
        break;
    case (long)SPARC32__NR_ioctl:
        ret = sparc32_l2a_ioctl(ctx, o0, o1, o2);
        break;
    case (long)SPARC32__NR_clock_gettime:
        ret = sparc32_l2a_clock_gettime(ctx, o0, o1);
        break;
    case (long)SPARC32__NR_clock_gettime64:
        ret = sparc32_l2a_clock_gettime64(ctx, o0, o1);
        break;
    case (long)SPARC32__NR_gettimeofday:
        ret = sparc32_l2a_gettimeofday(ctx, o0, o1);
        break;
    case (long)SPARC32__NR_clock_nanosleep:
        ret = sparc32_l2a_clock_nanosleep(ctx, o0, o1, o2, o3);
        break;
    case (long)SPARC32__NR_getrandom:
        ret = sparc32_l2a_getrandom(ctx, o0, o1, o2);
        break;
    case (long)SPARC32__NR_futex:
        ret = sparc32_l2a_futex(ctx, o0, o1, o2, o3);
        break;
    case (long)SPARC32__NR_futex_time64:
        ret = sparc32_l2a_futex_time64(ctx, o0, o1, o2, o3);
        break;
    case (long)SPARC32__NR_set_robust_list:
        ret = sys_set_robust_list(ctx, o0, o1);
        break;
    case (long)SPARC32__NR_get_robust_list:
        ret = sys_get_robust_list(ctx, o0, o1, o2);
        break;
    /* Lane L4c rlimit hook (oracle: values above, was default -ENOSYS). */
    case (long)SPARC32__NR_getrlimit:
        ret = sys_getrlimit(ctx, o0, o1);
        break;
    case (long)SPARC32__NR_prlimit64:
        ret = sys_prlimit64(ctx, o0, o1, o2, o3);
        break;
    case (long)SPARC32__NR_rt_sigaction:
        ret = sparc32_sys_rt_sigaction(ctx, o0, o1, o2, o3, o4);
        break;
    case (long)SPARC32__NR_sigaltstack:
        ret = sparc32_sys_sigaltstack(ctx, o0, o1);
        break;
    case (long)SPARC32__NR_rt_sigreturn:
        /* rt_sigreturn sets an absolute resume pc/npc like sigreturn. */
        ret = sparc32_sys_rt_sigreturn(ctx);
        if (ret == 0) {
            ctx->syscalls_executed++;
            return 0;
        }
        break;
    case (long)SPARC32__NR_sigreturn:
        /* sigreturn sets an absolute resume pc/npc; the common tail
         * advance below must not run a second time (same double-advance
         * class as the old trap_taken bug: resume would skip +4). */
        ret = sparc32_sys_sigreturn(ctx);
        if (ret == 0) {
            ctx->syscalls_executed++;
            return 0;
        }
        break;
    case (long)SPARC32__NR_uname:
        ret = sys_uname(ctx, o0);
        break;
    case (long)SPARC32__NR_set_tid_address:
        /* Phase-4 completion (lane L4a): record + real tid + async init. */
        ret = sparc32_thr_set_tid_address(ctx, o0);
        break;
    /* Lane L4a process/thread arms (src/os/threads.c owns the logic). */
    case (long)SPARC32__NR_fork:
        ret = sparc32_thr_fork(ctx);
        break;
    case (long)SPARC32__NR_vfork:
        ret = sparc32_thr_vfork(ctx);
        break;
    case (long)SPARC32__NR_pipe:
        ret = sparc32_thr_pipe(ctx);
        break;
    case (long)SPARC32__NR_pipe2:
        ret = sparc32_thr_pipe2(ctx, o0, o1);
        break;
    case (long)SPARC32__NR_wait4:
        ret = sparc32_thr_wait4(ctx, o0, o1, o2, o3);
        break;
    case (long)SPARC32__NR_waitpid:
        ret = sparc32_thr_waitpid(ctx, o0, o1, o2);
        break;
    case (long)SPARC32__NR_clone:
        ret = sparc32_thr_clone(ctx, o0, o1, o2, o3, o4);
        break;
    case (long)SPARC32__NR_execve:
        ret = sparc32_thr_execve(ctx, o0, o1, o2);
        break;
    case (long)SPARC32__NR_kill:
        ret = sparc32_thr_kill(ctx, o0, o1);
        break;
    case (long)SPARC32__NR_tkill:
        ret = sparc32_thr_tkill(ctx, o0, o1);
        break;
    case (long)SPARC32__NR_tgkill:
        ret = sparc32_thr_tgkill(ctx, o0, o1, o2);
        break;
    case (long)SPARC32__NR_rt_sigpending:
        ret = sparc32_thr_rt_sigpending(ctx, o0, o1);
        break;
    case (long)SPARC32__NR_rt_sigsuspend:
        ret = sparc32_thr_rt_sigsuspend(ctx, o0, o1);
        break;
    case (long)SPARC32__NR_setitimer:
        ret = sparc32_thr_setitimer(ctx, o0, o1, o2);
        break;
    default:
        ret = -ENOSYS;
        break;
    }

    /* Carry commit (E04): errors are negative host errno here.
     * mmap/mremap/brk return guest u32 addresses, whose high-bit patterns
     * would misread as errors; treat only the kernel -4095..-1 window
     * (u32 0xFFFFF001..0xFFFFFFFF) as an error for those three. */
    if (nr == (long)SPARC32__NR_mmap || nr == (long)SPARC32__NR_mmap2 ||
        nr == (long)SPARC32__NR_mremap || nr == (long)SPARC32__NR_brk) {
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
