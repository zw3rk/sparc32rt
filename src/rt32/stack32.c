/*
 * src/rt32/stack32.c — SPARC32 initial stack, argv, envp, and auxv builder
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Vendored from i686rt/src/rt32/rt32_stack32.c: renamed i686_→sparc32_,
 * retyped on sparc32_ctx_t. SPARC32 differences: no vDSO (SPEC has no
 * synthetic vDSO page; guests use their own ta 0x10 trampoline), the
 * 64-byte rwindow save area stays reserved below argc (SPEC section 2.1:
 * argc sits at %sp + 64), and the auxv carries the SPARC Linux entries
 * (AT_PHDR/PHENT/PHNUM/PAGESZ/ENTRY/UID/EUID/GID/EGID/CLKTCK/RANDOM/
 * EXECFN); AT_HWCAP is 0 until Phase 2 HWCAP discovery.
 */

#define _GNU_SOURCE
#include "rt32.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/random.h>
#endif

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#define RT32_STACK_SIZE (8U * 1024U * 1024U)

/* SPARC Linux AT_* tags used by the Phase-0 initial stack. */
#define SPARC_AT_NULL    0U
#define SPARC_AT_PHDR    3U
#define SPARC_AT_PHENT   4U
#define SPARC_AT_PHNUM   5U
#define SPARC_AT_PAGESZ  6U
/* AT_BASE is 7 on SPARC (NOT 4: tag 4 is AT_PHENT, verified against the
 * qemu-sparc -cpu LEON3 oracle which reports PHENT=0x20 at tag 4 and
 * BASE=0 at tag 7 for static binaries). AT_HWCAP2 is 26 (always 0:
 * no V8 HWCAP2 bit is defined). */
#define SPARC_AT_BASE    7U
#define SPARC_AT_FLAGS   8U
#define SPARC_AT_ENTRY   9U
#define SPARC_AT_UID     11U
#define SPARC_AT_EUID    12U
#define SPARC_AT_GID     13U
#define SPARC_AT_EGID    14U
#define SPARC_AT_PLATFORM 15U
/* SPARC Linux AT_HWCAP bits (glibc bits/hwcap.h, mirroring the kernel
 * arch/sparc uapi header): FLUSH/STBAR/SWAP/MULDIV are exactly what
 * qemu-sparc -cpu LEON3 advertises (auxv-dump probe: 0x0F); V9 stays
 * clear (V9-only encodings trap EXIT_UNDEF). No FPU bit exists in the
 * header (FPU is baseline V8, verified via E06 fcc/NaN/RD); the oracle
 * does not advertise FSMULD (0x400), so neither do we. */
#define SPARC_HWCAP_FLUSH   1U
#define SPARC_HWCAP_STBAR   2U
#define SPARC_HWCAP_SWAP    4U
#define SPARC_HWCAP_MULDIV  8U
#define SPARC_AT_HWCAP   16U
#define SPARC_AT_CLKTCK  17U
#define SPARC_AT_SECURE  23U
#define SPARC_AT_RANDOM  25U
#define SPARC_AT_HWCAP2  26U
#define SPARC_AT_EXECFN  31U

/* Big-endian 32-bit store to guest memory (SPARC is BE; the host may be
 * LE — never use native word stores for guest-visible words). */
static void st_be32(sparc32_ctx_t *ctx, uint32_t va, uint32_t v)
{
    uint8_t b[4];

    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)v;
    memcpy(sparc32_guest_ptr(ctx, va), b, sizeof(b));
}

static uint32_t push_bytes(sparc32_ctx_t *ctx, uint32_t *sp, const void *data, size_t len)
{
    if (*sp < ctx->stack_base || len > (size_t)(*sp - ctx->stack_base)) {
        return 0U;
    }
    *sp -= (uint32_t)len;
    memcpy(sparc32_guest_ptr(ctx, *sp), data, len);
    return *sp;
}

static uint32_t push_cstring(sparc32_ctx_t *ctx, uint32_t *sp, const char *s)
{
    size_t len = strlen(s) + 1U;
    return push_bytes(ctx, sp, s, len);
}

static int push_string_table(sparc32_ctx_t *ctx, uint32_t *sp, char **strs,
                             int max_count, uint32_t *out_ptrs, int *out_count)
{
    int count = 0;
    if (strs) {
        while (count < max_count && count < 511 && strs[count] != NULL) {
            count++;
        }
        if (count == 511 && strs[511] != NULL) {
            return -1;
        }
        for (int i = count - 1; i >= 0; i--) {
            out_ptrs[i] = push_cstring(ctx, sp, strs[i]);
            if (out_ptrs[i] == 0U) {
                return -1;
            }
        }
    }
    *out_count = count;
    return 0;
}

/* AT_RANDOM bytes: getrandom first on Linux, else /dev/urandom with
 * EINTR/short-read retry; -1 unless 16 CSPRNG bytes are obtained. */
static int rt32_get_rand(uint8_t out[16])
{
    size_t done = 0U;
#ifdef __linux__
    while (done < 16U) {
        ssize_t r = getrandom(out + done, 16U - done, 0);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (r == 0) {
            break;
        }
        done += (size_t)r;
    }
    if (done == 16U) {
        return 0;
    }
    done = 0U;
#endif
    {
        int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            return -1;
        }
        while (done < 16U) {
            ssize_t r = read(fd, out + done, 16U - done);
            if (r < 0) {
                if (errno == EINTR) {
                    continue;
                }
                close(fd);
                return -1;
            }
            if (r == 0) {
                close(fd);
                return -1;
            }
            done += (size_t)r;
        }
        close(fd);
    }
    return 0;
}

/* Heap-owned argv/envp/exec copies kept in ctx across execve, so
 * /proc/self/cmdline and /proc/self/exe stay valid after the staging
 * vectors are freed. Only pointers placed here are ever released, so a
 * caller-owned string already in ctx is never freed by mistake. */
static char **rt32_owned_argv;
static char **rt32_owned_envp;
static char *rt32_owned_exec;

static void rt32_free_owned_vec(char **v)
{
    int i;
    if (v == NULL) {
        return;
    }
    for (i = 0; v[i] != NULL; i++) {
        free(v[i]);
    }
    free(v);
}

static int rt32_dup_strvec(char **src, int n, char ***out)
{
    char **d;
    int i;
    *out = NULL;
    if (n <= 0 || src == NULL) {
        return 0;
    }
    d = (char **)malloc(((size_t)n + 1U) * sizeof(*d));
    if (d == NULL) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        size_t len;
        if (src[i] == NULL) {
            break;
        }
        len = strlen(src[i]) + 1U;
        d[i] = (char *)malloc(len);
        if (d[i] == NULL) {
            break;
        }
        memcpy(d[i], src[i], len);
    }
    if (i != n) {
        while (--i >= 0) {
            free(d[i]);
        }
        free(d);
        return -1;
    }
    d[n] = NULL;
    *out = d;
    return 0;
}

static int rt32_retain_args(sparc32_ctx_t *ctx, int argc, char **argv,
    char **envp, const char *execfn)
{
    char **nargv = NULL;
    char **nenvp = NULL;
    char *nexec = NULL;
    int nenv = 0;
    if (envp != NULL) {
        while (envp[nenv] != NULL) {
            nenv++;
        }
    }
    if (rt32_dup_strvec(argv, argc, &nargv) != 0 ||
        rt32_dup_strvec(envp, nenv, &nenvp) != 0) {
        rt32_free_owned_vec(nargv);
        rt32_free_owned_vec(nenvp);
        return -1;
    }
    if (execfn != NULL && execfn[0] != '\0') {
        size_t len = strlen(execfn) + 1U;
        nexec = (char *)malloc(len);
        if (nexec == NULL) {
            rt32_free_owned_vec(nargv);
            rt32_free_owned_vec(nenvp);
            return -1;
        }
        memcpy(nexec, execfn, len);
    }
    rt32_free_owned_vec(rt32_owned_argv);
    rt32_free_owned_vec(rt32_owned_envp);
    free(rt32_owned_exec);
    rt32_owned_argv = nargv;
    rt32_owned_envp = nenvp;
    rt32_owned_exec = nexec;
    ctx->guest_argc = argc;
    ctx->guest_argv = nargv;
    ctx->host_envp = nenvp;
    ctx->exec_path = nexec;
    return 0;
}

int rt32_stack_setup(sparc32_ctx_t *ctx, const rt32_elf_info_t *elf_info,
                    int guest_argc, char **guest_argv, char **host_envp,
                    uint32_t *out_sp)
{
    uint32_t stack_base = SPARC32_STACK_TOP - RT32_STACK_SIZE;
    void *host_stack;
    void *res;
    uint32_t sp;
    uint8_t rand_bytes[16];
    uint32_t at_random_va;
    uint32_t at_platform_va;
    uint32_t at_execfn_va;
    const char *execfn_str;
    uint32_t env_ptrs[512];
    uint32_t arg_ptrs[512];
    int envc = 0;
    int argc = 0;
    uint32_t auxv[40];
    size_t aux_idx = 0U;
    size_t total_words;
    uint32_t frame_bytes;
    uint32_t final_sp;
    size_t pos = 0;
    size_t copy_words;

    if (!ctx || !elf_info || !out_sp || guest_argc < 1 || !guest_argv || !guest_argv[0]) {
        return -1;
    }

    host_stack = sparc32_guest_ptr(ctx, stack_base);
    res = mmap(host_stack, RT32_STACK_SIZE, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (res == MAP_FAILED) {
        fprintf(stderr, "sparc32rt: failed to map guest stack: %s\n", strerror(errno));
        return -1;
    }
    ctx->stack_top  = SPARC32_STACK_TOP;
    ctx->stack_base = stack_base;
    rt32_vm_record_region(ctx, stack_base, SPARC32_STACK_TOP,
                         (uint32_t)(PROT_READ | PROT_WRITE), 0x12U, "[stack]");

    sp = SPARC32_STACK_TOP;

    if (rt32_get_rand(rand_bytes) != 0) {
        return -EIO;
    }
    at_random_va   = push_bytes(ctx, &sp, rand_bytes, sizeof(rand_bytes));
    at_platform_va = push_cstring(ctx, &sp, "sparc");
    execfn_str     = (ctx->exec_path && ctx->exec_path[0]) ? ctx->exec_path : guest_argv[0];
    at_execfn_va   = push_cstring(ctx, &sp, execfn_str);
    if (at_random_va == 0U || at_platform_va == 0U || at_execfn_va == 0U) {
        return -1;
    }

    if (push_string_table(ctx, &sp, host_envp, 511, env_ptrs, &envc) != 0 ||
        push_string_table(ctx, &sp, guest_argv, guest_argc, arg_ptrs, &argc) != 0) {
        return -1;
    }

    sp &= ~0x7U;

#define AUXV_PUT(tag, val) do { auxv[aux_idx++] = (tag); auxv[aux_idx++] = (val); } while (0)
    AUXV_PUT(SPARC_AT_PHDR, elf_info->phdr_vaddr);
    AUXV_PUT(SPARC_AT_PHENT, elf_info->phent);
    AUXV_PUT(SPARC_AT_PHNUM, elf_info->phnum);
    AUXV_PUT(SPARC_AT_PAGESZ, SPARC32_PAGE_SIZE);
    AUXV_PUT(SPARC_AT_FLAGS, 0U);
    /* App entry with PT_INTERP (elf32.c preserves it in app_entry while
     * entry becomes the interpreter's run entry); plain entry otherwise. */
    AUXV_PUT(SPARC_AT_ENTRY, elf_info->app_entry != 0U ? elf_info->app_entry
                                                       : elf_info->entry);
    AUXV_PUT(SPARC_AT_BASE, ctx->interp_base);
    AUXV_PUT(SPARC_AT_UID, (uint32_t)getuid());
    AUXV_PUT(SPARC_AT_EUID, (uint32_t)geteuid());
    AUXV_PUT(SPARC_AT_GID, (uint32_t)getgid());
    AUXV_PUT(SPARC_AT_EGID, (uint32_t)getegid());
    AUXV_PUT(SPARC_AT_HWCAP,
        SPARC_HWCAP_FLUSH | SPARC_HWCAP_STBAR | SPARC_HWCAP_SWAP |
        SPARC_HWCAP_MULDIV);
    AUXV_PUT(SPARC_AT_HWCAP2, 0U);
    AUXV_PUT(SPARC_AT_PLATFORM, at_platform_va);
    AUXV_PUT(SPARC_AT_CLKTCK, 100U);
    AUXV_PUT(SPARC_AT_SECURE, 0U);
    AUXV_PUT(SPARC_AT_RANDOM, at_random_va);
    AUXV_PUT(SPARC_AT_EXECFN, at_execfn_va);
    AUXV_PUT(SPARC_AT_NULL, 0U);
#undef AUXV_PUT

    /* Frame layout: 64-byte rwindow save area, then argc, argv[], NULL,
     * envp[], NULL, auxv[] — so argc sits at %sp + 64 (SPEC section 2.1). */
    total_words   = 1U + ((size_t)argc + 1U) + ((size_t)envc + 1U) + aux_idx;
    frame_bytes   = (uint32_t)(total_words * sizeof(uint32_t)) + SPARC32_RWINDOW_SIZE;
    if (sp < ctx->stack_base || (sp - ctx->stack_base) < frame_bytes + 16U) {
        return -1;
    }
    final_sp = (sp - frame_bytes) & ~0x7U;

    /* Guest-visible words are big-endian (st_be32); the host-order auxv[]
     * array is kept for the ctx->auxv_data cache below. */
    st_be32(ctx, final_sp + SPARC32_RWINDOW_SIZE + (uint32_t)(pos * 4U),
            (uint32_t)argc);
    pos++;
    for (int i = 0; i < argc; i++) {
        st_be32(ctx, final_sp + SPARC32_RWINDOW_SIZE + (uint32_t)(pos * 4U),
                arg_ptrs[i]);
        pos++;
    }
    st_be32(ctx, final_sp + SPARC32_RWINDOW_SIZE + (uint32_t)(pos * 4U), 0U);
    pos++;
    for (int i = 0; i < envc; i++) {
        st_be32(ctx, final_sp + SPARC32_RWINDOW_SIZE + (uint32_t)(pos * 4U),
                env_ptrs[i]);
        pos++;
    }
    st_be32(ctx, final_sp + SPARC32_RWINDOW_SIZE + (uint32_t)(pos * 4U), 0U);
    pos++;
    for (size_t i = 0; i < aux_idx; i++) {
        st_be32(ctx, final_sp + SPARC32_RWINDOW_SIZE + (uint32_t)(pos * 4U),
                auxv[i]);
        pos++;
    }

    /* Retain heap-owned copies: the caller's vectors may be freed or
     * replaced (execve staging) while /proc still reads them via ctx. */
    if (rt32_retain_args(ctx, argc, guest_argv, host_envp, execfn_str) != 0) {
        return -ENOMEM;
    }

    copy_words = aux_idx;
    if (copy_words > (sizeof(ctx->auxv_data) / sizeof(ctx->auxv_data[0]))) {
        copy_words = sizeof(ctx->auxv_data) / sizeof(ctx->auxv_data[0]);
    }
    memcpy(ctx->auxv_data, auxv, copy_words * sizeof(uint32_t));
    ctx->auxv_bytes = copy_words * sizeof(uint32_t);

    *out_sp = final_sp;
    return 0;
}
