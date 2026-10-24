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
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/random.h>
#endif

#define RT32_STACK_SIZE (8U * 1024U * 1024U)

/* SPARC Linux AT_* tags used by the Phase-0 initial stack. */
#define SPARC_AT_NULL    0U
#define SPARC_AT_PHDR    3U
#define SPARC_AT_PHENT   4U
#define SPARC_AT_PHNUM   5U
#define SPARC_AT_PAGESZ  6U
#define SPARC_AT_FLAGS   8U
#define SPARC_AT_ENTRY   9U
#define SPARC_AT_UID     11U
#define SPARC_AT_EUID    12U
#define SPARC_AT_GID     13U
#define SPARC_AT_EGID    14U
#define SPARC_AT_HWCAP   16U
#define SPARC_AT_CLKTCK  17U
#define SPARC_AT_SECURE  23U
#define SPARC_AT_RANDOM  25U
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
    uint32_t auxv[34];
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

#ifdef __linux__
    if (getrandom(rand_bytes, sizeof(rand_bytes), 0) != (ssize_t)sizeof(rand_bytes))
#else
    if (0)
#endif
    {
        for (size_t i = 0; i < sizeof(rand_bytes); i++) {
            rand_bytes[i] = (uint8_t)(0xA5U ^ (uint8_t)(i * 17U));
        }
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
    AUXV_PUT(SPARC_AT_ENTRY, elf_info->entry);
    AUXV_PUT(SPARC_AT_UID, (uint32_t)getuid());
    AUXV_PUT(SPARC_AT_EUID, (uint32_t)geteuid());
    AUXV_PUT(SPARC_AT_GID, (uint32_t)getgid());
    AUXV_PUT(SPARC_AT_EGID, (uint32_t)getegid());
    AUXV_PUT(SPARC_AT_HWCAP, 0U);
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

    ctx->guest_argc = argc;
    ctx->guest_argv = guest_argv;
    ctx->host_envp  = host_envp;

    copy_words = aux_idx;
    if (copy_words > (sizeof(ctx->auxv_data) / sizeof(ctx->auxv_data[0]))) {
        copy_words = sizeof(ctx->auxv_data) / sizeof(ctx->auxv_data[0]);
    }
    memcpy(ctx->auxv_data, auxv, copy_words * sizeof(uint32_t));
    ctx->auxv_bytes = copy_words * sizeof(uint32_t);

    *out_sp = final_sp;
    return 0;
}
