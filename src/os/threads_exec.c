/*
 * src/os/threads_exec.c — execve(59) process-image replacement (Phase 4, L4a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from threads.c for the 900-line file discipline. Reloads an ELF
 * into the same G window, rebuilds the stack/argv/envp, resets windows,
 * dispositions, pending signals and thread state for the new image.
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sparc32rt.h"

#include "interp/interp.h"
#include "os/l2a_access.h"
#include "os/syscalls_min.h"
#include "os/threads.h"
#include "rt32/rt32.h"

/* execve staging caps (moved with the block from threads.c). */
#define THR_EXEC_ARGS_MAX 256U
#define THR_EXEC_STR_MAX 4096U

/* Checked guest word load (moved with the exec block; sole user). */
static int thr_ld(sparc32_ctx_t *ctx, uint32_t va, uint32_t *out)
{
    uint8_t p[4];
    if (l2a_load(ctx, va, p, 4U) != 0) {
        return -EFAULT;
    }
    *out = get_be32(p);
    return 0;
}

/* execve(59): reload an ELF into the same G window (dispositions reset
 * via sparc32_signal_reset_all; stale handler VAs fault fail-closed).
 * FDs stay open (no CLOEXEC table yet; RC-H). */
static int thr_read_cstr(sparc32_ctx_t *ctx, uint32_t va, char *out,
    size_t cap)
{
    long rc = l2a_copy_cstring(ctx, va, out, (uint32_t)cap);
    return (int)rc;
}

static void thr_free_vec(char **v, size_t n);

static int thr_read_vec(sparc32_ctx_t *ctx, uint32_t vec_va, char **out,
    size_t cap, size_t *count)
{
    size_t n = 0U;
    uint32_t va = vec_va;
    *count = 0U;
    if (vec_va == 0U) {
        out[0] = NULL;
        return 0;
    }
    for (;;) {
        uint32_t eva;
        char *s;
        if (thr_ld(ctx, va, &eva) != 0) {
            thr_free_vec(out, n);
            return -EFAULT;
        }
        if (eva == 0U) {
            out[n] = NULL;
            *count = n;
            return 0;
        }
        if (n + 1U >= cap) {
            thr_free_vec(out, n);
            return -E2BIG;
        }
        s = (char *)malloc(THR_EXEC_STR_MAX);
        if (s == NULL) {
            thr_free_vec(out, n);
            return -ENOMEM;
        }
        {
            int s_rc = thr_read_cstr(ctx, eva, s, THR_EXEC_STR_MAX);
            if (s_rc != 0) {
                free(s);
                thr_free_vec(out, n);
                return s_rc;
            }
        }
        out[n++] = s;
        va += 4U;
    }
}

static void thr_free_vec(char **v, size_t n)
{
    size_t i;
    for (i = 0U; i < n; i++) {
        free(v[i]);
    }
}

long sparc32_thr_execve(sparc32_ctx_t *ctx, uint32_t path_va,
    uint32_t argv_va, uint32_t envp_va)
{
    rt32_elf_info_t info;
    char path[THR_EXEC_STR_MAX];
    char *argv[THR_EXEC_ARGS_MAX];
    char *envp[THR_EXEC_ARGS_MAX];
    size_t argc = 0U;
    size_t envc = 0U;
    uint32_t sp;
    size_t i;
    int rc;
    sparc32_threads_ensure_init(ctx);
    if (ctx == NULL) {
        return -EFAULT;
    }
    rc = thr_read_cstr(ctx, path_va, path, sizeof(path));
    if (rc != 0) {
        return rc;
    }
    if (path[0] == '\0') {
        return -ENOENT;
    }
    /* thr_read_vec frees its own partials on error and NULL-terminates
     * on success, so the vectors are always stack_setup-ready here. */
    rc = thr_read_vec(ctx, argv_va, argv, THR_EXEC_ARGS_MAX, &argc);
    if (rc != 0) {
        return rc;
    }
    rc = thr_read_vec(ctx, envp_va, envp, THR_EXEC_ARGS_MAX, &envc);
    if (rc != 0) {
        thr_free_vec(argv, argc);
        return rc;
    }
    /* Prepare and retain validated ELF + PT_INTERP descriptors and load
     * biases before mutating signal dispositions or tearing down the
     * caller's address space. */
    {
        rt32_elf_plan_t plan;
        rc = rt32_elf_prepare(ctx, -1, path, &plan);
        if (rc != 0) {
            thr_free_vec(argv, argc);
            thr_free_vec(envp, envc);
            return rc;
        }
        /* Point of no return: reset signal dispositions and replace the
         * guest VM image from the retained open descriptors. Any host
         * mapping failure after destroying the old VM terminates the
         * process fatally rather than returning to an unmapped caller. */
        sparc32_signal_reset_all();
        rt32_vm_reset_for_exec(ctx);
        rc = rt32_elf_commit_plan(ctx, &plan, &info);
        if (rc != 0) {
            thr_free_vec(argv, argc);
            thr_free_vec(envp, envc);
            _exit(127);
        }
    }
    rc = rt32_stack_setup(ctx, &info, (int)argc, argv, envp, &sp);
    thr_free_vec(argv, argc);
    thr_free_vec(envp, envc);
    if (rc != 0) {
        _exit(127);
    }
    /* Fresh-process CPU state (mirrors main.c load_guest entry). */
    for (i = 0U; i < 32U; i++) {
        ctx->r[i] = 0U;
        ctx->f[i] = 0U;
    }
    ctx->y = 0U;
    ctx->psr = 0U;
    ctx->fsr = 0U;
    ctx->cwp = 0U;
    ctx->cansave = 0U;
    ctx->canrestore = 0U;
    ctx->otherwin = 0U;
    ctx->cleanwin = 0U;
    ctx->r[SPARC32_SP] = sp;
    interp_window_reset();
    ctx->pending_signals = 0U;
    ctx->sig_mask = 0U;
    ctx->sync_sig_delivered = false;
    ctx->sig_last_frame_va = 0U;
    ctx->sig_last_frame_rt = 0U;
    ctx->exit_reason = SPARC32_EXIT_NONE;
    ctx->exit_arg = 0U;
    ctx->clear_child_tid = 0U;
    ctx->robust_list_head = 0U;
    ctx->robust_list_len = 0U;
    ctx->is_thread_clone = false;
    ctx->exec_path = NULL;
    /* Pre-compensate for the dispatch tail (pc = npc; npc += 4). */
    ctx->pc = info.entry - 4U;
    ctx->npc = info.entry;
    return 0;
}
