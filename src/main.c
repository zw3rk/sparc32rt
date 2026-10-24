/*
 * src/main.c — entry point and option handling for sparc32rt
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 1: --interp loads the guest ELF + stack and runs the reference
 * interpreter (run_interp); --dbt still reports Phase 2 and exits 1.
 */

/* POSIX 2008: setenv/environ under strict -std=c11 with musl. */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sparc32rt.h"
#include "rt32/rt32.h"
#include "interp/interp.h"
#include "os/syscalls_min.h"

extern char **environ;

#define SPARC32RT_VERSION "0.0-phase0"

static void usage(FILE *out)
{
    static const char *msg =
        "sparc32rt — SPARC V8 (LEON3/LEON4) Linux user-mode translator\n"
        "\n"
        "Usage:\n"
        "  sparc32rt [--window HEX] [--sysroot DIR]\n"
        "            [--engine interp|dbt] [--difftest] [--trace] -- PATH [ARGV0...]\n"
        "  sparc32rt --help\n"
        "  sparc32rt --version\n"
        "\n"
        "Environment: SPARC32RT_WINDOW, SPARC32RT_SYSROOT, SPARC32RT_ENGINE,\n"
        "             SPARC32RT_TRACE, SPARC32RT_HOST\n";
    fputs(msg, out);
}

static int parse_engine(const char *s, int *out)
{
    if (strcmp(s, "interp") == 0) {
        *out = SPARC32_ENGINE_INTERP;
        return 0;
    }
    if (strcmp(s, "dbt") == 0) {
        *out = SPARC32_ENGINE_DBT;
        return 0;
    }
    return -1;
}

/* Returns the index of the guest PATH in argv[], or -1 on error. */
static int parse_args(sparc32_ctx_t *ctx, int argc, char **argv)
{
    int i = 1;

    while (i < argc && strcmp(argv[i], "--") != 0) {
        if (strcmp(argv[i], "--help") == 0) {
            usage(stdout);
            exit(0);
        }
        if (strcmp(argv[i], "--version") == 0) {
            printf("sparc32rt %s\n", SPARC32RT_VERSION);
            exit(0);
        }
        if (strcmp(argv[i], "--interp") == 0) {
            ctx->engine = SPARC32_ENGINE_INTERP;
            i += 1;
            continue;
        }
        if (strcmp(argv[i], "--dbt") == 0) {
            ctx->engine = SPARC32_ENGINE_DBT;
            i += 1;
            continue;
        }
        if (strcmp(argv[i], "--difftest") == 0) {
            ctx->difftest = true;
            i += 1;
            continue;
        }
        if (strcmp(argv[i], "--trace") == 0) {
            ctx->trace_enabled = true;
            i += 1;
            continue;
        }
        if (i + 1 >= argc) {
            return -1;
        }
        if (strcmp(argv[i], "--window") == 0) {
            char *end = NULL;
            unsigned long long v = strtoull(argv[i + 1], &end, 0);
            if (end == argv[i + 1] || *end != '\0') {
                return -1;
            }
            (void)v;
            /* Stored via SPARC32RT_WINDOW; consumed by vm init later. */
            setenv("SPARC32RT_WINDOW", argv[i + 1], 1);
        } else if (strcmp(argv[i], "--sysroot") == 0) {
            ctx->sysroot = argv[i + 1];
        } else if (strcmp(argv[i], "--engine") == 0) {
            if (parse_engine(argv[i + 1], &ctx->engine) != 0) {
                return -1;
            }
        } else {
            return -1;
        }
        i += 2;
    }

    if (i >= argc) {
        return -1; /* missing "-- PATH" */
    }
    return i + 1; /* first token after "--" */
}

static void apply_env(sparc32_ctx_t *ctx)
{
    const char *s;

    if (ctx->engine == SPARC32_ENGINE_DBT || ctx->engine == SPARC32_ENGINE_INTERP) {
        /* Already set explicitly by --interp/--dbt/--engine; env must not override. */
    } else if ((s = getenv("SPARC32RT_ENGINE")) != NULL) {
        if (parse_engine(s, &ctx->engine) != 0) {
            fprintf(stderr, "sparc32rt: bad SPARC32RT_ENGINE=%s\n", s);
            exit(2);
        }
    }
    if (!ctx->trace_enabled && (s = getenv("SPARC32RT_TRACE")) != NULL && s[0] != '\0' &&
        strcmp(s, "0") != 0) {
        ctx->trace_enabled = true;
    }
    if (ctx->sysroot == NULL && (s = getenv("SPARC32RT_SYSROOT")) != NULL) {
        ctx->sysroot = s;
    }
    /* SPARC32RT_HOST=none opts out of the /dev/a32host handshake. */
    if ((s = getenv("SPARC32RT_HOST")) != NULL && strcmp(s, "none") == 0) {
        ctx->has_host_info = false;
    }
}

static const char *engine_name(int engine)
{
    return (engine == SPARC32_ENGINE_DBT) ? "dbt" : "interp";
}

/* Load the guest ELF + initial stack, then run the reference interpreter
 * until a terminal syscall or a stop reason. Returns the guest exit status. */
static int run_interp(sparc32_ctx_t *ctx)
{
    rt32_elf_info_t info;
    uint32_t sp;

    rt32_host_probe(ctx);
    if (rt32_vm_init(ctx, UINT64_MAX) != 0) {
        fprintf(stderr, "sparc32rt: cannot reserve the [G, G + 4 GiB) window\n");
        return 1;
    }
    if (rt32_elf_load(ctx, -1, ctx->exec_path, &info) != 0) {
        fprintf(stderr, "sparc32rt: cannot load '%s'\n", ctx->exec_path);
        return 1;
    }
    if (rt32_stack_setup(ctx, &info, ctx->guest_argc, ctx->guest_argv,
                         ctx->host_envp, &sp) != 0) {
        fprintf(stderr, "sparc32rt: cannot set up the guest stack\n");
        return 1;
    }
    /* E01: argc sits at [%sp + 64). stack_setup lays the stack out for
     * exactly the returned sp; pass it through unmasked. */
    ctx->r[SPARC32_SP] = sp;
    /* Fresh window state (E01): CWP=0 with window 0 WIM-marked, so the
     * first SAVE 0->7 rotates free and the first RESTORE 7->0 underfills
     * l/i from [post-restore sp]. */
    ctx->cwp = 0U;
    interp_window_reset();
    ctx->pc  = info.entry;
    ctx->npc = info.entry + 4U;
    if (ctx->trace_enabled) {
        size_t i;
        fprintf(stderr, "T entry=%08x sp=%08x regions=%zu\n", info.entry, sp,
                ctx->region_count);
        for (i = 0; i < ctx->region_count; i++) {
            fprintf(stderr, "T region %08x..%08x prot=%x %s\n",
                    ctx->regions[i].start, ctx->regions[i].end,
                    ctx->regions[i].prot, ctx->regions[i].name);
        }
    }
    for (;;) {
        long nr;
        long status;

        interp_run(ctx);
        if (ctx->exit_reason == SPARC32_EXIT_FAULT ||
            ctx->exit_reason == SPARC32_EXIT_SINGLE_STEP) {
            int signo;
            if (ctx->exit_reason == SPARC32_EXIT_SINGLE_STEP) {
                ctx->fault_addr = ctx->exit_dest;
            }
            signo = (ctx->fault_addr & 3U) != 0U ? 10 : 11;
            if (interp_try_deliver_sync(ctx, signo)) {
                continue;
            }
        }
        if (ctx->exit_reason != SPARC32_EXIT_SYSCALL) {
            fprintf(stderr,
                    "sparc32rt: interp stopped: reason=%u pc=0x%08x "
                    "dest=0x%08x fault=0x%08x\n"
                    "  g1=%08x g2=%08x g3=%08x g4=%08x o0=%08x o1=%08x o2=%08x "
                    "sp=%08x cwp=%u\n",
                    ctx->exit_reason, ctx->pc, ctx->exit_dest,
                    ctx->fault_addr, ctx->r[1], ctx->r[2], ctx->r[3],
                    ctx->r[4], ctx->r[8], ctx->r[9], ctx->r[10],
                    ctx->r[SPARC32_SP], ctx->cwp);
            return 1;
        }
        nr = (long)(int32_t)ctx->r[SPARC32_G1];
        status = sparc32_handle_syscall(ctx);
        if (sparc32_syscall_is_exit(nr)) {
            return (int)(status & 0xFFL);
        }
    }
}

int main(int argc, char **argv)
{
    sparc32_ctx_t ctx;
    int path_idx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.engine   = -1; /* unset: --interp/--dbt/--engine or SPARC32RT_ENGINE */
    ctx.nwindows = SPARC32_NWINDOWS;

    path_idx = parse_args(&ctx, argc, argv);
    if (path_idx < 0) {
        usage(stderr);
        return 2;
    }
    apply_env(&ctx);
    ctx.exec_path = argv[path_idx];
    ctx.guest_argc = argc - path_idx;
    ctx.guest_argv = &argv[path_idx];
    ctx.host_envp = environ;

    if (ctx.engine < 0) {
        ctx.engine = SPARC32_ENGINE_INTERP; /* default oracle engine */
    }
    if (ctx.difftest) {
        fprintf(stderr,
                "sparc32rt: --difftest needs interp (Phase 1) and dbt (Phase 2); "
                "dbt arrives in Phase 2\n");
        return 1;
    }
    if (ctx.engine == SPARC32_ENGINE_INTERP) {
        return run_interp(&ctx);
    }
    fprintf(stderr, "sparc32rt: engine %s selected; guest execution arrives "
                    "in Phase 2 (not executing %s)\n",
            engine_name(ctx.engine), ctx.exec_path);
    return 1;
}
