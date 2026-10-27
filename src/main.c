/*
 * src/main.c — entry point and option handling for sparc32rt
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 2: --interp runs the reference interpreter, --dbt runs the
 * AArch64 translator (both share load_guest + the syscall/signal loop),
 * --difftest runs the lockstep differential harness.
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
#include "interp/decode.h"
#include "interp/interp.h"
#include "interp/interp_priv.h"
#include "os/syscalls_min.h"
#include "dbt/dbt.h"
#include "dbt/difftest.h"

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

    while (i < argc) {
        if (strcmp(argv[i], "--") == 0) {
            return (i + 1 < argc) ? (i + 1) : -1;
        }
        if (argv[i][0] != '-') {
            return i;
        }
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

    return -1;
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

/* Load the guest ELF + initial stack, then run the reference interpreter
 * until a terminal syscall or a stop reason. Returns the guest exit status. */
/* Shared guest load: reserve window, load ELF, build the stack + argv,
 * install the ABI entry state. Used by --interp, --dbt and --difftest. */
static int load_guest(sparc32_ctx_t *ctx)
{
    rt32_elf_info_t info;
    uint32_t sp;

    rt32_host_probe(ctx);
    if (rt32_vm_init(ctx, UINT64_MAX) != 0) {
        fprintf(stderr, "sparc32rt: cannot reserve the [G, G + 4 GiB) window\n");
        return 1;
    }
    /* Bind the Regime VM (src/vm/vm32.c) to the reserved window so the
     * Soft-TLB tables, page publication, and Provider-A hooks observe
     * the same [G, G + 4 GiB) mapping the rt32 layer just reserved. */
    if (vm32_attach(ctx) != 0) {
        fprintf(stderr, "sparc32rt: cannot attach the Regime VM tables\n");
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
    return 0;
}

/* Safe guest instruction-word fetch for fault classification: reads
 * through the [G, G + 4 GiB) window only when [va, va + 4) is covered by
 * a readable tracked region, and never touches exit state (unlike
 * sparc32_fetch_decode, which would clobber the live fault record). */
static bool sparc32_fault_insn_word(const sparc32_ctx_t *ctx, uint32_t va,
    uint32_t *out)
{
    const uint8_t *p;
    if (out == NULL || !interp_range_ok(ctx, va, 4U, 1U)) {
        return false;
    }
    p = (const uint8_t *)sparc32_guest_ptr(ctx, va);
    *out = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    return true;
}

/*
 * Fault -> signal classification (RC-U3-r2 #2). Both engines report
 * alignment violations as EXIT_FAULT with fault_addr = VA, but
 * (fault_addr & 3) alone cannot see a 4-byte-aligned, 8-byte-misaligned
 * LDD/STD: that fault MUST deliver SIGBUS (10, BUS_ADRALN), never
 * SIGSEGV (11). Decode the faulting instruction (resolving one CTI
 * delay slot, since a faulting delay reports pc at the transfer for
 * JMPL but at the CTI for the other CTI classes) and report SIGBUS
 * only when a doubleword access (LDD/STD/LDDA/STDA) faulted on
 * (va & 7). FP LDDF/STDF are excluded on purpose: the interpreter
 * faults those only as 4-byte halves, so their 4-mod-8 faults are
 * mapping faults (SIGSEGV). Undecodable PCs keep the old heuristic.
 */
static int sparc32_classify_fault(const sparc32_ctx_t *ctx)
{
    uint32_t va = ctx->fault_addr;
    uint32_t pc = ctx->pc;
    uint32_t word;
    sparc32_decoded_t d;
    unsigned depth;
    if ((va & 3U) != 0U) {
        return 10;
    }
    if ((va & 7U) == 0U) {
        return 11;
    }
    for (depth = 0U; depth < 2U; depth++) {
        if (!sparc32_fault_insn_word(ctx, pc, &word)) {
            return 11;
        }
        sparc32_decode_word(word, &d);
        if (d.cls == (uint32_t)SPARC32_OP_CALL ||
            d.cls == (uint32_t)SPARC32_OP_BRANCH ||
            d.cls == (uint32_t)SPARC32_OP_FBRANCH ||
            d.cls == (uint32_t)SPARC32_OP_JMPL ||
            d.cls == (uint32_t)SPARC32_OP_TRAP) {
            pc += 4U;
            continue;
        }
        if (d.op == 3U &&
            (d.op3 == SPARC32_OP3_LDD || d.op3 == SPARC32_OP3_STD ||
             d.op3 == SPARC32_OP3_LDDA || d.op3 == SPARC32_OP3_STDA)) {
            return 10;
        }
        return 11;
    }
    return 11;
}

/* Engine run loop shared by --interp and --dbt: step until a stop, deliver
 * synchronous signals, dispatch syscalls. The step callback is interp_run
 * or a dbt_run shim; both report through ctx->exit_reason. */
typedef void (*engine_step_fn)(sparc32_ctx_t *ctx);

static void engine_interp_step(sparc32_ctx_t *ctx)
{
    interp_run(ctx);
}

static void engine_dbt_step(sparc32_ctx_t *ctx)
{
    (void)dbt_run(ctx);
}

static int run_engine(sparc32_ctx_t *ctx, engine_step_fn step, const char *tag)
{
    if (load_guest(ctx) != 0) {
        return 1;
    }
    for (;;) {
        long nr;
        long status;

        step(ctx);
        if (ctx->exit_reason == SPARC32_EXIT_FAULT ||
            ctx->exit_reason == SPARC32_EXIT_SINGLE_STEP) {
            int signo;
            if (ctx->exit_reason == SPARC32_EXIT_SINGLE_STEP) {
                ctx->fault_addr = ctx->exit_dest;
            }
            signo = sparc32_classify_fault(ctx);
            if (interp_try_deliver_sync(ctx, signo)) {
                continue;
            }
        }
        if (ctx->exit_reason != SPARC32_EXIT_SYSCALL) {
            fprintf(stderr,
                    "sparc32rt: %s stopped: reason=%u pc=0x%08x "
                    "dest=0x%08x fault=0x%08x\n"
                    "  g1=%08x g2=%08x g3=%08x g4=%08x o0=%08x o1=%08x o2=%08x "
                    "sp=%08x cwp=%u\n",
                    tag, ctx->exit_reason, ctx->pc, ctx->exit_dest,
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
        ctx.engine = SPARC32_ENGINE_DBT; /* default DBT engine */
    }
    if (ctx.difftest) {
        if (load_guest(&ctx) != 0) {
            return 1;
        }
        return difftest_run(&ctx);
    }
    if (ctx.engine == SPARC32_ENGINE_INTERP) {
        return run_engine(&ctx, engine_interp_step, "interp");
    }
    return run_engine(&ctx, engine_dbt_step, "dbt");
}
