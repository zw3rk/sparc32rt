/*
 * tests/check_thread_entry.c — host-runnable L4b thread-entry checks
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L4b (Phase 4): proves the host-thread entry trampoline
 * (src/rt32/thread_entry.S) establishes the translated-code register
 * conventions on any host thread and reports exits identically to the main
 * dispatcher entry (src/dbt/trampoline_a64.S):
 *   x19 = ctx, x20 = G (ctx->guest_base), x25 = prot-table base, NZCV = 0,
 *   SP 16-aligned at fragment entry; w16 -> ctx->exit_reason,
 *   w15 -> ctx->exit_dest, and the
 *   x24 chain_hits delta folded into ctx->chain_hits on return; x27/x28
 *   carry the chaining registers (block: live epoch word; step: zero word
 *   so epoch-gated chain probes bail).
 *
 * Method: a synthetic probe fragment (AArch64 asm below) records the entry
 * registers into a record area, samples the word under x28 (the epoch
 * probe target), bumps x24 by a known delta, then returns a fixed
 * (dest, reason) exit. The record area travels as the opaque x27/chain
 * slot (real fragments use that slot as the cache entry; the probe never
 * dereferences x27 as one), and a known epoch word travels as the x28
 * slot, so both chaining registers are observable. Host flags are poisoned
 * (all NZCV set) before every entry to prove the trampoline clears them.
 * Runs on the main thread and on a fresh pthread. Requires an AArch64
 * host; other hosts run the compile-time + offsetof pins only and SKIP.
 *
 * The D18 safe_syscall window itself is a Linux-target property (an svc
 * cannot execute on this host); it is covered by the cross-build plus the
 * --dbt no-regression runs, and this TU pins the ctx offsets both sides
 * share. x18 preservation is checked at runtime on Darwin (where the
 * compiler never allocates the platform register) and by source grepping
 * (no x18 in the rt32 assembly sources) on every host.
 *
 * Build: cc -std=c11 -D_POSIX_C_SOURCE=200809L -Werror=vla -pedantic \
 *          -Wall -Wextra -Werror -Iinclude -Isrc \
 *          tests/check_thread_entry.c src/rt32/thread_entry.S \
 *          -o _build/check_thread_entry -pthread
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sparc32rt.h"

#if defined(__aarch64__)
#include <pthread.h>
#endif

/* Entry points under test (src/rt32/thread_entry.S). Signatures mirror
 * dbt_enter_block/dbt_enter_step (src/dbt/dbt.h). */
extern void rt32_thread_enter_block(sparc32_ctx_t *ctx, const void *entry,
    const void *chain_entry, const uint32_t *epoch_ptr);
extern void rt32_thread_enter_step(sparc32_ctx_t *ctx, const void *entry,
    const void *chain_entry);

static int failures = 0;

/* S32-R8-7 anchor: THREAD_CORE installs x25 = g_vm32_prot_jit (owned by
 * src/vm/vm32.c in the full binary); this standalone probe TU provides
 * the table itself so the link holds and the probe can verify x25. */
static uint8_t tentry_prot_table[16];
uint8_t *g_vm32_prot_jit = tentry_prot_table;

#define EXPECT(tag, cond)                                                     \
    do {                                                                      \
        if (!(cond)) {                                                        \
            printf("FAIL %s: %s (line %d)\n", tag, #cond, __LINE__);         \
            ++failures;                                                       \
        }                                                                     \
    } while (0)

#define CHECK_OFF(type, member, expect)                                       \
    do {                                                                      \
        size_t got = offsetof(type, member);                                  \
        if (got != (size_t)(expect)) {                                        \
            printf("FAIL %s.%s: got %lu want %lu\n", #type, #member,         \
                (unsigned long)got, (unsigned long)(expect));                 \
            ++failures;                                                       \
        }                                                                     \
    } while (0)

/* Compile-time pins (duplicate the frozen header offsets from the consumer
 * side so a silent header edit breaks this TU too). */
_Static_assert(offsetof(sparc32_ctx_t, guest_base) == 0x130, "ctx.guest_base");
_Static_assert(offsetof(sparc32_ctx_t, exit_reason) == 0x138, "ctx.reason");
_Static_assert(offsetof(sparc32_ctx_t, exit_dest) == 0x144, "ctx.dest");
_Static_assert(offsetof(sparc32_ctx_t, chain_hits) == 0x168, "ctx.chain");

static void check_offsets(void)
{
    CHECK_OFF(sparc32_ctx_t, guest_base, 0x130);
    CHECK_OFF(sparc32_ctx_t, exit_reason, 0x138);
    CHECK_OFF(sparc32_ctx_t, exit_dest, 0x144);
    CHECK_OFF(sparc32_ctx_t, chain_hits, 0x168);
}

#if defined(__aarch64__)

/* Probe record area. Offsets match the immediates in tentry_probe below. */
struct tentry_rec {
    uint64_t ctx_seen;   /* +0:  x19 at fragment entry */
    uint64_t g_seen;     /* +8:  x20 at fragment entry */
    uint64_t nzcv;       /* +16: host NZCV at fragment entry */
    uint64_t sp_residue; /* +24: SP mod 16 at fragment entry (want 0) */
    uint64_t x27_seen;   /* +32: x27 at fragment entry */
    uint64_t x28_seen;   /* +40: x28 at fragment entry */
    uint32_t epoch_word; /* +48: word under x28 (epoch probe target) */
    uint32_t pad;        /* +52 */
    uint64_t x25_seen;   /* +56: x25 (prot-table base) at fragment entry */
};

_Static_assert(offsetof(struct tentry_rec, ctx_seen) == 0, "rec.ctx");
_Static_assert(offsetof(struct tentry_rec, g_seen) == 8, "rec.g");
_Static_assert(offsetof(struct tentry_rec, nzcv) == 16, "rec.nzcv");
_Static_assert(offsetof(struct tentry_rec, sp_residue) == 24, "rec.sp");
_Static_assert(offsetof(struct tentry_rec, x27_seen) == 32, "rec.x27");
_Static_assert(offsetof(struct tentry_rec, x28_seen) == 40, "rec.x28");
_Static_assert(offsetof(struct tentry_rec, epoch_word) == 48, "rec.epoch");
_Static_assert(offsetof(struct tentry_rec, x25_seen) == 56, "rec.x25");

#ifdef __APPLE__
#define TENTRY_ASM_NAME(x) "_" #x
#else
#define TENTRY_ASM_NAME(x) #x
#endif

/* Synthetic fragment: records entry state, samples [x28], bumps the
 * chain_hits delta, and exits with (dest 0x1000, reason BRANCH=1) — the
 * same w15/w16 exit protocol real emitted fragments use. Uses x2 (the
 * opaque chain slot, which the trampoline preserves into the fragment) as
 * the record base and x4 as the only scratch; touches no stack and never
 * x18. Only assembled on AArch64 hosts. */
__asm__(
".text\n"
"  .align 2\n"
"  .globl " TENTRY_ASM_NAME(tentry_probe) "\n"
TENTRY_ASM_NAME(tentry_probe) ":\n"
"  str x19, [x2, #0]\n"
"  str x20, [x2, #8]\n"
"  mrs x4, nzcv\n"
"  str x4, [x2, #16]\n"
"  mov x4, sp\n"
"  and x4, x4, #15\n"
"  str x4, [x2, #24]\n"
"  str x27, [x2, #32]\n"
"  str x28, [x2, #40]\n"
"  ldr w4, [x28]\n"
"  str w4, [x2, #48]\n"
"  str x25, [x2, #56]\n"
"  add x24, x24, #7\n"
"  movz w15, #0x1000\n"
"  movz w16, #1\n"
"  ret\n");

extern void tentry_probe(void);

#define TENTRY_WANT_G     0x0000ABCD12340000ULL
#define TENTRY_WANT_CHAIN 1000U
#define TENTRY_CHAIN_DELTA 7U
#define TENTRY_WANT_DEST  0x1000U
#define TENTRY_WANT_EXIT  1U /* SPARC32_EXIT_BRANCH, same value the main entry reports */
#define TENTRY_EPOCH_WORD 0xA5A5A5A5U

/* Poison host NZCV (set all four flags) so the probe can prove the entry
 * cleared them. Volatile: the following C call must not cross it. At the
 * call there are only moves between here and the bl, so no compiler-
 * emitted flag setter can intervene; a violation would fail loudly below. */
static void tentry_poison_host_flags(void)
{
    __asm__ volatile(
        "movz x9, #0xf000, lsl #16\n"
        "msr nzcv, x9\n"
        ::: "x9", "cc");
}

static void tentry_dump_rec(const struct tentry_rec *r)
{
    printf("  rec: ctx=%llx g=%llx nzcv=%llx sp_res=%llu x27=%llx x28=%llx epoch=%lx x25=%llx\n",
        (unsigned long long)r->ctx_seen, (unsigned long long)r->g_seen,
        (unsigned long long)r->nzcv, (unsigned long long)r->sp_residue,
        (unsigned long long)r->x27_seen, (unsigned long long)r->x28_seen,
        (unsigned long)r->epoch_word, (unsigned long long)r->x25_seen);
}

static void run_entry(const char *tag, int use_step)
{
    /* Static: sparc32_ctx_t is ~80 KiB, too big for casual stack use. */
    static sparc32_ctx_t ctx;
    static struct tentry_rec rec;
    uint32_t epoch = (uint32_t)TENTRY_EPOCH_WORD;
    int before = failures;

    memset(&ctx, 0, sizeof(ctx));
    memset(&rec, 0, sizeof(rec));
    ctx.guest_base = (uint64_t)TENTRY_WANT_G;
    ctx.chain_hits = (uint64_t)TENTRY_WANT_CHAIN;
    ctx.exit_reason = 0xFFFFFFFFU;
    ctx.exit_dest = 0xEEEEEEEEU;

    tentry_poison_host_flags();
    if (use_step != 0) {
        rt32_thread_enter_step(&ctx, (const void *)tentry_probe,
            (const void *)&rec);
    } else {
        rt32_thread_enter_block(&ctx, (const void *)tentry_probe,
            (const void *)&rec, &epoch);
    }

    EXPECT(tag, rec.ctx_seen == (uint64_t)(uintptr_t)&ctx);
    EXPECT(tag, rec.g_seen == (uint64_t)TENTRY_WANT_G);
    EXPECT(tag, rec.x25_seen == (uint64_t)(uintptr_t)tentry_prot_table);
    EXPECT(tag, rec.nzcv == 0U);
    EXPECT(tag, rec.sp_residue == 0U);
    EXPECT(tag, rec.x27_seen == (uint64_t)(uintptr_t)&rec);
    if (use_step != 0) {
        /* Step entry installs its own stack-resident zero word, never x3. */
        EXPECT(tag, rec.epoch_word == 0U);
        EXPECT(tag, rec.x28_seen != (uint64_t)(uintptr_t)&epoch);
    } else {
        EXPECT(tag, rec.x28_seen == (uint64_t)(uintptr_t)&epoch);
        EXPECT(tag, rec.epoch_word == (uint32_t)TENTRY_EPOCH_WORD);
    }
    /* Exit reporting identical to the main dispatcher entry: w16/w15 land
     * in exit_reason/exit_dest and the x24 delta folds into chain_hits. */
    EXPECT(tag, ctx.exit_reason == (uint32_t)TENTRY_WANT_EXIT);
    EXPECT(tag, ctx.exit_dest == (uint32_t)TENTRY_WANT_DEST);
    EXPECT(tag, ctx.chain_hits == (uint64_t)(TENTRY_WANT_CHAIN + TENTRY_CHAIN_DELTA));
    if (failures != before) {
        tentry_dump_rec(&rec);
        printf("  ctx: reason=%lu dest=%lx chain=%llu\n",
            (unsigned long)ctx.exit_reason, (unsigned long)ctx.exit_dest,
            (unsigned long long)ctx.chain_hits);
    }
}

#if defined(__APPLE__)
/* x18 preservation. x18 is platform-reserved on Darwin so the compiler
 * never allocates it; setting/reading it around the call needs no clobber
 * dance, and any trampoline write to x18 shows up as a mismatch. This
 * detector is Darwin-only: on Linux AArch64 the compiler may hold live
 * values in x18 across the call. */
static void run_x18(const char *tag)
{
    static sparc32_ctx_t ctx;
    static struct tentry_rec rec;
    uint32_t epoch = (uint32_t)TENTRY_EPOCH_WORD;
    uint64_t sentinel = 0x5A5A5A5A5A5A5A5AULL;
    uint64_t after = 0U;

    memset(&ctx, 0, sizeof(ctx));
    memset(&rec, 0, sizeof(rec));
    ctx.guest_base = (uint64_t)TENTRY_WANT_G;
    __asm__ volatile("mov x18, %0" :: "r"(sentinel) : "memory");
    rt32_thread_enter_block(&ctx, (const void *)tentry_probe,
        (const void *)&rec, &epoch);
    __asm__ volatile("mov %0, x18" : "=r"(after));
    EXPECT(tag, after == sentinel);
}
#endif

struct tentry_thread_arg {
    int use_step;
    int ok;
};

static void *tentry_thread_main(void *p)
{
    struct tentry_thread_arg *a = (struct tentry_thread_arg *)p;
    int before = failures;
    run_entry(a->use_step != 0 ? "pthread-step" : "pthread-block",
        a->use_step);
    a->ok = (failures == before);
    return NULL;
}

static void run_pthread(const char *tag, int use_step)
{
    struct tentry_thread_arg arg;
    pthread_t th;
    int rc;

    arg.use_step = use_step;
    arg.ok = 0;
    rc = pthread_create(&th, NULL, tentry_thread_main, &arg);
    EXPECT(tag, rc == 0);
    if (rc != 0) {
        return;
    }
    rc = pthread_join(th, NULL);
    EXPECT(tag, rc == 0);
    EXPECT(tag, arg.ok != 0);
}

#endif /* defined(__aarch64__) */

int main(void)
{
    check_offsets();
#if defined(__aarch64__)
    run_entry("main-block", 0);
    run_entry("main-step", 1);
#if defined(__APPLE__)
    run_x18("main-x18");
#endif
    run_pthread("pthread-block", 0);
    run_pthread("pthread-step", 1);
    if (failures != 0) {
        printf("FAILURES: %d\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
#else
    printf("SKIP (entry trampoline needs an AArch64 host)\n");
    return failures != 0 ? 1 : 0;
#endif
}
