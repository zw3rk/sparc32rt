/*
 * src/dbt/dbt.c — AArch64 DBT core: dispatcher, block cache, IBTC, RAS
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 2 lane L2b (SPEC sections 2-3, docs/lanes/phase-2.md). The block
 * cache, W^X code arena, direct-chaining dispatcher, IBTC, and RAS live
 * here; integer lowering is L2c's src/dbt/emit_int.h, wired here through
 * its real interface (sparc32_emit_ctx_t + sparc32_emit_insn, with
 * sparc32_emit_exit_singlestep for the page-final rule). Emitted BLR
 * helpers run the shared interp window/memory model (interp_priv.h via
 * L2c's emit_priv.h); this unit carries no translator-local duplicate of
 * that model, so interp and dbt observe one window/history for difftest.
 *
 * Exit reporting: every emitted exit carries the resume/fault guest PC in
 * w15 and the SPARC32_EXIT_* reason in w16; the trampoline stores them to
 * ctx->exit_dest/ctx->exit_reason and dbt_commit fixes up pc/npc from
 * them. EXIT_UNDEF / EXIT_SINGLE_STEP from emitted code are pristine
 * (exit_dest is the faulting insn, no guest state changed, except for
 * idempotent link writes), so the dispatcher replays one interp_step at
 * the exit PC. IBTC stays at the frozen SPARC32_IBTC_SIZE (1024).
 *
 * Invariants: every file <= 900 lines; curated C11 (no VLAs); guest
 * memory only through sparc32_fetch_decode region checks; guest data
 * pages never PROT_EXEC (the arena is anonymous host memory outside
 * [G, G + 4 GiB)); no x18 anywhere (no inline asm at all).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "sparc32rt.h"
#include "dbt/dbt.h"
#include "dbt/emit_int.h"
#include "interp/decode.h"
#include "interp/interp.h"
#include "rt32/a64_emit.h"

#ifndef MAP_ANONYMOUS
#ifdef MAP_ANON
#define MAP_ANONYMOUS MAP_ANON
#else
#define MAP_ANONYMOUS 0x20
#endif
#endif

/* ---- Chaining entries (asm layout contract with a64_emit_fp.c) ----
 * exit_branch slot probes read [x27, #(152 + s*8)] and chain targets as
 * {key|epoch @ +0, host_code @ +8} pairs (the same 16-byte prefix the
 * RAS-pop/IBTC-hit paths load from ctx entries). Slots stay NULL in
 * Phase 2, so every probe bails to the C dispatcher, which chains in
 * software; x27 must nonetheless point at a readable entry because the
 * probes dereference it unconditionally. One entry per cache slot. */
typedef struct {
    uint64_t    key_epoch;   /* +0: guest key | (uint64_t)epoch << 32 */
    const void *host_code;   /* +8 */
    uint8_t     pad[136];    /* +16..+151 */
    const void *slots[8];    /* +152..+215, always NULL in Phase 2 */
} dbt_chain_t;

_Static_assert(sizeof(dbt_chain_t) == 216,
    "dbt_chain_t must be 216 bytes");
_Static_assert(offsetof(dbt_chain_t, slots) == 152,
    "dbt_chain_t slots must start at +152");

/* ---- Block cache (direct-mapped, keyed by guest PC identity) ---- */

static dbt_block_t g_blocks[DBT_CACHE_SIZE];
static dbt_chain_t g_chain[DBT_CACHE_SIZE];
static uint32_t g_cache_epoch;
static uint32_t g_cached_count;

/* (dbt_enter_step's zero epoch word lives in trampoline_a64.S rodata, so
 * no cross-TU symbol is needed for the no-chain path.) */

static uint32_t dbt_cache_index(uint32_t pc)
{
    return (pc >> 2U) & (DBT_CACHE_SIZE - 1U);
}

/* ---- W^X code arena (anonymous host memory, outside the G window) ---- */

static uint8_t *g_arena_base;
static size_t g_arena_used;
static bool g_arena_published;

static size_t dbt_page_span(void)
{
    long page = sysconf(_SC_PAGESIZE);
    size_t p;
    if (page <= 0) {
        page = 4096;
    }
    p = (size_t)page;
    return (g_arena_used + p - 1U) & ~(p - 1U);
}

static void dbt_arena_reset(void)
{
    if (g_arena_base != NULL) {
        munmap((void *)g_arena_base, DBT_CODE_ARENA_SIZE);
    }
    g_arena_base = NULL;
    g_arena_used = 0;
    g_arena_published = false;
}

/* Ensure the arena exists and is writable (reopening RW after a publish;
 * W^X is never violated: RX and RW are strictly sequential). */
static bool dbt_arena_ensure_rw(sparc32_ctx_t *ctx)
{
    if (g_arena_base == NULL) {
        void *p = mmap(NULL, DBT_CODE_ARENA_SIZE,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            return false;
        }
        g_arena_base = (uint8_t *)p;
        g_arena_used = 0;
        g_arena_published = false;
        return true;
    }
    if (g_arena_published) {
        if (mprotect((void *)g_arena_base, dbt_page_span(),
                PROT_READ | PROT_WRITE) != 0) {
            return false;
        }
        g_arena_published = false;
        if (ctx != NULL) {
            ctx->wx_transitions += 1U;
        }
    }
    return true;
}

uint32_t *dbt_code_reserve(sparc32_ctx_t *ctx, size_t n_words)
{
    size_t bytes;
    uint32_t *out;
    if (n_words == 0U) {
        return NULL;
    }
    if (!dbt_arena_ensure_rw(ctx)) {
        return NULL;
    }
    bytes = n_words * sizeof(uint32_t);
    if (bytes > DBT_CODE_ARENA_SIZE - g_arena_used) {
        return NULL;
    }
    out = (uint32_t *)(g_arena_base + g_arena_used);
    g_arena_used += bytes;
    return out;
}

int dbt_code_publish(sparc32_ctx_t *ctx)
{
    size_t span;
    if (g_arena_base == NULL || g_arena_used == 0U) {
        return 0;
    }
    if (g_arena_published) {
        return 0;
    }
    span = dbt_page_span();
    if (mprotect((void *)g_arena_base, span, PROT_READ | PROT_EXEC) != 0) {
        return -1;
    }
    __builtin___clear_cache((char *)g_arena_base,
        (char *)g_arena_base + g_arena_used);
    g_arena_published = true;
    if (ctx != NULL) {
        ctx->wx_transitions += 1U;
        ctx->icache_flushes += 1U;
    }
    return 0;
}

/* ---- Decode helpers ---- */

static bool dbt_is_cti(const sparc32_decoded_t *d)
{
    return d->cls == (uint32_t)SPARC32_OP_CALL ||
        d->cls == (uint32_t)SPARC32_OP_BRANCH ||
        d->cls == (uint32_t)SPARC32_OP_FBRANCH ||
        d->cls == (uint32_t)SPARC32_OP_JMPL;
}

/* Block terminators. The emitter always terminates these fragments with
 * an exit (or chains away), so ending the block here is exact: BN
 * (cond 0) and untaken Ticc emit no exit and must fall through into
 * subsequently emitted code. */
/* Straight-line classes need a translate-level fallthrough exit when a
 * block ends on them (insn cap, page edge, single-insn dbt_step). CTI and
 * conditional-trap emitters terminate their own taken/not-taken paths;
 * unconditional transfers (BA/CALL/JMPL/TA) never fall through; PRIV
 * always exits via trap; FPU/ILL never execute (interp fallback). */
static bool dbt_falls_through(const sparc32_decoded_t *d)
{
    switch (d->cls) {
    case SPARC32_OP_CALL:
    case SPARC32_OP_JMPL:
    case SPARC32_OP_BRANCH:
    case SPARC32_OP_TRAP:
    case SPARC32_OP_PRIV:
    case SPARC32_OP_FPU:
    case SPARC32_OP_ILLEGAL:
        return false;
    default:
        return true;
    }
}

static bool dbt_block_ends(const sparc32_decoded_t *d)
{
    switch (d->cls) {
    case SPARC32_OP_CALL:
    case SPARC32_OP_JMPL:
    case SPARC32_OP_PRIV:
    case SPARC32_OP_FPU:
    case SPARC32_OP_ILLEGAL:
        return true;
    case SPARC32_OP_BRANCH:
    case SPARC32_OP_FBRANCH:
        return d->cond != 0U;
    case SPARC32_OP_TRAP:
        return d->cond == 8U;
    default:
        return false;
    }
}

/* ---- Translation: decode, emit, install ---- */

static const dbt_block_t *dbt_translate(sparc32_ctx_t *ctx, uint32_t pc,
    bool single)
{
    uint32_t idx = dbt_cache_index(pc);
    dbt_block_t *b = &g_blocks[idx];
    dbt_chain_t *ch = &g_chain[idx];
    uint32_t *mem;
    a64_buf_t buf;
    uint32_t cap;
    uint32_t cur = pc;
    uint32_t n = 0U;
    uint32_t end = pc;
    sparc32_decoded_t last;
    bool overflow = false;
    bool have_insn = false;
    uint32_t limit = single ? 1U : (uint32_t)DBT_MAX_INSNS_PER_BLOCK;

    mem = dbt_code_reserve(ctx,
        single ? (size_t)DBT_STEP_RESERVE_WORDS
               : (size_t)DBT_BLOCK_RESERVE_WORDS);
    if (mem == NULL) {
        /* Code cache full: drop all translations once and retry. A
         * second failure means mmap itself is broken: report it through
         * the normal lookup failure path (caller sets FAULT). */
        dbt_flush(ctx);
        mem = dbt_code_reserve(ctx,
            single ? (size_t)DBT_STEP_RESERVE_WORDS
                   : (size_t)DBT_BLOCK_RESERVE_WORDS);
        if (mem == NULL) {
            return NULL;
        }
    }
    cap = single ? (uint32_t)DBT_STEP_RESERVE_WORDS
                 : (uint32_t)DBT_BLOCK_RESERVE_WORDS;
    a64_buf_init(&buf, mem, (size_t)cap);
    /* Step fragments disable the self-loop fast path (guest_start_pc 0)
     * so a single-insn `ba .` cannot spin inside the fragment. */
    buf.guest_start_pc = single ? 0U : pc;

    while (n < limit) {
        sparc32_decoded_t d;
        sparc32_emit_ctx_t ec;
        bool cti;
        const sparc32_decoded_t *delayp = NULL;
        sparc32_decoded_t dd;
        if (sparc32_fetch_decode(ctx, cur, &d) != 0) {
            if (n == 0U) {
                return NULL;
            }
            break;
        }
        cti = dbt_is_cti(&d);
        if (cti) {
            if (sparc32_fetch_decode(ctx, cur + 4U, &dd) == 0) {
                delayp = &dd;
            }
        }
        ec.buf = &buf;
        ec.pc = cur;
        ec.fault_pc = cur;
        ec.delay = delayp;
        if (cti && (cur & 0xFFFU) == 0xFFCU) {
            /* Page-final CTI: pristine SINGLE_STEP at the CTI address
             * (conservative superset of the branch-only contract rule:
             * CALL/JMPL at 0xffc need the same replay treatment for
             * difftest parity). The dispatcher replays the whole CTI
             * via interp_step, exactly like interp_cti's tail. */
            if (sparc32_emit_exit_singlestep(&ec, cur) != 0) {
                overflow = true;
                break;
            }
        } else if (sparc32_emit_insn(&ec, &d) != 0) {
            overflow = true;
            break;
        }
        if (buf.overflow) {
            overflow = true;
            break;
        }
        last = d;
        have_insn = true;
        n += 1U;
        if (cti) {
            /* The delay slot executes inline; the block covers it. */
            end = cur + 8U;
            break;
        }
        end = cur + 4U;
        if (dbt_block_ends(&d)) {
            break;
        }
        cur += 4U;
        if ((cur & (SPARC32_PAGE_SIZE - 1U)) == 0U) {
            break;
        }
    }

    /* Fallthrough exit for straight-line endings (64-insn cap, page edge,
     * single-insn dbt_step fragments): CTI/trap emitters terminate their
     * own transfer paths, and PRIV/FPU/ILL never execute, so only plain
     * insns need one here. Without it execution falls off the arena tail
     * into a host SIGILL (observed on the first difftest step). */
    if (have_insn && !overflow && dbt_falls_through(&last)) {
        a64_emit_exit_branch(&buf, end);
        if (buf.overflow) {
            overflow = true;
        }
    }
    buf.guest_end_pc = end;
    if (!have_insn) {
        /* Overflow on the very first insn: keep a needs_interp stub so
         * execution falls back to interp_step with identical protocol. */
        b->start_pc = pc;
        b->end_pc = pc + 4U;
        b->n_insns = 0U;
        b->epoch = g_cache_epoch;
        b->valid = true;
        b->needs_interp = true;
        b->host_code = NULL;
        b->ends_cti = false;
        b->ends_trap = false;
        b->is_link = false;
        b->indirect = false;
    } else if (overflow) {
        /* Truncated fragments never execute: identical interp fallback. */
        b->start_pc = pc;
        b->end_pc = end;
        b->n_insns = n;
        b->epoch = g_cache_epoch;
        b->valid = true;
        b->needs_interp = true;
        b->host_code = NULL;
        b->ends_cti = false;
        b->ends_trap = false;
        b->is_link = false;
        b->indirect = false;
    } else {
        bool was_valid = b->valid && b->epoch == g_cache_epoch;
        b->start_pc = pc;
        b->end_pc = end;
        b->n_insns = n;
        b->epoch = g_cache_epoch;
        b->valid = true;
        b->needs_interp = false;
        b->host_code = (const void *)mem;
        b->ends_cti = dbt_is_cti(&last);
        b->ends_trap = last.cls == (uint32_t)SPARC32_OP_TRAP;
        b->indirect = last.cls == (uint32_t)SPARC32_OP_JMPL;
        b->is_link = false;
        if (b->ends_cti) {
            if (last.cls == (uint32_t)SPARC32_OP_CALL) {
                b->is_link = true;
            } else if (last.cls == (uint32_t)SPARC32_OP_JMPL &&
                last.rd == SPARC32_O7) {
                b->is_link = true;
            }
        }
        if (!was_valid && g_cached_count < DBT_CACHE_SIZE) {
            g_cached_count += 1U;
        }
    }
    memset(ch, 0, sizeof(*ch));
    ch->key_epoch = (uint64_t)b->start_pc | ((uint64_t)b->epoch << 32);
    ch->host_code = b->host_code;
    ctx->blocks_compiled += 1U;
    if (ctx->trace_enabled && have_insn && !overflow && b->host_code != NULL) {
        size_t wi;
        const uint32_t *words = (const uint32_t *)mem;
        fprintf(stderr, "T asm guest=%08x n=%u\n", pc, n);
        for (wi = 0; wi < buf.count; wi++) {
            fprintf(stderr, "T asm %08x\n", words[wi]);
        }
    }
    return b;
}

const dbt_block_t *dbt_lookup(sparc32_ctx_t *ctx, uint32_t pc)
{
    uint32_t idx;
    dbt_block_t *b;
    if (ctx == NULL) {
        return NULL;
    }
    idx = dbt_cache_index(pc);
    b = &g_blocks[idx];
    if (b->valid && b->epoch == g_cache_epoch && b->start_pc == pc) {
        return b;
    }
    return dbt_translate(ctx, pc, false);
}

void dbt_flush(sparc32_ctx_t *ctx)
{
    size_t i;
    (void)ctx;
    for (i = 0; i < DBT_CACHE_SIZE; i++) {
        g_blocks[i].valid = false;
        g_blocks[i].host_code = NULL;
        memset(&g_chain[i], 0, sizeof(g_chain[i]));
    }
    g_cached_count = 0;
    g_cache_epoch += 1U;
    dbt_arena_reset();
}

uint32_t dbt_cached_count(void)
{
    return g_cached_count;
}

/* Range hook for src/rt32/vm.c (SMC on mprotect/munmap/guest writes):
 * Phase 2 policy is a coarse whole-cache flush (dbt.h). */
void sparc32_dbt_invalidate_range(sparc32_ctx_t *ctx, uint32_t start,
    uint32_t end)
{
    (void)start;
    (void)end;
    dbt_flush(ctx);
}

/* ---- IBTC / RAS (architectural arrays in ctx, SPEC section 3.2) ----
 * The asm fast paths dereference .entry as a {key|epoch, host_code}
 * pair, so .entry always points back at its own slot (never at raw
 * code); NULL code zeroes the slot so the cbz guards bail. Epochs come
 * from g_cache_epoch, so a flush invalidates every stale entry. */

static void dbt_ibtc_fill(sparc32_ctx_t *ctx, uint32_t pc, const void *code)
{
    uint32_t idx = sparc32_ibtc_hash(pc);
    sparc32_ibtc_entry_t *e = &ctx->ibtc[idx];
    if (code == NULL) {
        memset(e, 0, sizeof(*e));
        return;
    }
    e->key = pc;
    e->epoch = g_cache_epoch;
    e->host_code = code;
    e->entry = (void *)e;
}

static void dbt_ras_push(sparc32_ctx_t *ctx, uint32_t ret_pc,
    const void *ret_code)
{
    sparc32_ibtc_entry_t *slot;
    if (ret_code == NULL) {
        return;
    }
    ctx->ras_top = (ctx->ras_top + 1U) % SPARC32_RAS_SIZE;
    slot = &ctx->ras[ctx->ras_top];
    slot->key = ret_pc;
    slot->epoch = g_cache_epoch;
    slot->host_code = ret_code;
    slot->entry = (void *)slot;
}

static const void *dbt_ras_peek(const sparc32_ctx_t *ctx, uint32_t pc)
{
    const sparc32_ibtc_entry_t *top = &ctx->ras[ctx->ras_top];
    if (top->key == pc && top->epoch == g_cache_epoch &&
        top->host_code != NULL) {
        return top->host_code;
    }
    return NULL;
}

static bool dbt_ibtc_probe_hit(const sparc32_ctx_t *ctx, uint32_t pc)
{
    uint32_t idx = sparc32_ibtc_hash(pc);
    const sparc32_ibtc_entry_t *e = &ctx->ibtc[idx];
    return e->key == pc && e->epoch == g_cache_epoch &&
        e->host_code != NULL;
}

void dbt_patch_chain(sparc32_ctx_t *ctx, const dbt_block_t *from,
    const dbt_block_t *to)
{
    if (ctx == NULL || from == NULL || to == NULL) {
        return;
    }
    /* Phase 2 chains in the C dispatcher (slots stay NULL so every
     * in-fragment probe bails); only the pairing is recorded here. */
    ctx->chain_hits += 1U;
    ctx->last_exec_entry = (void *)to->host_code;
}

/* ---- Exit commit: w15/w16 -> pc/npc ----
 * The trampoline stored w16 to exit_reason and w15 to exit_dest. Fix up
 * pc/npc to the interp-visible state for each reason: BRANCH/TRAP/FAULT
 * resume at the carried PC; SYSCALL carries the post-trap npc (ta + 4)
 * while interp leaves pc at the trap for the owner's pc = npc commit. */

static void dbt_commit(sparc32_ctx_t *ctx)
{
    uint32_t reason = ctx->exit_reason;
    uint32_t dest = ctx->exit_dest;
    switch (reason) {
    case SPARC32_EXIT_BRANCH:
    case SPARC32_EXIT_TRAP:
    case SPARC32_EXIT_FAULT:
    case SPARC32_EXIT_UNDEF:
    case SPARC32_EXIT_SINGLE_STEP:
        ctx->pc = dest;
        ctx->npc = dest + 4U;
        break;
    case SPARC32_EXIT_SYSCALL:
        ctx->pc = dest - 4U;
        ctx->npc = dest;
        break;
    default:
        break;
    }
}

/* Replay one interp_step at the exit PC for pristine UNDEF/SINGLE_STEP
 * exits. Returns true when the dispatcher should keep running (clean
 * step, or a progressed page-final CTI whose transfer is complete). */
static bool dbt_replay(sparc32_ctx_t *ctx)
{
    uint32_t before = ctx->exit_dest;
    ctx->pc = ctx->exit_dest;
    ctx->npc = ctx->exit_dest + 4U;
    /* Fresh reason: interp_step leaves exit_reason untouched on the
     * annulled-away path (interp_cti early return, e.g. BA,a at 0xffc),
     * so a stale SINGLE_STEP/UNDEF from the emitted exit would survive
     * and diverge from a clean interp_step (which reports NONE). */
    ctx->exit_reason = SPARC32_EXIT_NONE;
    interp_step(ctx);
    if (ctx->exit_reason == SPARC32_EXIT_NONE) {
        return true;
    }
    if ((ctx->exit_reason == SPARC32_EXIT_UNDEF ||
            ctx->exit_reason == SPARC32_EXIT_SINGLE_STEP) &&
        ctx->pc != before) {
        return true;
    }
    return false;
}

/* ---- Fallback execution: interp_step over one cached block ----
 * Only used when the arena is exhausted (needs_interp); exit protocol
 * is identical either way. */

static int dbt_exec_fallback(sparc32_ctx_t *ctx, const dbt_block_t *b)
{
    uint32_t guard = b->n_insns + 2U;
    ctx->exit_reason = SPARC32_EXIT_NONE;
    while (guard > 0U && ctx->exit_reason == SPARC32_EXIT_NONE) {
        interp_step(ctx);
        guard -= 1U;
        if (ctx->exit_reason == SPARC32_EXIT_NONE &&
            (ctx->pc < b->start_pc || ctx->pc >= b->end_pc)) {
            break;
        }
    }
    if (ctx->exit_reason == SPARC32_EXIT_NONE) {
        ctx->exit_reason = SPARC32_EXIT_BRANCH;
        ctx->exit_dest = ctx->pc;
    }
    return (int)ctx->exit_reason;
}

static int dbt_exec_enter(sparc32_ctx_t *ctx, const dbt_block_t *b,
    bool allow_chain)
{
    const void *chain;
    if (b->host_code == NULL) {
        return dbt_exec_fallback(ctx, b);
    }
    if (dbt_code_publish(ctx) != 0) {
        return dbt_exec_fallback(ctx, b);
    }
    chain = (const void *)&g_chain[dbt_cache_index(b->start_pc)];
    ctx->exit_reason = SPARC32_EXIT_NONE;
    if (allow_chain) {
        dbt_enter_block(ctx, b->host_code, chain, &g_cache_epoch);
    } else {
        dbt_enter_step(ctx, b->host_code, chain);
    }
    dbt_commit(ctx);
    return (int)ctx->exit_reason;
}

/* ---- Dispatcher ---- */

static void dbt_on_branch(sparc32_ctx_t *ctx, const dbt_block_t *b)
{
    /* Snapshot the live exit before speculative lookups (a faulting
     * target must not clobber this block's BRANCH exit). */
    uint32_t reason = ctx->exit_reason;
    uint32_t dest = ctx->exit_dest;
    uint32_t arg = ctx->exit_arg;
    uint32_t fault = ctx->fault_addr;
    uint32_t stopc = ctx->pc;
    uint32_t stopnpc = ctx->npc;
    bool is_link = b->is_link;
    bool indirect = b->indirect;
    uint32_t end_pc = b->end_pc;

    if (is_link) {
        const dbt_block_t *ret = dbt_lookup(ctx, end_pc);
        dbt_ras_push(ctx, end_pc, ret != NULL ? ret->host_code : NULL);
    }
    if (indirect) {
        if (dbt_ras_peek(ctx, dest) != NULL) {
            ctx->ras_hits += 1U;
        } else if (dbt_ibtc_probe_hit(ctx, dest)) {
            ctx->ibtc_hits += 1U;
        }
    }
    {
        const dbt_block_t *next = dbt_lookup(ctx, dest);
        dbt_ibtc_fill(ctx, dest, next != NULL ? next->host_code : NULL);
    }
    ctx->exit_reason = reason;
    ctx->exit_dest = dest;
    ctx->exit_arg = arg;
    ctx->fault_addr = fault;
    ctx->pc = stopc;
    ctx->npc = stopnpc;
    ctx->blocks_executed += 1U;
}

int dbt_run(sparc32_ctx_t *ctx)
{
    if (ctx == NULL) {
        return -1;
    }
    ctx->exit_reason = SPARC32_EXIT_NONE;
    for (;;) {
        const dbt_block_t *b = dbt_lookup(ctx, ctx->pc);
        int r;
        if (b == NULL) {
            if (ctx->exit_reason == SPARC32_EXIT_NONE) {
                ctx->exit_reason = SPARC32_EXIT_FAULT;
                ctx->fault_addr = ctx->pc;
            }
            return (int)ctx->exit_reason;
        }
        r = dbt_exec_enter(ctx, b, true);
        if (r == (int)SPARC32_EXIT_BRANCH) {
            dbt_on_branch(ctx, b);
            /* Break chaining only for async signals (pending_signals is
             * set by another thread; Phase 4 wires main's async path).
             * Synchronous delivery already completed inside the faulting
             * iteration's main-loop turn, so chaining resumes normally;
             * breaking on the sticky sync_sig_delivered flag stranded
             * every post-handler branch back in main (fatal). */
            if (ctx->pending_signals != 0U) {
                return (int)ctx->exit_reason;
            }
            continue;
        }
        if (r == (int)SPARC32_EXIT_UNDEF ||
            r == (int)SPARC32_EXIT_SINGLE_STEP) {
            if (dbt_replay(ctx)) {
                continue;
            }
            return (int)ctx->exit_reason;
        }
        return r;
    }
}

int dbt_step(sparc32_ctx_t *ctx)
{
    const dbt_block_t *b;
    int r;
    uint32_t entry_pc = 0U;
    if (ctx == NULL) {
        return -1;
    }
    entry_pc = ctx->pc;
    ctx->exit_reason = SPARC32_EXIT_NONE;
    /* No chaining: a fresh single-insn fragment executes through the
     * no-chain trampoline, so exactly one guest instruction runs (a CTI
     * with its delay slot counts as one step, as in interp_step). */
    b = dbt_translate(ctx, ctx->pc, true);
    if (b == NULL) {
        if (ctx->exit_reason == SPARC32_EXIT_NONE) {
            ctx->exit_reason = SPARC32_EXIT_FAULT;
            ctx->fault_addr = ctx->pc;
        }
        return (int)ctx->exit_reason;
    }
    r = dbt_exec_enter(ctx, b, false);
    if (r == (int)SPARC32_EXIT_UNDEF ||
        r == (int)SPARC32_EXIT_SINGLE_STEP) {
        dbt_replay(ctx);
    }
    /* Lockstep parity: interp_step reports NONE after a completed insn
     * (transfers just advance pc/npc). A BRANCH exit from the single
     * fragment is the same completed step, so commit pc/npc from the
     * exit dest and normalize to NONE; faults/traps/syscalls pass
     * through unchanged to match interp exactly. */
    if (getenv("SPARC32RT_DBTTRACE") != NULL) {
        fprintf(stderr, "T dbtstep in=%08x out=%u dest=%08x pc=%08x npc=%08x\n",
            entry_pc, (unsigned)ctx->exit_reason, ctx->exit_dest,
            ctx->pc, ctx->npc);
    }
    if (ctx->exit_reason == (uint32_t)SPARC32_EXIT_BRANCH) {
        ctx->pc = ctx->exit_dest;
        ctx->npc = ctx->exit_dest + 4U;
        ctx->exit_reason = SPARC32_EXIT_NONE;
        return (int)SPARC32_EXIT_NONE;
    }
    return (int)ctx->exit_reason;
}
