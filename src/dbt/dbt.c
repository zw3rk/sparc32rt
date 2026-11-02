/*
 * src/dbt/dbt.c — AArch64 DBT core: translator and dispatcher
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 2 lane L2b (SPEC sections 2-3). Block translation and the
 * chaining dispatcher live here; code arena, block cache, IBTC, RAS,
 * and SMC invalidation live in src/dbt/dbt_cache.c.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sparc32rt.h"
#include "dbt/aot/aot_cache.h"
#include "dbt/aot/mem_site.h"
#include "dbt/dbt.h"
#include "dbt/dbt_priv.h"
#include "dbt/emit_int.h"
#include "interp/decode.h"
#include "interp/interp.h"
#include "os/threads.h"
#include "rt32/a64_emit.h"

/* ---- Decode helpers ---- */

static bool dbt_is_cti(const sparc32_decoded_t *d)
{
    return d->cls == (uint32_t)SPARC32_OP_CALL ||
        d->cls == (uint32_t)SPARC32_OP_BRANCH ||
        d->cls == (uint32_t)SPARC32_OP_FBRANCH ||
        d->cls == (uint32_t)SPARC32_OP_JMPL;
}

static bool dbt_falls_through(const sparc32_decoded_t *d)
{
    switch (d->cls) {
    case SPARC32_OP_CALL:
    case SPARC32_OP_JMPL:
    case SPARC32_OP_BRANCH:
    case SPARC32_OP_TRAP:
    case SPARC32_OP_PRIV:
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

/* ---- Translation: decode, emit, install (caller holds g_dbt_lock) ---- */

static const dbt_block_t *dbt_translate_locked(sparc32_ctx_t *ctx, uint32_t pc,
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

    mem = dbt_code_reserve_locked(ctx,
        single ? (size_t)DBT_STEP_RESERVE_WORDS
               : (size_t)DBT_BLOCK_RESERVE_WORDS);
    if (mem == NULL) {
        dbt_flush_locked(ctx);
        mem = dbt_code_reserve_locked(ctx,
            single ? (size_t)DBT_STEP_RESERVE_WORDS
                   : (size_t)DBT_BLOCK_RESERVE_WORDS);
        if (mem == NULL) {
            return NULL;
        }
    }
    cap = single ? (uint32_t)DBT_STEP_RESERVE_WORDS
                 : (uint32_t)DBT_BLOCK_RESERVE_WORDS;
    a64_buf_init(&buf, mem, (size_t)cap);
    buf.guest_start_pc = single ? 0U : pc;

    while (n < limit) {
        sparc32_decoded_t d;
        sparc32_emit_ctx_t ec;
        bool cti;
        const sparc32_decoded_t *delayp = NULL;
        sparc32_decoded_t dd;
        if (sparc32_fetch_decode(ctx, cur, &d) != 0) {
            if (n == 0U) {
                g_arena_used -= (size_t)cap * sizeof(uint32_t);
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
        if (cti || dbt_block_ends(&d)) {
            sparc32_emit_fp_flush(&buf);
        }
        if (cti && (cur & 0xFFFU) == 0xFFCU) {
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

    if (have_insn && !overflow && dbt_falls_through(&last)) {
        sparc32_emit_fp_flush(&buf);
        a64_emit_exit_branch(&buf, end);
        if (buf.overflow) {
            overflow = true;
        }
    }
    if (have_insn && !overflow && buf.count < (size_t)cap) {
        g_arena_used -= ((size_t)cap - buf.count) * sizeof(uint32_t);
    } else if (!have_insn || overflow) {
        g_arena_used -= (size_t)cap * sizeof(uint32_t);
    }
    buf.guest_end_pc = end;
    if (b->valid && b->start_pc != pc) {
        dbt_bump_epoch_locked();
    }
    if (!have_insn || overflow) {
        b->start_pc = pc;
        b->end_pc = have_insn ? end : (pc + 4U);
        b->n_insns = have_insn ? n : 0U;
        b->epoch = g_cache_epoch;
        b->valid = true;
        b->needs_interp = true;
        b->host_code = NULL;
        b->ends_cti = false;
        b->ends_trap = false;
        b->is_link = false;
        b->indirect = false;
        b->slot_count = 0U;
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
        {
            unsigned si;
            unsigned sc = buf.exit_slot_count;
            if (sc > 8U) {
                sc = 8U;
            }
            for (si = 0U; si < sc; si++) {
                b->slot_pcs[si] = buf.exit_slot_pcs[si];
            }
            b->slot_count = sc;
        }
        if (!was_valid && g_cached_count < DBT_CACHE_SIZE) {
            g_cached_count += 1U;
        }
    }
    memset(ch, 0, sizeof(*ch));
    ch->key_epoch = (uint64_t)b->start_pc | ((uint64_t)b->epoch << 32);
    ch->host_code = b->host_code;
    if (b->host_code != NULL && end > pc) {
        vm32_note_code_page(pc, end - pc);
        (void)sparc32_aot_cache_record(pc, end - pc, 1u);
    }
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

static const dbt_block_t *dbt_lookup_locked(sparc32_ctx_t *ctx, uint32_t pc)
{
    uint32_t idx;
    dbt_block_t *b;
    if (ctx == NULL) {
        return NULL;
    }
    idx = dbt_cache_index(pc);
    b = &g_blocks[idx];
    if (b->valid && b->start_pc == pc) {
        if (b->epoch != g_cache_epoch) {
            b->epoch = g_cache_epoch;
            memset(&g_chain[idx], 0, sizeof(g_chain[idx]));
            g_chain[idx].key_epoch =
                (uint64_t)b->start_pc | ((uint64_t)b->epoch << 32);
            g_chain[idx].host_code = b->host_code;
        }
        return b;
    }
    return dbt_translate_locked(ctx, pc, false);
}

const dbt_block_t *dbt_lookup(sparc32_ctx_t *ctx, uint32_t pc)
{
    const dbt_block_t *b;
    if (ctx == NULL) {
        return NULL;
    }
    dbt_lock_acquire();
    b = dbt_lookup_locked(ctx, pc);
    if (b != NULL && b->host_code != NULL) {
        (void)dbt_code_publish_locked(ctx);
    }
    dbt_lock_release();
    return b;
}

/* ---- Exit commit: w15/w16 -> pc/npc ---- */

static void dbt_commit(sparc32_ctx_t *ctx)
{
    uint32_t reason = ctx->exit_reason;
    uint32_t dest = ctx->exit_dest;
    switch (reason) {
    case SPARC32_EXIT_BRANCH:
    case SPARC32_EXIT_UNDEF:
    case SPARC32_EXIT_SINGLE_STEP:
        ctx->pc = dest;
        ctx->npc = dest + 4U;
        break;
    case SPARC32_EXIT_TRAP:
    case SPARC32_EXIT_FAULT:
        ctx->pc = dest;
        if (ctx->jmpl_delay_armed != 0u) {
            ctx->npc = ctx->jmpl_target;
            aot_delay_target_set(ctx, ctx->jmpl_target);
        } else {
            ctx->npc = dest + 4U;
        }
        break;
    case SPARC32_EXIT_SYSCALL:
        ctx->pc = dest - 4U;
        ctx->npc = dest;
        break;
    default:
        break;
    }
}

static bool dbt_replay(sparc32_ctx_t *ctx)
{
    uint32_t before = ctx->exit_dest;
    ctx->pc = ctx->exit_dest;
    ctx->npc = ctx->exit_dest + 4U;
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
    const void *entry;
    const void *chain;
    dbt_block_t snap;
    ctx->jmpl_delay_armed = 0u;
    dbt_lock_acquire();
    dbt_runner_enter_locked();
    snap = *b;
    if (snap.host_code == NULL || !snap.valid ||
        dbt_code_publish_locked(ctx) != 0) {
        dbt_lock_release();
        dbt_runner_leave();
        return dbt_exec_fallback(ctx, &snap);
    }
    entry = snap.host_code;
    chain = (const void *)&g_chain[dbt_cache_index(snap.start_pc)];
    dbt_lock_release();

    ctx->exit_reason = SPARC32_EXIT_NONE;
    ctx->last_exec_entry = (void *)chain;
    if (allow_chain) {
        dbt_enter_block(ctx, entry, chain, &g_cache_epoch);
    } else {
        dbt_enter_step(ctx, entry, chain);
    }
    dbt_runner_leave();
    dbt_commit(ctx);
    return (int)ctx->exit_reason;
}

/* ---- Dispatcher ---- */

static void dbt_on_branch(sparc32_ctx_t *ctx, const dbt_block_t *b)
{
    uint32_t reason;
    uint32_t dest;
    uint32_t arg;
    uint32_t fault;
    uint32_t stopc;
    uint32_t stopnpc;
    bool is_link;
    bool indirect;
    uint32_t end_pc;
    uint32_t from_pc;
    uint32_t from_slots[8];
    uint32_t from_count;
    uint32_t si;

    dbt_lock_acquire();
    if (ctx->last_exec_entry != NULL) {
        const dbt_chain_t *lch = (const dbt_chain_t *)ctx->last_exec_entry;
        if (lch >= &g_chain[0] && lch < &g_chain[DBT_CACHE_SIZE]) {
            const dbt_block_t *lb = &g_blocks[lch - &g_chain[0]];
            if (lb->valid && lb->epoch == g_cache_epoch) {
                b = lb;
            }
        }
    }
    reason = ctx->exit_reason;
    dest = ctx->exit_dest;
    arg = ctx->exit_arg;
    fault = ctx->fault_addr;
    stopc = ctx->pc;
    stopnpc = ctx->npc;
    is_link = b->is_link;
    indirect = b->indirect;
    end_pc = b->end_pc;
    from_pc = b->start_pc;
    from_count = b->slot_count;
    if (from_count > 8U) {
        from_count = 8U;
    }
    for (si = 0U; si < from_count; si++) {
        from_slots[si] = b->slot_pcs[si];
    }

    if (is_link) {
        const dbt_block_t *ret = dbt_lookup_locked(ctx, end_pc);
        dbt_ras_push(ctx, end_pc, ret != NULL ? ret->host_code : NULL);
        if (ret != NULL && ret->host_code != NULL) {
            uint32_t from_idx = dbt_cache_index(from_pc);
            const dbt_block_t *cur = &g_blocks[from_idx];
            if (cur->valid && cur->epoch == g_cache_epoch &&
                cur->start_pc == from_pc) {
                g_chain[from_idx].ret_entry =
                    &g_chain[dbt_cache_index(end_pc)];
            }
        }
    }
    if (indirect) {
        if (dbt_ras_peek(ctx, dest) != NULL) {
            ctx->ras_hits += 1U;
        } else if (dbt_ibtc_probe_hit(ctx, dest)) {
            ctx->ibtc_hits += 1U;
        }
    }
    {
        const dbt_block_t *next = dbt_lookup_locked(ctx, dest);
        dbt_ibtc_fill(ctx, dest, next != NULL ? next->host_code : NULL);
        if (next != NULL && next->host_code != NULL) {
            uint32_t from_idx = dbt_cache_index(from_pc);
            const dbt_block_t *cur = &g_blocks[from_idx];
            if (cur->valid && cur->epoch == g_cache_epoch &&
                cur->start_pc == from_pc) {
                for (si = 0U; si < from_count; si++) {
                    if (from_slots[si] == dest) {
                        g_chain[from_idx].slots[si] =
                            &g_chain[dbt_cache_index(dest)];
                        break;
                    }
                }
            }
        }
    }
    (void)dbt_code_publish_locked(ctx);
    dbt_lock_release();

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
        if (ctx->pending_signals != 0U && interp_poll_async(ctx)) {
            continue;
        }
        r = dbt_exec_enter(ctx, b, true);
        if (r == (int)SPARC32_EXIT_BRANCH) {
            dbt_on_branch(ctx, b);
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
    if (ctx->pending_signals != 0U && interp_poll_async(ctx)) {
        return (int)ctx->exit_reason;
    }
    dbt_lock_acquire();
    b = dbt_translate_locked(ctx, ctx->pc, true);
    if (b != NULL && b->host_code != NULL) {
        (void)dbt_code_publish_locked(ctx);
    }
    dbt_lock_release();
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
