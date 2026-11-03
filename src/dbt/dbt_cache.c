/*
 * src/dbt/dbt_cache.c — DBT W^X code arena, block cache, IBTC, RAS, and SMC
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from src/dbt/dbt.c for the 900-line per-file discipline.
 * Owns the W^X code arena, direct-mapped block/chaining tables, thread-safe
 * runner quiescence for arena mprotect/reset, range-selective SMC cache
 * invalidation, and IBTC/RAS helpers.
 */

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#ifdef __APPLE__
#include <libkern/OSCacheControl.h>
#endif

#include "dbt/aot/aot_cache.h"
#include "dbt/dbt_priv.h"
#include "sparc32rt.h"

#ifndef MAP_ANONYMOUS
#ifdef MAP_ANON
#define MAP_ANONYMOUS MAP_ANON
#else
#define MAP_ANONYMOUS 0x20
#endif
#endif

dbt_block_t g_blocks[DBT_CACHE_SIZE];
dbt_chain_t g_chain[DBT_CACHE_SIZE];
uint32_t    g_cache_epoch = 1U;
uint32_t    g_cached_count;
size_t      g_arena_used;

static uint8_t *g_arena_base;
static bool     g_arena_published;
static size_t   g_arena_published_used;

static pthread_mutex_t g_dbt_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_dbt_quiesce_cv = PTHREAD_COND_INITIALIZER;
static uint32_t        g_dbt_active_runners;
static bool            g_dbt_writer_waiting;
static _Thread_local uint32_t t_dbt_quiesce_held;

void dbt_lock_acquire(void)
{
    pthread_mutex_lock(&g_dbt_lock);
}

void dbt_lock_release(void)
{
    pthread_mutex_unlock(&g_dbt_lock);
}

void dbt_bump_epoch_locked(void)
{
    uint32_t next = __atomic_add_fetch(&g_cache_epoch, 1U, __ATOMIC_SEQ_CST);
    if (next == 0U) {
        size_t ci;
        for (ci = 0U; ci < DBT_CACHE_SIZE; ci++) {
            g_blocks[ci].valid = false;
            g_blocks[ci].host_code = NULL;
            memset(&g_chain[ci], 0, sizeof(g_chain[ci]));
        }
        g_cached_count = 0U;
        __atomic_store_n(&g_cache_epoch, 1U, __ATOMIC_SEQ_CST);
    }
}

static void dbt_wait_quiescent_locked(void)
{
    if (__atomic_load_n(&g_dbt_active_runners, __ATOMIC_SEQ_CST) == 0U) {
        return;
    }
    __atomic_store_n(&g_dbt_writer_waiting, true, __ATOMIC_SEQ_CST);
    /* Bump epoch so any runner spinning in a self-loop or chained loop
     * bails out to C at the end of its current basic block. */
    dbt_bump_epoch_locked();
    while (__atomic_load_n(&g_dbt_active_runners, __ATOMIC_SEQ_CST) > 0U) {
        pthread_cond_wait(&g_dbt_quiesce_cv, &g_dbt_lock);
    }
    __atomic_store_n(&g_dbt_writer_waiting, false, __ATOMIC_SEQ_CST);
    pthread_cond_broadcast(&g_dbt_quiesce_cv);
}

void dbt_runner_enter_locked(void)
{
    while (__atomic_load_n(&g_dbt_writer_waiting, __ATOMIC_SEQ_CST)) {
        pthread_cond_wait(&g_dbt_quiesce_cv, &g_dbt_lock);
    }
    __atomic_add_fetch(&g_dbt_active_runners, 1U, __ATOMIC_SEQ_CST);
}

void dbt_runner_leave(void)
{
    uint32_t rem = __atomic_sub_fetch(&g_dbt_active_runners, 1U,
        __ATOMIC_SEQ_CST);
    if (rem == 0U &&
        __atomic_load_n(&g_dbt_writer_waiting, __ATOMIC_SEQ_CST)) {
        pthread_mutex_lock(&g_dbt_lock);
        pthread_cond_broadcast(&g_dbt_quiesce_cv);
        pthread_mutex_unlock(&g_dbt_lock);
    }
}

/* VM-mutation quiescence (S32-R3-3): the VM writer path holds g_dbt_lock
 * across the whole mutation (lock order g_dbt_lock -> VM spinlock,
 * matching fork prepare), so no generated guest access is in flight
 * while host mappings or protections change. In-flight runners drain;
 * new runners block in dbt_runner_enter_locked until dbt_quiesce_end. */
void dbt_quiesce_begin(void)
{
    dbt_lock_acquire();
    dbt_wait_quiescent_locked();
    t_dbt_quiesce_held = 1U;
}

void dbt_quiesce_end(void)
{
    t_dbt_quiesce_held = 0U;
    dbt_lock_release();
}

/* Coordinated fork (S32-R3-2): prepare drains execution under g_dbt_lock
 * (same order as the VM path: thr_live_lock -> g_dbt_lock -> VM
 * spinlock), the parent just releases, and the single-threaded child
 * owns the lock, resets the runner state no vanished thread can drain,
 * and rebuilds the lock/cond. The COW code arena stays valid. */
void dbt_fork_prepare(void)
{
    dbt_lock_acquire();
    dbt_wait_quiescent_locked();
}

void dbt_fork_parent(void)
{
    dbt_lock_release();
}

void dbt_fork_child_reset(void)
{
    __atomic_store_n(&g_dbt_active_runners, 0U, __ATOMIC_SEQ_CST);
    __atomic_store_n(&g_dbt_writer_waiting, false, __ATOMIC_SEQ_CST);
    t_dbt_quiesce_held = 0U;
    pthread_mutex_unlock(&g_dbt_lock);
    pthread_mutex_destroy(&g_dbt_lock);
    pthread_mutex_init(&g_dbt_lock, NULL);
    pthread_cond_destroy(&g_dbt_quiesce_cv);
    pthread_cond_init(&g_dbt_quiesce_cv, NULL);
}

#ifndef __APPLE__
static size_t dbt_page_span(void)
{
    long page = sysconf(_SC_PAGESIZE);
    size_t p = (page > 0) ? (size_t)page : 4096U;
    return (g_arena_used + p - 1U) & ~(p - 1U);
}
#endif

/* Recycle the arena without unmapping g_arena_base so concurrent or
 * nested callers never observe an unmapped code arena address. */
static void dbt_arena_reset_locked(void)
{
    dbt_wait_quiescent_locked();
    g_arena_used = 0U;
    g_arena_published_used = 0U;
    g_arena_published = false;
}

static bool dbt_arena_ensure_rw_locked(sparc32_ctx_t *ctx)
{
    if (g_arena_base == NULL) {
#ifdef __APPLE__
        void *p = mmap(NULL, DBT_CODE_ARENA_SIZE,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
#else
        void *p = mmap(NULL, DBT_CODE_ARENA_SIZE,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
        if (p == MAP_FAILED) {
            return false;
        }
#ifdef __APPLE__
        pthread_jit_write_protect_np(0);
#endif
        g_arena_base = (uint8_t *)p;
        g_arena_used = 0U;
        g_arena_published_used = 0U;
        g_arena_published = false;
        return true;
    }
    if (g_arena_published) {
#ifdef __APPLE__
        pthread_jit_write_protect_np(0);
#else
        dbt_wait_quiescent_locked();
        if (mprotect((void *)g_arena_base, dbt_page_span(),
                PROT_READ | PROT_WRITE) != 0) {
            return false;
        }
#endif
        g_arena_published = false;
        if (ctx != NULL) {
            ctx->wx_transitions += 1U;
        }
    } else {
#ifdef __APPLE__
        pthread_jit_write_protect_np(0);
#endif
    }
    return true;
}

uint32_t *dbt_code_reserve_locked(sparc32_ctx_t *ctx, size_t n_words)
{
    size_t bytes;
    uint32_t *out;
    if (n_words == 0U) {
        return NULL;
    }
    if (!dbt_arena_ensure_rw_locked(ctx)) {
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

uint32_t *dbt_code_reserve(sparc32_ctx_t *ctx, size_t n_words)
{
    uint32_t *out;
    dbt_lock_acquire();
    out = dbt_code_reserve_locked(ctx, n_words);
    dbt_lock_release();
    return out;
}

int dbt_code_publish_locked(sparc32_ctx_t *ctx)
{
    if (g_arena_base == NULL || g_arena_used == 0U) {
        return 0;
    }
    if (g_arena_published) {
#ifdef __APPLE__
        pthread_jit_write_protect_np(1);
#endif
        return 0;
    }
#ifdef __APPLE__
    pthread_jit_write_protect_np(1);
    if (g_arena_used > g_arena_published_used) {
        sys_icache_invalidate((void *)(g_arena_base + g_arena_published_used),
            g_arena_used - g_arena_published_used);
        g_arena_published_used = g_arena_used;
    }
#else
    {
        size_t span = dbt_page_span();
        if (mprotect((void *)g_arena_base, span, PROT_READ | PROT_EXEC) != 0) {
            return -1;
        }
        if (g_arena_used > g_arena_published_used) {
            __builtin___clear_cache(
                (char *)g_arena_base + g_arena_published_used,
                (char *)g_arena_base + g_arena_used);
            g_arena_published_used = g_arena_used;
        }
    }
#endif
    g_arena_published = true;
    if (ctx != NULL) {
        ctx->wx_transitions += 1U;
        ctx->icache_flushes += 1U;
    }
    return 0;
}

int dbt_code_publish(sparc32_ctx_t *ctx)
{
    int rc;
    dbt_lock_acquire();
    rc = dbt_code_publish_locked(ctx);
    dbt_lock_release();
    return rc;
}

void dbt_flush_locked(sparc32_ctx_t *ctx)
{
    size_t i;
    (void)ctx;
    dbt_arena_reset_locked();
    for (i = 0U; i < DBT_CACHE_SIZE; i++) {
        g_blocks[i].valid = false;
        g_blocks[i].host_code = NULL;
        memset(&g_chain[i], 0, sizeof(g_chain[i]));
    }
    g_cached_count = 0U;
    dbt_bump_epoch_locked();
}

void dbt_flush(sparc32_ctx_t *ctx)
{
    dbt_lock_acquire();
    dbt_flush_locked(ctx);
    dbt_lock_release();
}

uint32_t dbt_cached_count(void)
{
    uint32_t c;
    dbt_lock_acquire();
    c = g_cached_count;
    dbt_lock_release();
    return c;
}

static void dbt_invalidate_range_locked(uint32_t start, uint32_t end)
{
    bool invalidated = false;
    size_t i;
    for (i = 0U; i < DBT_CACHE_SIZE; i++) {
        if (g_blocks[i].valid &&
            g_blocks[i].end_pc > start &&
            g_blocks[i].start_pc < end) {
            g_blocks[i].valid = false;
            g_blocks[i].host_code = NULL;
            memset(&g_chain[i], 0, sizeof(g_chain[i]));
            if (g_cached_count > 0U) {
                g_cached_count -= 1U;
            }
            invalidated = true;
        }
    }
    {
        uint32_t lo = sparc32_page_down(start);
        uint32_t hi = sparc32_page_up(end);
        if (hi < end) {
            hi = UINT32_MAX;
        }
        vm32_clear_code_range(lo, hi);
        for (i = 0U; i < DBT_CACHE_SIZE; i++) {
            const dbt_block_t *b = &g_blocks[i];
            if (b->valid && b->end_pc > lo && b->start_pc < hi) {
                vm32_note_code_page(b->start_pc, b->end_pc - b->start_pc);
            }
        }
    }
    if (invalidated) {
        dbt_bump_epoch_locked();
    }
}

/* Range-selective invalidation (S32-4, S32-5): retire cached blocks
 * overlapping [start, end), clear RT_PAGE_HAS_CODE on unmapped/mprotected
 * pages, and bump g_cache_epoch only when a block was retired without
 * unmapping or stripping PROT_EXEC from g_arena_base. When called from
 * a VM writer that already holds dbt_quiesce_begin (g_dbt_lock), skip
 * re-acquiring the non-recursive mutex on the same thread. */
void sparc32_dbt_invalidate_range(sparc32_ctx_t *ctx, uint32_t start,
    uint32_t end)
{
    (void)ctx;
    if (end <= start) {
        return;
    }
    if (t_dbt_quiesce_held != 0U) {
        dbt_invalidate_range_locked(start, end);
        return;
    }
    dbt_lock_acquire();
    dbt_invalidate_range_locked(start, end);
    dbt_lock_release();
}

void dbt_ibtc_fill(sparc32_ctx_t *ctx, uint32_t pc, const void *code)
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
    e->entry = (void *)&g_chain[dbt_cache_index(pc)];
}

void dbt_ras_push(sparc32_ctx_t *ctx, uint32_t ret_pc,
    const void *ret_code)
{
    sparc32_ibtc_entry_t *slot;
    if (ret_code == NULL) {
        return;
    }
    slot = &ctx->ras[ctx->ras_top];
    slot->key = ret_pc;
    slot->epoch = g_cache_epoch;
    slot->host_code = ret_code;
    slot->entry = (void *)&g_chain[dbt_cache_index(ret_pc)];
    ctx->ras_top = (ctx->ras_top + 1U) % SPARC32_RAS_SIZE;
}

const void *dbt_ras_peek(const sparc32_ctx_t *ctx, uint32_t pc)
{
    const sparc32_ibtc_entry_t *top =
        &ctx->ras[(ctx->ras_top + SPARC32_RAS_SIZE - 1U) %
            SPARC32_RAS_SIZE];
    if (top->key == pc && top->epoch == g_cache_epoch &&
        top->host_code != NULL) {
        return top->host_code;
    }
    return NULL;
}

bool dbt_ibtc_probe_hit(const sparc32_ctx_t *ctx, uint32_t pc)
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
    ctx->chain_hits += 1U;
    ctx->last_exec_entry = (void *)to->host_code;
}

void dbt_jmpl_record_target(sparc32_ctx_t *ctx, uint32_t target)
{
    if (ctx == NULL) {
        return;
    }
    ctx->jmpl_target = target;
    ctx->jmpl_delay_armed = 1u;
    aot_delay_target_set(ctx, target);
}
