/*
 * src/dbt/dbt_priv.h — Internal DBT cache, arena, and synchronization state
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared between src/dbt/dbt.c and src/dbt/dbt_cache.c for the 900-line
 * per-file discipline.
 */

#ifndef SPARC32RT_DBT_DBT_PRIV_H
#define SPARC32RT_DBT_DBT_PRIV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dbt/dbt.h"
#include "sparc32rt.h"

/* ---- Chaining entries (asm layout contract with a64_emit_fp.c) ---- */
typedef struct {
    uint64_t    key_epoch;   /* +0: guest key | (uint64_t)epoch << 32 */
    const void *host_code;   /* +8 */
    uint8_t     pad0[80];    /* +16..+95 */
    const void *ret_entry;   /* +96, NULL until a linked call patches it */
    uint8_t     pad1[48];    /* +104..+151 */
    const void *slots[8];    /* +152..+215 */
} dbt_chain_t;

_Static_assert(sizeof(dbt_chain_t) == 216,
    "dbt_chain_t must be 216 bytes");
_Static_assert(offsetof(dbt_chain_t, ret_entry) == 96,
    "dbt_chain_t ret_entry must start at +96");
_Static_assert(offsetof(dbt_chain_t, slots) == 152,
    "dbt_chain_t slots must start at +152");

extern dbt_block_t g_blocks[DBT_CACHE_SIZE];
extern dbt_chain_t g_chain[DBT_CACHE_SIZE];
extern uint32_t    g_cache_epoch;
extern uint32_t    g_cached_count;
extern size_t      g_arena_used;

static inline uint32_t dbt_cache_index(uint32_t pc)
{
    return (pc >> 2U) & (DBT_CACHE_SIZE - 1U);
}

void dbt_lock_acquire(void);
void dbt_lock_release(void);
void dbt_runner_enter_locked(void);
void dbt_runner_leave(void);

uint32_t *dbt_code_reserve_locked(sparc32_ctx_t *ctx, size_t n_words);
int dbt_code_publish_locked(sparc32_ctx_t *ctx);
void dbt_flush_locked(sparc32_ctx_t *ctx);
void dbt_bump_epoch_locked(void);

void dbt_ibtc_fill(sparc32_ctx_t *ctx, uint32_t pc, const void *code);
void dbt_ras_push(sparc32_ctx_t *ctx, uint32_t ret_pc, const void *ret_code);
const void *dbt_ras_peek(const sparc32_ctx_t *ctx, uint32_t pc);
bool dbt_ibtc_probe_hit(const sparc32_ctx_t *ctx, uint32_t pc);

#endif /* SPARC32RT_DBT_DBT_PRIV_H */
