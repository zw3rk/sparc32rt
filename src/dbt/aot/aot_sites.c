/*
 * src/dbt/aot/aot_sites.c — Site table, JMPL delay-target side table,
 * NPC resolution & rollback (Wave U3, lane U3-sparc32)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements the C side of mem_site.h: a fixed side table of dynamic
 * delay-slot targets (sparc32rt.h is frozen, so no ctx field), the
 * NPC resolver for RT_NPC_SEQUENTIAL / STATIC_TARGET / DYNAMIC_CTX,
 * and the sp_rollback_delta applier. The signal-rewind anchor math
 * (seq_start_offset) is consumed by the DBT signal path; this unit only
 * records and resolves.
 */

#include "dbt/aot/mem_site.h"

#include <string.h>

#include "interp/interp_priv.h"

/* Side table: latest dynamic JMPL target per live ctx (frozen ctx). */
#define AOT_DELAY_SLOTS 64u

typedef struct {
    const sparc32_ctx_t *ctx;
    uint32_t target;
    uint64_t seq;
} aot_delay_slot_t;

static aot_delay_slot_t g_delay_slots[AOT_DELAY_SLOTS];
static uint64_t g_delay_seq = 0u;

void aot_delay_target_set(const sparc32_ctx_t *ctx, uint32_t target)
{
    uint64_t i;
    uint64_t victim = 0u;
    if (ctx == NULL) {
        return;
    }
    for (i = 0u; i < (uint64_t)AOT_DELAY_SLOTS; i++) {
        if (g_delay_slots[i].ctx == ctx) {
            g_delay_slots[i].target = target;
            g_delay_slots[i].seq = ++g_delay_seq;
            return;
        }
    }
    for (i = 1u; i < (uint64_t)AOT_DELAY_SLOTS; i++) {
        if (g_delay_slots[i].seq < g_delay_slots[victim].seq) {
            victim = i;
        }
    }
    g_delay_slots[victim].ctx = ctx;
    g_delay_slots[victim].target = target;
    g_delay_slots[victim].seq = ++g_delay_seq;
}

uint32_t aot_delay_target_get(const sparc32_ctx_t *ctx)
{
    uint64_t i;
    if (ctx == NULL) {
        return 0u;
    }
    for (i = 0u; i < (uint64_t)AOT_DELAY_SLOTS; i++) {
        if (g_delay_slots[i].ctx == ctx) {
            return g_delay_slots[i].target;
        }
    }
    return 0u;
}

uint32_t aot_site_resolve_npc(const dbt_mem_site_t *site,
    uint32_t block_base, uint32_t delay_target)
{
    uint32_t pc;
    if (site == NULL) {
        return 0u;
    }
    pc = block_base + (uint32_t)site->guest_pc_delta;
    switch (site->npc_mode) {
    case RT_NPC_SEQUENTIAL:
        return pc + 4u;
    case RT_NPC_STATIC_TARGET:
        return block_base + (uint32_t)site->npc_delta;
    case RT_NPC_DYNAMIC_CTX:
        return delay_target;
    default:
        break;
    }
    return 0u;
}

void aot_site_apply_rollback(sparc32_ctx_t *ctx,
    const dbt_mem_site_t *site)
{
    uint32_t reg;
    if (ctx == NULL || site == NULL) {
        return;
    }
    if (site->sp_rollback_delta == 0) {
        return;
    }
    reg = (uint32_t)site->addr_base_reg & 31u;
    if (reg == 0u) {
        return;
    }
    ctx->r[reg] -= (uint32_t)(int32_t)site->sp_rollback_delta;
    ctx->r[0] = 0u;
}

/*
 * Validate a two-word SPARC transfer span [va, va+8) for read (is_store
 * == false, LDD) or write (is_store == true, STD) without touching any
 * architectural register or guest byte. Multi-transfer instructions must
 * validate the first and last byte before committing (Rev 4 section
 * 4.3.3); callers load/store only after this returns true.
 */
bool aot_span_ok(sparc32_ctx_t *ctx, uint32_t va, bool is_store)
{
    uint32_t need = is_store ? 2u : 1u;
    if (ctx == NULL) {
        return false;
    }
    if ((va & 3u) != 0u) {
        ctx->exit_reason = SPARC32_EXIT_FAULT;
        ctx->fault_addr = va;
        return false;
    }
    if (!interp_range_ok(ctx, va, 8u, need)) {
        ctx->exit_reason = SPARC32_EXIT_FAULT;
        ctx->fault_addr = va;
        return false;
    }
    return true;
}
