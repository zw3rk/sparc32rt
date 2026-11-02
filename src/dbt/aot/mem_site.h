/*
 * src/dbt/aot/mem_site.h — Relative mem-site records, Soft-TLB entries,
 * dynamic delay-slot recovery & pre-commit rollback (Wave U3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements UNIFICATION-PLAN.md Rev 4 sections 4.3/4.4 for sparc32rt:
 *
 * - dbt_mem_site_t: 24-byte purely-relative site record serialized into
 *   AOT block payloads (section 4.3). npc_mode resolves the post-fault
 *   guest NPC; RT_NPC_DYNAMIC_CTX covers SPARC JMPL (and MIPS JR on the
 *   sibling lane), whose target lives only in a register at run time.
 * - sp_rollback_delta + addr_base_reg: pre-store stack/base adjustment
 *   undone on fault (section 4.3). On SPARC the multi-transfer LDD/STD
 *   validate the whole span before committing any register, so no unwind
 *   is ever needed; the helper below serves the single-access
 *   pre-commit case shared with the sibling lanes.
 * - Write-tag discipline (section 4.4): VM32_PROT_FAST_WRITE is valid only
 *   when the page is writable, promoted past PAGE_COW_CLEAN, and carries
 *   neither PAGE_HAS_CODE nor PAGE_HAS_SW_RESERVATION.
 *
 * sparc32rt.h is Coordinator-frozen, so the run-time JMPL delay target
 * is NOT a ctx field here: aot_sites.c keeps a small side table keyed by
 * ctx (aot_delay_target_set/get). No AArch64 assembly in this header.
 */

#ifndef SPARC32RT_DBT_AOT_MEM_SITE_H
#define SPARC32RT_DBT_AOT_MEM_SITE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sparc32rt.h"

/* Post-fault NPC resolution modes (Rev 4 section 4.3.3). */
typedef enum {
    RT_NPC_SEQUENTIAL = 0, /* guest_npc = guest_pc + insn_len */
    RT_NPC_STATIC_TARGET = 1, /* guest_npc = block_base + site->npc_delta */
    RT_NPC_DYNAMIC_CTX = 2 /* guest_npc = aot_delay_target_get(ctx) */
} rt_npc_mode_t;

/* Site flags (dbt_mem_site_t.flags). */
#define RT_SITE_STORE (1u << 0) /* Store site (else load) */
#define RT_SITE_SIGNED (1u << 1) /* Sign-extending load */
#define RT_SITE_BE (1u << 2) /* Big-endian access (always set on sparc32) */
#define RT_SITE_IN_DELAY_SLOT (1u << 3) /* Site in a CTI delay slot */
#define RT_SITE_PRE_COMMITTED_SP (1u << 4) /* Base reg written pre-access */

/* Purely relative 24-byte site record (AOT-serializable). */
typedef struct {
    uint16_t seq_start_offset; /* .L_tlb_seq_start_k (signal rewind) */
    uint16_t host_insn_offset; /* .L_tlb_mem_insn_k (faulting ldr/str) */
    uint16_t cont_insn_offset; /* .L_tlb_cont_k (resume point) */
    uint16_t guest_pc_delta; /* Faulting PC minus block->guest_pc_base */
    int32_t npc_delta; /* Static target delta (RT_NPC_STATIC_TARGET) */
    uint32_t insn_word; /* Raw guest instruction word */
    int16_t sp_rollback_delta; /* Base-reg pre-adjust to undo on fault */
    uint8_t npc_mode; /* rt_npc_mode_t */
    uint8_t width; /* 1, 2, 4, 8, or 16 */
    uint8_t flags; /* RT_SITE_* bits */
    uint8_t val_or_dst_reg; /* Load dst / store value register */
    uint8_t addr_base_reg; /* Base register if sp_rollback_delta != 0 */
    uint8_t reserved;
} dbt_mem_site_t;

_Static_assert(sizeof(dbt_mem_site_t) == 24,
    "dbt_mem_site_t must be 24 bytes");

/* Guest page-state bits backing the write-tag rule (Rev 4 section 4.4). */
#define RT_PAGE_COW_CLEAN (1u << 0) /* MAP_PRIVATE file page, not promoted */
#define RT_PAGE_COW_DIRTY (1u << 1) /* Promoted in place (HVA unchanged) */
#define RT_PAGE_HAS_CODE (1u << 2) /* Live DBT blocks translated from page */
#define RT_PAGE_HAS_SW_RESERVATION (1u << 3) /* Active atomic reservation */

/*
 * Record the dynamic JMPL target for ctx (DBT-emitted JMPL sites store
 * rs1+src2 here before the delay slot so fault recovery and the AOT
 * rewriter can resolve RT_NPC_DYNAMIC_CTX without a ctx layout change).
 */
void aot_delay_target_set(const sparc32_ctx_t *ctx, uint32_t target);

/* Fetch the last recorded dynamic target for ctx (0 when none). */
uint32_t aot_delay_target_get(const sparc32_ctx_t *ctx);

/*
 * Resolve the resume NPC for a faulting site. block_base is the guest PC
 * of the translated block; delay_target is consulted only for
 * RT_NPC_DYNAMIC_CTX. Returns 0 for an unknown mode (caller treats it
 * as a hard fault, never as a valid NPC).
 */
uint32_t aot_site_resolve_npc(const dbt_mem_site_t *site,
    uint32_t block_base, uint32_t delay_target);

/*
 * Undo a pre-committed stack/base adjustment after a fault: when
 * site->sp_rollback_delta != 0, subtracts it from
 * ctx->r[site->addr_base_reg] (writes via the %g0 guard). SPARC LDD/STD
 * validate-then-commit, so this only fires for single-access sites that
 * chose pre-commit over post-.L_tlb_cont_k writeback.
 */
void aot_site_apply_rollback(sparc32_ctx_t *ctx,
    const dbt_mem_site_t *site);

/*
 * Validate a two-word SPARC transfer span [va, va+8) for read (LDD) or
 * write (STD) without touching any architectural register or guest byte
 * (Rev 4 section 4.3.3 validate-before-commit). False reports
 * EXIT_FAULT/fault_addr; implemented in aot_sites.c.
 */
bool aot_span_ok(sparc32_ctx_t *ctx, uint32_t va, bool is_store);

/* True when write_tag may stay valid for a page with this state/prot. */
static inline bool rt_write_tag_allowed(uint32_t page_state,
    uint32_t page_prot)
{
    if ((page_prot & 2U) == 0U) {
        return false;
    }
    if ((page_state & RT_PAGE_COW_CLEAN) != 0U) {
        return false;
    }
    if ((page_state & (RT_PAGE_HAS_CODE | RT_PAGE_HAS_SW_RESERVATION))
        != 0U) {
        return false;
    }
    return true;
}

#endif /* SPARC32RT_DBT_AOT_MEM_SITE_H */
