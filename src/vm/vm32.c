/*
 * src/vm/vm32.c — Class-A 32-bit 4 GiB window, Regime A1/A2 (Wave U3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements UNIFICATION-PLAN.md Rev 4 section 4.6 for sparc32rt:
 *
 * Regime A1 (host page size H == 4096, native 4 KiB Linux and every
 * hyper-linux run): reserve one 4 GiB MAP_PRIVATE|MAP_ANONYMOUS window
 * [G, G + 4 GiB) with x20 = G and emit the 1-instruction hardware load
 * / store [x20, wAddr, uxtw]. Every 4 KiB guest page maps 1:1 to a host
 * page; guest fork() is native kernel MAP_PRIVATE COW.
 *
 * Regime A2 (H > 4096: standalone 16 KiB macOS Mach-O backend_darwin.c
 * and native 16K/64K Linux without /dev/a32host): the same 4 GiB range
 * is a single MAP_PRIVATE|MAP_ANONYMOUS arena whose active host pages
 * carry the union of their 4 KiB sub-page permissions (PROT_READ |
 * PROT_WRITE, never PROT_EXEC). x20 is bound to &tlb[0] and every DBT
 * access runs the 7-instruction Soft-TLB (mem_site.h); permission checks
 * happen in software at site instruction 6, so RELRO + .data sharing one
 * 16 KiB host page costs zero SIGSEGV traps and every page keeps one
 * coherent address HVA = G + gva for DBT, interp_step, futex, and
 * syscall copyin/copyout.
 *
 * Page state + the per-thread 128 KiB TLB live here; file backing and
 * the family inode table live in vm_file.c (Provider A, section 5.1).
 * Host primitives come from src/os/backend.h (dual backend, section 6).
 * No AArch64 assembly in this unit (x18 discipline is vacuous here).
 */

#define _POSIX_C_SOURCE 200809L

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sparc32rt.h"
#include "dbt/aot/mem_site.h"
#include "os/backend.h"

/* Class-A window: exactly 4 GiB of 32-bit guest address space. */
#define VM32_WINDOW_LEN 0x100000000ULL
#define VM32_GUEST_PAGE 4096u
#define VM32_PAGE_COUNT (VM32_WINDOW_LEN / VM32_GUEST_PAGE)

/* Regime selectors. */
typedef enum {
    VM32_REGIME_A1 = 1, /* Direct [x20, wAddr, uxtw], H == 4096 */
    VM32_REGIME_A2 = 2 /* Soft-TLB over MAP_PRIVATE arena, H > 4096 */
} vm32_regime_t;

static vm32_regime_t g_vm32_regime = VM32_REGIME_A1;
static bool g_vm32_ready = false;
static uint64_t g_vm32_base = 0u;

/* Per-4 KiB guest page protection (Linux PROT bits) and state bits. */
static uint8_t *g_vm32_prot = NULL;
static uint8_t *g_vm32_state = NULL;

/* Per-thread Soft-TLB (128 KiB): owner ctx + entries, see mem_site.h. */
static _Thread_local rt_tlb_entry_t t_tlb[RT_TLB_SIZE];
static _Thread_local const sparc32_ctx_t *t_tlb_owner = NULL;

static void vm32_tlb_reset_thread(const sparc32_ctx_t *ctx)
{
    uint64_t i;
    for (i = 0u; i < (uint64_t)RT_TLB_SIZE; i++) {
        t_tlb[i].read_tag = RT_TLB_INVALID_TAG;
        t_tlb[i].addend = 0u;
        t_tlb[i].write_tag = RT_TLB_INVALID_TAG;
        t_tlb[i].flags_reserved = 0u;
    }
    t_tlb_owner = ctx;
}

/* Current regime (valid after vm32_reserve). */
int vm32_regime(void)
{
    return (int)g_vm32_regime;
}

/* True once the window has been reserved for this process. */
bool vm32_ready(void)
{
    return g_vm32_ready;
}

/*
 * Reserve the 4 GiB window and bind ctx->guest_base. Regime follows the
 * live host page size: H == 4096 selects A1 (x20 = G, hardware
 * addressing), H > 4096 selects A2 (x20 = &tlb[0], Soft-TLB). Returns 0
 * on success, -1 on host mapping failure.
 */
int vm32_reserve(sparc32_ctx_t *ctx)
{
    size_t host_page;
    void *base = NULL;
    int rc;
    if (ctx == NULL) {
        return -1;
    }
    if (g_vm32_ready) {
        ctx->guest_base = g_vm32_base;
        return 0;
    }
    host_page = rt_host_page_size();
    g_vm32_regime = (host_page == (size_t)VM32_GUEST_PAGE) ?
        VM32_REGIME_A1 : VM32_REGIME_A2;
    rc = rt_host_map_anon(NULL, (size_t)VM32_WINDOW_LEN, 0, 0, 1, &base);
    if (rc != 0 || base == NULL) {
        return -1;
    }
    g_vm32_prot = (uint8_t *)calloc((size_t)VM32_PAGE_COUNT, 1u);
    g_vm32_state = (uint8_t *)calloc((size_t)VM32_PAGE_COUNT, 1u);
    if (g_vm32_prot == NULL || g_vm32_state == NULL) {
        free(g_vm32_prot);
        free(g_vm32_state);
        g_vm32_prot = NULL;
        g_vm32_state = NULL;
        rt_host_unmap(base, (size_t)VM32_WINDOW_LEN);
        return -1;
    }
    g_vm32_base = (uint64_t)(uintptr_t)base;
    g_vm32_ready = true;
    ctx->guest_base = g_vm32_base;
    vm32_tlb_reset_thread(ctx);
    return 0;
}

/* Canonical host address: every engine addresses HVA = G + gva. */
void *vm32_hva(const sparc32_ctx_t *ctx, uint32_t gva)
{
    (void)ctx;
    return (void *)(uintptr_t)(g_vm32_base + (uint64_t)gva);
}

/*
 * Publish per-page state after an mmap/mprotect/munmap commit (section
 * 4.5 Step 4 caller). Marks PAGE_HAS_CODE-free writable pages valid for
 * write_tag via rt_write_tag_allowed; callers then refresh the TLB.
 */
void vm32_publish_page(uint32_t gva, uint32_t prot, uint32_t state)
{
    uint64_t vpn = (uint64_t)(gva / VM32_GUEST_PAGE);
    if (!g_vm32_ready || vpn >= (uint64_t)VM32_PAGE_COUNT) {
        return;
    }
    g_vm32_prot[vpn] = (uint8_t)(prot & 7u);
    g_vm32_state[vpn] = (uint8_t)(state & 0xFFu);
}

/*
 * Soft-TLB miss helper (shared per-block trampoline target, section
 * 4.3.3): validates [gva, gva+width) against the published tables,
 * refreshes the calling thread's entry, and returns the canonical HVA.
 * On fault sets ctx EXIT_FAULT/fault_addr and returns NULL. Widths 1/2
 * /4/8 stay single-page fast; width 16 validates both touched pages.
 */
void *vm_tlb_miss_helper(sparc32_ctx_t *ctx, uint32_t gva, uint32_t width,
    bool is_store)
{
    uint64_t vpn;
    uint64_t idx;
    uintptr_t addend;
    uint8_t prot;
    uint8_t state;
    if (ctx == NULL || !g_vm32_ready) {
        return NULL;
    }
    if (width != 1u && width != 2u && width != 4u && width != 8u &&
        width != 16u) {
        ctx->exit_reason = SPARC32_EXIT_FAULT;
        ctx->fault_addr = gva;
        return NULL;
    }
    if ((gva & (width > 4u ? 3u : (width - 1u))) != 0u) {
        ctx->exit_reason = SPARC32_EXIT_FAULT;
        ctx->fault_addr = gva;
        return NULL;
    }
    vpn = (uint64_t)(gva / VM32_GUEST_PAGE);
    if (vpn >= (uint64_t)VM32_PAGE_COUNT) {
        ctx->exit_reason = SPARC32_EXIT_FAULT;
        ctx->fault_addr = gva;
        return NULL;
    }
    if (t_tlb_owner != ctx) {
        vm32_tlb_reset_thread(ctx);
    }
    prot = g_vm32_prot[vpn];
    state = g_vm32_state[vpn];
    if (is_store ? (prot & 2u) == 0u : (prot & 1u) == 0u) {
        ctx->exit_reason = SPARC32_EXIT_FAULT;
        ctx->fault_addr = gva;
        return NULL;
    }
    if (is_store && !rt_write_tag_allowed((uint32_t)state, (uint32_t)prot)) {
        ctx->exit_reason = SPARC32_EXIT_FAULT;
        ctx->fault_addr = gva;
        return NULL;
    }
    idx = (vpn & (uint64_t)(RT_TLB_SIZE - 1u));
    /* Per-entry addend is host_page_base - tag (mem_site.h): the arena
     * is one contiguous reservation, so this page's host base is
     * G + vpn * 4 KiB. A bare G under-subtracts by the page base and
     * misplaces every A2 HVA by up to 4 GiB - 4 KiB. */
    addend = (uintptr_t)g_vm32_base +
        (uintptr_t)(vpn * (uint64_t)VM32_GUEST_PAGE);
    t_tlb[idx].read_tag = (uint64_t)(vpn * (uint64_t)VM32_GUEST_PAGE);
    t_tlb[idx].addend = addend - (uintptr_t)t_tlb[idx].read_tag;
    t_tlb[idx].write_tag = is_store ? t_tlb[idx].read_tag :
        t_tlb[idx].write_tag;
    if (!is_store) {
        t_tlb[idx].write_tag = rt_write_tag_allowed((uint32_t)state,
            (uint32_t)prot) ? t_tlb[idx].read_tag : RT_TLB_INVALID_TAG;
    }
    return vm32_hva(ctx, gva);
}

/*
 * Range-selective Soft-TLB invalidation (section 4.5 Step 5): fewer than
 * 512 pages invalidate only the covered indices, anything larger clears
 * the calling thread's table (peers clear lazily via the quiescence
 * epoch + preemption rewind).
 */
void vm32_tlb_invalidate(uint32_t start, uint32_t len)
{
    uint64_t first;
    uint64_t count;
    uint64_t i;
    if (!g_vm32_ready) {
        return;
    }
    first = (uint64_t)(start / VM32_GUEST_PAGE);
    count = (uint64_t)((len + (size_t)VM32_GUEST_PAGE - 1u) /
        (size_t)VM32_GUEST_PAGE);
    if (count >= 512u) {
        vm32_tlb_reset_thread(t_tlb_owner);
        return;
    }
    for (i = 0u; i < count; i++) {
        uint64_t idx = (first + i) & (uint64_t)(RT_TLB_SIZE - 1u);
        t_tlb[idx].read_tag = RT_TLB_INVALID_TAG;
        t_tlb[idx].write_tag = RT_TLB_INVALID_TAG;
    }
}

/*
 * SMC hook: a store or copyout to a PAGE_HAS_CODE page retires the
 * overlapping DBT blocks (via the existing vm_invalidate_jit path) and
 * clears the write tags so further stores trap into the miss helper.
 */
void vm32_note_code_page(uint32_t gva, uint32_t len)
{
    uint64_t vpn = (uint64_t)(gva / VM32_GUEST_PAGE);
    if (!g_vm32_ready || vpn >= (uint64_t)VM32_PAGE_COUNT) {
        return;
    }
    g_vm32_state[vpn] |= (uint8_t)RT_PAGE_HAS_CODE;
    vm32_tlb_invalidate(gva, len);
}
