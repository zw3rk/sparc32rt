/*
 * src/vm/vm32.c — Class-A 32-bit 4 GiB window, Regime A1/A2 (Wave U3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements the 4 GiB guest window and per-4 KiB page protection/state
 * tables for sparc32rt:
 *
 * Regime A1 (host page size H == 4096, native 4 KiB Linux and every
 * hyper-linux run): reserve one 4 GiB MAP_PRIVATE|MAP_ANONYMOUS window
 * [G, G + 4 GiB) with x20 = G. Every 4 KiB guest page maps 1:1 to a host
 * page; guest fork() is native kernel MAP_PRIVATE COW.
 *
 * Regime A2 (H > 4096: standalone 16 KiB macOS Mach-O backend_darwin.c
 * and native 16K/64K Linux without /dev/a32host): the same 4 GiB range
 * is a single MAP_PRIVATE|MAP_ANONYMOUS arena whose active host pages
 * carry the union of their 4 KiB sub-page permissions (PROT_READ |
 * PROT_WRITE, never PROT_EXEC). x20 = G and x25 = g_vm32_prot_jit so
 * every inline DBT access and interpreter/syscall helper probes the
 * per-4 KiB protection table directly while sharing HVA = G + gva.
 *
 * Per-4 KiB page protection/state tables live here; file backing and
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
    VM32_REGIME_A1 = 1, /* H == 4096 */
    VM32_REGIME_A2 = 2  /* H > 4096 sub-page software permissions */
} vm32_regime_t;

static vm32_regime_t g_vm32_regime = VM32_REGIME_A1;
static bool g_vm32_ready = false;
static uint64_t g_vm32_base = 0u;

/* Per-4 KiB guest page protection (Linux PROT bits) and state bits. */
static uint8_t *g_vm32_prot = NULL;
static uint8_t *g_vm32_state = NULL;
static uint64_t g_vm32_code_mask[4096];

/* P13-4 JIT-visible alias of g_vm32_prot. trampoline_a64.S loads this
 * pointer into callee-saved x25 once per block entry, so every inline
 * load/store probes the table with a single LDRB (no MOVZ/MOVK). */
uint8_t *g_vm32_prot_jit = NULL;

/* P13-4 bit 3 (VM32_PROT_FAST_WRITE): 1 iff the page is writable
 * ((prot & 2) != 0) and holds no translated code
 * ((state & RT_PAGE_HAS_CODE) == 0), so an inline store needs one
 * TBZ instead of a prot check plus a code-bitmap check. */
#define VM32_PROT_FAST_WRITE 0x08u

/* Centralize every g_vm32_prot/g_vm32_state mutation through this
 * helper so bit 3 never goes stale (P13-4 invariant 8). */
static inline void vm32_sync_fast_write(uint32_t vpn)
{
    uint8_t p = g_vm32_prot[vpn];
    uint8_t s = g_vm32_state[vpn];
    if (((p & 2u) != 0u) && ((s & (uint8_t)RT_PAGE_HAS_CODE) == 0u)) {
        g_vm32_prot[vpn] = (uint8_t)(p | VM32_PROT_FAST_WRITE);
    } else {
        g_vm32_prot[vpn] = (uint8_t)(p & (uint8_t)~VM32_PROT_FAST_WRITE);
    }
}

/* Current regime (valid after vm32_reserve/vm32_attach). */
int vm32_regime(void)
{
    return (int)g_vm32_regime;
}

/* True once the window has been reserved for this process. */
bool vm32_ready(void)
{
    return g_vm32_ready;
}

/* Allocate the per-4 KiB protection/state tables (shared by the fresh
 * reserve path and the adopt path below). */
static int vm32_alloc_tables(void)
{
    if (g_vm32_prot == NULL) {
        g_vm32_prot = (uint8_t *)calloc((size_t)VM32_PAGE_COUNT, 1u);
        if (g_vm32_prot == NULL) {
            return -1;
        }
    }
    if (g_vm32_state == NULL) {
        g_vm32_state = (uint8_t *)calloc((size_t)VM32_PAGE_COUNT, 1u);
        if (g_vm32_state == NULL) {
            free(g_vm32_prot);
            g_vm32_prot = NULL;
            return -1;
        }
    }
    return 0;
}

/*
 * Reserve the 4 GiB window and bind ctx->guest_base.
 * Returns 0 on success, -1 on host mapping failure.
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
    if (vm32_alloc_tables() != 0) {
        rt_host_unmap(base, (size_t)VM32_WINDOW_LEN);
        return -1;
    }
    g_vm32_prot_jit = g_vm32_prot;
    g_vm32_base = (uint64_t)(uintptr_t)base;
    g_vm32_ready = true;
    ctx->guest_base = g_vm32_base;
    return 0;
}

/*
 * Adopt the window the rt32 layer already reserved (RC-U3-r2 #4):
 * rt32_vm_init runs first and binds ctx->guest_base, so the Regime VM
 * must observe that same [G, G + 4 GiB) mapping instead of reserving a
 * second window. Allocates the protection/state tables when missing,
 * selects the regime from the live host page size, and marks the VM
 * ready. Idempotent: re-attaching an already-ready process just
 * rebinds ctx. Returns 0 on success, -1 on allocation failure.
 */
int vm32_attach(sparc32_ctx_t *ctx)
{
    size_t host_page;
    if (ctx == NULL) {
        return -1;
    }
    if (g_vm32_ready) {
        ctx->guest_base = g_vm32_base;
        return 0;
    }
    if (vm32_alloc_tables() != 0) {
        return -1;
    }
    g_vm32_prot_jit = g_vm32_prot;
    host_page = rt_host_page_size();
    g_vm32_regime = (host_page == (size_t)VM32_GUEST_PAGE) ?
        VM32_REGIME_A1 : VM32_REGIME_A2;
    g_vm32_base = ctx->guest_base;
    g_vm32_ready = true;
    return 0;
}

/* Clear all per-page permissions and state across execve reset. */
void vm32_reset(void)
{
    if (!g_vm32_ready) {
        return;
    }
    if (g_vm32_prot != NULL) {
        memset(g_vm32_prot, 0, (size_t)VM32_PAGE_COUNT);
    }
    if (g_vm32_state != NULL) {
        memset(g_vm32_state, 0, (size_t)VM32_PAGE_COUNT);
    }
    memset(g_vm32_code_mask, 0, sizeof(g_vm32_code_mask));
}

/* Canonical host address: every engine addresses HVA = G + gva. */
void *vm32_hva(const sparc32_ctx_t *ctx, uint32_t gva)
{
    (void)ctx;
    return (void *)(uintptr_t)(g_vm32_base + (uint64_t)gva);
}

/*
 * Publish per-page state after an mmap/mprotect/munmap commit.
 */
void vm32_publish_page(uint32_t gva, uint32_t prot, uint32_t state)
{
    uint64_t vpn = (uint64_t)(gva / VM32_GUEST_PAGE);
    if (!g_vm32_ready || vpn >= (uint64_t)VM32_PAGE_COUNT) {
        return;
    }
    g_vm32_prot[vpn] = (uint8_t)(prot & 7u);
    g_vm32_state[vpn] = (uint8_t)(state & 0xFFu);
    vm32_sync_fast_write((uint32_t)vpn);
}

/*
 * Revert one page to CLEAN after a file shrink (RC-U3-r4): pages fully
 * beyond the new EOF must refill from the file on next fault instead of
 * serving stale DIRTY bytes. Other state bits (CODE/RESERVATION) and
 * the recorded protection are preserved.
 */
uint32_t vm32_page_state(uint32_t gva)
{
    uint64_t vpn = (uint64_t)(gva / VM32_GUEST_PAGE);
    if (!g_vm32_ready || vpn >= (uint64_t)VM32_PAGE_COUNT) {
        return 0u;
    }
    return (uint32_t)g_vm32_state[vpn];
}

void vm32_page_revert_clean(uint32_t gva)
{
    uint64_t vpn = (uint64_t)(gva / VM32_GUEST_PAGE);
    uint8_t state;
    if (!g_vm32_ready || vpn >= (uint64_t)VM32_PAGE_COUNT) {
        return;
    }
    state = g_vm32_state[vpn];
    if ((state & (uint8_t)RT_PAGE_COW_DIRTY) == 0u) {
        return;
    }
    state &= (uint8_t)~RT_PAGE_COW_DIRTY;
    state |= (uint8_t)RT_PAGE_COW_CLEAN;
    g_vm32_state[vpn] = state;
    vm32_sync_fast_write((uint32_t)vpn);
}

/* Retained no-op hook for VM lifecycle callers; permissions live in
 * g_vm32_prot / g_vm32_prot_jit and take effect immediately. */
void vm32_tlb_invalidate(uint32_t start, uint32_t len)
{
    (void)start;
    (void)len;
}

/*
 * SMC hook: mark all 4 KiB pages covered by [gva, gva + len) as holding
 * translated code and clear VM32_PROT_FAST_WRITE so subsequent stores trap
 * into the slow path and invalidate stale translations.
 */
void vm32_note_code_page(uint32_t gva, uint32_t len)
{
    uint64_t first;
    uint64_t last;
    uint64_t vpn;
    uint64_t lfirst;
    uint64_t llast;
    uint64_t line;
    uint32_t eff_len = (len == 0u) ? 1u : len;
    if (!g_vm32_ready) {
        return;
    }
    lfirst = (uint64_t)(gva >> 6);
    llast = ((uint64_t)gva + (uint64_t)eff_len - 1u) >> 6;
    for (line = lfirst; line <= llast; line++) {
        uint32_t pv = (uint32_t)(line >> 6) & 4095u;
        uint32_t bit = (uint32_t)line & 63u;
        __atomic_or_fetch(&g_vm32_code_mask[pv], (uint64_t)1u << bit,
            __ATOMIC_RELEASE);
    }
    first = (uint64_t)(gva / VM32_GUEST_PAGE);
    last = ((uint64_t)gva + (uint64_t)eff_len - 1u) /
        (uint64_t)VM32_GUEST_PAGE;
    if (last >= (uint64_t)VM32_PAGE_COUNT) {
        last = (uint64_t)VM32_PAGE_COUNT - 1u;
    }
    for (vpn = first; vpn <= last; vpn++) {
        g_vm32_state[vpn] |= (uint8_t)RT_PAGE_HAS_CODE;
        vm32_sync_fast_write((uint32_t)vpn);
    }
}

void vm32_clear_code_range(uint32_t start, uint32_t end)
{
    uint64_t first;
    uint64_t last;
    uint64_t vpn;
    if (!g_vm32_ready || end <= start) {
        return;
    }
    first = (uint64_t)(start / VM32_GUEST_PAGE);
    last = (uint64_t)((end - 1u) / VM32_GUEST_PAGE);
    if (last >= (uint64_t)VM32_PAGE_COUNT) {
        last = (uint64_t)VM32_PAGE_COUNT - 1u;
    }
    for (vpn = first; vpn <= last; vpn++) {
        g_vm32_state[vpn] &= (uint8_t)~RT_PAGE_HAS_CODE;
        __atomic_store_n(&g_vm32_code_mask[(uint32_t)vpn & 4095u], 0ULL,
            __ATOMIC_RELEASE);
        vm32_sync_fast_write((uint32_t)vpn);
    }
}

bool vm32_range_has_code(uint32_t gva, size_t len)
{
    uint64_t first;
    uint64_t last;
    uint64_t vpn;
    if (!g_vm32_ready || g_vm32_state == NULL || len == 0u) {
        return false;
    }
    if (len <= 64u && (((gva ^ (gva + (uint32_t)len - 1u)) >> 12) == 0u)) {
        uint32_t pv = gva >> 12;
        uint64_t mask;
        uint32_t b0;
        uint32_t b1;
        if ((g_vm32_state[pv] & (uint8_t)RT_PAGE_HAS_CODE) == 0u) {
            return false;
        }
        mask = __atomic_load_n(&g_vm32_code_mask[pv & 4095u], __ATOMIC_ACQUIRE);
        b0 = (gva >> 6) & 63u;
        b1 = ((gva + (uint32_t)len - 1u) >> 6) & 63u;
        return (((mask >> b0) & 1ULL) != 0ULL) ||
            (((mask >> b1) & 1ULL) != 0ULL);
    }
    first = (uint64_t)(gva / VM32_GUEST_PAGE);
    last = ((uint64_t)gva + (uint64_t)len - 1u) / (uint64_t)VM32_GUEST_PAGE;
    if (last >= (uint64_t)VM32_PAGE_COUNT) {
        last = (uint64_t)VM32_PAGE_COUNT - 1u;
    }
    for (vpn = first; vpn <= last; vpn++) {
        if ((g_vm32_state[vpn] & (uint8_t)RT_PAGE_HAS_CODE) != 0u) {
            return true;
        }
    }
    return false;
}

/* Lane P5 inline fast-path tables (emit_priv.h): per-4K prot/state bases
 * for the JIT to check alignment-mapped permissions inline. */
const uint8_t *sparc32_vm_prot_base(void)
{
    return g_vm32_prot;
}

const uint8_t *sparc32_vm_state_base(void)
{
    return g_vm32_state;
}
