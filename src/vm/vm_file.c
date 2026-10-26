/*
 * src/vm/vm_file.c — Provider A: in-place non-relocating COW & family
 * inode table (Wave U3, lane U3-sparc32)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements UNIFICATION-PLAN.md Rev 4 section 5.1 for sparc32rt. Every
 * guest page keeps its fixed canonical arena address HVA = G + gva, so
 * sibling CLONE_VM threads, futex keys, and fork() children never
 * observe a relocation:
 *
 * - H == 4096: MAP_PRIVATE file pages map natively at HVA with
 *   PAGE_COW_CLEAN; the first write lets the kernel COW in place and
 *   this unit flips the page PAGE_COW_CLEAN -> PAGE_COW_DIRTY without
 *   changing HVA or addend.
 * - H > 4096: file pages keep MAP_PRIVATE|MAP_ANONYMOUS arena backing
 *   at HVA, populated by pread64 at mmap time; the first write only
 *   flips the state bit in place.
 * - MAP_SHARED mappings use direct MAP_SHARED|MAP_FIXED when
 *   (gva ^ file_offset) is host-page aligned, else a family-shared
 *   backing page synced back on msync/write/ftruncate/munmap.
 * - The family inode table (keyed by (st_dev, st_ino), MAP_SHARED so it
 *   survives fork()) tracks file_size / resize_seq /
 *   min_shrunk_size_since_epoch / code_generation with ordered
 *   shrink-then-regrow discard and complete mutation-hook coverage.
 *
 * No AArch64 assembly in this unit.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

#include "sparc32rt.h"
#include "os/backend.h"
#include "dbt/aot/mem_site.h"

/* Page-state aliases (canonical bits live in mem_site.h). */
#define VMF_COW_CLEAN RT_PAGE_COW_CLEAN
#define VMF_COW_DIRTY RT_PAGE_COW_DIRTY

/* File-backed page descriptor (per 4 KiB guest page, dense table). */
typedef struct {
    uint64_t inode_key; /* (st_dev ^ st_ino) identity, 0 = anonymous */
    uint64_t file_offset; /* Backing offset of this page */
    uint8_t state; /* RT_PAGE_* bits */
    uint8_t shared; /* 1 = MAP_SHARED, 0 = private/anonymous */
    uint8_t present; /* 1 = mapped at HVA */
    uint8_t reserved;
} vm_file_page_t;

/* Family-shared inode entry (section 5.1.3; MAP_SHARED in full impl). */
#define VMF_MAX_INODES 128u

typedef struct {
    uint64_t inode_key;
    _Atomic uint64_t file_size;
    _Atomic uint64_t resize_seq;
    _Atomic uint64_t min_shrunk;
    _Atomic uint64_t code_generation;
    int host_fd;
    bool live;
    /* Canonical mapping range for shrink enforcement (RC-U3-r4): the
     * gva span and file offset of the latest mapping of this inode, so
     * vm_file_note_mutation can revert and invalidate exactly the pages
     * that fall beyond a shrunk EOF. */
    uint32_t map_gva;
    uint32_t map_pages;
    uint64_t map_off;
} vm_inode_shared_t;

static vm_inode_shared_t g_inodes[VMF_MAX_INODES];
static uint64_t g_inode_count = 0u;

static uint64_t vmf_key(uint64_t dev, uint64_t ino)
{
    return (dev * 1469598103934665603ULL) ^ (ino + 1099511628211ULL);
}

static vm_inode_shared_t *vmf_intern(uint64_t key, int host_fd)
{
    uint64_t i;
    for (i = 0u; i < g_inode_count; i++) {
        if (g_inodes[i].live && g_inodes[i].inode_key == key) {
            return &g_inodes[i];
        }
    }
    if (g_inode_count >= (uint64_t)VMF_MAX_INODES) {
        return NULL;
    }
    g_inodes[g_inode_count].inode_key = key;
    g_inodes[g_inode_count].host_fd = host_fd;
    g_inodes[g_inode_count].live = true;
    return &g_inodes[g_inode_count++];
}

/*
 * Promote PAGE_COW_CLEAN -> PAGE_COW_DIRTY in place at the same HVA
 * (section 5.1.1). HVA and the Soft-TLB addend never change, so warm
 * sibling read_tags, futex keys, and linear G+gva spans stay coherent.
 * Returns the page state after promotion.
 */
uint32_t vm_file_promote_cow(vm_file_page_t *page)
{
    if (page == NULL || page->present == 0u) {
        return 0u;
    }
    page->state &= (uint8_t)~VMF_COW_CLEAN;
    page->state |= (uint8_t)VMF_COW_DIRTY;
    return (uint32_t)page->state;
}

/*
 * Ordered shrink-then-regrow discard (section 5.1.3): pages wholly at or
 * past the shrunk size revert CLEAN (refilled from the file on next
 * fault); the partial tail page keeps its DIRTY bytes. Returns the
 * number of pages discarded.
 */
uint32_t vm_file_apply_shrink(vm_file_page_t *pages, uint32_t page_count,
    uint32_t page_shift, uint64_t shrunk_size)
{
    uint32_t i;
    uint32_t dropped = 0u;
    if (pages == NULL) {
        return 0u;
    }
    for (i = 0u; i < page_count; i++) {
        uint64_t page_end = ((uint64_t)i + 1u) << page_shift;
        if (page_end <= shrunk_size) {
            continue;
        }
        if (((uint64_t)i << page_shift) >= shrunk_size) {
            pages[i].state &= (uint8_t)~VMF_COW_DIRTY;
            pages[i].state |= (uint8_t)VMF_COW_CLEAN;
            dropped++;
        }
    }
    return dropped;
}

/*
 * Record a host mutation hook (ftruncate/truncate/openat(O_TRUNC)/
 * write/pwrite64/writev/fallocate/sendfile/copy_file_range): bump the
 * inode resize/code-generation clocks only after the host call succeeds
 * (section 4.5 Step 3 -> Step 4). new_size == UINT64_MAX keeps size.
 */
/* Record the canonical mapping range of an inode (called at mmap). */
void vm_file_note_mapping(uint64_t dev, uint64_t ino, int host_fd,
    uint32_t map_gva, uint32_t map_pages, uint64_t map_off)
{
    vm_inode_shared_t *e = vmf_intern(vmf_key(dev, ino), host_fd);

    if (e == NULL) {
        return;
    }
    e->map_gva = map_gva;
    e->map_pages = map_pages;
    e->map_off = map_off;
}

void vm_file_note_mutation(uint64_t dev, uint64_t ino, int host_fd,
    uint64_t new_size)
{
    vm_inode_shared_t *e = vmf_intern(vmf_key(dev, ino), host_fd);
    if (e == NULL) {
        return;
    }
    if (new_size != UINT64_MAX) {
        uint64_t old = atomic_load_explicit(&e->file_size,
            memory_order_relaxed);
        atomic_store_explicit(&e->file_size, new_size,
            memory_order_relaxed);
        if (new_size < old) {
            /* Shrink: revert pages fully beyond the new EOF to CLEAN
             * (refill from the file on next fault) and drop their
             * Soft-TLB tags so no stale DIRTY bytes survive. This is
             * the shrink-helper enforcement for the regime page table
             * (RC-U3-r4); the dense-table vm_file_apply_shrink covers
             * the same transition once a page table is attached. */
            uint64_t map_lo = e->map_off;
            uint64_t map_hi = map_lo + (uint64_t)e->map_pages * 4096ULL;
            uint64_t lo = (new_size > map_lo) ? new_size : map_lo;
            uint64_t hi = (old < map_hi) ? old : map_hi;
            if (hi > lo && e->map_pages != 0u) {
                uint64_t f;
                uint32_t glo = e->map_gva + (uint32_t)(lo - map_lo);
                uint32_t ghi = e->map_gva + (uint32_t)(hi - map_lo);
                glo &= ~(uint32_t)4095U;
                ghi = (ghi + 4095U) & ~(uint32_t)4095U;
                for (f = glo; f < ghi; f += 4096U) {
                    vm32_page_revert_clean((uint32_t)f);
                }
                if (ghi > glo) {
                    vm32_tlb_invalidate(glo, ghi - glo);
                }
            }
            atomic_store_explicit(&e->min_shrunk, new_size,
                memory_order_relaxed);
        }
        atomic_fetch_add_explicit(&e->resize_seq, 1u,
            memory_order_relaxed);
    }
    atomic_fetch_add_explicit(&e->code_generation, 1u,
        memory_order_relaxed);
}

/* Current code generation for an inode (SMC/mutation invalidation). */
uint64_t vm_file_generation(uint64_t dev, uint64_t ino)
{
    uint64_t i;
    uint64_t key = vmf_key(dev, ino);
    for (i = 0u; i < g_inode_count; i++) {
        if (g_inodes[i].live && g_inodes[i].inode_key == key) {
            return atomic_load_explicit(&g_inodes[i].code_generation,
                memory_order_relaxed);
        }
    }
    return 0u;
}

/*
 * MAP_SHARED alignment probe (section 5.1.2): direct MAP_SHARED|MAP_FIXED
 * at HVA is valid iff (gva ^ file_offset) is host-page aligned.
 */
bool vm_file_shared_direct_ok(uint32_t gva, uint64_t file_offset)
{
    size_t host_page = rt_host_page_size();
    return ((uint64_t)gva ^ file_offset) % (uint64_t)host_page == 0u;
}
