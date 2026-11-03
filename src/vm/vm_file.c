/*
 * src/vm/vm_file.c — Provider-A file-tracking table (Wave U3, lane U3-sparc32)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements a process-local table of guest file mappings for shrink and
 * mutation handling. Each mmap of a file registers one entry keyed by
 * ((st_dev, st_ino), map_gva) holding the guest range, the backing file
 * offset, and the tracked file_size / code_generation clocks.
 * Host truncate/write hooks (vm_file_note_mutation) bump the
 * clocks and revert pages that fall beyond a shrunk EOF to clean.
 * munmap, MAP_FIXED replacement, mremap source retirement, and exec
 * reset retire entries via vm_file_unregister_range / vm_file_reset so
 * unmapped records are skipped by later hooks and their slots recycled.
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

/* Process-local tracked inode entry. */
#define VMF_MAX_INODES 128u

typedef struct {
    uint64_t inode_key;
    _Atomic uint64_t file_size;
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

/* Allocate a table slot, recycling a retired entry first (S32-R5-9) so
 * the 128-entry table is not permanently exhausted by churn. */
static vm_inode_shared_t *vmf_alloc(uint64_t key, int host_fd,
    uint32_t map_gva)
{
    uint64_t i;
    for (i = 0u; i < g_inode_count; i++) {
        if (!g_inodes[i].live) {
            g_inodes[i].inode_key = key;
            g_inodes[i].host_fd = host_fd;
            g_inodes[i].live = true;
            g_inodes[i].map_gva = map_gva;
            g_inodes[i].map_pages = 0u;
            g_inodes[i].map_off = 0u;
            atomic_store_explicit(&g_inodes[i].file_size, 0u,
                memory_order_relaxed);
            atomic_store_explicit(&g_inodes[i].code_generation, 1u,
                memory_order_relaxed);
            return &g_inodes[i];
        }
    }
    if (g_inode_count >= (uint64_t)VMF_MAX_INODES) {
        return NULL;
    }
    g_inodes[g_inode_count].inode_key = key;
    g_inodes[g_inode_count].host_fd = host_fd;
    g_inodes[g_inode_count].live = true;
    g_inodes[g_inode_count].map_gva = map_gva;
    g_inodes[g_inode_count].map_pages = 0u;
    g_inodes[g_inode_count].map_off = 0u;
    atomic_store_explicit(&g_inodes[g_inode_count].file_size, 0u,
        memory_order_relaxed);
    atomic_store_explicit(&g_inodes[g_inode_count].code_generation, 1u,
        memory_order_relaxed);
    return &g_inodes[g_inode_count++];
}

/* Intern by (inode key, mapped gva): a second mmap of the same file at a
 * different gva allocates a separate entry rather than overwriting the
 * earlier mapping's range (RC-U3-r5), so shrink handling reaches every
 * mapping of the inode. */
static vm_inode_shared_t *vmf_intern(uint64_t key, int host_fd,
    uint32_t map_gva)
{
    uint64_t i;
    for (i = 0u; i < g_inode_count; i++) {
        if (g_inodes[i].live && g_inodes[i].inode_key == key &&
            g_inodes[i].map_gva == map_gva) {
            return &g_inodes[i];
        }
    }
    return vmf_alloc(key, host_fd, map_gva);
}

/*
 * Record a host mutation hook (ftruncate/truncate/openat(O_TRUNC)/
 * write/pwrite64/writev/fallocate/sendfile/copy_file_range): bump the
 * inode resize/code-generation clocks only after the host call succeeds
 * (section 4.5 Step 3 -> Step 4). new_size == UINT64_MAX keeps size.
 */
/* Record the canonical mapping range of an inode (called at mmap).
 * RC-U3-r5: one entry per mapping, not per inode. A second mmap of the
 * same (dev, ino) at a different gva allocates a separate entry instead
 * of overwriting the earlier mapping, so shrink and generation handling
 * reach every mapping. */
void vm_file_note_mapping(uint64_t dev, uint64_t ino, int host_fd,
    uint32_t map_gva, uint32_t map_pages, uint64_t map_off)
{
    uint64_t key = vmf_key(dev, ino);
    vm_inode_shared_t *e = vmf_intern(key, host_fd, map_gva);

    if (e == NULL) {
        return;
    }
    e->map_pages = map_pages;
    e->map_off = map_off;
}

/* Apply a shrink to one mapping entry (RC-U3-r4 enforcement). */
static void vmf_shrink_entry(vm_inode_shared_t *e, uint64_t new_size,
    uint64_t old)
{
    uint64_t map_lo = e->map_off;
    uint64_t map_hi = map_lo + (uint64_t)e->map_pages * 4096ULL;
    uint64_t lo = (new_size > map_lo) ? new_size : map_lo;
    uint64_t hi = (old < map_hi) ? old : map_hi;

    if (hi <= lo || e->map_pages == 0u) {
        return;
    }
    {
        uint64_t f;
        uint32_t glo = e->map_gva + (uint32_t)(lo - map_lo);
        uint32_t ghi = e->map_gva + (uint32_t)(hi - map_lo);
        glo &= ~(uint32_t)4095U;
        ghi = (ghi + 4095U) & ~(uint32_t)4095U;
        for (f = glo; f < ghi; f += 4096U) {
            vm32_page_revert_clean((uint32_t)f);
        }
    }
}

void vm_file_note_mutation(uint64_t dev, uint64_t ino, int host_fd,
    uint64_t new_size)
{
    uint64_t key = vmf_key(dev, ino);
    uint64_t i;

    /* RC-U3-r5: act on every mapping of the inode, not just the first
     * intern hit, so no mapping keeps stale bytes past a shrink. */
    (void)host_fd;
    for (i = 0u; i < (uint64_t)VMF_MAX_INODES; i++) {
        vm_inode_shared_t *e = &g_inodes[i];
        uint64_t old;
        if (!e->live || e->inode_key != key) {
            continue;
        }
        if (new_size == UINT64_MAX) {
            atomic_fetch_add_explicit(&e->code_generation, 1u,
                memory_order_relaxed);
            continue;
        }
        old = atomic_load_explicit(&e->file_size, memory_order_relaxed);
        atomic_store_explicit(&e->file_size, new_size,
            memory_order_relaxed);
        if (new_size < old) {
            vmf_shrink_entry(e, new_size, old);
        }
        atomic_fetch_add_explicit(&e->code_generation, 1u,
            memory_order_relaxed);
    }
}

/* Retire (part of) a guest range from the file-tracking table (S32-R5-9).
 * Called on munmap, MAP_FIXED replacement, and mremap source retirement so
 * later mutation hooks skip unmapped records and vmf_alloc recycles their
 * slots. Full coverage retires the entry; partial coverage trims it; a
 * hole in the middle splits the tail into a recycled slot when one is
 * free (otherwise the tail tracking is dropped). */
void vm_file_unregister_range(uint32_t gva, uint32_t len)
{
    uint32_t start = gva & ~(uint32_t)4095U;
    uint64_t end64 = (uint64_t)gva + (uint64_t)len;
    uint32_t end;
    uint64_t i;
    if (len == 0U) {
        return;
    }
    end = (uint32_t)((end64 + 4095ULL) & ~4095ULL);
    if (end <= start) {
        return;
    }
    for (i = 0u; i < (uint64_t)VMF_MAX_INODES; i++) {
        vm_inode_shared_t *e = &g_inodes[i];
        uint32_t elo;
        uint32_t ehi;
        if (!e->live || e->map_pages == 0u) {
            continue;
        }
        elo = e->map_gva;
        ehi = elo + e->map_pages * 4096U;
        if (ehi <= start || elo >= end) {
            continue;
        }
        if (start <= elo && end >= ehi) {
            e->live = false;
            e->map_pages = 0u;
            continue;
        }
        if (start <= elo) {
            uint32_t drop = (end - elo) / 4096U;
            e->map_gva += drop * 4096U;
            e->map_off += (uint64_t)drop * 4096ULL;
            e->map_pages -= drop;
            if (e->map_pages == 0u) {
                e->live = false;
            }
            continue;
        }
        if (end >= ehi) {
            e->map_pages = (start - elo) / 4096U;
            if (e->map_pages == 0u) {
                e->live = false;
            }
            continue;
        }
        {
            uint32_t front_pages = (start - elo) / 4096U;
            uint32_t tail_gva = end;
            uint32_t tail_pages = (ehi - end) / 4096U;
            uint64_t tail_off = e->map_off + (uint64_t)(end - elo);
            vm_inode_shared_t *t;
            e->map_pages = front_pages;
            t = vmf_alloc(e->inode_key, e->host_fd, tail_gva);
            if (t == NULL) {
                continue;
            }
            t->map_pages = tail_pages;
            t->map_off = tail_off;
            atomic_store_explicit(&t->file_size,
                atomic_load_explicit(&e->file_size, memory_order_relaxed),
                memory_order_relaxed);
            atomic_store_explicit(&t->code_generation,
                atomic_load_explicit(&e->code_generation,
                    memory_order_relaxed),
                memory_order_relaxed);
        }
    }
}

/* Retire every file-tracking record (S32-R5-9): exec reset destroys the
 * whole address space, so no mapping survives into the new image. */
void vm_file_reset(void)
{
    uint64_t i;
    for (i = 0u; i < (uint64_t)VMF_MAX_INODES; i++) {
        g_inodes[i].live = false;
        g_inodes[i].map_pages = 0u;
    }
    g_inode_count = 0u;
}
