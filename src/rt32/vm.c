/*
 * src/rt32/vm.c — Guest 4 GiB window [G, G+4GiB) reservation and VMA core
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Vendored from i686rt/src/rt32/rt32_vm.c: renamed i686_→sparc32_ /
 * I686_→SPARC32_, retyped on sparc32_ctx_t; guest VA ceiling is
 * SPARC32_TASK_SIZE_TOP (0xF0000000, the SPARC32 Linux user limit; no
 * x86 compat ceiling or kuser page). The mmap / mprotect / munmap /
 * mremap engine lives in vm_mmap.c (900-line split); shared state and
 * locked helpers are declared in vm_int.h.
 */

#define _GNU_SOURCE
#include "vm_int.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

typedef struct {
    int      fd;
    uint32_t pgoff;
    uint64_t dev;
    uint64_t ino;
} vm_region_meta_t;

static size_t vm_host_page_size(void)
{
    long p = sysconf(_SC_PAGESIZE);
    return (p > (long)SPARC32_PAGE_SIZE) ? (size_t)p : (size_t)SPARC32_PAGE_SIZE;
}

static _Atomic uint32_t g_vm_lock = 0U;
static _Atomic uint32_t g_vm_readers = 0U;
static _Atomic uint32_t g_vm_writer_waiting = 0U;
static _Thread_local uint32_t t_vm_lock_held = 0U;
static _Thread_local uint32_t t_vm_read_depth = 0U;
static sparc32_ctx_t   *g_vm_root_ctx = NULL;
static uint32_t         g_vm_brk_base = 0U;
static uint32_t         g_vm_brk_curr = 0U;
uint32_t                g_vm_mmap_cursor = RT32_MMAP_BASE_32;
static sparc32_region_t g_vm_regions[SPARC32_MAX_REGIONS];
static vm_region_meta_t g_vm_region_meta[SPARC32_MAX_REGIONS];
static size_t           g_vm_region_count = 0U;

int vm_dup_backing_fd(int fd)
{
    int dup_fd;
    if (fd < 0) {
        return -1;
    }
    dup_fd = fcntl(fd, F_DUPFD_CLOEXEC, 512);
    if (dup_fd < 0) {
        dup_fd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    }
    return dup_fd;
}

void vm_close_backing_fd(int fd)
{
    if (fd >= 0) {
        (void)close(fd);
    }
}

void sparc32_vm_access_enter(void)
{
    if (t_vm_lock_held != 0U || t_vm_read_depth++ > 0U) {
        return;
    }
    for (;;) {
        while (atomic_load_explicit(&g_vm_writer_waiting,
                   memory_order_acquire) != 0U ||
               atomic_load_explicit(&g_vm_lock,
                   memory_order_acquire) != 0U) {
        }
        atomic_fetch_add_explicit(&g_vm_readers, 1U, memory_order_acq_rel);
        if (atomic_load_explicit(&g_vm_writer_waiting,
                memory_order_acquire) == 0U &&
            atomic_load_explicit(&g_vm_lock,
                memory_order_acquire) == 0U) {
            return;
        }
        atomic_fetch_sub_explicit(&g_vm_readers, 1U, memory_order_release);
    }
}

void sparc32_vm_access_leave(void)
{
    if (t_vm_lock_held != 0U) {
        return;
    }
    if (t_vm_read_depth > 0U && --t_vm_read_depth == 0U) {
        atomic_fetch_sub_explicit(&g_vm_readers, 1U, memory_order_release);
    }
}

void vm_lock_acquire(void)
{
    atomic_fetch_add_explicit(&g_vm_writer_waiting, 1U, memory_order_acq_rel);
    sparc32_spin_lock(&g_vm_lock);
    t_vm_lock_held = 1U;
    atomic_fetch_sub_explicit(&g_vm_writer_waiting, 1U, memory_order_release);
    while (atomic_load_explicit(&g_vm_readers, memory_order_acquire) != 0U) {
    }
}

void vm_lock_release(void)
{
    t_vm_lock_held = 0U;
    sparc32_spin_unlock(&g_vm_lock);
}

/* Fork-child reset (Section 3 #1): fork() retains only the calling thread,
 * so reader/writer-wait/spin state inherited from dead sibling threads
 * would deadlock the child's first VM mutation (vm_lock_acquire spins for
 * g_vm_readers == 0). The forking thread's own thread-local depth is
 * cleared with it: its read holds (if any) counted toward the discarded
 * pre-fork reader total, so keeping them would underflow the fresh count
 * on the matching leave. Async-signal-safe: plain relaxed stores only. */
void sparc32_vm_fork_child_reset(void)
{
    atomic_store_explicit(&g_vm_readers, 0U, memory_order_relaxed);
    atomic_store_explicit(&g_vm_writer_waiting, 0U, memory_order_relaxed);
    atomic_store_explicit(&g_vm_lock, 0U, memory_order_relaxed);
    t_vm_lock_held = 0U;
    t_vm_read_depth = 0U;
}

uint64_t vm_page_align_up(uint64_t v)
{
    return (v + 0xFFFULL) & ~0xFFFULL;
}

int vm_reserve_prot_none(sparc32_ctx_t *ctx, uint32_t start, uint32_t len)
{
    size_t hp = vm_host_page_size();
    void *res;
    if (hp > (size_t)SPARC32_PAGE_SIZE) {
        uint32_t mask = (uint32_t)hp - 1U;
        uint32_t in_start = (start + mask) & ~mask;
        uint32_t in_end   = (start + len) & ~mask;
        if (in_end > in_start) {
            (void)mprotect(sparc32_guest_ptr(ctx, in_start),
                           (size_t)(in_end - in_start), PROT_NONE);
        }
        return 0;
    }
    res = mmap(sparc32_guest_ptr(ctx, start), (size_t)len, PROT_NONE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (res == MAP_FAILED) {
        return -errno;
    }
    return 0;
}

/* Translation-cache invalidation on guest mm ops (SMC): real since the
 * Phase 2 DBT; the interpreter has no code cache (the call is cheap). */
#ifdef SPARC32RT_NO_DBT
void vm_invalidate_jit(sparc32_ctx_t *ctx, uint32_t start, uint32_t end)
{
    (void)ctx; (void)start; (void)end;
}
#else
extern void sparc32_dbt_invalidate_range(sparc32_ctx_t *ctx, uint32_t start,
                                         uint32_t end);
void vm_invalidate_jit(sparc32_ctx_t *ctx, uint32_t start, uint32_t end)
{
    sparc32_dbt_invalidate_range(ctx, start, end);
}
#endif

void vm_sync_from_ctx(sparc32_ctx_t *ctx)
{
    if (ctx->brk_base != 0U && g_vm_brk_base != ctx->brk_base) {
        g_vm_brk_base = ctx->brk_base;
        g_vm_brk_curr = ctx->brk_curr;
    }
}

void vm_sync_brk_to_ctx(sparc32_ctx_t *ctx)
{
    if (g_vm_brk_base != 0U) {
        ctx->brk_base = g_vm_brk_base;
        ctx->brk_curr = g_vm_brk_curr;
        if (g_vm_root_ctx != NULL && g_vm_root_ctx != ctx) {
            g_vm_root_ctx->brk_base = g_vm_brk_base;
            g_vm_root_ctx->brk_curr = g_vm_brk_curr;
        }
    }
}

static void vm_copy_state_to_ctx(sparc32_ctx_t *dst)
{
    size_t count;

    if (g_vm_brk_base != 0U) {
        dst->brk_base = g_vm_brk_base;
        dst->brk_curr = g_vm_brk_curr;
    }
    count = (g_vm_region_count <= SPARC32_MAX_REGIONS) ? g_vm_region_count : SPARC32_MAX_REGIONS;
    dst->mmap_cursor  = g_vm_mmap_cursor;
    dst->region_count = count;
    if (count > 0U) {
        memcpy(dst->regions, g_vm_regions, count * sizeof(sparc32_region_t));
    }
}

void vm_sync_to_ctx(sparc32_ctx_t *ctx)
{
    vm_copy_state_to_ctx(ctx);
    if (g_vm_root_ctx != NULL && g_vm_root_ctx != ctx) {
        vm_copy_state_to_ctx(g_vm_root_ctx);
    }
}

static void vm_remove_region_at(size_t idx)
{
    if (idx >= g_vm_region_count) {
        return;
    }
    vm_close_backing_fd(g_vm_region_meta[idx].fd);
    if (idx + 1U < g_vm_region_count) {
        memmove(&g_vm_regions[idx], &g_vm_regions[idx + 1U],
                (g_vm_region_count - idx - 1U) * sizeof(sparc32_region_t));
        memmove(&g_vm_region_meta[idx], &g_vm_region_meta[idx + 1U],
                (g_vm_region_count - idx - 1U) * sizeof(vm_region_meta_t));
    }
    g_vm_region_count--;
}

static int vm_insert_region_raw_ext(uint32_t start, uint32_t end,
                                    uint32_t prot, uint32_t flags,
                                    const char *name, int fd, uint32_t pgoff)
{
    sparc32_region_t *r;
    size_t pos = 0U;

    if (start >= end || g_vm_region_count >= SPARC32_MAX_REGIONS) {
        return -1;
    }
    while (pos < g_vm_region_count && g_vm_regions[pos].start < start) {
        pos++;
    }
    if (pos < g_vm_region_count) {
        memmove(&g_vm_regions[pos + 1U], &g_vm_regions[pos],
                (g_vm_region_count - pos) * sizeof(sparc32_region_t));
        memmove(&g_vm_region_meta[pos + 1U], &g_vm_region_meta[pos],
                (g_vm_region_count - pos) * sizeof(vm_region_meta_t));
    }
    g_vm_region_count++;
    r = &g_vm_regions[pos];
    r->start = start;
    r->end   = end;
    r->prot  = prot;
    r->flags = flags;
    if (name) {
        snprintf(r->name, sizeof(r->name), "%s", name);
    } else {
        r->name[0] = '\0';
    }
    g_vm_region_meta[pos].fd    = vm_dup_backing_fd(fd);
    g_vm_region_meta[pos].pgoff = (fd >= 0) ? pgoff : 0U;
    g_vm_region_meta[pos].dev   = 0ULL;
    g_vm_region_meta[pos].ino   = 0ULL;
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) == 0) {
            g_vm_region_meta[pos].dev = (uint64_t)st.st_dev;
            g_vm_region_meta[pos].ino = (uint64_t)st.st_ino;
        }
    }
    return 0;
}

static void vm_coalesce_regions_locked(void)
{
    size_t dst = 0U;
    size_t src;

    if (g_vm_region_count < 2U) {
        return;
    }
    for (src = 1U; src < g_vm_region_count; src++) {
        sparc32_region_t *prev = &g_vm_regions[dst];
        const sparc32_region_t *curr = &g_vm_regions[src];
        vm_region_meta_t *prev_m = &g_vm_region_meta[dst];
        const vm_region_meta_t *curr_m = &g_vm_region_meta[src];
        uint32_t prev_pages = (prev->end - prev->start) / SPARC32_PAGE_SIZE;
        bool same_backing = (prev_m->fd < 0 && curr_m->fd < 0) ||
            (prev_m->fd >= 0 && curr_m->fd >= 0 &&
             prev_m->dev == curr_m->dev && prev_m->ino == curr_m->ino &&
             curr_m->pgoff == prev_m->pgoff + prev_pages);
        if (prev->end == curr->start && prev->prot == curr->prot &&
            prev->flags == curr->flags && strcmp(prev->name, curr->name) == 0 &&
            same_backing) {
            vm_close_backing_fd(curr_m->fd);
            prev->end = curr->end;
        } else {
            dst++;
            if (dst != src) {
                g_vm_regions[dst] = *curr;
                g_vm_region_meta[dst] = *curr_m;
            }
        }
    }
    g_vm_region_count = dst + 1U;
}

bool vm_can_split_range_locked(uint32_t start, uint32_t end, bool is_mprotect)
{
    size_t extra = 0U;
    size_t removed = 0U;
    size_t i;

    vm_coalesce_regions_locked();
    for (i = 0U; i < g_vm_region_count; i++) {
        const sparc32_region_t *r = &g_vm_regions[i];
        if (r->end <= start || r->start >= end) {
            continue;
        }
        if (!is_mprotect && r->start >= start && r->end <= end) {
            removed++;
            continue;
        }
        if (r->start < start && r->end > end) {
            extra += is_mprotect ? 2U : 1U;
        } else if (is_mprotect && (r->start < start || r->end > end)) {
            extra += 1U;
        }
    }
    return (g_vm_region_count - removed + extra) <= SPARC32_MAX_REGIONS;
}

static void vm_unmap_regions_locked(uint32_t unmap_start, uint32_t unmap_end)
{
    size_t i = 0U;

    while (i < g_vm_region_count) {
        sparc32_region_t *r = &g_vm_regions[i];
        if (r->end <= unmap_start || r->start >= unmap_end) {
            i++;
            continue;
        }
        if (r->start >= unmap_start && r->end <= unmap_end) {
            vm_remove_region_at(i);
            continue;
        }
        if (r->start < unmap_start && r->end > unmap_end) {
            sparc32_region_t orig;
            vm_region_meta_t orig_m;
            uint32_t right_pgoff;
            if (g_vm_region_count + 1U >= SPARC32_MAX_REGIONS) {
                size_t before = g_vm_region_count;
                vm_coalesce_regions_locked();
                if (g_vm_region_count != before) {
                    i = 0U;
                    continue;
                }
            }
            orig = *r;
            orig_m = g_vm_region_meta[i];
            right_pgoff = orig_m.pgoff + (unmap_end - orig.start) / SPARC32_PAGE_SIZE;
            if (vm_insert_region_raw_ext(unmap_end, orig.end,
                                         orig.prot, orig.flags, orig.name,
                                         orig_m.fd, right_pgoff) == 0) {
                g_vm_regions[i].end = unmap_start;
                i += 2U;
            } else {
                i++;
            }
            continue;
        }
        if (r->start < unmap_start) {
            r->end = unmap_start;
        } else {
            if (g_vm_region_meta[i].fd >= 0) {
                g_vm_region_meta[i].pgoff += (unmap_end - r->start) / SPARC32_PAGE_SIZE;
            }
            r->start = unmap_end;
        }
        i++;
    }
}

void vm_unmap_regions_pub(uint32_t unmap_start, uint32_t unmap_end)
{
    vm_unmap_regions_locked(unmap_start, unmap_end);
}

int vm_record_region_ext_locked(uint32_t start, uint32_t end,
                                uint32_t prot, uint32_t flags, const char *name,
                                int fd, uint32_t pgoff)
{
    char name_copy[64];
    uint32_t clean_flags;
    int rc;

    if (start >= end) {
        return -1;
    }
    if (name) {
        snprintf(name_copy, sizeof(name_copy), "%s", name);
    } else {
        name_copy[0] = '\0';
    }
    clean_flags = flags & ~(RT32_MAP_FIXED | RT32_MAP_FIXED_NOREPLACE);
    vm_unmap_regions_locked(start, end);
    rc = vm_insert_region_raw_ext(start, end, prot, clean_flags, name_copy, fd, pgoff);
    if (rc < 0) {
        vm_coalesce_regions_locked();
        rc = vm_insert_region_raw_ext(start, end, prot, clean_flags, name_copy, fd, pgoff);
    }
    vm_coalesce_regions_locked();
    if (rc == 0) {
        uint32_t va;
        for (va = start & ~(uint32_t)0xFFFU; va < end; va += SPARC32_PAGE_SIZE) {
            vm32_publish_page(va, prot & 0x7U, vm32_page_state(va));
        }
    }
    return rc;
}

int vm_record_region_locked(uint32_t start, uint32_t end,
                            uint32_t prot, uint32_t flags, const char *name)
{
    return vm_record_region_ext_locked(start, end, prot, flags, name, -1, 0U);
}

void vm_mprotect_regions_locked(uint32_t mp_start, uint32_t mp_end, uint32_t prot)
{
    size_t i = 0U;

    while (i < g_vm_region_count) {
        sparc32_region_t *r = &g_vm_regions[i];
        if (r->end <= mp_start || r->start >= mp_end) {
            i++;
            continue;
        }
        if (r->start >= mp_start && r->end <= mp_end) {
            r->prot = prot;
            i++;
            continue;
        }
        sparc32_region_t orig = *r;
        vm_region_meta_t orig_m = g_vm_region_meta[i];
        if (orig.start < mp_start && orig.end > mp_end) {
            if (g_vm_region_count + 2U <= SPARC32_MAX_REGIONS) {
                uint32_t mid_pgoff = orig_m.pgoff + (mp_start - orig.start) / SPARC32_PAGE_SIZE;
                uint32_t right_pgoff = orig_m.pgoff + (mp_end - orig.start) / SPARC32_PAGE_SIZE;
                r->end = mp_start;
                (void)vm_insert_region_raw_ext(mp_start, mp_end, prot, orig.flags, orig.name,
                                               orig_m.fd, mid_pgoff);
                (void)vm_insert_region_raw_ext(mp_end, orig.end, orig.prot, orig.flags, orig.name,
                                               orig_m.fd, right_pgoff);
                i += 3U;
            } else {
                r->prot = prot;
                i++;
            }
        } else if (orig.start < mp_start) {
            uint32_t right_pgoff = orig_m.pgoff + (mp_start - orig.start) / SPARC32_PAGE_SIZE;
            if (vm_insert_region_raw_ext(mp_start, orig.end, prot, orig.flags, orig.name,
                                         orig_m.fd, right_pgoff) == 0) {
                g_vm_regions[i].end = mp_start;
                i += 2U;
            } else {
                r->prot = prot;
                i++;
            }
        } else {
            uint32_t right_pgoff = orig_m.pgoff + (mp_end - orig.start) / SPARC32_PAGE_SIZE;
            r->start = mp_end;
            if (orig_m.fd >= 0) {
                g_vm_region_meta[i].pgoff = right_pgoff;
            }
            if (vm_insert_region_raw_ext(orig.start, mp_end, prot, orig.flags, orig.name,
                                         orig_m.fd, orig_m.pgoff) == 0) {
                i += 2U;
            } else {
                r->start = orig.start;
                g_vm_region_meta[i].pgoff = orig_m.pgoff;
                r->prot  = prot;
                i++;
            }
        }
    }
    vm_coalesce_regions_locked();
}

bool vm_range_overlaps_locked(uint32_t start, uint32_t end)
{
    size_t i;

    for (i = 0U; i < g_vm_region_count && g_vm_regions[i].start < end; i++) {
        if (g_vm_regions[i].end > start) {
            return true;
        }
    }
    return false;
}

bool vm_check_mapped_range_ext_locked(uint32_t start, uint32_t end,
                                      uint32_t *out_prot, uint32_t *out_flags,
                                      char *out_name, size_t name_sz,
                                      int *out_fd, uint32_t *out_pgoff)
{
    uint32_t cur = start;
    bool     first = true;
    uint32_t first_prot  = 0U;
    uint32_t first_flags = 0U;
    size_t i;

    if (start >= end) {
        return false;
    }
    for (i = 0U; i < g_vm_region_count; i++) {
        const sparc32_region_t *r = &g_vm_regions[i];
        if (r->end <= cur) {
            continue;
        }
        if (r->start > cur) {
            return false;
        }
        if (first) {
            uint32_t off_pages = (start - r->start) / SPARC32_PAGE_SIZE;
            first_prot  = r->prot;
            first_flags = r->flags & 0x23U;
            if (out_prot) {
                *out_prot = r->prot;
            }
            if (out_flags) {
                *out_flags = r->flags;
            }
            if (out_name && name_sz > 0U) {
                snprintf(out_name, name_sz, "%s", r->name);
            }
            if (out_fd) {
                *out_fd = g_vm_region_meta[i].fd;
            }
            if (out_pgoff) {
                *out_pgoff = (g_vm_region_meta[i].fd >= 0) ?
                    (g_vm_region_meta[i].pgoff + off_pages) : 0U;
            }
            first = false;
        } else if ((out_prot != NULL && r->prot != first_prot) ||
                   (out_flags != NULL && (r->flags & 0x23U) != first_flags)) {
            return false;
        }
        if (r->end >= end) {
            return true;
        }
        cur = r->end;
    }
    return false;
}

bool vm_check_mapped_range_locked(uint32_t start, uint32_t end,
                                  uint32_t *out_prot, uint32_t *out_flags,
                                  char *out_name, size_t name_sz)
{
    return vm_check_mapped_range_ext_locked(start, end, out_prot, out_flags,
                                            out_name, name_sz, NULL, NULL);
}

int vm_find_free_gap_locked(uint64_t aligned_len, uint32_t *out_va)
{
    uint64_t hp_align = (uint64_t)vm_host_page_size() - 1ULL;
    uint64_t cursor_cand;
    uint64_t cand;
    size_t i;

    if (aligned_len == 0ULL ||
        aligned_len > (uint64_t)(RT32_MMAP_TOP_32 - RT32_MMAP_BASE_32)) {
        return -1;
    }

    cursor_cand = (vm_page_align_up((uint64_t)g_vm_mmap_cursor) + hp_align) & ~hp_align;
    if (cursor_cand < (uint64_t)RT32_MMAP_BASE_32) {
        cursor_cand = (uint64_t)RT32_MMAP_BASE_32;
    }
    if (cursor_cand + aligned_len <= (uint64_t)RT32_MMAP_TOP_32 &&
        !vm_range_overlaps_locked((uint32_t)cursor_cand, (uint32_t)(cursor_cand + aligned_len))) {
        *out_va = (uint32_t)cursor_cand;
        return 0;
    }

    cand = (uint64_t)RT32_MMAP_BASE_32;
    for (i = 0U; i < g_vm_region_count; i++) {
        uint64_t r_start = (uint64_t)g_vm_regions[i].start;
        uint64_t r_end   = (vm_page_align_up((uint64_t)g_vm_regions[i].end) + hp_align) & ~hp_align;
        if (r_end <= cand) {
            continue;
        }
        if (cand + aligned_len <= r_start) {
            break;
        }
        cand = r_end;
    }

    if (cand + aligned_len > (uint64_t)RT32_MMAP_TOP_32) {
        return -1;
    }

    *out_va = (uint32_t)cand;
    return 0;
}

static int try_reserve_window(uint64_t base)
{
    uint64_t map_start;
    uint64_t map_len;
    void *res;

    if ((base & (SPARC32_PAGE_SIZE - 1ULL)) != 0ULL || base > UINT64_MAX - RT32_WINDOW_SIZE) {
        return -1;
    }

    map_start = (base == 0ULL) ? (uint64_t)SPARC32_LOW_GUARD_SIZE : base;
    map_len   = (base == 0ULL) ? (RT32_WINDOW_SIZE - (uint64_t)SPARC32_LOW_GUARD_SIZE)
                               : RT32_WINDOW_SIZE;

#ifdef __linux__
    res = mmap((void *)(uintptr_t)map_start, (size_t)map_len, PROT_NONE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (res == MAP_FAILED && (errno == EINVAL || errno == EOPNOTSUPP)) {
        res = mmap((void *)(uintptr_t)map_start, (size_t)map_len, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
#else
    res = mmap((void *)(uintptr_t)map_start, (size_t)map_len, PROT_NONE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
    if (res == MAP_FAILED) {
        return -1;
    }
    if ((uint64_t)(uintptr_t)res != map_start) {
        munmap(res, (size_t)map_len);
        return -1;
    }
    return 0;
}

int rt32_vm_init(sparc32_ctx_t *ctx, uint64_t requested_window)
{
    uint64_t base = requested_window;
    bool     has_explicit = (requested_window != UINT64_MAX);

    if (!ctx) {
        return -1;
    }

    if (!has_explicit) {
        const char *env_win = getenv("SPARC32RT_WINDOW");
        if (env_win && env_win[0] != '\0') {
            char *endp = NULL;
            errno = 0;
            {
                unsigned long long val = strtoull(env_win, &endp, 0);
                if (strchr(env_win, '-') != NULL || errno == ERANGE || !endp ||
                    endp == env_win || *endp != '\0' || (uint64_t)val == UINT64_MAX) {
                    fprintf(stderr, "sparc32rt: invalid SPARC32RT_WINDOW '%s'\n", env_win);
                    return -1;
                }
                base = (uint64_t)val;
                has_explicit = true;
            }
        }
    }

    if (has_explicit) {
        if (try_reserve_window(base) != 0) {
            fprintf(stderr, "sparc32rt: failed to reserve guest window at 0x%llx\n",
                    (unsigned long long)base);
            return -1;
        }
        ctx->guest_base = base;
    } else if (ctx->has_host_info && ctx->host_info.window_hint != 0ULL &&
               try_reserve_window(ctx->host_info.window_hint) == 0) {
        ctx->guest_base = ctx->host_info.window_hint;
    } else {
        bool found = false;
        uint64_t cand;
        if (try_reserve_window(0ULL) == 0) {
            ctx->guest_base = 0ULL;
        } else {
            for (cand = 0x100000000ULL; cand < 0x1000000000ULL; cand += 0x100000000ULL) {
                if (try_reserve_window(cand) == 0) {
                    ctx->guest_base = cand;
                    found = true;
                    break;
                }
            }
            if (!found) {
                fprintf(stderr, "sparc32rt: unable to find free 4 GiB guest window\n");
                return -1;
            }
        }
    }

    vm_lock_acquire();
    g_vm_root_ctx     = ctx;
    g_vm_brk_base     = 0U;
    g_vm_brk_curr     = 0U;
    g_vm_mmap_cursor  = RT32_MMAP_BASE_32;
    g_vm_region_count = 0U;
    ctx->mmap_cursor  = RT32_MMAP_BASE_32;
    ctx->region_count = 0U;
    vm_lock_release();
    return 0;
}

int rt32_vm_record_region(sparc32_ctx_t *ctx, uint32_t start, uint32_t end,
                         uint32_t prot, uint32_t flags, const char *name)
{
    int rc;

    if (!ctx || start >= end) {
        return -1;
    }
    (void)vm32_attach(ctx);
    vm_lock_acquire();
    vm_sync_from_ctx(ctx);
    rc = vm_record_region_locked(start, end, prot, flags, name);
    vm_sync_to_ctx(ctx);
    vm_lock_release();
    return rc;
}

/* Exec teardown: drop every tracked region (Phase 0 has no persistent
 * vDSO page, so exec clears the whole table; the Phase 2 vDSO, if any,
 * re-registers itself at stack setup). */
void rt32_vm_reset_for_exec(sparc32_ctx_t *ctx)
{
    size_t i;

    vm_lock_acquire();
    for (i = 0U; i < g_vm_region_count; i++) {
        vm_close_backing_fd(g_vm_region_meta[i].fd);
        g_vm_region_meta[i].fd = -1;
        g_vm_region_meta[i].pgoff = 0U;
    }
    g_vm_region_count = 0U;
    g_vm_brk_base  = 0U;
    g_vm_brk_curr  = 0U;
    g_vm_mmap_cursor = RT32_MMAP_BASE_32;
    vm_lock_release();

    /* Kernel exec semantics: the old address space is destroyed. Reset
     * the window back to PROT_NONE while keeping [G, G+4GiB) reserved. */
    (void)mmap(sparc32_guest_ptr(ctx, SPARC32_LOW_GUARD_SIZE),
               (size_t)(RT32_WINDOW_SIZE - (uint64_t)SPARC32_LOW_GUARD_SIZE),
               PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    vm32_reset();

    ctx->brk_base    = 0U;
    ctx->brk_curr    = 0U;
    ctx->mmap_cursor = RT32_MMAP_BASE_32;
    ctx->region_count = 0U;
    (void)rt32_vm_record_region(ctx, 0U, SPARC32_LOW_GUARD_SIZE,
                                0U, 0x32U, "[null_guard]");
}

uint32_t rt32_vm_brk(sparc32_ctx_t *ctx, uint32_t new_brk)
{
    uint32_t brk_limit;
    uint64_t old_page64;
    uint64_t new_page64;
    uint32_t old_page;
    uint32_t new_page;

    if (!ctx) {
        return 0U;
    }
    vm_lock_acquire();
    vm_sync_from_ctx(ctx);

    brk_limit = (g_vm_brk_base < RT32_MMAP_BASE_32) ? RT32_MMAP_BASE_32 : RT32_MMAP_TOP_32;
    if (new_brk == 0U || new_brk < g_vm_brk_base || new_brk > brk_limit) {
        uint32_t curr = g_vm_brk_curr;
        vm_sync_brk_to_ctx(ctx);
        vm_lock_release();
        return curr;
    }

    old_page64 = vm_page_align_up((uint64_t)g_vm_brk_curr);
    new_page64 = vm_page_align_up((uint64_t)new_brk);
    if (new_page64 > (uint64_t)brk_limit) {
        uint32_t curr = g_vm_brk_curr;
        vm_sync_brk_to_ctx(ctx);
        vm_lock_release();
        return curr;
    }

    old_page = (uint32_t)old_page64;
    new_page = (uint32_t)new_page64;

    if (new_page > old_page) {
        if (vm_range_overlaps_locked(old_page, new_page)) {
            uint32_t curr = g_vm_brk_curr;
            vm_sync_brk_to_ctx(ctx);
            vm_lock_release();
            return curr;
        }
        {
            uint32_t len = new_page - old_page;
            size_t hp = vm_host_page_size();
            if (hp > (size_t)SPARC32_PAGE_SIZE) {
                uint32_t mask = (uint32_t)hp - 1U;
                uint32_t hp_start = old_page & ~mask;
                uint32_t hp_end   = (new_page + mask) & ~mask;
                if (mprotect(sparc32_guest_ptr(ctx, hp_start),
                             (size_t)(hp_end - hp_start),
                             PROT_READ | PROT_WRITE) != 0) {
                    uint32_t curr = g_vm_brk_curr;
                    vm_sync_brk_to_ctx(ctx);
                    vm_lock_release();
                    return curr;
                }
                memset(sparc32_guest_ptr(ctx, old_page), 0, (size_t)len);
            } else {
                void *host_addr = sparc32_guest_ptr(ctx, old_page);
                void *res = mmap(host_addr, len, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
                if (res == MAP_FAILED) {
                    uint32_t curr = g_vm_brk_curr;
                    vm_sync_brk_to_ctx(ctx);
                    vm_lock_release();
                    return curr;
                }
            }
        }
        (void)vm_record_region_locked(old_page, new_page,
                                      (uint32_t)(PROT_READ | PROT_WRITE), 0x22U, "[heap]");
    } else if (new_page < old_page) {
        uint32_t len = old_page - new_page;
        /* Re-reserve shrunk brk pages with PROT_NONE inside the guest window */
        (void)vm_reserve_prot_none(ctx, new_page, len);
        vm_unmap_regions_pub(new_page, old_page);
        {
            uint32_t va;
            for (va = new_page; va < old_page; va += SPARC32_PAGE_SIZE) {
                vm32_publish_page(va, 0U, 0U);
            }
        }
    }

    g_vm_brk_curr = new_brk;
    if (new_page != old_page) {
        vm_sync_to_ctx(ctx);
    } else {
        vm_sync_brk_to_ctx(ctx);
    }
    vm_lock_release();

    if (new_page < old_page) {
        vm_invalidate_jit(ctx, new_page, old_page);
    }
    return new_brk;
}

void rt32_vm_sync_ctx(sparc32_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    vm_lock_acquire();
    vm_sync_from_ctx(ctx);
    vm_sync_to_ctx(ctx);
    vm_lock_release();
}