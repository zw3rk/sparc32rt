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
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

static _Atomic uint32_t g_vm_lock = 0U;
static sparc32_ctx_t   *g_vm_root_ctx = NULL;
static uint32_t         g_vm_brk_base = 0U;
static uint32_t         g_vm_brk_curr = 0U;
uint32_t                g_vm_mmap_cursor = RT32_MMAP_BASE_32;
static sparc32_region_t g_vm_regions[SPARC32_MAX_REGIONS];
static size_t           g_vm_region_count = 0U;

void vm_lock_acquire(void)
{
    sparc32_spin_lock(&g_vm_lock);
}

void vm_lock_release(void)
{
    sparc32_spin_unlock(&g_vm_lock);
}

uint64_t vm_page_align_up(uint64_t v)
{
    return (v + 0xFFFULL) & ~0xFFFULL;
}

int vm_reserve_prot_none(sparc32_ctx_t *ctx, uint32_t start, uint32_t len)
{
    void *res = mmap(sparc32_guest_ptr(ctx, start), (size_t)len, PROT_NONE,
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
    if (idx + 1U < g_vm_region_count) {
        memmove(&g_vm_regions[idx], &g_vm_regions[idx + 1U],
                (g_vm_region_count - idx - 1U) * sizeof(sparc32_region_t));
    }
    g_vm_region_count--;
}

static int vm_insert_region_raw(uint32_t start, uint32_t end,
                                uint32_t prot, uint32_t flags, const char *name)
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
        if (prev->end == curr->start && prev->prot == curr->prot &&
            prev->flags == curr->flags && strcmp(prev->name, curr->name) == 0) {
            prev->end = curr->end;
        } else {
            dst++;
            if (dst != src) {
                g_vm_regions[dst] = *curr;
            }
        }
    }
    g_vm_region_count = dst + 1U;
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
            if (g_vm_region_count + 1U >= SPARC32_MAX_REGIONS) {
                size_t before = g_vm_region_count;
                vm_coalesce_regions_locked();
                if (g_vm_region_count != before) {
                    i = 0U;
                    continue;
                }
            }
            orig = *r;
            if (vm_insert_region_raw(unmap_end, orig.end,
                                     orig.prot, orig.flags, orig.name) == 0) {
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
            r->start = unmap_end;
        }
        i++;
    }
}

void vm_unmap_regions_pub(uint32_t unmap_start, uint32_t unmap_end)
{
    vm_unmap_regions_locked(unmap_start, unmap_end);
}

int vm_record_region_locked(uint32_t start, uint32_t end,
                            uint32_t prot, uint32_t flags, const char *name)
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
    rc = vm_insert_region_raw(start, end, prot, clean_flags, name_copy);
    if (rc < 0) {
        vm_coalesce_regions_locked();
        rc = vm_insert_region_raw(start, end, prot, clean_flags, name_copy);
    }
    vm_coalesce_regions_locked();
    return rc;
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
        if (orig.start < mp_start && orig.end > mp_end) {
            if (g_vm_region_count + 2U <= SPARC32_MAX_REGIONS) {
                r->end = mp_start;
                (void)vm_insert_region_raw(mp_start, mp_end, prot, orig.flags, orig.name);
                (void)vm_insert_region_raw(mp_end, orig.end, orig.prot, orig.flags, orig.name);
                i += 3U;
            } else {
                r->prot = prot;
                i++;
            }
        } else if (orig.start < mp_start) {
            if (vm_insert_region_raw(mp_start, orig.end, prot, orig.flags, orig.name) == 0) {
                g_vm_regions[i].end = mp_start;
                i += 2U;
            } else {
                r->prot = prot;
                i++;
            }
        } else {
            r->start = mp_end;
            if (vm_insert_region_raw(orig.start, mp_end, prot, orig.flags, orig.name) == 0) {
                i += 2U;
            } else {
                r->start = orig.start;
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

bool vm_check_mapped_range_locked(uint32_t start, uint32_t end,
                                  uint32_t *out_prot, uint32_t *out_flags,
                                  char *out_name, size_t name_sz)
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

int vm_find_free_gap_locked(uint64_t aligned_len, uint32_t *out_va)
{
    uint64_t cursor_cand;
    uint64_t cand;
    size_t i;

    if (aligned_len == 0ULL ||
        aligned_len > (uint64_t)(RT32_MMAP_TOP_32 - RT32_MMAP_BASE_32)) {
        return -1;
    }

    cursor_cand = vm_page_align_up((uint64_t)g_vm_mmap_cursor);
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
        uint64_t r_end   = vm_page_align_up((uint64_t)g_vm_regions[i].end);
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

    res = mmap((void *)(uintptr_t)map_start, (size_t)map_len, PROT_NONE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (res == MAP_FAILED && (errno == EINVAL || errno == EOPNOTSUPP)) {
        res = mmap((void *)(uintptr_t)map_start, (size_t)map_len, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
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
    vm_lock_acquire();
    g_vm_region_count = 0U;
    g_vm_brk_base  = 0U;
    g_vm_brk_curr  = 0U;
    g_vm_mmap_cursor = RT32_MMAP_BASE_32;
    vm_lock_release();

    /* Kernel exec semantics: the old address space is destroyed. Tear the
     * window back down to PROT_NONE; the new image and stack re-map pages. */
    (void)munmap((void *)(uintptr_t)SPARC32_LOW_GUARD_SIZE,
                 (size_t)(RT32_WINDOW_SIZE - (uint64_t)SPARC32_LOW_GUARD_SIZE));

    ctx->brk_base    = 0U;
    ctx->brk_curr    = 0U;
    ctx->mmap_cursor = RT32_MMAP_BASE_32;
    ctx->region_count = 0U;
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
        (void)vm_record_region_locked(old_page, new_page,
                                      (uint32_t)(PROT_READ | PROT_WRITE), 0x22U, "[heap]");
    } else if (new_page < old_page) {
        uint32_t len = old_page - new_page;
        /* Re-reserve shrunk brk pages with PROT_NONE inside the guest window */
        (void)vm_reserve_prot_none(ctx, new_page, len);
        vm_unmap_regions_pub(new_page, old_page);
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