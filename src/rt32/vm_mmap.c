/*
 * src/rt32/vm_mmap.c — Guest mmap2/mprotect/munmap/mremap engine
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Vendored from i686rt/src/rt32/rt32_vm.c (second half): renamed
 * i686_→sparc32_ / I686_→SPARC32_, retyped on sparc32_ctx_t; guest VA
 * ceiling is SPARC32_TASK_SIZE_TOP (0xF0000000). Locked helpers and the
 * CLONE_VM page-table lock live in vm.c / vm_int.h.
 */

#define _GNU_SOURCE
#include "vm_int.h"

#include "dbt/aot/mem_site.h"
#include "os/backend.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

/* Ensure the Regime VM observes the rt32 window (RC-U3-r2 #4):
 * vm32_attach is idempotent, so mapping operations call it
 * unconditionally before publishing. */
static void vm_mmap_ensure_regime(sparc32_ctx_t *ctx)
{
    if (ctx != NULL) {
        (void)vm32_attach(ctx);
    }
}

/* Lock-held DBT invalidation (S32-R4-3): runs while vm_lock quiescence
 * is still held, before vm_lock_release(), so no runner executes a
 * stale translation between the table commit and the retire. */
static void vm_invalidate_jit_locked(sparc32_ctx_t *ctx, uint32_t start,
    uint32_t end)
{
    if (ctx == NULL || end <= start) {
        return;
    }
    vm_invalidate_jit(ctx, start, end);
}

/* Publish one mapping commit to the Regime VM (RC-U3-r2 #4): per-page
 * guest protection for the Soft-TLB miss helper. MAP_PRIVATE
 * file pages publish PAGE_COW_CLEAN so the write-miss promotion branch
 * is reachable; everything else publishes state 0. */
static void vm_mmap_publish_keep_state(sparc32_ctx_t *ctx, uint32_t start,
    uint32_t end, uint32_t prot);

static void vm_mmap_publish(sparc32_ctx_t *ctx, uint32_t start, uint32_t end,
    uint32_t prot, uint32_t state)
{
    uint32_t va;
    if (ctx == NULL || end <= start) {
        return;
    }
    for (va = start; va < end; va += SPARC32_PAGE_SIZE) {
        vm32_publish_page(va, prot & 0x7U, state);
    }
}

/* File-tracking range retirement (src/vm/vm_file.c). */
extern void vm_file_unregister_range(uint32_t gva, uint32_t len);
extern void vm_file_reset(void);

/* Record a file-backed mapping in the Provider-A family table (RC-U3-r2
 * #4): fstat the host fd for its (dev, ino) identity so later
 * truncate/write hooks can match the mapping. The range is registered
 * BEFORE the size is recorded (S32-R5-8) so the fresh entry observes the
 * initial file size; the reverse order would leave it at 0 and the first
 * post-mmap ftruncate shrink would compare against 0 instead. */
static void vm_mmap_note_file(int host_fd, uint32_t map_gva,
    uint32_t map_pages, uint64_t map_off)
{
    struct stat st;
    if (host_fd < 0 || fstat(host_fd, &st) != 0) {
        return;
    }
    vm_file_note_mapping((uint64_t)st.st_dev, (uint64_t)st.st_ino,
        host_fd, map_gva, map_pages, map_off);
    vm_file_note_mutation((uint64_t)st.st_dev, (uint64_t)st.st_ino,
        host_fd, (uint64_t)st.st_size);
}

static uint32_t vm_mmap2_locked(sparc32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot,
                                uint32_t flags, int fd, uint32_t pgoffset)
{
    uint64_t aligned_len = vm_page_align_up((uint64_t)len);
    int host_flags = 0;
    uint32_t target_va     = 0U;
    bool     update_cursor = false;
    int      host_prot;
    void    *host_target;
    off_t    host_off;

    if (!ctx || len == 0U || (flags & 0x03U) == 0U || (flags & 0x03U) == 0x03U) {
        return (uint32_t)(-EINVAL);
    }
    if (aligned_len == 0ULL || aligned_len > (uint64_t)SPARC32_TASK_SIZE_TOP) {
        return (uint32_t)(-ENOMEM);
    }

    if (flags & 0x01U) {
        host_flags |= MAP_SHARED;
    }
    if (flags & 0x02U) {
        host_flags |= MAP_PRIVATE;
    }
    if (flags & RT32_MAP_ANONYMOUS) {
        host_flags |= MAP_ANONYMOUS;
    }

    if ((flags & (RT32_MAP_FIXED | RT32_MAP_FIXED_NOREPLACE)) != 0U) {
        if ((addr & (SPARC32_PAGE_SIZE - 1U)) != 0U || addr < SPARC32_LOW_GUARD_SIZE) {
            return (uint32_t)(-EINVAL);
        }
        if ((uint64_t)addr + aligned_len > (uint64_t)SPARC32_TASK_SIZE_TOP) {
            return (uint32_t)(-ENOMEM);
        }
        if ((flags & RT32_MAP_FIXED_NOREPLACE) != 0U &&
            vm_range_overlaps_locked(addr, (uint32_t)((uint64_t)addr + aligned_len))) {
            return (uint32_t)(-EEXIST);
        }
        /* MAP_FIXED replaces whatever lived here (S32-R5-9): the
         * overwritten file-tracking range is retired only after the host
         * mapping succeeds (see below), so a failed mmap keeps tracking. */
        target_va = addr;
    } else {
        uint32_t hint_va = sparc32_page_down(addr);
        if (addr != 0U &&
            hint_va >= RT32_MMAP_BASE_32 &&
            (uint64_t)hint_va + aligned_len <= (uint64_t)RT32_MMAP_TOP_32 &&
            !vm_range_overlaps_locked(hint_va, (uint32_t)((uint64_t)hint_va + aligned_len))) {
            target_va = hint_va;
        } else if (vm_find_free_gap_locked(aligned_len, &target_va) != 0) {
            return (uint32_t)(-ENOMEM);
        } else {
            update_cursor = true;
        }
    }

    host_prot   = sparc32_host_prot(ctx, prot);
    host_target = sparc32_guest_ptr(ctx, target_va);
    host_off    = (off_t)pgoffset * (off_t)SPARC32_PAGE_SIZE;
    /* Host mapping through the backend hooks (Rev 4 section 6) with the
     * exact Linux semantics above: MAP_FIXED placement (the NOREPLACE
     * overlap pre-check already ran), anon vs file backing. */
    {
        void *hook_out = NULL;
        int map_rc = -EINVAL;
        int anon_shm_fd = -1;
        int rec_fd = ((host_flags & MAP_ANONYMOUS) != 0) ? -1 : fd;
        uint32_t rec_pgoff = ((host_flags & MAP_ANONYMOUS) != 0) ? 0U : pgoffset;

        if ((host_flags & MAP_ANONYMOUS) != 0) {
            if ((host_flags & MAP_SHARED) != 0) {
                if (rt_host_create_shared_mem("sparc32rt-anon",
                        (size_t)aligned_len, &anon_shm_fd) == 0 &&
                    anon_shm_fd >= 0) {
                    map_rc = rt_host_map_file(host_target, (size_t)aligned_len,
                        host_prot, 1, 1, anon_shm_fd, 0ULL, &hook_out);
                    if (map_rc == 0 && hook_out == host_target) {
                        rec_fd = anon_shm_fd;
                        rec_pgoff = 0U;
                    } else {
                        if (map_rc == 0 && hook_out != NULL) {
                            (void)rt_host_unmap(hook_out, (size_t)aligned_len);
                        }
                        (void)close(anon_shm_fd);
                        anon_shm_fd = -1;
                    }
                }
            }
            if (anon_shm_fd < 0) {
                map_rc = rt_host_map_anon(host_target, (size_t)aligned_len,
                    host_prot, 1, 0, &hook_out);
            }
        } else {
            map_rc = rt_host_map_file(host_target, (size_t)aligned_len,
                host_prot, (host_flags & MAP_SHARED) != 0, 1, fd,
                (uint64_t)host_off, &hook_out);
        }
        if (map_rc != 0 || hook_out != host_target) {
            if (map_rc == 0) {
                (void)rt_host_unmap(hook_out, (size_t)aligned_len);
            }
            if (anon_shm_fd >= 0) {
                (void)close(anon_shm_fd);
            }
            return (uint32_t)(map_rc != 0 ? map_rc : -EEXIST);
        }

        /* MAP_FIXED replacement (S32-R5-9): retire the overwritten
         * file-tracking range only after the host mapping succeeded,
         * right before registering the new mapping. */
        if ((flags & RT32_MAP_FIXED) != 0U &&
            (flags & RT32_MAP_FIXED_NOREPLACE) == 0U) {
            vm_file_unregister_range(target_va, (uint32_t)aligned_len);
        }
        /* Regime VM + Provider-A lifecycle (RC-U3-r2 #4): attach, publish
         * the committed protection, and register file-backed ranges by
         * inode identity. */
        vm_mmap_ensure_regime(ctx);
        vm_mmap_publish(ctx, target_va,
            (uint32_t)((uint64_t)target_va + aligned_len), prot,
            ((host_flags & MAP_PRIVATE) != 0 &&
                (host_flags & MAP_ANONYMOUS) == 0) ? RT_PAGE_COW_CLEAN : 0U);
        if ((host_flags & MAP_ANONYMOUS) == 0) {
            vm_mmap_note_file(fd, target_va,
                (uint32_t)(aligned_len / (uint64_t)SPARC32_PAGE_SIZE),
                (uint64_t)host_off);
        }

        {
            int rec_rc = vm_record_region_ext_locked(
                target_va, (uint32_t)((uint64_t)target_va + aligned_len),
                prot & 0x7U, flags, "[mmap]", rec_fd, rec_pgoff);
            if (rec_rc != 0) {
                vm_file_unregister_range(target_va,
                    (uint32_t)aligned_len);
                (void)vm_reserve_prot_none(ctx, target_va,
                    (uint32_t)aligned_len);
                vm_mmap_publish(ctx, target_va,
                    (uint32_t)((uint64_t)target_va + aligned_len), 0U, 0U);
                if (anon_shm_fd >= 0) {
                    (void)close(anon_shm_fd);
                }
                return (uint32_t)(-ENOMEM);
            }
        }
#if defined(__APPLE__)
        if ((host_flags & MAP_ANONYMOUS) == 0) {
            struct stat eof_st;
            if (fstat(fd, &eof_st) == 0) {
                uint64_t avail = 0ULL;
                if ((uint64_t)eof_st.st_size > (uint64_t)host_off) {
                    avail = (uint64_t)eof_st.st_size - (uint64_t)host_off;
                }
                if (avail < aligned_len) {
                    uint64_t first_tail = (avail +
                        (uint64_t)(SPARC32_PAGE_SIZE - 1U)) &
                        ~((uint64_t)(SPARC32_PAGE_SIZE - 1U));
                    if (first_tail < aligned_len) {
                        uint32_t tail_start =
                            target_va + (uint32_t)first_tail;
                        uint32_t tail_end = (uint32_t)(
                            (uint64_t)target_va + aligned_len);
                        vm_mmap_publish(ctx, tail_start, tail_end,
                            prot, 0U);
                        vm_mprotect_regions_locked(tail_start, tail_end,
                            prot & 0x7U);
                        /* Zero-fill only private writable tails: the host
                         * mapping mirrors guest prot, so a read-only tail
                         * is host-read-only (memset would SIGSEGV) and a
                         * shared tail past EOF is kernel-zeroed on read
                         * (memset could SIGBUS). Either way reads see 0. */
                        if ((host_flags & MAP_SHARED) == 0 &&
                            (prot & 0x2U) != 0U) {
                            memset(sparc32_guest_ptr(ctx, tail_start),
                                0, (size_t)(tail_end - tail_start));
                        }
                    }
                }
            }
        }
#endif
        if (update_cursor) {
            g_vm_mmap_cursor = (uint32_t)((uint64_t)target_va + aligned_len);
        }
        if (anon_shm_fd >= 0) {
            (void)close(anon_shm_fd);
        }
    }
    return target_va;
}

uint32_t rt32_vm_mmap2(sparc32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot,
                      uint32_t flags, int fd, uint32_t pgoffset)
{
    uint32_t res;

    if (!ctx) {
        return (uint32_t)(-EINVAL);
    }

    vm_lock_acquire();
    vm_sync_from_ctx(ctx);
    res = vm_mmap2_locked(ctx, addr, len, prot, flags, fd, pgoffset);
    if (res <= 0xFFFFF000U &&
        ((flags & (RT32_MAP_FIXED | RT32_MAP_FIXED_NOREPLACE)) != 0U ||
         (prot & (uint32_t)PROT_EXEC) != 0U)) {
        vm_invalidate_jit_locked(ctx, res,
            (uint32_t)((uint64_t)res + vm_page_align_up((uint64_t)len)));
    }
    vm_sync_to_ctx(ctx);
    vm_lock_release();
    return res;
}

static int vm_mprotect_locked(sparc32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot)
{
    uint64_t aligned_len;
    uint64_t end64;

    if (!ctx || (addr & (SPARC32_PAGE_SIZE - 1U)) != 0U || addr < 0x1000U || (prot & ~0x7U) != 0U) {
        return -EINVAL;
    }
    if (len == 0U) {
        return 0;
    }
    aligned_len = vm_page_align_up((uint64_t)len);
    end64       = (uint64_t)addr + aligned_len;
    if (addr < SPARC32_LOW_GUARD_SIZE ||
        aligned_len == 0ULL ||
        end64 > (uint64_t)SPARC32_TASK_SIZE_TOP ||
        !vm_check_mapped_range_locked(addr, (uint32_t)end64, NULL, NULL, NULL, 0U) ||
        !vm_can_split_range_locked(addr, (uint32_t)end64, true)) {
        return -ENOMEM;
    }

    {
        int prot_rc = rt_host_protect(sparc32_guest_ptr(ctx, addr),
            (size_t)aligned_len, sparc32_host_prot(ctx, prot));
        if (prot_rc != 0) {
            return prot_rc;
        }
    }

    /* Regime VM lifecycle (RC-U3-r2 #4): publish the committed
     * protection over the range. */
    vm_mmap_ensure_regime(ctx);
    vm_mmap_publish_keep_state(ctx, addr, (uint32_t)end64, prot);
    vm_mprotect_regions_locked(addr, (uint32_t)end64, prot & 0x7U);
    return 0;
}

/*
 * Publish a protection change while preserving per-page state (RC-U3-r5):
 * mprotect must not reset PAGE_COW_CLEAN (or DIRTY/HAS_CODE bits), or
 * later promotion and shrink-state handling observe state 0.
 */
static void vm_mmap_publish_keep_state(sparc32_ctx_t *ctx, uint32_t start,
    uint32_t end, uint32_t prot)
{
    uint32_t va;
    if (ctx == NULL || end <= start) {
        return;
    }
    for (va = start; va < end; va += SPARC32_PAGE_SIZE) {
        vm32_publish_page(va, prot & 0x7U, vm32_page_state(va));
    }
}

int rt32_vm_mprotect(sparc32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot)
{
    int rc;

    if (!ctx) {
        return -EINVAL;
    }

    vm_lock_acquire();
    vm_sync_from_ctx(ctx);
    rc = vm_mprotect_locked(ctx, addr, len, prot);
    if (rc == 0 && len > 0U) {
        vm_invalidate_jit_locked(ctx, addr,
            (uint32_t)((uint64_t)addr + vm_page_align_up((uint64_t)len)));
    }
    vm_sync_to_ctx(ctx);
    vm_lock_release();
    return rc;
}

int vm_munmap_locked(sparc32_ctx_t *ctx, uint32_t addr, uint32_t len)
{
    uint64_t aligned_len;
    uint32_t start;
    uint32_t end;
    int rc;

    if (!ctx || (addr & (SPARC32_PAGE_SIZE - 1U)) != 0U || len == 0U) {
        return -EINVAL;
    }
    aligned_len = vm_page_align_up((uint64_t)len);
    if (addr < SPARC32_LOW_GUARD_SIZE ||
        (uint64_t)addr + aligned_len > (uint64_t)SPARC32_TASK_SIZE_TOP) {
        return -EINVAL;
    }

    start = sparc32_page_down(addr);
    end = (uint32_t)((uint64_t)start + aligned_len);
    if (!vm_can_split_range_locked(start, end, false)) {
        return -ENOMEM;
    }
    /* Keep the [G, G+4GiB) reservation intact by replacing unmapped pages with PROT_NONE */
    rc = vm_reserve_prot_none(ctx, start, (uint32_t)aligned_len);
    if (rc != 0) {
        return rc;
    }
    /* Regime VM lifecycle (RC-U3-r2 #4): the range is PROT_NONE now;
     * publish that. */
    vm_mmap_ensure_regime(ctx);
    vm_mmap_publish(ctx, start, end, 0U, 0U);

    /* Retire the unmapped file-tracking range (S32-R5-9) so later shrinks
     * skip it and its table slot is recycled. */
    vm_file_unregister_range(start, end - start);
    vm_unmap_regions_pub(start, end);
    if (g_vm_mmap_cursor == end && start >= RT32_MMAP_BASE_32) {
        g_vm_mmap_cursor = start;
    }
    return 0;
}

int rt32_vm_munmap(sparc32_ctx_t *ctx, uint32_t addr, uint32_t len)
{
    int rc;

    if (!ctx) {
        return -EINVAL;
    }

    vm_lock_acquire();
    vm_sync_from_ctx(ctx);
    rc = vm_munmap_locked(ctx, addr, len);
    if (rc == 0) {
        vm_invalidate_jit_locked(ctx, addr,
            (uint32_t)((uint64_t)addr + vm_page_align_up((uint64_t)len)));
    }
    vm_sync_to_ctx(ctx);
    vm_lock_release();
    return rc;
}

uint32_t rt32_vm_mremap(sparc32_ctx_t *ctx, uint32_t old_addr, uint32_t old_len,
                       uint32_t new_len, uint32_t flags, uint32_t new_addr)
{
    uint64_t old_aligned;
    uint64_t new_aligned;
    uint32_t prot       = 0x3U;
    uint32_t orig_flags = 0x22U;
    int      orig_fd    = -1;
    uint32_t orig_pgoff = 0U;
    char     orig_name[64];
    bool     is_anon;
    bool     is_shared;
    uint32_t keep_flags;
    const char *region_name;

    if (!ctx || (old_addr & (SPARC32_PAGE_SIZE - 1U)) != 0U ||
        old_len == 0U || new_len == 0U) {
        return (uint32_t)(-EINVAL);
    }
    if ((flags & ~(RT32_MREMAP_MAYMOVE | RT32_MREMAP_FIXED)) != 0U ||
        ((flags & RT32_MREMAP_FIXED) != 0U && (flags & RT32_MREMAP_MAYMOVE) == 0U)) {
        return (uint32_t)(-EINVAL);
    }

    old_aligned = vm_page_align_up((uint64_t)old_len);
    new_aligned = vm_page_align_up((uint64_t)new_len);
    if (old_addr < SPARC32_LOW_GUARD_SIZE ||
        (uint64_t)old_addr + old_aligned > (uint64_t)SPARC32_TASK_SIZE_TOP) {
        return (uint32_t)(-EINVAL);
    }
    if (new_aligned == 0ULL || new_aligned > (uint64_t)SPARC32_TASK_SIZE_TOP) {
        return (uint32_t)(-ENOMEM);
    }

    vm_lock_acquire();
    vm_sync_from_ctx(ctx);

    orig_name[0] = '\0';
    if (!vm_check_mapped_range_ext_locked(
            old_addr, (uint32_t)((uint64_t)old_addr + old_aligned),
            &prot, &orig_flags, orig_name, sizeof(orig_name),
            &orig_fd, &orig_pgoff)) {
        vm_sync_to_ctx(ctx);
        vm_lock_release();
        return (uint32_t)(-EFAULT);
    }
    is_anon     = ((orig_flags & RT32_MAP_ANONYMOUS) != 0U) || (orig_fd < 0);
    is_shared   = (orig_flags & 0x01U) != 0U;
    keep_flags  = orig_flags & 0x23U;
    {
        int      hold_fd   = vm_dup_backing_fd(orig_fd);
        bool     has_shm   = is_shared && (hold_fd >= 0);
        uint32_t eff_flags = has_shm ? 0x01U :
            ((is_shared ? 0x01U : 0x02U) | (is_anon ? RT32_MAP_ANONYMOUS : 0U));
        int      eff_fd    = has_shm ? hold_fd : (is_anon ? -1 : hold_fd);
        uint32_t eff_pgoff = (is_anon && !has_shm) ? 0U : orig_pgoff;

        region_name = (orig_name[0] != '\0') ? orig_name : "[mmap]";
        if (has_shm && is_anon && new_aligned > old_aligned) {
            struct stat st;
            uint64_t req_sz = (uint64_t)orig_pgoff * (uint64_t)SPARC32_PAGE_SIZE + new_aligned;
            if (fstat(hold_fd, &st) == 0 && (uint64_t)st.st_size < req_sz) {
                (void)ftruncate(hold_fd, (off_t)req_sz);
            }
        }

        if ((flags & RT32_MREMAP_FIXED) == 0U) {
            if (new_aligned == old_aligned) {
                vm_close_backing_fd(hold_fd);
                vm_sync_to_ctx(ctx);
                vm_lock_release();
                return old_addr;
            }
            if (new_aligned < old_aligned) {
                /* mremap shrink (S32-R5-9): vm_munmap_locked retires the
                 * file-tracking range of the shrunk-away tail. */
                uint32_t unmap_addr = old_addr + (uint32_t)new_aligned;
                uint32_t unmap_len  = (uint32_t)(old_aligned - new_aligned);
                int rc = vm_munmap_locked(ctx, unmap_addr, unmap_len);
                if (rc == 0) {
                    vm_invalidate_jit_locked(ctx, unmap_addr,
                        unmap_addr + unmap_len);
                }
                vm_close_backing_fd(hold_fd);
                vm_sync_to_ctx(ctx);
                vm_lock_release();
                if (rc != 0) {
                    return (uint32_t)rc;
                }
                return old_addr;
            }

            {
                uint32_t old_end = (uint32_t)((uint64_t)old_addr + old_aligned);
                uint64_t new_end = (uint64_t)old_addr + new_aligned;
                uint32_t ext_pgoff = (is_anon && !has_shm) ? 0U :
                    (orig_pgoff + (uint32_t)(old_aligned / (uint64_t)SPARC32_PAGE_SIZE));
                if (new_end <= (uint64_t)SPARC32_TASK_SIZE_TOP &&
                    !vm_range_overlaps_locked(old_end, (uint32_t)new_end)) {
                    uint32_t ext = (uint32_t)(-ENOMEM);
                    if (has_shm && rt_host_page_size() > (size_t)SPARC32_PAGE_SIZE) {
                        void *hook_out = NULL;
                        void *base_ptr = sparc32_guest_ptr(ctx, old_addr);
                        if (rt_host_map_file(base_ptr, (size_t)new_aligned,
                                sparc32_host_prot(ctx, prot), 1, 1, hold_fd,
                                (uint64_t)orig_pgoff * (uint64_t)SPARC32_PAGE_SIZE,
                                &hook_out) == 0 && hook_out == base_ptr) {
                            vm_mmap_ensure_regime(ctx);
                            vm_mmap_publish(ctx, old_end, (uint32_t)new_end, prot, 0U);
                            ext = old_end;
                        }
                    } else {
                        ext = vm_mmap2_locked(ctx, old_end,
                            (uint32_t)(new_aligned - old_aligned), prot,
                            eff_flags | RT32_MAP_FIXED, eff_fd, ext_pgoff);
                    }
                    if (ext <= 0xFFFFF000U) {
                        int ext_rec = vm_record_region_ext_locked(
                            old_end, (uint32_t)new_end, prot, keep_flags,
                            region_name, eff_fd, ext_pgoff);
                        if (ext_rec != 0) {
                            (void)vm_munmap_locked(ctx, old_end,
                                (uint32_t)(new_aligned - old_aligned));
                            vm_close_backing_fd(hold_fd);
                            vm_sync_to_ctx(ctx);
                            vm_lock_release();
                            return (uint32_t)(-ENOMEM);
                        }
                        {
                            uint32_t ext_end = (uint32_t)new_end;
                            if (g_vm_mmap_cursor >= old_addr && g_vm_mmap_cursor < ext_end &&
                                ext_end <= RT32_MMAP_TOP_32) {
                                g_vm_mmap_cursor = ext_end;
                            }
                        }
                        if ((prot & (uint32_t)PROT_EXEC) != 0U) {
                            vm_invalidate_jit_locked(ctx, old_end,
                                (uint32_t)new_end);
                        }
                        vm_close_backing_fd(hold_fd);
                        vm_sync_to_ctx(ctx);
                        vm_lock_release();
                        return old_addr;
                    }
                }
            }

            if ((flags & RT32_MREMAP_MAYMOVE) == 0U) {
                vm_close_backing_fd(hold_fd);
                vm_sync_to_ctx(ctx);
                vm_lock_release();
                return (uint32_t)(-ENOMEM);
            }
        } else {
            if ((new_addr & (SPARC32_PAGE_SIZE - 1U)) != 0U || new_addr < SPARC32_LOW_GUARD_SIZE ||
                (uint64_t)new_addr + new_aligned > (uint64_t)SPARC32_TASK_SIZE_TOP ||
                ((uint64_t)new_addr < (uint64_t)old_addr + old_aligned &&
                 (uint64_t)old_addr < (uint64_t)new_addr + new_aligned)) {
                vm_close_backing_fd(hold_fd);
                vm_sync_to_ctx(ctx);
                vm_lock_release();
                return (uint32_t)(-EINVAL);
            }
        }

        {
            bool     is_fixed  = (flags & RT32_MREMAP_FIXED) != 0U;
            bool     need_copy = !has_shm;
            uint32_t init_prot = need_copy ?
                ((prot & ~((uint32_t)PROT_EXEC)) | (uint32_t)(PROT_READ | PROT_WRITE)) : prot;
            uint32_t new_va    = vm_mmap2_locked(ctx, is_fixed ? new_addr : 0U,
                                                 (uint32_t)new_aligned, init_prot,
                                                 eff_flags | (is_fixed ? RT32_MAP_FIXED : 0U),
                                                 eff_fd, eff_pgoff);
            size_t copy_bytes;

            if (new_va > 0xFFFFF000U) {
                vm_close_backing_fd(hold_fd);
                vm_sync_to_ctx(ctx);
                vm_lock_release();
                return new_va;
            }

            if (need_copy) {
                uint8_t *dst_ptr = (uint8_t *)sparc32_guest_ptr(ctx, new_va);
                const uint8_t *src_ptr = (const uint8_t *)sparc32_guest_ptr(ctx, old_addr);
                if ((prot & 0x1U) == 0U) {
                    (void)rt_host_protect(sparc32_guest_ptr(ctx, old_addr),
                        (size_t)old_aligned, PROT_READ);
                }
                copy_bytes = (size_t)((old_aligned < new_aligned) ? old_aligned : new_aligned);
                if (is_anon) {
                    memcpy(dst_ptr, src_ptr, copy_bytes);
                } else {
                    size_t off;
                    for (off = 0U; off < copy_bytes; off += SPARC32_PAGE_SIZE) {
                        uint8_t old_st = vm32_page_state(old_addr + (uint32_t)off);
                        if ((old_st & RT_PAGE_COW_DIRTY) != 0U) {
                            memcpy(dst_ptr + off, src_ptr + off, SPARC32_PAGE_SIZE);
                            vm32_note_page_write(new_va + (uint32_t)off, SPARC32_PAGE_SIZE);
                        }
                    }
                }
                if (prot != init_prot) {
                    (void)vm_mprotect_locked(ctx, new_va, (uint32_t)new_aligned, prot);
                }
            }
            {
                int move_rec = vm_record_region_ext_locked(
                    new_va, (uint32_t)((uint64_t)new_va + new_aligned),
                    prot, keep_flags, region_name, eff_fd, eff_pgoff);
                if (move_rec != 0) {
                    (void)vm_munmap_locked(ctx, new_va,
                        (uint32_t)new_aligned);
                    vm_close_backing_fd(hold_fd);
                    vm_sync_to_ctx(ctx);
                    vm_lock_release();
                    return (uint32_t)(-ENOMEM);
                }
            }
            (void)vm_munmap_locked(ctx, old_addr, (uint32_t)old_aligned);
            /* mremap relocate (S32-R5-9): retire the old source range so
             * later mutation hooks skip it (vm_munmap_locked already
             * retires the covered tail; this guarantees the source). */
            vm_file_unregister_range(old_addr, (uint32_t)old_aligned);
            vm_invalidate_jit_locked(ctx, old_addr,
                (uint32_t)((uint64_t)old_addr + old_aligned));
            if (is_fixed || (prot & (uint32_t)PROT_EXEC) != 0U) {
                vm_invalidate_jit_locked(ctx, new_va,
                    (uint32_t)((uint64_t)new_va + new_aligned));
            }
            vm_close_backing_fd(hold_fd);
            vm_sync_to_ctx(ctx);
            vm_lock_release();
            return new_va;
        }
    }
}

/* Reserve [start, start+len) as PROT_NONE without touching the region
 * table (moved from vm.c for the 900-line discipline). */
int vm_reserve_prot_none(sparc32_ctx_t *ctx, uint32_t start, uint32_t len)
{
    size_t hp = vm_host_page_size();
    void *res;
    if (hp > (size_t)SPARC32_PAGE_SIZE) {
        uint32_t mask = (uint32_t)hp - 1U;
        uint32_t in_start = (start + mask) & ~mask;
        uint32_t in_end   = (start + len) & ~mask;
        if (in_end > in_start) {
            if (mprotect(sparc32_guest_ptr(ctx, in_start),
                         (size_t)(in_end - in_start), PROT_NONE) != 0) {
                return -errno;
            }
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

/* Exec teardown (S32-R3-4): drop every tracked region (no persistent
 * vDSO page, so exec clears the whole table; the stack setup path
 * re-registers what the new image needs). The whole replacement stays
 * under the writer lock: vm_lock_acquire already quiesced DBT runners,
 * so no generated access is in flight while the old window is
 * destroyed, and no concurrent mapper can observe the torn table.
 * Cached translations for the destroyed image are retired after the
 * lock drops (the new image reuses the same VAs, so stale blocks must
 * not survive). */
void rt32_vm_reset_for_exec(sparc32_ctx_t *ctx)
{
    vm_lock_acquire();
    vm_reset_table_locked();

    /* Kernel exec semantics: the old address space is destroyed. Reset
     * the window back to PROT_NONE while keeping [G, G+4GiB) reserved. */
    (void)mmap(sparc32_guest_ptr(ctx, SPARC32_LOW_GUARD_SIZE),
               (size_t)(RT32_WINDOW_SIZE - (uint64_t)SPARC32_LOW_GUARD_SIZE),
               PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    vm32_reset();
    /* The old address space is gone (S32-R5-9): retire every file-tracking
     * record with it so no stale mapping survives into the new image. */
    vm_file_reset();
    vm_invalidate_jit_locked(ctx, SPARC32_LOW_GUARD_SIZE, 0xFFFFFFFFU);
    vm_lock_release();

    ctx->brk_base    = 0U;
    ctx->brk_curr    = 0U;
    ctx->mmap_cursor = RT32_MMAP_BASE_32;
    ctx->region_count = 0U;
    (void)rt32_vm_record_region(ctx, 0U, SPARC32_LOW_GUARD_SIZE,
                                0U, 0x32U, "[null_guard]");
}
