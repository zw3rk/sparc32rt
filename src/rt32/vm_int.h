/*
 * src/rt32/vm_int.h — Internal shared declarations for vm.c / vm_mmap.c
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Not part of the frozen rt32.h surface; only the two VMA translation
 * units include this header.
 */

#ifndef SPARC32RT_RT32_VM_INT_H
#define SPARC32RT_RT32_VM_INT_H

#include "rt32.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RT32_WINDOW_SIZE         0x100000000ULL
#define RT32_MMAP_BASE_32        0x40000000U /* Guest non-fixed mmap region base (1 GiB) */
#define RT32_MMAP_TOP_32         0xEE000000U /* Below the SPARC32 stack (0xEFFF0000) */
#define RT32_MAP_FIXED           0x10U
#define RT32_MAP_ANONYMOUS       0x20U
#define RT32_MAP_FIXED_NOREPLACE 0x100000U
#define RT32_MREMAP_MAYMOVE      1U
#define RT32_MREMAP_FIXED        2U

extern uint32_t g_vm_mmap_cursor;

void vm_lock_acquire(void);
void vm_lock_release(void);
uint64_t vm_page_align_up(uint64_t v);
int vm_reserve_prot_none(sparc32_ctx_t *ctx, uint32_t start, uint32_t len);
void vm_invalidate_jit(sparc32_ctx_t *ctx, uint32_t start, uint32_t end);
void vm_sync_from_ctx(sparc32_ctx_t *ctx);
void vm_sync_brk_to_ctx(sparc32_ctx_t *ctx);
void vm_sync_to_ctx(sparc32_ctx_t *ctx);
int vm_record_region_locked(uint32_t start, uint32_t end,
                            uint32_t prot, uint32_t flags, const char *name);
int vm_record_region_ext_locked(uint32_t start, uint32_t end,
                                uint32_t prot, uint32_t flags, const char *name,
                                int fd, uint32_t pgoff);
void vm_mprotect_regions_locked(uint32_t mp_start, uint32_t mp_end, uint32_t prot);
bool vm_range_overlaps_locked(uint32_t start, uint32_t end);
bool vm_check_mapped_range_locked(uint32_t start, uint32_t end,
                                  uint32_t *out_prot, uint32_t *out_flags,
                                  char *out_name, size_t name_sz);
bool vm_check_mapped_range_ext_locked(uint32_t start, uint32_t end,
                                      uint32_t *out_prot, uint32_t *out_flags,
                                      char *out_name, size_t name_sz,
                                      int *out_fd, uint32_t *out_pgoff);
int vm_dup_backing_fd(int fd);
void vm_close_backing_fd(int fd);
bool vm_can_split_range_locked(uint32_t start, uint32_t end, bool is_mprotect);
int vm_find_free_gap_locked(uint64_t aligned_len, uint32_t *out_va);
int vm_munmap_locked(sparc32_ctx_t *ctx, uint32_t addr, uint32_t len);
void vm_unmap_regions_pub(uint32_t unmap_start, uint32_t unmap_end);

#endif /* SPARC32RT_RT32_VM_INT_H */
