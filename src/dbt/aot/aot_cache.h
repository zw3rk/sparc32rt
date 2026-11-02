/*
 * src/dbt/aot/aot_cache.h — Persistent AOT code cache, public interface.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * On-disk format v4 (little-endian host order; both supported hosts are
 * little-endian, verified at runtime on save/load):
 *
 *   header: u64 magic "SRT3AOT4", u32 format 4, u32 block_count,
 *           u64 code_generation, char authority[64]
 *   per block: u32 guest_pc_base, u32 guest_len, u32 site_count (0:
 *           this engine tracks no per-block mem sites), u32 code_offset,
 *           u32 code_len (0), u64 guest_hash (FNV-1a over the guest bytes
 *           in [guest_pc_base, guest_pc_base + guest_len) at record time)
 *
 * Policy (mutation rejection): a warm start re-hashes every persisted
 * block against the live guest mapping and consults only blocks whose
 * hash still matches; anything else (bad magic, stale generation,
 * unreadable guest bytes, hash drift after SMC/munmap) falls back to
 * cold translation, never to executing stale records. Persisted records
 * are metadata + hashes only: warm execution re-translates (the
 * translator is deterministic), so reload output is byte-identical by
 * construction and the warm-hit counter reports how many lookups were
 * covered by revalidated entries.
 */

#ifndef SPARC32RT_DBT_AOT_CACHE_H
#define SPARC32RT_DBT_AOT_CACHE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dbt/aot/mem_site.h"

/* Code-generation identity: bump when the DBT emitter changes so warm
 * starts from an older emitter cold-translate instead of trusting
 * revalidated ranges recorded under different code. */
#define SPARC32_AOT_CODE_GENERATION 1u

#define SPARC32_AOT_AUTHORITY "sparc32rt"

/* FNV-1a 64-bit over arbitrary bytes (guest-hash primitive). Never
 * returns 0 for a non-empty input (0 maps to 1): 0 stays the "no
 * hash" sentinel. */
uint64_t sparc32_aot_fnv1a(const void *bytes, size_t len);

int sparc32_aot_cache_init(const char *authority, uint64_t code_generation);
bool sparc32_aot_cache_ready(void);
int sparc32_aot_cache_check_header(const void *hdr_bytes, size_t len,
    uint64_t live_generation);
int sparc32_aot_cache_add_block(uint32_t guest_pc_base, uint32_t guest_len,
    const dbt_mem_site_t *sites, uint32_t site_count);

/* Record one sealed block carrying no site table (this engine tracks
 * no per-block mem_site_t): stores range + guest hash for warm
 * revalidation. Returns 0 on success, -1 when the tables are full. */
int sparc32_aot_cache_record(uint32_t guest_pc_base, uint32_t guest_len,
    uint64_t guest_hash);

void sparc32_aot_cache_invalidate(uint64_t new_generation);
uint32_t sparc32_aot_cache_blocks(void);
uint32_t sparc32_aot_cache_sites(void);

/* Serialize the cold-run table to `path` (header + block records).
 * Returns 0 on success, -1 on I/O or byte-order failure. A table with
 * zero blocks still writes a valid header. */
int sparc32_aot_cache_save(const char *path);

/* Guest-byte hash callback for warm validation (implemented by the
 * caller, which owns the guest mapping): must hash [va, va + len) and
 * return 0 when those bytes are unreadable. */
typedef uint64_t (*sparc32_aot_hash_fn)(uint32_t va, uint32_t len,
    void *opaque);

/* Load `path`, validate magic/format/generation/authority, and
 * revalidate every block with `hash_fn`: matching blocks enter the
 * warm table, the rest are dropped. Returns the number of revalidated
 * blocks, or -1 when the file is unusable (caller cold-translates).
 * A successful load with zero revalidated blocks returns 0. */
int sparc32_aot_cache_load(const char *path, sparc32_aot_hash_fn hash_fn,
    void *opaque);

/* Drop the warm table (SMC/mprotect/munmap/arena recycle make
 * revalidated ranges stale). The accumulating cold-run table is
 * unaffected. */
void sparc32_aot_cache_warm_drop(void);

/* True when `pc` starts a revalidated warm block (counts the hit for
 * the warm-hit probe below). */
bool sparc32_aot_cache_warm_hit(uint32_t pc);

/* Warm-table probes for the `--aot-cache` stderr note. */
uint32_t sparc32_aot_cache_warm_blocks(void);
uint32_t sparc32_aot_cache_warm_hits(void);

#endif /* SPARC32RT_DBT_AOT_CACHE_H */
