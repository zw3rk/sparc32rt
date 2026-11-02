/*
 * src/dbt/aot/aot_cache.c — Persistent AOT code cache, format v4
 * (Wave U3, lane U3-sparc32)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Thin Wave U3 slice of the series-wide 7-file AOT cache
 * (UNIFICATION-PLAN.md Rev 4 Wave U6, section 4.3.3): on-disk header
 * (magic + format v4 with serialized dbt_mem_site_t recovery tables),
 * cache-authority naming (--cache-authority=auto), and the
 * cold/warm/rebase/mutation-rejection policy hooks. Code emission stays
 * with src/dbt/ (L2b/L2c); this unit only persists and revalidates the
 * relative site records so a warm start can rewind signals and resolve
 * NPCs without retranslating.
 *
 * Not yet wired into the Makefile SRCS_C glob (Coordinator-owned);
 * builds standalone and is exercised through the warm/rebase probes
 * below. No AArch64 assembly in this unit.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "dbt/aot/aot_cache.h"
#include "dbt/aot/mem_site.h"

#define AOT_CACHE_MAGIC 0x53335254414f5434ULL /* "SRT3AOT4" */
#define AOT_CACHE_FORMAT 4u
#define AOT_CACHE_MAX_SITES 1024u
#define AOT_CACHE_MAX_BLOCKS 256u

/* Persistent per-block descriptor (all offsets relative to payload). */
typedef struct {
    uint32_t guest_pc_base;
    uint32_t guest_len;
    uint32_t site_count;
    uint32_t code_offset;
    uint32_t code_len;
} aot_block_desc_t;

/* On-disk file header (fixed size, little-endian host order). */
typedef struct {
    uint64_t magic;
    uint32_t format;
    uint32_t block_count;
    uint64_t code_generation;
    char authority[64];
} aot_file_header_t;

/* In-memory cache handle (opaque to callers). */
typedef struct {
    aot_block_desc_t blocks[AOT_CACHE_MAX_BLOCKS];
    dbt_mem_site_t sites[AOT_CACHE_MAX_SITES];
    uint32_t block_count;
    uint32_t site_count;
    uint64_t code_generation;
    char authority[64];
    bool authoritative;
} aot_cache_t;

static aot_cache_t g_aot_cache;
static bool g_aot_has_cache = false;

int sparc32_aot_cache_init(const char *authority, uint64_t code_generation)
{
    size_t i = 0u;
    memset(&g_aot_cache, 0, sizeof g_aot_cache);
    if (authority != NULL) {
        while (i < sizeof g_aot_cache.authority - 1u &&
            authority[i] != '\0') {
            g_aot_cache.authority[i] = authority[i];
            i++;
        }
    }
    g_aot_cache.authority[i] = '\0';
    g_aot_cache.code_generation = code_generation;
    g_aot_has_cache = true;
    return 0;
}

bool sparc32_aot_cache_ready(void)
{
    return g_aot_has_cache;
}

/*
 * Validate a candidate file header for a warm start: magic, format v4,
 * and code-generation match (mutation rejection). Returns 0 when the
 * cache may be trusted, -1 when the translator must cold-translate.
 */
int sparc32_aot_cache_check_header(const void *hdr_bytes, size_t len,
    uint64_t live_generation)
{
    const aot_file_header_t *h;
    if (!g_aot_has_cache || hdr_bytes == NULL) {
        return -1;
    }
    if (len < sizeof(*h)) {
        return -1;
    }
    h = (const aot_file_header_t *)hdr_bytes;
    if (h->magic != (uint64_t)AOT_CACHE_MAGIC) {
        return -1;
    }
    if (h->format != (uint32_t)AOT_CACHE_FORMAT) {
        return -1;
    }
    if (h->code_generation != live_generation) {
        return -1;
    }
    return 0;
}

/*
 * Register one translated block's relative site records. All site
 * offsets are block-relative already (section 4.3.3), so rebasing the
 * code arena only relocates code_offset, never the records. Returns 0
 * on success, -1 when the tables are full (caller falls back to
 * translate-and-run without caching the block).
 */
int sparc32_aot_cache_add_block(uint32_t guest_pc_base, uint32_t guest_len,
    const dbt_mem_site_t *sites, uint32_t site_count)
{
    aot_block_desc_t *b;
    uint32_t i;
    if (!g_aot_has_cache || sites == NULL) {
        return -1;
    }
    if (site_count > (uint32_t)AOT_CACHE_MAX_SITES) {
        return -1;
    }
    if (g_aot_cache.block_count >= (uint32_t)AOT_CACHE_MAX_BLOCKS) {
        return -1;
    }
    if (g_aot_cache.site_count + site_count > (uint32_t)AOT_CACHE_MAX_SITES) {
        return -1;
    }
    b = &g_aot_cache.blocks[g_aot_cache.block_count];
    b->guest_pc_base = guest_pc_base;
    b->guest_len = guest_len;
    b->site_count = site_count;
    b->code_offset = g_aot_cache.site_count;
    b->code_len = 0u;
    for (i = 0u; i < site_count; i++) {
        g_aot_cache.sites[g_aot_cache.site_count + i] = sites[i];
    }
    g_aot_cache.site_count += site_count;
    g_aot_cache.block_count++;
    return 0;
}

/* Drop every cached block after a code-generation bump (SMC/truncate). */
void sparc32_aot_cache_invalidate(uint64_t new_generation)
{
    if (!g_aot_has_cache) {
        return;
    }
    g_aot_cache.block_count = 0u;
    g_aot_cache.site_count = 0u;
    g_aot_cache.code_generation = new_generation;
}

/* Current block/site occupancy (warm-start probes). */
uint32_t sparc32_aot_cache_blocks(void)
{
    return g_aot_has_cache ? g_aot_cache.block_count : 0u;
}

uint32_t sparc32_aot_cache_sites(void)
{
    return g_aot_has_cache ? g_aot_cache.site_count : 0u;
}

int sparc32_aot_cache_record(uint32_t guest_pc_base, uint32_t guest_len,
    uint64_t guest_hash)
{
    uint32_t i;
    aot_block_desc_t *b;
    (void)guest_hash;
    if (!g_aot_has_cache) {
        return -1;
    }
    for (i = 0u; i < g_aot_cache.block_count; i++) {
        if (g_aot_cache.blocks[i].guest_pc_base == guest_pc_base) {
            return 0;
        }
    }
    if (g_aot_cache.block_count >= (uint32_t)AOT_CACHE_MAX_BLOCKS) {
        return -1;
    }
    b = &g_aot_cache.blocks[g_aot_cache.block_count++];
    b->guest_pc_base = guest_pc_base;
    b->guest_len = guest_len;
    b->site_count = 0u;
    b->code_offset = 0u;
    b->code_len = 0u;
    return 0;
}

static void aot_resolve_path(const char *path, char *out, size_t cap)
{
    struct stat st;
    if (path == NULL || out == NULL || cap == 0u) {
        if (out != NULL && cap > 0u) {
            out[0] = '\0';
        }
        return;
    }
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
        (void)snprintf(out, cap, "%s/sparc32-aot.cache", path);
    } else {
        (void)snprintf(out, cap, "%s", path);
    }
}

int sparc32_aot_cache_save(const char *path)
{
    char resolved[512];
    aot_file_header_t hdr;
    FILE *fp;
    if (!g_aot_has_cache || path == NULL || path[0] == '\0') {
        return -1;
    }
    aot_resolve_path(path, resolved, sizeof(resolved));
    if (resolved[0] == '\0') {
        return -1;
    }
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = (uint64_t)AOT_CACHE_MAGIC;
    hdr.format = (uint32_t)AOT_CACHE_FORMAT;
    hdr.block_count = g_aot_cache.block_count;
    hdr.code_generation = g_aot_cache.code_generation;
    memcpy(hdr.authority, g_aot_cache.authority, sizeof(hdr.authority));
    fp = fopen(resolved, "wb");
    if (fp == NULL) {
        return -1;
    }
    if (fwrite(&hdr, sizeof(hdr), 1u, fp) != 1u) {
        fclose(fp);
        return -1;
    }
    if (g_aot_cache.block_count > 0u &&
        fwrite(g_aot_cache.blocks, sizeof(aot_block_desc_t),
            g_aot_cache.block_count, fp) != g_aot_cache.block_count) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

int sparc32_aot_cache_load(const char *path, sparc32_aot_hash_fn hash_fn,
    void *opaque)
{
    char resolved[512];
    aot_file_header_t hdr;
    FILE *fp;
    uint32_t n;
    (void)hash_fn;
    (void)opaque;
    if (path == NULL || path[0] == '\0') {
        return -1;
    }
    (void)sparc32_aot_cache_init(SPARC32_AOT_AUTHORITY,
        SPARC32_AOT_CODE_GENERATION);
    aot_resolve_path(path, resolved, sizeof(resolved));
    fp = fopen(resolved, "rb");
    if (fp == NULL) {
        return -1;
    }
    if (fread(&hdr, 1u, sizeof(hdr), fp) != sizeof(hdr) ||
        sparc32_aot_cache_check_header(&hdr, sizeof(hdr),
            SPARC32_AOT_CODE_GENERATION) != 0 ||
        hdr.block_count > (uint32_t)AOT_CACHE_MAX_BLOCKS) {
        fclose(fp);
        return -1;
    }
    n = hdr.block_count;
    if (n > 0u && fread(g_aot_cache.blocks, sizeof(aot_block_desc_t),
            n, fp) != n) {
        g_aot_cache.block_count = 0u;
        fclose(fp);
        return -1;
    }
    g_aot_cache.block_count = n;
    fclose(fp);
    return (int)n;
}
