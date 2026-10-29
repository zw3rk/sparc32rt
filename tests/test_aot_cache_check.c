/*
 * tests/test_aot_cache_check.c — host-native AOT cache generation check.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Exercises the in-memory AOT block cache (src/dbt/aot/aot_cache.c)
 * through its public API only: the cache starts unready; init with an
 * authority and code generation makes it ready; add_block registers
 * relative site records and bumps the block/site counters; a warm-start
 * header candidate is accepted only with matching magic ("SRT3AOT4",
 * src/dbt/aot/aot_cache.c), format, and live code generation, and is
 * rejected on short input, bad magic, stale generation, or a missing
 * cache; invalidate drops every block after a generation bump (SMC /
 * truncate). Prints AOT-CACHE: PASS and exits 0 on success.
 *
 * Build & run (host-native):
 *   cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
 *     -Iinclude -Isrc tests/test_aot_cache_check.c \
 *     src/dbt/aot/aot_cache.c -o /tmp/test_aot_cache_check && \
 *     /tmp/test_aot_cache_check
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dbt/aot/mem_site.h"

int sparc32_aot_cache_init(const char *authority, uint64_t code_generation);
bool sparc32_aot_cache_ready(void);
int sparc32_aot_cache_check_header(const void *hdr_bytes, size_t len,
    uint64_t live_generation);
int sparc32_aot_cache_add_block(uint32_t guest_pc_base, uint32_t guest_len,
    const dbt_mem_site_t *sites, uint32_t site_count);
void sparc32_aot_cache_invalidate(uint64_t new_generation);
uint32_t sparc32_aot_cache_blocks(void);
uint32_t sparc32_aot_cache_sites(void);

static int failures = 0;

static void expect(int cond, const char *what)
{
    if (cond == 0) {
        printf("AOT-CACHE FAIL: %s\n", what);
        failures++;
    }
}

/* On-disk header layout (src/dbt/aot/aot_cache.c aot_file_header_t):
 * u64 magic @0, u32 format @8, u32 block_count @12, u64 generation @16. */
static void put_u64(uint8_t *p, uint64_t v)
{
    (void)memcpy(p, &v, sizeof v);
}

static void put_u32(uint8_t *p, uint32_t v)
{
    (void)memcpy(p, &v, sizeof v);
}

int main(void)
{
    dbt_mem_site_t sites[2];
    uint8_t hdr[96];

    expect(!sparc32_aot_cache_ready(), "cache unready before init");
    expect(sparc32_aot_cache_check_header(hdr, sizeof hdr, 7u) != 0,
        "header check without cache rejected");
    expect(sparc32_aot_cache_init("parity", 7u) == 0, "init generation 7");
    expect(sparc32_aot_cache_ready(), "cache ready after init");
    expect(sparc32_aot_cache_blocks() == 0u, "no blocks after init");
    expect(sparc32_aot_cache_sites() == 0u, "no sites after init");

    (void)memset(sites, 0, sizeof sites);
    expect(sparc32_aot_cache_add_block(0x1000u, 64u, sites, 1u) == 0,
        "add first block");
    expect(sparc32_aot_cache_blocks() == 1u, "one block cached");
    expect(sparc32_aot_cache_sites() == 1u, "one site cached");
    expect(sparc32_aot_cache_add_block(0x2000u, 32u, sites, 2u) == 0,
        "add second block");
    expect(sparc32_aot_cache_blocks() == 2u, "two blocks cached");
    expect(sparc32_aot_cache_sites() == 3u, "three sites cached");
    expect(sparc32_aot_cache_add_block(0x3000u, 32u, NULL, 1u) != 0,
        "NULL sites rejected");

    (void)memset(hdr, 0, sizeof hdr);
    put_u64(hdr, 0x53335254414f5434ULL);
    put_u32(hdr + 8, 4u);
    put_u32(hdr + 12, 2u);
    put_u64(hdr + 16, 7u);
    expect(sparc32_aot_cache_check_header(hdr, sizeof hdr, 7u) == 0,
        "matching header accepted");
    expect(sparc32_aot_cache_check_header(hdr, 8u, 7u) != 0,
        "short header rejected");
    expect(sparc32_aot_cache_check_header(NULL, sizeof hdr, 7u) != 0,
        "NULL header rejected");
    put_u64(hdr, 0xDEADBEEFDEADBEEFULL);
    expect(sparc32_aot_cache_check_header(hdr, sizeof hdr, 7u) != 0,
        "bad magic rejected");
    put_u64(hdr, 0x53335254414f5434ULL);
    put_u64(hdr + 16, 8u);
    expect(sparc32_aot_cache_check_header(hdr, sizeof hdr, 7u) != 0,
        "stale generation rejected");

    sparc32_aot_cache_invalidate(8u);
    expect(sparc32_aot_cache_blocks() == 0u, "invalidate drops blocks");
    expect(sparc32_aot_cache_sites() == 0u, "invalidate drops sites");
    expect(sparc32_aot_cache_ready(), "cache stays ready after invalidate");
    put_u64(hdr + 16, 8u);
    put_u64(hdr, 0x53335254414f5434ULL);
    expect(sparc32_aot_cache_check_header(hdr, sizeof hdr, 8u) == 0,
        "new generation accepted after invalidate");

    if (failures == 0) {
        printf("AOT-CACHE: PASS\n");
        return 0;
    }
    printf("AOT-CACHE: FAIL (%d)\n", failures);
    return 1;
}
