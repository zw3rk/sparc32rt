/*
 * src/interp/interp_priv.h — Shared internals for the interp engine
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
Internal linkage between interp.c / interp_mem.c / interp_win.c /
 * interp_signal.c. Not part of the public engine API (interp.h).
 */

#ifndef SPARC32RT_INTERP_PRIV_H
#define SPARC32RT_INTERP_PRIV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sparc32rt.h"
#include "interp/decode.h"

void interp_wreg(sparc32_ctx_t *ctx, uint32_t rd, uint32_t v);
bool interp_range_ok(const sparc32_ctx_t *ctx, uint32_t va, uint32_t len,
    uint32_t need);
bool interp_mem_rd(sparc32_ctx_t *ctx, uint32_t va, void *dst, uint32_t len);
bool interp_mem_wr(sparc32_ctx_t *ctx, uint32_t va, const void *src,
    uint32_t len);
bool interp_ld_be(sparc32_ctx_t *ctx, uint32_t va, uint32_t len,
    uint32_t *out);
bool interp_st_be(sparc32_ctx_t *ctx, uint32_t va, uint32_t len, uint32_t v);
bool interp_spill_to(sparc32_ctx_t *ctx, uint32_t w, uint32_t va);
bool interp_fill_from(sparc32_ctx_t *ctx, uint32_t w, uint32_t va);
bool interp_window(sparc32_ctx_t *ctx, const sparc32_decoded_t *d,
    bool is_save);

#endif /* SPARC32RT_INTERP_PRIV_H */
