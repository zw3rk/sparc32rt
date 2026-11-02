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

/* Async safe-point poll (interp_signal.c, Phase 4): deliver the lowest
 * unblocked pending signal with an installed handler; true when a
 * delivery redirected pc (caller keeps running). */
bool interp_poll_async(sparc32_ctx_t *ctx);
bool interp_fill_from(sparc32_ctx_t *ctx, uint32_t w, uint32_t va);
bool interp_window(sparc32_ctx_t *ctx, const sparc32_decoded_t *d,
    bool is_save);
/* Real SPARC signal constants (C2-3: verified against the uClibc
 * sysroot headers; shared by the syscall layer and delivery). */
#define SPARC32_SA_ONSTACK 1U
#define SPARC32_SA_RESTART 2U
#define SPARC32_SA_NODEFER 0x20U
#define SPARC32_SA_SIGINFO 0x200U
#define SPARC32_SS_ONSTACK 1U
#define SPARC32_SS_DISABLE 2U
#define SPARC32_MINSIGSTKSZ 4096U
#define SPARC32_SIGFPU_SIZE 136U
/* C2-3 signal extensions (implemented in os/syscalls_sig.c, consulted
 * by interp_signal.c delivery): full disposition (handler/restorer/
 * accepted SA_* flags/sa_mask), alternate-stack state, and onstack mark. */
int sparc32_signal_get_full(int sig, uint32_t *handler_va,
    uint32_t *restorer_va, uint32_t *flags);
int sparc32_signal_get_action(int sig, uint32_t *handler_va,
    uint32_t *restorer_va, uint32_t *flags, uint64_t *sa_mask);
int sparc32_sigaltstack_state(uint32_t *sp, uint32_t *size, int *onstack);
void sparc32_sigaltstack_set_onstack(int onstack);
void sparc32_l2a_set_blocked_mask(sparc32_ctx_t *ctx, uint64_t mask);
/* Flush-windows trap (ta 3, C2-3): spill every cached caller window to
 * its recorded stack slot so setjmp/longjmp and signal frames observe
 * fully spilled stacks. The cache values are published unchanged, so no
 * counter changes (a later RESTORE still fills the identical image);
 * false propagates the spill fault (exit_reason/fault_addr already
 * set by the memory layer). */
bool interp_flush_windows(sparc32_ctx_t *ctx);

#endif /* SPARC32RT_INTERP_PRIV_H */
