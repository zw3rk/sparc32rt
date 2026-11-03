/*
 * src/interp/interp.h — Reference interpreter entry points (Phase 1, L1b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Declares the SPEC section 3.1 interpreter interface implemented in
 * src/interp/interp.c. Coordinator-owned wiring header; L1b owns the
 * implementation.
 */

#ifndef SPARC32RT_INTERP_INTERP_H
#define SPARC32RT_INTERP_INTERP_H

#include "sparc32rt.h"

/* Execute one guest instruction at ctx->pc/ctx->npc, updating ctx in place.
 * Sets ctx->exit_reason (SPARC32_EXIT_*) when the run loop must stop. */
void interp_step(sparc32_ctx_t *ctx);

/* Reset the window file + WIM to fresh-process state (CWP=0, WIM=0x01).
 * main calls this once per guest run, before the first interp_run. */
void interp_window_reset(void);

/* Run guest instructions until ctx->exit_reason != SPARC32_EXIT_NONE. */
void interp_run(sparc32_ctx_t *ctx);

/* Try synchronous delivery of signo (4 SIGILL / 8 SIGFPE / 10 SIGBUS /
 * 11 SIGSEGV) for a fault recorded in ctx->fault_addr (or exit_dest for
 * traps). Builds the rt_signal_frame32 and redirects to the installed
 * old-style handler; returns true when delivered (exit state cleared for
 * continued interp_run). Returns false when no handler is installed or
 * the frame does not fit — caller keeps the stop reason. */
bool interp_try_deliver_sync(sparc32_ctx_t *ctx, int signo);

/* Instruction-aware fault -> signal classification (10 SIGBUS vs 11 SIGSEGV).
 * Shared by src/main.c and clone-thread fault delivery in src/os/threads.c. */
int sparc32_classify_fault(const sparc32_ctx_t *ctx);

/* Map an architectural trap stop (EXIT_TRAP/EXIT_UNDEF) to its guest
 * signal (4 SIGILL / 8 SIGFPE, 0 when not mappable). Shared by the
 * main and clone-thread run loops (S32-R7-15). */
int sparc32_trap_signo(const sparc32_ctx_t *ctx);

#endif /* SPARC32RT_INTERP_INTERP_H */
