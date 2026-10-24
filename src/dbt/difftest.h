/*
 * src/dbt/difftest.h — Lockstep interp-vs-dbt differential harness (Phase 2)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L2d owns this file (Phase 2, SPEC sections 2-3). It declares the
 * --difftest entry point consumed by the Coordinator-owned main.c wiring:
 * difftest_run() steps the reference interpreter (src/interp/, L1b) and
 * the DBT single-step entry (L2b) in lockstep from the same loaded guest
 * and compares the full user-visible state after every instruction.
 *
 * Compared state: r[32], pc, npc, psr.icc (N/Z/V/C only), y, fsr, f[32],
 * and the register-window management state (cwp, cansave, canrestore,
 * otherwin, cleanwin, nwindows). Guest memory — including the spilled
 * window save areas — is shared: both step-copies carry the same
 * guest_base into one [G, G + 4 GiB) mapping, so memory cannot diverge
 * by construction and only the register views are compared.
 *
 * Syscalls (EXIT_SYSCALL) run exactly once through the shared
 * sparc32_handle_syscall() handler (L1c/L2a); the resulting state is then
 * mirrored into both engines before resuming.
 */

#ifndef SPARC32RT_DBT_DIFFTEST_H
#define SPARC32RT_DBT_DIFFTEST_H

#include "sparc32rt.h"

/*
 * DBT single-instruction entry (defined by lane L2b in src/dbt/dbt.c).
 *
 * Contract (Phase-2 lane card L2b): translate and execute exactly one
 * guest instruction at ctx->pc/ctx->npc with no chaining, reporting
 * through the same exit-reason protocol as interp_step/interp_run
 * (ctx->exit_reason SPARC32_EXIT_*, ctx->fault_addr, ctx->exit_dest).
 * In particular one difftest iteration — one interp_step plus one
 * dbt_step from identical state — must consume the identical instruction
 * extent (a CTI plus its delay slot counts as one step on both sides,
 * matching interp_step granularity).
 *
 * Canonical declaration lives in L2b's src/dbt/dbt.h; this compatible
 * forward declaration lets difftest.c compile standalone until the
 * Coordinator merges the lanes.
 */
int dbt_step(sparc32_ctx_t *ctx);

/*
 * Lockstep difftest from the already-loaded guest in *ctx.
 *
 * Prints "difftest: 0 divergences ..." when the guest terminates via an
 * exit syscall with no state mismatch, or the first divergence (step PC,
 * differing fields, guest backtrace) otherwise.
 *
 * Returns the guest exit status on a divergence-free guest exit, 1 on the
 * first state divergence, 2 when both engines agree on a non-exit stop
 * (matching fault/trap) or the step budget is exhausted.
 */
int difftest_run(sparc32_ctx_t *ctx);

#endif /* SPARC32RT_DBT_DIFFTEST_H */
