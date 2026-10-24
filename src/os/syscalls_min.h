/*
 * src/os/syscalls_min.h — Minimal syscall layer entry points (Phase 1, L1c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Declares the Phase-1 syscall subset implemented in src/os/syscalls_min.c.
 * Coordinator-owned wiring header; L1c owns the implementation.
 */

#ifndef SPARC32RT_OS_SYSCALLS_MIN_H
#define SPARC32RT_OS_SYSCALLS_MIN_H

#include "sparc32rt.h"

/* Nonzero when nr is a terminal exit (exit/exit_group). */
int sparc32_syscall_is_exit(long nr);

/* Short name for nr, or NULL when out of range. */
const char *sparc32_syscall_name(long nr);

/* Dispatch %g1 (%o0..%o5 args), commit the SPARC carry convention, advance
 * pc = npc; npc += 4. Returns the guest exit status for exit/exit_group,
 * 0 otherwise. */
long sparc32_handle_syscall(sparc32_ctx_t *ctx);

/* Look up the installed old-style handler for sig (1..31). Returns 0 with
 * the handler/restorer VAs filled when installed, -1 otherwise. Phase-1
 * sync delivery (interp_try_deliver_sync) consults this. */
int sparc32_signal_get(int sig, uint32_t *handler_va, uint32_t *restorer_va);

#endif /* SPARC32RT_OS_SYSCALLS_MIN_H */
