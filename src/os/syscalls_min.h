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

/* Single host-to-guest errno mapping (S32-R13-8): SPARC Linux follows
 * SunOS numbering (arch/sparc/include/uapi/asm/errno.h), so ENOSYS is
 * 90 (not 38) and ETIMEDOUT is 60 (not 110). Every layer returns
 * negative host errnos; only the carry commit (and this function)
 * converts. Declared here so futex.c shares it instead of keeping
 * conflicting SP_* constants. */
uint32_t sparc32_errno_from_host(long host_errno);

/* Short name for nr, or NULL when out of range. */
const char *sparc32_syscall_name(long nr);

/* Dispatch %g1 (%o0..%o5 args), commit the SPARC carry convention, advance
 * pc = npc; npc += 4. Returns the guest exit status for exit/exit_group,
 * 0 otherwise. */
long sparc32_handle_syscall(sparc32_ctx_t *ctx);

/* SPARC rt_sigprocmask how values (NOT the generic 0/1/2): 1 = BLOCK,
 * 2 = UNBLOCK, 4 = SETMASK (qemu target_signal.h; how=0 is EINVAL). */
#define SPARC_SIG_BLOCK 1U
#define SPARC_SIG_UNBLOCK 2U
#define SPARC_SIG_SETMASK 4U

/* Signal disposition kinds (S32-R3-6): the table distinguishes default,
 * ignored, and caught instead of collapsing DFL/IGN into "absent". */
#define SPARC32_SIG_DISP_DFL 0
#define SPARC32_SIG_DISP_IGN 1
#define SPARC32_SIG_DISP_CAUGHT 2

/* Look up the installed old-style handler for sig (1..31). Returns 0 with
 * the handler/restorer VAs filled when caught, -1 otherwise. Phase-1
 * sync delivery (interp_try_deliver_sync) consults this. */
int sparc32_signal_get(int sig, uint32_t *handler_va, uint32_t *restorer_va);

/* Current disposition kind for sig (one of SPARC32_SIG_DISP_*). */
int sparc32_signal_disposition(int sig);

/* Drop every installed disposition (process teardown path). */
void sparc32_signal_reset_all(void);

/* execve(59) disposition reset: caught signals return to SIG_DFL with
 * the host disposition synced back; ignored dispositions survive, and
 * the blocked mask plus pending queues are left untouched. */
void sparc32_signal_reset_for_exec(void);

#endif /* SPARC32RT_OS_SYSCALLS_MIN_H */
