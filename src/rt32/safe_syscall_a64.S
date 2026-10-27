/*
 * src/rt32/safe_syscall_a64.S — D18 signal-window race-free host syscall gate
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * long rt32_safe_syscall(long nr, long a0, long a1, long a2,
 *                        long a3, long a4, long a5);
 *
 * Performs one AArch64 Linux host syscall (nr in x8, args in x0..x5).
 * D18 contract for the Phase 4 signal layer: the single `svc #0` is the
 * commit point. A signal that arrives with the interrupted PC inside
 * [rt32_safe_syscall, rt32_safe_syscall_end) either completed (PC past
 * the svc: return x0 as usual) or is restartable (PC at the svc: re-issue
 * with the saved register arguments); the window never spans host code
 * that holds translator locks. Uses only x0..x8 — never x18.
 *
 * Phase 4 lane L4b (thread/signal contract, code unchanged):
 *   Register use: x0..x8 only — never the platform register x18, so host
 *   pthread runtimes keep their reservation on every thread.
 *   Any-thread window: the restartable window is a pure PC range delimited
 *   by the two global symbols; the gate keeps no per-thread state, uses no
 *   stack, and touches no translator locks, so the D18 sync-fault semantics
 *   hold identically on the main thread and on every host pthread entered
 *   via src/rt32/thread_entry.S.
 *   Async protocol: host signal handlers must only set the per-thread
 *   pending flag (an async-signal-safe store, never a longjmp out of
 *   translated code); delivery happens at dispatcher safe points
 *   (phase-4.md contract 5). Translated regions run with asynchronous host
 *   signals masked by the C caller wherever the kernel allows
 *   (pthread_sigmask around the thread-entry calls), so an async signal is
 *   observed only as a pending flag at the next safe point, never as an
 *   interruption of translated code or of the svc above.
 */

    .text
    .align 2
#ifdef __APPLE__
    .globl _rt32_safe_syscall
_rt32_safe_syscall:
#else
    .globl rt32_safe_syscall
    .type rt32_safe_syscall, %function
#endif
rt32_safe_syscall:
    mov     x8, x0
    mov     x0, x1
    mov     x1, x2
    mov     x2, x3
    mov     x3, x4
    mov     x4, x5
    mov     x5, x6
    svc     #0
    ret
#ifdef __APPLE__
    .globl _rt32_safe_syscall_end
_rt32_safe_syscall_end:
#else
    .globl rt32_safe_syscall_end
#endif
rt32_safe_syscall_end:
#ifndef __APPLE__
    .size rt32_safe_syscall, . - rt32_safe_syscall
#endif
