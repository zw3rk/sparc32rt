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
 */

    .text
    .align 2
    .globl rt32_safe_syscall
    .type rt32_safe_syscall, %function
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
rt32_safe_syscall_end:
    .globl rt32_safe_syscall_end
    .size rt32_safe_syscall, . - rt32_safe_syscall
