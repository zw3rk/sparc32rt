/*
 * src/rt32/thread_entry.S — Phase 4 lane L4b: host-thread entry into translated code
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * A new host pthread (created by L4a's src/os/threads.c clone path) reaches
 * translated code through rt32_thread_enter_block / rt32_thread_enter_step
 * rather than the main dispatcher's dbt_enter_block / dbt_enter_step
 * (src/dbt/trampoline_a64.S, owned by L2b and therefore not editable from
 * this lane). A separate trampoline is needed (not an extension of the D18
 * gate) because thread entry must clear NZCV, guarantee 16-aligned SP, and
 * install the x27/x28 chaining registers — frame-building entry logic that
 * does not belong in the leafless single-svc safe_syscall gate, whose
 * restartable window is reasoned about as one instruction.
 *
 * Exit protocol (identical to the main dispatcher entry on purpose): every
 * emitted exit carries the resume/fault guest PC in w15 and the
 * SPARC32_EXIT_* reason in w16; both entries store w16 -> ctx->exit_reason
 * (0x138) and w15 -> ctx->exit_dest (0x144), fold the in-fragment
 * chain_hits delta (x24) into ctx->chain_hits (0x168), and return to C.
 * The C caller then commits pc/npc exactly like dbt_commit in
 * src/dbt/dbt.c:
 *   BRANCH/TRAP/FAULT/UNDEF/SINGLE_STEP: pc = exit_dest, npc = exit_dest + 4
 *   SYSCALL:                             pc = exit_dest - 4, npc = exit_dest
 *
 * Register contract (matches src/rt32/a64_emit.h and the L2b trampoline):
 *   in:  x0 = ctx (sparc32_ctx_t *), x1 = entry (host RX fragment address),
 *         x2 = chaining entry for x27, x3 = epoch word for x28 (block only;
 *         step installs its own zero word, so x3 is ignored there).
 *   x19 = ctx (xCtx); x20 = G loaded from ctx->guest_base at 0x130 (xG, so
 *         guest memory is addressed [x20, wAddr, uxtw]); x25 = the
 *         g_vm32_prot_jit base (like the L2b trampoline); x24 = 0 on entry
 *         and the chain_hits delta on exit; x27/x28 = chaining registers;
 *         x29/x30 = frame/link; d8-d15 preserved across the call.
 *   x0-x3 still hold the C arguments on fragment entry (the trampoline
 *         reads them without clobbering before the blr).
 *   out: w15/w16 -> ctx as above; x0-x3 clobbered (argument registers).
 *   NZCV is cleared (msr nzcv, xzr) before the blr, so translated code
 *         always starts from defined flags on every thread. SP is
 *         16-aligned on entry (AAPCS64/pthread guarantee) and every
 *         push/pop below is a balanced 16-byte pair, so translated code
 *         observes 16-aligned SP.
 *   The step entry points x28 at a stack-resident zero word (emitted
 *         epoch-gated chain probes all read 0 and bail, exactly like the
 *         L2b zero-epoch word) instead of rodata, so this file assembles
 *         unchanged under GAS/ELF and the Apple Mach-O assembler
 *         (only .text/.align/.globl/.macro directives are used).
 *
 * Signal rules: this trampoline holds no translator locks and performs no
 * svc, so the D18 safe_syscall window (defined solely by the symbol range
 * [rt32_safe_syscall, rt32_safe_syscall_end) in safe_syscall_a64.S) is
 * unaffected. Synchronous host faults from translated code take the L4a
 * signal path; asynchronous host signals never interrupt translated code
 * directly — the host handler sets the per-thread pending flag only, and
 * delivery happens at dispatcher safe points (phase-4.md contract 5).
 * Translated regions run with asynchronous host signals masked by the C
 * caller wherever the kernel allows.
 *
 * Never reads or writes the AArch64 platform register x18.
 *
 * Symbol spelling: L4B_ENTRY adds the Mach-O underscore on Apple hosts so
 * the same file links both into the Linux/ELF translator and directly into
 * the macOS host unit test (tests/check_thread_entry.c).
 */

#ifdef __APPLE__
#define L4B_ENTRY(x) _##x
#else
#define L4B_ENTRY(x) x
#endif

    .text
    .align 2

    /* Callee-saved save/restore shared by both entries (no x18 anywhere). */
    .macro THREAD_PROLOGUE
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!
    stp d8, d9, [sp, #-16]!
    stp d10, d11, [sp, #-16]!
    stp d12, d13, [sp, #-16]!
    stp d14, d15, [sp, #-16]!
    .endm

    .macro THREAD_EPILOGUE
    ldp d14, d15, [sp], #16
    ldp d12, d13, [sp], #16
    ldp d10, d11, [sp], #16
    ldp d8, d9, [sp], #16
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ldp x29, x30, [sp], #16
    ret
    .endm

    /* Core: x0 = ctx, x1 = entry, x27/x28 already installed by the entry
     * prologue. Reads x0-x3 without clobbering them before the blr. */
    .macro THREAD_CORE
    mov x19, x0
    ldr x20, [x0, #0x130]
    /* S32-R8-7: install the x25 prot-table base like the L2b trampoline
     * (trampoline_a64.S), so inline fast-path loads/stores can probe
     * [x25, wVpn, uxtw]. */
#ifdef __APPLE__
    adrp x25, _g_vm32_prot_jit@PAGE
    ldr x25, [x25, _g_vm32_prot_jit@PAGEOFF]
#else
    adrp x25, g_vm32_prot_jit
    ldr x25, [x25, #:lo12:g_vm32_prot_jit]
#endif
    msr nzcv, xzr
    mov x24, xzr
    blr x1
    str w16, [x19, #0x138]
    str w15, [x19, #0x144]
    ldr x2, [x19, #0x168]
    add x2, x2, x24
    str x2, [x19, #0x168]
    .endm

    .globl L4B_ENTRY(rt32_thread_enter_block)
L4B_ENTRY(rt32_thread_enter_block):
    THREAD_PROLOGUE
    /* x27 = chaining entry, x28 = live epoch word (chaining allowed). */
    mov x27, x2
    mov x28, x3
    THREAD_CORE
    THREAD_EPILOGUE

    .globl L4B_ENTRY(rt32_thread_enter_step)
L4B_ENTRY(rt32_thread_enter_step):
    THREAD_PROLOGUE
    /* Chaining disabled: x28 points at a stack-resident zero word, so every
     * epoch-gated chain probe bails and exactly one fragment executes. */
    sub sp, sp, #16
    str xzr, [sp]
    mov x28, sp
    mov x27, x2
    THREAD_CORE
    add sp, sp, #16
    THREAD_EPILOGUE
