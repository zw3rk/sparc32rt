/*
 * src/dbt/trampoline_a64.S — DBT enter/exit trampoline (AArch64)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 2 lane L2b (SPEC sections 2-3). Enters translated code with the
 * Class-A window base in x20 (xG) and the ctx pointer in x19, so
 * emitted fragments address guest memory as [x20, wAddr, uxtw].
 *
 * Register contract (matches src/rt32/a64_emit.h and src/dbt/emit_int.h):
 *   x0 = ctx, x1 = entry (host RX address in the DBT code arena),
 *   x2 = chaining entry for x27 (dbt.c slots, NULL bails to C),
 *   x3 = epoch word for x28 (&g_cache_epoch to allow chaining).
 * Every emitted exit returns via `ret` with the resume/fault guest PC
 * in w15 and the SPARC32_EXIT_* reason in w16; the trampoline stores
 * w16 -> ctx->exit_reason (0x138) and w15 -> ctx->exit_dest (0x144),
 * folds the in-fragment chain_hits delta (x24) into ctx, and returns to
 * the C dispatcher, which commits pc/npc from the exit. dbt_enter_step
 * points x28 at a zero epoch word instead, so every epoch-gated chain
 * probe (slots, self-loop, RAS-pop, IBTC-hit) deterministically bails
 * and exactly one guest instruction executes (difftest lockstep).
 *
 * Never reads or writes the AArch64 platform register x18.
 * Assembled only by an AArch64 toolchain; the C dispatcher (dbt.c)
 * calls dbt_enter_block/dbt_enter_step and reads back ctx state.
 */

    .text
    .arch armv8-a
    .align 2

/* Shared tail: x0 = ctx, x1 = entry, x27/x28 already set by the entry
 * prologue that branched here. */
.Ldbt_enter_go:
    /* x19 = ctx (xCtx), x20 = G (xG) for [x20, wAddr, uxtw] access. */
    mov x19, x0
    ldr x20, [x0, #0x130]

    /* P13-4: x25 = g_vm32_prot base (callee-saved, preserved by every
     * C helper per AAPCS64), so inline loads/stores probe the per-4K
     * prot table with one LDRB [x25, wVpn, uxtw] (never x18). */
#ifdef __APPLE__
    adrp x25, _g_vm32_prot_jit@PAGE
    ldr x25, [x25, _g_vm32_prot_jit@PAGEOFF]
#else
    adrp x25, g_vm32_prot_jit
    ldr x25, [x25, #:lo12:g_vm32_prot_jit]
#endif

    /* Zero the in-trampoline chain_hits delta (x24 per a64_emit.h). */
    mov x24, xzr

    /* Enter translated code; fragments return here via `ret`. */
    blr x1
    str x27, [x19, #0x170]

    /* Commit the exit: w16 -> exit_reason, w15 -> exit_dest. */
    str w16, [x19, #0x138]
    str w15, [x19, #0x144]
    /* Fold the in-fragment chain_hits delta into ctx. */
    ldr x2, [x19, #0x168]
    add x2, x2, x24
    str x2, [x19, #0x168]

    /* Epilogue: restore and return to the C dispatcher. */
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

/* Prologue shared by both entries: save fp/lr + callee-saved pairs
 * (no x18 anywhere), then install x27/x28 and join the shared tail. */
    .macro DBT_ENTER_PROLOGUE
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

#ifdef __APPLE__
    .globl _dbt_enter_block
_dbt_enter_block:
#else
    .globl dbt_enter_block
    .type dbt_enter_block, %function
#endif
dbt_enter_block:
    DBT_ENTER_PROLOGUE
    /* x27 = chaining entry, x28 = live epoch word (chaining allowed). */
    mov x27, x2
    mov x28, x3
    b .Ldbt_enter_go
#ifndef __APPLE__
    .size dbt_enter_block, .-dbt_enter_block
#endif

#ifdef __APPLE__
    .globl _dbt_enter_step
_dbt_enter_step:
#else
    .globl dbt_enter_step
    .type dbt_enter_step, %function
#endif
dbt_enter_step:
    DBT_ENTER_PROLOGUE
    /* x27 = chaining entry (slots NULL, probes bail); x28 = zero epoch
     * word so every epoch-gated chain probe bails: single execution. */
    mov x27, x2
    adr x28, .Ldbt_zero_epoch
    b .Ldbt_enter_go
#ifndef __APPLE__
    .size dbt_enter_step, .-dbt_enter_step
#endif

    .align 2
.Ldbt_zero_epoch:
    .word 0

/*
 * Chain-tail helper for emitted indirect exits: x0 = ctx, x1 = guest
 * target PC in w1. Probes the ctx IBTC (SPARC32_IBTC_SIZE entries of 32
 * bytes at 0x990, hash (pc >> 2) & (size - 1)) and branches to the
 * cached host entry when the key matches, else returns to C with
 * EXIT_BRANCH/exit_dest set. Leaf routine: uses only caller-saved
 * temporaries (x2-x5); x18 untouched.
 */
    .align 2
#ifdef __APPLE__
    .globl _dbt_ibtc_tail
_dbt_ibtc_tail:
#else
    .globl dbt_ibtc_tail
    .type dbt_ibtc_tail, %function
#endif
dbt_ibtc_tail:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    /* idx = (w1 >> 2) & (SPARC32_IBTC_SIZE - 1); entry = 0x990 + idx*32. */
    lsr w2, w1, #2
    and w2, w2, #1023
    lsl x2, x2, #5
    add x2, x0, x2
    add x2, x2, #0x990
    /* Compare key (entry + 0); miss -> EXIT_BRANCH to dispatcher. */
    ldr w3, [x2, #0]
    cmp w3, w1
    b.ne .Lmiss
    ldr x4, [x2, #8]
    cbz x4, .Lmiss
    ldp x29, x30, [sp], #16
    br x4
.Lmiss:
    mov w3, #1
    str w3, [x0, #0x138]
    str w1, [x0, #0x144]
    ldp x29, x30, [sp], #16
    ret
#ifndef __APPLE__
    .size dbt_ibtc_tail, .-dbt_ibtc_tail
#endif
