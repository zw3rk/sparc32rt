/*
 * tests/test_h1_smc.c — Phase 7 (H1) self-modifying-code & W^X guest
 * (freestanding, V8-only).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Rewrites guest instructions on stack, heap, and anonymous-mmap pages
 * with an explicit mprotect +EXEC barrier before executing (the frozen
 * W^X contract: guest data pages are never host-EXEC; the mprotect is
 * the publish barrier, matching what real JITs do). Verifies the NEW
 * bytes run on qemu-sparc -cpu LEON3, --interp, and --dbt; then strips
 * EXEC and verifies all three engines fault (fetch-X, RC6 R1/R8) via a
 * guest SIGSEGV handler that exits 0 only on the expected fault.
 *
 * Covers: rewrite on an anonymous-mmap page (stale-block gate: execute
 * v1 so --dbt caches it, rewrite + barrier, re-execute must run v2),
 * self-patch of a later block of an already-executed function, a
 * cross-page rewrite (function straddling a page boundary; the
 * translator splits blocks at page edges), write-while-executing with
 * eventual-consistency assertions (10 alternating write+barrier cycles,
 * then 100 consecutive re-executions all running the new code, 0 stale
 * executions), rewrite on a stack page, rewrite on a heap (brk) page.
 *
 * Every rewrite is bracketed by mprotect (RW to write, RX to run), so
 * the existing vm_invalidate_jit hooks on the mprotect path (which
 * whole-cache flush the DBT: sparc32_dbt_invalidate_range) are the only
 * invalidation the gate needs; no emitter/store hook is required, and
 * none is added. A rewrite observed without its barrier would be a
 * stale-block FAIL, never silent success.
 *
 * Build (E-phase discipline):
 *   sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static \
 *     -o /tmp/test_h1_smc tests/test_h1_smc.c
 * Oracle: qemu-sparc -cpu LEON3 /tmp/test_h1_smc
 * Translator: sparc32rt --interp -- /tmp/test_h1_smc
 *             sparc32rt --dbt -- /tmp/test_h1_smc
 *
 * Pure top-level asm (no libc, no C runtime). E04 discipline:
 * snapshot-before-print, helpers clobber %o0-%o2, %g1, %g3, %g4 while
 * %g5-%g7 survive; live values otherwise sit in .bss words. Only V8
 * encodings (Bicc, no BPcc/BPr/membar/cas/popc/flushw). Large
 * immediates use `set`, never `mov`.
 */
__asm__(
"\t.text\n\t.align 4\n\t.global _start\n"
"_start:\n"
"\tsethi %hi(msg_start), %g2\nor %g2, %lo(msg_start), %g2\n\tcall puts\n\tnop\n"
/* --- Install the SIGSEGV probe handler first: any fault before the
 * final phase is unexpected and must FAIL, not hang. --- */
"\tsethi %hi(expfault), %g5\nor %g5, %lo(expfault), %g5\n\tmov 0, %g6\n\tst %g6, [%g5]\n"
"\tsethi %hi(act), %g5\nor %g5, %lo(act), %g5\n"
"\tsethi %hi(h_segv), %g6\nor %g6, %lo(h_segv), %g6\n\tst %g6, [%g5]\n"
"\tmov 0, %g6\n\tst %g6, [%g5 + 4]\n\tst %g6, [%g5 + 8]\n\tst %g6, [%g5 + 12]\n\tst %g6, [%g5 + 16]\n"
"\tmov 11, %o0\n\tmov %g5, %o1\n\tmov 0, %o2\n\tmov 0, %o3\n\tmov 8, %o4\n\tmov 102, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(msg_seg), %g2\nor %g2, %lo(msg_seg), %g2\n\tcall puts\n\tnop\n"
/* --- Phase A: mmap 3 pages RW; write funcA v1 (ret 0xA1). --- */
"\tmov 0, %o0\n\tset 12288, %o1\n\tmov 3, %o2\n\tmov 0x22, %o3\n\tsub %g0, 1, %o4\n\tmov 0, %o5\n\tmov 56, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tst %o0, [%g5]\n\tmov %o0, %g5\n"
"\tset 0x901020a1, %g6\n\tst %g6, [%g5]\n"
"\tset 0x81c3e008, %g6\n\tst %g6, [%g5 + 4]\n"
"\tset 0x01000000, %g6\n\tst %g6, [%g5 + 8]\n"
/* --- Barrier: publish RX, then execute v1. --- */
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %o0\n"
"\tset 12288, %o1\n\tmov 5, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, 0\n\tbne fail\n\tnop\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %g6\n"
"\tjmpl %g6, %o7\n\tnop\n"
"\tcmp %o0, 0xa1\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_mmap), %g2\nor %g2, %lo(msg_mmap), %g2\n\tcall puts\n\tnop\n"
/* --- Rewrite to v2 (ret 0xA2) through RW, re-publish RX, re-execute.
 * A stale cached block would still return 0xA1 and FAIL here. --- */
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %o0\n"
"\tset 12288, %o1\n\tmov 3, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %g5\n"
"\tset 0x901020a2, %g6\n\tst %g6, [%g5]\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %o0\n"
"\tset 12288, %o1\n\tmov 5, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %g6\n"
"\tjmpl %g6, %o7\n\tnop\n"
"\tcmp %o0, 0xa2\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_rewr), %g2\nor %g2, %lo(msg_rewr), %g2\n\tcall puts\n\tnop\n"
/* --- Phase D: self-patch a later block. funcD at A+8192: block1 sets
 * %o1 = 0xD0 (proves block1 ran), later block returns %o0 = X.
 * Execute once (both blocks translate), patch X, barrier, re-execute:
 * the later block must run new (stale X1 FAILs). --- */
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %g5\n"
"\tset 8192, %g6\n\tadd %g5, %g6, %g5\n"
"\tsethi %hi(saved_d), %g6\nor %g6, %lo(saved_d), %g6\n\tst %g5, [%g6]\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %o0\n"
"\tset 12288, %o1\n\tmov 3, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_d), %g5\nor %g5, %lo(saved_d), %g5\n\tld [%g5], %g5\n"
"\tset 0x921020d0, %g6\n\tst %g6, [%g5]\n"
"\tset 0x901020d1, %g6\n\tst %g6, [%g5 + 4]\n"
"\tset 0x81c3e008, %g6\n\tst %g6, [%g5 + 8]\n"
"\tset 0x01000000, %g6\n\tst %g6, [%g5 + 12]\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %o0\n"
"\tset 12288, %o1\n\tmov 5, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_d), %g5\nor %g5, %lo(saved_d), %g5\n\tld [%g5], %g6\n"
"\tjmpl %g6, %o7\n\tnop\n"
"\tcmp %o0, 0xd1\n\tbne fail\n\tnop\n"
"\tcmp %o1, 0xd0\n\tbne fail\n\tnop\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %o0\n"
"\tset 12288, %o1\n\tmov 3, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_d), %g5\nor %g5, %lo(saved_d), %g5\n\tld [%g5], %g5\n"
"\tset 0x901020d2, %g6\n\tst %g6, [%g5 + 4]\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %o0\n"
"\tset 12288, %o1\n\tmov 5, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_d), %g5\nor %g5, %lo(saved_d), %g5\n\tld [%g5], %g6\n"
"\tjmpl %g6, %o7\n\tnop\n"
"\tcmp %o0, 0xd2\n\tbne fail\n\tnop\n"
"\tcmp %o1, 0xd0\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_self), %g2\nor %g2, %lo(msg_self), %g2\n\tcall puts\n\tnop\n"
/* --- Phase E: cross-page rewrite. funcX: `or` at A+4092 (last word
 * of page 0), `retl`/`nop` at A+4096/+4100 (page 1). The translator
 * splits blocks at page edges; the barrier covers both pages. --- */
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %g5\n"
"\tset 4092, %g6\n\tadd %g5, %g6, %g5\n"
"\tsethi %hi(saved_x), %g6\nor %g6, %lo(saved_x), %g6\n\tst %g5, [%g6]\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %o0\n"
"\tset 12288, %o1\n\tmov 3, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_x), %g5\nor %g5, %lo(saved_x), %g5\n\tld [%g5], %g5\n"
"\tset 0x901020e1, %g6\n\tst %g6, [%g5]\n"
"\tset 0x81c3e008, %g6\n\tst %g6, [%g5 + 4]\n"
"\tset 0x01000000, %g6\n\tst %g6, [%g5 + 8]\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %o0\n"
"\tset 12288, %o1\n\tmov 5, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_x), %g5\nor %g5, %lo(saved_x), %g5\n\tld [%g5], %g6\n"
"\tjmpl %g6, %o7\n\tnop\n"
"\tcmp %o0, 0xe1\n\tbne fail\n\tnop\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %o0\n"
"\tset 12288, %o1\n\tmov 3, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_x), %g5\nor %g5, %lo(saved_x), %g5\n\tld [%g5], %g5\n"
"\tset 0x901020e2, %g6\n\tst %g6, [%g5]\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %o0\n"
"\tset 12288, %o1\n\tmov 5, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_x), %g5\nor %g5, %lo(saved_x), %g5\n\tld [%g5], %g6\n"
"\tjmpl %g6, %o7\n\tnop\n"
"\tcmp %o0, 0xe2\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_xpg), %g2\nor %g2, %lo(msg_xpg), %g2\n\tcall puts\n\tnop\n"
/* --- Phase F: write-while-executing, eventual consistency. 10
 * alternating write+barrier cycles (0xF1/0xF2), then one final
 * write+barrier (0xF3) followed by 100 consecutive executions that
 * must ALL run the new code (any stale execution FAILs). --- */
"\tsethi %hi(wwx_i), %g5\nor %g5, %lo(wwx_i), %g5\n\tmov 0, %g6\n\tst %g6, [%g5]\n"
"wwx_loop:\n"
"\tsethi %hi(wwx_i), %g5\nor %g5, %lo(wwx_i), %g5\n\tld [%g5], %g6\n"
"\tcmp %g6, 10\n\tbge wwx_final\n\tnop\n"
"\tandcc %g6, 1, %g0\n\tbz wwx_even\n\tnop\n"
"\tset 0x901020f2, %g6\n\tba wwx_have\n\tnop\n"
"wwx_even:\n"
"\tset 0x901020f1, %g6\n"
"wwx_have:\n"
"\tsethi %hi(wwx_w), %g5\nor %g5, %lo(wwx_w), %g5\n\tst %g6, [%g5]\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %o0\n"
"\tset 12288, %o1\n\tmov 3, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, 0\n\tbne fail\n\tnop\n"
"\tsethi %hi(wwx_w), %g5\nor %g5, %lo(wwx_w), %g5\n\tld [%g5], %g6\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %g5\n"
"\tst %g6, [%g5]\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %o0\n"
"\tset 12288, %o1\n\tmov 5, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, 0\n\tbne fail\n\tnop\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %g6\n"
"\tjmpl %g6, %o7\n\tnop\n"
"\tsethi %hi(wwx_i), %g5\nor %g5, %lo(wwx_i), %g5\n\tld [%g5], %g6\n"
"\tandcc %g6, 1, %g0\n\tbz wwx_xeven\n\tnop\n"
"\tcmp %o0, 0xf2\n\tbne fail\n\tnop\n\tba wwx_next\n\tnop\n"
"wwx_xeven:\n"
"\tcmp %o0, 0xf1\n\tbne fail\n\tnop\n"
"wwx_next:\n"
"\tsethi %hi(wwx_i), %g5\nor %g5, %lo(wwx_i), %g5\n\tld [%g5], %g6\n\tadd %g6, 1, %g6\n\tst %g6, [%g5]\n"
"\tba wwx_loop\n\tnop\n"
"wwx_final:\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %o0\n"
"\tset 12288, %o1\n\tmov 3, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %g5\n"
"\tset 0x901020f3, %g6\n\tst %g6, [%g5]\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %o0\n"
"\tset 12288, %o1\n\tmov 5, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(wwx_n), %g5\nor %g5, %lo(wwx_n), %g5\n\tmov 0, %g6\n\tst %g6, [%g5]\n"
"wwx100:\n"
"\tsethi %hi(wwx_n), %g5\nor %g5, %lo(wwx_n), %g5\n\tld [%g5], %g6\n"
"\tcmp %g6, 100\n\tbge wwx_done\n\tnop\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %g6\n"
"\tjmpl %g6, %o7\n\tnop\n"
"\tcmp %o0, 0xf3\n\tbne fail\n\tnop\n"
"\tsethi %hi(wwx_n), %g5\nor %g5, %lo(wwx_n), %g5\n\tld [%g5], %g6\n\tadd %g6, 1, %g6\n\tst %g6, [%g5]\n"
"\tba wwx100\n\tnop\n"
"wwx_done:\n"
"\tsethi %hi(wwx_n), %g5\nor %g5, %lo(wwx_n), %g5\n\tld [%g5], %g6\n"
"\tcmp %g6, 100\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_wwx), %g2\nor %g2, %lo(msg_wwx), %g2\n\tcall puts\n\tnop\n"
/* --- Phase B: stack page. Scratch buffer 16 KiB below %sp (the stack
 * mapping is 8 MiB); the buffer page alone goes RX while it runs, so
 * no stack access may happen inside the RX window (leaf code only,
 * no SAVE, no spills). Restored to RW afterwards. --- */
"\tmov %sp, %g6\n"
"\tset 16384, %g4\n\tsub %g6, %g4, %g6\n"
"\tandn %g6, 0xfff, %g6\n"
"\tsethi %hi(saved_spage), %g5\nor %g5, %lo(saved_spage), %g5\n\tst %g6, [%g5]\n"
"\tadd %g6, 2048, %g6\n"
"\tsethi %hi(saved_s), %g5\nor %g5, %lo(saved_s), %g5\n\tst %g6, [%g5]\n"
"\tsethi %hi(saved_s), %g5\nor %g5, %lo(saved_s), %g5\n\tld [%g5], %g5\n"
"\tset 0x901020b1, %g6\n\tst %g6, [%g5]\n"
"\tset 0x81c3e008, %g6\n\tst %g6, [%g5 + 4]\n"
"\tset 0x01000000, %g6\n\tst %g6, [%g5 + 8]\n"
"\tsethi %hi(saved_spage), %g5\nor %g5, %lo(saved_spage), %g5\n\tld [%g5], %o0\n"
"\tset 4096, %o1\n\tmov 5, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, 0\n\tbne fail\n\tnop\n"
"\tsethi %hi(saved_s), %g5\nor %g5, %lo(saved_s), %g5\n\tld [%g5], %g6\n"
"\tjmpl %g6, %o7\n\tnop\n"
"\tcmp %o0, 0xb1\n\tbne fail\n\tnop\n"
"\tsethi %hi(saved_spage), %g5\nor %g5, %lo(saved_spage), %g5\n\tld [%g5], %o0\n"
"\tset 4096, %o1\n\tmov 3, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_s), %g5\nor %g5, %lo(saved_s), %g5\n\tld [%g5], %g5\n"
"\tset 0x901020b2, %g6\n\tst %g6, [%g5]\n"
"\tsethi %hi(saved_spage), %g5\nor %g5, %lo(saved_spage), %g5\n\tld [%g5], %o0\n"
"\tset 4096, %o1\n\tmov 5, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_s), %g5\nor %g5, %lo(saved_s), %g5\n\tld [%g5], %g6\n"
"\tjmpl %g6, %o7\n\tnop\n"
"\tcmp %o0, 0xb2\n\tbne fail\n\tnop\n"
"\tsethi %hi(saved_spage), %g5\nor %g5, %lo(saved_spage), %g5\n\tld [%g5], %o0\n"
"\tset 4096, %o1\n\tmov 3, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(msg_stack), %g2\nor %g2, %lo(msg_stack), %g2\n\tcall puts\n\tnop\n"
/* --- Phase C: heap (brk) page. Grow by 8192, take the first new
 * page, same write/barrier/run/rewrite cycle (0xC1/0xC2). --- */
"\tmov 0, %o0\n\tmov 17, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_h0), %g5\nor %g5, %lo(saved_h0), %g5\n\tst %o0, [%g5]\n\tmov %o0, %g6\n"
"\tset 8192, %g4\n\tadd %g6, %g4, %o0\n\tmov 17, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_h0), %g5\nor %g5, %lo(saved_h0), %g5\n\tld [%g5], %g6\n"
"\tset 4095, %g4\n\tadd %g6, %g4, %g6\n"
"\tandn %g6, 0xfff, %g6\n"
"\tsethi %hi(saved_hb), %g5\nor %g5, %lo(saved_hb), %g5\n\tst %g6, [%g5]\n"
"\tsethi %hi(saved_hb), %g5\nor %g5, %lo(saved_hb), %g5\n\tld [%g5], %g5\n"
"\tset 0x901020c1, %g6\n\tst %g6, [%g5]\n"
"\tset 0x81c3e008, %g6\n\tst %g6, [%g5 + 4]\n"
"\tset 0x01000000, %g6\n\tst %g6, [%g5 + 8]\n"
"\tsethi %hi(saved_hb), %g5\nor %g5, %lo(saved_hb), %g5\n\tld [%g5], %o0\n"
"\tset 4096, %o1\n\tmov 5, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, 0\n\tbne fail\n\tnop\n"
"\tsethi %hi(saved_hb), %g5\nor %g5, %lo(saved_hb), %g5\n\tld [%g5], %g6\n"
"\tjmpl %g6, %o7\n\tnop\n"
"\tcmp %o0, 0xc1\n\tbne fail\n\tnop\n"
"\tsethi %hi(saved_hb), %g5\nor %g5, %lo(saved_hb), %g5\n\tld [%g5], %o0\n"
"\tset 4096, %o1\n\tmov 3, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_hb), %g5\nor %g5, %lo(saved_hb), %g5\n\tld [%g5], %g5\n"
"\tset 0x901020c2, %g6\n\tst %g6, [%g5]\n"
"\tsethi %hi(saved_hb), %g5\nor %g5, %lo(saved_hb), %g5\n\tld [%g5], %o0\n"
"\tset 4096, %o1\n\tmov 5, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_hb), %g5\nor %g5, %lo(saved_hb), %g5\n\tld [%g5], %g6\n"
"\tjmpl %g6, %o7\n\tnop\n"
"\tcmp %o0, 0xc2\n\tbne fail\n\tnop\n"
"\tsethi %hi(saved_hb), %g5\nor %g5, %lo(saved_hb), %g5\n\tld [%g5], %o0\n"
"\tset 4096, %o1\n\tmov 3, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(msg_heap), %g2\nor %g2, %lo(msg_heap), %g2\n\tcall puts\n\tnop\n"
/* --- Phase G: strip EXEC from page A and jump in. All three engines
 * must fault (fetch-X); the handler prints PASS and exits 0. --- */
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %o0\n"
"\tset 4096, %o1\n\tmov 3, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(expfault), %g5\nor %g5, %lo(expfault), %g5\n\tmov 1, %g6\n\tst %g6, [%g5]\n"
"\tsethi %hi(msg_probe), %g2\nor %g2, %lo(msg_probe), %g2\n\tcall puts\n\tnop\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %g6\n"
"\tjmpl %g6, %o7\n\tnop\n"
"\tba fail\n\tnop\n"
/* --- SIGSEGV probe handler: snapshots signo, then decides. Only the
 * armed phase-G fault may pass, and only with signo 11. --- */
"h_segv:\n"
"\tsethi %hi(snap_segv), %g3\nor %g3, %lo(snap_segv), %g3\n\tst %o0, [%g3]\n"
"\tsethi %hi(expfault), %g3\nor %g3, %lo(expfault), %g3\n\tld [%g3], %g3\n"
"\ttst %g3\n\tbz seg_unexp\n\tnop\n"
"\tsethi %hi(snap_segv), %g3\nor %g3, %lo(snap_segv), %g3\n\tld [%g3], %g3\n"
"\tcmp %g3, 11\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_fault), %g2\nor %g2, %lo(msg_fault), %g2\n\tcall puts\n\tnop\n"
"\tsethi %hi(msg_pass), %g2\nor %g2, %lo(msg_pass), %g2\n\tcall puts\n\tnop\n"
"\tmov 0, %o0\n\tmov 1, %g1\n\tta 0x10\n"
"seg_unexp:\n"
"\tsethi %hi(msg_unexp), %g2\nor %g2, %lo(msg_unexp), %g2\n\tcall puts\n\tnop\n"
"fail:\n"
"\tsethi %hi(msg_fail), %g2\nor %g2, %lo(msg_fail), %g2\n\tcall puts\n\tnop\n"
"\tmov 1, %o0\n\tmov 1, %g1\n\tta 0x10\n"
/* --- helpers (leaf calls; clobber o0-o2,g1,g3,g4; g5-g7 survive). --- */
"puts:\n\tmov %g2, %g4\n"
"1:\n\tldub [%g4], %g3\n\ttst %g3\n\tbz 2f\n\tadd %g4, 1, %g4\n\tba 1b\n\tnop\n"
"2:\n\tsub %g4, %g2, %o2\n\tmov %g2, %o1\n\tmov 1, %o0\n\tmov 4, %g1\n\tta 0x10\n\tretl\n\tnop\n"
"\t.data\n\t.align 4\n"
"msg_start:\n\t.asciz \"H1-SMC start\\n\"\n"
"msg_seg:\n\t.asciz \"segsig ok\\n\"\n"
"msg_mmap:\n\t.asciz \"mmap ok\\n\"\n"
"msg_rewr:\n\t.asciz \"rewrite ok\\n\"\n"
"msg_self:\n\t.asciz \"selfpatch ok\\n\"\n"
"msg_xpg:\n\t.asciz \"xpage ok\\n\"\n"
"msg_wwx:\n\t.asciz \"wwx 100/100\\n\"\n"
"msg_stack:\n\t.asciz \"stack ok\\n\"\n"
"msg_heap:\n\t.asciz \"heap ok\\n\"\n"
"msg_probe:\n\t.asciz \"fault-probe\\n\"\n"
"msg_fault:\n\t.asciz \"fault ok\\n\"\n"
"msg_pass:\n\t.asciz \"H1-SMC-PASS\\n\"\n"
"msg_unexp:\n\t.asciz \"UNEXPECTED-FAULT\\n\"\n"
"msg_fail:\n\t.asciz \"H1-SMC-FAIL\\n\"\n"
"\t.bss\n\t.align 4\n"
"saved_a:\n\t.skip 4\n"
"saved_d:\n\t.skip 4\n"
"saved_x:\n\t.skip 4\n"
"saved_s:\n\t.skip 4\n"
"saved_spage:\n\t.skip 4\n"
"saved_h0:\n\t.skip 4\n"
"saved_hb:\n\t.skip 4\n"
"wwx_i:\n\t.skip 4\n"
"wwx_n:\n\t.skip 4\n"
"wwx_w:\n\t.skip 4\n"
"act:\n\t.skip 20\n"
"expfault:\n\t.skip 4\n"
"snap_segv:\n\t.skip 4\n"
);
