/*
 * tests/test_p5_interp.c — Synthetic PT_INTERP interpreter probe (ET_DYN).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Freestanding V8-only probe linked ET_DYN; named by the app's
 * PT_INTERP path (/tmp/sparc32rt-p5interp). Reads the one initial stack
 * (argc at %sp+64), asserts AT_BASE(7) != 0 and AT_ENTRY(9) != 0, touches
 * AT_PHDR(3) (both images must be mapped or this faults), prints
 * "interp-first", then jumps to the app entry with stack and windows
 * untouched. Expected stdout with the companion app: exactly
 * "interp-first\napp-ran\n", exit 0, on qemu-sparc -cpu LEON3, --interp
 * and --dbt alike (no addresses are printed).
 *
 * POSITION INDEPENDENCE: the translator's loader applies no dynamic
 * relocations, and the probe must run at any load bias (0x3F000000+ on
 * the translator, anywhere on qemu). Therefore EVERYTHING (code and
 * strings) lives in .text, scratch state lives in %l registers, and all
 * addresses derive from the PC captured at entry plus same-section
 * symbol differences (link-time constants, no dynamic relocs; verify
 * with `readelf -r`: no R_SPARC_* entries). There are no .data/.bss
 * references at all.
 *
 * Build (inside the sparc32rt-oracle container):
 *   sparc64-linux-gnu-gcc -m32 -nostdlib -shared -Wl,-e,_start \
 *     -o /tmp/sparc32rt-p5interp tests/test_p5_interp.c
 * Verify: readelf -h shows ET_DYN, EM_SPARC, e_flags 0, no PT_INTERP;
 * readelf -r shows no relocations.
 *
 * Pure top-level asm, V8 encodings only. Comparisons use Z/N only:
 * unsigned branches after SUBcc read the C bit, whose convention
 * differs across engines (oracle says borrow), so small-positive
 * comparisons use Z/N, which coincide with unsigned ones under 2^31.
 */
__asm__(
"\t.text\n\t.align 4\n\t.global _start\n"
"_start:\n"
/* Capture PC: after `call`, %o7 holds this insn's address == _start. */
"\tcall 1f\n\tnop\n"
"1:\n\tmov %o7, %l0\n"
/* --- argc base: sp+64 preferred (qemu + translator layout) --- */
"\tld [%sp + 64], %g5\n"
"\tsub %g5, 1, %g4\n\tsrl %g4, 9, %g4\n\ttst %g4\n\tbnz try_sp\n\tnop\n"
"\tadd %sp, 64, %l1\n\tba base_ok\n\tnop\n"
"try_sp:\n"
"\tld [%sp], %g5\n"
"\tsub %g5, 1, %g4\n\tsrl %g4, 9, %g4\n\ttst %g4\n\tbnz fail\n\tnop\n"
"\tmov %sp, %l1\n"
"base_ok:\n"
/* --- walk envp -> auxv; scan ENTRY/BASE/PHDR --- */
"\tld [%l1], %g5\n"
"\tsub %g5, 1, %g4\n\tsrl %g4, 9, %g4\n\ttst %g4\n\tbnz fail\n\tnop\n"
"\tadd %g5, 1, %g5\n\tsll %g5, 2, %g5\n\tadd %l1, %g5, %l2\n\tadd %l2, 4, %l2\n"
"\tmov 2048, %l3\n"
"env_loop:\n"
"\tsubcc %l3, 1, %l3\n\tbz fail\n\tnop\n"
"\tld [%l2], %g5\n\ttst %g5\n\tbnz env_next\n\tnop\n\tba aux_go\n\tnop\n"
"env_next:\n\tadd %l2, 4, %l2\n\tba env_loop\n\tnop\n"
"aux_go:\n\tadd %l2, 4, %l2\n\tmov 48, %l3\n"
"tag_loop:\n"
"\tsubcc %l3, 1, %l3\n\tbz fail\n\tnop\n"
"\tld [%l2], %g2\n\ttst %g2\n\tbz tag_done\n\tnop\n"
"\tld [%l2 + 4], %g5\n"
"\tcmp %g2, 9\n\tbne t_not9\n\tnop\n\tmov %g5, %l4\n\tba tag_next\n\tnop\n"
"t_not9:\n\tcmp %g2, 7\n\tbne t_not7\n\tnop\n\tmov %g5, %l5\n\tba tag_next\n\tnop\n"
"t_not7:\n\tcmp %g2, 3\n\tbne tag_next\n\tnop\n\tmov %g5, %l6\n"
"tag_next:\n\tadd %l2, 8, %l2\n\tba tag_loop\n\tnop\n"
"tag_done:\n"
/* --- AT_BASE must be set, AT_ENTRY nonzero, PHDR mapped --- */
"\ttst %l5\n\tbz fail\n\tnop\n"
"\ttst %l4\n\tbz fail\n\tnop\n"
"\ttst %l6\n\tbz fail\n\tnop\n"
"\tld [%l6], %g0\n"
"\tadd %l0, (m_first - _start), %g2\n\tcall puts\n\tnop\n"
/* --- jump to the app entry; stack and windows untouched --- */
"\tmov %l4, %g2\n"
"\tjmpl %g2, %g0\n\tnop\n"
"fail:\n"
"\tadd %l0, (m_fail - _start), %g2\n\tcall puts\n\tnop\n"
"\tmov 1, %o0\n\tmov 1, %g1\n\tta 0x10\n"
"puts:\n\tmov %g2, %g4\n"
"1:\n\tldub [%g4], %g3\n\ttst %g3\n\tbz 2f\n\tnop\n\tadd %g4, 1, %g4\n\tba 1b\n\tnop\n"
"2:\n\tsub %g4, %g2, %o2\n\tmov %g2, %o1\n\tmov 1, %o0\n\tmov 4, %g1\n\tta 0x10\n\tretl\n\tnop\n"
"m_first:\n\t.asciz \"interp-first\\n\"\n"
"m_fail:\n\t.asciz \"interp-FAIL\\n\"\n"
);
