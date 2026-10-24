/*
 * tests/test_h3_coremark.c — Phase 7 (H3) freestanding SPARC V8 throughput guest.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * CoreMark-flavoured integer workload for the H3 6-step perf loop:
 * per pass over a 256-word array it runs an LCG-equivalent fill
 * (xorshift32: sll/srl/xor only), an insertion sort (branches +
 * loads/stores), a bitwise CRC16-CCITT (poly 0x1021) over all 1024
 * bytes, and an 8-state transition walk with per-state counters.
 * ITERS passes execute between two clock_gettime(CLOCK_MONOTONIC)
 * timestamps (SPARC nr 257); the guest prints the deterministic
 * checksum plus the four raw 32-bit words of each stamp buffer so
 * the host can derive elapsed time. Layout differs by platform
 * (qemu/kernel sparc32 timespec: sec at w0, nsec at w1; the
 * translator's l2a 16-byte __kernel_timespec: sec at w1, nsec at
 * w2); the host parser selects fields per runner. Deterministic
 * stdout (checksum + PASS) must be byte-identical on
 * qemu-sparc -cpu LEON3, --interp and --dbt; the stamp words vary
 * run to run and are parsed, not diffed.
 *
 * Build (E-phase discipline):
 *   sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static \
 *     -o /tmp/h3 tests/test_h3_coremark.c
 * Oracle: qemu-sparc -cpu LEON3 /tmp/h3  (exit 0, deterministic stdout)
 *
 * Pure top-level asm (no libc, no C runtime). E04 discipline:
 * helpers (puts/puthex/putc/putnl) clobber %o0-%o2, %g1, %g3, %g4;
 * %g2/%g5/%g6/%g7 survive; pointers are reloaded after helper calls.
 * V8 purity: Bicc mnemonics only (no BPcc), no mul/div, no %y,
 * no windows, no CASA; every immediate fits simm13 or is built
 * with sethi (set).
 */
__asm__(
"	.text\n	.align 4\n	.global _start\n"
"	.equ H3_ITERS, 1000\n"
"	.equ H3_N, 256\n"
"_start:\n"
"	sethi %hi(msg_start), %g2\nor %g2, %lo(msg_start), %g2\n	call puts\n	nop\n"
/* --- t0 = clock_gettime(MONOTONIC=1, t0buf); nr 257 --- */
"	mov 1, %o0\n"
"	sethi %hi(t0buf), %g2\nor %g2, %lo(t0buf), %g2\n	mov %g2, %o1\n"
"	mov 257, %g1\n	ta 0x10\n	bcs fail\n	nop\n"
/* --- outer pass loop (counter lives in pass_idx memory) --- */
"pass_loop:\n"
/* --- phase 1: xorshift32 fill of arr[0..255]; x in %g4, ptr %g6, left %g5 --- */
"	sethi %hi(seed0), %g3\nor %g3, %lo(seed0), %g3\n	ld [%g3], %g4\n"
"	sethi %hi(arr), %g6\nor %g6, %lo(arr), %g6\n"
"	set H3_N, %g5\n"
"fill_loop:\n"
"	sll %g4, 13, %g3\n	xor %g4, %g3, %g4\n"
"	srl %g4, 17, %g3\n	xor %g4, %g3, %g4\n"
"	sll %g4, 5, %g3\n	xor %g4, %g3, %g4\n"
"	st %g4, [%g6]\n	add %g6, 4, %g6\n"
"	subcc %g5, 1, %g5\n	bnz fill_loop\n	nop\n"
/* --- phase 2: insertion sort ascending; base %g6, i %g3, key %g4 --- */
"	sethi %hi(arr), %g6\nor %g6, %lo(arr), %g6\n"
"	mov 1, %g3\n"
"sort_outer:\n"
"	sll %g3, 2, %g4\n	add %g6, %g4, %g4\n	ld [%g4], %g4\n"
"	mov %g3, %g5\n"
"sort_inner:\n"
"	cmp %g5, 0\n	ble sort_next\n	nop\n"
"	sll %g5, 2, %g7\n	add %g6, %g7, %g7\n	ld [%g7 - 4], %g1\n"
"	cmp %g1, %g4\n	ble sort_next\n	nop\n"
"	st %g1, [%g7]\n	sub %g5, 1, %g5\n	ba sort_inner\n	nop\n"
"sort_next:\n"
"	sll %g5, 2, %g7\n	add %g6, %g7, %g7\n	st %g4, [%g7]\n"
"	add %g3, 1, %g3\n	cmp %g3, H3_N\n	bl sort_outer\n	nop\n"
/* --- phase 3: bitwise CRC16-CCITT over 1024 bytes; crc %g4=0xFFFF --- */
/* (mask lives in %g6, byte/bit counters in %o4/%o5: helpers never run
   inside the loops, so %o3-%o5 are scratch here) */
"	set 0xffff, %g4\n"
"	set 0x10000, %g6\n"
"	sethi %hi(arr), %g3\nor %g3, %lo(arr), %g3\n"
"	set 1024, %g5\n"
"	set 0x1021, %g1\n"
"crc_word_top:\n"
"	ld [%g3], %g2\n	add %g3, 4, %g3\n	mov 4, %o4\n"
"crc_byte:\n"
"	srl %g2, 24, %g7\n	sll %g2, 8, %g2\n"
"	sll %g7, 8, %g7\n	xor %g4, %g7, %g4\n"
"	mov 8, %o5\n"
"crc_bit:\n"
"	sll %g4, 1, %g4\n"
"	andcc %g4, %g6, %g0\n	bz crc_nopoly\n	nop\n"
"	xor %g4, %g1, %g4\n"
"crc_nopoly:\n"
"	subcc %o5, 1, %o5\n	bnz crc_bit\n	nop\n"
"	subcc %o4, 1, %o4\n	bnz crc_byte\n	nop\n"
"	subcc %g5, 4, %g5\n	bnz crc_word_top\n	nop\n"
"	set 0xffff, %g7\n	and %g4, %g7, %g4\n"
"	sethi %hi(cksum), %g3\nor %g3, %lo(cksum), %g3\n	st %g4, [%g3]\n"
);
__asm__(
/* --- phase 4: 8-state walk; state %g2=0, base %g6, cnt base in %g7 --- */
"	mov %g0, %g2\n"
"	sethi %hi(arr), %g6\nor %g6, %lo(arr), %g6\n"
"	sethi %hi(cnt), %g7\nor %g7, %lo(cnt), %g7\n"
"	mov %g0, %g3\n"
"walk_loop:\n"
"	sll %g3, 2, %g4\n	add %g6, %g4, %g4\n	ld [%g4], %g4\n"
"	and %g4, 7, %g5\n	add %g2, %g5, %g2\n"
"	srl %g4, 29, %g5\n	add %g2, %g5, %g2\n"
"	and %g2, 7, %g2\n"
"	sll %g2, 2, %g5\n	add %g7, %g5, %g5\n"
"	ld [%g5], %g4\n	add %g4, 1, %g4\n	st %g4, [%g5]\n"
"	add %g3, 1, %g3\n	cmp %g3, H3_N\n	bl walk_loop\n	nop\n"
/* --- fold: cksum ^= state; passes++ --- */
"	sethi %hi(cksum), %g3\nor %g3, %lo(cksum), %g3\n"
"	ld [%g3], %g4\n	xor %g4, %g2, %g4\n	st %g4, [%g3]\n"
"	sethi %hi(passes), %g3\nor %g3, %lo(passes), %g3\n"
"	ld [%g3], %g4\n	add %g4, 1, %g4\n	st %g4, [%g3]\n"
/* --- next pass --- */
"	sethi %hi(pass_idx), %g3\nor %g3, %lo(pass_idx), %g3\n"
"	ld [%g3], %g5\n	add %g5, 1, %g5\n	st %g5, [%g3]\n"
"	set H3_ITERS, %g7\n	cmp %g5, %g7\n	bl pass_loop\n	nop\n"
/* --- self-checks: pass_idx == ITERS, cksum != 0 --- */
"	set H3_ITERS, %g7\n	cmp %g5, %g7\n	bne fail\n	nop\n"
"	sethi %hi(cksum), %g3\nor %g3, %lo(cksum), %g3\n"
"	ld [%g3], %g4\n	cmp %g4, 0\n	be fail\n	nop\n"
/* --- t1 = clock_gettime(MONOTONIC=1, t1buf) --- */
"	mov 1, %o0\n"
"	sethi %hi(t1buf), %g2\nor %g2, %lo(t1buf), %g2\n	mov %g2, %o1\n"
"	mov 257, %g1\n	ta 0x10\n	bcs fail\n	nop\n"
/* --- report: deterministic part first --- */
"	sethi %hi(msg_iters), %g2\nor %g2, %lo(msg_iters), %g2\n	call puts\n	nop\n"
"	sethi %hi(passes), %g6\nor %g6, %lo(passes), %g6\n"
"	ld [%g6], %g2\n	call puthex\n	nop\n"
"	sethi %hi(msg_crc), %g2\nor %g2, %lo(msg_crc), %g2\n	call puts\n	nop\n"
"	sethi %hi(cksum), %g6\nor %g6, %lo(cksum), %g6\n"
"	ld [%g6], %g2\n	call puthex\n	nop\n"
"	sethi %hi(msg_t0), %g2\nor %g2, %lo(msg_t0), %g2\n	call puts\n	nop\n"
"	sethi %hi(t0buf), %g6\nor %g6, %lo(t0buf), %g6\n"
"	ld [%g6], %g2\n	call puthex\n	nop\n"
"	mov ' ', %g2\n	call putc\n	nop\n"
"	sethi %hi(t0buf), %g6\nor %g6, %lo(t0buf), %g6\n"
"	ld [%g6 + 4], %g2\n	call puthex\n	nop\n"
"	mov ' ', %g2\n	call putc\n	nop\n"
"	sethi %hi(t0buf), %g6\nor %g6, %lo(t0buf), %g6\n"
"	ld [%g6 + 8], %g2\n	call puthex\n	nop\n"
"	mov ' ', %g2\n	call putc\n	nop\n"
"	sethi %hi(t0buf), %g6\nor %g6, %lo(t0buf), %g6\n"
"	ld [%g6 + 12], %g2\n	call puthex\n	nop\n"
"	sethi %hi(msg_t1), %g2\nor %g2, %lo(msg_t1), %g2\n	call puts\n	nop\n"
"	sethi %hi(t1buf), %g6\nor %g6, %lo(t1buf), %g6\n"
"	ld [%g6], %g2\n	call puthex\n	nop\n"
"	mov ' ', %g2\n	call putc\n	nop\n"
"	sethi %hi(t1buf), %g6\nor %g6, %lo(t1buf), %g6\n"
"	ld [%g6 + 4], %g2\n	call puthex\n	nop\n"
"	mov ' ', %g2\n	call putc\n	nop\n"
"	sethi %hi(t1buf), %g6\nor %g6, %lo(t1buf), %g6\n"
"	ld [%g6 + 8], %g2\n	call puthex\n	nop\n"
"	mov ' ', %g2\n	call putc\n	nop\n"
"	sethi %hi(t1buf), %g6\nor %g6, %lo(t1buf), %g6\n"
"	ld [%g6 + 12], %g2\n	call puthex\n	nop\n"
"	sethi %hi(msg_pass), %g2\nor %g2, %lo(msg_pass), %g2\n	call puts\n	nop\n"
"	mov 0, %o0\n	mov 1, %g1\n	ta 0x10\n"
"fail:\n"
"	sethi %hi(msg_fail), %g2\nor %g2, %lo(msg_fail), %g2\n	call puts\n	nop\n"
"	mov 1, %o0\n	mov 1, %g1\n	ta 0x10\n"
);
__asm__(
"	! ---------- helpers (E01 discipline; %g6 = value for puthex) ----------\n"
"puts:\n	mov %g2, %g4\n"
"1:\n	ldub [%g4], %g3\n	tst %g3\n	bz 2f\n	add %g4, 1, %g4\n	ba 1b\n	nop\n"
"2:\n	sub %g4, %g2, %o2\n	mov %g2, %o1\n	mov 1, %o0\n	mov 4, %g1\n	ta 0x10\n	retl\n	nop\n"
"puthex:\n	sethi %hi(hexbuf), %g3\nor %g3, %lo(hexbuf), %g3\n	mov 28, %o2\n"
"1:\n	srl %g2, %o2, %g4\n	and %g4, 0xf, %g4\n	cmp %g4, 10\n	bl 2f\n	nop\n"
"	add %g4, 'a' - 10, %g4\n	ba 3f\n	nop\n"
"2:\n	add %g4, '0', %g4\n"
"3:\n	stb %g4, [%g3]\n	add %g3, 1, %g3\n	subcc %o2, 4, %o2\n	bge 1b\n	nop\n"
"	sethi %hi(hexbuf), %o1\nor %o1, %lo(hexbuf), %o1\n"
"	mov 1, %o0\n	mov 8, %o2\n	mov 4, %g1\n	ta 0x10\n	retl\n	nop\n"
"putc:\n	sethi %hi(charbuf), %g3\nor %g3, %lo(charbuf), %g3\n	stb %g2, [%g3]\n"
"	mov 1, %o0\n mov %g3, %o1\n	mov 1, %o2\n	mov 4, %g1\n	ta 0x10\n	retl\n	nop\n"
"	.data\n	.align 4\n"
"msg_start:\n	.asciz \"H3-COREMARK start\\n\"\n"
"msg_iters:\n	.asciz \"iters \"\n"
"msg_crc:\n	.asciz \" crc \"\n"
"msg_t0:\n	.asciz \" t0 \"\n"
"msg_t1:\n	.asciz \" t1 \"\n"
"msg_pass:\n	.asciz \"\\nH3-COREMARK-PASS\\n\"\n"
"msg_fail:\n	.asciz \"H3-COREMARK-FAIL\\n\"\n"
"	.align 4\n"
"seed0:\n	.word 0x12345678\n"
"	.section .bss\n	.align 4\n"
"hexbuf:\n	.skip 8\n"
"charbuf:\n	.skip 4\n"
"cksum:\n	.skip 4\n"
"passes:\n	.skip 4\n"
"pass_idx:\n	.skip 4\n"
"t0buf:\n	.skip 16\n"
"t1buf:\n	.skip 16\n"
"arr:\n	.skip 1024\n"
"cnt:\n	.skip 32\n"
);
