/*
 * tests/test_p6_adjacent.c — Phase 6 adjacent-4 KiB-protection guest.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Freestanding V8-only guest (no libc): one 6-page anonymous mapping is
 * carved into adjacent 4 KiB pages with distinct permissions, mirroring
 * the stage-1 AP/UXN split the frozen Phase-6 contract requires:
 *
 *   p0 RW data | p1 RX code | p2 RELRO->RO | p3 .bss RW | p4 guard | p5 RW
 *
 * Checks (every fault expectation verified against qemu-sparc first):
 * execute-near-write (call into RX p1 while neighbors hold patterns,
 * then re-dirty the adjacent RW word and call again),
 * write-near-execute (store to RX p1 faults SIGSEGV), data read from
 * the RX page, RELRO freeze (p2 read OK + write faults + restore
 * intact), zero-filled .bss p3 then RW,
 * PROT_NONE guard p4 between two RW pages (load faults, store faults,
 * RW after restore), boundary words at both ends of the region.
 * Residual: qemu-sparc SIGSEGVs a fetch from a PROT_READ-only (no
 * PROT_EXEC) page, but neither translator engine enforces fetch-X, so no
 * NX-fetch probe is encoded here (see docs/lanes/phase-6-parity.md R1).
 * Exit 0 prints P6-ADJ-PASS; stdout is byte-identical on
 * qemu-sparc -cpu LEON3, --interp and --dbt (only verdict lines, never
 * addresses, pids, or signal payloads).
 *
 * Build (E-phase discipline):
 *   sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static \
 *     -o /tmp/test_p6_adjacent tests/test_p6_adjacent.c
 * Oracle: qemu-sparc -cpu LEON3 /tmp/test_p6_adjacent
 *
 * Pure top-level asm (no libc, no C runtime). E04 discipline:
 * snapshot-before-print, helpers clobber %o0-%o2, %g1, %g3, %g4 while
 * %g5-%g7 survive; live values otherwise sit in .bss words. Only V8
 * encodings (Bicc, no BPcc/BPr/membar/cas/popc/flushw, no annulled
 * branches). Signal frame pc/npc at +100/+104 (E05 probe convention).
 */
__asm__(
"\t.text\n\t.align 4\n\t.global _start\n"
"_start:\n"
"	sethi %hi(sa), %g2\nor %g2, %lo(sa), %g2\n"
"	sethi %hi(faulthandler), %g3\nor %g3, %lo(faulthandler), %g3\n"
"	st %g3, [%g2]\n"
"	sethi %hi(my_restorer), %g3\nor %g3, %lo(my_restorer), %g3\n	st %g3, [%g2 + 8]\n"
"	mov 0, %g3\n"
"	st %g3, [%g2 + 4]\n	st %g3, [%g2 + 12]\n	st %g3, [%g2 + 16]\n"
"	mov 11, %o0\n	mov %g2, %o1\n	mov 0, %o2\n	mov 0, %o3\n	mov 8, %o4\n"
"	mov 102, %g1\n	ta 0x10\n	bcs fail\n	nop\n"
"	sethi %hi(sa), %g2\nor %g2, %lo(sa), %g2\n"
"	mov %g2, %o1\n	mov 10, %o0\n	mov 0, %o2\n	mov 0, %o3\n	mov 8, %o4\n"
"	mov 102, %g1\n	ta 0x10\n	bcs fail\n	nop\n"
"	sethi %hi(m_start), %g2\nor %g2, %lo(m_start), %g2\n	call puts\n	nop\n"
/* --- mmap 6 pages (24576 B) anonymous RW. --- */
"	mov 0, %o0\n	set 24576, %o1\n	mov 3, %o2\n	mov 0x22, %o3\n	sub %g0, 1, %o4\n	mov 0, %o5\n	mov 56, %g1\n	ta 0x10\n	bcs fail\n	nop\n"
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	st %o0, [%g5]\n"
"	sethi %hi(m_map), %g2\nor %g2, %lo(m_map), %g2\n	call puts\n	nop\n"
/* --- boundary + neighbor writes: last word p0, first word p2, first/last p5. --- */
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %g6\n"
"	set 0xdeadbeef, %g4\n	st %g4, [%g6 + 4092]\n"
"	set 4096, %g7\n	sll %g7, 1, %g7\n	add %g6, %g7, %g4\n"
"	set 0x12345678, %g7\n	st %g7, [%g4]\n"
"	set 24576, %g4\n	add %g6, %g4, %g4\n	add %g4, -4, %g4\n"
"	set 0xa5a5a5a5, %g7\n	st %g7, [%g4]\n"
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %g6\n"
"	set 20480, %g4\n	add %g6, %g4, %g4\n	set 0x55aa55aa, %g7\n	st %g7, [%g4]\n"
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %g6\n"
"	set 0xdeadbeef, %g4\n	ld [%g6 + 4092], %g7\n	cmp %g7, %g4\n	bne fail\n	nop\n"
"	set 4096, %g4\n	sll %g4, 1, %g4\n	add %g6, %g4, %g4\n"
"	set 0x12345678, %g7\n	ld [%g4], %g5\n	cmp %g5, %g7\n	bne fail\n	nop\n"
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %g6\n"
"	set 20480, %g4\n	add %g6, %g4, %g4\n	set 0x55aa55aa, %g7\n"
"	ld [%g4], %g5\n	cmp %g5, %g7\n	bne fail\n	nop\n"
"	set 24576, %g4\n	add %g6, %g4, %g4\n	add %g4, -4, %g4\n"
"	set 0xa5a5a5a5, %g7\n	ld [%g4], %g5\n	cmp %g5, %g7\n	bne fail\n	nop\n"
"	sethi %hi(m_adj), %g2\nor %g2, %lo(m_adj), %g2\n	call puts\n	nop\n"
/* --- .bss page p3 still zero-filled: check first + last word. --- */
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %g6\n"
"	set 12288, %g4\n	add %g6, %g4, %g6\n	ld [%g6], %g4\n	tst %g4\n	bnz fail\n	nop\n"
"	ld [%g6 + 4092], %g4\n	tst %g4\n	bnz fail\n	nop\n"
"	sethi %hi(m_bssz), %g2\nor %g2, %lo(m_bssz), %g2\n	call puts\n	nop\n"
/* --- copy rxfunc snippet to p0 (NX target) and p1 (RX target). --- */
"	sethi %hi(rxfunc), %g2\nor %g2, %lo(rxfunc), %g2\n"
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %g6\n"
"	ld [%g2], %g4\n	st %g4, [%g6]\n"
"	ld [%g2 + 4], %g4\n	st %g4, [%g6 + 4]\n"
"	ld [%g2 + 8], %g4\n	st %g4, [%g6 + 8]\n"
"	set 4096, %g7\n	add %g6, %g7, %g6\n"
"	ld [%g2], %g4\n	st %g4, [%g6]\n"
"	ld [%g2 + 4], %g4\n	st %g4, [%g6 + 4]\n"
"	ld [%g2 + 8], %g4\n	st %g4, [%g6 + 8]\n"
/* --- mprotect p1 -> PROT_READ|PROT_EXEC. --- */
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %g6\n"
"	set 4096, %g7\n	add %g6, %g7, %o0\n	set 4096, %o1\n	mov 5, %o2\n	mov 74, %g1\n	ta 0x10\n	bcs fail\n	nop\n"
"	sethi %hi(m_rx), %g2\nor %g2, %lo(m_rx), %g2\n	call puts\n	nop\n"
/* --- data read from the RX page matches the linked snippet. --- */
"	sethi %hi(rxfunc), %g2\nor %g2, %lo(rxfunc), %g2\n	ld [%g2], %g4\n"
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %g6\n"
"	set 4096, %g7\n	add %g6, %g7, %g6\n	ld [%g6], %g5\n	cmp %g5, %g4\n	bne fail\n	nop\n"
"	sethi %hi(m_rxread), %g2\nor %g2, %lo(m_rxread), %g2\n	call puts\n	nop\n"
/* --- execute-near-write: call into RX p1 while neighbors hold patterns. --- */
"	sethi %hi(m_flag), %g2\nor %g2, %lo(m_flag), %g2\n	mov %g2, %o0\n"
"	set 0x9e3779b9, %g1\n"
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %g6\n"
"	set 4096, %g7\n	add %g6, %g7, %g6\n	jmpl %g6, %o7\n	nop\n"
"	sethi %hi(m_flag), %g2\nor %g2, %lo(m_flag), %g2\n	ld [%g2], %g4\n"
"	set 0x9e3779b9, %g5\n	cmp %g4, %g5\n	bne fail\n	nop\n"
"	sethi %hi(m_rxexec), %g2\nor %g2, %lo(m_rxexec), %g2\n	call puts\n	nop\n"
/* --- write-near-execute: phase 1 faults storing to the RX page. --- */
"	sethi %hi(phase), %g2\nor %g2, %lo(phase), %g2\n	mov 1, %g3\n	st %g3, [%g2]\n"
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %g6\n"
"	set 4096, %g7\n	add %g6, %g7, %g6\n	st %g0, [%g6]\n"
"	sethi %hi(m_nowritebad), %g2\nor %g2, %lo(m_nowritebad), %g2\n	call puts\n	nop\n"
"	ba fail\n	nop\n"
"r1:\n"
"	sethi %hi(saved_signo), %g2\nor %g2, %lo(saved_signo), %g2\n	ld [%g2], %g2\n"
"	cmp %g2, 11\n	bne fail\n	nop\n"
"	sethi %hi(m_nowrite), %g2\nor %g2, %lo(m_nowrite), %g2\n	call puts\n	nop\n"
/* --- execute-near-write again: re-dirty the adjacent RW word, re-run RX. --- */
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %g6\n"
"	set 0x51ed51ed, %g4\n	st %g4, [%g6 + 4092]\n"
"	sethi %hi(m_flag), %g2\nor %g2, %lo(m_flag), %g2\n	mov %g2, %o0\n"
"	set 0x1badb002, %g1\n"
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %g6\n"
"	set 4096, %g7\n	add %g6, %g7, %g6\n	jmpl %g6, %o7\n	nop\n"
"	sethi %hi(m_flag), %g2\nor %g2, %lo(m_flag), %g2\n	ld [%g2], %g4\n"
"	set 0x1badb002, %g5\n	cmp %g4, %g5\n	bne fail\n	nop\n"
"	sethi %hi(m_exec2), %g2\nor %g2, %lo(m_exec2), %g2\n	call puts\n	nop\n"
/* --- RELRO: freeze p2 read-only; read must succeed. --- */
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %g6\n"
"	set 4096, %g7\n	sll %g7, 1, %g7\n	add %g6, %g7, %o0\n	set 4096, %o1\n	mov 1, %o2\n	mov 74, %g1\n	ta 0x10\n	bcs fail\n	nop\n"
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %g6\n"
"	set 4096, %g4\n	sll %g4, 1, %g4\n	add %g6, %g4, %g4\n"
"	set 0x12345678, %g7\n	ld [%g4], %g5\n	cmp %g5, %g7\n	bne fail\n	nop\n"
"	sethi %hi(m_relror), %g2\nor %g2, %lo(m_relror), %g2\n	call puts\n	nop\n"
/* --- RELRO: phase 2 faults writing the frozen page. --- */
"	sethi %hi(phase), %g2\nor %g2, %lo(phase), %g2\n	mov 2, %g3\n	st %g3, [%g2]\n"
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %g6\n"
"	set 4096, %g4\n	sll %g4, 1, %g4\n	add %g6, %g4, %g6\n	st %g0, [%g6]\n"
"	sethi %hi(m_relrowbad), %g2\nor %g2, %lo(m_relrowbad), %g2\n	call puts\n	nop\n"
"	ba fail\n	nop\n"
"r2:\n"
"	sethi %hi(saved_signo), %g2\nor %g2, %lo(saved_signo), %g2\n	ld [%g2], %g2\n"
"	cmp %g2, 11\n	bne fail\n	nop\n"
"	sethi %hi(m_relrow), %g2\nor %g2, %lo(m_relrow), %g2\n	call puts\n	nop\n"
/* --- RELRO: restore RW, pattern intact. --- */
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %g6\n"
"	set 4096, %g7\n	sll %g7, 1, %g7\n	add %g6, %g7, %o0\n	set 4096, %o1\n	mov 3, %o2\n	mov 74, %g1\n	ta 0x10\n	bcs fail\n	nop\n"
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %g6\n"
"	set 4096, %g4\n	sll %g4, 1, %g4\n	add %g6, %g4, %g4\n"
"	set 0x12345678, %g7\n	ld [%g4], %g5\n	cmp %g5, %g7\n	bne fail\n	nop\n"
"	sethi %hi(m_relroback), %g2\nor %g2, %lo(m_relroback), %g2\n	call puts\n	nop\n"
/* --- .bss page p3 writable now: pattern round-trip, first + last word. --- */
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %g6\n"
"	set 12288, %g4\n	add %g6, %g4, %g6\n"
"	set 0xfeedface, %g4\n	st %g4, [%g6]\n	st %g4, [%g6 + 4092]\n"
"	ld [%g6], %g4\n	set 0xfeedface, %g7\n	cmp %g4, %g7\n	bne fail\n	nop\n"
"	ld [%g6 + 4092], %g4\n	cmp %g4, %g7\n	bne fail\n	nop\n"
"	sethi %hi(m_bssrw), %g2\nor %g2, %lo(m_bssrw), %g2\n	call puts\n	nop\n"
/* --- guard: mprotect p4 -> PROT_NONE. --- */
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %g6\n"
"	set 4096, %g7\n	sll %g7, 2, %g7\n	add %g6, %g7, %o0\n	set 4096, %o1\n	mov 0, %o2\n	mov 74, %g1\n	ta 0x10\n	bcs fail\n	nop\n"
/* --- guard: phase 3 faults loading the NONE page. --- */
"	sethi %hi(phase), %g2\nor %g2, %lo(phase), %g2\n	mov 3, %g3\n	st %g3, [%g2]\n"
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %g6\n"
"	set 4096, %g7\n	sll %g7, 2, %g7\n	add %g6, %g7, %g6\n	ld [%g6], %g4\n"
"	sethi %hi(m_guardlbad), %g2\nor %g2, %lo(m_guardlbad), %g2\n	call puts\n	nop\n"
"	ba fail\n	nop\n"
"r3:\n"
"	sethi %hi(saved_signo), %g2\nor %g2, %lo(saved_signo), %g2\n	ld [%g2], %g2\n"
"	cmp %g2, 11\n	bne fail\n	nop\n"
"	sethi %hi(m_guardl), %g2\nor %g2, %lo(m_guardl), %g2\n	call puts\n	nop\n"
/* --- guard: phase 4 faults storing to the NONE page. --- */
"	sethi %hi(phase), %g2\nor %g2, %lo(phase), %g2\n	mov 4, %g3\n	st %g3, [%g2]\n"
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %g6\n"
"	set 4096, %g7\n	sll %g7, 2, %g7\n	add %g6, %g7, %g6\n	st %g0, [%g6]\n"
"	sethi %hi(m_guardsbad), %g2\nor %g2, %lo(m_guardsbad), %g2\n	call puts\n	nop\n"
"	ba fail\n	nop\n"
"r4:\n"
"	sethi %hi(saved_signo), %g2\nor %g2, %lo(saved_signo), %g2\n	ld [%g2], %g2\n"
"	cmp %g2, 11\n	bne fail\n	nop\n"
"	sethi %hi(m_guards), %g2\nor %g2, %lo(m_guards), %g2\n	call puts\n	nop\n"
/* --- guard: restore RW between the two RW pages, pattern round-trip. --- */
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %g6\n"
"	set 4096, %g7\n	sll %g7, 2, %g7\n	add %g6, %g7, %o0\n	set 4096, %o1\n	mov 3, %o2\n	mov 74, %g1\n	ta 0x10\n	bcs fail\n	nop\n"
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %g6\n"
"	set 4096, %g7\n	sll %g7, 2, %g7\n	add %g6, %g7, %g6\n"
"	set 0x0badf00d, %g4\n	st %g4, [%g6]\n	st %g4, [%g6 + 4092]\n"
"	ld [%g6], %g4\n	set 0x0badf00d, %g7\n	cmp %g4, %g7\n	bne fail\n	nop\n"
"	ld [%g6 + 4092], %g4\n	cmp %g4, %g7\n	bne fail\n	nop\n"
"	sethi %hi(m_guardrw), %g2\nor %g2, %lo(m_guardrw), %g2\n	call puts\n	nop\n"
/* --- munmap the whole region. --- */
"	sethi %hi(saved_base), %g5\nor %g5, %lo(saved_base), %g5\n	ld [%g5], %o0\n"
"	set 24576, %o1\n	mov 73, %g1\n	ta 0x10\n	bcs fail\n	nop\n"
"	cmp %o0, 0\n	bne fail\n	nop\n"
"	sethi %hi(m_unmap), %g2\nor %g2, %lo(m_unmap), %g2\n	call puts\n	nop\n"
"	sethi %hi(m_pass), %g2\nor %g2, %lo(m_pass), %g2\n	call puts\n	nop\n"
"	mov 0, %o0\n	mov 1, %g1\n	ta 0x10\n"
"fail:\n"
"	sethi %hi(m_fail), %g2\nor %g2, %lo(m_fail), %g2\n	call puts\n	nop\n"
"	mov 1, %o0\n	mov 1, %g1\n	ta 0x10\n"
"	.global faulthandler\n"
"faulthandler:\n"
"	mov %sp, %g4\n"
"	mov %o0, %g5\n"
"	sethi %hi(saved_signo), %g2\nor %g2, %lo(saved_signo), %g2\n	st %g5, [%g2]\n"
"	sethi %hi(phase), %g2\nor %g2, %lo(phase), %g2\n	ld [%g2], %g2\n"
"	cmp %g2, 1\n	be d1\n	nop\n"
"	cmp %g2, 2\n	be d2\n	nop\n"
"	cmp %g2, 3\n	be d3\n	nop\n"
"	cmp %g2, 4\n	be d4\n	nop\n"
"	sethi %hi(m_unexp), %g2\nor %g2, %lo(m_unexp), %g2\n	call puts\n	nop\n"
"	mov 1, %o0\n	mov 1, %g1\n	ta 0x10\n"
"d1:\n"
"	sethi %hi(r1), %g5\nor %g5, %lo(r1), %g5\n	ba do_resume\n	nop\n"
"d2:\n"
"	sethi %hi(r2), %g5\nor %g5, %lo(r2), %g5\n	ba do_resume\n	nop\n"
"d3:\n"
"	sethi %hi(r3), %g5\nor %g5, %lo(r3), %g5\n	ba do_resume\n	nop\n"
"d4:\n"
"	sethi %hi(r4), %g5\nor %g5, %lo(r4), %g5\n	ba do_resume\n	nop\n"
"do_resume:\n"
"	add %g5, 4, %g6\n	st %g5, [%g4 + 100]\n	st %g6, [%g4 + 104]\n"
"	sethi %hi(my_restorer), %g5\nor %g5, %lo(my_restorer), %g5\n	jmp %g5\n	nop\n"
"	.global my_restorer\n"
"my_restorer:\n	mov 216, %g1\n	ta 0x10\n	ba fail\n	nop\n"
"rxfunc:\n"
"	st %g1, [%o0]\n"
"	jmpl %o7 + 8, %g0\n	nop\n"
"puts:\n	mov %g2, %g4\n"
"1:\n	ldub [%g4], %g3\n	tst %g3\n	bz 2f\n	add %g4, 1, %g4\n	ba 1b\n	nop\n"
"2:\n	sub %g4, %g2, %o2\n	mov %g2, %o1\n	mov 1, %o0\n	mov 4, %g1\n	ta 0x10\n	retl\n	nop\n"
"	.data\n	.align 4\n"
"m_start:\n	.asciz \"P6-ADJ start\\n\"\n"
"m_map:\n	.asciz \"map ok\\n\"\n"
"m_adj:\n	.asciz \"adj rw ok\\n\"\n"
"m_bssz:\n	.asciz \"bss zero ok\\n\"\n"
"m_rx:\n	.asciz \"rx protect ok\\n\"\n"
"m_rxread:\n	.asciz \"rx read ok\\n\"\n"
"m_rxexec:\n	.asciz \"rx exec ok\\n\"\n"
"m_nowrite:\n	.asciz \"rx nowrite ok\\n\"\n"
"m_nowritebad:\n	.asciz \"rx write did NOT fault\\n\"\n"
"m_exec2:\n	.asciz \"rx exec2 ok\\n\"\n"
"m_relror:\n	.asciz \"relro read ok\\n\"\n"
"m_relrow:\n	.asciz \"relro nowrite ok\\n\"\n"
"m_relrowbad:\n	.asciz \"relro write did NOT fault\\n\"\n"
"m_relroback:\n	.asciz \"relro restore ok\\n\"\n"
"m_bssrw:\n	.asciz \"bss rw ok\\n\"\n"
"m_guardl:\n	.asciz \"guard noload ok\\n\"\n"
"m_guardlbad:\n	.asciz \"guard load did NOT fault\\n\"\n"
"m_guards:\n	.asciz \"guard nostore ok\\n\"\n"
"m_guardsbad:\n	.asciz \"guard store did NOT fault\\n\"\n"
"m_guardrw:\n	.asciz \"guard rw ok\\n\"\n"
"m_unmap:\n	.asciz \"unmap ok\\n\"\n"
"m_unexp:\n	.asciz \"P6-ADJ-UNEXPECTED\\n\"\n"
"m_pass:\n	.asciz \"P6-ADJ-PASS\\n\"\n"
"m_fail:\n	.asciz \"P6-ADJ-FAIL\\n\"\n"
"	.bss\n	.align 4\n"
"sa:\n	.skip 20\n"
"phase:\n	.skip 4\n"
"saved_base:\n	.skip 4\n"
"saved_signo:\n	.skip 4\n"
"m_flag:\n	.skip 4\n"
);
