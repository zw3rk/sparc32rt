/*
 * tests/test_p6_mmap.c — Phase 6 host-contract probe guest (freestanding, V8-only).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Covers the frozen Phase-6 contract §2.1 three-layer page rules
 * (AT_PAGESZ = 4096) with raw `ta 0x10` traps (no libc: the Debian
 * sparc64 toolchain links libc as EM_SPARC32PLUS, which neither the
 * SPEC oracle `qemu-sparc -cpu LEON3` nor the V8 loader admits):
 * mmap/mmap2 unaligned-MAP_FIXED addr/offset and len == 0 -> -EINVAL
 * with positive-len round-up; mprotect/munmap unaligned addr ->
 * -EINVAL, munmap len == 0 -> -EINVAL, mprotect len == 0 ->
 * success no-op; mremap unaligned old/new(FIXED) addr or
 * new_size == 0 -> -EINVAL with size round-up; mremap fixed-moves
 * and MREMAP_MAYMOVE growth with data preservation; brk
 * byte-exactness across page boundaries. Deterministic stdout
 * (addresses are never printed); exit 0 means every check passed.
 *
 * qemu gaps (observed, sparc32rt-oracle:latest; both are qemu-user
 * deviations, not contract bugs — real-kernel ground truth was taken
 * with a native perl-syscall control on arm64 Debian:
 *   mprotect0: ret=0 errno=0; mremap-new0: ret=-1 errno=22;
 *   munmap0: ret=-1 errno=22):
 *   Q1: mprotect(addr, 0, prot) -> qemu ENOMEM(12), kernel 0.
 *       oracle strace: mprotect(0x3fffb000,0,PROT_READ) = -1 errno=12.
 *   Q2: mremap(addr, size, 0, 0, 0) -> qemu ENOMEM(12), kernel
 *       EINVAL(22). Byte-array probe under qemu-sparc -cpu LEON3
 *       returned [12,22,22,0,22,12,0,0] for
 *       [mprotect-0, munmap-un, munmap-0, mremap-shrink,
 *        mremap-unaligned, mremap-new0, mremap-grow, mremap-fixed].
 * The two affected checks accept exactly the contracted value or
 * the documented qemu value (any other errno fails); every other
 * check is strict. No gap has side effects: the mapping survives
 * both (shrink/grow/fixed checks follow and pass on all engines).
 *
 * CoW fork snapshot (contract Class-A row: "CoW fork snapshot when
 * has_host_info"): on native Linux has_host_info is false and fork(2)
 * duplicates the whole [G, G+4GiB) window through host copy-on-write
 * mappings, which already satisfies Linux fork snapshot semantics;
 * the DBT code cache survives as shared CoW pages and is flushed on
 * next execute via the existing invalidate hooks. No translator
 * change is mandated for native-Linux correctness. hyper-linux-only
 * snapshot cooperation (broker-mediated page sharing keyed on
 * has_host_info) is residual: the oracle container has no
 * /dev/a32host, so that path is verified by construction
 * (constants/handshake flow) rather than by execution here.
 *
 * Window/task-3 evidence (run separately, same binary family):
 *   --window 0x100000000 accepted + guest runs to PASS under
 *   --interp and --dbt; SPARC32RT_HOST=none bypasses the handshake.
 *
 * Build (E-phase discipline):
 *   sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static \
 *     -o /tmp/test_p6_mmap tests/test_p6_mmap.c
 * Oracle: qemu-sparc -cpu LEON3 /tmp/test_p6_mmap
 * Translator: sparc32rt --interp -- /tmp/test_p6_mmap
 *             sparc32rt --dbt -- /tmp/test_p6_mmap
 *
 * Pure top-level asm (no libc, no C runtime). E04 discipline:
 * snapshot-before-print, helpers clobber %o0-%o2, %g1, %g3, %g4 while
 * %g5-%g7 survive; live values otherwise sit in .bss words. Only V8
 * encodings (Bicc, no BPcc/BPr/membar/cas/popc/flushw).
 */
__asm__(
"\t.text\n\t.align 4\n\t.global _start\n"
"_start:\n"
"\tsethi %hi(msg_start), %g2\nor %g2, %lo(msg_start), %g2\n\tcall puts\n\tnop\n"
/* --- A = mmap2(0, 16384, RW, PRIVATE|ANON); must succeed. --- */
"\tmov 0, %o0\n\tset 16384, %o1\n\tmov 3, %o2\n\tmov 0x22, %o3\n\tsub %g0, 1, %o4\n\tmov 0, %o5\n\tmov 56, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tst %o0, [%g5]\n"
/* --- mmap2 len == 0 -> EINVAL(22). --- */
"\tmov 0, %o0\n\tmov 0, %o1\n\tmov 3, %o2\n\tmov 0x22, %o3\n\tsub %g0, 1, %o4\n\tmov 0, %o5\n\tmov 56, %g1\n\tta 0x10\n\tbcc fail\n\tnop\n"
"\tcmp %o0, 22\n\tbne fail\n\tnop\n"
/* --- mmap(71) len == 0 -> EINVAL. --- */
"\tmov 0, %o0\n\tmov 0, %o1\n\tmov 3, %o2\n\tmov 0x22, %o3\n\tsub %g0, 1, %o4\n\tmov 0, %o5\n\tmov 71, %g1\n\tta 0x10\n\tbcc fail\n\tnop\n"
"\tcmp %o0, 22\n\tbne fail\n\tnop\n"
/* --- mmap2 MAP_FIXED unaligned addr (A+1) -> EINVAL. --- */
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %o0\n\tadd %o0, 1, %o0\n\tset 4096, %o1\n\tmov 3, %o2\n\tmov 0x32, %o3\n\tsub %g0, 1, %o4\n\tmov 0, %o5\n\tmov 56, %g1\n\tta 0x10\n\tbcc fail\n\tnop\n"
"\tcmp %o0, 22\n\tbne fail\n\tnop\n"
/* --- mmap(71) MAP_FIXED unaligned byte offset -> EINVAL. --- */
"\tmov 0, %o0\n\tset 4096, %o1\n\tmov 3, %o2\n\tmov 0x32, %o3\n\tsub %g0, 1, %o4\n\tmov 1, %o5\n\tmov 71, %g1\n\tta 0x10\n\tbcc fail\n\tnop\n"
"\tcmp %o0, 22\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_einval), %g2\nor %g2, %lo(msg_einval), %g2\n\tcall puts\n\tnop\n"
/* --- Round-up: B = mmap2(0, 100); byte at B+4095 must be addressable. --- */
"\tmov 0, %o0\n\tmov 100, %o1\n\tmov 3, %o2\n\tmov 0x22, %o3\n\tsub %g0, 1, %o4\n\tmov 0, %o5\n\tmov 56, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_b), %g5\nor %g5, %lo(saved_b), %g5\n\tst %o0, [%g5]\n\tmov %o0, %g7\n"
"\tmov 0xab, %g6\n\tstb %g6, [%g7 + 4095]\n\tldub [%g7 + 4095], %g6\n\tcmp %g6, 0xab\n\tbne fail\n\tnop\n"
/* --- mprotect(B, 100, RO) ok; read still fine; back to RW. --- */
"\tmov %g7, %o0\n\tmov 100, %o1\n\tmov 1, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, 0\n\tbne fail\n\tnop\n"
"\tldub [%g7 + 4095], %g6\n\tcmp %g6, 0xab\n\tbne fail\n\tnop\n"
"\tmov %g7, %o0\n\tmov 100, %o1\n\tmov 3, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
/* --- munmap(B, 100) ok (round-up unmaps the whole page). --- */
"\tmov %g7, %o0\n\tmov 100, %o1\n\tmov 73, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, 0\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_roundup), %g2\nor %g2, %lo(msg_roundup), %g2\n\tcall puts\n\tnop\n"
/* --- mprotect(A, 4096, RO) ok, then RW; unaligned -> EINVAL. --- */
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tld [%g5], %g7\n"
"\tmov %g7, %o0\n\tset 4096, %o1\n\tmov 1, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tmov %g7, %o0\n\tset 4096, %o1\n\tmov 3, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tadd %g7, 1, %o0\n\tset 4096, %o1\n\tmov 1, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcc fail\n\tnop\n"
"\tcmp %o0, 22\n\tbne fail\n\tnop\n"
/* --- mprotect(A, 0, R) -> success no-op (o0 == 0, carry clear).
 * qemu gap Q1: qemu-sparc returns ENOMEM(12) here (real Linux
 * returns 0; native control confirmed). Accept exactly 0 or 12;
 * anything else fails. --- */
"\tmov %g7, %o0\n\tmov 0, %o1\n\tmov 1, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcc mp0ok\n\tnop\n"
"\tcmp %o0, 12\n\tbne fail\n\tnop\n"
"\tba mp0done\n\tnop\n"
"mp0ok:\n"
"\tcmp %o0, 0\n\tbne fail\n\tnop\n"
"mp0done:\n"
/* --- munmap(A+1, 4096) -> EINVAL; munmap(A, 0) -> EINVAL. --- */
"\tadd %g7, 1, %o0\n\tset 4096, %o1\n\tmov 73, %g1\n\tta 0x10\n\tbcc fail\n\tnop\n"
"\tcmp %o0, 22\n\tbne fail\n\tnop\n"
"\tmov %g7, %o0\n\tmov 0, %o1\n\tmov 73, %g1\n\tta 0x10\n\tbcc fail\n\tnop\n"
"\tcmp %o0, 22\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_prot), %g2\nor %g2, %lo(msg_prot), %g2\n\tcall puts\n\tnop\n"
/* --- mremap(A+1, 4096, 4096, 0) unaligned old -> EINVAL. --- */
"\tadd %g7, 1, %o0\n\tset 4096, %o1\n\tset 4096, %o2\n\tmov 0, %o3\n\tmov 0, %o4\n\tmov 250, %g1\n\tta 0x10\n\tbcc fail\n\tnop\n"
"\tcmp %o0, 22\n\tbne fail\n\tnop\n"
/* --- mremap(A, 4096, 0, 0) new_size == 0 -> EINVAL.
 * qemu gap Q2: qemu-sparc returns ENOMEM(12) here (real Linux
 * returns EINVAL; native control confirmed). Accept exactly 22 or
 * 12; anything else fails. Mapping must survive either way (the
 * shrink/grow/fixed checks below prove it). --- */
"\tmov %g7, %o0\n\tset 4096, %o1\n\tmov 0, %o2\n\tmov 0, %o3\n\tmov 0, %o4\n\tmov 250, %g1\n\tta 0x10\n\tbcc fail\n\tnop\n"
"\tcmp %o0, 22\n\tbeq mr0done\n\tnop\n"
"\tcmp %o0, 12\n\tbne fail\n\tnop\n"
"mr0done:\n"
"\tsethi %hi(msg_reinval), %g2\nor %g2, %lo(msg_reinval), %g2\n\tcall puts\n\tnop\n"
/* --- Pattern at A; mremap(A, 16384, 4096, 0) shrink -> same addr. --- */
"\tset 0xdeadbeef, %g6\n\tst %g6, [%g7]\n\tset 0x12345678, %g6\n\tst %g6, [%g7 + 4]\n"
"\tmov %g7, %o0\n\tset 16384, %o1\n\tset 4096, %o2\n\tmov 0, %o3\n\tmov 0, %o4\n\tmov 250, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, %g7\n\tbne fail\n\tnop\n"
"\tld [%g7], %g6\n\tset 0xdeadbeef, %o0\n\tcmp %g6, %o0\n\tbne fail\n\tnop\n"
"\tld [%g7 + 4], %g6\n\tset 0x12345678, %o0\n\tcmp %g6, %o0\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_shrink), %g2\nor %g2, %lo(msg_shrink), %g2\n\tcall puts\n\tnop\n"
/* --- mremap(A, 4096, 16384, MAYMOVE) grow; data follows the return. --- */
"\tmov %g7, %o0\n\tset 4096, %o1\n\tset 16384, %o2\n\tmov 1, %o3\n\tmov 0, %o4\n\tmov 250, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tmov %o0, %g7\n"
"\tsethi %hi(saved_a), %g5\nor %g5, %lo(saved_a), %g5\n\tst %g7, [%g5]\n"
"\tld [%g7], %g6\n\tset 0xdeadbeef, %o0\n\tcmp %g6, %o0\n\tbne fail\n\tnop\n"
"\tld [%g7 + 4], %g6\n\tset 0x12345678, %o0\n\tcmp %g6, %o0\n\tbne fail\n\tnop\n"
/* --- Round-up proof on the grown area: byte at D+16383 addressable. --- */
"\tset 16383, %g4\n\tadd %g7, %g4, %g4\n\tmov 0xcd, %g6\n\tstb %g6, [%g4]\n\tldub [%g4], %g6\n\tcmp %g6, 0xcd\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_grow), %g2\nor %g2, %lo(msg_grow), %g2\n\tcall puts\n\tnop\n"
/* --- FIXED move: C = mmap2(0, 8192); munmap(C); move D -> C. --- */
"\tmov 0, %o0\n\tset 8192, %o1\n\tmov 3, %o2\n\tmov 0x22, %o3\n\tsub %g0, 1, %o4\n\tmov 0, %o5\n\tmov 56, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tmov %o0, %g6\n"
"\tmov %o0, %o0\n\tset 8192, %o1\n\tmov 73, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tmov %g7, %o0\n\tset 16384, %o1\n\tset 4096, %o2\n\tmov 3, %o3\n\tmov %g6, %o4\n\tmov 250, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, %g6\n\tbne fail\n\tnop\n"
"\tld [%g6], %g5\n\tset 0xdeadbeef, %o0\n\tcmp %g5, %o0\n\tbne fail\n\tnop\n"
"\tld [%g6 + 4], %g5\n\tset 0x12345678, %o0\n\tcmp %g5, %o0\n\tbne fail\n\tnop\n"
/* --- Old D is freed: mmap2 FIXED at D must succeed again. --- */
"\tmov %g7, %o0\n\tset 4096, %o1\n\tmov 3, %o2\n\tmov 0x32, %o3\n\tsub %g0, 1, %o4\n\tmov 0, %o5\n\tmov 56, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, %g7\n\tbne fail\n\tnop\n"
"\tmov %g7, %o0\n\tset 4096, %o1\n\tmov 73, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tmov %g6, %o0\n\tset 4096, %o1\n\tmov 73, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(msg_fixed), %g2\nor %g2, %lo(msg_fixed), %g2\n\tcall puts\n\tnop\n"
/* --- brk byte-exactness: +1, +5000 across pages, bytes, shrink. --- */
"\tmov 0, %o0\n\tmov 17, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_brk), %g5\nor %g5, %lo(saved_brk), %g5\n\tst %o0, [%g5]\n\tmov %o0, %g7\n"
"\tadd %g7, 1, %o0\n\tmov 17, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tadd %g7, 1, %g6\n\tcmp %o0, %g6\n\tbne fail\n\tnop\n"
"\tmov 0x5a, %g6\n\tstb %g6, [%g7]\n\tldub [%g7], %g6\n\tcmp %g6, 0x5a\n\tbne fail\n\tnop\n"
"\tset 5000, %g4\n\tadd %g7, %g4, %o0\n\tmov 17, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tadd %g7, %g4, %g6\n\tcmp %o0, %g6\n\tbne fail\n\tnop\n"
"\tset 4096, %g4\n\tadd %g7, %g4, %g4\n\tmov 0x5b, %g6\n\tstb %g6, [%g4]\n\tldub [%g4], %g6\n\tcmp %g6, 0x5b\n\tbne fail\n\tnop\n"
"\tset 4999, %g4\n\tadd %g7, %g4, %g4\n\tmov 0x5c, %g6\n\tstb %g6, [%g4]\n\tldub [%g4], %g6\n\tcmp %g6, 0x5c\n\tbne fail\n\tnop\n"
"\tldub [%g7], %g6\n\tcmp %g6, 0x5a\n\tbne fail\n\tnop\n"
"\tmov %g7, %o0\n\tmov 17, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, %g7\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_brk), %g2\nor %g2, %lo(msg_brk), %g2\n\tcall puts\n\tnop\n"
"\tsethi %hi(msg_pass), %g2\nor %g2, %lo(msg_pass), %g2\n\tcall puts\n\tnop\n"
"\tmov 0, %o0\n\tmov 1, %g1\n\tta 0x10\n"
"fail:\n"
"\tsethi %hi(msg_fail), %g2\nor %g2, %lo(msg_fail), %g2\n\tcall puts\n\tnop\n"
"\tmov 1, %o0\n\tmov 1, %g1\n\tta 0x10\n"
/* --- helpers (leaf calls; ra saved in memory; clobber o0-o2,g1,g3,g4). --- */
"puts:\n\tmov %g2, %g4\n"
"1:\n\tldub [%g4], %g3\n\ttst %g3\n\tbz 2f\n\tadd %g4, 1, %g4\n\tba 1b\n\tnop\n"
"2:\n\tsub %g4, %g2, %o2\n\tmov %g2, %o1\n\tmov 1, %o0\n\tmov 4, %g1\n\tta 0x10\n\tretl\n\tnop\n"
"\t.data\n\t.align 4\n"
"msg_start:\n\t.asciz \"P6-MMAP start\\n\"\n"
"msg_einval:\n\t.asciz \"einval ok\\n\"\n"
"msg_roundup:\n\t.asciz \"roundup ok\\n\"\n"
"msg_prot:\n\t.asciz \"prot ok\\n\"\n"
"msg_reinval:\n\t.asciz \"mremap-einval ok\\n\"\n"
"msg_shrink:\n\t.asciz \"mremap-shrink ok\\n\"\n"
"msg_grow:\n\t.asciz \"mremap-grow ok\\n\"\n"
"msg_fixed:\n\t.asciz \"mremap-fixed ok\\n\"\n"
"msg_brk:\n\t.asciz \"brk ok\\n\"\n"
"msg_pass:\n\t.asciz \"P6-MMAP-PASS\\n\"\n"
"msg_fail:\n\t.asciz \"P6-MMAP-FAIL\\n\"\n"
"\t.bss\n\t.align 4\n"
"saved_a:\n\t.skip 4\n"
"saved_b:\n\t.skip 4\n"
"saved_brk:\n\t.skip 4\n"
);
