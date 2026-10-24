/*
 * tests/test_p2_sys.c — Phase 2 raw-syscall guest (freestanding, V8-only).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Exercises the L2a static-libc syscall surface with raw `ta 0x10`
 * traps (no libc: the Debian sparc64 toolchain links libc as
 * EM_SPARC32PLUS with BPcc/V9 encodings, which neither the SPEC oracle
 * `qemu-sparc -cpu LEON3` nor the V8 loader admits). Deterministic
 * stdout; exit 0 means every check passed.
 *
 * Covers: getpid, brk, mmap2/munmap (anonymous RW + pattern), openat /
 * write / close / openat / lseek / read / fstat / close / unlink
 * (64-byte round-trip, byte-compared), clock_gettime, getrandom.
 *
 * Build (E-phase discipline):
 *   sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static \
 *     -o /tmp/test_p2_sys tests/test_p2_sys.c
 * Oracle: qemu-sparc -cpu LEON3 /tmp/test_p2_sys
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
/* --- getpid(20): must succeed (C==0); value never printed. --- */
"\tmov 20, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(msg_pid), %g2\nor %g2, %lo(msg_pid), %g2\n\tcall puts\n\tnop\n"
/* --- brk: read current, extend by 8192, expect exact new value. --- */
"\tmov 0, %o0\n\tmov 17, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_brk), %g5\nor %g5, %lo(saved_brk), %g5\n\tst %o0, [%g5]\n"
"\tset 8192, %g6\n\tadd %o0, %g6, %o0\n\tmov 17, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_brk), %g5\nor %g5, %lo(saved_brk), %g5\n\tld [%g5], %g6\n\tset 8192, %g7\n\tadd %g6, %g7, %g6\n\tcmp %o0, %g6\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_brk), %g2\nor %g2, %lo(msg_brk), %g2\n\tcall puts\n\tnop\n"
/* --- mmap2(56) anon 16384 RW; pattern fill; verify; munmap(73). --- */
"\tmov 0, %o0\n\tset 16384, %o1\n\tmov 3, %o2\n\tmov 0x22, %o3\n\tsub %g0, 1, %o4\n\tmov 0, %o5\n\tmov 56, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_map), %g5\nor %g5, %lo(saved_map), %g5\n\tst %o0, [%g5]\n\tmov %o0, %g7\n"
"\tset 0xdeadbeef, %g6\n\tst %g6, [%g7]\n\tset 0x12345678, %g6\n\tst %g6, [%g7 + 4]\n\tld [%g7], %g5\n\tset 0xdeadbeef, %g6\n\tcmp %g5, %g6\n\tbne fail\n\tnop\n"
"\tld [%g7 + 4], %g5\n\tset 0x12345678, %g6\n\tcmp %g5, %g6\n\tbne fail\n\tnop\n"
"\tmov %g7, %o0\n\tset 16384, %o1\n\tmov 73, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, 0\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_mmap), %g2\nor %g2, %lo(msg_mmap), %g2\n\tcall puts\n\tnop\n"
/* --- openat(AT_FDCWD, path, W|C|T, 0644); write 64 B; close. --- */
"\tmov -100, %o0\n\tsethi %hi(file_path), %g5\nor %g5, %lo(file_path), %g5\n\tmov %g5, %o1\n\tset 0x601, %o2\n\tmov 0x1a4, %o3\n\tmov 284, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_fd), %g5\nor %g5, %lo(saved_fd), %g5\n\tst %o0, [%g5]\n"
"\tsethi %hi(pattern), %g5\nor %g5, %lo(pattern), %g5\n\tmov %g5, %o1\n\tmov 64, %o2\n\tmov 4, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, 64\n\tbne fail\n\tnop\n"
"\tsethi %hi(saved_fd), %g5\nor %g5, %lo(saved_fd), %g5\n\tld [%g5], %o0\n\tmov 6, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(msg_write), %g2\nor %g2, %lo(msg_write), %g2\n\tcall puts\n\tnop\n"
/* --- stat(38) path: expect success; size checked via lseek next. --- */
"\tsethi %hi(file_path), %g5\nor %g5, %lo(file_path), %g5\n\tmov %g5, %o0\n\tsethi %hi(statbuf), %g6\nor %g6, %lo(statbuf), %g6\n\tmov %g6, %o1\n\tmov 38, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(msg_stat), %g2\nor %g2, %lo(msg_stat), %g2\n\tcall puts\n\tnop\n"
/* --- reopen RDONLY; lseek END (expect 64); lseek SET (expect 0). --- */
"\tmov -100, %o0\n\tsethi %hi(file_path), %g5\nor %g5, %lo(file_path), %g5\n\tmov %g5, %o1\n\tmov 0, %o2\n\tmov 284, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_fd), %g5\nor %g5, %lo(saved_fd), %g5\n\tst %o0, [%g5]\n"
"\tmov 0, %o1\n\tmov 2, %o2\n\tmov 19, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, 64\n\tbne fail\n\tnop\n"
"\tsethi %hi(saved_fd), %g5\nor %g5, %lo(saved_fd), %g5\n\tld [%g5], %o0\n\tmov 0, %o1\n\tmov 0, %o2\n\tmov 19, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, 0\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_seek), %g2\nor %g2, %lo(msg_seek), %g2\n\tcall puts\n\tnop\n"
/* --- read 64 B back; byte-compare against pattern; close; unlink. --- */
"\tsethi %hi(saved_fd), %g5\nor %g5, %lo(saved_fd), %g5\n\tld [%g5], %o0\n\tsethi %hi(readback), %g6\nor %g6, %lo(readback), %g6\n\tmov %g6, %o1\n\tmov 64, %o2\n\tmov 3, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, 64\n\tbne fail\n\tnop\n"
"\tsethi %hi(pattern), %g5\nor %g5, %lo(pattern), %g5\n\tsethi %hi(readback), %g6\nor %g6, %lo(readback), %g6\n\tmov 16, %g7\n"
"cmp_loop:\n"
"\tld [%g5], %o0\n\tld [%g6], %o1\n\tcmp %o0, %o1\n\tbne fail\n\tnop\n"
"\tadd %g5, 4, %g5\n\tadd %g6, 4, %g6\n\tsubcc %g7, 1, %g7\n\tbnz cmp_loop\n\tnop\n"
"\tsethi %hi(saved_fd), %g5\nor %g5, %lo(saved_fd), %g5\n\tld [%g5], %o0\n\tmov 6, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(file_path), %g5\nor %g5, %lo(file_path), %g5\n\tmov %g5, %o0\n\tmov 10, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(msg_file), %g2\nor %g2, %lo(msg_file), %g2\n\tcall puts\n\tnop\n"
/* --- clock_gettime(MONOTONIC=1): expect success; value not printed. --- */
"\tmov 1, %o0\n\tsethi %hi(tsbuf), %g5\nor %g5, %lo(tsbuf), %g5\n\tmov %g5, %o1\n\tmov 257, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, 0\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_clock), %g2\nor %g2, %lo(msg_clock), %g2\n\tcall puts\n\tnop\n"
/* --- getrandom(16 B): expect exactly 16; bytes never printed. --- */
"\tsethi %hi(randbuf), %g5\nor %g5, %lo(randbuf), %g5\n\tmov %g5, %o0\n\tmov 16, %o1\n\tmov 0, %o2\n\tmov 347, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, 16\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_rand), %g2\nor %g2, %lo(msg_rand), %g2\n\tcall puts\n\tnop\n"
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
"msg_start:\n\t.asciz \"P2-SYS start\\n\"\n"
"msg_pid:\n\t.asciz \"getpid ok\\n\"\n"
"msg_brk:\n\t.asciz \"brk ok\\n\"\n"
"msg_mmap:\n\t.asciz \"mmap ok\\n\"\n"
"msg_write:\n\t.asciz \"write ok\\n\"\n"
"msg_stat:\n\t.asciz \"stat ok\\n\"\n"
"msg_seek:\n\t.asciz \"seek ok\\n\"\n"
"msg_file:\n\t.asciz \"file ok\\n\"\n"
"msg_clock:\n\t.asciz \"clock ok\\n\"\n"
"msg_rand:\n\t.asciz \"rand ok\\n\"\n"
"msg_pass:\n\t.asciz \"P2-SYS-PASS\\n\"\n"
"msg_fail:\n\t.asciz \"P2-SYS-FAIL\\n\"\n"
"file_path:\n\t.asciz \"/tmp/sparc32rt-p2sys.tmp\"\n"
"\t.align 4\n"
"pattern:\n\t.word 0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10\n"
"\t.word 0x11121314, 0x15161718, 0x191a1b1c, 0x1d1e1f20\n"
"\t.word 0x21222324, 0x25262728, 0x292a2b2c, 0x2d2e2f30\n"
"\t.word 0x31323334, 0x35363738, 0x393a3b3c, 0x3d3e3f40\n"
"\t.bss\n\t.align 4\n"
"saved_brk:\n\t.skip 4\n"
"saved_map:\n\t.skip 4\n"
"saved_fd:\n\t.skip 4\n"
"statbuf:\n\t.skip 128\n"
"readback:\n\t.skip 64\n"
"tsbuf:\n\t.skip 16\n"
"randbuf:\n\t.skip 16\n"
);
