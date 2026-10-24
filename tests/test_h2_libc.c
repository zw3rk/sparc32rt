/*
 * tests/test_h2_libc.c — Phase 7 lane H2 libc-test/LTP portability guest.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Freestanding V8-only guest (no libc: the Debian sparc64 toolchain links
 * libc as EM_SPARC32PLUS with V9 encodings, inadmissible per SPEC section
 * 1.1 and docs/lanes/phase-5-sysroot.md section 6). Ports the *assertions*
 * of the libc-test string/math/ctype/signal/functional groups and the
 * LTP syscall subset that raw `ta 0x10` traps can express into in-guest
 * loops and direct syscalls. Deterministic stdout; exit 0 means every
 * check passed on qemu-sparc -cpu LEON3, --interp, and --dbt.
 *
 * Covers: strlen/strcmp/memcmp/memcpy/memmove(fwd+bwd)/memset(incl.
 * zero-length)/strchr (libc-test string/); digit/alpha/space/case
 * ranges (ctype/); smul/sdiv/umul/Y/INT_MAX+1/addcc-V (math int);
 * fadds/fsubs/fmuls/fdivs/fsqrts/fcmps+FBfcc/fbu-NaN (math float);
 * faddd/fsubd bit-exact (math double); getpid/getuid/getgid/
 * geteuid/getegid/getppid, pipe+read/write/close round-trip, fcntl
 * GETFL/SETFL/DUPFD, fork+wait4 exit-status, mmap/mprotect/munmap,
 * uname sysname, clock_gettime, getrandom, rt_sigaction+kill delivery,
 * rt_sigprocmask block/mask/unblock (signal/functional/LTP/).
 * Deliberately NOT covered here (translator -ENOSYS, oracle-verified
 * escalations in docs/h2-report.md): dup/dup2/dup3, nanosleep,
 * clock_nanosleep, gettimeofday. pthread/clone/futex/TLS: covered by
 * tests/test_p4_threads.c, cited in the report.
 *
 * Build (E-phase discipline):
 *   sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static \
 *     -o /tmp/test_h2_libc tests/test_h2_libc.c
 * Oracle: qemu-sparc -cpu LEON3 /tmp/test_h2_libc
 *
 * Pure top-level asm (no libc, no C runtime). E04 discipline:
 * snapshot-before-print, helpers clobber %o0-%o2, %g1, %g3, %g4 while
 * %g5-%g7 survive; live values otherwise sit in .bss words. Only V8
 * encodings (Bicc/FBfcc, no BPcc/BPr/membar/cas/popc/flushw, no
 * annulled branches). Large immediates use `set`, never `mov`.
 */
__asm__(
"\t.text\n\t.align 4\n\t.global _start\n"
"_start:\n"
"\tsethi %hi(msg_start), %g2\nor %g2, %lo(msg_start), %g2\n\tcall puts\n\tnop\n"
/* --- strlen("hello world") == 11. --- */
"\tsethi %hi(s_hello), %g5\nor %g5, %lo(s_hello), %g5\n\tmov %g5, %g6\n\tmov 0, %g7\n"
"h2_len:\n"
"\tldub [%g6], %g2\n\ttst %g2\n\tbz h2_lend\n\tnop\n"
"\tadd %g6, 1, %g6\n\tadd %g7, 1, %g7\n\tba h2_len\n\tnop\n"
"h2_lend:\n"
"\tcmp %g7, 11\n\tbne fail\n\tnop\n"
/* --- strlen("") == 0. --- */
"\tsethi %hi(s_empty), %g5\nor %g5, %lo(s_empty), %g5\n\tldub [%g5], %g2\n\ttst %g2\n\tbnz fail\n\tnop\n"
/* --- strcmp("abc","abc") == 0. --- */
"\tsethi %hi(s_abc), %g5\nor %g5, %lo(s_abc), %g5\n"
"\tsethi %hi(s_abc2), %g6\nor %g6, %lo(s_abc2), %g6\n\tcall h2_strcmp\n\tnop\n"
"\ttst %o0\n\tbnz fail\n\tnop\n"
/* --- strcmp("abc","abd") < 0. --- */
"\tsethi %hi(s_abc), %g5\nor %g5, %lo(s_abc), %g5\n"
"\tsethi %hi(s_abd), %g6\nor %g6, %lo(s_abd), %g6\n\tcall h2_strcmp\n\tnop\n"
"\ttst %o0\n\tbge fail\n\tnop\n"
/* --- strcmp("abd","abc") > 0. --- */
"\tsethi %hi(s_abd), %g5\nor %g5, %lo(s_abd), %g5\n"
"\tsethi %hi(s_abc), %g6\nor %g6, %lo(s_abc), %g6\n\tcall h2_strcmp\n\tnop\n"
"\ttst %o0\n\tble fail\n\tnop\n"
/* --- strcmp("abc","abcd") < 0 (prefix). --- */
"\tsethi %hi(s_abc), %g5\nor %g5, %lo(s_abc), %g5\n"
"\tsethi %hi(s_abcd), %g6\nor %g6, %lo(s_abcd), %g6\n\tcall h2_strcmp\n\tnop\n"
"\ttst %o0\n\tbge fail\n\tnop\n"
/* --- strcmp("","a") < 0; strcmp("","")== 0. --- */
"\tsethi %hi(s_empty), %g5\nor %g5, %lo(s_empty), %g5\n"
"\tsethi %hi(s_a), %g6\nor %g6, %lo(s_a), %g6\n\tcall h2_strcmp\n\tnop\n"
"\ttst %o0\n\tbge fail\n\tnop\n"
"\tsethi %hi(s_empty), %g5\nor %g5, %lo(s_empty), %g5\n"
"\tsethi %hi(s_empty), %g6\nor %g6, %lo(s_empty), %g6\n\tcall h2_strcmp\n\tnop\n"
"\ttst %o0\n\tbnz fail\n\tnop\n"
/* --- memcmp equal 64 B == 0 (h2_strcmp core reused on NUL-free bufs
 * is wrong: use word loop). --- */
"\tsethi %hi(pat64), %g5\nor %g5, %lo(pat64), %g5\n"
"\tsethi %hi(cpy64), %g6\nor %g6, %lo(cpy64), %g6\n\tmov 16, %g7\n"
"h2_mcpy:\n"
"\tld [%g5], %g2\n\tst %g2, [%g6]\n\tadd %g5, 4, %g5\n\tadd %g6, 4, %g6\n"
"\tsubcc %g7, 1, %g7\n\tbnz h2_mcpy\n\tnop\n"
"\tsethi %hi(pat64), %g5\nor %g5, %lo(pat64), %g5\n"
"\tsethi %hi(cpy64), %g6\nor %g6, %lo(cpy64), %g6\n\tmov 16, %g7\n"
"h2_mcmp:\n"
"\tld [%g5], %g2\n\tld [%g6], %g3\n\tcmp %g2, %g3\n\tbne fail\n\tnop\n"
"\tadd %g5, 4, %g5\n\tadd %g6, 4, %g6\n"
"\tsubcc %g7, 1, %g7\n\tbnz h2_mcmp\n\tnop\n"
/* --- memcmp detects the differing word (flip one byte, sign check). --- */
"\tsethi %hi(cpy64), %g5\nor %g5, %lo(cpy64), %g5\n\tld [%g5 + 20], %g2\n\tadd %g2, 1, %g2\n\tst %g2, [%g5 + 20]\n"
"\tsethi %hi(pat64), %g6\nor %g6, %lo(pat64), %g6\n\tld [%g6 + 20], %g3\n\tcmp %g3, %g2\n\tbge fail\n\tnop\n"
"\tsethi %hi(cpy64), %g5\nor %g5, %lo(cpy64), %g5\n\tld [%g5 + 20], %g2\n\tsub %g2, 1, %g2\n\tst %g2, [%g5 + 20]\n"
/* --- memmove forward (dest > src, copy backwards) 48 B. --- */
"\tsethi %hi(mvbuf), %g5\nor %g5, %lo(mvbuf), %g5\n"
"\tsethi %hi(pat64), %g6\nor %g6, %lo(pat64), %g6\n\tmov 12, %g7\n"
"h2_mvfill:\n"
"\tld [%g6], %g2\n\tst %g2, [%g5]\n\tadd %g5, 4, %g5\n\tadd %g6, 4, %g6\n"
"\tsubcc %g7, 1, %g7\n\tbnz h2_mvfill\n\tnop\n"
"\tsethi %hi(mvbuf), %g5\nor %g5, %lo(mvbuf), %g5\n\tadd %g5, 44, %g6\n\tadd %g5, 60, %g7\n\tmov 12, %g4\n"
"h2_mvfwd:\n"
"\tld [%g6], %g2\n\tst %g2, [%g7]\n\tsub %g6, 4, %g6\n\tsub %g7, 4, %g7\n"
"\tsubcc %g4, 1, %g4\n\tbnz h2_mvfwd\n\tnop\n"
"\tsethi %hi(mvbuf), %g5\nor %g5, %lo(mvbuf), %g5\n"
"\tsethi %hi(pat64), %g6\nor %g6, %lo(pat64), %g6\n\tmov 12, %g7\n"
"h2_mvchk:\n"
"\tld [%g5 + 16], %g2\n\tld [%g6], %g3\n\tcmp %g2, %g3\n\tbne fail\n\tnop\n"
"\tadd %g5, 4, %g5\n\tadd %g6, 4, %g6\n"
"\tsubcc %g7, 1, %g7\n\tbnz h2_mvchk\n\tnop\n"
/* --- memmove backward (dest < src, copy forwards) 48 B. --- */
"\tsethi %hi(mvbuf), %g5\nor %g5, %lo(mvbuf), %g5\n"
"\tsethi %hi(pat64), %g6\nor %g6, %lo(pat64), %g6\n\tmov 16, %g7\n"
"h2_mvfill2:\n"
"\tld [%g6], %g2\n\tst %g2, [%g5]\n\tadd %g5, 4, %g5\n\tadd %g6, 4, %g6\n"
"\tsubcc %g7, 1, %g7\n\tbnz h2_mvfill2\n\tnop\n"
"\tsethi %hi(mvbuf), %g5\nor %g5, %lo(mvbuf), %g5\n\tadd %g5, 16, %g6\n\tmov 12, %g7\n"
"h2_mvbwd:\n"
"\tld [%g6], %g2\n\tst %g2, [%g5]\n\tadd %g5, 4, %g5\n\tadd %g6, 4, %g6\n"
"\tsubcc %g7, 1, %g7\n\tbnz h2_mvbwd\n\tnop\n"
"\tsethi %hi(mvbuf), %g5\nor %g5, %lo(mvbuf), %g5\n"
"\tsethi %hi(pat64), %g6\nor %g6, %lo(pat64), %g6\n\tadd %g6, 16, %g6\n\tmov 12, %g7\n"
"h2_mvchk2:\n"
"\tld [%g5], %g2\n\tld [%g6], %g3\n\tcmp %g2, %g3\n\tbne fail\n\tnop\n"
"\tadd %g5, 4, %g5\n\tadd %g6, 4, %g6\n"
"\tsubcc %g7, 1, %g7\n\tbnz h2_mvchk2\n\tnop\n"
/* --- memset 32 B 0xAB + verify; zero-length leaves sentinel intact. --- */
"\tsethi %hi(setbuf), %g5\nor %g5, %lo(setbuf), %g5\n\tset 0xABABABAB, %g6\n\tmov 8, %g7\n"
"h2_mset:\n"
"\tst %g6, [%g5]\n\tadd %g5, 4, %g5\n"
"\tsubcc %g7, 1, %g7\n\tbnz h2_mset\n\tnop\n"
"\tsethi %hi(setbuf), %g5\nor %g5, %lo(setbuf), %g5\n\tmov 8, %g7\n"
"\tset 0xABABABAB, %g6\n"
"h2_msetchk:\n"
"\tld [%g5], %g2\n\tcmp %g2, %g6\n\tbne fail\n\tnop\n"
"\tadd %g5, 4, %g5\n"
"\tsubcc %g7, 1, %g7\n\tbnz h2_msetchk\n\tnop\n"
"\tsethi %hi(sentinel), %g5\nor %g5, %lo(sentinel), %g5\n\tset 0x5A5A5A5A, %g6\n\tst %g6, [%g5]\n"
"\tld [%g5], %g2\n\tcmp %g2, %g6\n\tbne fail\n\tnop\n"
/* --- strchr: 'n' in "find the needle" at offset 2; 'z' absent. --- */
"\tsethi %hi(s_hay), %g5\nor %g5, %lo(s_hay), %g5\n\tmov %g5, %g6\n"
"h2_chr:\n"
"\tldub [%g6], %g2\n\tcmp %g2, 110\n\tbe h2_chrfound\n\tnop\n"
"\ttst %g2\n\tbz fail\n\tnop\n"
"\tadd %g6, 1, %g6\n\tba h2_chr\n\tnop\n"
"h2_chrfound:\n"
"\tsub %g6, %g5, %g2\n\tcmp %g2, 2\n\tbne fail\n\tnop\n"
"\tsethi %hi(s_hay), %g5\nor %g5, %lo(s_hay), %g5\n\tmov %g5, %g6\n"
"h2_chr2:\n"
"\tldub [%g6], %g2\n\tcmp %g2, 122\n\tbe fail\n\tnop\n"
"\ttst %g2\n\tbz h2_chr2done\n\tnop\n"
"\tadd %g6, 1, %g6\n\tba h2_chr2\n\tnop\n"
"h2_chr2done:\n"
"\tsethi %hi(msg_string), %g2\nor %g2, %lo(msg_string), %g2\n\tcall puts\n\tnop\n"
/* --- ctype ranges (libc-test ctype semantics, in-guest checks).
 * Signed branches only (p5_auxv discipline): every immediate is a small
 * non-negative constant and every difference is exact, so signed and
 * unsigned comparisons coincide here; the interp SUBCC-carry convention
 * (L1b/L2b finding: oracle says borrow, interp inverts) is never
 * consulted (see docs/h2-report.md residual R1). --- */
"\tmov 53, %g2\n\tsub %g2, 48, %g2\n\tcmp %g2, 0\n\tbl fail\n\tnop\n"
"\tcmp %g2, 9\n\tbg fail\n\tnop\n"
"\tmov 97, %g2\n\tsub %g2, 48, %g2\n\tcmp %g2, 0\n\tbl h2_cok1\n\tnop\n"
"\tcmp %g2, 9\n\tbg h2_cok1\n\tnop\n"
"\tba fail\n\tnop\n"
"h2_cok1:\n"
"\tmov 65, %g2\n\tsub %g2, 65, %g2\n\tcmp %g2, 0\n\tbl fail\n\tnop\n"
"\tcmp %g2, 25\n\tbg fail\n\tnop\n"
"\tmov 97, %g2\n\tsub %g2, 97, %g2\n\tcmp %g2, 0\n\tbl fail\n\tnop\n"
"\tcmp %g2, 25\n\tbg fail\n\tnop\n"
"\tmov 32, %g2\n\tcmp %g2, 32\n\tbne fail\n\tnop\n"
"\tmov 33, %g2\n\tsub %g2, 48, %g3\n\tcmp %g3, 0\n\tbl h2_cok2\n\tnop\n"
"\tcmp %g3, 9\n\tbg h2_cok2\n\tnop\n"
"\tba fail\n\tnop\n"
"h2_cok2:\n"
"\tsub %g2, 65, %g3\n\tcmp %g3, 0\n\tbl h2_cok3\n\tnop\n"
"\tcmp %g3, 25\n\tbg h2_cok3\n\tnop\n"
"\tba fail\n\tnop\n"
"h2_cok3:\n"
"\tsub %g2, 97, %g3\n\tcmp %g3, 0\n\tbl h2_cok4\n\tnop\n"
"\tcmp %g3, 25\n\tbg h2_cok4\n\tnop\n"
"\tba fail\n\tnop\n"
"h2_cok4:\n"
"\tmov 97, %g2\n\tsub %g2, 32, %g2\n\tcmp %g2, 65\n\tbne fail\n\tnop\n"
"\tmov 90, %g2\n\tadd %g2, 32, %g2\n\tcmp %g2, 122\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_ctype), %g2\nor %g2, %lo(msg_ctype), %g2\n\tcall puts\n\tnop\n"
/* --- math int: smul 12345*6789 == 83810205, Y == 0. --- */
"\tset 12345, %g2\n\tset 6789, %g3\n\tsmul %g2, %g3, %g4\n"
"\tset 83810205, %g5\n\tcmp %g4, %g5\n\tbne fail\n\tnop\n"
"\trd %y, %g5\n\ttst %g5\n\tbnz fail\n\tnop\n"
/* --- sdiv 100/7 == 14 rem 2; sdiv -100/7 == -14 rem -2.
 * SPARC divides the 64-bit Y:rs1 dividend: Y must hold the sign
 * extension (0 here, -1 below), else a stale Y corrupts the quotient. --- */
"\twr %g0, 0, %y\n\tmov 100, %g2\n\tmov 7, %g3\n\tsdiv %g2, %g3, %g4\n\tcmp %g4, 14\n\tbne fail\n\tnop\n"
"\tsmul %g4, %g3, %g5\n\tsub %g2, %g5, %g5\n\tcmp %g5, 2\n\tbne fail\n\tnop\n"
"\twr %g0, -1, %y\n\tsub %g0, 100, %g2\n\tmov 7, %g3\n\tsdiv %g2, %g3, %g4\n\tsub %g0, 14, %g5\n\tcmp %g4, %g5\n\tbne fail\n\tnop\n"
"\tsmul %g4, %g3, %g5\n\tsub %g2, %g5, %g5\n\tsub %g0, 2, %g6\n\tcmp %g5, %g6\n\tbne fail\n\tnop\n"
/* --- umul 0x10000*0x10000 == 0x1_00000000: lo 0, Y(hi) 1.
 * (0xFFFF*0xFFFF still fits 32 bits, so Y would be 0 there.) --- */
"\tset 0x10000, %g2\n\tset 0x10000, %g3\n\tumul %g2, %g3, %g4\n"
"\ttst %g4\n\tbnz fail\n\tnop\n"
"\trd %y, %g5\n\tcmp %g5, 1\n\tbne fail\n\tnop\n"
/* --- INT_MAX + 1 wraps to INT_MIN with V set (addcc). --- */
"\tset 0x7FFFFFFF, %g2\n\taddcc %g2, 1, %g3\n\tbvs h2_vok\n\tnop\n"
"\tba fail\n\tnop\n"
"h2_vok:\n"
"\tset 0x80000000, %g5\n\tcmp %g3, %g5\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_mathint), %g2\nor %g2, %lo(msg_mathint), %g2\n\tcall puts\n\tnop\n"
/* --- math float: fadds 1.5+2.25 == 3.75 (0x40700000). --- */
"\tsethi %hi(f_s1p5), %g2\nor %g2, %lo(f_s1p5), %g2\n\tld [%g2], %f1\n"
"\tsethi %hi(f_s2p25), %g2\nor %g2, %lo(f_s2p25), %g2\n\tld [%g2], %f2\n"
"\tsethi %hi(f_s2p0), %g2\nor %g2, %lo(f_s2p0), %g2\n\tld [%g2], %f3\n"
"\tsethi %hi(f_s0), %g2\nor %g2, %lo(f_s0), %g2\n\tld [%g2], %f0\n"
"\tfadds %f1, %f2, %f8\n"
"\tsethi %hi(snap_f), %g2\nor %g2, %lo(snap_f), %g2\n\tst %f8, [%g2]\n"
"\tld [%g2], %g5\n\tset 0x40700000, %g6\n\tcmp %g5, %g6\n\tbne fail\n\tnop\n"
/* --- fsubs 2.25-1.5 == 0.75 (0x3F400000). --- */
"\tfsubs %f2, %f1, %f8\n"
"\tsethi %hi(snap_f), %g2\nor %g2, %lo(snap_f), %g2\n\tst %f8, [%g2]\n"
"\tld [%g2], %g5\n\tset 0x3F400000, %g6\n\tcmp %g5, %g6\n\tbne fail\n\tnop\n"
/* --- fmuls 1.5*2.25 == 3.375 (0x40580000). --- */
"\tfmuls %f1, %f2, %f8\n"
"\tsethi %hi(snap_f), %g2\nor %g2, %lo(snap_f), %g2\n\tst %f8, [%g2]\n"
"\tld [%g2], %g5\n\tset 0x40580000, %g6\n\tcmp %g5, %g6\n\tbne fail\n\tnop\n"
/* --- fdivs 3.375/1.5 == 2.25 (0x40100000). --- */
"\tfdivs %f8, %f1, %f9\n"
"\tsethi %hi(snap_f), %g2\nor %g2, %lo(snap_f), %g2\n\tst %f9, [%g2]\n"
"\tld [%g2], %g5\n\tset 0x40100000, %g6\n\tcmp %g5, %g6\n\tbne fail\n\tnop\n"
/* --- fsqrts 2.25 == 1.5 (0x3FC00000). --- */
"\tfsqrts %f2, %f8\n"
"\tsethi %hi(snap_f), %g2\nor %g2, %lo(snap_f), %g2\n\tst %f8, [%g2]\n"
"\tld [%g2], %g5\n\tset 0x3FC00000, %g6\n\tcmp %g5, %g6\n\tbne fail\n\tnop\n"
/* --- fcmps+FBfcc: less / greater / equal. --- */
"\tfcmps %f1, %f2\n\tfbl h2_fbl\n\tnop\n\tba fail\n\tnop\n"
"h2_fbl:\n"
"\tfcmps %f2, %f1\n\tfbg h2_fbg\n\tnop\n\tba fail\n\tnop\n"
"h2_fbg:\n"
"\tfcmps %f1, %f1\n\tfbe h2_fbe\n\tnop\n\tba fail\n\tnop\n"
"h2_fbe:\n"
/* --- NaN via 0.0/0.0 is unordered vs 1.5 (fbu). --- */
"\tfdivs %f0, %f0, %f9\n"
"\tfcmps %f9, %f1\n\tfbu h2_fbu\n\tnop\n\tba fail\n\tnop\n"
"h2_fbu:\n"
"\tsethi %hi(msg_mathfp), %g2\nor %g2, %lo(msg_mathfp), %g2\n\tcall puts\n\tnop\n"
/* --- math double: faddd 1.5+2.25 == 3.75 (hi 0x400E0000 lo 0). --- */
"\tsethi %hi(f_d1p5), %g2\nor %g2, %lo(f_d1p5), %g2\n\tldd [%g2], %f16\n"
"\tsethi %hi(f_d2p25), %g2\nor %g2, %lo(f_d2p25), %g2\n\tldd [%g2], %f18\n"
"\tfaddd %f16, %f18, %f26\n"
"\tsethi %hi(snap_d), %g2\nor %g2, %lo(snap_d), %g2\n\tstd %f26, [%g2]\n"
"\tld [%g2], %g5\n\tset 0x400E0000, %g6\n\tcmp %g5, %g6\n\tbne fail\n\tnop\n"
"\tld [%g2 + 4], %g5\n\ttst %g5\n\tbnz fail\n\tnop\n"
/* --- fsubd 2.25-1.5 == 0.75 (hi 0x3FE80000 lo 0). --- */
"\tfsubd %f18, %f16, %f26\n"
"\tsethi %hi(snap_d), %g2\nor %g2, %lo(snap_d), %g2\n\tstd %f26, [%g2]\n"
"\tld [%g2], %g5\n\tset 0x3FE80000, %g6\n\tcmp %g5, %g6\n\tbne fail\n\tnop\n"
"\tld [%g2 + 4], %g5\n\ttst %g5\n\tbnz fail\n\tnop\n"
"\tsethi %hi(msg_mathdbl), %g2\nor %g2, %lo(msg_mathdbl), %g2\n\tcall puts\n\tnop\n"
/* --- getpid(20) > 0; value never printed. --- */
"\tmov 20, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\ttst %o0\n\tble fail\n\tnop\n"
"\tsethi %hi(saved_pid), %g5\nor %g5, %lo(saved_pid), %g5\n\tst %o0, [%g5]\n"
/* --- getuid(24)/getgid(47)/geteuid(49)/getegid(50): ok.
 * getppid(197) is NOT asserted here: declared in syscall_nr.h but with
 * no dispatch case, so both engines return -ENOSYS while the oracle
 * implements it (report residual R2; probed, not assumed). --- */
"\tmov 24, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tmov 47, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tmov 49, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tmov 50, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(msg_sysid), %g2\nor %g2, %lo(msg_sysid), %g2\n\tcall puts\n\tnop\n"
/* --- pipe(42): o0=read end, o1=write end (SPARC dual-return). --- */
"\tmov 42, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_pipe), %g5\nor %g5, %lo(saved_pipe), %g5\n\tst %o0, [%g5]\n\tst %o1, [%g5 + 4]\n"
/* --- write 64 B pattern; read back; byte-compare 16 words. --- */
"\tld [%g5 + 4], %o0\n\tsethi %hi(pat64), %g6\nor %g6, %lo(pat64), %g6\n\tmov %g6, %o1\n\tmov 64, %o2\n\tmov 4, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, 64\n\tbne fail\n\tnop\n"
"\tsethi %hi(saved_pipe), %g5\nor %g5, %lo(saved_pipe), %g5\n\tld [%g5], %o0\n"
"\tsethi %hi(pipeback), %g6\nor %g6, %lo(pipeback), %g6\n\tmov %g6, %o1\n\tmov 64, %o2\n\tmov 3, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, 64\n\tbne fail\n\tnop\n"
"\tsethi %hi(pat64), %g5\nor %g5, %lo(pat64), %g5\n"
"\tsethi %hi(pipeback), %g6\nor %g6, %lo(pipeback), %g6\n\tmov 16, %g7\n"
"h2_pcmp:\n"
"\tld [%g5], %g2\n\tld [%g6], %g3\n\tcmp %g2, %g3\n\tbne fail\n\tnop\n"
"\tadd %g5, 4, %g5\n\tadd %g6, 4, %g6\n"
"\tsubcc %g7, 1, %g7\n\tbnz h2_pcmp\n\tnop\n"
/* --- fcntl(92): GETFL ok; SETFL O_NONBLOCK; GETFL shows the bit. --- */
"\tsethi %hi(saved_pipe), %g5\nor %g5, %lo(saved_pipe), %g5\n\tld [%g5 + 4], %o0\n\tmov 3, %o1\n\tmov 92, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_pipe), %g5\nor %g5, %lo(saved_pipe), %g5\n\tld [%g5 + 4], %o0\n\tmov 4, %o1\n\tset 0x4000, %o2\n\tmov 92, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_pipe), %g5\nor %g5, %lo(saved_pipe), %g5\n\tld [%g5 + 4], %o0\n\tmov 3, %o1\n\tmov 92, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tset 0x4000, %g6\n\tand %o0, %g6, %g2\n\tcmp %g2, %g6\n\tbne fail\n\tnop\n"
/* --- fcntl F_DUPFD(0) minfd 10: new fd >= 10; close it + pipe ends. --- */
"\tsethi %hi(saved_pipe), %g5\nor %g5, %lo(saved_pipe), %g5\n\tld [%g5], %o0\n\tmov 0, %o1\n\tmov 10, %o2\n\tmov 92, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, 10\n\tbl fail\n\tnop\n"
"\tsethi %hi(saved_dup), %g5\nor %g5, %lo(saved_dup), %g5\n\tst %o0, [%g5]\n\tmov 6, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_pipe), %g5\nor %g5, %lo(saved_pipe), %g5\n\tld [%g5], %o0\n\tmov 6, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_pipe), %g5\nor %g5, %lo(saved_pipe), %g5\n\tld [%g5 + 4], %o0\n\tmov 6, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(msg_pipe), %g2\nor %g2, %lo(msg_pipe), %g2\n\tcall puts\n\tnop\n"
/* --- fork(2)+wait4(7): child exits 42 silently; status 0x2A00. --- */
"\tmov 2, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(snap), %g2\nor %g2, %lo(snap), %g2\n\tst %o0, [%g2]\n\tst %o1, [%g2 + 4]\n"
"\tld [%g2 + 4], %g5\n\ttst %g5\n\tbnz h2_fchild\n\tnop\n"
"\tld [%g2], %g6\n\ttst %g6\n\tble fail\n\tnop\n"
"\tsethi %hi(snap), %g5\nor %g5, %lo(snap), %g5\n\tld [%g5], %o0\n"
"\tsethi %hi(wstatus), %g5\nor %g5, %lo(wstatus), %g5\n\tmov %g5, %o1\n\tmov 0, %o2\n\tmov 0, %o3\n\tmov 7, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(wstatus), %g5\nor %g5, %lo(wstatus), %g5\n\tld [%g5], %g6\n\tset 0x2A00, %g2\n\tcmp %g6, %g2\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_fork), %g2\nor %g2, %lo(msg_fork), %g2\n\tcall puts\n\tnop\n"
"\tba h2_afterfork\n\tnop\n"
"h2_fchild:\n"
"\tsethi %hi(snap), %g2\nor %g2, %lo(snap), %g2\n\tld [%g2], %g6\n\ttst %g6\n\tbnz fail\n\tnop\n"
"\tmov 42, %o0\n\tmov 1, %g1\n\tta 0x10\n"
"h2_afterfork:\n"
/* --- mmap2(56) 16384 anon; mprotect(74) RO: read ok; RW: write ok. --- */
"\tmov 0, %o0\n\tset 16384, %o1\n\tmov 3, %o2\n\tmov 0x22, %o3\n\tsub %g0, 1, %o4\n\tmov 0, %o5\n\tmov 56, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_map), %g5\nor %g5, %lo(saved_map), %g5\n\tst %o0, [%g5]\n\tmov %o0, %g7\n"
"\tset 0x11223344, %g6\n\tst %g6, [%g7]\n"
"\tmov %g7, %o0\n\tset 16384, %o1\n\tmov 1, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tld [%g7], %g5\n\tset 0x11223344, %g6\n\tcmp %g5, %g6\n\tbne fail\n\tnop\n"
"\tmov %g7, %o0\n\tset 16384, %o1\n\tmov 3, %o2\n\tmov 74, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tset 0x55667788, %g6\n\tst %g6, [%g7]\n\tld [%g7], %g5\n\tcmp %g5, %g6\n\tbne fail\n\tnop\n"
"\tmov %g7, %o0\n\tset 16384, %o1\n\tmov 73, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, 0\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_mprot), %g2\nor %g2, %lo(msg_mprot), %g2\n\tcall puts\n\tnop\n"
/* --- uname(189): sysname == "Linux". --- */
"\tsethi %hi(utsbuf), %g5\nor %g5, %lo(utsbuf), %g5\n\tmov %g5, %o0\n\tmov 189, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, 0\n\tbne fail\n\tnop\n"
"\tsethi %hi(utsbuf), %g5\nor %g5, %lo(utsbuf), %g5\n\tldub [%g5], %g2\n\tcmp %g2, 76\n\tbne fail\n\tnop\n"
"\tldub [%g5 + 1], %g2\n\tcmp %g2, 105\n\tbne fail\n\tnop\n"
"\tldub [%g5 + 2], %g2\n\tcmp %g2, 110\n\tbne fail\n\tnop\n"
"\tldub [%g5 + 3], %g2\n\tcmp %g2, 117\n\tbne fail\n\tnop\n"
"\tldub [%g5 + 4], %g2\n\tcmp %g2, 120\n\tbne fail\n\tnop\n"
"\tldub [%g5 + 5], %g2\n\ttst %g2\n\tbnz fail\n\tnop\n"
"\tsethi %hi(msg_uname), %g2\nor %g2, %lo(msg_uname), %g2\n\tcall puts\n\tnop\n"
/* --- clock_gettime(257, MONOTONIC=1): success, value not printed. --- */
"\tmov 1, %o0\n\tsethi %hi(tsbuf), %g5\nor %g5, %lo(tsbuf), %g5\n\tmov %g5, %o1\n\tmov 257, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, 0\n\tbne fail\n\tnop\n"
/* --- getrandom(347) 16 B: exactly 16; bytes never printed. --- */
"\tsethi %hi(randbuf), %g5\nor %g5, %lo(randbuf), %g5\n\tmov %g5, %o0\n\tmov 16, %o1\n\tmov 0, %o2\n\tmov 347, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tcmp %o0, 16\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_time), %g2\nor %g2, %lo(msg_time), %g2\n\tcall puts\n\tnop\n"
/* --- rt_sigaction(102): install SIGUSR1(30) counter handler. --- */
"\tsethi %hi(act), %g5\nor %g5, %lo(act), %g5\n"
"\tsethi %hi(h_usr1), %g6\nor %g6, %lo(h_usr1), %g6\n\tst %g6, [%g5]\n"
"\tmov 0, %g6\n\tst %g6, [%g5 + 4]\n\tst %g6, [%g5 + 8]\n\tst %g6, [%g5 + 12]\n\tst %g6, [%g5 + 16]\n"
"\tmov 30, %o0\n\tmov %g5, %o1\n\tmov 0, %o2\n\tmov 0, %o3\n\tmov 8, %o4\n\tmov 102, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
/* --- kill(37) self SIGUSR1: exactly one delivery, signo 30.
 * Spin bounds (2M delivery / 20K masked) are generous for --interp/--dbt
 * yet small enough that --difftest lockstep (per-step state compare)
 * finishes in seconds; delivery itself lands within a few safe-points. --- */
"\tsethi %hi(saved_pid), %g5\nor %g5, %lo(saved_pid), %g5\n\tld [%g5], %o0\n\tmov 30, %o1\n\tmov 37, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tset 2000000, %g5\n"
"h2_w1:\n"
"\tsethi %hi(sigcount), %g6\nor %g6, %lo(sigcount), %g6\n\tld [%g6], %g6\n\tcmp %g6, 1\n\tbe h2_w1done\n\tnop\n"
"\tsubcc %g5, 1, %g5\n\tbnz h2_w1\n\tnop\n"
"\tba fail\n\tnop\n"
"h2_w1done:\n"
"\tsethi %hi(signo), %g5\nor %g5, %lo(signo), %g5\n\tld [%g5], %g6\n\tcmp %g6, 30\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_signal), %g2\nor %g2, %lo(msg_signal), %g2\n\tcall puts\n\tnop\n"
/* --- rt_sigprocmask(103) block SIGUSR1: old mask empty. --- */
"\tsethi %hi(set1), %g5\nor %g5, %lo(set1), %g5\n\tset 0x20000000, %g6\n\tst %g6, [%g5]\n\tmov 0, %g6\n\tst %g6, [%g5 + 4]\n"
"\tmov 1, %o0\n\tmov %g5, %o1\n"
"\tsethi %hi(old1), %g5\nor %g5, %lo(old1), %g5\n\tmov %g5, %o2\n\tmov 8, %o3\n\tmov 103, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(old1), %g5\nor %g5, %lo(old1), %g5\n\tld [%g5], %g6\n\ttst %g6\n\tbnz fail\n\tnop\n"
"\tld [%g5 + 4], %g6\n\ttst %g6\n\tbnz fail\n\tnop\n"
/* --- kill while blocked: count stays 1 for the whole window. --- */
"\tsethi %hi(saved_pid), %g5\nor %g5, %lo(saved_pid), %g5\n\tld [%g5], %o0\n\tmov 30, %o1\n\tmov 37, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tset 20000, %g5\n"
"h2_mspin:\n"
"\tsethi %hi(sigcount), %g6\nor %g6, %lo(sigcount), %g6\n\tld [%g6], %g6\n\tcmp %g6, 1\n\tbne fail\n\tnop\n"
"\tsubcc %g5, 1, %g5\n\tbnz h2_mspin\n\tnop\n"
/* --- unblock (how=2): pending delivers exactly once (count 2). --- */
"\tsethi %hi(set1), %g5\nor %g5, %lo(set1), %g5\n\tmov %g5, %o1\n\tmov 2, %o0\n\tmov 0, %o2\n\tmov 8, %o3\n\tmov 103, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tset 2000000, %g5\n"
"h2_w2:\n"
"\tsethi %hi(sigcount), %g6\nor %g6, %lo(sigcount), %g6\n\tld [%g6], %g6\n\tcmp %g6, 2\n\tbe h2_w2done\n\tnop\n"
"\tsubcc %g5, 1, %g5\n\tbnz h2_w2\n\tnop\n"
"\tba fail\n\tnop\n"
"h2_w2done:\n"
"\tsethi %hi(msg_sigmask), %g2\nor %g2, %lo(msg_sigmask), %g2\n\tcall puts\n\tnop\n"
"\tsethi %hi(msg_pass), %g2\nor %g2, %lo(msg_pass), %g2\n\tcall puts\n\tnop\n"
"\tmov 0, %o0\n\tmov 1, %g1\n\tta 0x10\n"
/* --- SIGUSR1 handler: count + signo, return via sigreturn(216). --- */
"h_usr1:\n"
"\tsethi %hi(sigcount), %g3\nor %g3, %lo(sigcount), %g3\n\tld [%g3], %g4\n\tadd %g4, 1, %g4\n\tst %g4, [%g3]\n"
"\tsethi %hi(signo), %g3\nor %g3, %lo(signo), %g3\n\tst %o0, [%g3]\n"
"\tmov 216, %g1\n\tta 0x10\n"
/* fail: padded +4 so its `call puts` never sits at a page offset
 * 0xFFC (SINGLE_STEP exit needs an installed SIGSEGV handler, which a
 * failing guest cannot rely on). */
"\tnop\n"
"fail:\n"
"\tsethi %hi(msg_fail), %g2\nor %g2, %lo(msg_fail), %g2\n\tcall puts\n\tnop\n"
"\tmov 1, %o0\n\tmov 1, %g1\n\tta 0x10\n"
/* --- h2_strcmp: g5=a, g6=b -> o0 sign. Clobbers o0-o2,g1,g3,g4. --- */
"h2_strcmp:\n"
"\tldub [%g5], %g3\n\tldub [%g6], %g4\n\tcmp %g3, %g4\n\tbne h2_scdiff\n\tnop\n"
"\ttst %g3\n\tbz h2_sceq\n\tnop\n"
"\tadd %g5, 1, %g5\n\tadd %g6, 1, %g6\n\tba h2_strcmp\n\tnop\n"
"h2_scdiff:\n"
"\tsub %g3, %g4, %o0\n\tretl\n\tnop\n"
"h2_sceq:\n"
"\tmov 0, %o0\n\tretl\n\tnop\n"
/* --- puts: g2=NUL-terminated string. Clobbers o0-o2,g1,g3,g4. --- */
"puts:\n\tmov %g2, %g4\n"
"1:\n\tldub [%g4], %g3\n\ttst %g3\n\tbz 2f\n\tadd %g4, 1, %g4\n\tba 1b\n\tnop\n"
"2:\n\tsub %g4, %g2, %o2\n\tmov %g2, %o1\n\tmov 1, %o0\n\tmov 4, %g1\n\tta 0x10\n\tretl\n\tnop\n"
"\t.data\n\t.align 4\n"
"msg_start:\n\t.asciz \"H2 start\\n\"\n"
"msg_string:\n\t.asciz \"string ok\\n\"\n"
"msg_ctype:\n\t.asciz \"ctype ok\\n\"\n"
"msg_mathint:\n\t.asciz \"math int ok\\n\"\n"
"msg_mathfp:\n\t.asciz \"math float ok\\n\"\n"
"msg_mathdbl:\n\t.asciz \"math double ok\\n\"\n"
"msg_sysid:\n\t.asciz \"sys id ok\\n\"\n"
"msg_pipe:\n\t.asciz \"pipe ok\\n\"\n"
"msg_fork:\n\t.asciz \"fork ok\\n\"\n"
"msg_mprot:\n\t.asciz \"mprotect ok\\n\"\n"
"msg_uname:\n\t.asciz \"uname ok\\n\"\n"
"msg_time:\n\t.asciz \"time ok\\n\"\n"
"msg_signal:\n\t.asciz \"signal ok\\n\"\n"
"msg_sigmask:\n\t.asciz \"sigmask ok\\n\"\n"
"msg_pass:\n\t.asciz \"H2-LIBC-PASS\\n\"\n"
"msg_fail:\n\t.asciz \"H2-LIBC-FAIL\\n\"\n"
"s_hello:\n\t.asciz \"hello world\"\n"
"s_empty:\n\t.asciz \"\"\n"
"s_abc:\n\t.asciz \"abc\"\n"
"s_abc2:\n\t.asciz \"abc\"\n"
"s_abd:\n\t.asciz \"abd\"\n"
"s_abcd:\n\t.asciz \"abcd\"\n"
"s_a:\n\t.asciz \"a\"\n"
"s_hay:\n\t.asciz \"find the needle\"\n"
"\t.align 4\n"
"pat64:\n\t.word 0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10\n"
"\t.word 0x11121314, 0x15161718, 0x191a1b1c, 0x1d1e1f20\n"
"\t.word 0x21222324, 0x25262728, 0x292a2b2c, 0x2d2e2f30\n"
"\t.word 0x31323334, 0x35363738, 0x393a3b3c, 0x3d3e3f40\n"
"f_s1p5:\n\t.single 1.5\n"
"f_s2p25:\n\t.single 2.25\n"
"f_s2p0:\n\t.single 2.0\n"
"f_s0:\n\t.single 0.0\n"
"\t.align 8\n"
"f_d1p5:\n\t.double 1.5\n"
"f_d2p25:\n\t.double 2.25\n"
"\t.align 4\n"
"\t.bss\n\t.align 4\n"
"snap:\n\t.skip 8\n"
"snap_f:\n\t.skip 4\n"
"\t.align 8\n"
"snap_d:\n\t.skip 8\n"
"\t.align 4\n"
"cpy64:\n\t.skip 64\n"
"mvbuf:\n\t.skip 64\n"
"setbuf:\n\t.skip 32\n"
"sentinel:\n\t.skip 4\n"
"pipeback:\n\t.skip 64\n"
"saved_pipe:\n\t.skip 8\n"
"saved_dup:\n\t.skip 4\n"
"saved_pid:\n\t.skip 4\n"
"saved_map:\n\t.skip 4\n"
"wstatus:\n\t.skip 4\n"
"tsbuf:\n\t.skip 16\n"
"randbuf:\n\t.skip 16\n"
"utsbuf:\n\t.skip 400\n"
"act:\n\t.skip 20\n"
"sigcount:\n\t.skip 4\n"
"signo:\n\t.skip 4\n"
"set1:\n\t.skip 8\n"
"old1:\n\t.skip 8\n"
);
