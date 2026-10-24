/*
 * tests/test_p4_threads.c — Phase 4 threading guest (freestanding, V8-only).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Exercises the L4a thread/process surface with raw `ta 0x10` traps
 * (no libc: freestanding top-level asm with `_start`, helper calls,
 * deterministic stdout, fail label + exit codes, after tests/test_p2_sys.c).
 * Exit 0 means every check passed.
 *
 * Covers: fork(2)+wait4(7) round-trip (E04 shape: child %o0=0/%o1=1,
 * status 0x0700 for exit(7)); clone(217) thread + shared-memory counter
 * (counter starts at 0, child adds 1000, parent adds 24 after the child
 * phase gate; exact expected total 1024); %g7 TLS independence
 * (parent %g7=PVAL by direct write, child %g7=CVAL via CLONE_SETTLS; each
 * reads its own value back after the sibling ran); futex(142) WAIT/WAKE
 * rendezvous both directions (value 0 and nonzero 0x11111111 cookies);
 * CLONE_CHILD_CLEARTID cleared on thread exit; child exit(0) ends only the
 * calling thread.
 *
 * Oracle behavior pinned under qemu-sparc -cpu LEON3 (qemu 7.2):
 * - clone arg order (qemu -strace) is BACKWARDS: o0=flags, o1=newsp,
 *   o2=parent_tidptr, o3=tls, o4=child_tidptr.
 * - Thread creation requires the glibc pthread flag set including
 *   CLONE_SYSVSEM (0x40000): flags 0x2D0F00 = CLONE_VM|CLONE_FS|
 *   CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|
 *   CLONE_CHILD_CLEARTID with exit signal 0 (a nonzero exit signal with
 *   CLONE_THREAD is EINVAL). Without CLONE_SYSVSEM qemu returns EINVAL.
 * - Futex words use plain (unswapped) values; WAIT blocks while
 *   *uaddr==val and returns EAGAIN when already different.
 * - Signal handlers must return via sigreturn(216), not rt_sigreturn(101)
 *   (the latter resumes at NULL under this qemu; probed minimal).
 *
 * Build (E-phase discipline):
 *   sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static \
 *     -o /tmp/t4t tests/test_p4_threads.c
 * Oracle: qemu-sparc -cpu LEON3 /tmp/t4t   (exit 0, deterministic stdout)
 *
 * Pure top-level asm (no libc, no C runtime). E04 discipline:
 * snapshot-before-print, helpers clobber %o0-%o2, %g1, %g3, %g4 while
 * %g5-%g7 survive (parent keeps its TLS value in %g7 across calls);
 * live values otherwise sit in .bss words. Only V8 encodings
 * (Bicc, no BPcc/BPr/membar/cas/popc/flushw). Large immediates use
 * `set`, never `mov` (simm13 overflow). No guest addresses printed
 * (mmap base/pids vary); only exact expected values are printed.
 */
__asm__(
"\t.text\n\t.align 4\n\t.global _start\n"
"_start:\n"
"\tsethi %hi(msg_start), %g2\nor %g2, %lo(msg_start), %g2\n\tcall puts\n\tnop\n"
/* --- fork(2): snapshot %o0/%o1 in both processes BEFORE calls. --- */
"\tmov 2, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(snap), %g2\nor %g2, %lo(snap), %g2\n\tst %o0, [%g2]\n\tst %o1, [%g2 + 4]\n"
"\tld [%g2 + 4], %g5\n\ttst %g5\n\tbnz is_child\n\tnop\n"
"\tld [%g2], %g6\n\ttst %g6\n\tbz is_child\n\tnop\n"
/* --- parent: child pid must be > 0, %o1 must be 0. --- */
"\tsethi %hi(snap), %g2\nor %g2, %lo(snap), %g2\n\tld [%g2], %g6\n\ttst %g6\n\tble fail\n\tnop\n"
"\tld [%g2 + 4], %g5\n\ttst %g5\n\tbnz fail\n\tnop\n"
"\tsethi %hi(msg_fork), %g2\nor %g2, %lo(msg_fork), %g2\n\tcall puts\n\tnop\n"
/* --- wait4(pid, &status, 0, NULL): expect status 0x0700 (exit(7)). --- */
"\tsethi %hi(snap), %g5\nor %g5, %lo(snap), %g5\n\tld [%g5], %o0\n"
"\tsethi %hi(wstatus), %g5\nor %g5, %lo(wstatus), %g5\n\tmov %g5, %o1\n\tmov 0, %o2\n\tmov 0, %o3\n\tmov 7, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(wstatus), %g5\nor %g5, %lo(wstatus), %g5\n\tld [%g5], %g6\n\tset 0x700, %g2\n\tcmp %g6, %g2\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_wait), %g2\nor %g2, %lo(msg_wait), %g2\n\tcall puts\n\tnop\n"
"\tba thread_part\n\tnop\n"
"is_child:\n"
/* --- child: %o0 must be 0, %o1 must be 1 (E04 SPARC marker). --- */
"\tsethi %hi(snap), %g2\nor %g2, %lo(snap), %g2\n\tld [%g2], %g6\n\ttst %g6\n\tbnz fail\n\tnop\n"
"\tld [%g2 + 4], %g5\n\tcmp %g5, 1\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_child), %g2\nor %g2, %lo(msg_child), %g2\n\tcall puts\n\tnop\n"
"\tmov 7, %o0\n\tmov 1, %g1\n\tta 0x10\n"
"thread_part:\n"
/* --- mmap 64 KiB anonymous RW for the child stack. --- */
"\tmov 0, %o0\n\tset 65536, %o1\n\tmov 3, %o2\n\tmov 0x22, %o3\n\tsub %g0, 1, %o4\n\tmov 0, %o5\n\tmov 56, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(child_sp), %g5\nor %g5, %lo(child_sp), %g5\n\tset 65472, %g6\n\tadd %o0, %g6, %o0\n\tst %o0, [%g5]\n"
/* --- shared words: counter=0, stage=0, added_c=0, child_ok=0. --- */
"\tsethi %hi(counter), %g5\nor %g5, %lo(counter), %g5\n\tmov 0, %g6\n\tst %g6, [%g5]\n"
"\tsethi %hi(stage), %g5\nor %g5, %lo(stage), %g5\n\tst %g6, [%g5]\n"
"\tsethi %hi(added_c), %g5\nor %g5, %lo(added_c), %g5\n\tst %g6, [%g5]\n"
"\tsethi %hi(child_ok), %g5\nor %g5, %lo(child_ok), %g5\n\tst %g6, [%g5]\n"
/* --- parent TLS value in %g7 (direct write; qemu keeps it per-thread). --- */
"\tset 0x13171317, %g7\n"
"\tsethi %hi(parent_g7), %g5\nor %g5, %lo(parent_g7), %g5\n\tst %g7, [%g5]\n"
/* --- counter starts at 0; child adds 1000, parent adds 24; total 1024. --- */
"\tsethi %hi(counter), %g5\nor %g5, %lo(counter), %g5\n\tmov 0, %g6\n\tst %g6, [%g5]\n"
/* --- clone(0x2D0F00, newsp, NULL, CVAL, &cleartid): BACKWARDS order. --- */
"\tset 0x2d0f00, %o0\n"
"\tsethi %hi(child_sp), %g5\nor %g5, %lo(child_sp), %g5\n\tld [%g5], %o1\n"
"\tmov 0, %o2\n\tset 0x5e5e5e5e, %o3\n"
"\tsethi %hi(cleartid), %g5\nor %g5, %lo(cleartid), %g5\n\tmov %g5, %o4\n"
"\tmov 217, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\ttst %o0\n\tbz child_entry\n\tnop\n"
/* --- parent: tid must be > 0; snapshot before any call. --- */
"\tsethi %hi(child_tid), %g5\nor %g5, %lo(child_tid), %g5\n\tst %o0, [%g5]\n\tld [%g5], %g6\n\ttst %g6\n\tble fail\n\tnop\n"
"\tsethi %hi(msg_clone), %g2\nor %g2, %lo(msg_clone), %g2\n\tcall puts\n\tnop\n"
/* --- wait for the child share gate: futex WAIT on added_c (race-free under
 * any thread scheduling; a pure spin can starve the sibling under TCG).
 * EAGAIN means already set: proceed. --- */
"\tsethi %hi(ts15s), %g5\nor %g5, %lo(ts15s), %g5\n\tmov 15, %g6\n\tst %g6, [%g5]\n\tmov 0, %g6\n\tst %g6, [%g5 + 4]\n"
"\tsethi %hi(added_c), %g5\nor %g5, %lo(added_c), %g5\n\tmov %g5, %o0\n\tmov 0, %o1\n\tmov 0, %o2\n\tsethi %hi(ts15s), %g6\nor %g6, %lo(ts15s), %g6\n\tmov %g6, %o3\n\tmov 142, %g1\n\tta 0x10\n\tbcc p_added\n\tnop\n"
"\tsethi %hi(snap), %g5\nor %g5, %lo(snap), %g5\n\tst %o0, [%g5]\n\tld [%g5], %g6\n\tcmp %g6, 11\n\tbne fail\n\tnop\n"
"p_added:\n"
/* --- child share must be exactly 1000 before the parent adds. --- */
"\tsethi %hi(counter), %g6\nor %g6, %lo(counter), %g6\n\tld [%g6], %g6\n\tset 1000, %g2\n\tcmp %g6, %g2\n\tbne fail\n\tnop\n"
/* --- parent adds 24 unit increments; exact total 1024. --- */
"\tsethi %hi(counter), %g5\nor %g5, %lo(counter), %g5\n\tmov 24, %g6\n"
"p_add:\n"
"\tld [%g5], %g2\n\tadd %g2, 1, %g2\n\tst %g2, [%g5]\n\tsubcc %g6, 1, %g6\n\tbnz p_add\n\tnop\n"
"\tld [%g5], %g6\n\tset 1024, %g2\n\tcmp %g6, %g2\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_count), %g2\nor %g2, %lo(msg_count), %g2\n\tcall puts\n\tnop\n"
"\tmov %g6, %g2\n\tcall puthex\n\tnop\n"
"\tcall putnl\n\tnop\n"
/* --- poke stage=0x11111111, wake the child. --- */
"\tsethi %hi(stage), %g5\nor %g5, %lo(stage), %g5\n\tset 0x11111111, %g6\n\tst %g6, [%g5]\n"
"\tmov %g5, %o0\n\tmov 1, %o1\n\tmov 1, %o2\n\tmov 0, %o3\n\tmov 142, %g1\n\tta 0x10\n\tnop\n"
/* --- wait for stage=0x22222222 (EAGAIN means already poked: proceed). --- */
"\tsethi %hi(ts15s), %g5\nor %g5, %lo(ts15s), %g5\n\tmov 15, %g6\n\tst %g6, [%g5]\n\tmov 0, %g6\n\tst %g6, [%g5 + 4]\n"
"\tsethi %hi(stage), %g5\nor %g5, %lo(stage), %g5\n\tmov %g5, %o0\n\tmov 0, %o1\n\tset 0x11111111, %o2\n\tsethi %hi(ts15s), %g6\nor %g6, %lo(ts15s), %g6\n\tmov %g6, %o3\n\tmov 142, %g1\n\tta 0x10\n\tbcc p_woke\n\tnop\n"
"\tsethi %hi(snap), %g5\nor %g5, %lo(snap), %g5\n\tst %o0, [%g5]\n\tld [%g5], %g6\n\tcmp %g6, 11\n\tbne fail\n\tnop\n"
"p_woke:\n"
"\tsethi %hi(stage), %g5\nor %g5, %lo(stage), %g5\n\tld [%g5], %g6\n\tset 0x22222222, %g2\n\tcmp %g6, %g2\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_stage), %g2\nor %g2, %lo(msg_stage), %g2\n\tcall puts\n\tnop\n"
"\tmov %g6, %g2\n\tcall puthex\n\tnop\n"
"\tcall putnl\n\tnop\n"
/* --- final checks: counter still 1024, child_ok, TLS both sides, cleartid. --- */
"\tsethi %hi(counter), %g5\nor %g5, %lo(counter), %g5\n\tld [%g5], %g6\n\tset 1024, %g2\n\tcmp %g6, %g2\n\tbne fail\n\tnop\n"
"\tsethi %hi(child_ok), %g5\nor %g5, %lo(child_ok), %g5\n\tld [%g5], %g6\n\tcmp %g6, 1\n\tbne fail\n\tnop\n"
"\tsethi %hi(child_g7), %g5\nor %g5, %lo(child_g7), %g5\n\tld [%g5], %g6\n\tset 0x5e5e5e5e, %g2\n\tcmp %g6, %g2\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_tlsc), %g2\nor %g2, %lo(msg_tlsc), %g2\n\tcall puts\n\tnop\n"
"\tsethi %hi(child_g7), %g5\nor %g5, %lo(child_g7), %g5\n\tld [%g5], %g2\n\tcall puthex\n\tnop\n"
"\tcall putnl\n\tnop\n"
"\tsethi %hi(parent_g7), %g5\nor %g5, %lo(parent_g7), %g5\n\tld [%g5], %g6\n\tset 0x13171317, %g2\n\tcmp %g6, %g2\n\tbne fail\n\tnop\n"
"\tset 0x13171317, %g2\n\tcmp %g7, %g2\n\tbne fail\n\tnop\n"
"\tsethi %hi(cleartid), %g5\nor %g5, %lo(cleartid), %g5\n\tld [%g5], %g6\n\ttst %g6\n\tbnz fail\n\tnop\n"
"\tsethi %hi(msg_tls), %g2\nor %g2, %lo(msg_tls), %g2\n\tcall puts\n\tnop\n"
"\tsethi %hi(msg_futex), %g2\nor %g2, %lo(msg_futex), %g2\n\tcall puts\n\tnop\n"
"\tsethi %hi(msg_pass), %g2\nor %g2, %lo(msg_pass), %g2\n\tcall puts\n\tnop\n"
"\tmov 0, %o0\n\tmov 1, %g1\n\tta 0x10\n"
"child_entry:\n"
/* --- child: %g7 must be CVAL (CLONE_SETTLS); store first (no calls yet). --- */
"\tsethi %hi(child_g7), %g5\nor %g5, %lo(child_g7), %g5\n\tst %g7, [%g5]\n"
/* --- child adds 1000 unit increments, then opens the phase gate. --- */
"\tsethi %hi(counter), %g5\nor %g5, %lo(counter), %g5\n\tset 1000, %g6\n"
"c_add:\n"
"\tld [%g5], %g2\n\tadd %g2, 1, %g2\n\tst %g2, [%g5]\n\tsubcc %g6, 1, %g6\n\tbnz c_add\n\tnop\n"
"\tsethi %hi(added_c), %g5\nor %g5, %lo(added_c), %g5\n\tmov 1, %g6\n\tst %g6, [%g5]\n"
"\tmov %g5, %o0\n\tmov 1, %o1\n\tmov 1, %o2\n\tmov 0, %o3\n\tmov 142, %g1\n\tta 0x10\n\tnop\n"
/* --- wait for stage=0x11111111 (EAGAIN means already poked: proceed). --- */
"\tsethi %hi(ts15s), %g5\nor %g5, %lo(ts15s), %g5\n\tmov 15, %g6\n\tst %g6, [%g5]\n\tmov 0, %g6\n\tst %g6, [%g5 + 4]\n"
"\tsethi %hi(stage), %g5\nor %g5, %lo(stage), %g5\n\tmov %g5, %o0\n\tmov 0, %o1\n\tmov 0, %o2\n\tsethi %hi(ts15s), %g6\nor %g6, %lo(ts15s), %g6\n\tmov %g6, %o3\n\tmov 142, %g1\n\tta 0x10\n\tbcc c_woke\n\tnop\n"
"\tsethi %hi(snap), %g5\nor %g5, %lo(snap), %g5\n\tst %o0, [%g5]\n\tld [%g5], %g6\n\tcmp %g6, 11\n\tbne fail\n\tnop\n"
"c_woke:\n"
"\tsethi %hi(stage), %g5\nor %g5, %lo(stage), %g5\n\tld [%g5], %g6\n\tset 0x11111111, %g2\n\tcmp %g6, %g2\n\tbne fail\n\tnop\n"
/* --- sibling ran: %g7 must still be CVAL; counter must be 1024 already. --- */
"\tset 0x5e5e5e5e, %g2\n\tcmp %g7, %g2\n\tbne fail\n\tnop\n"
"\tsethi %hi(counter), %g5\nor %g5, %lo(counter), %g5\n\tld [%g5], %g6\n\tset 1024, %g2\n\tcmp %g6, %g2\n\tbne fail\n\tnop\n"
/* --- answer stage=0x22222222, wake the parent, mark done. --- */
"\tsethi %hi(stage), %g5\nor %g5, %lo(stage), %g5\n\tset 0x22222222, %g6\n\tst %g6, [%g5]\n"
"\tmov %g5, %o0\n\tmov 1, %o1\n\tmov 1, %o2\n\tmov 0, %o3\n\tmov 142, %g1\n\tta 0x10\n\tnop\n"
"\tsethi %hi(child_ok), %g5\nor %g5, %lo(child_ok), %g5\n\tmov 1, %g6\n\tst %g6, [%g5]\n"
/* --- thread exit: ends only this thread (parent continues). --- */
"\tmov 0, %o0\n\tmov 1, %g1\n\tta 0x10\n"
"fail:\n"
"\tsethi %hi(msg_fail), %g2\nor %g2, %lo(msg_fail), %g2\n\tcall puts\n\tnop\n"
"\tmov 1, %o0\n\tmov 1, %g1\n\tta 0x10\n"
/* --- helpers (leaf calls; clobber o0-o2,g1,g3,g4; g5-g7 survive). --- */
"puts:\n\tmov %g2, %g4\n"
"1:\n\tldub [%g4], %g3\n\ttst %g3\n\tbz 2f\n\tadd %g4, 1, %g4\n\tba 1b\n\tnop\n"
"2:\n\tsub %g4, %g2, %o2\n\tmov %g2, %o1\n\tmov 1, %o0\n\tmov 4, %g1\n\tta 0x10\n\tretl\n\tnop\n"
"puthex:\n"
"\tsethi %hi(hexbuf), %g3\nor %g3, %lo(hexbuf), %g3\n\tmov 28, %o2\n"
"1:\n\tsrl %g2, %o2, %g4\n\tand %g4, 0xf, %g4\n\tcmp %g4, 10\n\tbl 2f\n\tnop\n"
"\tadd %g4, 'a' - 10, %g4\n\tba 3f\n\tnop\n"
"2:\n\tadd %g4, '0', %g4\n"
"3:\n\tstb %g4, [%g3]\n\tadd %g3, 1, %g3\n\tsubcc %o2, 4, %o2\n\tbge 1b\n\tnop\n"
"\tsethi %hi(hexbuf), %o1\nor %o1, %lo(hexbuf), %o1\n\tmov 1, %o0\n\tmov 8, %o2\n\tmov 4, %g1\n\tta 0x10\n\tretl\n\tnop\n"
"putnl:\n"
"\tmov 10, %g2\n\tba putc\n\tnop\n"
"putc:\n"
"\tsethi %hi(charbuf), %g3\nor %g3, %lo(charbuf), %g3\n\tstb %g2, [%g3]\n\tmov 1, %o0\n\tmov %g3, %o1\n\tmov 1, %o2\n\tmov 4, %g1\n\tta 0x10\n\tretl\n\tnop\n"
"\t.data\n\t.align 4\n"
"msg_start:\n\t.asciz \"P4-THR start\\n\"\n"
"msg_fork:\n\t.asciz \"fork parent ok\\n\"\n"
"msg_child:\n\t.asciz \"fork child ok\\n\"\n"
"msg_wait:\n\t.asciz \"wait4 status ok\\n\"\n"
"msg_clone:\n\t.asciz \"clone ok\\n\"\n"
"msg_count:\n\t.asciz \"counter=\\n\"\n"
"msg_stage:\n\t.asciz \"stage=\\n\"\n"
"msg_tlsc:\n\t.asciz \"child g7=\\n\"\n"
"msg_tls:\n\t.asciz \"tls ok\\n\"\n"
"msg_futex:\n\t.asciz \"futex ok\\n\"\n"
"msg_pass:\n\t.asciz \"P4-THR-PASS\\n\"\n"
"msg_fail:\n\t.asciz \"P4-THR-FAIL\\n\"\n"
"\t.bss\n\t.align 4\n"
"hexbuf:\n\t.skip 8\n"
"charbuf:\n\t.skip 4\n"
"snap:\n\t.skip 8\n"
"wstatus:\n\t.skip 4\n"
"child_sp:\n\t.skip 4\n"
"child_tid:\n\t.skip 4\n"
"counter:\n\t.skip 4\n"
"stage:\n\t.skip 4\n"
"added_c:\n\t.skip 4\n"
"child_ok:\n\t.skip 4\n"
"child_g7:\n\t.skip 4\n"
"parent_g7:\n\t.skip 4\n"
"cleartid:\n\t.skip 4\n"
"ts15s:\n\t.skip 8\n"
);
