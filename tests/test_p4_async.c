/*
 * tests/test_p4_async.c — Phase 4 async-signal guest (freestanding, V8-only).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Exercises rt_sigaction/kill/setitimer/sigprocmask/sigsuspend with raw
 * `ta 0x10` traps (no libc: freestanding top-level asm with `_start`,
 * helper calls, deterministic stdout, fail label + exit codes, after
 * tests/test_p2_sys.c). Exit 0 means every check passed.
 *
 * Covers: rt_sigaction(102) 5-arg install (sig, act, oact, restorer,
 * sigsetsize=8) for SIGUSR1=30 and SIGALRM=14; three acknowledged
 * self-kill(37) deliveries with exact handler-flag counts 1..3 and
 * signo==30 observed in %o0; setitimer(83) ITIMER_REAL one-shot 500 ms
 * with exact single SIGALRM delivery; rt_sigprocmask(103) BLOCK (how=1)
 * of SIGUSR1 (mask word {0x20000000,0} = bit 29 = signal 30, old mask
 * read back {0,0}) with kill-while-blocked proving no delivery, then
 * UNBLOCK (how=2; old mask read back {0x20000000,0}) proving the
 * pending signal delivers exactly once (count 3->4); rt_sigsuspend(107)
 * with an empty mask waking on a pending SIGUSR1 (count 4->5) and
 * returning EINTR (carry + errno 4). SPARC how values are 1/2/4, not
 * the generic 0/1/2 (qemu target_signal.h; how=0 is EINVAL on oracle).
 *
 * Oracle behavior pinned under qemu-sparc -cpu LEON3 (qemu 7.2):
 * - Signal numbers: SIGUSR1=30, SIGALRM=14 (probed via kill+handler).
 * - Handlers installed via rt_sigaction must return via sigreturn(216):
 *   rt_sigreturn(101) resumes at NULL (SIGSEGV si_addr=NULL) under this
 *   qemu, while 216 resumes exactly (probed minimal handler, exit 0).
 * - Standard signals do not queue: one kill while blocked yields exactly
 *   one later delivery (count steps are exact, never "at least").
 *
 * Build (E-phase discipline):
 *   sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static \
 *     -o /tmp/t4a tests/test_p4_async.c
 * Oracle: qemu-sparc -cpu LEON3 /tmp/t4a   (exit 0, deterministic stdout)
 *
 * Pure top-level asm (no libc, no C runtime). E04 discipline:
 * snapshot-before-print, helpers clobber %o0-%o2, %g1, %g3, %g4 while
 * %g5-%g7 survive; live values otherwise sit in .bss words. Only V8
 * encodings (Bicc, no BPcc/BPr/membar/cas/popc/flushw). Large
 * immediates use `set`, never `mov`. Handlers touch only %g3/%g4 and
 * return via sigreturn(216); the frame preserves everything else. No
 * pids/addresses printed (they vary); only exact expected values are.
 */
__asm__(
"\t.text\n\t.align 4\n\t.global _start\n"
"_start:\n"
"\tsethi %hi(msg_start), %g2\nor %g2, %lo(msg_start), %g2\n\tcall puts\n\tnop\n"
/* --- getpid (value never printed); install SIGUSR1 counter handler. --- */
"\tmov 20, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_pid), %g5\nor %g5, %lo(saved_pid), %g5\n\tst %o0, [%g5]\n"
"\tsethi %hi(act), %g5\nor %g5, %lo(act), %g5\n"
"\tsethi %hi(h_usr1), %g6\nor %g6, %lo(h_usr1), %g6\n\tst %g6, [%g5]\n"
"\tmov 0, %g6\n\tst %g6, [%g5 + 4]\n\tst %g6, [%g5 + 8]\n\tst %g6, [%g5 + 12]\n\tst %g6, [%g5 + 16]\n"
"\tmov 30, %o0\n\tmov %g5, %o1\n\tmov 0, %o2\n\tmov 0, %o3\n\tmov 8, %o4\n\tmov 102, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(msg_sa), %g2\nor %g2, %lo(msg_sa), %g2\n\tcall puts\n\tnop\n"
/* --- three acknowledged self-kills: exact counts 1, 2, 3. --- */
"\tsethi %hi(saved_pid), %g5\nor %g5, %lo(saved_pid), %g5\n\tld [%g5], %o0\n\tmov 30, %o1\n\tmov 37, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tset 20000000, %g5\n"
"w1:\n"
"\tsethi %hi(sigcount), %g6\nor %g6, %lo(sigcount), %g6\n\tld [%g6], %g6\n\tcmp %g6, 1\n\tbe w1done\n\tnop\n"
"\tsubcc %g5, 1, %g5\n\tbnz w1\n\tnop\n"
"\tba fail\n\tnop\n"
"w1done:\n"
"\tsethi %hi(saved_pid), %g5\nor %g5, %lo(saved_pid), %g5\n\tld [%g5], %o0\n\tmov 30, %o1\n\tmov 37, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tset 20000000, %g5\n"
"w2:\n"
"\tsethi %hi(sigcount), %g6\nor %g6, %lo(sigcount), %g6\n\tld [%g6], %g6\n\tcmp %g6, 2\n\tbe w2done\n\tnop\n"
"\tsubcc %g5, 1, %g5\n\tbnz w2\n\tnop\n"
"\tba fail\n\tnop\n"
"w2done:\n"
"\tsethi %hi(saved_pid), %g5\nor %g5, %lo(saved_pid), %g5\n\tld [%g5], %o0\n\tmov 30, %o1\n\tmov 37, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tset 20000000, %g5\n"
"w3:\n"
"\tsethi %hi(sigcount), %g6\nor %g6, %lo(sigcount), %g6\n\tld [%g6], %g6\n\tcmp %g6, 3\n\tbe w3done\n\tnop\n"
"\tsubcc %g5, 1, %g5\n\tbnz w3\n\tnop\n"
"\tba fail\n\tnop\n"
"w3done:\n"
/* --- handler must have observed signo 30 in %o0. --- */
"\tsethi %hi(signo), %g5\nor %g5, %lo(signo), %g5\n\tld [%g5], %g6\n\tcmp %g6, 30\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_kill), %g2\nor %g2, %lo(msg_kill), %g2\n\tcall puts\n\tnop\n"
"\tsethi %hi(msg_signo), %g2\nor %g2, %lo(msg_signo), %g2\n\tcall puts\n\tnop\n"
"\tmov %g6, %g2\n\tcall puthex\n\tnop\n"
"\tcall putnl\n\tnop\n"
/* --- install SIGALRM handler; one-shot ITIMER_REAL 200 ms. --- */
"\tsethi %hi(act), %g5\nor %g5, %lo(act), %g5\n"
"\tsethi %hi(h_alrm), %g6\nor %g6, %lo(h_alrm), %g6\n\tst %g6, [%g5]\n"
"\tmov 14, %o0\n\tmov %g5, %o1\n\tmov 0, %o2\n\tmov 0, %o3\n\tmov 8, %o4\n\tmov 102, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(itv), %g5\nor %g5, %lo(itv), %g5\n\tmov 0, %g6\n\tst %g6, [%g5]\n\tst %g6, [%g5 + 4]\n\tst %g6, [%g5 + 8]\n\tset 500000, %g6\n\tst %g6, [%g5 + 12]\n"
"\tmov 0, %o0\n\tmov %g5, %o1\n\tmov 0, %o2\n\tmov 83, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tset 100000000, %g5\n"
"wa:\n"
"\tsethi %hi(alrmcount), %g6\nor %g6, %lo(alrmcount), %g6\n\tld [%g6], %g6\n\tcmp %g6, 1\n\tbe wadone\n\tnop\n"
"\tsubcc %g5, 1, %g5\n\tbnz wa\n\tnop\n"
"\tba fail\n\tnop\n"
"wadone:\n"
"\tsethi %hi(msg_itimer), %g2\nor %g2, %lo(msg_itimer), %g2\n\tcall puts\n\tnop\n"
/* --- block SIGUSR1 (how=1; bit 29 = signal 30); old mask reads back empty. --- */
"\tsethi %hi(set1), %g5\nor %g5, %lo(set1), %g5\n\tset 0x20000000, %g6\n\tst %g6, [%g5]\n\tmov 0, %g6\n\tst %g6, [%g5 + 4]\n"
"\tmov 1, %o0\n\tmov %g5, %o1\n"
"\tsethi %hi(old1), %g5\nor %g5, %lo(old1), %g5\n\tmov %g5, %o2\n\tmov 8, %o3\n\tmov 103, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(old1), %g5\nor %g5, %lo(old1), %g5\n\tld [%g5], %g6\n\ttst %g6\n\tbnz fail\n\tnop\n"
"\tld [%g5 + 4], %g6\n\ttst %g6\n\tbnz fail\n\tnop\n"
"\tsethi %hi(msg_block), %g2\nor %g2, %lo(msg_block), %g2\n\tcall puts\n\tnop\n"
/* --- kill while blocked: count must stay exactly 3 for the whole window. --- */
"\tsethi %hi(saved_pid), %g5\nor %g5, %lo(saved_pid), %g5\n\tld [%g5], %o0\n\tmov 30, %o1\n\tmov 37, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tset 500000, %g5\n"
"mspin:\n"
"\tsethi %hi(sigcount), %g6\nor %g6, %lo(sigcount), %g6\n\tld [%g6], %g6\n\tcmp %g6, 3\n\tbne fail\n\tnop\n"
"\tsubcc %g5, 1, %g5\n\tbnz mspin\n\tnop\n"
"\tsethi %hi(msg_masked), %g2\nor %g2, %lo(msg_masked), %g2\n\tcall puts\n\tnop\n"
/* --- unblock: old mask reads back the blocked set; pending delivers once. --- */
"\tsethi %hi(set1), %g5\nor %g5, %lo(set1), %g5\n\tmov %g5, %o1\n"
"\tsethi %hi(old2), %g5\nor %g5, %lo(old2), %g5\n\tmov %g5, %o2\n\tmov 2, %o0\n\tmov 8, %o3\n\tmov 103, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(old2), %g5\nor %g5, %lo(old2), %g5\n\tld [%g5], %g6\n\tset 0x20000000, %g2\n\tcmp %g6, %g2\n\tbne fail\n\tnop\n"
"\tld [%g5 + 4], %g6\n\ttst %g6\n\tbnz fail\n\tnop\n"
"\tset 20000000, %g5\n"
"w4:\n"
"\tsethi %hi(sigcount), %g6\nor %g6, %lo(sigcount), %g6\n\tld [%g6], %g6\n\tcmp %g6, 4\n\tbe w4done\n\tnop\n"
"\tsubcc %g5, 1, %g5\n\tbnz w4\n\tnop\n"
"\tba fail\n\tnop\n"
"w4done:\n"
"\tsethi %hi(msg_unblock), %g2\nor %g2, %lo(msg_unblock), %g2\n\tcall puts\n\tnop\n"
/* --- sigsuspend wake: re-block, kill (pending), suspend with empty mask. --- */
"\tsethi %hi(set1), %g5\nor %g5, %lo(set1), %g5\n\tmov %g5, %o1\n\tmov 1, %o0\n\tmov 0, %o2\n\tmov 8, %o3\n\tmov 103, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(saved_pid), %g5\nor %g5, %lo(saved_pid), %g5\n\tld [%g5], %o0\n\tmov 30, %o1\n\tmov 37, %g1\n\tta 0x10\n\tbcs fail\n\tnop\n"
"\tsethi %hi(emptyset), %g5\nor %g5, %lo(emptyset), %g5\n\tmov 0, %g6\n\tst %g6, [%g5]\n\tst %g6, [%g5 + 4]\n\tmov %g5, %o0\n\tmov 8, %o1\n\tmov 107, %g1\n\tta 0x10\n\tbcc fail\n\tnop\n"
/* --- must return via EINTR: carry set, errno 4. Snapshot before calls. --- */
"\tsethi %hi(snap), %g5\nor %g5, %lo(snap), %g5\n\tst %o0, [%g5]\n\tld [%g5], %g6\n\tcmp %g6, 4\n\tbne fail\n\tnop\n"
"\tsethi %hi(sigcount), %g5\nor %g5, %lo(sigcount), %g5\n\tld [%g5], %g6\n\tcmp %g6, 5\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_sus), %g2\nor %g2, %lo(msg_sus), %g2\n\tcall puts\n\tnop\n"
/* --- one-shot itimer must still show exactly one delivery. --- */
"\tsethi %hi(alrmcount), %g5\nor %g5, %lo(alrmcount), %g5\n\tld [%g5], %g6\n\tcmp %g6, 1\n\tbne fail\n\tnop\n"
"\tsethi %hi(msg_pass), %g2\nor %g2, %lo(msg_pass), %g2\n\tcall puts\n\tnop\n"
"\tmov 0, %o0\n\tmov 1, %g1\n\tta 0x10\n"
/* --- handlers: count only (%g3/%g4), return via sigreturn(216). --- */
"h_usr1:\n"
"\tsethi %hi(sigcount), %g3\nor %g3, %lo(sigcount), %g3\n\tld [%g3], %g4\n\tadd %g4, 1, %g4\n\tst %g4, [%g3]\n"
"\tsethi %hi(signo), %g3\nor %g3, %lo(signo), %g3\n\tst %o0, [%g3]\n"
"\tmov 216, %g1\n\tta 0x10\n"
"h_alrm:\n"
"\tsethi %hi(alrmcount), %g3\nor %g3, %lo(alrmcount), %g3\n\tld [%g3], %g4\n\tadd %g4, 1, %g4\n\tst %g4, [%g3]\n"
"\tmov 216, %g1\n\tta 0x10\n"
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
"msg_start:\n\t.asciz \"P4-ASYNC start\\n\"\n"
"msg_sa:\n\t.asciz \"sigaction ok\\n\"\n"
"msg_kill:\n\t.asciz \"kill ok 3\\n\"\n"
"msg_signo:\n\t.asciz \"signo=\\n\"\n"
"msg_itimer:\n\t.asciz \"itimer ok 1\\n\"\n"
"msg_block:\n\t.asciz \"block ok\\n\"\n"
"msg_masked:\n\t.asciz \"masked ok\\n\"\n"
"msg_unblock:\n\t.asciz \"unblock ok 4\\n\"\n"
"msg_sus:\n\t.asciz \"sigsuspend ok 5\\n\"\n"
"msg_pass:\n\t.asciz \"P4-ASYNC-PASS\\n\"\n"
"msg_fail:\n\t.asciz \"P4-ASYNC-FAIL\\n\"\n"
"\t.bss\n\t.align 4\n"
"hexbuf:\n\t.skip 8\n"
"charbuf:\n\t.skip 4\n"
"snap:\n\t.skip 4\n"
"saved_pid:\n\t.skip 4\n"
"act:\n\t.skip 20\n"
"sigcount:\n\t.skip 4\n"
"signo:\n\t.skip 4\n"
"alrmcount:\n\t.skip 4\n"
"itv:\n\t.skip 16\n"
"set1:\n\t.skip 8\n"
"old1:\n\t.skip 8\n"
"old2:\n\t.skip 8\n"
"emptyset:\n\t.skip 8\n"
);
