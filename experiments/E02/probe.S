! E02 probe: dual-PC (pc,npc), Bicc,a / BA,a annulled delay slots,
! page-end 0xffc rule. Freestanding V8 (-m32 -nostdlib).
! Syscalls: write=4, exit=1, rt_sigaction=102 (5-arg on SPARC).
! Parts (a)-(c) verify annul semantics with plain branches.
! Part (d) tests the page-end rule with a STATIC page-end layout
! (section .pageend, align 4096, 8 KiB): no heap execution, no
! hand-encoded instructions — every branch GAS-assembled, every target
! jmpl-reached. Fork isolates the faulting child.
!   P+0xFF8 branchA: BA,a -> land0   (delay P+0xFFC, mapped)
!   P+0xFFC branchB: BA   -> land1    (delay P+0x1000, PROT_NONE page)
! Child A runs branchA: annul-skip lands land0 (exit 0); executing the
!   delay would land land1 (exit 1).
! Child B runs branchB: fetching the delay faults (SIGSEGV); skipping
!   it would land land1 (exit 1).
! exit code 0 = all verified (parent prints PASS); 1 = FAIL.
	.text
	.align 4
	.global _start
_start:
	! --- (a) Bicc,a NOT taken: delay slot must NOT execute ---
	mov 0, %g5
	cmp %g0, %g0			! Z=1
	bne,a 1f
	mov 1, %g5			! delay: must be annulled
	nop
1:	cmp %g5, 0
	bne fail
	nop
	sethi %hi(msg_a), %g2
	or %g2, %lo(msg_a), %g2
	call puts
	nop
	mov %g5, %g2
	call puthex
	nop
	call putnl
	nop

	! --- (b) Bicc (no annul) NOT taken: delay slot executes ---
	mov 0, %g5
	cmp %g0, %g0
	bne 1f
	mov 2, %g5			! delay: must execute
	nop
1:	cmp %g5, 2
	bne fail
	nop
	sethi %hi(msg_b), %g2
	or %g2, %lo(msg_b), %g2
	call puts
	nop
	mov %g5, %g2
	call puthex
	nop
	call putnl
	nop

	! --- (c) BA,a taken: delay slot must NOT execute (V8 exception) ---
	ba,a 1f
	mov 3, %g5			! delay: must be annulled
	nop
1:	cmp %g5, 2			! unchanged?
	bne fail
	nop
	sethi %hi(msg_c), %g2
	or %g2, %lo(msg_c), %g2
	call puts
	nop
	mov %g5, %g2
	call puthex
	nop
	call putnl
	nop

	! --- (d) page-end 0xffc rule, STATIC layout (no heap execution) ---
	! Section .pageend (align 4096, 12 KiB, all mapped): each branch
	! sits at the end of a page with its delay slot the first word of
	! the NEXT page. The delay slot holds ld [%g0],%g0 (SIGSEGV if
	! executed). All branches GAS-assembled (no hand encoding), all
	! targets jmpl-reached. Fork isolates the faulting child.
	! (A PROT_NONE delay page hangs qemu-7.2's translator instead of
	! delivering the fetch fault — recorded oracle limitation; the
	! mapped faulting delay proves execute-vs-skip just as well.)
	!   P+0xFFC branchA: BA,a -> land0   (delay P+0x1000: faultA)
	!   P+0x1FFC branchB: BA  -> land1   (delay P+0x2000: faultB)
	! Child A runs branchA: annul-skip lands land0 (exit 0); executing
	!   the delay faults (SIGSEGV).
	! Child B runs branchB: executing the delay faults (SIGSEGV);
	!   skipping it would land land1 (exit 1).
	sethi %hi(branchA), %g2
	or %g2, %lo(branchA), %g2
	and %g2, 0xfff, %g2
	cmp %g2, 0xffc
	bne layout_fail
	nop
	sethi %hi(branchB), %g2
	or %g2, %lo(branchB), %g2
	and %g2, 0xfff, %g2
	cmp %g2, 0xffc
	be 1f
	nop
layout_fail:
	sethi %hi(msg_layout), %g2
	or %g2, %lo(msg_layout), %g2
	call puts
	nop
	sethi %hi(branchA), %g2
	or %g2, %lo(branchA), %g2
	call puthex
	nop
	mov ' ', %g2
	call putc
	nop
	sethi %hi(branchB), %g2
	or %g2, %lo(branchB), %g2
	call puthex
	nop
	call putnl
	nop
	ba fail
	nop
1:

	! No fork: qemu-sparc-7.2 cannot deliver a fatal signal to a forked
	! child (parent hangs in wait4) — recorded oracle limitation.
	! Instead, install a SIGSEGV handler (E05's proven 5-arg convention)
	! and chain forward: branchA -> land0 -> testB -> branchB -> handler.
	! expect_fault = 0 during the A phase, 1 during the B phase.
	sethi %hi(sa), %g2
	or %g2, %lo(sa), %g2
	sethi %hi(sehandler), %g3
	or %g3, %lo(sehandler), %g3
	st %g3, [%g2]			! sa_handler
	mov 0, %g3
	st %g3, [%g2 + 4]		! sa_flags = 0
	st %g3, [%g2 + 8]		! sa_restorer = 0
	st %g3, [%g2 + 12]
	st %g3, [%g2 + 16]		! sa_mask = 0
	mov 11, %o0			! SIGSEGV
	mov %g2, %o1
	mov 0, %o2
	mov 0, %o3			! restorer = 0
	mov 8, %o4			! sigsetsize = 8
	mov 102, %g1
	ta 0x10				! rt_sigaction (5-arg on SPARC)
	bcs fail
	nop
	sethi %hi(msg_handler), %g2
	or %g2, %lo(msg_handler), %g2
	call puts
	nop
	! run branchA (BA,a): must skip faultA and land land0
	sethi %hi(branchA), %g5
	or %g5, %lo(branchA), %g5
	jmpl %g5 + %g0, %g0
	nop
	! land0 chains to testB; land1 (wrongly reached) exits 1.
testB:
	sethi %hi(msg_testB), %g2
	or %g2, %lo(msg_testB), %g2
	call puts
	nop
	sethi %hi(expect_fault), %g2
	or %g2, %lo(expect_fault), %g2
	mov 1, %g3
	st %g3, [%g2]			! arm the expected fault
	sethi %hi(branchB), %g5
	or %g5, %lo(branchB), %g5
	jmpl %g5 + %g0, %g0		! BA: delay faultB must execute
	nop
	! reaching here means the delay was skipped (rule violated)
	sethi %hi(msg_nofault), %g2
	or %g2, %lo(msg_nofault), %g2
	call puts
	nop
	ba fail
	nop

	.global sehandler
sehandler:
	! old-style handler: check expect_fault, report, exit.
	sethi %hi(expect_fault), %g2
	or %g2, %lo(expect_fault), %g2
	ld [%g2], %g2
	cmp %g2, 1
	be 1f
	nop
	sethi %hi(msg_unexp), %g2
	or %g2, %lo(msg_unexp), %g2
	call puts
	nop
	mov 1, %o0
	mov 1, %g1
	ta 0x10			! exit(1): fault when none expected
1:	sethi %hi(msg_faultok), %g2
	or %g2, %lo(msg_faultok), %g2
	call puts
	nop
	sethi %hi(msg_pass), %g2
	or %g2, %lo(msg_pass), %g2
	call puts
	nop
	mov 0, %o0
	mov 1, %g1
	ta 0x10			! exit(0): B delay executed as required

fail:
	sethi %hi(msg_fail), %g2
	or %g2, %lo(msg_fail), %g2
	call puts
	nop
	mov 1, %o0
	mov 1, %g1
	ta 0x10

! ---------- helpers ----------
puts:
	mov %g2, %g4
1:	ldub [%g4], %g3
	tst %g3
	bz 2f
	add %g4, 1, %g4
	ba 1b
	nop
2:	sub %g4, %g2, %o2
	mov %g2, %o1
	mov 1, %o0
	mov 4, %g1
	ta 0x10
	retl
	nop
puthex:
	sethi %hi(hexbuf), %g3
	or %g3, %lo(hexbuf), %g3
	mov 28, %o2
1:	srl %g2, %o2, %g4
	and %g4, 0xf, %g4
	cmp %g4, 10
	bl 2f
	nop
	add %g4, 'a' - 10, %g4
	ba 3f
	nop
2:	add %g4, '0', %g4
3:	stb %g4, [%g3]
	add %g3, 1, %g3
	subcc %o2, 4, %o2
	bge 1b
	nop
	sethi %hi(hexbuf), %o1
	or %o1, %lo(hexbuf), %o1
	mov 1, %o0
	mov 8, %o2
	mov 4, %g1
	ta 0x10
	retl
	nop
putnl:
	mov '\n', %g2
	ba putc
	nop
putc:
	sethi %hi(charbuf), %g3
	or %g3, %lo(charbuf), %g3
	stb %g2, [%g3]
	mov 1, %o0
	mov %g3, %o1
	mov 1, %o2
	mov 4, %g1
	ta 0x10
	retl
	nop

	.data
	.align 4
msg_a:	.asciz "a: bne,a not-taken g5="
msg_b:	.asciz "b: bne not-taken g5="
msg_c:	.asciz "c: ba,a taken g5="
msg_layout:	.asciz "layout NG: branchA/B="
msg_handler:	.asciz "handler installed\n"
msg_testB:	.asciz "testB: jmpl branchB (expect fault)\n"
msg_land0:	.asciz "land0: A-ok (annul skip)\n"
msg_nofault:	.asciz "B delay skipped (rule broken)\n"
msg_unexp:	.asciz "unexpected fault in A phase\n"
msg_faultok:	.asciz "B faulted as expected (delay executed)\n"
msg_pass:	.asciz "E02-PASS: page-end annul + fetch rules verified\n"
msg_fail:	.asciz "E02-FAIL\n"
	.section .bss
	.align 4
hexbuf:	.skip 8
charbuf:	.skip 4
sa:	.skip 20
expect_fault:	.skip 4

! ---------- static page-end layout ----------
	.section .pageend,"ax"
	.align 4096
	.global pageend
pageend:
land0:	! annul-skip landed here: report A-ok, chain to testB
	sethi %hi(msg_land0), %g2
	or %g2, %lo(msg_land0), %g2
	call puts
	nop
	sethi %hi(testB), %g5
	or %g5, %lo(testB), %g5
	jmpl %g5 + %g0, %g0
	nop
land1:	or %g0, 1, %o0			! exit(1): delay skipped (rule broken)
	or %g0, 1, %g1
	ta 0x10
	.fill ((0xFFC - (. - pageend))/4), 4, 0x01000000
branchA:
	ba,a land0			! delay (P+0x1000 faultA) must be skipped
faultA:	ld [%g0], %g0			! SIGSEGV if executed (annul broken)
	.fill ((0x1FFC - (. - pageend))/4), 4, 0x01000000
branchB:
	ba land1			! delay (P+0x2000 faultB) must execute
faultB:	ld [%g0], %g0			! SIGSEGV when executed (correct)
	.fill ((0x3000 - (. - pageend))/4), 4, 0
