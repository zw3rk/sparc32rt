! E04 probe: SPARC32 ta 0x10 syscall convention (PSR.icc.C), pipe(42),
! fork(2) %o0/%o1 child convention. Freestanding V8 (-m32 -nostdlib).
! exit code 0 = completed; 1 = self-check FAIL.
	.text
	.align 4
	.global _start
_start:
	! --- getpid(20): expect C=0, %o0 = pid > 0 ---
	mov 20, %g1
	ta 0x10
	bcs fail
	nop
	tst %o0
	ble fail
	nop
	mov %o0, %g5			! save pid
	sethi %hi(msg_pid), %g2
	or %g2, %lo(msg_pid), %g2
	call puts
	nop
	mov %g5, %g2
	call puthex
	nop
	call putnl
	nop

	! --- error case: close(-1) -> expect C=1, %o0 = EBADF(9) ---
	mov 6, %g1
	mov -1, %o0
	ta 0x10
	bcc fail			! must carry on error
	nop
	! snapshot errno BEFORE any call (puts clobbers %o0-%o2)
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
	st %o0, [%g2]
	sethi %hi(msg_errno), %g2
	or %g2, %lo(msg_errno), %g2
	call puts
	nop
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
	ld [%g2], %g2
	call puthex
	nop
	call putnl
	nop
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
	ld [%g2], %g3
	cmp %g3, 9			! EBADF == 9 on sparc
	bne fail
	nop

	! --- pipe(42): try no-arg register-return form first ---
	mov 42, %g1
	ta 0x10
	bcs pipe_ptr			! if carry, try pointer form
	nop
	tst %o0
	bl pipe_ptr			! negative? try pointer form
	nop
	tst %o1
	ble pipe_ptr
	nop
	ba pipe_have
	nop
pipe_ptr:
	! SPARC pipe takes no pointer: sys_sparc_pipe ignores args and
	! returns both fds in %o0/%o1. Re-issue and validate positively.
	mov 42, %g1
	ta 0x10
	bcs fail
	nop
	tst %o0
	ble fail
	nop
	tst %o1
	ble fail
	nop
pipe_have:
	sethi %hi(pipefds), %g3
	or %g3, %lo(pipefds), %g3
	st %o0, [%g3]
	st %o1, [%g3 + 4]
	sethi %hi(msg_pipe), %g2
	or %g2, %lo(msg_pipe), %g2
	call puts
	nop
	sethi %hi(pipefds), %g3
	or %g3, %lo(pipefds), %g3
	ld [%g3], %g2
	call puthex
	nop
	mov ' ', %g2
	call putc
	nop
	sethi %hi(pipefds), %g3		! reload: puthex/putc clobber %g3
	or %g3, %lo(pipefds), %g3
	ld [%g3 + 4], %g2
	call puthex
	nop
	call putnl
	nop
	! round-trip: write "E04-OK" to fd[1], read from fd[0]
	sethi %hi(pipefds), %g3		! reload: helpers clobber %g3
	or %g3, %lo(pipefds), %g3
	ld [%g3 + 4], %o0		! fd1
	sethi %hi(msg_hello), %o1
	or %o1, %lo(msg_hello), %o1
	mov 7, %o2
	mov 4, %g1
	ta 0x10
	bcs fail
	nop
	cmp %o0, 7
	bne fail
	nop
	sethi %hi(pipefds), %g3		! reload: trap clobbers nothing but be safe
	or %g3, %lo(pipefds), %g3
	ld [%g3], %o0			! fd0
	sethi %hi(pipebuf), %o1
	or %o1, %lo(pipebuf), %o1
	mov 7, %o2
	mov 3, %g1
	ta 0x10			! read
	bcs fail
	nop
	cmp %o0, 7
	bne fail
	nop
	sethi %hi(msg_piperd), %g2
	or %g2, %lo(msg_piperd), %g2
	call puts
	nop
	sethi %hi(pipebuf), %g2
	or %g2, %lo(pipebuf), %g2
	call puts
	nop
	call putnl
	nop

	! --- fork(2): snapshot %o0/%o1 in both processes BEFORE calls ---
	mov 2, %g1
	ta 0x10
	bcs fail
	nop
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
	st %o0, [%g2 + 4]
	st %o1, [%g2 + 8]
	ld [%g2 + 4], %g6
	ld [%g2 + 8], %g5
	sethi %hi(msg_fork), %g2
	or %g2, %lo(msg_fork), %g2
	call puts
	nop
	mov %g6, %g2
	call puthex
	nop
	mov ' ', %g2
	call putc
	nop
	mov %g5, %g2
	call puthex
	nop
	call putnl
	nop
	! child iff (%o1==1) or (%o0==0 with parent o0>0):
	tst %g5
	bnz is_child
	nop
	tst %g6
	bz is_child
	nop
	! --- parent: wait4(child) ---
	sethi %hi(msg_parent), %g2
	or %g2, %lo(msg_parent), %g2
	call puts
	nop
	mov %g6, %o0			! pid
	sethi %hi(wstatus), %o1
	or %o1, %lo(wstatus), %o1
	mov 0, %o2
	mov 0, %o3
	mov 7, %g1
	ta 0x10			! wait4
	bcs fail
	nop
	sethi %hi(msg_wstatus), %g2
	or %g2, %lo(msg_wstatus), %g2
	call puts
	nop
	sethi %hi(wstatus), %g3
	or %g3, %lo(wstatus), %g3
	ld [%g3], %g2
	call puthex
	nop
	call putnl
	nop
	sethi %hi(msg_pass), %g2
	or %g2, %lo(msg_pass), %g2
	call puts
	nop
	mov 0, %o0
	mov 1, %g1
	ta 0x10
is_child:
	sethi %hi(msg_child), %g2
	or %g2, %lo(msg_child), %g2
	call puts
	nop
	mov 7, %o0
	mov 1, %g1
	ta 0x10			! exit(7)

fail:
	sethi %hi(msg_fail), %g2
	or %g2, %lo(msg_fail), %g2
	call puts
	nop
	mov 1, %o0
	mov 1, %g1
	ta 0x10

! ---------- helpers (same as E01) ----------
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
msg_pid:	.asciz "pid="
msg_errno:	.asciz "close(-1) errno="
msg_pipe:	.asciz "pipe fds="
msg_hello:	.asciz "E04-OK\n"
msg_piperd:	.asciz "pipe read=["
msg_fork:	.asciz "fork o0="
msg_parent:	.asciz "parent waiting\n"
msg_wstatus:	.asciz "wait4 status="
msg_child:	.asciz "child alive\n"
msg_pass:	.asciz "E04-PASS\n"
msg_fail:	.asciz "E04-FAIL\n"
	.section .bss
	.align 4
hexbuf:	.skip 8
charbuf:	.skip 4
snap:	.skip 12
pipefds:	.skip 8
pipebuf:	.skip 16
wstatus:	.skip 4
