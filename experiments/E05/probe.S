! E05 probe: SPARC32 rt_signal_frame32 layout (348 B, sparc_stackf 96 B).
! Installs a minimal SIGSEGV handler via rt_sigaction(102), triggers a
! fault at a known address, and dumps 112 words (448 B) from the handler's
! %sp so field offsets (sparc_stackf, siginfo, pt_regs32, mask, fpu_save,
! insns[2], extramask, extra_size, rwin_save, stack) can be verified offline.
! Freestanding V8 (-m32 -nostdlib). Syscalls: write=4, exit=1, rt_sigaction=102.
	.text
	.align 4
	.global _start
_start:
	! install handler for SIGSEGV(11): act = {handler, flags=0, restorer, mask}
	sethi %hi(sa), %g2
	or %g2, %lo(sa), %g2
	sethi %hi(handler), %g3
	or %g3, %lo(handler), %g3
	st %g3, [%g2]			! sa_handler
	mov 0, %g3
	st %g3, [%g2 + 4]		! sa_flags = 0 (old-style, 1 arg)
	st %g3, [%g2 + 8]		! sa_restorer = 0
	st %g3, [%g2 + 12]		! sa_mask[0] = 0
	st %g3, [%g2 + 16]		! sa_mask[1] = 0
	mov 11, %o0			! SIGSEGV
	mov %g2, %o1			! act
	mov 0, %o2			! oldact = NULL
	mov 0, %o3			! restorer = 0 (unused, no SA_RESTORER)
	mov 8, %o4			! sigsetsize = 8
	mov 102, %g1
	ta 0x10				! rt_sigaction (5-arg on SPARC)
	bcs fail
	nop
	sethi %hi(msg_installed), %g2
	or %g2, %lo(msg_installed), %g2
	call puts
	nop
	! print the faulting insn address for correlation with regs.pc
	sethi %hi(msg_pc), %g2
	or %g2, %lo(msg_pc), %g2
	call puts
	nop
	sethi %hi(faultinsn), %g2
	or %g2, %lo(faultinsn), %g2
	call puthex
	nop
	call putnl
	nop
	! fault: load from 0xdead0000 (unmapped)
	sethi %hi(0xdead0000), %g4
faultinsn:
	ld [%g4], %g2
	! must not reach here
	ba fail
	nop

	.global handler
handler:
	! old-style handler: %o0 = signo; %sp -> signal frame.
	! Dump 112 words from %sp, then exit(0).
	mov %sp, %g6			! frame base (save: puts clobbers %sp? no,
					! puts uses %o regs; keep frame ptr in %g6)
	sethi %hi(msg_frame), %g2
	or %g2, %lo(msg_frame), %g2
	call puts
	nop
	mov %g6, %g2
	call puthex
	nop
	call putnl
	nop
	mov 0, %g5			! word index
1:	sll %g5, 2, %g2
	add %g6, %g2, %g2
	ld [%g2], %g2
	call puthex
	nop
	add %g5, 1, %g5
	! newline every 4 words
	mov %g5, %g2
	and %g2, 3, %g2
	cmp %g2, 0
	bne 2f
	nop
	call putnl
	nop
	ba 3f
	nop
2:	mov ' ', %g2
	call putc
	nop
3:	cmp %g5, 112
	bl 1b
	nop
	sethi %hi(msg_pass), %g2
	or %g2, %lo(msg_pass), %g2
	call puts
	nop
	mov 0, %o0
	mov 1, %g1
	ta 0x10

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
msg_installed:	.asciz "handler installed\n"
msg_pc:	.asciz "faultinsn="
msg_frame:	.asciz "frame@sp="
msg_pass:	.asciz "E05-PASS\n"
msg_fail:	.asciz "E05-FAIL\n"
	.section .bss
	.align 4
sa:	.skip 20
hexbuf:	.skip 8
charbuf:	.skip 4
