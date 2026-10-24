! E01 probe: SAVE/RESTORE 64-byte window semantics + _start (%sp + 64) layout.
! Freestanding SPARC V8 (-m32 -nostdlib). Syscalls: write=4, exit=1.
! Prints register/memory facts; exit code 0 = completed, 1 = self-check FAIL.
	.text
	.align 4
	.global _start
_start:
	! --- _start stack layout: argc at [%sp+64] ---
	mov %sp, %g2
	sethi %hi(msg_sp), %g2
	or %g2, %lo(msg_sp), %g2
	call puts
	nop
	mov %sp, %g2
	call puthex
	nop
	call putnl
	nop

	ld [%sp + 64], %g2		! argc
	sethi %hi(msg_argc), %g2
	or %g2, %lo(msg_argc), %g2
	call puts
	nop
	ld [%sp + 64], %g2
	call puthex
	nop
	call putnl
	nop

	! argv = %sp + 68; print argv[0] string
	ld [%sp + 68], %g2		! argv[0] pointer
	sethi %hi(msg_argv0), %g2
	or %g2, %lo(msg_argv0), %g2
	call puts
	nop
	ld [%sp + 68], %g2
	call puthex
	nop
	call putnl
	nop
	ld [%sp + 68], %g2		! argv[0] chars
	call puts
	nop
	call putnl
	nop

	! envp[0]: scan past argv NULL
	ld [%sp + 64], %g5		! argc
	add %sp, 68, %g4		! &argv[0]
	sll %g5, 2, %g3
	add %g4, %g3, %g4		! &argv[argc] (NULL)
	ld [%g4 + 4], %g2		! envp[0] pointer (may be NULL)
	sethi %hi(msg_envp0), %g2
	or %g2, %lo(msg_envp0), %g2
	call puts
	nop
	ld [%g4 + 4], %g2
	call puthex
	nop
	call putnl
	nop

	! dump 16 words at [%sp+64 .. %sp+128): stack layout evidence
	sethi %hi(msg_stack), %g2
	or %g2, %lo(msg_stack), %g2
	call puts
	nop
	add %sp, 64, %g6		! base (survives calls: %g6 untouched)
	mov 0, %g5			! index
1:	sll %g5, 2, %g4
	add %g6, %g4, %g4
	ld [%g4], %g2
	call puthex
	nop
	add %g5, 1, %g5
	and %g5, 3, %g4
	cmp %g4, 0
	bne 2f
	nop
	call putnl
	nop
	ba 3f
	nop
2:	mov ' ', %g2
	call putc
	nop
3:	cmp %g5, 16
	bl 1b
	nop
	call putnl
	nop

	! --- window rotation + underfill semantics ---
	mov 1, %o0
	mov 2, %o1
	mov 3, %l0
	mov 4, %l1
	! snapshot entry sp + [sp, sp+64) to expect area (fill source).
	! (Nothing below writes [sp,sp+64): sentinel fill targets
	! [sp-96,sp), calls use no stack, so the copy stays exact.)
	sethi %hi(entrysp), %g4
	or %g4, %lo(entrysp), %g4
	st %sp, [%g4]
	add %sp, 0, %g4
	sethi %hi(expect), %g6
	or %g6, %lo(expect), %g6
	mov 16, %g3
1:	ld [%g4], %g5
	st %g5, [%g6]
	add %g4, 4, %g4
	add %g6, 4, %g6
	subcc %g3, 1, %g3
	bnz 1b
	nop
	! fill the would-be spill area [sp-96, sp) with sentinel 0x5A5A5A5A
	add %sp, -96, %g4
	mov 24, %g3			! 24 words
	set 0x5A5A5A5A, %g5
1:	st %g5, [%g4]
	add %g4, 4, %g4
	subcc %g3, 1, %g3
	bnz 1b
	nop
	save %sp, -96, %sp
	! after save: old %o0/%o1 must be visible as %i0/%i1
	sethi %hi(msg_after_save), %g2
	or %g2, %lo(msg_after_save), %g2
	call puts
	nop
	mov %i0, %g2
	call puthex
	nop
	mov ' ', %g2
	call putc
	nop
	mov %i1, %g2
	call puthex
	nop
	call putnl
	nop
	cmp %i0, 1
	bne fail
	nop
	cmp %i1, 2
	bne fail
	nop
	! new window %l/%o are private to it; %i aliases the old %o,
	! so only touch %l/%o here to avoid destroying saved state.
	mov 5, %l0
	mov 6, %o0
	restore
	! Snapshot restored regs to memory BEFORE any call: puts/puthex
	! overwrite %o0-%o2 (fd/len/return), which would fake the readings.
	! snap layout: o0 o1 l0..l7 i0..i7 sp  (19 words).
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
	st %o0, [%g2]
	st %o1, [%g2 + 4]
	st %l0, [%g2 + 8]
	st %l1, [%g2 + 12]
	st %l2, [%g2 + 16]
	st %l3, [%g2 + 20]
	st %l4, [%g2 + 24]
	st %l5, [%g2 + 28]
	st %l6, [%g2 + 32]
	st %l7, [%g2 + 36]
	st %i0, [%g2 + 40]
	st %i1, [%g2 + 44]
	st %i2, [%g2 + 48]
	st %i3, [%g2 + 52]
	st %i4, [%g2 + 56]
	st %i5, [%g2 + 60]
	st %i6, [%g2 + 64]
	st %i7, [%g2 + 68]
	mov %sp, %g3
	st %g3, [%g2 + 72]
	! print the 19 snapshot words (loads from memory only)
	sethi %hi(msg_after_restore), %g2
	or %g2, %lo(msg_after_restore), %g2
	call puts
	nop
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
	mov 0, %g5			! word index
1:	sll %g5, 2, %g4
	add %g2, %g4, %g4
	ld [%g4], %g7			! value -> %g7 (call-preserved)
	mov %g7, %g2
	call puthex
	nop
	add %g5, 1, %g5
	cmp %g5, 19
	bne 2f
	nop
	call putnl
	nop
	sethi %hi(snap), %g2		! reload: putnl clobbers %g2
	or %g2, %lo(snap), %g2
	ba 3f
	nop
2:	and %g5, 3, %g4
	cmp %g4, 0
	bne 4f
	nop
	call putnl
	nop
	sethi %hi(snap), %g2		! reload: putnl clobbers %g2
	or %g2, %lo(snap), %g2
	ba 3f
	nop
4:	mov ' ', %g2
	call putc
	nop
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
3:	cmp %g5, 19
	bl 1b
	nop
	! verify rotation survivors from the memory snapshot
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
	ld [%g2], %g3
	cmp %g3, 1			! o0: old outs survive (fill skips outs)
	bne fail
	nop
	ld [%g2 + 4], %g3
	cmp %g3, 2			! o1: same
	bne fail
	nop
	ld [%g2 + 72], %g3
	sethi %hi(entrysp), %g4
	or %g4, %lo(entrysp), %g4
	ld [%g4], %g4
	cmp %g3, %g4			! sp restored to entry value
	bne fail
	nop
	! verify fill: snap l/i (snap+8 .. snap+68) == expect[0..15].
	! restore traps (window 0 was invalid, wim=1) and refills l/i
	! from [restored sp]; the pre-save markers are correctly gone.
	sethi %hi(snap), %g4
	or %g4, %lo(snap), %g4
	add %g4, 8, %g4
	sethi %hi(expect), %g6
	or %g6, %lo(expect), %g6
	mov 0, %g5
10:	sll %g5, 2, %g3
	add %g4, %g3, %g3
	ld [%g3], %g3			! actual fill value
	sll %g5, 2, %g7
	add %g6, %g7, %g7
	ld [%g7], %g7			! expected stack value
	cmp %g3, %g7
	bne 11f
	nop
	add %g5, 1, %g5
	cmp %g5, 16
	bl 10b
	nop
	ba 12f
	nop
11:	! stash idx/actual/expected BEFORE any call (calls clobber all)
	sethi %hi(filldiag), %g2
	or %g2, %lo(filldiag), %g2
	st %g5, [%g2]
	st %g3, [%g2 + 4]
	st %g7, [%g2 + 8]
	sethi %hi(msg_fill), %g2
	or %g2, %lo(msg_fill), %g2
	call puts
	nop
	sethi %hi(filldiag), %g2
	or %g2, %lo(filldiag), %g2
	ld [%g2], %g2
	call puthex
	nop
	mov ' ', %g2
	call putc
	nop
	sethi %hi(filldiag), %g2
	or %g2, %lo(filldiag), %g2
	ld [%g2 + 4], %g2
	call puthex
	nop
	mov ' ', %g2
	call putc
	nop
	sethi %hi(filldiag), %g2
	or %g2, %lo(filldiag), %g2
	ld [%g2 + 8], %g2
	call puthex
	nop
	call putnl
	nop
	ba fail
	nop
12:
	! sentinel area [sp-96,sp) must be intact (no spill by SAVE)
	add %sp, -96, %g4
	mov 24, %g3
	set 0x5A5A5A5A, %g5
	mov 0, %g7			! mismatch index (%g7 survives calls)
1:	ld [%g4], %g2
	cmp %g2, %g5
	bne 4f
	nop
	add %g4, 4, %g4
	add %g7, 1, %g7
	subcc %g3, 1, %g3
	bnz 1b
	nop
	ba 5f
	nop
4:	sethi %hi(msg_sentinel), %g2
	or %g2, %lo(msg_sentinel), %g2
	call puts
	nop
	mov %g7, %g2
	call puthex
	nop
	mov ' ', %g2
	call putc
	nop
	ld [%g4], %g2
	call puthex
	nop
	call putnl
	nop
	ba fail
	nop
5:

	sethi %hi(msg_pass), %g2
	or %g2, %lo(msg_pass), %g2
	call puts
	nop
	mov 0, %o0
	mov 1, %g1
	ta 0x10			! exit(0)

fail:
	sethi %hi(msg_fail), %g2
	or %g2, %lo(msg_fail), %g2
	call puts
	nop
	mov 1, %o0
	mov 1, %g1
	ta 0x10			! exit(1)

! ---------- helpers ----------
! puts: %g2 = NUL-terminated string. Clobbers %o0-%o2,%g1,%g3,%g4.
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
! puthex: %g2 = u32, prints 8 hex digits. Clobbers %o0-%o2,%g1,%g3,%g4.
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
! putnl: prints '\n'. Clobbers like write.
putnl:
	mov '\n', %g2
	ba putc
	nop
! putc: %g2 = char. Clobbers %o0-%o2,%g1,%g3.
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
msg_sp:	.asciz "sp="
msg_argc:	.asciz "argc@sp+64="
msg_argv0:	.asciz "argv0ptr="
msg_envp0:	.asciz "envp0ptr="
msg_stack:	.asciz "stack[sp+64..sp+128):\n"
msg_after_save:	.asciz "after-save i0 i1="
msg_after_restore:	.asciz "after-restore o0 o1 l0 l1 sp="
msg_sentinel:	.asciz "sentinel mismatch idx val="
msg_fill:	.asciz "fill mismatch idx actual expected="
msg_pass:	.asciz "E01-PASS: rotation ok, no SAVE spill\n"
msg_fail:	.asciz "E01-FAIL\n"
	.section .bss
	.align 4
hexbuf:	.skip 8
charbuf:	.skip 4
snap:	.skip 76
expect:	.skip 64
entrysp:	.skip 4
filldiag:	.skip 12
