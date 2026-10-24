! E03 casa.S: CASA execution demo — EXPECTED ORACLE OUTCOME: guest death.
! Attempts casa [%o0] 0x0a, %o1, %o2 (0x15E22149, match case) on the
! qemu-sparc 7.2 linux-user oracle. The CASA case (op3=0x3c) is compiled
! out under CONFIG_USER_ONLY (translate.c: `#if !defined(CONFIG_USER_ONLY)
! || defined(TARGET_SPARC64)`), so translation falls to `default:
! goto illegal_insn`... observed empirically as trap 0x24 = TT_NCP_INSN,
! which linux-user cpu_loop does NOT handle -> prints
! "Unhandled trap: 0x24", dumps state, exit(1). The guest print below
! NEVER appears; its absence is the finding. Run: qemu-sparc -cpu LEON3.
! Freestanding V8 (-m32 -fno-pie -no-pie -nostdlib -static).
	.text
	.align 4
	.global _start
_start:
	sethi %hi(casamem), %o0
	or %o0, %lo(casamem), %o0
	sethi %hi(0x11111111), %o1
	or %o1, %lo(0x11111111), %o1
	sethi %hi(0x22222222), %o2
	or %o2, %lo(0x22222222), %o2
	.word 0x15E22149		! casa [%o0] 0x0a, %o1, %o2 (match)
	! --- reached only if the oracle executes CASA: report + exit(0) ---
	sethi %hi(msg_alive), %g2
	or %g2, %lo(msg_alive), %g2
	call puts
	nop
	mov %o2, %g2
	call puthex
	nop
	call putnl
	nop
	mov 0, %o0
	mov 1, %g1
	ta 0x10
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
msg_alive:	.asciz "casa survived rd="
casamem:	.word 0x11111111
	.section .bss
	.align 4
hexbuf:	.skip 8
charbuf:	.skip 4
