! E03 probe: LEON3/4 UMUL/SMUL/UDIV/SDIV, Y register (RDY/WRY),
! LDSTUB/SWAP. Freestanding V8 (-m32 -nostdlib). Syscalls: write=4, exit=1.
! CASA is intentionally NOT executed: qemu-sparc 7.2 linux-user compiles
! out the CASA case under CONFIG_USER_ONLY (trap 0x24 = TT_NCP_INSN kills
! the guest). Encoding hand-derived + objdump-verified (0x15E22149);
! semantics per manual go into Phase-1 interp. See casa.S + FINDINGS.
! snap[16..19] hold the CASA operands' memory pre-state.
! KEY DISCIPLINE (learned E01): snapshot every result to memory BEFORE
! any call — puts/puthex/putc clobber %o0-%o2 and %g3/%g4.
! exit code 0 = completed; 1 = self-check FAIL.
	.text
	.align 4
	.global _start
_start:
	! --- RDY at rest ---
	rd %y, %g2
	sethi %hi(snap), %g3
	or %g3, %lo(snap), %g3
	st %g2, [%g3]			! snap[0] = y_init
	! --- WRY/RDY round-trip (imm must fit simm13) ---
	wr %g0, 0x234, %y
	rd %y, %g2
	cmp %g2, 0x234			! check BEFORE any call
	bne fail
	nop
	st %g2, [%g3 + 4]		! snap[1] = y_roundtrip

	! --- UMUL: 0x12345678 * 0x9abcdef0 ---
	sethi %hi(0x12345678), %g2
	or %g2, %lo(0x12345678), %g2
	sethi %hi(0x9abcdef0), %g4
	or %g4, %lo(0x9abcdef0), %g4
	umul %g2, %g4, %g5		! rd = low32
	rd %y, %g6			! Y = high32
	st %g6, [%g3 + 8]		! snap[2] = umul hi
	st %g5, [%g3 + 12]		! snap[3] = umul lo

	! --- UMULcc overflow flag: 0xffffffff * 2 (V must be 1) ---
	mov -1, %g2
	mov 2, %g4
	umulcc %g2, %g4, %g5
	st %g5, [%g3 + 16]		! snap[4] = umulcc lo
	bvs 1f
	nop
	mov 0, %g5
	ba 2f
	nop
1:	mov 1, %g5
2:	st %g5, [%g3 + 20]		! snap[5] = umulcc V

	! --- SMUL: (-7) * 3 = -21 ---
	mov -7, %g2
	mov 3, %g4
	smul %g2, %g4, %g5
	rd %y, %g6
	st %g6, [%g3 + 24]		! snap[6] = smul hi
	st %g5, [%g3 + 28]		! snap[7] = smul lo

	! --- UDIV: 0x1_00000000 / 3 = 0x55555555 (Y=1, rs1=0) ---
	mov 1, %g2
	wr %g2, %g0, %y		! Y = 1
	mov 0, %g2
	mov 3, %g4
	udiv %g2, %g4, %g5
	st %g5, [%g3 + 32]		! snap[8] = udiv q

	! --- UDIVcc overflow: 0x1_FFFFFFFF / 1 ---
	sethi %hi(0xffffffff), %g2
	or %g2, %lo(0xffffffff), %g2
	mov 1, %g5
	wr %g5, %g0, %y		! Y = 1
	mov 1, %g4
	udivcc %g2, %g4, %g5
	st %g5, [%g3 + 36]		! snap[9] = udivcc q
	bvs 1f
	nop
	mov 0, %g5
	ba 2f
	nop
1:	mov 1, %g5
2:	st %g5, [%g3 + 40]		! snap[10] = udivcc V

	! --- SDIV: (-7) / 2 = -3 (truncation toward zero) ---
	mov -1, %g5
	wr %g5, %g0, %y		! Y = -1 (sign extension of rs1)
	mov -7, %g2
	mov 2, %g4
	sdiv %g2, %g4, %g5
	st %g5, [%g3 + 44]		! snap[11] = sdiv q

	! --- LDSTUB: byte 0x5a -> rd, mem := 0xff ---
	sethi %hi(ldstubmem), %g2
	or %g2, %lo(ldstubmem), %g2
	ldstub [%g2], %g4
	st %g4, [%g3 + 48]		! snap[12] = ldstub rd
	ldub [%g2], %g4
	st %g4, [%g3 + 52]		! snap[13] = ldstub mem

	! --- SWAP: mem 0x11223344 <-> reg 0xaabbccdd ---
	sethi %hi(swapmem), %g2
	or %g2, %lo(swapmem), %g2
	sethi %hi(0xaabbccdd), %g4
	or %g4, %lo(0xaabbccdd), %g4
	swap [%g2], %g4
	st %g4, [%g3 + 56]		! snap[14] = swap rd
	ld [%g2], %g4
	st %g4, [%g3 + 60]		! snap[15] = swap mem

	! --- LDSTUB/SWAP-equivalent atomics: CASA intentionally NOT executed ---
	! casa [%o0] 0x0a, %o1, %o2 = 0xD5E22149 (op=3, rd=o2, op3=0x3c,
	! rs1=o0, i=1, asi=0x0a, rs2=o1 — hand-derived, objdump cross-checked).
	! The oracle (qemu-sparc 7.2 linux-user) cannot execute it: the CASA
	! case is compiled out under CONFIG_USER_ONLY (trap 0x24 = TT_NCP_INSN,
	! qemu kills the guest). See casa.S (expected-trap demo) + FINDINGS.
	! snap[16..19] record the CASA memory operands' PRE-STATE instead:
	! the translator's Phase-1 interp implements CASA semantics per manual.
	sethi %hi(casamem), %o0
	or %o0, %lo(casamem), %o0
	ld [%o0], %g4
	st %g4, [%g3 + 64]		! snap[16] = casamem pre-state (0x11111111)
	st %g4, [%g3 + 68]		! snap[17] = casamem pre-state copy
	sethi %hi(casamem2), %o0
	or %o0, %lo(casamem2), %o0
	ld [%o0], %g4
	st %g4, [%g3 + 72]		! snap[18] = casamem2 pre-state (0)
	st %g4, [%g3 + 76]		! snap[19] = casamem2 pre-state copy

	! --- print snap[0..19] ---
	sethi %hi(msg_head), %g2
	or %g2, %lo(msg_head), %g2
	call puts
	nop
	sethi %hi(snap), %g6
	or %g6, %lo(snap), %g6
	mov 0, %g5
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
	sethi %hi(snap), %g6
	or %g6, %lo(snap), %g6
3:	cmp %g5, 20
	bl 1b
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
msg_head:	.asciz "snap[y0 y1 umulhi umullo uccP uccV smulhi smullo udiv uccQ uccV sdiv ldrd ldmem swrd swmem cpre0 cpre0c cpre1 cpre1c]:\n"
msg_pass:	.asciz "E03-PASS\n"
msg_fail:	.asciz "E03-FAIL\n"
ldstubmem:	.byte 0x5a
	.align 4
swapmem:	.word 0x11223344
casamem:	.word 0x11111111
casamem2:	.word 0
	.section .bss
	.align 4
hexbuf:	.skip 8
charbuf:	.skip 4
snap:	.skip 80
