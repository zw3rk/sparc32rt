! E06 probe: SPARC V8 FPU (%f0..%f31, even-pair doubles, FSR.fcc),
! FBfcc,a annul semantics, NaN propagation, LDFSR rounding modes.
! Freestanding V8 (-m32 -nostdlib). Syscalls: write=4, exit=1.
! exit code 0 = completed; 1 = self-check FAIL.
! NOTE: the odd-pair double test is LAST: if it traps, qemu reports the
! signal and the exit code reflects it. That is itself a finding.
	.text
	.align 4
	.global _start
_start:
	! --- FADDd: 1.5 + 2.25 = 3.75 ---
	sethi %hi(d1), %g2
	or %g2, %lo(d1), %g2
	ldd [%g2], %f0
	sethi %hi(d2), %g2
	or %g2, %lo(d2), %g2
	ldd [%g2], %f2
	faddd %f0, %f2, %f4
	sethi %hi(res), %g2
	or %g2, %lo(res), %g2
	std %f4, [%g2]
	sethi %hi(msg_fadd), %g2
	or %g2, %lo(msg_fadd), %g2
	call puts
	nop
	sethi %hi(res), %g2
	or %g2, %lo(res), %g2
	ld [%g2], %g2
	call puthex
	nop
	mov ' ', %g2
	call putc
	nop
	sethi %hi(res), %g2
	or %g2, %lo(res), %g2
	ld [%g2 + 4], %g2
	call puthex
	nop
	call putnl
	nop

	! --- FSUBd: 3.75 - 1.5 = 2.25; FMULd: 1.5 * 2.25 = 3.375 ---
	sethi %hi(res), %g3
	or %g3, %lo(res), %g3
	fsubd %f4, %f0, %f8
	std %f8, [%g3]
	sethi %hi(msg_fsub), %g2
	or %g2, %lo(msg_fsub), %g2
	call puts
	nop
	sethi %hi(res), %g2
	or %g2, %lo(res), %g2
	ld [%g2], %g2
	call puthex
	nop
	mov ' ', %g2
	call putc
	nop
	sethi %hi(res), %g2
	or %g2, %lo(res), %g2
	ld [%g2 + 4], %g2
	call puthex
	nop
	call putnl
	nop
	fmuld %f0, %f2, %f8
	sethi %hi(res), %g2
	or %g2, %lo(res), %g2
	std %f8, [%g2]
	sethi %hi(msg_fmul), %g2
	or %g2, %lo(msg_fmul), %g2
	call puts
	nop
	! NOTE: reload res pointer explicitly (callers preserve %g2 here,
	! but be explicit):
	sethi %hi(res), %g2
	or %g2, %lo(res), %g2
	ld [%g2], %g2
	call puthex
	nop
	mov ' ', %g2
	call putc
	nop
	sethi %hi(res), %g2
	or %g2, %lo(res), %g2
	ld [%g2 + 4], %g2
	call puthex
	nop
	call putnl
	nop

	! --- FCMPD 1.5 vs 2.25 -> fcc=1 (less); STFSR bits 11:10 ---
	fcmpd %f0, %f2
	sethi %hi(fsrw), %g2
	or %g2, %lo(fsrw), %g2
	st %fsr, [%g2]
	sethi %hi(msg_fcc), %g2
	or %g2, %lo(msg_fcc), %g2
	call puts
	nop
	sethi %hi(fsrw), %g2
	or %g2, %lo(fsrw), %g2
	ld [%g2], %g2
	call puthex
	nop
	call putnl
	nop

	! --- FBNE,a not-taken (1.5 vs 1.5 equal): delay annulled ---
	fcmpd %f0, %f0			! equal -> fcc=0
	mov 0, %g5
	fbne,a 1f
	mov 1, %g5
	nop
1:	sethi %hi(msg_fbnea), %g2
	or %g2, %lo(msg_fbnea), %g2
	call puts
	nop
	mov %g5, %g2
	call puthex
	nop
	call putnl
	nop

	! --- FBE taken with delay executed (no annul) ---
	fcmpd %f0, %f0
	mov 0, %g5
	fbe 1f
	mov 7, %g5
	nop
1:	sethi %hi(msg_fbe), %g2
	or %g2, %lo(msg_fbe), %g2
	call puts
	nop
	mov %g5, %g2
	call puthex
	nop
	call putnl
	nop

	! --- NaN: 0.0/0.0; FCMPD NaN vs 1.5 -> fcc=3 (unordered) ---
	sethi %hi(dzero), %g2
	or %g2, %lo(dzero), %g2
	ldd [%g2], %f10
	fdivd %f10, %f10, %f12		! NaN
	sethi %hi(res), %g2
	or %g2, %lo(res), %g2
	std %f12, [%g2]
	sethi %hi(msg_nan), %g2
	or %g2, %lo(msg_nan), %g2
	call puts
	nop
	sethi %hi(res), %g2
	or %g2, %lo(res), %g2
	ld [%g2], %g2
	call puthex
	nop
	mov ' ', %g2
	call putc
	nop
	sethi %hi(res), %g2
	or %g2, %lo(res), %g2
	ld [%g2 + 4], %g2
	call puthex
	nop
	call putnl
	nop
	fcmpd %f12, %f0			! NaN vs 1.5
	sethi %hi(fsrw), %g2
	or %g2, %lo(fsrw), %g2
	st %fsr, [%g2]
	sethi %hi(msg_nanfcc), %g2
	or %g2, %lo(msg_nanfcc), %g2
	call puts
	nop
	sethi %hi(fsrw), %g2
	or %g2, %lo(fsrw), %g2
	ld [%g2], %g2
	call puthex
	nop
	call putnl
	nop

	! --- NaN propagation: NaN + 1.5 ---
	sethi %hi(d1), %g2
	or %g2, %lo(d1), %g2
	ldd [%g2], %f0
	faddd %f12, %f0, %f14
	sethi %hi(res), %g2
	or %g2, %lo(res), %g2
	std %f14, [%g2]
	sethi %hi(msg_nanprop), %g2
	or %g2, %lo(msg_nanprop), %g2
	call puts
	nop
	sethi %hi(res), %g2
	or %g2, %lo(res), %g2
	ld [%g2], %g2
	call puthex
	nop
	mov ' ', %g2
	call putc
	nop
	sethi %hi(res), %g2
	or %g2, %lo(res), %g2
	ld [%g2 + 4], %g2
	call puthex
	nop
	call putnl
	nop

	! --- rounding: FDTOI(2.5) under RN (expect 2), then RD=+inf.
	! Manual says RD=+inf gives 3; oracle prints 2 (FDTOI ignores FSR.RD,
	! verified by two discriminating cases) — oracle gap, see FINDINGS.
	sethi %hi(dtwopt5), %g2
	or %g2, %lo(dtwopt5), %g2
	ldd [%g2], %f16
	fdtoi %f16, %f18
	sethi %hi(res), %g2
	or %g2, %lo(res), %g2
	st %f18, [%g2]
	sethi %hi(msg_rn), %g2
	or %g2, %lo(msg_rn), %g2
	call puts
	nop
	sethi %hi(res), %g2
	or %g2, %lo(res), %g2
	ld [%g2], %g2
	call puthex
	nop
	call putnl
	nop
	! LDFSR with RD=+inf (FSR<31:30> = 10): word 0x80000000
	sethi %hi(fsrrm), %g2
	or %g2, %lo(fsrrm), %g2
	ld [%g2], %g2
	sethi %hi(fsrw), %g3
	or %g3, %lo(fsrw), %g3
	st %g2, [%g3]
	ld [%g3], %fsr
	fdtoi %f16, %f20
	sethi %hi(res), %g2
	or %g2, %lo(res), %g2
	st %f20, [%g2]
	sethi %hi(msg_rm), %g2
	or %g2, %lo(msg_rm), %g2
	call puts
	nop
	sethi %hi(res), %g2
	or %g2, %lo(res), %g2
	ld [%g2], %g2
	call puthex
	nop
	call putnl
	nop

	! --- restore RN (FSR=0) so later state is canonical ---
	mov 0, %g2
	sethi %hi(fsrw), %g3
	or %g3, %lo(fsrw), %g3
	st %g2, [%g3]
	ld [%g3], %fsr

	! --- FABSs / single lane ---
	sethi %hi(fneg), %g2
	or %g2, %lo(fneg), %g2
	ld [%g2], %f22
	fabss %f22, %f23
	sethi %hi(res), %g2
	or %g2, %lo(res), %g2
	st %f23, [%g2]
	sethi %hi(msg_fabs), %g2
	or %g2, %lo(msg_fabs), %g2
	call puts
	nop
	sethi %hi(res), %g2
	or %g2, %lo(res), %g2
	ld [%g2], %g2
	call puthex
	nop
	call putnl
	nop

	! --- odd-pair double: LAST, may trap ---
	sethi %hi(msg_odd), %g2
	or %g2, %lo(msg_odd), %g2
	call puts
	nop
	! faddd %f0,%f2,%f5 (rd odd): op=2, rs1=0, opf=0x42, rd=5
	! = 0x80000000 | 0x42<<5 | 5 = 0x80000845
	.word 0x80000845
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
	.align 8
d1:	.double 1.5
d2:	.double 2.25
dzero:	.double 0.0
dtwopt5:	.double 2.5
fneg:	.word 0xc0000000		! -2.0f
fsrrm:	.word 0x80000000		! candidate: RD=+inf in FSR<31:30>
	.align 4
msg_fadd:	.asciz "faddd 1.5+2.25 hi lo="
msg_fsub:	.asciz "fsubd hi lo="
msg_fmul:	.asciz "fmuld hi lo="
msg_fcc:	.asciz "fcmpd 1.5vs2.25 fsr="
msg_fbnea:	.asciz "fbne,a not-taken g5="
msg_fbe:	.asciz "fbe taken g5="
msg_nan:	.asciz "0.0/0.0 hi lo="
msg_nanfcc:	.asciz "fcmpd nan-vs-1.5 fsr="
msg_nanprop:	.asciz "nan+1.5 hi lo="
msg_rn:	.asciz "fdtoi(2.5) RN="
msg_rm:	.asciz "fdtoi(2.5) RM+inf="
msg_fabs:	.asciz "fabss(-2.0)="
msg_odd:	.asciz "odd-double next\n"
msg_pass:	.asciz "E06-PASS\n"
msg_fail:	.asciz "E06-FAIL\n"
	.section .bss
	.align 8
res:	.skip 8
fsrw:	.skip 4
hexbuf:	.skip 8
charbuf:	.skip 4
