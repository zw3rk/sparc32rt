# E03 FINDINGS — `UMUL`/`SMUL`/`UDIV`/`SDIV`, `Y`, `LDSTUB`/`SWAP`, `CASA`

Oracle: `qemu-sparc -cpu LEON3`. Status: **PASS, exit 0** (executable subset).
`casa.S`: expected-trap demo — `Unhandled trap: 0x24`, qemu exit 1.

## Observed snapshot (all values hand-verified against the V8 manual)

```
snap[y0 y1 umulhi umullo uccP uccV smulhi smullo udiv uccQ uccV sdiv
     ldrd ldmem swrd swmem cpre0 cpre0c cpre1 cpre1c]:
00000000 00000234 0b00ea4e 242d2080
fffffffe 00000000 ffffffff ffffffeb
55555555 ffffffff 00000001 fffffffd
0000005a 000000ff 11223344 aabbccdd
11111111 11111111 00000000 00000000
E03-PASS
```

| # | field | observed | manual expectation | ok |
|---|-------|----------|--------------------|----|
| 0 | y0 (Y init) | 0 | Y=0 at reset | yes |
| 1 | y1 | 0x234 | `wr %g0,0x234,%y; rd` roundtrip | yes |
| 2 | umulhi | 0x0b00ea4e | hi(0x12345678×0x9abcdef0) | yes |
| 3 | umullo | 0x242d2080 | lo(…) (python-verified) | yes |
| 4 | uccP | 0xfffffffe | umulcc(-1,2) = -2 | yes |
| 5 | uccV | 0 | -2 fits in s32, no overflow | yes |
| 6 | smulhi | 0xffffffff | hi(-7×3), sign extension | yes |
| 7 | smullo | 0xffffffeb | -21 | yes |
| 8 | udiv | 0x55555555 | (Y:rs1)=(1:0)/3, Y-divide hazard | yes |
| 9 | uccQ | 0xffffffff | lo32((1:0xffffffff)/1) | yes |
| 10 | uccV | 1 | quotient overflows 32 bits | yes |
| 11 | sdiv | 0xfffffffd | -7/2 = -3 (truncate to zero) | yes |
| 12 | ldrd | 0x5a | LDSTUB returns old byte | yes |
| 13 | ldmem | 0xff | LDSTUB writes 0xFF | yes |
| 14 | swrd | 0x11223344 | SWAP returns old mem | yes |
| 15 | swmem | 0xaabbccdd | SWAP writes reg | yes |
| 16-19 | cpre* | 11111111 11111111 0 0 | CASA operand pre-state (unexecuted) | yes |

## CASA encoding (hand-derived, objdump cross-checked)

`casa [%o0] 0x0a, %o1, %o2` = `rd(10)<<25 | op3(0x3c)<<19 | rs1(8)<<14 |
i(1)<<13 | asi(0x0a)<<5 | rs2(9)` = **`0x15E22149`**; ASI 0x0b variant
**`0x15E22169`**. (An earlier draft had rs1/rd swapped — `casa [%o2]…` —
caught by objdump decode; the translator's decoder must use architecture
field order, not mnemonic order.)

## CASA oracle gap (demonstrated in-vivo by `casa.S`)

```
Unhandled trap: 0x24
pc: 000100d0  npc: 000100d4     <- the casa word
%o0-7: 000201de 11111111 22222222 ...
exit=1
```

Root cause (qemu v7.2.0 source): `target/sparc/translate.c` gates
`case 0x3c` (casa) with `#if !defined(CONFIG_USER_ONLY) ||
defined(TARGET_SPARC64)` — on `qemu-sparc` linux-user the case is compiled
out and translation traps `0x24 = TT_NCP_INSN`, which `linux-user`
`cpu_loop` does not handle (kills the guest; no signal is delivered).
Additionally `get_asi` (32-bit) sends every immediate-ASI alternate access to
`TT_ILL_INSN`. So **no qemu-user variant executes 32-bit user-mode CASA**
(the 64-bit `get_asi` path traps `asi < 0x80` in user mode too).
The LEON3 CPU def *does* carry `CPU_FEATURE_CASA` — the feature exists, the
user-mode translate path does not.

Translator consequence: CASA (match → swap+rd=old, mismatch → rd=old,
mem unchanged; ASI 0x0a user data) is implemented from the manual in
Phase-1 `interp` (+ DBT), with `casa.S` retained as the oracle-gap witness.
Single-threaded semantic risk is nil (atomicity unobservable); SMP atomicity
is out of scope for Phase 1 (recorded residual risk).

## Translator implications

- MUL/DIV `Y` hazard: `UDIV`/`SDIV` consume `(Y:rs1)`; `UMUL/SMUL` produce
  `Y`. Interp/DBT must thread `Y` through every MUL/DIV site (E03 #8 proves
  live-Y dependence).
- `UMULcc/SMULcc` icc.V semantics verified (#5=0, #10=1); `SDIV` truncates (#11).
- `LDSTUB`/`SWAP` atomic byte/word verified (#12-15).
