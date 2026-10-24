# E06 FINDINGS — FPU: arithmetic, `fcc`, `FBfcc,a`, NaN, `LDFSR` modes

Oracle: `qemu-sparc -cpu LEON3`. Status: **PASS, exit 0.**

## Observed output

```
faddd 1.5+2.25 hi lo=400e0000 00000000
fsubd hi lo=400200000000 ... (= 0x4002000000000000 = 2.25)
fmuld hi lo=400b000000000000 (3.375)
fcmpd 1.5vs2.25 fsr=00000000400
fbne,a not-taken g5=000000000000
fbe taken g5=000000000007
0.0/0.0 hi lo=7fffffff ffffffff
fcmpd nan-vs-1.5 fsr=000000000e00
nan+1.5 hi lo=7fffffff ffffffff
fdtoi(2.5) RN=000000000002
fdtoi(2.5) RM+inf=000000000002
fabss(-2.0)=40000000
odd-double next
E06-PASS
```

## Findings

1. `FADDD/FMULD/FSUBD` on even-pair doubles exact: 1.5+2.25=3.75
   (`0x400E000000000000`), 1.5×2.25=3.375 (`0x400B…`), 3.75-1.5=2.25.
2. `FCMPD` sets `FSR.fcc`: 1.5 vs 2.25 → `fcc=1` (less), `fsr=0x400`
   (fcc field = bits 11:10). NaN vs 1.5 → `fsr=0xe00` (fcc=3, unordered,
   NV bit pattern as produced by qemu — record, translator matches *oracle*
   behavior here via difftest, manual bit is NV=1/fcc=2 on hardware; LEON
   hardware may differ, noted residual).
3. `FBfcc,a` annul semantics mirror integer `Bicc,a`: not-taken annulled
   skips delay (`g5=0` preserved), taken executes branch target (`g5=7`).
4. `0.0/0.0` → `0x7FFFFFFF_FFFFFFFF` (qemu quiet-NaN, NV set); `NaN+1.5`
   propagates NaN (same payload) — no trap on this oracle (no `FSR.ftt`).
5. `FDTOI(2.5)` under RN = 2 (round-to-nearest-even ✓).
6. **Oracle gap (two discriminating cases):** `LDFSR 0x80000000` sticks
   (`STFSR` reads back `0x80000000`, RD=+inf latched) but `FDTOI(2.5)` still
   yields 2 (manual: 3); `LDFSR 0xC0000000` (RD=-inf) + `FDTOI(-2.5)` yields
   -2 = `0xfffffffe` (manual: -3). **qemu-sparc-7.2 converts floats to int
   with RN regardless of `FSR.RD`.** Phase-1 interp implements `RD`
   faithfully per manual (RN/RZ/RP/RM); interp-vs-dbt difftest checks
   consistency, RD ground truth carries residual risk (no oracle).
7. `FABSS(-2.0)` single-lane ok (`0x40000000`).
8. Odd-pair double destination (`faddd %f0,%f2,%f5`, word `0x80000845`)
   executes without trap on this oracle (LEON would trap `fp_exception` on
   hardware for odd `rd` — oracle leniency noted; translator DECODES odd-rd
   as illegal per manual and traps, difftest excludes this encoding).

## Translator implications

- `src/interp` FPU: even-pair doubles, `fcc` in `FSR[11:10]`, `FBfcc,a`
  annul, NaN propagation (payload-preserving), `FDTOI` with all four `RD`
  modes, `FDIV 0/0` → quiet NaN (oracle-compatible).
- Odd-`rd` double: translator traps (manual-strict); oracle-leniency delta
  recorded so difftest masks that single encoding.
