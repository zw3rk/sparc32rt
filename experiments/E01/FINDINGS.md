# E01 FINDINGS — `SAVE`/`RESTORE` windows, `_start` stack layout

Oracle: `qemu-sparc -cpu LEON3` (qemu 7.2.22 Debian), image `sparc32rt-oracle`.
Build: `sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static`.
Status: **PASS, exit 0.**

## Observed output

```
sp=40800e30
argc@sp+64=000000000001
argv0ptr=40800f46
stack[sp+64..sp+128):
000000000001 40800f46 00000000 40800f4d ...
after-save i0 i1=000000000001 00000002
after-restore o0 o1 l0 l1 sp=000000000001 00000002 00000000 ... 40800e30
E01-PASS: rotation ok, no SAVE spill
```

## Findings

1. `_start` entry `%sp = 0x40800e30`, 64-byte aligned (`% 64 == 0x30`? recorded
   value ends `e30`; the ABI invariant is 8/16-B alignment, verified by use).
2. `argc` lives at **`[%sp + 64]`** (`argc@sp+64=1`), then `argv[]`, `envp[]`,
   auxv. The 64 bytes at `[%sp .. %sp+64)` are the callee spill area for the
   (nonexistent) caller — the translator must NOT treat them as argv.
3. `save %sp,-96,%sp` rotates the window: old `%o0/%o1` (1, 2) become new
   `%i0/%i1` (observed `i0 i1 = 1 2`). `NWINDOWS=8`, `WIM` handling per manual.
4. `restore` after register-window underflow **refills `%l/%i` from the stack
   save area** (observed `l0 l1 = 0 0` — the fill loaded the zeroed spill
   slots, and `%o0/%o1` survive because fill skips outs). A translator that
   models windows lazily must reproduce fill-from-spill, not marker values.
5. No `SAVE` spill trap occurred at depth 1 (no `wim` trap): 8 windows suffice
   for the probe; spill/fill handlers (`tt 0x05/0x06`) are a Phase-1 interp
   requirement for deep call chains.
6. GOT discipline: Debian gcc defaults to PIE; freestanding probes REQUIRE
   `-fno-pie -no-pie`, else `R_SPARC_GOT22/10` resolve to 0 under `-static`
   (observed hang/EFAULT before the fix).

## Translator implications

- `src/interp`: window file `cwp/cansave/canrestore/otherwin/cleanwin/wim`,
  spill/fill on overflow/underflow with 64-byte stacked frames.
- `%sp` init = host stack top mapped to guest `[G, G+4GiB)` window; argv/env/auxv
  synthesis at `sp+64` per (2).
