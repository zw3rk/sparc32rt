# E02 FINDINGS — dual-PC, `Bicc,a`/`BA,a` annul, page-end fetch rule

Oracle: `qemu-sparc -cpu LEON3`. Status: **PASS, exit 0.**

## Observed output

```
a: bne,a not-taken g5=000000000000
b: bne not-taken g5=000000000002
c: ba,a taken g5=000000000002
handler installed
land0: A-ok (annul skip)
testB: jmpl branchB (expect fault)
B faulted as expected (delay executed)
E02-PASS: page-end annul + fetch rules verified
```

## Findings

1. `Bicc,a` not-taken: delay slot **skipped, no fault even when the delay
   instruction would fault** (`branchA`: `BA,a` at page end `P+0xFFC`, delay =
   faulting `ld [%g0]`; annulled → control lands `land0`, verified chained).
2. `Bicc` (non-annulled) not-taken: delay slot **executes** (`g5=2` proves the
   delay `mov` ran).
3. `BA` taken: delay slot **always executes** — a faulting delay instruction
   raises SIGSEGV *before* the branch takes effect (verified via SIGSEGV
   handler: `B faulted as expected`, process exits 0 from the handler).
4. Page-end rule: a control transfer whose delay slot is the last word of a
   mapped page faults if the delay instruction faults — the fetch happens
   regardless of taken-ness for non-annulled branches (matches SPARC V8
   §5: the delay instruction is always fetched except when annulled).
5. **Oracle limitation (recorded, worked around):** `qemu-sparc-7.2` cannot
   deliver a fatal signal to a *forked child* — the parent hangs in `wait4`
   (observed `exit 124` timeout). Fork-isolated fault tests are therefore
   unreliable on this oracle; E02 installs an in-process SIGSEGV handler
   (5-arg `rt_sigaction`, cf. E05) and chains `branchA → land0 → testB →
   branchB → handler` in one process. Deterministic, no fork needed.
6. Static `.pageend` section (12 KiB, `branchA@P+0xFFC`, `branchB@P+0x1FFC`)
   used instead of heap code-gen: qemu-7.2 TCG hangs on `jmpl` into a
   freshly-`mmap`ed RWX page and on `PROT_NONE` delay-slot fetch (SIGILL with
   `si_addr` = delay-slot address observed in scratch). Static placement only.

## Translator implications

- `src/interp` + `src/dbt`: model `(pc, npc)` pair; annul bit suppresses the
  delay slot *including its faults*; non-annulled delay faults preempt the
  branch. DBT block boundaries must split on every control transfer; a block
  may not span a page end when the delay slot can fault (or must carry the
  fault check inline).
