# E05 FINDINGS — `rt_signal_frame32` layout, handler ABI

Oracle: `qemu-sparc -cpu LEON3`. Status: **PASS, exit 0.**

## Observed output (head)

```
handler installed
faultinsn=0000010140
frame@sp=40800c50
00000000 ... (ss: 24 zero words)
f3800000 00010140 00010144 00000000
00000000 00000004 0000000a 0002032c
dead0000 ...
...
00000008 00000000 40800e30 00010134
00000000 40800d20 821020d8 91d02010
E05-PASS
```

Separate capture: `signo sp= 00000000000b 40800c50`, exit 0.

## Findings

1. `rt_sigaction(102)` on SPARC is **5-arg**: `o0=sig, o1=act, o2=oact,
   o3=restorer, o4=sigsetsize(=8)`. The 4-arg form returns `EINVAL`
   (qemu `do_sigaction` enforces `sigsize == sizeof(target_sigset_t)`).
   `sa` struct used: `{handler, flags=0, restorer=0, mask[2]=0}` (20 B).
2. Old-style handler (`flags=0`): **signo delivered in `%o0`** — observed
   `%o0 = 0x0b = 11 = SIGSEGV` for a faulting `ld [0xdead0000]`.
3. Frame `%sp = 0x40800c50` at handler entry, 16-byte aligned; deterministic
   across runs (matches `signo` capture).
4. `sparc_stackf ss` (96 B = 24 words) is all zeros: at fault time no window
   was live (`%l/%i` zero) and the xargs spill area is zeroed.
5. Interrupted `pc/npc` are recoverable from the frame: words 25-26 hold
   `0x10140/0x10144` = `faultinsn`/`faultinsn+4` exactly. `rt_sigreturn`
   must restore `%pc/%npc` from these slots.
6. `si_addr = 0xdead0000` present in the frame (word 32).
7. Interrupted `%sp = 0x40800e30` present in the frame (word 42) — identical
   to the E01 `_start` sp (deterministic stack base).
8. Frame total: 22 dumped rows × 16 B = 352 B ≥ 348 B `rt_signal_frame32`
   (qemu `target_rt_signal_frame`: `ss + siginfo + pt_regs + mask +
   fpu_save + insns[2] + stack + extra_size + rwin_save`).
9. qemu frame ≠ byte-identical kernel frame (qemu builds it in
   `linux-user/sparc/signal.c`); per-word kernel offsets (e.g. `si_signo`
   position) must come from `signal_32.c`, with the oracle used for
   behavioral checks (pc/npc/signo/sp recovery), not byte offsets.
10. Scratch lesson: data words after `.asciz` need explicit `.align 4`
    (misaligned `ld` → host SIGBUS, not guest SIGSEGV).

## Translator implications

- Phase 2/3 signal injection: build `rt_signal_frame32` with pc/npc/sp/
  si_addr at the observed slots; deliver `%o0 = signo`; `rt_sigreturn(175?)`
  restores pc/npc (number from `syscall.tbl` in Phase 0).
- The `restorer`/`sigsetsize` 5-arg convention is frozen into
  `src/os/syscall_nr.h` + rt_sigaction emulation.
