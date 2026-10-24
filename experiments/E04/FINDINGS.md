# E04 FINDINGS — `ta 0x10` convention, `pipe`, `fork`/`wait4`

Oracle: `qemu-sparc -cpu LEON3`. Status: **PASS, exit 0.**

## Observed output

```
pid=000000000014
close(-1) errno=000000000009
pipe fds=00000000000c 0000000d
pipe read=[E04-OK
fork o0=000000000000 00000001
child alive
fork o0=000000000016 00000000
parent waiting
wait4 status=0000000700
E04-PASS
```

## Findings

1. Syscall convention: `ta 0x10`, number in `%g1`, args `%o0..o5`, return in
   `%o0/%o1`, error signalled by **PSR `icc.C` set + `%o0` = errno**
   (verified: `getpid=0x14`, `close(-1)` → C=1, `%o0 = EBADF = 9`).
2. `pipe(42)`: **SPARC `sys_sparc_pipe` convention — no pointer argument**;
   qemu implements it (`linux-user/syscall.c do_pipe`: `regwptr[1] =
   host_pipe[1]; return host_pipe[0]`). Observed `o0=12` (read end),
   `o1=13` (write end), round-trip `write(o1,"E04-OK",7)` + `read(o0)` of 7
   bytes verified. The generic-pointer `pipe(fds)` form is NOT used.
3. `fork(2)`: parent `%o0` = child pid (0x16=22), `%o1` = 0; child `%o0` = 0,
   **`%o1` = 1** (classic SPARC child marker, observed `fork o0=0 1`).
   Both sides snapshot before any call (helpers clobber `%o` regs).
4. `wait4(7)` returns pid; `wstatus = 0x0700` = exited(7) (child did
   `exit(7)`): `WEXITSTATUS` = `status>>8` holds.
5. **Probe bug fixed (not an oracle issue):** an earlier revision printed
   `pipe fds=12,9` and failed the round-trip. Root cause: `%g3` (pipefds
   pointer) was not reloaded after `puthex`/`putc` (which clobber `%g3`),
   so the second print and the `fd1` load read BSS garbage. Snapshot-before-
   print + reload-pointer-after-call is now the enforced discipline.
6. Syscall numbers used: `write=4, exit=1, fork=2, read=3, close=6,
   wait4=7, getpid=20, pipe=42` — consistent with `/oracle/syscall.tbl`
   (Linux v6.6) and qemu `strace` names.

## Translator implications

- `src/os/syscall_nr.h` (Phase 0, frozen): SPARC numbers above; carry-bit
  error convention (C + errno) vs AArch64 (`x0 = -errno`) must be translated
  at the syscall boundary in `src/rt32` + `src/os`.
- `pipe`: return both fds in `%o0/%o1`, ignore pointer arg (never valid on
  real LEON Linux either — `sys_sparc_pipe` takes no args).
- `fork`: child `%o0=0, %o1=1`; parent `%o0=pid, %o1=0`. `clone`/`CLONE_VM`
  table locking (D18/D19 substrate) builds on this.
