# Phase 5 Sysroot Record — Dynamic V8 Userland (Lane `L5b`)

Commit: lane `lane/p5-l5b` (this file) + `tests/test_p5_dyn.c` +
`tests/test_p5_dynlib.c`. Companion card: `docs/lanes/phase-5.md`
(L5b card + frozen contract §4).

## 1. Verdict

(Pending: a nixpkgs `sparc-linux-gnu` glibc source build is running;
§5 records its outcome. If it succeeds, this section becomes the
provenance + pass record. If it fails, the verdict is the documented
negative: no pure-V8 dynamic sysroot obtainable, Debian userland
provably inadmissible, loader NOT weakened — plus the explicit
`unresolved` escalation in §8.)

## 2. Toolchain provenance (everything tried)

- `flake.lock` nixpkgs: `github:NixOS/nixpkgs/nixos-unstable`,
  rev `09063bd1f2b36fd9fd793c36dfade7bd40a93dfc`,
  `lastModified 1792210252`,
  `narHash sha256-Mh0PUaIv4nFY+8wAGonaEh8iBzwsmdNlwjVHmFg1Biw=`.
- Registry `nixpkgs` (`nix registry list`): user
  `flake:nixpkgs path:/nix/store/fjr02205wq70r3vghhfbfzv5g97nr4ya-source`,
  system `flake:nixpkgs path:/nix/store/640irzgl08asrnjly4dspdbx8lz3cvqr-source`.
- `(import <nixpkgs> {}).lib.version` = `"26.11pre-git"`.
- Oracle image `sparc32rt-oracle:latest`: Debian
  `sparc64-linux-gnu-gcc 12.2.0 (Debian 12.2.0-13)`,
  `qemu-sparc 7.2.22 (Debian 1:7.2+dfsg-7+deb12u18+b3)`, no
  `readelf`/`python3`/`busybox` inside (used
  `sparc64-linux-gnu-readelf/objdump`, `od`, shell).
- Translator under test: `_build/sparc32rt` (`sparc32rt 0.0-phase0`),
  cross-built with
  `/nix/store/82ac69jwkpj68v4mx22yxnwzqj0ql4l5-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin/aarch64-unknown-linux-musl-gcc`
  via `make build CC=... BUILD_DIR=_build` (clean).

## 3. Attempt 1 — `nix shell nixpkgs#pkgsCross.sparc-linux-gnu.stdenv.cc`

NOT OBTAINABLE through that path: the attribute does not exist.

```sh
nix eval --json nixpkgs#legacyPackages.aarch64-darwin.pkgsCross \
  --apply 'x: builtins.filter (n: builtins.match ".*sparc.*" n != null) (builtins.attrNames x)'
# => []
nix eval --impure --expr 'builtins.attrNames (import <nixpkgs> {}).lib.systems.examples' \
  | tr ',' '\n' | grep -i sparc   # => no match (exit 1)
nix path-info --impure nixpkgs#pkgsCross.sparc-linux-gnu.stdenv.cc
# => error: flake 'flake:nixpkgs' does not provide attribute
#    '...pkgsCross.sparc-linux-gnu.stdenv.cc'
```

`pkgsCross` is populated from `lib.systems.examples`, which names no
SPARC target at this nixpkgs revision (full `attrNames` list archived
in the lane log: 80+ entries, zero `sparc*`). The card's literal
command cannot work; the lane proceeded to the equivalent explicit
cross (`crossSystem = { config = "sparc-linux-gnu"; }`, §4).

## 4. Attempt 2 — explicit nixpkgs `sparc-linux-gnu` cross (glibc)

The cross instantiates (`stdenv.cc.name` evaluates):

```sh
nix eval --impure --expr \
  '(import <nixpkgs> { crossSystem = { config = "sparc-linux-gnu"; }; }).stdenv.cc.name'
# => "sparc-linux-gnu-gcc-wrapper-16.2.0"
```

but its `glibc-2.44-57` refuses the host platform:

```sh
nix path-info --impure --expr \
  'let pkgs = import <nixpkgs> { crossSystem = { config = "sparc-linux-gnu"; }; }; in pkgs.stdenv.cc'
# => error: Refusing to evaluate package 'glibc-2.44-57' in
#    .../pkgs/development/libraries/glibc/default.nix:218 because it is
#    not available on the requested hostPlatform:
#      hostPlatform.system = "sparc-linux"
#      package.meta.platforms = [ "x86_64-linux" "aarch64-linux"
#        "arc-linux" "armv5tel-linux" ... (24 entries, NO "sparc-linux") ]
```

Negative cached as a binary sysroot, but nix's own error message
authorizes the source-build override
(`NIXPKGS_ALLOW_UNSUPPORTED_SYSTEM=1`), which is exactly the card's
second option ("a `sparc-linux-gnu` libc build from source"). With the
override the plan evaluates to 12 derivations to build + 7 paths to
fetch (153.9 MiB):

```sh
export NIXPKGS_ALLOW_UNSUPPORTED_SYSTEM=1
nix build --impure --expr \
  'let pkgs = import <nixpkgs> { crossSystem = { config = "sparc-linux-gnu"; }; }; in pkgs.stdenv.cc' \
  --out-link /tmp/sparc-linux-gnu-cc --print-build-logs
# plan: sparc-linux-gnu-binutils-2.46 (+wrapper), -nolibc-gcc-16.2.0
# (+wrapper), linux-headers-7.2, glibc-nolibgcc-sparc-linux-gnu-2.44-57,
# libgcc-sparc-linux-gnu-16.2.0, glibc-sparc-linux-gnu-2.44-57,
# sparc-linux-gnu-gcc-16.2.0 (+wrapper), stdenv-darwin
```

Outcome in §5.

## 5. Attempt 2 outcome — source build + V8 qualification

(Pending build completion; this section will record: build log tail,
`$out` store path, `sparc-linux-gnu-gcc -dumpmachine`,
`readelf -h` machine/flags of a dynamic hello, `od` bytes at ELF
offset 18, `qemu-sparc -cpu LEON3` run, then `test_p5_dyn` /
`libp5dyn.so` builds and oracle-vs-`--interp`/`--dbt`/`--difftest`
results, then the BusyBox run from §7.)

## 6. Debian oracle toolchain — proved inadmissible (no loader weakening)

All runs inside `sparc32rt-oracle:latest`
(`docker run --rm --memory 2g --cpus 2 --platform linux/arm64
-v "$PWD:/w" -w /w`), container cleanup verified (`docker ps` shows
no `sparc32rt-l5b*` container after every run).

Toolchain: `sparc64-linux-gnu-gcc (Debian 12.2.0-13) 12.2.0`.

### 6.1 Every Debian-linked `-m32` binary is `EM_SPARC32PLUS` (18)

```sh
sparc64-linux-gnu-gcc -m32 -O2 -o /tmp/h32  hello.c            # dynamic
sparc64-linux-gnu-gcc -m32 -mcpu=v8 -O2 -o /tmp/h32v8 hello.c # dynamic, forced V8 codegen
sparc64-linux-gnu-gcc -m32 -O2 -static -o /tmp/h32s hello.c   # static
sparc64-linux-gnu-readelf -h /tmp/h32   | grep -E 'Machine|Flags'   # Sparc v8+, 0x100
sparc64-linux-gnu-readelf -h /tmp/h32v8 | grep -E 'Machine|Flags'   # Sparc v8+, 0x100 (!)
sparc64-linux-gnu-readelf -h /tmp/h32s  | grep -E 'Machine|Flags'   # Sparc v8+, 0x300
od -A d -t x1 -j 18 -N 2 /tmp/h32    # 0000018 00 12  (18 = EM_SPARC32PLUS)
od -A d -t x1 -j 18 -N 2 /tmp/h32s   # 0000018 00 12  (same)
```

`-mcpu=v8` does NOT rescue the link: libc/startfiles pull the image
back to v8+. SPEC §1.1 admission (`e_machine == EM_SPARC (2)`,
`e_flags ∈ {0, 0x300}`) rejects all three at the header.

### 6.2 The stream itself is V9 (`MOVcc`, `%xcc`), not just the header

Plain `sparc64-linux-gnu-gcc -m32 -O2 -c` user code (no libc involved):

```c
int br(int x) { if (x > 0) return 1; return 0; }
```

```asm
<br>:
   0:  9d e3 bf a0   save  %sp, -96, %sp
   4:  80 a6 20 00   cmp  %i0, 0
   8:  b0 10 20 00   clr  %i0
   c:  81 cf e0 08   return  %i7 + 8
  10:  91 66 a0 01   movg  %icc, 1, %o0     # V9 MOVcc, illegal on V8
  14:  30 68 00 03   b,a   %xcc, 20 <.>     # V9 %xcc branch, illegal on V8
```

`movg`/`%xcc` trap `EXIT_UNDEF`/SIGILL on a V8 context — exactly the
RC2 finding, re-verified on gcc 12.2.0.

### 6.3 Oracle and both engines agree loudly (rejection proof)

```sh
qemu-sparc -cpu LEON3 /tmp/h32_dyn     # Invalid ELF image for this architecture, exit 255
qemu-sparc -cpu LEON3 /tmp/h32_static  # Invalid ELF image for this architecture, exit 255
_build/sparc32rt --interp -- /tmp/h32_dyn
# sparc32rt: /tmp/h32_dyn: EM_SPARC32PLUS rejected (V8 context only)
# sparc32rt: cannot load '/tmp/h32_dyn'   (exit 1, -ENOEXEC path)
_build/sparc32rt --dbt -- /tmp/h32_dyn       # identical rejection, exit 1
_build/sparc32rt --interp -- /tmp/h32_static # identical rejection, exit 1
_build/sparc32rt --dbt -- /tmp/h32_static    # identical rejection, exit 1
```

Oracle-vs-translator parity on the negative: qemu refuses the image
before executing a single instruction; `sparc32rt` refuses it in
`load_elf32_image` before mapping anything. No V9 byte ever reaches
the decoder on either side.

## 7. BusyBox

Blocked on the same sysroot: the oracle image ships no `busybox`
(`which busybox` → not found) and no V8-capable libc to link one
against (§6). The qualification command, ready to run once §5 yields
a V8 sysroot with BusyBox built from it:

```sh
# oracle:
qemu-sparc -cpu LEON3 /path/to/busybox sh -c 'ls / && echo ok | wc -c' > /tmp/bb.oracle
# engines (same rootfs visible to the guest):
_build/sparc32rt --interp -- /path/to/busybox sh -c 'ls / && echo ok | wc -c' > /tmp/bb.interp
_build/sparc32rt --dbt    -- /path/to/busybox sh -c 'ls / && echo ok | wc -c' > /tmp/bb.dbt
cmp /tmp/bb.oracle /tmp/bb.interp && cmp /tmp/bb.oracle /tmp/bb.dbt
_build/sparc32rt --difftest -- /path/to/busybox sh -c 'ls / && echo ok | wc -c'  # 0 divergences
```

## 8. Residual gaps / unresolved escalation

- (If §5 succeeds: delete this section, record passes.)
- (If §5 fails:) no pure-V8 dynamic sysroot is obtainable from
  nixpkgs (no `pkgsCross` target AND glibc refuses `sparc-linux`;
  source build fails with <log tail>), and the Debian
  `sparc64-linux-gnu` toolchain is provably inadmissible (§6). The
  loader was NOT weakened to admit `EM_SPARC32PLUS`. Escalate to the
  Coordinator: `test_p5_dyn` + `libp5dyn.so` are committed and
  host-verified (`P5-DYN-PASS`, exit 0) but await a V8 sysroot for
  oracle/engine qualification, as does BusyBox (§7). Candidate
  follow-ups outside this lane: Buildroot `sparc`/`leon3` toolchain
  build, or a hand-rolled Canadian-cross glibc outside nixpkgs.

## 9. Guest test notes (`tests/test_p5_dyn.c`, `tests/test_p5_dynlib.c`)

- `test_p5_dyn.c` (174 lines): `dlopen("./libp5dyn.so", RTLD_NOW)`
  by explicit relative path (no `RPATH`/`$ORIGIN` dependence, no
  `LD_LIBRARY_PATH` needed — one fewer loader feature in the
  critical path), then `add`/`name`/`pair`/`exe-TLS`/`lib-TLS`/
  `missing-symbol` checks, `dlclose`, `P5-DYN-PASS`, exit 0. Uses the
  `*(void **)(&fn) = dlsym(...)` spelling so it stays
  `-std=c11 -Wall -Wextra` clean without function-pointer cast
  warnings.
- `test_p5_dynlib.c` (62 lines): dependency-free DSO
  (`p5_dyn_add`, `p5_dyn_name`, `p5_dyn_pair_sum`,
  `p5_dyn_strlen`, `__thread p5_lib_tls_counter`,
  `p5_dyn_tls_bump`).
- Host self-check (logic only, NOT an oracle substitute):
  `cc -std=c11 -Wall -Wextra` builds both warning-free and the pair
  prints exactly
  `dlopen ok / add ok 42 / name ok p5-dynlib / pair ok 42 /
  exe-tls ok 8 / lib-tls ok 1 2 / missing ok / P5-DYN-PASS`,
  exit 0.
- `make check` (build + `check-line-limits` + `check-abi-invariants`)
  is unaffected: guest sources are not part of the build and the
  line-limit gate scans `src include` only.
