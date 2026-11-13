#!/bin/sh
# tests/check_r13_r16.sh — regression gate for the Round 13-16 remediation.
#
# Runs:
#   1. the host-native C unit test (R13-2 sigreturn, R13-3 sysroot,
#      R14 decode classes, R15 oracle semantics, R13-7 double-dest);
#   2. tests/guests/r13r16 under --interp and --dbt (exit 0 required)
#      and under --difftest (0 divergences required);
#   3. tests/guests/r14t2trap under --interp and --dbt (exit 0 required).
#      r14t2trap is excluded from --difftest on purpose: its SIGTRAP is
#      delivered synchronously, and lockstep difftest only drives
#      delivery for EXIT_FAULT (see src/dbt/difftest.c).
#
# Usage: sh tests/check_r13_r16.sh [path-to-sparc32rt]
set -u
BIN=${1:-_build/sparc32rt}
fail=0

if ! python3 tools/gen_r13r16_guest.py tests/guests/r13r16 >/dev/null; then
    echo "R13-R16: guest regeneration failed"
    exit 1
fi

# 1. Host-native units (needs only the host C compiler).
if cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
        -Iinclude -Isrc tests/test_r13_r16.c src/os/syscalls_sig.c \
        src/interp/interp_win.c src/interp/interp_mem.c \
        src/interp/decode.c src/rt32/elf32.c src/interp/fp_arith.c \
        -o /tmp/test_r13_r16 \
    && /tmp/test_r13_r16; then
    echo "R13-R16: host units PASS"
else
    echo "R13-R16: host units FAIL"
    fail=1
fi

# 2. End-to-end guest (both engines must agree with the oracle).
for engine in interp dbt; do
    if "$BIN" --engine "$engine" -- tests/guests/r13r16; then
        echo "R13-R16: r13r16 $engine PASS"
    else
        echo "R13-R16: r13r16 $engine FAIL (exit $?)"
        fail=1
    fi
done
if "$BIN" --difftest -- tests/guests/r13r16; then
    echo "R13-R16: r13r16 difftest PASS"
else
    echo "R13-R16: r13r16 difftest FAIL (exit $?)"
    fail=1
fi

# 3. Trapping-delay npc probe (interp + dbt; difftest skips by design).
for engine in interp dbt; do
    if "$BIN" --engine "$engine" -- tests/guests/r14t2trap; then
        echo "R13-R16: r14t2trap $engine PASS"
    else
        echo "R13-R16: r14t2trap $engine FAIL (exit $?)"
        fail=1
    fi
done

exit "$fail"
