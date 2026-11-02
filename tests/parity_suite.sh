#!/bin/sh
# tests/parity_suite.sh — Wave C2 uniform 10-category guest matrix gate.
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# SPARC V8 (LEON3/LEON4) uniform 10-category parity gate. Sources the
# frozen cross-repo contract ../../rt-series/tools/parity_contract.sh
# and emits one structured PARITY_ROW per executed check, finishing with
# parity_summary (non-zero exit on any FAIL/GAP/SKIP, or zero PASS).
#
# Rows:
#   struct      make check-line-limits, make check-abi-invariants,
#               make build-darwin, host thread-entry check, host AOT
#               cache unit check.
#   sparcv8     10-category uniform guest matrix (--interp and --dbt)
#               against committed goldens in tests/golden/:
#                 1. p1_isa      integer/branch/window/unaligned/trap torture
#                 2. p2_libc     static uClibc-ng printf/malloc/qsort/fileio
#                 3. p3_fp       IEEE-754 single/double/quad + FSR torture
#                 4. p3_torture  portable FP/signal/VM/atomics torture
#                 5. tcg_smoke   portable ALU/signal/mmap/thread torture
#                 6. p4_threads  clone/futex/TLS (%g7) + RT signal delivery
#                 7. p5_dyn      dynamic PT_INTERP (ld-uClibc.so.0) + dlopen
#                 8. h1_smc      self-modifying code + FLUSH I-cache coherence
#                 9. h4_cxx      C++17 exceptions, RTTI, and std::thread
#                10. bench_smoke bench-sparc32 --smoke (ALL_PASS, no FAIL)
#               plus lockstep --difftest (0 divergences) on freestanding
#               single-threaded guests (p1_isa, p3_fp, h1_smc), the
#               explicit register-window SAVE/RESTORE check, and a real
#               guest-ELF aot_reload cold-emit -> warm-reload check
#               (--dbt --cache <dir>, magic 0x53335254414f5434).
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1
CONTRACT="$ROOT/../rt-series/tools/parity_contract.sh"
if [ ! -f "$CONTRACT" ]; then
    echo "parity_suite: frozen contract missing: $CONTRACT" >&2
    exit 2
fi
. "$CONTRACT"
parity_init "sparc32rt"

OUT="$ROOT/_build/parity"
mkdir -p "$OUT"
HOST="$(uname -s 2>/dev/null || echo unknown)"
GOLDEN_DIR="$ROOT/tests/golden"
GUEST_DIR="$ROOT/tests/guests"
SYSROOT="$ROOT/tests/sysroot"
BENCH="$ROOT/../rt-series/_build/bench/bench-sparc32"
RT_LINUX="$ROOT/_build/sparc32rt"
RT_DARWIN="$ROOT/_build/sparc32rt-darwin"
HL="$ROOT/../rt-series/_build/hl"

# ---- structural + host unit rows --------------------------------------
_t0="$(parity_now_ms)"
if make check-line-limits >/dev/null 2>&1; then
    parity_row "struct" "$HOST" "check-line-limits" "host" "PASS" \
        "$(( $(parity_now_ms) - _t0 ))" "every .c/.h/.S <= 900 lines"
else
    parity_row "struct" "$HOST" "check-line-limits" "host" "FAIL" "0" \
        "see make check-line-limits"
fi

_t0="$(parity_now_ms)"
if make check-abi-invariants >"$OUT/host-abi.log" 2>&1; then
    parity_row "struct" "$HOST" "check-abi-invariants" "host" "PASS" \
        "$(( $(parity_now_ms) - _t0 ))" "ALL OK"
else
    parity_row "struct" "$HOST" "check-abi-invariants" "host" "FAIL" "0" \
        "see $OUT/host-abi.log"
fi

if [ "$HOST" = "Darwin" ] && [ ! -x "$RT_DARWIN" ]; then
    echo "note: building missing $RT_DARWIN (make build-darwin)"
    make build-darwin >/dev/null 2>&1 || true
fi
_t0="$(parity_now_ms)"
if [ "$HOST" = "Darwin" ]; then
    if [ -x "$RT_DARWIN" ]; then
        parity_row "struct" "$HOST" "build-darwin" "host" "PASS" \
            "$(( $(parity_now_ms) - _t0 ))" "$RT_DARWIN present"
    else
        parity_row "struct" "$HOST" "build-darwin" "host" "GAP" "0" \
            "no darwin translator (make build-darwin failed)"
    fi
fi

_t0="$(parity_now_ms)"
if cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
        -Iinclude -Isrc tests/check_thread_entry.c \
        src/rt32/thread_entry.S -o "$OUT/host_thread_entry" 2>"$OUT/host-thread.log" \
    && timeout --kill-after=5s 15s "$OUT/host_thread_entry" >"$OUT/host-thread.out" 2>&1 \
    && grep -q "PASS" "$OUT/host-thread.out"; then
    parity_row "struct" "$HOST" "host-thread-entry" "host" "PASS" \
        "$(( $(parity_now_ms) - _t0 ))" "entry-convention probe PASS"
else
    parity_row "struct" "$HOST" "host-thread-entry" "host" "FAIL" "0" \
        "see $OUT/host-thread.log"
fi

_t0="$(parity_now_ms)"
if cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
        -Iinclude -Isrc tests/test_aot_cache_check.c \
        src/dbt/aot/aot_cache.c -o "$OUT/host_aot_cache_check" \
        2>"$OUT/host-aot.log" \
    && timeout --kill-after=5s 15s "$OUT/host_aot_cache_check" >"$OUT/host-aot.out" 2>&1 \
    && grep -q "AOT-CACHE: PASS" "$OUT/host-aot.out"; then
    parity_row "struct" "$HOST" "host-aot-cache" "host" "PASS" \
        "$(( $(parity_now_ms) - _t0 ))" "generation/header/invalidate PASS"
else
    parity_row "struct" "$HOST" "host-aot-cache" "host" "FAIL" "0" \
        "see $OUT/host-aot.log"
fi

# ---- runner resolution ------------------------------------------------
RT_BIN=""
RT_TAG="none"
if [ "$HOST" = "Darwin" ] && [ -x "$RT_DARWIN" ]; then
    RT_BIN="$RT_DARWIN"
    RT_TAG="$HOST/darwin"
elif [ -x "$RT_LINUX" ] && "$RT_LINUX" --version >/dev/null 2>&1; then
    RT_BIN="$RT_LINUX"
    RT_TAG="$HOST/native"
elif [ -x "$HL" ] && [ -x "$RT_LINUX" ] && "$HL" "$RT_LINUX" --version >/dev/null 2>&1; then
    RT_BIN="$HL $RT_LINUX"
    RT_TAG="$HOST/hl"
fi

# rt_run_guest <engine> <guest-name> <stdout-file>: executes a guest in
# tests/guests/ with --sysroot tests/sysroot and cwd=tests/guests (so
# p5_dyn resolves ./libp5dyn.so).
rt_run_guest() {
    _eng="$1"
    _gname="$2"
    _out="$3"
    # shellcheck disable=SC2086
    (cd "$GUEST_DIR" && timeout --kill-after=5s 45s $RT_BIN \
        --sysroot "$SYSROOT" --engine "$_eng" -- "./$_gname" >"$_out" 2>&1)
}

# golden_row <case> <engine> <golden> <exit-file> <actual> <exit> <t0>
golden_row() {
    _case="$1"; _eng="$2"; _golden="$3"; _exitf="$4"
    _actual="$5"; _exit="$6"; _t0="$7"
    _ms=$(( $(parity_now_ms) - _t0 ))
    if [ ! -f "$_golden" ]; then
        parity_row "sparcv8" "$RT_TAG" "$_case" "$_eng" "GAP" "$_ms" \
            "golden missing: $_golden"
        return
    fi
    _want_rc=0
    if [ -f "$_exitf" ]; then
        _want_rc="$(cat "$_exitf")"
    fi
    if [ "$_exit" != "$_want_rc" ]; then
        parity_row "sparcv8" "$RT_TAG" "$_case" "$_eng" "FAIL" "$_ms" \
            "exit=$_exit want=$_want_rc"
        return
    fi
    if parity_check_golden "$_golden" "$_actual"; then
        parity_row "sparcv8" "$RT_TAG" "$_case" "$_eng" "PASS" "$_ms" \
            "byte-identical, exit $_exit"
    else
        parity_row "sparcv8" "$RT_TAG" "$_case" "$_eng" "FAIL" "$_ms" \
            "stdout differs from golden (exit $_exit)"
    fi
}

# ---- 9 guest ELF categories (--interp + --dbt vs committed goldens) ---
GUEST_CASES="p1_isa p2_libc p3_fp p3_torture tcg_smoke p4_threads p5_dyn h1_smc h4_cxx"

if [ -z "$RT_BIN" ]; then
    for _g in $GUEST_CASES; do
        for _eng in interp dbt; do
            parity_row "sparcv8" "$HOST" "$_g" "$_eng" "GAP" "0" \
                "no runnable translator"
        done
    done
else
    for _g in $GUEST_CASES; do
        if [ ! -x "$GUEST_DIR/$_g" ]; then
            for _eng in interp dbt; do
                parity_row "sparcv8" "$RT_TAG" "$_g" "$_eng" "GAP" "0" \
                    "missing guest $GUEST_DIR/$_g"
            done
            continue
        fi
        for _eng in interp dbt; do
            _t0="$(parity_now_ms)"
            _rc=0
            rt_run_guest "$_eng" "$_g" "$OUT/rt-$_eng-$_g.txt" || _rc=$?
            golden_row "$_g" "$_eng" \
                "$GOLDEN_DIR/$_g.out" "$GOLDEN_DIR/$_g.exit" \
                "$OUT/rt-$_eng-$_g.txt" "$_rc" "$_t0"
        done
    done

    # ---- lockstep --difftest on freestanding single-threaded guests ---
    for _g in p1_isa p3_fp h1_smc; do
        if [ ! -x "$GUEST_DIR/$_g" ]; then
            parity_row "sparcv8" "$RT_TAG" "$_g-difftest" "difftest" "GAP" \
                "0" "missing guest $GUEST_DIR/$_g"
            continue
        fi
        _t0="$(parity_now_ms)"
        _rc=0
        # shellcheck disable=SC2086
        timeout --kill-after=5s 45s $RT_BIN --engine dbt --difftest \
            -- "$GUEST_DIR/$_g" >"$OUT/rt-difftest-$_g.txt" 2>&1 || _rc=$?
        if [ "$_rc" -eq 0 ] && \
                grep -a -q "0 divergences" "$OUT/rt-difftest-$_g.txt"; then
            parity_row "sparcv8" "$RT_TAG" "$_g-difftest" "difftest" \
                "PASS" "$(( $(parity_now_ms) - _t0 ))" \
                "$(grep -a -m1 -o '0 divergences ([0-9]* steps[^)]*)' "$OUT/rt-difftest-$_g.txt" || echo '0 divergences')"
        else
            parity_row "sparcv8" "$RT_TAG" "$_g-difftest" "difftest" \
                "FAIL" "0" "exit=$_rc, see $OUT/rt-difftest-$_g.txt"
        fi
    done
fi

# ---- register-window SAVE/RESTORE -------------------------------------
_t0="$(parity_now_ms)"
if [ -f "$GOLDEN_DIR/p1_isa.out" ] && [ -f "$OUT/rt-dbt-p1_isa.txt" ] && \
        grep -a -q "save depth-i=0x000000c0 unwind=1 spok=1" \
            "$GOLDEN_DIR/p1_isa.out" && \
        grep -a -q "save depth-i=0x000000c0 unwind=1 spok=1" \
            "$OUT/rt-dbt-p1_isa.txt"; then
    parity_row "sparcv8" "$RT_TAG" "window-save-restore" "dbt" \
        "PASS" "$(( $(parity_now_ms) - _t0 ))" \
        "SAVE depth-3 + unwind report identical"
else
    parity_row "sparcv8" "$RT_TAG" "window-save-restore" "dbt" \
        "FAIL" "0" "window report line missing or divergent"
fi

# ---- category 10: bench_smoke -----------------------------------------
if [ -x "$BENCH" ] && [ -n "$RT_BIN" ]; then
    for _eng in interp dbt; do
        _t0="$(parity_now_ms)"
        _rc=0
        # shellcheck disable=SC2086
        timeout --kill-after=5s 45s $RT_BIN --engine "$_eng" \
            -- "$BENCH" --smoke >"$OUT/bench-$_eng.txt" 2>&1 || _rc=$?
        if [ "$_rc" -eq 0 ] && grep -q "ALL_PASS" "$OUT/bench-$_eng.txt" \
                && ! grep -q "FAIL" "$OUT/bench-$_eng.txt"; then
            parity_row "sparcv8" "$RT_TAG" "bench_smoke" "$_eng" \
                "PASS" "$(( $(parity_now_ms) - _t0 ))" "ALL_PASS, no FAIL"
        else
            parity_row "sparcv8" "$RT_TAG" "bench_smoke" "$_eng" \
                "FAIL" "0" "exit=$_rc, see $OUT/bench-$_eng.txt"
        fi
    done
else
    for _eng in interp dbt; do
        parity_row "sparcv8" "$HOST" "bench_smoke" "$_eng" "GAP" "0" \
            "bench binary or translator missing"
    done
fi

# ---- real-guest aot_reload (cold-emit -> warm-reload) -----------------
AOT_DIR="$OUT/aot-cache"
rm -rf "$AOT_DIR"
mkdir -p "$AOT_DIR"
if [ -n "$RT_BIN" ] && [ -x "$GUEST_DIR/p1_isa" ]; then
    _t0="$(parity_now_ms)"
    _crc=0
    _wrc=0
    # shellcheck disable=SC2086
    timeout --kill-after=5s 45s $RT_BIN --engine dbt --cache "$AOT_DIR" \
        -- "$GUEST_DIR/p1_isa" >"$OUT/aot-cold.txt" 2>&1 || _crc=$?
    # shellcheck disable=SC2086
    timeout --kill-after=5s 45s $RT_BIN --engine dbt --cache "$AOT_DIR" \
        -- "$GUEST_DIR/p1_isa" >"$OUT/aot-warm.txt" 2>&1 || _wrc=$?
    _cfile="$AOT_DIR/sparc32-aot.cache"
    _magic="$(head -c 8 "$_cfile" 2>/dev/null || true)"
    if [ "$_crc" -eq 0 ] && [ "$_wrc" -eq 0 ] && [ -s "$_cfile" ] && \
            [ "$_magic" = "4TOATR3S" ] && \
            cmp -s "$OUT/aot-cold.txt" "$OUT/aot-warm.txt" && \
            cmp -s "$OUT/aot-cold.txt" "$GOLDEN_DIR/p1_isa.out"; then
        _csz="$(wc -c <"$_cfile" | tr -d ' ')"
        parity_row "sparcv8" "$RT_TAG" "aot_reload" "dbt" \
            "PASS" "$(( $(parity_now_ms) - _t0 ))" \
            "cold->warm byte-identical, magic=SRT3AOT4 (${_csz}B)"
    else
        parity_row "sparcv8" "$RT_TAG" "aot_reload" "dbt" \
            "FAIL" "0" "crc=$_crc wrc=$_wrc magic=$_magic"
    fi
else
    parity_row "sparcv8" "$HOST" "aot_reload" "dbt" "GAP" "0" \
        "translator or p1_isa guest missing"
fi

parity_summary
