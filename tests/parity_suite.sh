#!/bin/sh
# tests/parity_suite.sh — Wave C1 catalogue parity gate (lane C1-3).
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# SPARC V8 (LEON3/LEON4) Tier S gate. Sources the frozen cross-repo
# contract ../../rt-series/tools/parity_contract.sh and emits one
# structured PARITY_ROW per executed check, finishing with
# parity_summary (non-zero exit on any FAIL/GAP/SKIP, or zero PASS).
#
# Rows:
#   struct  make check-line-limits, make check-abi-invariants,
#           make build-darwin, host thread-entry check, host AOT
#           cache check.
#   sparcv8 guest execution parity (--engine interp/dbt, --difftest)
#           on _build/parity/{p1,p3,p4t} against committed goldens in
#           tests/golden/ (*_leon3.txt, from the pinned oracle below),
#           plus an explicit register-window SAVE/RESTORE row and
#           bench-sparc32 --smoke (when present).
#
# Oracle pinning: qemu-sparc 7.2 (Debian bookworm) -cpu LEON3. Newer
# qemu (trixie, 9.x) boots user-mode SPARC with a non-zero initial
# FSR, so the p3 guest fails its fsr0==0 prologue check there while
# passing under 7.2; the oracle leg self-validates (a native qemu is
# used only when its output matches the committed golden, otherwise
# the pinned bookworm container runs it) so the gate never depends on
# a live version string.
#
# Environments: translator legs prefer a native _build/sparc32rt,
# then hyper-linux (../rt-series/_build/hl), then a Linux container;
# guest builds need sparc64-linux-gnu-gcc -m32 (native or trixie
# container); oracle legs need qemu-sparc -cpu LEON3 (native or
# bookworm container). Missing capability rows are omitted with a
# `note:` line (fewer rows, never GAP-masked); any executed mismatch
# is FAIL and fails the gate.
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
BENCH="$ROOT/../rt-series/_build/bench/bench-sparc32"
RT_LINUX="$ROOT/_build/sparc32rt"
RT_DARWIN="$ROOT/_build/sparc32rt-darwin"
HL="$ROOT/../rt-series/_build/hl"

# ---- runner resolution ------------------------------------------------
RT_MODE="none"
if [ -x "$RT_LINUX" ] && "$RT_LINUX" --version >/dev/null 2>&1; then
    RT_MODE="native"
elif [ -x "$HL" ] && [ -x "$RT_LINUX" ] && \
        "$HL" "$RT_LINUX" --version >/dev/null 2>&1; then
    RT_MODE="hl"
elif command -v docker >/dev/null 2>&1; then
    RT_MODE="docker"
fi

have_docker() { command -v docker >/dev/null 2>&1; }

DOCKER_NAME="sparc32rt-c13-$$"
docker_cleanup() { docker rm -f "$DOCKER_NAME" >/dev/null 2>&1 || true; }

# rt_run <engine-flag> <guest> <stdout-file>: runs the translator via
# the resolved mode. Returns the guest exit code.
rt_run() {
    local _eng="$1" _guest="$2" _out="$3" _crel _rc
    case "$RT_MODE" in
        native)
            timeout --kill-after=10s 90s "$RT_LINUX" --engine "$_eng" \
                -- "$_guest" >"$_out" 2>&1
            ;;
        hl)
            timeout --kill-after=10s 90s "$HL" "$RT_LINUX" --engine \
                "$_eng" -- "$_guest" >"$_out" 2>&1
            ;;
        docker)
            _crel="/w/_build/parity/$(basename "$_guest")"
            trap docker_cleanup EXIT INT TERM
            timeout --kill-after=30s 500s docker run --rm \
                --name "$DOCKER_NAME" --memory 2g --cpus 2 \
                --platform linux/arm64 -v "$ROOT:/w" -w /w \
                debian:trixie-slim \
                /w/_build/sparc32rt --engine "$_eng" -- "$_crel" \
                >"$_out" 2>&1
            _rc=$?
            trap - EXIT INT TERM
            docker_cleanup
            return $_rc
            ;;
        *) return 127 ;;
    esac
}

# golden_row <abi> <host> <case> <engine> <golden> <actual> <exit>: strict
# byte compare (binary-safe) plus exit-0 precondition.
golden_row() {
    local _t0 _abi _host _case _eng _golden _actual _exit _ms
    _t0="$(parity_now_ms)"
    _abi="$1"; _host="$2"; _case="$3"; _eng="$4"
    _golden="$5"; _actual="$6"; _exit="$7"
    _ms=0
    if [ ! -f "$_golden" ]; then
        parity_row "$_abi" "$_host" "$_case" "$_eng" "GAP" "$_ms" \
            "golden missing: $_golden"
        return
    fi
    if [ "$_exit" -ne 0 ]; then
        parity_row "$_abi" "$_host" "$_case" "$_eng" "FAIL" "$_ms" \
            "exit=$_exit"
        return
    fi
    if parity_check_golden "$_golden" "$_actual"; then
        _ms=$(( $(parity_now_ms) - _t0 ))
        parity_row "$_abi" "$_host" "$_case" "$_eng" "PASS" "$_ms" \
            "byte-identical, exit 0"
    else
        parity_row "$_abi" "$_host" "$_case" "$_eng" "FAIL" "$_ms" \
            "stdout differs from golden"
    fi
}

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

if [ ! -x "$RT_DARWIN" ]; then
    echo "note: building missing $RT_DARWIN (make build-darwin)"
    make build-darwin >/dev/null 2>&1 || true
fi
_t0="$(parity_now_ms)"
if [ -x "$RT_DARWIN" ]; then
    parity_row "struct" "$HOST" "build-darwin" "host" "PASS" \
        "$(( $(parity_now_ms) - _t0 ))" "$RT_DARWIN present"
else
    parity_row "struct" "$HOST" "build-darwin" "host" "GAP" "0" \
        "no darwin translator (make build-darwin failed)"
fi

_t0="$(parity_now_ms)"
if cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
        -Iinclude -Isrc tests/check_thread_entry.c \
        src/rt32/thread_entry.S -o "$OUT/host_thread_entry" 2>"$OUT/host-thread.log" \
    && "$OUT/host_thread_entry" >"$OUT/host-thread.out" 2>&1 \
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
    && "$OUT/host_aot_cache_check" >"$OUT/host-aot.out" 2>&1 \
    && grep -q "AOT-CACHE: PASS" "$OUT/host-aot.out"; then
    parity_row "struct" "$HOST" "host-aot-cache" "host" "PASS" \
        "$(( $(parity_now_ms) - _t0 ))" "generation/header/invalidate PASS"
else
    parity_row "struct" "$HOST" "host-aot-cache" "host" "FAIL" "0" \
        "see $OUT/host-aot.log"
fi

# ---- guest builds -------------------------------------------------------
# Freestanding guests (_build/parity/, gitignored): reuse when newer
# than their sources, else build with a native sparc cross gcc, else
# in a trixie container. Each guest gets an availability row.
need_build=""
for _g in p1 p3 p4t; do
    _src=""
    case "$_g" in
        p1) _src="tests/test_p1_isa.c" ;;
        p3) _src="tests/test_p3_fp_simd.c" ;;
        p4t) _src="tests/test_p4_threads.c" ;;
    esac
    if [ -x "$OUT/$_g" ] && [ "$OUT/$_g" -nt "$ROOT/$_src" ]; then
        parity_row "sparcv8" "$HOST" "$_g-guest-build" "host" "PASS" "0" \
            "cached, newer than $_src"
    else
        need_build="$need_build $_g"
    fi
done

if [ -n "$need_build" ]; then
    if command -v sparc64-linux-gnu-gcc >/dev/null 2>&1; then
        for _g in $need_build; do
            _src=""
            case "$_g" in
                p1) _src="tests/test_p1_isa.c" ;;
                p3) _src="tests/test_p3_fp_simd.c" ;;
                p4t) _src="tests/test_p4_threads.c" ;;
            esac
            _t0="$(parity_now_ms)"
            if sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib \
                    -static -o "$OUT/$_g" "$ROOT/$_src" \
                    >"$OUT/build-$_g.log" 2>&1; then
                parity_row "sparcv8" "$HOST" "$_g-guest-build" "host" \
                    "PASS" "$(( $(parity_now_ms) - _t0 ))" \
                    "native sparc64-linux-gnu-gcc -m32"
            else
                parity_row "sparcv8" "$HOST" "$_g-guest-build" "host" \
                    "GAP" "0" "native build failed, see $OUT/build-$_g.log"
            fi
        done
    elif have_docker; then
        _t0="$(parity_now_ms)"
        trap docker_cleanup EXIT INT TERM
        if timeout --kill-after=30s 500s docker run --rm \
                --name "$DOCKER_NAME" --memory 2g --cpus 2 \
                --platform linux/arm64 -v "$ROOT:/w" -w /w \
                debian:trixie-slim bash -lc '
set -eu
apt-get update -qq && DEBIAN_FRONTEND=noninteractive \
    apt-get install -y -qq gcc-sparc64-linux-gnu \
    lib32gcc-14-dev-sparc64-cross >/dev/null 2>&1
mkdir -p _build/parity
sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static \
    -o _build/parity/p1 tests/test_p1_isa.c
sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static \
    -o _build/parity/p3 tests/test_p3_fp_simd.c
sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib -static \
    -o _build/parity/p4t tests/test_p4_threads.c
' >"$OUT/docker-build.log" 2>&1; then
            for _g in $need_build; do
                if [ -x "$OUT/$_g" ]; then
                    parity_row "sparcv8" "$HOST" "$_g-guest-build" \
                        "host" "PASS" \
                        "$(( $(parity_now_ms) - _t0 ))" \
                        "trixie container build"
                else
                    parity_row "sparcv8" "$HOST" "$_g-guest-build" \
                        "host" "GAP" "0" "container build missed $_g"
                fi
            done
        else
            for _g in $need_build; do
                parity_row "sparcv8" "$HOST" "$_g-guest-build" "host" \
                    "GAP" "0" "container build failed, see $OUT/docker-build.log"
            done
        fi
        trap - EXIT INT TERM
        docker_cleanup
        docker ps --format '{{.Names}}' | grep -q "$DOCKER_NAME" && \
            echo "note: container $DOCKER_NAME still listed" || true
    else
        for _g in $need_build; do
            parity_row "sparcv8" "$HOST" "$_g-guest-build" "host" "GAP" \
                "0" "no sparc cross gcc and no docker"
        done
    fi
fi

# ---- oracle vs golden ---------------------------------------------------
# A native qemu-sparc is trusted only when it reproduces the committed
# golden (self-validating oracle); otherwise the pinned bookworm
# (qemu-sparc 7.2) container runs the oracle legs.
ORACLE_MODE="none"
if command -v qemu-sparc >/dev/null 2>&1; then
    _ok=1
    for _g in p1 p3 p4t; do
        if [ -x "$OUT/$_g" ] && \
                timeout --kill-after=10s 60s qemu-sparc -cpu LEON3 \
                    "$OUT/$_g" >"$OUT/oracle-native-$_g.txt" 2>&1 && \
                parity_check_golden "$GOLDEN_DIR/${_g}_leon3.txt" \
                    "$OUT/oracle-native-$_g.txt"; then
            :
        else
            _ok=0
        fi
    done
    if [ "$_ok" -eq 1 ]; then
        ORACLE_MODE="native"
        echo "note: native $(qemu-sparc --version | head -1) reproduces goldens"
    else
        echo "note: native qemu-sparc diverges from goldens (trixie FSR quirk?)"
    fi
fi
if [ "$ORACLE_MODE" = "none" ] && have_docker; then
    trap docker_cleanup EXIT INT TERM
    if timeout --kill-after=30s 400s docker run --rm \
            --name "$DOCKER_NAME" --memory 2g --cpus 2 \
            --platform linux/arm64 -v "$ROOT:/w" -w /w \
            debian:bookworm-slim bash -lc '
set -eu
apt-get update -qq && DEBIAN_FRONTEND=noninteractive \
    apt-get install -y -qq qemu-user >/dev/null 2>&1
qemu-sparc --version | head -1
for g in p1 p3 p4t; do
    rc=0
    timeout --kill-after=10s 60s qemu-sparc -cpu LEON3 _build/parity/$g \
        > _build/parity/oracle-$g.txt 2>&1 || rc=$?
    echo "$g oracle exit=$rc"
done
' >"$OUT/docker-oracle.log" 2>&1; then
        ORACLE_MODE="docker"
    else
        echo "note: bookworm oracle container failed, see $OUT/docker-oracle.log"
    fi
    trap - EXIT INT TERM
    docker_cleanup
fi

for _g in p1 p3 p4t; do
    _t0="$(parity_now_ms)"
    case "$ORACLE_MODE" in
        native) _of="$OUT/oracle-native-$_g.txt" ;;
        docker) _of="$OUT/oracle-$_g.txt" ;;
        *)
            echo "note: no oracle for $_g (no qemu, no docker)"
            continue
            ;;
    esac
    if [ ! -x "$OUT/$_g" ]; then
        parity_row "sparcv8" "$HOST" "$_g-oracle-vs-golden" "oracle" \
            "GAP" "0" "guest missing"
    elif parity_check_golden "$GOLDEN_DIR/${_g}_leon3.txt" "$_of"; then
        _qemu="$(grep -m1 -o 'qemu-sparc version [^ ]*' "$OUT/docker-oracle.log" 2>/dev/null || echo native-qemu)"
        parity_row "sparcv8" "$HOST" "$_g-oracle-vs-golden" "oracle" \
            "PASS" "$(( $(parity_now_ms) - _t0 ))" "$_qemu -cpu LEON3"
    else
        parity_row "sparcv8" "$HOST" "$_g-oracle-vs-golden" "oracle" \
            "FAIL" "0" "oracle output differs from golden"
    fi
done

# ---- translator vs golden + difftest ------------------------------------
if [ "$RT_MODE" = "none" ]; then
    for _g in p1 p3 p4t; do
        for _eng in interp dbt; do
            parity_row "sparcv8" "$HOST" "$_g-vs-golden" "$_eng" "GAP" \
                "0" "no translator runner (no native/hl/docker)"
        done
    done
else
    for _g in p1 p3 p4t; do
        if [ ! -x "$OUT/$_g" ]; then
            for _eng in interp dbt; do
                parity_row "sparcv8" "$HOST" "$_g-vs-golden" "$_eng" \
                    "GAP" "0" "guest missing"
            done
            continue
        fi
        for _eng in interp dbt; do
            _rc=0
            rt_run "$_eng" "$OUT/$_g" "$OUT/rt-$_eng-$_g.txt" || _rc=$?
            golden_row "sparcv8" "$HOST/$RT_MODE" "$_g-vs-golden" "$_eng" \
                "$GOLDEN_DIR/${_g}_leon3.txt" "$OUT/rt-$_eng-$_g.txt" "$_rc"
        done
    done
    # --difftest is lockstep interp-vs-dbt inside one run (threaded p4t
    # excluded: lockstep is only meaningful single-threaded).
    for _g in p1 p3; do
        if [ ! -x "$OUT/$_g" ]; then
            parity_row "sparcv8" "$HOST" "$_g-difftest" "difftest" "GAP" \
                "0" "guest missing"
            continue
        fi
        _t0="$(parity_now_ms)"
        _rc=0
        case "$RT_MODE" in
            native)
                timeout --kill-after=10s 90s "$RT_LINUX" --engine dbt \
                    --difftest -- "$OUT/$_g" >"$OUT/rt-difftest-$_g.txt" \
                    2>&1 || _rc=$?
                ;;
            hl)
                timeout --kill-after=10s 90s "$HL" "$RT_LINUX" \
                    --engine dbt --difftest -- "$OUT/$_g" \
                    >"$OUT/rt-difftest-$_g.txt" 2>&1 || _rc=$?
                ;;
            docker)
                trap docker_cleanup EXIT INT TERM
                timeout --kill-after=30s 500s docker run --rm \
                    --name "$DOCKER_NAME" --memory 2g --cpus 2 \
                    --platform linux/arm64 -v "$ROOT:/w" -w /w \
                    debian:trixie-slim \
                    /w/_build/sparc32rt --engine dbt --difftest \
                    -- "/w/_build/parity/$_g" \
                    >"$OUT/rt-difftest-$_g.txt" 2>&1 || _rc=$?
                trap - EXIT INT TERM
                docker_cleanup
                ;;
        esac
        if [ "$_rc" -eq 0 ] && \
                grep -a -q "0 divergences" "$OUT/rt-difftest-$_g.txt"; then
            parity_row "sparcv8" "$HOST/$RT_MODE" "$_g-difftest" \
                "difftest" "PASS" "$(( $(parity_now_ms) - _t0 ))" \
                "$(grep -a -m1 -o '0 divergences ([0-9]* steps[^)]*)' "$OUT/rt-difftest-$_g.txt" || echo '0 divergences')"
        else
            parity_row "sparcv8" "$HOST/$RT_MODE" "$_g-difftest" \
                "difftest" "FAIL" "0" "exit=$_rc, see $OUT/rt-difftest-$_g.txt"
        fi
    done
fi

# ---- register-window SAVE/RESTORE ---------------------------------------
# The p1 guest rotates three register windows (SAVE depth 3) and
# unwinds them; the golden pins the exact window report line.
_t0="$(parity_now_ms)"
if [ -f "$GOLDEN_DIR/p1_leon3.txt" ] && [ -f "$OUT/rt-dbt-p1.txt" ] && \
        grep -a -q "save depth-i=0x000000c0 unwind=1 spok=1" \
            "$GOLDEN_DIR/p1_leon3.txt" && \
        grep -a -q "save depth-i=0x000000c0 unwind=1 spok=1" \
            "$OUT/rt-dbt-p1.txt"; then
    parity_row "sparcv8" "$HOST/$RT_MODE" "window-save-restore" "dbt" \
        "PASS" "$(( $(parity_now_ms) - _t0 ))" \
        "SAVE depth-3 + unwind report identical"
else
    parity_row "sparcv8" "$HOST/$RT_MODE" "window-save-restore" "dbt" \
        "FAIL" "0" "window report line missing or divergent"
fi

# ---- bench smoke (when present) -----------------------------------------
if [ -x "$BENCH" ] && [ -x "$RT_DARWIN" ]; then
    for _eng in interp dbt; do
        _t0="$(parity_now_ms)"
        _rc=0
        if [ "$_eng" = "interp" ]; then
            timeout --kill-after=10s 60s "$RT_DARWIN" --engine interp \
                -- "$BENCH" --smoke >"$OUT/bench-$_eng.txt" 2>&1 || _rc=$?
        else
            timeout --kill-after=10s 60s "$RT_DARWIN" --engine dbt \
                -- "$BENCH" --smoke >"$OUT/bench-$_eng.txt" 2>&1 || _rc=$?
        fi
        if [ "$_rc" -eq 0 ] && grep -q "ALL_PASS" "$OUT/bench-$_eng.txt" \
                && ! grep -q "FAIL" "$OUT/bench-$_eng.txt"; then
            parity_row "sparcv8" "$HOST/darwin" "bench-smoke" "$_eng" \
                "PASS" "$(( $(parity_now_ms) - _t0 ))" "ALL_PASS, no FAIL"
        else
            parity_row "sparcv8" "$HOST/darwin" "bench-smoke" "$_eng" \
                "FAIL" "0" "exit=$_rc, see $OUT/bench-$_eng.txt"
        fi
    done
else
    echo "note: bench smoke skipped (bench or darwin translator missing)"
fi

parity_summary
