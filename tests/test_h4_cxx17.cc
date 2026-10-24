/*
 * tests/test_h4_cxx17.cc — Phase 7 lane H4 C++17 guest (hosted).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Exercises real C++17 semantics, nothing emulated with C constructs:
 *  - try/catch unwinding across three call frames (RAII destructors run
 *    in reverse order, message preserved, catch by const ref, rethrow);
 *  - unwinding while a signal handler is installed and a signal is
 *    delivered mid-chain (handler returns normally — no throw out of
 *    a handler, which would be UB; the unwind still completes exactly);
 *  - dynamic_cast RTTI (pointer up/down/cross casts, null on failure,
 *    reference bad_cast, typeid identity);
 *  - std::thread (N threads x REPS atomic increments, join, exact sum);
 *  - thread_local destructors (one tracer per thread, dtor count == N
 *    after join; the main-thread tracer is intentionally not observed —
 *    its destruction order vs atexit is implementation-defined).
 *
 * Deterministic stdout (no addresses, pids, or timing); exit 0 means
 * every check passed, exit 1 names the first failure on stdout.
 *
 * Host soundness proof (this machine):
 *   c++ -std=c++17 -Wall -Wextra -o /tmp/h4host tests/test_h4_cxx17.cc
 *   /tmp/h4host   (exit 0, output below in §5)
 *
 * DOCUMENTED NEGATIVE (no V8 C++ toolchain exists here; contract §4).
 * Nothing below is claimed runnable on the oracle or either engine —
 * no gate was weakened. Exact investigation trail (oracle image
 * sparc32rt-oracle:latest, qemu-sparc 7.2.22, Debian gcc 12.2.0-13):
 *
 *  1. No C++ frontend in the image: `sparc64-linux-gnu-gcc -x c++`
 *     fails with `fatal error: cannot execute 'cc1plus'`, and
 *     /usr/sparc64-linux-gnu/include carries C headers only (no c++/).
 *  2. `apt-get install g++-sparc64-linux-gnu` works after `apt-get
 *     update` (candidate 4:12.2.0-5) and provides cc1plus plus v12
 *     cross C++ headers — but only a 64-bit libstdc++ link target:
 *     static and dynamic `-m32` links both fail with `skipping
 *     incompatible .../12/libstdc++.so` / `cannot find -lstdc++`.
 *     The 32-bit runtime libstdc++.so.6 exists in
 *     /usr/sparc64-linux-gnu/lib32 (runtime-only package, no .so
 *     dev symlink, no 32-bit libstdc++.a anywhere).
 *  3. Closest achievable link (workarounds only, committed nowhere):
 *       mkdir -p /tmp/s32
 *       ln -s /usr/sparc64-linux-gnu/lib32/libstdc++.so.6 \
 *         /tmp/s32/libstdc++.so
 *       ln -s /usr/sparc64-linux-gnu/lib32/libatomic.so.1 \
 *         /tmp/s32/libatomic.so
 *       sparc64-linux-gnu-g++ -m32 -mcpu=v8 -std=c++17 -pthread \
 *         -o /tmp/h4v8h tests/test_h4_cxx17.cc -L/tmp/s32 -latomic
 *     (-latomic is mandatory: -mcpu=v8 has no CASA, so the compiler
 *     emits __atomic_fetch_add_4 calls instead of inline atomics.)
 *     LINK_RC=0, but the result is NOT V8-clean:
 *       Machine: Sparc v8+, Flags: 0x100 (= EF_SPARC_32PLUS),
 *       NEEDED libstdc++.so.6 libm libgcc_s libc (+libatomic).
 *     The v8+ marking comes entirely from Debian's prebuilt 32-bit
 *     runtime: `objdump -d lib32/libstdc++.so.6 | grep -c casa|popc|
 *     membar|flushw` = 4, while our `-mcpu=v8` object contributes 0
 *     casa/popc. Default `-m32` (no -mcpu=v8) is v8+ throughout.
 *  4. `qemu-sparc -cpu LEON3 /tmp/h4v8h` → `Invalid ELF image for
 *     this architecture`, RC=255 (with a lib32 sysroot: identical).
 *     The translator rejects the same binary by construction:
 *     src/rt32/elf32.c refuses EM_SPARC32PLUS and any e_flags other
 *     than 0/0x300 (0x100 is neither), and the dependency closure
 *     contains real V9 opcodes no V8 context can execute.
 *     (Diagnostic only, admissible nowhere: qemu-sparc32plus with
 *     the same sysroot produced no output, RC=137 — not pursued,
 *     32plus is not an oracle CPU.)
 *  5. Therefore no committed C++ feature can be verified on the
 *     oracle or either engine here. The precise missing piece: a
 *     V8-target C++ toolchain whose libstdc++/libgcc_s/libc are
 *     built V8-clean (machine Sparc, flags 0) — Debian's multilib
 *     ships v8+ 32-bit runtimes only, nixpkgs has no sparc cross
 *     target at all (Phase 5 record), and building a V8 sysroot
 *     from source is outside this lane. A freestanding
 *     `-ffreestanding -fno-exceptions -fno-rtti` subset dies at the
 *     same gate (no 32-bit C++ link target), so it was not pursued
 *     past step 2 — and per the lane card, C-mimicked C++ would not
 *     count anyway.
 *
 * Host soundness proof (exact acceptance evidence, this machine):
 *   c++ -std=c++17 -Wall -Wextra -o /tmp/h4host tests/test_h4_cxx17.cc
 *   /tmp/h4host  → exit 0:
 *     H4-CXX17 start
 *     unwind frames=3 dtors=2 order=2,1 msg=boom-17
 *     rethrow val=42 dtor=7
 *     unwind signal=USR1 seen=1 dtors=12,11 msg=sig-17
 *     rtti down=x cross=null bad_cast=1 typeid=ok
 *     threads n=4 reps=1000 sum=4000 tld_dtors=4
 *     H4-CXX17-PASS
 */

#include <atomic>
#include <cstdio>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <thread>
#include <typeinfo>

#if defined(__unix__) || defined(__APPLE__)
#include <signal.h>
#define H4_HAVE_POSIX_SIGNAL 1
#endif

namespace {

int failures = 0;

#define CHECK(cond, tag)                                   \
  do {                                                     \
    if (!(cond)) {                                         \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__,  \
                  tag);                                    \
      ++failures;                                          \
      return false;                                        \
    }                                                      \
  } while (0)

/* --- unwinding across call frames ---------------------------------- */

int unwind_log[8];
int unwind_n = 0;

struct Guard {
  int id;
  explicit Guard(int i) : id(i) {}
  ~Guard() { unwind_log[unwind_n++] = id; }
};

void h4_level3() { throw std::runtime_error("boom-17"); }

void h4_level2() {
  Guard g(2);
  h4_level3();
}

void h4_level1() {
  Guard g(1);
  h4_level2();
}

bool test_unwind_frames() {
  unwind_n = 0;
  try {
    h4_level1();
  } catch (const std::exception &e) {
    CHECK(std::strcmp(e.what(), "boom-17") == 0, "unwind-msg");
  }
  CHECK(unwind_n == 2, "unwind-count");
  CHECK(unwind_log[0] == 2 && unwind_log[1] == 1, "unwind-order");
  std::printf("unwind frames=3 dtors=2 order=2,1 msg=boom-17\n");
  return failures == 0;
}

bool test_rethrow() {
  bool inner = false;
  unwind_n = 0;
  try {
    try {
      Guard g(7);
      throw 42;
    } catch (int v) {
      CHECK(v == 42, "rethrow-val");
      inner = true;
      throw;
    }
  } catch (int v) {
    CHECK(inner && v == 42, "rethrow-outer");
  }
  CHECK(unwind_n == 1 && unwind_log[0] == 7, "rethrow-dtor");
  std::printf("rethrow val=42 dtor=7\n");
  return failures == 0;
}

/* --- unwinding with a signal delivered mid-chain -------------------- */

#if defined(H4_HAVE_POSIX_SIGNAL)
volatile sig_atomic_t h4_sig_seen = 0;

void h4_on_usr1(int) { h4_sig_seen = 1; }

void h4_sig_level2() {
  Guard g(12);
  raise(SIGUSR1);
  throw std::runtime_error("sig-17");
}

bool test_unwind_signal() {
  struct sigaction sa;
  std::memset(&sa, 0, sizeof sa);
  sa.sa_handler = h4_on_usr1;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  CHECK(sigaction(SIGUSR1, &sa, nullptr) == 0, "sig-install");
  h4_sig_seen = 0;
  unwind_n = 0;
  try {
    Guard g(11);
    h4_sig_level2();
  } catch (const std::exception &e) {
    CHECK(std::strcmp(e.what(), "sig-17") == 0, "sig-msg");
  }
  CHECK(h4_sig_seen == 1, "sig-delivered");
  CHECK(unwind_n == 2, "sig-count");
  CHECK(unwind_log[0] == 12 && unwind_log[1] == 11, "sig-order");
  std::printf("unwind signal=USR1 seen=1 dtors=12,11 msg=sig-17\n");
  return failures == 0;
}
#endif

/* --- dynamic_cast RTTI ---------------------------------------------- */

struct H4Base {
  virtual ~H4Base() {}
  virtual const char *kind() const { return "base"; }
};

struct H4D1 : H4Base {
  int x;
  explicit H4D1(int v) : x(v) {}
  const char *kind() const override { return "d1"; }
};

struct H4D2 : H4Base {
  const char *kind() const override { return "d2"; }
};

bool test_rtti() {
  H4D1 d1(0x1117);
  H4D2 d2;
  H4Base *b1 = &d1;
  H4Base *b2 = &d2;
  H4D1 *down = dynamic_cast<H4D1 *>(b1);
  CHECK(down != nullptr && down->x == 0x1117, "rtti-down");
  CHECK(dynamic_cast<H4D2 *>(b1) == nullptr, "rtti-cross-null");
  CHECK(dynamic_cast<H4Base *>(b1) == b1, "rtti-up");
  bool threw = false;
  try {
    H4D1 &ref = dynamic_cast<H4D1 &>(*b2);
    (void)ref;
  } catch (const std::bad_cast &) {
    threw = true;
  }
  CHECK(threw, "rtti-badcast");
  CHECK(typeid(*b1) == typeid(H4D1), "rtti-typeid-eq");
  CHECK(typeid(*b1) != typeid(H4D2), "rtti-typeid-ne");
  std::printf("rtti down=x cross=null bad_cast=1 typeid=ok\n");
  return failures == 0;
}

/* --- std::thread + thread_local destructors -------------------------- */

constexpr int H4_NTHREADS = 4;
constexpr int H4_REPS = 1000;

std::atomic<long> h4_counter{0};
std::atomic<int> h4_tld_dtors{0};

struct H4ThreadTracer {
  bool armed = false;
  void touch() { armed = true; }
  ~H4ThreadTracer() {
    if (armed)
      h4_tld_dtors.fetch_add(1, std::memory_order_relaxed);
  }
};

thread_local H4ThreadTracer h4_tracer;

void h4_worker() {
  h4_tracer.touch();
  for (int i = 0; i < H4_REPS; ++i)
    h4_counter.fetch_add(1, std::memory_order_relaxed);
}

bool test_threads() {
  h4_counter.store(0);
  h4_tld_dtors.store(0);
  std::thread th[H4_NTHREADS];
  for (int i = 0; i < H4_NTHREADS; ++i)
    th[i] = std::thread(h4_worker);
  for (int i = 0; i < H4_NTHREADS; ++i)
    th[i].join();
  CHECK(h4_counter.load() == H4_NTHREADS * H4_REPS, "thread-sum");
  CHECK(h4_tld_dtors.load() == H4_NTHREADS, "thread-tld-dtors");
  std::printf("threads n=4 reps=1000 sum=4000 tld_dtors=4\n");
  return failures == 0;
}

}  // namespace

int main() {
  std::printf("H4-CXX17 start\n");
  bool ok = true;
  ok = test_unwind_frames() && ok;
  ok = test_rethrow() && ok;
#if defined(H4_HAVE_POSIX_SIGNAL)
  ok = test_unwind_signal() && ok;
#endif
  ok = test_rtti() && ok;
  ok = test_threads() && ok;
  if (ok && failures == 0) {
    std::printf("H4-CXX17-PASS\n");
    return 0;
  }
  std::printf("H4-CXX17-FAIL\n");
  return 1;
}
