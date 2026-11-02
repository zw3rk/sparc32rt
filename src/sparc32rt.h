/*
 * src/sparc32rt.h — Core context, constants, and module interfaces for sparc32rt
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 0 freeze (SPEC section 2.1): the layout of the ABI-locked prefix of
 * sparc32_ctx_t is locked for the future DBT trampoline (Phase 2) and the
 * a64 emitter. Fields after the IBTC array are C-only and may be extended
 * at the tail between phases; never inside the locked prefix.
 *
 * CPU state (SPEC section 2.1): active 32-register view r[32]
 * (%g0..%g7 = r[0..7] with r[0]=0, %o0..%o7 = r[8..15] with %o6 = %sp,
 * %l0..%l7 = r[16..23], %i0..%i7 = r[24..31] with %i6 = %fp), pc, npc,
 * y, psr (icc bits 23:20 = N,Z,V,C), fsr (fcc bits 11:10),
 * f[32] (%f0..%f31). Register-window management state (cwp, cansave,
 * canrestore, otherwin, cleanwin, nwindows) tracks the 8 LEON3 windows;
 * SAVE/RESTORE spill/fill the active %l/%i view to the guest stack.
 */

#ifndef SPARC32RT_H
#define SPARC32RT_H

#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "a32host.h" /* vendored, byte-identical to a32rt/i686rt (D14) */

/* Active register-view indices. */
#define SPARC32_G0 0U
#define SPARC32_G1 1U
#define SPARC32_G2 2U
#define SPARC32_G3 3U
#define SPARC32_G4 4U
#define SPARC32_G5 5U
#define SPARC32_G6 6U
#define SPARC32_G7 7U
#define SPARC32_O0 8U
#define SPARC32_O1 9U
#define SPARC32_O2 10U
#define SPARC32_O3 11U
#define SPARC32_O4 12U
#define SPARC32_O5 13U
#define SPARC32_O6 14U
#define SPARC32_O7 15U
#define SPARC32_SP 14U /* %o6 = %sp */
#define SPARC32_L0 16U
#define SPARC32_I0 24U
#define SPARC32_I6 30U
#define SPARC32_FP 30U /* %i6 = %fp */

/* PSR icc bits (SPEC section 2.1: bits 23:20 hold N,Z,V,C). */
#define SPARC32_PSR_N (1U << 23)
#define SPARC32_PSR_Z (1U << 22)
#define SPARC32_PSR_V (1U << 21)
#define SPARC32_PSR_C (1U << 20)
#define SPARC32_PSR_ICC_MASK \
    (SPARC32_PSR_N | SPARC32_PSR_Z | SPARC32_PSR_V | SPARC32_PSR_C)

/* FSR fcc bits (SPEC section 2.1: bits 11:10). */
#define SPARC32_FSR_FCC_SHIFT 10U
#define SPARC32_FSR_FCC_MASK  (3U << SPARC32_FSR_FCC_SHIFT)

/* Register-window constants (LEON3: 8 windows). */
#define SPARC32_NWINDOWS     8U
#define SPARC32_RWINDOW_SIZE 64U /* 16 big-endian words at [%sp + 0 .. %sp + 60] */

/* Block exit reasons (engines return to the dispatcher via ctx->exit_reason). */
#define SPARC32_EXIT_NONE        0U
#define SPARC32_EXIT_BRANCH     1U /* taken branch/call/jump/ret to ctx->exit_dest */
#define SPARC32_EXIT_SYSCALL    2U /* ta 0x10: %g1 = nr, %o0..%o5 = args */
#define SPARC32_EXIT_UNDEF      3U /* undecodable insn: interpreter single-step */
#define SPARC32_EXIT_FAULT      4U /* guest memory fault; ctx->fault_addr set */
#define SPARC32_EXIT_TRAP       5U /* ta other than 0x10 / debug trap */
#define SPARC32_EXIT_SINGLE_STEP 6U /* page-final non-annulled branch at 0xffc */

/* Architectural limits, cache capacities, page/window constants. */
#define SPARC32_MAX_REGIONS   512U
#define SPARC32_RAS_SIZE      64U
#define SPARC32_IBTC_SIZE     1024U
#define SPARC32_PAGE_SIZE     4096U
#define SPARC32_TASK_SIZE_TOP 0xF0000000U /* SPARC32 Linux user limit (SPEC 1.1) */
#define SPARC32_STACK_TOP     0xEFFF0000U /* initial stack top (SPEC 1.1) */
#define SPARC32_SIGTRAMP_PAGE 0xEFFFE000U /* sigtramp page (owned by L0b sigframe) */
#define SPARC32_LOW_GUARD_SIZE 0x00010000U

typedef struct sparc32_region {
    uint32_t start;
    uint32_t end;
    uint32_t prot;
    uint32_t flags;
    char     name[64];
} sparc32_region_t;

typedef struct sparc32_ibtc_entry {
    uint32_t    key;       /* guest PC (identity, no delay-slot bit) */
    uint32_t    epoch;
    const void *host_code;
    void       *entry;
    uint64_t    pad;
} sparc32_ibtc_entry_t;

_Static_assert(sizeof(sparc32_ibtc_entry_t) == 32, "sparc32_ibtc_entry_t must be 32 bytes");

/* Engine selection (SPARC32RT_ENGINE, --engine). */
enum {
    SPARC32_ENGINE_INTERP = 0, /* portable C interpreter: correctness oracle */
    SPARC32_ENGINE_DBT    = 1  /* SPARC V8 -> A64 dynamic binary translator */
};

/*
 * Architectural + runtime state for a SPARC V8 guest thread.
 *
 * ABI-locked prefix (offsets 0..0x8990) shared with the Phase 2 trampoline:
 *   0x000 r[32]          %g/%o/%l/%i active window view (r[0] = 0)
 *   0x080 pc, 0x084 npc, 0x088 y, 0x08c psr
 *   0x090 fsr, 0x094 f[32]
 *   0x114 cwp..nwindows   register-window management state
 *   0x130 guest_base     host base G of the [G, G+4GiB) window
 *   0x138 exit_reason / exit_arg, 0x140 fault_addr, 0x144 exit_dest
 *   0x190 ras[64], 0x990 ibtc[1024]
 */
typedef struct sparc32_ctx {
    uint32_t r[32];                 /* 0x000 active window view */
    uint32_t pc;                    /* 0x080 */
    uint32_t npc;                   /* 0x084 */
    uint32_t y;                     /* 0x088 */
    uint32_t psr;                   /* 0x08c */
    uint32_t fsr;                   /* 0x090 */
    uint32_t f[32];                 /* 0x094 */
    uint32_t cwp;                   /* 0x114 current window pointer */
    uint32_t cansave;               /* 0x118 */
    uint32_t canrestore;            /* 0x11c */
    uint32_t otherwin;              /* 0x120 */
    uint32_t cleanwin;              /* 0x124 */
    uint32_t nwindows;              /* 0x128 */
    uint32_t pad_win;               /* 0x12c reserved */
    uint64_t guest_base;            /* 0x130 */
    uint32_t exit_reason;           /* 0x138 */
    uint32_t exit_arg;              /* 0x13c */
    uint32_t fault_addr;            /* 0x140 */
    uint32_t exit_dest;             /* 0x144 */
    uint64_t sig_mask;              /* 0x148 */
    volatile uint64_t pending_signals; /* 0x150 */
    bool     trace_enabled;         /* 0x158 */
    bool     gdb_enabled;           /* 0x159 */
    bool     single_step;           /* 0x15a */
    volatile bool sync_sig_delivered; /* 0x15b */
    uint32_t pad_lock1;             /* 0x15c */
    uint64_t blocks_executed;       /* 0x160 */
    uint64_t chain_hits;            /* 0x168 */
    void    *last_exec_entry;       /* 0x170 */
    uint64_t ibtc_hits;             /* 0x178 */
    uint64_t ras_hits;              /* 0x180 */
    uint32_t ras_top;               /* 0x188 */
    uint32_t pad_lock2;             /* 0x18c */
    sparc32_ibtc_entry_t ras[SPARC32_RAS_SIZE];   /* 0x190 */
    sparc32_ibtc_entry_t ibtc[SPARC32_IBTC_SIZE]; /* 0x990 */

    /* ---- C-only tail (no asm offset dependencies; extend at end only) ---- */

    /* Guest memory layout & allocator inside [G, G + 4GiB) */
    uint32_t brk_base;
    uint32_t brk_curr;
    uint32_t mmap_cursor;       /* bottom-up guest mmap cursor */
    uint32_t interp_base;
    uint32_t elf_base;
    uint32_t elf_entry;
    uint32_t stack_top;
    uint32_t stack_base;

    /* Host handshake (/dev/a32host, A32H_ABI 1.0/1.1) */
    a32h_info_t host_info;
    bool        has_host_info;

    /* Tracked guest regions (sorted by start) for /proc/self/maps + gaps */
    sparc32_region_t regions[SPARC32_MAX_REGIONS];
    size_t           region_count;

    /* Thread, futex, and signal state */
    uint32_t clear_child_tid;
    uint32_t robust_list_head;
    uint32_t robust_list_len;
    uint32_t altstack_sp;
    uint32_t altstack_size;
    uint32_t altstack_flags;
    int      host_tid;
    bool     is_thread_clone;

    /* Guest startup metadata for /proc/self/{cmdline,auxv,exe} */
    int      guest_argc;
    char   **guest_argv;
    char   **host_envp;
    uint32_t auxv_data[64];
    size_t   auxv_bytes;

    /* Configuration & engine selection */
    const char *sysroot;
    const char *exec_path;
    const char *cache_dir;
    int         engine;         /* SPARC32_ENGINE_* */
    bool        difftest;
    bool        stats_enabled;
    int         gdb_port;

    /* Instrumentation counters */
    uint64_t blocks_compiled;
    uint64_t syscalls_executed;
    uint64_t icache_flushes;
    uint64_t wx_transitions;

    /* Signal-frame anchor, per thread (fork/exec reset in Phase 4). */
    uint32_t sig_last_frame_va; /* 0 = none pending */
    uint32_t sig_last_frame_rt;

    /* JMPL delay-slot recovery (RC-U3-r2 #3): the DBT-emitted JMPL
     * sequence records its computed dynamic target here before running
     * the delay slot; delay-slot fault recovery reads this per-context
     * field (never the aot_sites.c global table, whose entries can be
     * evicted by other live contexts). */
    uint32_t jmpl_target;
    uint8_t jmpl_delay_armed;
    uint8_t jmpl_pad[3];
} sparc32_ctx_t;

/* ABI-locked offsets (Phase 2 trampoline + a64 emitter must agree). */
#define SPARC32_CTX_R_OFFSET       0x000U
#define SPARC32_CTX_PC_OFFSET      0x080U
#define SPARC32_CTX_PSR_OFFSET     0x08cU
#define SPARC32_CTX_F_OFFSET       0x094U
#define SPARC32_CTX_CWP_OFFSET     0x114U
#define SPARC32_CTX_GUEST_BASE_OFFSET 0x130U

_Static_assert(offsetof(sparc32_ctx_t, r) == 0, "r must be at offset 0");
_Static_assert(offsetof(sparc32_ctx_t, pc) == 0x080, "pc must be at offset 0x080");
_Static_assert(offsetof(sparc32_ctx_t, npc) == 0x084, "npc must be at offset 0x084");
_Static_assert(offsetof(sparc32_ctx_t, y) == 0x088, "y must be at offset 0x088");
_Static_assert(offsetof(sparc32_ctx_t, psr) == 0x08c, "psr must be at offset 0x08c");
_Static_assert(offsetof(sparc32_ctx_t, fsr) == 0x090, "fsr must be at offset 0x090");
_Static_assert(offsetof(sparc32_ctx_t, f) == 0x094, "f must be at offset 0x094");
_Static_assert(offsetof(sparc32_ctx_t, cwp) == 0x114, "cwp must be at offset 0x114");
_Static_assert(offsetof(sparc32_ctx_t, cansave) == 0x118, "cansave must be at 0x118");
_Static_assert(offsetof(sparc32_ctx_t, canrestore) == 0x11c, "canrestore must be at 0x11c");
_Static_assert(offsetof(sparc32_ctx_t, otherwin) == 0x120, "otherwin must be at 0x120");
_Static_assert(offsetof(sparc32_ctx_t, cleanwin) == 0x124, "cleanwin must be at 0x124");
_Static_assert(offsetof(sparc32_ctx_t, nwindows) == 0x128, "nwindows must be at 0x128");
_Static_assert(offsetof(sparc32_ctx_t, guest_base) == 0x130, "guest_base must be at 0x130");
_Static_assert(offsetof(sparc32_ctx_t, exit_reason) == 0x138, "exit_reason must be at 0x138");
_Static_assert(offsetof(sparc32_ctx_t, exit_arg) == 0x13c, "exit_arg must be at 0x13c");
_Static_assert(offsetof(sparc32_ctx_t, fault_addr) == 0x140, "fault_addr must be at 0x140");
_Static_assert(offsetof(sparc32_ctx_t, exit_dest) == 0x144, "exit_dest must be at 0x144");
_Static_assert(offsetof(sparc32_ctx_t, sig_mask) == 0x148, "sig_mask must be at 0x148");
_Static_assert(offsetof(sparc32_ctx_t, pending_signals) == 0x150, "pending_signals must be at 0x150");
_Static_assert(offsetof(sparc32_ctx_t, trace_enabled) == 0x158, "trace_enabled must be at 0x158");
_Static_assert(offsetof(sparc32_ctx_t, blocks_executed) == 0x160, "blocks_executed must be at 0x160");
_Static_assert(offsetof(sparc32_ctx_t, chain_hits) == 0x168, "chain_hits must be at 0x168");
_Static_assert(offsetof(sparc32_ctx_t, last_exec_entry) == 0x170, "last_exec_entry must be at 0x170");
_Static_assert(offsetof(sparc32_ctx_t, ibtc_hits) == 0x178, "ibtc_hits must be at 0x178");
_Static_assert(offsetof(sparc32_ctx_t, ras_hits) == 0x180, "ras_hits must be at 0x180");
_Static_assert(offsetof(sparc32_ctx_t, ras_top) == 0x188, "ras_top must be at 0x188");
_Static_assert(offsetof(sparc32_ctx_t, ras) == 0x190, "ras must be at offset 0x190");
_Static_assert(offsetof(sparc32_ctx_t, ibtc) == 0x990, "ibtc must be at offset 0x990");
_Static_assert(sizeof(sparc32_ibtc_entry_t) * SPARC32_IBTC_SIZE == 32768,
               "IBTC array must span offsets 0x990..0x8990");

static inline void sparc32_spin_lock(_Atomic uint32_t *lock)
{
    while (atomic_exchange_explicit(lock, 1U, memory_order_acquire) != 0U) {
        sched_yield();
    }
}

static inline void sparc32_spin_unlock(_Atomic uint32_t *lock)
{
    atomic_store_explicit(lock, 0U, memory_order_release);
}

/* Guest VA -> host pointer. va is u32: never sign-extend or truncate. */
static inline void *sparc32_guest_ptr(const sparc32_ctx_t *ctx, uint32_t guest_va)
{
    return (void *)(uintptr_t)(ctx->guest_base + (uint64_t)guest_va);
}

static inline uint32_t sparc32_page_down(uint32_t x)
{
    return x & ~(SPARC32_PAGE_SIZE - 1U);
}

static inline uint32_t sparc32_page_up(uint32_t x)
{
    return (x + (SPARC32_PAGE_SIZE - 1U)) & ~(SPARC32_PAGE_SIZE - 1U);
}

/* Cache keys hash on guest PC only; SPARC insns are 4-byte aligned. */
static inline uint32_t sparc32_make_key(uint32_t pc)
{
    return pc;
}

static inline uint32_t sparc32_ibtc_hash(uint32_t pc)
{
    return (pc >> 2U) & (SPARC32_IBTC_SIZE - 1U);
}

/*
 * Regime VM + Provider-A runtime hooks (RC-U3-r2 #4: defined in
 * src/vm/vm32.c and src/vm/vm_file.c; wired into the runtime VM
 * lifecycle from src/main.c and src/rt32/vm_mmap.c).
 */
int vm32_attach(sparc32_ctx_t *ctx);
void vm32_reset(void);
void vm32_publish_page(uint32_t gva, uint32_t prot, uint32_t state);
uint32_t vm32_page_state(uint32_t gva);
void vm32_page_revert_clean(uint32_t gva);
void vm32_note_page_write(uint32_t gva, size_t len);
void vm32_note_code_page(uint32_t gva, uint32_t len);
void vm32_clear_code_range(uint32_t start, uint32_t end);
bool vm32_range_has_code(uint32_t gva, size_t len);
const uint8_t *sparc32_vm_prot_base(void);
const uint8_t *sparc32_vm_state_base(void);
void sparc32_vm_access_enter(void);
void sparc32_vm_access_leave(void);
void sparc32_vm_fork_child_reset(void);
void vm_file_note_mutation(uint64_t dev, uint64_t ino, int host_fd,
    uint64_t new_size);
void vm_file_note_mapping(uint64_t dev, uint64_t ino, int host_fd,
    uint32_t map_gva, uint32_t map_pages, uint64_t map_off);
void vm_invalidate_jit(sparc32_ctx_t *ctx, uint32_t start, uint32_t end);

/*
 * Guest prot -> host prot for window mappings. Guest PROT_EXEC is never
 * host-exec (window is data; translated code lives outside the window),
 * which also dissolves any W^X conflict; SMC write-protection is layered
 * on top by the JIT, not here.
 */
static inline int sparc32_host_prot(const sparc32_ctx_t *ctx, uint32_t guest_prot)
{
    (void)ctx;
    uint32_t p = guest_prot & 0x7U;
    if ((p & 0x4U) != 0U) {
        p |= 0x1U; /* PROT_EXEC implies PROT_READ on host */
        p &= ~0x4U;
    }
    return (int)p;
}

#endif /* SPARC32RT_H */
