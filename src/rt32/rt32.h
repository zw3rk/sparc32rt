/*
 * src/rt32/rt32.h — Interfaces of the vendored SPARC32 ISA-agnostic core
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copy-first vendoring from the proven i686rt src/rt32/ substrate:
 * mechanical renames i686_→rt32_ (rt32_vm.c, rt32_elf32.c, rt32_stack32.c,
 * rt32_host.c, rt32_a64_emit.[ch]), all code retyped on the frozen
 * sparc32_ctx_t from src/sparc32rt.h. a32h_* / A32H_* handshake symbols
 * are untouched (include/a32host.h is byte-identical, A32H_ABI 1.0/1.1).
 *
 * Per-file i686rt origins:
 *   vm.c            ← i686rt/src/rt32/rt32_vm.c (window init, regions, brk)
 *   vm_mmap.c       ← i686rt/src/rt32/rt32_vm.c (mmap2/mprotect/munmap/mremap,
 *                     gap finder, CLONE_VM page-table locking)
 *   elf32.c         ← i686rt/src/rt32/rt32_elf32.c (ELF32 loader; EM_SPARC,
 *                     big-endian, e_flags == 0 admission)
 *   stack32.c       ← i686rt/src/rt32/rt32_stack32.c (initial stack with the
 *                     64-byte rwindow save area; argc at %sp + 64)
 *   host.c          ← i686rt/src/rt32/rt32_host.c (/dev/a32host probe)
 *   a64_emit.[ch]   ← i686rt/src/rt32/rt32_a64_emit.[ch] (host-side AArch64
 *                     encoder: [x20, wAddr, uxtw] guest access; split into
 *                     a64_emit.c (integer/core) + a64_emit_fp.c (FP/crypto,
 *                     exclusives, exits) to hold the 900-line limit)
 *   safe_syscall_a64.S ← D18 signal-window race-free host-syscall commit
 *                     point (restartable by the Phase 4 signal layer).
 *
 * Environment variables read by this code:
 *   SPARC32RT_WINDOW — requested guest window base G for vm init
 *   SPARC32RT_HOST   — set to "none" to skip the /dev/a32host probe
 */

#ifndef SPARC32RT_RT32_H
#define SPARC32RT_RT32_H

#include "sparc32rt.h"

/* Host handshake (host.c) */
void rt32_host_probe(sparc32_ctx_t *ctx);

/* Guest window & memory management (vm.c, vm_mmap.c) */
int      rt32_vm_init(sparc32_ctx_t *ctx, uint64_t requested_window);
int      rt32_vm_record_region(sparc32_ctx_t *ctx, uint32_t start, uint32_t end,
                              uint32_t prot, uint32_t flags, const char *name);
uint32_t rt32_vm_brk(sparc32_ctx_t *ctx, uint32_t new_brk);
void rt32_vm_reset_for_exec(sparc32_ctx_t *ctx);
uint32_t rt32_vm_mmap2(sparc32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot,
                       uint32_t flags, int fd, uint32_t pgoffset);
int      rt32_vm_mprotect(sparc32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot);
int      rt32_vm_munmap(sparc32_ctx_t *ctx, uint32_t addr, uint32_t len);
uint32_t rt32_vm_mremap(sparc32_ctx_t *ctx, uint32_t old_addr, uint32_t old_len,
                        uint32_t new_len, uint32_t flags, uint32_t new_addr);
void     rt32_vm_sync_ctx(sparc32_ctx_t *ctx);

/* Safe host syscall with a D18 restartable commit point (safe_syscall_a64.S) */
long rt32_safe_syscall(long nr, long a0, long a1, long a2, long a3, long a4, long a5);

/* ELF32 loader & initial stack (elf32.c, stack32.c) */
typedef struct rt32_elf_info {
    uint32_t entry;
    uint32_t app_entry;
    uint32_t phdr_vaddr;
    uint32_t phent;
    uint32_t phnum;
    uint32_t load_bias;
    uint32_t max_vaddr;
    uint32_t interp_base;
    uint32_t text_start;
    uint32_t text_end;
    char     interp_path[256];
} rt32_elf_info_t;

/* Runtime-mapped span of one PT_LOAD segment (S32-R3-10): the
 * prepare pass retains the validated geometry so overlap validation
 * reuses it instead of reparsing the image. */
typedef struct rt32_elf_span {
    uint32_t start;
    uint32_t end;
} rt32_elf_span_t;

#define RT32_ELF_MAX_SPANS 64U

typedef struct rt32_elf_plan {
    int             exec_fd;
    int             interp_fd;
    uint32_t        exec_pie_base;
    uint32_t        interp_pie_base;
    rt32_elf_info_t exec_info;
    rt32_elf_info_t interp_info;
    rt32_elf_span_t exec_spans[RT32_ELF_MAX_SPANS];
    size_t          exec_nspan;
    rt32_elf_span_t interp_spans[RT32_ELF_MAX_SPANS];
    size_t          interp_nspan;
    char            exec_path[256];
} rt32_elf_plan_t;

int  rt32_open_guest_ro(const sparc32_ctx_t *ctx, const char *guest_path);
int  rt32_elf_prepare(const sparc32_ctx_t *ctx, int exec_fd, const char *path,
                      rt32_elf_plan_t *out_plan);
void rt32_elf_plan_close(rt32_elf_plan_t *plan);
int  rt32_elf_commit_plan(sparc32_ctx_t *ctx, rt32_elf_plan_t *plan,
                          rt32_elf_info_t *out_info);
int  rt32_elf_validate(const sparc32_ctx_t *ctx, const char *path);
int  rt32_elf_load(sparc32_ctx_t *ctx, int exec_fd, const char *path,
                   rt32_elf_info_t *out_info);
int rt32_stack_setup(sparc32_ctx_t *ctx, const rt32_elf_info_t *elf_info,
                    int guest_argc, char **guest_argv, char **host_envp,
                    uint32_t *out_sp);

#endif /* SPARC32RT_RT32_H */
