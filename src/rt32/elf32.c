/*
 * src/rt32/elf32.c — ELFCLASS32 (EM_SPARC) big-endian loader
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Vendored from i686rt/src/rt32/rt32_elf32.c: renamed i686_→sparc32_,
 * retyped on sparc32_ctx_t, EM_386→EM_SPARC with ELFDATA2MSB and the
 * strict SPEC section 2.1 admission (e_flags == 0 ONLY; EM_SPARC32PLUS
 * and EF_SPARC_32PLUS fail with ENOEXEC, since V8+ 64-bit %g registers
 * and V9 insns have no 32-bit V8 context). SPARC code is word-aligned.
 */

#define _GNU_SOURCE
#include "rt32.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

static size_t elf_host_page(void)
{
    long p = sysconf(_SC_PAGESIZE);
    return (p > (long)SPARC32_PAGE_SIZE) ? (size_t)p : (size_t)SPARC32_PAGE_SIZE;
}

#define EI_NIDENT   16U
#define ELFCLASS32  1U
#define ELFDATA2MSB 2U
#define ET_EXEC     2U
#define ET_DYN      3U
#define EM_SPARC    2U
#define EM_SPARC32PLUS 18U
#define EF_SPARC_32PLUS 0x100U

#define PT_LOAD   1U
#define PT_INTERP 3U
#define PT_PHDR   6U

#define PF_X 0x1U
#define PF_W 0x2U
#define PF_R 0x4U

typedef struct elf32_ehdr {
    uint8_t  e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} elf32_ehdr_t;

typedef struct elf32_phdr {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
} elf32_phdr_t;

/* ELF header fields arrive big-endian on disk; swap to host order. */
static uint16_t be16(uint16_t v)
{
    return (uint16_t)((uint16_t)(v >> 8) | (uint16_t)(v << 8));
}

static uint32_t be32(uint32_t v)
{
    return ((v >> 24) & 0xFFU) | ((v >> 8) & 0xFF00U) |
           ((v << 8) & 0xFF0000U) | ((v << 24) & 0xFF000000U);
}

static void ehdr_from_be(elf32_ehdr_t *h)
{
    h->e_type      = be16(h->e_type);
    h->e_machine   = be16(h->e_machine);
    h->e_version    = be32(h->e_version);
    h->e_entry     = be32(h->e_entry);
    h->e_phoff     = be32(h->e_phoff);
    h->e_shoff     = be32(h->e_shoff);
    h->e_flags     = be32(h->e_flags);
    h->e_ehsize    = be16(h->e_ehsize);
    h->e_phentsize = be16(h->e_phentsize);
    h->e_phnum     = be16(h->e_phnum);
    h->e_shentsize = be16(h->e_shentsize);
    h->e_shnum     = be16(h->e_shnum);
    h->e_shstrndx  = be16(h->e_shstrndx);
}

static void phdr_from_be(elf32_phdr_t *p)
{
    p->p_type   = be32(p->p_type);
    p->p_offset = be32(p->p_offset);
    p->p_vaddr  = be32(p->p_vaddr);
    p->p_paddr  = be32(p->p_paddr);
    p->p_filesz = be32(p->p_filesz);
    p->p_memsz  = be32(p->p_memsz);
    p->p_flags  = be32(p->p_flags);
    p->p_align  = be32(p->p_align);
}

int rt32_open_guest_ro(const sparc32_ctx_t *ctx, const char *guest_path)
{
    if (guest_path == NULL || guest_path[0] == '\0') {
        return -1;
    }
    /* Absolute guest paths resolve against the sysroot; the full resolver
     * (relative paths, /proc magic) arrives with the Phase 2 syscall marshal. */
    if (ctx != NULL && guest_path[0] == '/' &&
        ctx->sysroot != NULL && ctx->sysroot[0] != '\0') {
        char resolved[PATH_MAX];
        int n = snprintf(resolved, sizeof(resolved), "%s%s", ctx->sysroot, guest_path);
        if (n > 0 && (size_t)n < sizeof(resolved)) {
            int fd = open(resolved, O_RDONLY | O_CLOEXEC);
            if (fd >= 0) {
                return fd;
            }
        }
    }
    return open(guest_path, O_RDONLY | O_CLOEXEC);
}

static int pread_full(int fd, void *buf, size_t count, off_t offset)
{
    uint8_t *p = (uint8_t *)buf;
    size_t total = 0;
    while (total < count) {
        ssize_t n = pread(fd, p + total, count - total, offset + (off_t)total);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        total += (size_t)n;
    }
    return 0;
}

static int protect_and_record_seg(sparc32_ctx_t *ctx, uint32_t start, uint32_t end,
                                  uint32_t guest_prot, const char *label)
{
    size_t hp = elf_host_page();
    if (hp > (size_t)SPARC32_PAGE_SIZE) {
        uint32_t mask = (uint32_t)hp - 1U;
        uint32_t hp_start = start & ~mask;
        uint32_t hp_end   = (end + mask) & ~mask;
        int hprot = (guest_prot == 0U) ? PROT_NONE : (PROT_READ | PROT_WRITE);
        if (mprotect(sparc32_guest_ptr(ctx, hp_start), hp_end - hp_start,
                     hprot) != 0) {
            fprintf(stderr, "sparc32rt: %s: mprotect failed on [0x%x, 0x%x): %s\n",
                    label, start, end, strerror(errno));
            return -1;
        }
    } else if (mprotect(sparc32_guest_ptr(ctx, start), end - start,
                        sparc32_host_prot(ctx, guest_prot)) != 0) {
        fprintf(stderr, "sparc32rt: %s: mprotect failed on [0x%x, 0x%x): %s\n",
                label, start, end, strerror(errno));
        return -1;
    }
    rt32_vm_record_region(ctx, start, end, guest_prot, 0x12U, label);
    return 0;
}

static int load_elf32_image(sparc32_ctx_t *ctx, int fd, uint32_t default_pie_base,
                            const char *label, rt32_elf_info_t *out, bool commit,
                            rt32_elf_span_t *spans_out, size_t *nspan_out)
{
    struct stat st;
    elf32_ehdr_t ehdr;
    elf32_phdr_t phdrs[64];
    size_t nspan = 0U;
    size_t phdr_bytes;
    uint32_t min_vaddr = UINT32_MAX;
    uint32_t load_bias = 0U;
    uint64_t entry64 = 0ULL;
    uint16_t i;
    uint32_t highest_mapped_end  = 0U;
    uint32_t highest_mapped_prot = 0U;
    uint32_t prev_seg_end        = 0U;
    uint32_t fallback_phdr_vaddr = 0U;
    bool     entry_in_load       = false;
    bool     phdr_in_load        = false;

    if (fstat(fd, &st) != 0) {
        return -errno;
    }
    if (S_ISDIR(st.st_mode)) {
        return -EISDIR;
    }
    if (!S_ISREG(st.st_mode)) {
        return -EACCES;
    }
    if (pread_full(fd, &ehdr, sizeof(ehdr), 0) != 0) {
        if (commit) {
            fprintf(stderr, "sparc32rt: %s: failed to read ELF header\n", label);
        }
        return -ENOEXEC;
    }

    if (ehdr.e_ident[0] != 0x7fU || ehdr.e_ident[1] != 'E' ||
        ehdr.e_ident[2] != 'L'  || ehdr.e_ident[3] != 'F') {
        if (commit) {
            fprintf(stderr, "sparc32rt: %s: not an ELF file\n", label);
        }
        return -ENOEXEC;
    }
    if (ehdr.e_ident[4] != ELFCLASS32 || ehdr.e_ident[5] != ELFDATA2MSB) {
        if (commit) {
            fprintf(stderr, "sparc32rt: %s: not a 32-bit big-endian SPARC ELF\n", label);
        }
        return -ENOEXEC;
    }
    ehdr_from_be(&ehdr);
    if (ehdr.e_machine == EM_SPARC32PLUS) {
        if (commit) {
            fprintf(stderr, "sparc32rt: %s: EM_SPARC32PLUS rejected (V8 context only)\n", label);
        }
        return -ENOEXEC;
    }
    if (ehdr.e_machine != EM_SPARC) {
        if (commit) {
            fprintf(stderr, "sparc32rt: %s: not a SPARC (EM_SPARC) ELF\n", label);
        }
        return -ENOEXEC;
    }
    if (ehdr.e_flags != 0U && ehdr.e_flags != 0x300U) {
        if (commit) {
            fprintf(stderr, "sparc32rt: %s: e_flags 0x%x rejected (V8 requires 0)\n",
                    label, ehdr.e_flags);
        }
        return -ENOEXEC;
    }
    if (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) {
        if (commit) {
            fprintf(stderr, "sparc32rt: %s: unsupported ELF type %u\n", label, ehdr.e_type);
        }
        return -ENOEXEC;
    }
    if (ehdr.e_phentsize != sizeof(elf32_phdr_t) || ehdr.e_phnum == 0U || ehdr.e_phnum > 64U) {
        if (commit) {
            fprintf(stderr, "sparc32rt: %s: invalid program header table\n", label);
        }
        return -ENOEXEC;
    }

    phdr_bytes = (size_t)ehdr.e_phnum * sizeof(elf32_phdr_t);
    if (pread_full(fd, phdrs, phdr_bytes, (off_t)ehdr.e_phoff) != 0) {
        if (commit) {
            fprintf(stderr, "sparc32rt: %s: failed to read program headers\n", label);
        }
        return -ENOEXEC;
    }
    for (i = 0; i < ehdr.e_phnum; i++) {
        phdr_from_be(&phdrs[i]);
        if (phdrs[i].p_type == PT_LOAD && phdrs[i].p_memsz > 0U) {
            if (phdrs[i].p_vaddr < min_vaddr) {
                min_vaddr = phdrs[i].p_vaddr;
            }
        }
    }
    if (min_vaddr == UINT32_MAX) {
        if (commit) {
            fprintf(stderr, "sparc32rt: %s: no PT_LOAD segments\n", label);
        }
        return -ENOEXEC;
    }

    if (ehdr.e_type == ET_DYN && min_vaddr < 0x10000U) {
        load_bias = default_pie_base;
    }

    if (ehdr.e_entry == 0U) {
        if (commit) {
            fprintf(stderr, "sparc32rt: %s: missing entry point (e_entry == 0)\n", label);
        }
        return -ENOEXEC;
    }

    entry64 = (uint64_t)ehdr.e_entry + (uint64_t)load_bias;
    if (entry64 < 0x10000ULL || entry64 >= (uint64_t)SPARC32_TASK_SIZE_TOP) {
        if (commit) {
            fprintf(stderr, "sparc32rt: %s: entry point 0x%llx out of guest bounds\n",
                    label, (unsigned long long)entry64);
        }
        return -ENOEXEC;
    }
    /* SPARC code is always 4-byte aligned; the DBT fetches whole words. */
    if ((entry64 & 3ULL) != 0ULL) {
        if (commit) {
            fprintf(stderr, "sparc32rt: %s: misaligned entry point 0x%llx\n",
                    label, (unsigned long long)entry64);
        }
        return -ENOEXEC;
    }

    memset(out, 0, sizeof(*out));
    out->load_bias = load_bias + sparc32_page_down(min_vaddr);
    out->entry     = (uint32_t)entry64;
    out->phent     = ehdr.e_phentsize;
    out->phnum     = ehdr.e_phnum;

    for (i = 0; i < ehdr.e_phnum; i++) {
        const elf32_phdr_t *ph = &phdrs[i];
        if (ph->p_type == PT_PHDR) {
            uint64_t phdr_va64 = (uint64_t)load_bias + (uint64_t)ph->p_vaddr;
            if (phdr_va64 + phdr_bytes <= (uint64_t)SPARC32_TASK_SIZE_TOP) {
                out->phdr_vaddr = (uint32_t)phdr_va64;
            }
        } else if (ph->p_type == PT_INTERP) {
            if (ph->p_filesz == 0U || ph->p_filesz >= sizeof(out->interp_path)) {
                if (commit) {
                    fprintf(stderr, "sparc32rt: %s: invalid PT_INTERP filesz %u\n",
                            label, ph->p_filesz);
                }
                return -ENOEXEC;
            }
            if (pread_full(fd, out->interp_path, ph->p_filesz, (off_t)ph->p_offset) != 0) {
                return -ENOEXEC;
            }
            out->interp_path[ph->p_filesz] = '\0';
            if (out->interp_path[0] == '\0') {
                return -ENOEXEC;
            }
        }
    }

    for (i = 0; i < ehdr.e_phnum; i++) {
        const elf32_phdr_t *ph = &phdrs[i];
        uint64_t seg_vaddr64;
        uint64_t memsz;
        uint32_t seg_vaddr;
        uint64_t seg_end64;
        uint32_t page_start;
        uint64_t map_end64;
        uint32_t map_end;
        uint32_t map_start;
        uint32_t guest_prot;
        uint32_t shared_end;
        uint32_t merged_prot;
        uint32_t read_file_off;
        uint32_t read_file_len;
        uint32_t base_va;
        size_t r;

        if (ph->p_type != PT_LOAD || ph->p_memsz == 0U) {
            continue;
        }
        if (ph->p_filesz > ph->p_memsz ||
            (uint64_t)ph->p_offset + (uint64_t)ph->p_filesz > (uint64_t)st.st_size) {
            if (commit) {
                fprintf(stderr, "sparc32rt: %s: invalid segment filesz (0x%x) > memsz (0x%x)\n",
                        label, ph->p_filesz, ph->p_memsz);
            }
            return -ENOEXEC;
        }

        seg_vaddr64 = (uint64_t)load_bias + (uint64_t)ph->p_vaddr;
        memsz       = (uint64_t)ph->p_memsz;
        if (seg_vaddr64 >= (uint64_t)SPARC32_TASK_SIZE_TOP ||
            seg_vaddr64 + memsz > (uint64_t)SPARC32_TASK_SIZE_TOP) {
            if (commit) {
                fprintf(stderr, "sparc32rt: %s: segment [0x%llx, 0x%llx) out of guest bounds\n",
                        label, (unsigned long long)seg_vaddr64,
                        (unsigned long long)(seg_vaddr64 + memsz));
            }
            return -ENOEXEC;
        }

        seg_vaddr = (uint32_t)seg_vaddr64;
        seg_end64 = seg_vaddr64 + memsz;
        if (seg_vaddr < prev_seg_end) {
            if (commit) {
                fprintf(stderr, "sparc32rt: %s: overlapping or out-of-order PT_LOAD segment at 0x%x\n",
                        label, seg_vaddr);
            }
            return -ENOEXEC;
        }
        prev_seg_end = (uint32_t)seg_end64;

        if (out->entry != 0U) {
            uint32_t entry_pc      = out->entry;
            uint32_t entry_min_len = 4U;
            if ((ph->p_flags & PF_X) != 0U &&
                entry_pc >= seg_vaddr &&
                (uint64_t)entry_pc + entry_min_len <= seg_vaddr64 + memsz) {
                entry_in_load = true;
            }
        }
        page_start = sparc32_page_down(seg_vaddr);
        map_end64  = (seg_end64 + 0xFFFULL) & ~0xFFFULL;
        if (page_start < 0x10000U || map_end64 > (uint64_t)SPARC32_TASK_SIZE_TOP) {
            if (commit) {
                fprintf(stderr, "sparc32rt: %s: segment [0x%x, 0x%llx) out of guest bounds\n",
                        label, page_start, (unsigned long long)map_end64);
            }
            return -ENOEXEC;
        }
        map_end   = (uint32_t)map_end64;
        map_start = (page_start < highest_mapped_end) ? highest_mapped_end : page_start;
        /* Retain the validated runtime span (S32-R3-10): [page_start,
         * map_end) is exactly what the commit phase maps, so the
         * prepare pass keeps it for overlap validation. */
        if (spans_out != NULL && nspan < RT32_ELF_MAX_SPANS) {
            spans_out[nspan].start = page_start;
            spans_out[nspan].end = map_end;
            nspan++;
        }
        if (commit && ctx != NULL) {
            for (r = 0U; r < ctx->region_count; r++) {
                if (map_start < ctx->regions[r].end && map_end > ctx->regions[r].start) {
                    fprintf(stderr, "sparc32rt: %s: segment [0x%x, 0x%x) overlaps existing region\n",
                            label, map_start, map_end);
                    return -ENOEXEC;
                }
            }
        }

        guest_prot = ((ph->p_flags & PF_R) ? (uint32_t)PROT_READ : 0U) |
                     ((ph->p_flags & PF_W) ? (uint32_t)PROT_WRITE : 0U) |
                     ((ph->p_flags & PF_X) ? (uint32_t)PROT_EXEC : 0U);

        shared_end  = (map_end < map_start) ? map_end : map_start;
        merged_prot = highest_mapped_prot | guest_prot;
        read_file_off = ph->p_offset;
        read_file_len = ph->p_filesz;
        if (ph->p_filesz > 0U) {
            uint32_t page_off = ph->p_vaddr & 0xFFFU;
            if (page_start == map_start && page_off != 0U && ph->p_offset >= page_off) {
                read_file_off = ph->p_offset - page_off;
                read_file_len = ph->p_filesz + page_off;
            }
        }

        if (commit && ctx != NULL) {
            if (page_start < map_start) {
                size_t hp = elf_host_page();
                uint32_t mask = (uint32_t)hp - 1U;
                uint32_t hp_start = page_start & ~mask;
                uint32_t hp_end   = (shared_end + mask) & ~mask;
                if (mprotect(sparc32_guest_ptr(ctx, hp_start), hp_end - hp_start,
                             PROT_READ | PROT_WRITE) != 0) {
                    return -ENOMEM;
                }
            }

            if (map_end > map_start) {
                size_t hp = elf_host_page();
                if (hp > (size_t)SPARC32_PAGE_SIZE) {
                    uint32_t mask = (uint32_t)hp - 1U;
                    uint32_t hp_start = map_start & ~mask;
                    uint32_t hp_end   = (map_end + mask) & ~mask;
                    if (mprotect(sparc32_guest_ptr(ctx, hp_start), hp_end - hp_start,
                                 PROT_READ | PROT_WRITE) != 0) {
                        return -ENOMEM;
                    }
                    memset(sparc32_guest_ptr(ctx, map_start), 0, map_end - map_start);
                } else {
                    void *res = mmap(sparc32_guest_ptr(ctx, map_start), map_end - map_start,
                                     PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
                    if (res == MAP_FAILED) {
                        return -ENOMEM;
                    }
                }
            }

            if (ph->p_filesz > 0U) {
                uint32_t dst_va = (read_file_off < ph->p_offset) ? map_start : seg_vaddr;
                if (pread_full(fd, sparc32_guest_ptr(ctx, dst_va), read_file_len,
                               (off_t)read_file_off) != 0) {
                    return -ENOEXEC;
                }
            }

            if (ph->p_memsz > ph->p_filesz) {
                memset(sparc32_guest_ptr(ctx, seg_vaddr + ph->p_filesz), 0,
                       (size_t)(ph->p_memsz - ph->p_filesz));
            }

            if (page_start < map_start) {
                if (protect_and_record_seg(ctx, page_start, shared_end, merged_prot, label) != 0) {
                    return -ENOMEM;
                }
                highest_mapped_prot = merged_prot;
            }
            if (map_end > map_start) {
                if (protect_and_record_seg(ctx, map_start, map_end, guest_prot, label) != 0) {
                    return -ENOMEM;
                }
                highest_mapped_end  = map_end;
                highest_mapped_prot = guest_prot;
            }
        } else {
            if (page_start < map_start) {
                highest_mapped_prot = merged_prot;
            }
            if (map_end > map_start) {
                highest_mapped_end  = map_end;
                highest_mapped_prot = guest_prot;
            }
        }

        if (ph->p_flags & PF_X) {
            if (out->text_start == 0U || seg_vaddr < out->text_start) {
                out->text_start = seg_vaddr;
            }
            if (seg_vaddr + ph->p_memsz > out->text_end) {
                out->text_end = seg_vaddr + ph->p_memsz;
            }
        }

        base_va = (read_file_off < ph->p_offset) ? page_start : seg_vaddr;
        if (out->phdr_vaddr != 0U &&
            out->phdr_vaddr >= base_va &&
            (uint64_t)out->phdr_vaddr + phdr_bytes <= (uint64_t)base_va + (uint64_t)read_file_len) {
            phdr_in_load = true;
        }
        if (fallback_phdr_vaddr == 0U && read_file_off <= ehdr.e_phoff &&
            (uint64_t)ehdr.e_phoff + phdr_bytes <= (uint64_t)read_file_off + (uint64_t)read_file_len) {
            fallback_phdr_vaddr = base_va + (ehdr.e_phoff - read_file_off);
        }

        if (map_end > out->max_vaddr) {
            out->max_vaddr = map_end;
        }
    }

    if (!phdr_in_load) {
        out->phdr_vaddr = 0U;
    }
    if (out->phdr_vaddr == 0U) {
        out->phdr_vaddr = fallback_phdr_vaddr;
    }

    if (!entry_in_load) {
        if (commit) {
            fprintf(stderr, "sparc32rt: %s: entry point 0x%x is not within any PT_LOAD segment\n",
                    label, out->entry);
        }
        return -ENOEXEC;
    }

    if (nspan_out != NULL) {
        *nspan_out = nspan;
    }
    return 0;
}

void rt32_elf_plan_close(rt32_elf_plan_t *plan)
{
    if (!plan) {
        return;
    }
    if (plan->exec_fd >= 0) {
        close(plan->exec_fd);
        plan->exec_fd = -1;
    }
    if (plan->interp_fd >= 0) {
        close(plan->interp_fd);
        plan->interp_fd = -1;
    }
}

/* True interval-overlap test for two mapped spans (S32-R3-10: the
 * spans come from the validated plan, not a second parse). */
static bool elf_spans_overlap(rt32_elf_span_t a, rt32_elf_span_t b)
{
    return a.start < b.end && b.start < a.end;
}

int rt32_elf_prepare(const sparc32_ctx_t *ctx, int exec_fd, const char *path,
                     rt32_elf_plan_t *out_plan)
{
    int rc;
    uint32_t brk_base;

    if (!out_plan) {
        return -EINVAL;
    }
    memset(out_plan, 0, sizeof(*out_plan));
    out_plan->exec_fd   = -1;
    out_plan->interp_fd = -1;
    out_plan->exec_pie_base = 0x00400000U;
    if (path) {
        snprintf(out_plan->exec_path, sizeof(out_plan->exec_path), "%s", path);
    }

    if (exec_fd >= 0) {
        out_plan->exec_fd = dup(exec_fd);
        if (out_plan->exec_fd < 0) {
            return -errno;
        }
    } else {
        if (!path || path[0] == '\0') {
            return -ENOENT;
        }
        out_plan->exec_fd = rt32_open_guest_ro(ctx, path);
        if (out_plan->exec_fd < 0) {
            return -errno;
        }
    }

    rc = load_elf32_image(NULL, out_plan->exec_fd, out_plan->exec_pie_base,
                          out_plan->exec_path[0] ? out_plan->exec_path : "[guest]",
                          &out_plan->exec_info, false,
                          out_plan->exec_spans, &out_plan->exec_nspan);
    if (rc != 0) {
        rt32_elf_plan_close(out_plan);
        return rc;
    }

    brk_base = sparc32_page_up(out_plan->exec_info.max_vaddr);
    out_plan->interp_pie_base = (brk_base > 0x3F000000U) ? brk_base : 0x3F000000U;

    if (out_plan->exec_info.interp_path[0] != '\0') {
        out_plan->interp_fd = rt32_open_guest_ro(ctx, out_plan->exec_info.interp_path);
        if (out_plan->interp_fd < 0) {
            int err = errno;
            rt32_elf_plan_close(out_plan);
            return -err;
        }
        rc = load_elf32_image(NULL, out_plan->interp_fd, out_plan->interp_pie_base,
                              out_plan->exec_info.interp_path, &out_plan->interp_info, false,
                              out_plan->interp_spans, &out_plan->interp_nspan);
        if (rc != 0) {
            rt32_elf_plan_close(out_plan);
            return rc;
        }
        /* True interval-overlap check between the interpreter and
         * executable segments (S32-R3-10): every retained exec PT_LOAD
         * span is tested against every retained interp PT_LOAD span.
         * The spans come from the same validated parse that commit
         * maps, so no second geometry interpretation can drift. The
         * old span-edge test (interp bias below the exec end with the
         * interp end past the exec bias) falsely rejected a
         * non-rebased interpreter landing in a hole between
         * executable segments even though no mapped pages collide.
         * Either span list is non-empty here: both images parsed with
         * at least one PT_LOAD above. */
        {
            size_t i;
            size_t j;
            for (i = 0U; i < out_plan->exec_nspan; i++) {
                for (j = 0U; j < out_plan->interp_nspan; j++) {
                    if (elf_spans_overlap(out_plan->exec_spans[i],
                            out_plan->interp_spans[j])) {
                        rt32_elf_plan_close(out_plan);
                        return -ENOEXEC;
                    }
                }
            }
        }
    }
    return 0;
}

int rt32_elf_validate(const sparc32_ctx_t *ctx, const char *path)
{
    rt32_elf_plan_t plan;
    int rc = rt32_elf_prepare(ctx, -1, path, &plan);
    if (rc == 0) {
        rt32_elf_plan_close(&plan);
    }
    return rc;
}

int rt32_elf_commit_plan(sparc32_ctx_t *ctx, rt32_elf_plan_t *plan,
                         rt32_elf_info_t *out_info)
{
    int rc;

    if (!ctx || !plan || !out_info || plan->exec_fd < 0) {
        rt32_elf_plan_close(plan);
        return -EINVAL;
    }

    rc = load_elf32_image(ctx, plan->exec_fd, plan->exec_pie_base,
                          plan->exec_path[0] ? plan->exec_path : "[guest]",
                          out_info, true, NULL, NULL);
    if (rc != 0) {
        rt32_elf_plan_close(plan);
        return rc;
    }

    ctx->elf_base  = out_info->load_bias;
    ctx->elf_entry = out_info->entry;
    ctx->brk_base  = sparc32_page_up(out_info->max_vaddr);
    ctx->brk_curr  = ctx->brk_base;

    if (out_info->interp_path[0] != '\0') {
        rt32_elf_info_t interp_info;
        uint32_t interp_end;
        int irc = load_elf32_image(ctx, plan->interp_fd, plan->interp_pie_base,
                                   out_info->interp_path, &interp_info, true,
                                   NULL, NULL);
        if (irc != 0) {
            rt32_elf_plan_close(plan);
            return irc;
        }
        out_info->interp_base = interp_info.load_bias;
        ctx->interp_base      = interp_info.load_bias;
        ctx->elf_entry        = interp_info.entry;
        out_info->app_entry   = out_info->entry;
        out_info->entry       = interp_info.entry;
        interp_end            = sparc32_page_up(interp_info.max_vaddr);
        if (ctx->brk_base >= interp_info.load_bias && ctx->brk_base < interp_end) {
            ctx->brk_base = interp_end;
            ctx->brk_curr = interp_end;
        }
    }

    rt32_elf_plan_close(plan);
    return 0;
}

int rt32_elf_load(sparc32_ctx_t *ctx, int exec_fd, const char *path, rt32_elf_info_t *out_info)
{
    rt32_elf_plan_t plan;
    int rc;

    if (!ctx || !out_info) {
        if (exec_fd >= 0) {
            close(exec_fd);
        }
        return -EINVAL;
    }
    rc = rt32_elf_prepare(ctx, exec_fd, path, &plan);
    if (exec_fd >= 0) {
        close(exec_fd);
    }
    if (rc != 0) {
        return rc;
    }
    return rt32_elf_commit_plan(ctx, &plan, out_info);
}