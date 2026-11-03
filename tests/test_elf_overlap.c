/*
 * tests/test_elf_overlap.c — host-native interp/exec overlap check.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Regression test for Section 3 #8: rt32_elf_prepare must apply a true
 * interval-overlap check between the interpreter and executable PT_LOAD
 * segments. Crafts minimal SPARC ELF32 images in /tmp and drives
 * rt32_elf_prepare in dry-run mode (no guest memory touched):
 *   A. non-rebased interpreter landing in a hole between two executable
 *      segments is accepted (the old span-edge test rejected it);
 *   B. an interpreter truly overlapping an executable segment is
 *      rejected with -ENOEXEC;
 *   C. a rebased dynamic executable/interpreter pair is accepted;
 *   D. adjacent (touching but non-overlapping) images are accepted;
 *   E. a PT_LOAD with mismatched p_offset/p_vaddr page congruence is
 *      rejected with -ENOEXEC (S32-R9-7);
 *   F. a congruent nonzero-offset unaligned PT_LOAD is accepted.
 * Prints ELF-OVERLAP: PASS and exits 0 on success.
 *
 * Build & run (host-native):
 *   cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
 *     -Iinclude -Isrc tests/test_elf_overlap.c \
 *     src/rt32/elf32.c -o /tmp/test_elf_overlap && \
 *     /tmp/test_elf_overlap
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "rt32/rt32.h"

/* rt32_vm_record_region is only reached on the commit path; dry-run
 * prepare never calls it, but the link needs the symbol. */
int rt32_vm_record_region(sparc32_ctx_t *ctx, uint32_t start, uint32_t end,
                          uint32_t prot, uint32_t flags, const char *name)
{
    (void)ctx;
    (void)start;
    (void)end;
    (void)prot;
    (void)flags;
    (void)name;
    return 0;
}

static int failures = 0;

static void expect(int cond, const char *what)
{
    if (cond == 0) {
        printf("ELF-OVERLAP FAIL: %s\n", what);
        failures++;
    }
}

static void put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

typedef struct {
    uint32_t vaddr;
    uint32_t memsz;
    uint32_t flags;
} tseg_t;

#define T_IMG_SIZE 0x4000U
#define T_PHDR_OFF 52U
#define T_INTERP_OFF 512U
#define T_SEG0_OFF 0U
#define T_SEG0_FILESZ 0x400U
#define T_SEGN_OFF 0x1000U
#define T_SEGN_FILESZ 0x100U

/* Minimal SPARC ELF32: ehdr + phdrs + optional PT_INTERP path. Segment
 * file bytes are never read in dry-run mode, so filesz only needs to
 * satisfy the header bounds checks. offs optionally overrides the
 * default file offsets (NULL keeps 0/0x1000); used for the page-offset
 * congruence cases. */
static int write_image_off(const char *path, uint16_t etype,
                           const tseg_t *segs, const uint32_t *offs,
                           size_t nseg, uint32_t entry, const char *interp)
{
    uint8_t img[T_IMG_SIZE];
    size_t phnum = nseg + ((interp != NULL) ? 1U : 0U);
    size_t i;
    FILE *f;
    memset(img, 0, sizeof img);
    if (phnum == 0U || phnum > 4U || nseg == 0U) {
        return -1;
    }
    img[0] = 0x7fU;
    img[1] = (uint8_t)'E';
    img[2] = (uint8_t)'L';
    img[3] = (uint8_t)'F';
    img[4] = 1U;
    img[5] = 2U;
    img[6] = 1U;
    put_be16(img + 16, etype);
    put_be16(img + 18, 2U);
    put_be32(img + 20, 1U);
    put_be32(img + 24, entry);
    put_be32(img + 28, (uint32_t)T_PHDR_OFF);
    put_be32(img + 32, 0U);
    put_be32(img + 36, 0U);
    put_be16(img + 40, 52U);
    put_be16(img + 42, 32U);
    put_be16(img + 44, (uint16_t)phnum);
    put_be16(img + 46, 0U);
    put_be16(img + 48, 0U);
    put_be16(img + 50, 0U);
    for (i = 0U; i < nseg; i++) {
        uint8_t *ph = img + T_PHDR_OFF + i * 32U;
        uint32_t off = (offs != NULL) ? offs[i] :
            ((i == 0U) ? (uint32_t)T_SEG0_OFF : (uint32_t)T_SEGN_OFF);
        uint32_t fsz = (i == 0U) ? (uint32_t)T_SEG0_FILESZ
                                 : (uint32_t)T_SEGN_FILESZ;
        put_be32(ph + 0, 1U);
        put_be32(ph + 4, off);
        put_be32(ph + 8, segs[i].vaddr);
        put_be32(ph + 12, segs[i].vaddr);
        put_be32(ph + 16, fsz);
        put_be32(ph + 20, segs[i].memsz);
        put_be32(ph + 24, segs[i].flags);
        put_be32(ph + 28, 0x1000U);
    }
    if (interp != NULL) {
        uint8_t *ph = img + T_PHDR_OFF + nseg * 32U;
        size_t len = strlen(interp) + 1U;
        if (len >= 256U || (uint32_t)T_INTERP_OFF + (uint32_t)len > T_IMG_SIZE) {
            return -1;
        }
        put_be32(ph + 0, 3U);
        put_be32(ph + 4, (uint32_t)T_INTERP_OFF);
        memcpy(img + T_INTERP_OFF, interp, len);
        put_be32(ph + 16, (uint32_t)len);
    }
    f = fopen(path, "wb");
    if (f == NULL) {
        return -1;
    }
    if (fwrite(img, 1, sizeof img, f) != sizeof img) {
        (void)fclose(f);
        return -1;
    }
    return fclose(f);
}

static int write_image(const char *path, uint16_t etype,
                       const tseg_t *segs, size_t nseg, uint32_t entry,
                       const char *interp)
{
    return write_image_off(path, etype, segs, NULL, nseg, entry, interp);
}

/* Drive one prepare: returns the rt32_elf_prepare result code. */
static int run_prepare(const char *exec_path)
{
    rt32_elf_plan_t plan;
    int rc = rt32_elf_prepare(NULL, -1, exec_path, &plan);
    if (rc == 0) {
        rt32_elf_plan_close(&plan);
    }
    return rc;
}

int main(void)
{
    char exec_path[128];
    char interp_path[128];
    int rc;
    snprintf(exec_path, sizeof exec_path,
             "/tmp/sparc32rt-elfov-exec.elf");
    snprintf(interp_path, sizeof interp_path,
             "/tmp/sparc32rt-elfov-interp.elf");

    /* Case A: interpreter in a hole between executable segments. */
    {
        static const tseg_t exec_segs[] = {
            { 0x10000U, 0x1000U, 5U },
            { 0x40000U, 0x1000U, 6U },
        };
        static const tseg_t interp_segs[] = {
            { 0x20000U, 0x1000U, 5U },
        };
        expect(write_image(interp_path, 2U, interp_segs, 1U, 0x20000U,
            NULL) == 0, "case A: write interp");
        expect(write_image(exec_path, 2U, exec_segs, 2U, 0x10000U,
            interp_path) == 0, "case A: write exec");
        rc = run_prepare(exec_path);
        expect(rc == 0, "case A: interp in exec hole accepted");
    }

    /* Case B: interpreter truly overlapping an executable segment. */
    {
        static const tseg_t exec_segs[] = {
            { 0x10000U, 0x2000U, 5U },
        };
        static const tseg_t interp_segs[] = {
            { 0x11000U, 0x2000U, 5U },
        };
        expect(write_image(interp_path, 2U, interp_segs, 1U, 0x11000U,
            NULL) == 0, "case B: write interp");
        expect(write_image(exec_path, 2U, exec_segs, 1U, 0x10000U,
            interp_path) == 0, "case B: write exec");
        rc = run_prepare(exec_path);
        expect(rc == -ENOEXEC, "case B: overlapping interp rejected");
    }

    /* Case C: rebased dynamic pair (ET_DYN below 0x10000). */
    {
        static const tseg_t exec_segs[] = {
            { 0x0U, 0x5000U, 5U },
        };
        static const tseg_t interp_segs[] = {
            { 0x0U, 0x3000U, 5U },
        };
        expect(write_image(interp_path, 3U, interp_segs, 1U, 0x1000U,
            NULL) == 0, "case C: write interp");
        expect(write_image(exec_path, 3U, exec_segs, 1U, 0x1000U,
            interp_path) == 0, "case C: write exec");
        rc = run_prepare(exec_path);
        expect(rc == 0, "case C: rebased dynamic pair accepted");
    }

    /* Case D: adjacent images sharing only an edge. */
    {
        static const tseg_t exec_segs[] = {
            { 0x10000U, 0x1000U, 5U },
        };
        static const tseg_t interp_segs[] = {
            { 0x11000U, 0x1000U, 5U },
        };
        expect(write_image(interp_path, 2U, interp_segs, 1U, 0x11000U,
            NULL) == 0, "case D: write interp");
        expect(write_image(exec_path, 2U, exec_segs, 1U, 0x10000U,
            interp_path) == 0, "case D: write exec");
        rc = run_prepare(exec_path);
        expect(rc == 0, "case D: adjacent images accepted");
    }

    /* Case E: p_offset/p_vaddr page-congruence mismatch rejected. */
    {
        static const tseg_t exec_segs[] = {
            { 0x10000U, 0x1000U, 5U },
        };
        static const uint32_t exec_offs[] = { 0x1U };
        expect(write_image_off(exec_path, 2U, exec_segs, exec_offs, 1U,
            0x10000U, NULL) == 0, "case E: write exec");
        rc = run_prepare(exec_path);
        expect(rc == -ENOEXEC, "case E: incongruent LOAD rejected");
    }

    /* Case F: nonzero but congruent p_offset/p_vaddr accepted. */
    {
        static const tseg_t exec_segs[] = {
            { 0x11001U, 0x1000U, 5U },
        };
        static const uint32_t exec_offs[] = { 0x1001U };
        expect(write_image_off(exec_path, 2U, exec_segs, exec_offs, 1U,
            0x11004U, NULL) == 0, "case F: write exec");
        rc = run_prepare(exec_path);
        expect(rc == 0, "case F: congruent unaligned LOAD accepted");
    }

    (void)remove(exec_path);
    (void)remove(interp_path);
    if (failures == 0) {
        printf("ELF-OVERLAP: PASS\n");
        return 0;
    }
    return 1;
}
