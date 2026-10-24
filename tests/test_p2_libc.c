/*
 * tests/test_p2_libc.c — Phase 2 static-libc guest (lane L2d).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Exercises exactly the static-libc surface the Phase-2 syscall layer
 * must carry: hello, printf (int/%x/%s), malloc/free/calloc/realloc
 * (including a 1 MiB block), qsort over 10k ints (order verified), and
 * file I/O (openat/write/read/lseek/stat/close round-trip of 64 KiB,
 * byte-compared). Deterministic stdout; exit 0 means every check passed.
 *
 * Build (target cross-CC, static):
 *   sparc64-linux-gnu-gcc -m32 -static -O2 -o /tmp/t2 tests/test_p2_libc.c
 * Oracle:
 *   qemu-sparc -cpu LEON3 /tmp/t2
 * must match bit-for-bit.
 */

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define P2_FILE_BYTES 65536U
#define P2_QSORT_N 10000U
#define P2_MIB_BYTES (1024U * 1024U)
#define P2_TMP_PATH "/tmp/p2_libc_t.bin"

static uint32_t p2_rng_state = 0x12345678U;

static uint32_t p2_rng(void)
{
    p2_rng_state = p2_rng_state * 1103515245U + 12345U;
    return (p2_rng_state >> 16) & 0x7FFFU;
}

static int p2_data[P2_QSORT_N];
static unsigned char p2_wbuf[P2_FILE_BYTES];
static unsigned char p2_rbuf[P2_FILE_BYTES];

static int p2_fail(const char *msg)
{
    printf("P2-LIBC-FAIL %s\n", msg);
    fflush(stdout);
    return 1;
}

static int p2_cmp_int(const void *pa, const void *pb)
{
    int a = *(const int *)pa;
    int b = *(const int *)pb;
    return (a > b) - (a < b);
}

static int p2_check_printf(void)
{
    printf("hello libc\n");
    printf("int=%d hex=%x str=%s\n", -42, 0xDEADBEEFU, "sparc");
    return 0;
}

static int p2_check_alloc(void)
{
    unsigned char *big;
    unsigned int i;
    int *arr;
    int *grown;
    int *zeroed;

    arr = (int *)malloc(16U * sizeof(int));
    if (arr == NULL) {
        return p2_fail("malloc16");
    }
    for (i = 0U; i < 16U; i++) {
        arr[i] = (int)(i * i);
    }
    for (i = 0U; i < 16U; i++) {
        if (arr[i] != (int)(i * i)) {
            free(arr);
            return p2_fail("malloc16-content");
        }
    }
    free(arr);

    zeroed = (int *)calloc(64U, sizeof(int));
    if (zeroed == NULL) {
        return p2_fail("calloc");
    }
    for (i = 0U; i < 64U; i++) {
        if (zeroed[i] != 0) {
            free(zeroed);
            return p2_fail("calloc-zero");
        }
    }
    grown = (int *)realloc(zeroed, 128U * sizeof(int));
    if (grown == NULL) {
        free(zeroed);
        return p2_fail("realloc");
    }
    for (i = 0U; i < 64U; i++) {
        if (grown[i] != 0) {
            free(grown);
            return p2_fail("realloc-preserve");
        }
    }
    free(grown);

    big = (unsigned char *)malloc(P2_MIB_BYTES);
    if (big == NULL) {
        return p2_fail("malloc-1mib");
    }
    memset(big, 0xA5, P2_MIB_BYTES);
    for (i = 0U; i < P2_MIB_BYTES; i++) {
        if (big[i] != 0xA5U) {
            free(big);
            return p2_fail("malloc-1mib-content");
        }
    }
    free(big);
    printf("alloc ok\n");
    return 0;
}

static int p2_check_qsort(void)
{
    unsigned int i;
    for (i = 0U; i < P2_QSORT_N; i++) {
        p2_data[i] = (int)p2_rng();
    }
    qsort(p2_data, P2_QSORT_N, sizeof(int), p2_cmp_int);
    for (i = 1U; i < P2_QSORT_N; i++) {
        if (p2_data[i - 1U] > p2_data[i]) {
            return p2_fail("qsort-order");
        }
    }
    printf("qsort ok n=%u first=%d last=%d\n", P2_QSORT_N,
        p2_data[0], p2_data[P2_QSORT_N - 1U]);
    return 0;
}

static int p2_write_all(int fd, const unsigned char *buf, unsigned int len)
{
    unsigned int off = 0U;
    while (off < len) {
        ssize_t n = write(fd, buf + off, (size_t)(len - off));
        if (n <= 0) {
            return -1;
        }
        off += (unsigned int)n;
    }
    return 0;
}

static int p2_read_all(int fd, unsigned char *buf, unsigned int len)
{
    unsigned int off = 0U;
    while (off < len) {
        ssize_t n = read(fd, buf + off, (size_t)(len - off));
        if (n <= 0) {
            return -1;
        }
        off += (unsigned int)n;
    }
    return 0;
}

static int p2_check_file(void)
{
    struct stat st;
    struct stat fst;
    unsigned int i;
    int fd;

    for (i = 0U; i < P2_FILE_BYTES; i++) {
        p2_wbuf[i] = (unsigned char)(i & 0xFFU);
    }
    fd = openat(AT_FDCWD, P2_TMP_PATH, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return p2_fail("openat");
    }
    if (p2_write_all(fd, p2_wbuf, P2_FILE_BYTES) != 0) {
        close(fd);
        return p2_fail("write64k");
    }
    if (lseek(fd, 0, SEEK_SET) != 0) {
        close(fd);
        return p2_fail("lseek");
    }
    memset(p2_rbuf, 0, P2_FILE_BYTES);
    if (p2_read_all(fd, p2_rbuf, P2_FILE_BYTES) != 0) {
        close(fd);
        return p2_fail("read64k");
    }
    if (memcmp(p2_wbuf, p2_rbuf, P2_FILE_BYTES) != 0) {
        close(fd);
        return p2_fail("roundtrip-bytes");
    }
    if (fstat(fd, &fst) != 0 || fst.st_size != (int32_t)P2_FILE_BYTES) {
        close(fd);
        return p2_fail("fstat-size");
    }
    if (stat(P2_TMP_PATH, &st) != 0 || st.st_size != (int32_t)P2_FILE_BYTES) {
        close(fd);
        return p2_fail("stat-size");
    }
    if (close(fd) != 0) {
        return p2_fail("close");
    }
    if (unlink(P2_TMP_PATH) != 0) {
        return p2_fail("unlink");
    }
    printf("file ok bytes=%u\n", P2_FILE_BYTES);
    return 0;
}

int main(void)
{
    if (p2_check_printf() != 0) {
        return 1;
    }
    if (p2_check_alloc() != 0) {
        return 1;
    }
    if (p2_check_qsort() != 0) {
        return 1;
    }
    if (p2_check_file() != 0) {
        return 1;
    }
    printf("P2-LIBC-PASS\n");
    return 0;
}
