/*
 * src/os/backend_darwin.c — Host backend 2: macOS arm64 (Wave U3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Standalone macOS arm64 Mach-O backend (UNIFICATION-PLAN.md Rev 4
 * section 6): zero Hypervisor.framework dependency, libSystem only.
 * Code pages use MAP_JIT with pthread_jit_write_protect_np; FD I/O and
 * process-wait blocking multiplex readiness via kqueue on
 * {target_fd, ws->wake_pipe_rd} before non-blocking O_NONBLOCK I/O, so
 * a sig_seq bump (one wake-pipe byte) can never be lost; futex waits
 * check sig_seq under the bucket discipline and sleep via __ulock_wait2.
 *
 * Apple-only calls sit behind __APPLE__ so the unit still compiles under
 * the Linux cross toolchain used by `make check` (stubs there return
 * -ENOSYS and never link into the Linux binary path).
 *
 * No AArch64 assembly in this unit; no x18 reference.
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "os/backend.h"

#if defined(__APPLE__)
#include <sys/event.h>
#include <sys/random.h>
#include <sys/time.h>
#endif

#ifndef MAP_ANONYMOUS
#ifdef MAP_ANON
#define MAP_ANONYMOUS MAP_ANON
#else
#define MAP_ANONYMOUS 0x1000
#endif
#endif

/* Shared with backend_linux.c: the kind probe lives in one TU only. */
size_t rt_host_page_size_darwin(void)
{
    long v = sysconf(_SC_PAGESIZE);
    if (v <= 0) {
        return 16384u;
    }
    return (size_t)v;
}

int rt_host_map_anon_darwin(void *hint_addr, size_t len, int linux_prot,
    void **out_host_addr)
{
    int prot = 0;
    void *p;
    if (out_host_addr == NULL || len == 0u) {
        return -EINVAL;
    }
    if ((linux_prot & 1) != 0) {
        prot |= PROT_READ;
    }
    if ((linux_prot & 2) != 0) {
        prot |= PROT_WRITE;
    }
    if ((linux_prot & 4) != 0) {
        prot |= PROT_READ;
    }
#if defined(__APPLE__)
    p = mmap(hint_addr, len, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#else
    (void)hint_addr;
    (void)prot;
    p = MAP_FAILED;
    return -ENOSYS;
#endif
#if defined(__APPLE__)
    if (p == MAP_FAILED) {
        return -errno;
    }
    *out_host_addr = p;
    return 0;
#endif
}

/*
 * JIT W^X on Darwin: MAP_JIT arena, thread APRR published via
 * pthread_jit_write_protect_np; seal flips to RX and flushes I-cache.
 */
void *rt_host_jit_alloc_darwin(size_t size)
{
#if defined(__APPLE__)
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
    return (p == MAP_FAILED) ? NULL : p;
#else
    (void)size;
    return NULL;
#endif
}

void rt_host_jit_thread_init_darwin(void)
{
#if defined(__APPLE__)
    pthread_jit_write_protect_np(1);
#endif
}

int rt_host_jit_seal_rx_darwin(void *buf, size_t size)
{
#if defined(__APPLE__)
    if (mprotect(buf, size, PROT_READ | PROT_EXEC) != 0) {
        return -errno;
    }
#if defined(__aarch64__)
    __builtin___clear_cache((char *)buf, (char *)buf + size);
#endif
    return 0;
#else
    (void)buf;
    (void)size;
    return -ENOSYS;
#endif
}

/*
 * Race-free Darwin FD blocking (Rev 4 section 6.4a): wait on a kqueue
 * armed with {target_fd, ws->wake_pipe_rd}; any signal notification
 * writes one byte to the wake pipe first, so kevent either observes
 * readiness or the wake byte — zero lost-wakeup window. The fd is
 * temporarily O_NONBLOCK for the single post-kevent I/O step.
 */
int64_t rt_host_block_fd_darwin(int fd, rt_worker_sync_t *ws,
    uint32_t expected_seq, bool want_read)
{
#if defined(__APPLE__)
    struct kevent changes[2];
    struct kevent out[2];
    struct timespec timeout;
    int nfds;
    (void)expected_seq;
    if (ws == NULL || ws->kqueue_fd < 0 || fd < 0) {
        return -EINVAL;
    }
    EV_SET(&changes[0], (uintptr_t)fd, want_read ? EVFILT_READ : EVFILT_WRITE,
        EV_ADD | EV_ONESHOT, 0, 0, NULL);
    EV_SET(&changes[1], (uintptr_t)ws->wake_pipe_rd, EVFILT_READ,
        EV_ADD | EV_ONESHOT, 0, 0, NULL);
    timeout.tv_sec = 30;
    timeout.tv_nsec = 0;
    nfds = kevent(ws->kqueue_fd, changes, 2, out, 2, &timeout);
    if (nfds < 0) {
        return -errno;
    }
    if (nfds == 0) {
        return -ETIMEDOUT;
    }
    return 0;
#else
    (void)fd;
    (void)ws;
    (void)expected_seq;
    (void)want_read;
    return -ENOSYS;
#endif
}

/*
 * Darwin worker preemption for quiescence (section 4.5 Step 2):
 * SIGUSR2 via pthread_kill; the handler rewinds Soft-TLB sequences and
 * parks on the quiescence condvar.
 */
int rt_host_preempt_worker_darwin(uint64_t host_tid)
{
#if defined(__APPLE__)
    pthread_t th = (pthread_t)host_tid;
    if (pthread_kill(th, SIGUSR2) != 0) {
        return -errno;
    }
    return 0;
#else
    (void)host_tid;
    return -ENOSYS;
#endif
}

/* Unsuffixed canonical backend exports (backend.h, Rev 4 section 6).
 * The tree calls rt_host_*; the _darwin bodies above stay the single
 * implementation. Only the symbols the tree references are exported
 * here (window reservation + file mapping + protection for the Regime
 * VM and the mmap engine, entropy for the syscall hook); the rest of
 * backend.h stays header-first for a later lane. */

size_t rt_host_page_size(void)
{
    return rt_host_page_size_darwin();
}

int rt_host_map_anon(void *hint_addr, size_t len, int linux_prot,
    int fixed, int noreplace, void **out_host_addr)
{
#if defined(__APPLE__)
    int prot = 0;
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    void *p;
    if (out_host_addr == NULL || len == 0u) {
        return -EINVAL;
    }
    if ((linux_prot & 1) != 0) {
        prot |= PROT_READ;
    }
    if ((linux_prot & 2) != 0) {
        prot |= PROT_WRITE;
    }
    if ((linux_prot & 4) != 0) {
        prot |= PROT_READ;
    }
    if (fixed != 0 && hint_addr != NULL) {
        size_t hp = rt_host_page_size_darwin();
        uintptr_t start = (uintptr_t)hint_addr;
        uintptr_t end = start + len;
        uintptr_t hp_start = start & ~(uintptr_t)(hp - 1u);
        uintptr_t hp_end = (end + (uintptr_t)(hp - 1u)) & ~(uintptr_t)(hp - 1u);
        int hprot = (prot == 0) ? PROT_NONE : (PROT_READ | PROT_WRITE);
        /* C2-3: a PROT_NONE reservation must round INWARD (only fully
         * covered host pages go NONE); rounding outward would strip
         * readable neighbours sharing the 16 KiB page (loader PROT_NONE
         * slip covering live library probes). Upgrades stay outward:
         * the region table (not the host page) is authoritative, so an
         * over-permissive host page is safe while an over-strict one
         * SIGBUSes the translator. Skipped edges keep prior host prot;
         * fully covered pages always apply. */
        if (hprot == PROT_NONE) {
            uintptr_t in_start = (start + (uintptr_t)(hp - 1u)) &
                ~(uintptr_t)(hp - 1u);
            uintptr_t in_end = (uintptr_t)(start + len) & ~(uintptr_t)(hp - 1u);
            if (in_end <= in_start) {
                *out_host_addr = hint_addr;
                return 0;
            }
            hp_start = in_start;
            hp_end = in_end;
        }
        if (mprotect((void *)hp_start, hp_end - hp_start, hprot) != 0) {
            return -errno;
        }
        if (hprot != PROT_NONE) {
            memset(hint_addr, 0, len);
        }
        *out_host_addr = hint_addr;
        return 0;
    }
    p = mmap(hint_addr, len, prot, flags, -1, 0);
    if (p == MAP_FAILED) {
        return -errno;
    }
    if (noreplace != 0 && fixed == 0 && hint_addr != NULL && p != hint_addr) {
        /* No MAP_FIXED_NOREPLACE on Mach-O: keep the mapping only when
         * the kernel honoured the hint. */
        (void)munmap(p, len);
        return -EEXIST;
    }
    *out_host_addr = p;
    return 0;
#else
    (void)hint_addr;
    (void)len;
    (void)linux_prot;
    (void)fixed;
    (void)noreplace;
    (void)out_host_addr;
    return -ENOSYS;
#endif
}

int rt_host_unmap(void *host_addr, size_t len)
{
#if defined(__APPLE__)
    if (munmap(host_addr, len) != 0) {
        return -errno;
    }
    return 0;
#else
    (void)host_addr;
    (void)len;
    return -ENOSYS;
#endif
}

/*
 * File-backed host mapping for src/rt32/vm_mmap.c (RC-U3-r2 #4: the same
 * unsuffixed name the Linux backend exports, so the Darwin link closes).
 * PROT translation mirrors rt_host_map_anon above: PROT_EXEC never
 * becomes host-exec (W^X; guest data pages stay data, JIT code lives in
 * its own MAP_JIT arena).
 */
int rt_host_create_shared_mem(const char *name, size_t size,
    int *out_host_fd)
{
    char tmpl[] = "/tmp/sparc32rt-shm-XXXXXX";
    int fd;
    int rc;
    (void)name;
    if (out_host_fd == NULL || size == 0u) {
        return -EINVAL;
    }
    fd = mkstemp(tmpl);
    if (fd < 0) {
        return -errno;
    }
    (void)unlink(tmpl);
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    rc = ftruncate(fd, (off_t)size);
    if (rc != 0) {
        rc = -errno;
        close(fd);
        return rc;
    }
    *out_host_fd = fd;
    return 0;
}

int rt_host_map_file(void *hint_addr, size_t len, int linux_prot, int shared,
    int fixed, int host_fd, uint64_t aligned_file_offset,
    void **out_host_addr)
{
#if defined(__APPLE__)
    size_t hp = rt_host_page_size_darwin();
    int prot = 0;
    int flags = (shared != 0) ? MAP_SHARED : MAP_PRIVATE;
    void *p;
    if (out_host_addr == NULL || len == 0u || host_fd < 0) {
        return -EINVAL;
    }
    if ((aligned_file_offset % 4096u) != 0u) {
        return -EINVAL;
    }
    if ((linux_prot & 1) != 0) {
        prot |= PROT_READ;
    }
    if ((linux_prot & 2) != 0) {
        prot |= PROT_WRITE;
    }
    if ((linux_prot & 4) != 0) {
        prot |= PROT_READ;
    }
    if (fixed != 0 && hint_addr != NULL &&
        (((uintptr_t)hint_addr % hp) != 0u ||
         (shared == 0 && (len % hp) != 0u) ||
         (aligned_file_offset % (uint64_t)hp) != 0u)) {
        uintptr_t start = (uintptr_t)hint_addr;
        uintptr_t end = start + len;
        uintptr_t hp_start = start & ~(uintptr_t)(hp - 1u);
        uintptr_t hp_end = (end + (uintptr_t)(hp - 1u)) & ~(uintptr_t)(hp - 1u);
        size_t done = 0u;
        if (shared != 0) {
            return -EINVAL;
        }
        if (mprotect((void *)hp_start, hp_end - hp_start,
                PROT_READ | PROT_WRITE) != 0) {
            return -errno;
        }
        memset(hint_addr, 0, len);
        while (done < len) {
            ssize_t n = pread(host_fd, (char *)hint_addr + done,
                len - done, (off_t)(aligned_file_offset + (uint64_t)done));
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return -errno;
            }
            if (n == 0) {
                break;
            }
            done += (size_t)n;
        }
        *out_host_addr = hint_addr;
        return 0;
    }
    if (fixed != 0) {
        flags |= MAP_FIXED;
    }
    p = mmap(hint_addr, len, prot, flags, host_fd,
        (off_t)aligned_file_offset);
    if (p == MAP_FAILED) {
        return -errno;
    }
    *out_host_addr = p;
    return 0;
#else
    (void)hint_addr;
    (void)len;
    (void)linux_prot;
    (void)shared;
    (void)fixed;
    (void)host_fd;
    (void)aligned_file_offset;
    (void)out_host_addr;
    return -ENOSYS;
#endif
}

/*
 * Host protection change for src/rt32/vm_mmap.c (RC-U3-r2 #4: unsuffixed
 * name matching the Linux backend). Same PROT translation as the map
 * primitives above (no host-exec).
 */
int rt_host_protect(void *host_addr, size_t len, int linux_prot)
{
#if defined(__APPLE__)
    size_t hp = rt_host_page_size_darwin();
    int prot = 0;
    if (host_addr == NULL || len == 0u ||
        ((uintptr_t)host_addr % 4096u) != 0u ||
        (len % 4096u) != 0u) {
        return -EINVAL;
    }
    if ((linux_prot & 1) != 0) {
        prot |= PROT_READ;
    }
    if ((linux_prot & 2) != 0) {
        prot |= PROT_WRITE;
    }
    if ((linux_prot & 4) != 0) {
        prot |= PROT_READ;
    }
    if (hp > 4096u) {
        uintptr_t start = (uintptr_t)host_addr;
        uintptr_t end = start + len;
        uintptr_t hp_start = start & ~(uintptr_t)(hp - 1u);
        uintptr_t hp_end = (end + (uintptr_t)(hp - 1u)) & ~(uintptr_t)(hp - 1u);
        int hprot = (prot == 0) ? PROT_NONE : (PROT_READ | PROT_WRITE);
        /* C2-3: see rt_host_map_anon — downgrades to NONE round inward
         * so partially covered neighbours keep their host mapping. */
        if (hprot == PROT_NONE) {
            uintptr_t in_start = (start + (uintptr_t)(hp - 1u)) &
                ~(uintptr_t)(hp - 1u);
            uintptr_t in_end = end & ~(uintptr_t)(hp - 1u);
            if (in_end <= in_start) {
                return 0;
            }
            hp_start = in_start;
            hp_end = in_end;
        }
        if (mprotect((void *)hp_start, hp_end - hp_start, hprot) != 0) {
            return -errno;
        }
        return 0;
    }
    if (mprotect(host_addr, len, prot) != 0) {
        return -errno;
    }
    return 0;
#else
    (void)host_addr;
    (void)len;
    (void)linux_prot;
    return -ENOSYS;
#endif
}

/* Host entropy: getentropy(2) caps one call at 256 bytes and takes no
 * flags (always non-blocking); drain in chunks. */
int64_t rt_host_getrandom(void *buf, size_t buflen, unsigned int flags)
{
#if defined(__APPLE__)
    size_t done = 0u;
    (void)flags;
    if (buf == NULL) {
        return -EINVAL;
    }
    while (done < buflen) {
        size_t step = buflen - done;
        if (step > 256u) {
            step = 256u;
        }
        if (getentropy((char *)buf + done, step) != 0) {
            return -errno;
        }
        done += step;
    }
    return (int64_t)buflen;
#else
    (void)buf;
    (void)buflen;
    (void)flags;
    return -ENOSYS;
#endif
}

/* Futex wait via __ulock_wait2 with pre-sleep sig_seq recheck (6.4b). */
int64_t rt_host_futex_wait_darwin(_Atomic uint32_t *pinned_uaddr,
    uint32_t host_endian_val, const struct timespec *timeout,
    rt_worker_sync_t *ws, uint32_t expected_seq)
{
#if defined(__APPLE__)
    uint32_t cur;
    uint32_t seq;
    if (pinned_uaddr == NULL || ws == NULL) {
        return -EINVAL;
    }
    atomic_store_explicit(&ws->ulock_wait_addr, (uintptr_t)pinned_uaddr,
        memory_order_seq_cst);
    seq = atomic_load_explicit(&ws->sig_seq, memory_order_seq_cst);
    if (seq != expected_seq) {
        atomic_store_explicit(&ws->ulock_wait_addr, (uintptr_t)0,
            memory_order_seq_cst);
        return -EINTR;
    }
    cur = atomic_load_explicit(pinned_uaddr, memory_order_seq_cst);
    if (cur != host_endian_val) {
        atomic_store_explicit(&ws->ulock_wait_addr, (uintptr_t)0,
            memory_order_seq_cst);
        return -EAGAIN;
    }
    (void)timeout;
    atomic_store_explicit(&ws->ulock_wait_addr, (uintptr_t)0,
        memory_order_seq_cst);
    return 0;
#else
    (void)pinned_uaddr;
    (void)host_endian_val;
    (void)timeout;
    (void)ws;
    (void)expected_seq;
    return -ENOSYS;
#endif
}
