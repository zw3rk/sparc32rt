/*
 * src/rt32/procfs.h — /proc/self interception served from translator state
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L5a (Phase 5): absolute /proc/self/{exe,maps,cmdline,stat,auxv}
 * paths are served from translator state (guest mappings, argv, auxv
 * snapshot) — never the host's. Everything else (including other
 * /proc/self/<name> such as oom_score_adj) falls through to the host.
 * All entry points return host-style results (>= 0 value, negative
 * host errno); the openat path argument is a NUL-terminated host copy.
 */

#ifndef SPARC32RT_RT32_PROCFS_H
#define SPARC32RT_RT32_PROCFS_H

#include "sparc32rt.h"

long rt32_procfs_openat(sparc32_ctx_t *ctx, int dirfd, const char *path,
                        int host_flags, unsigned host_mode);
long rt32_procfs_readlink(sparc32_ctx_t *ctx, uint32_t path_va,
                          uint32_t buf_va, uint32_t len);
long rt32_procfs_readlinkat(sparc32_ctx_t *ctx, uint32_t dirfd,
                            uint32_t path_va, uint32_t buf_va, uint32_t len);

#endif /* SPARC32RT_RT32_PROCFS_H */
