# Self-documenting Makefile for sparc32rt — SPARC V8 -> AArch64 user-mode translator
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := help
.PHONY: help all build check check-line-limits check-abi-invariants clean

BUILD_DIR := _build

# Cross toolchain for aarch64-linux static-PIE output. An explicit CC from
# the environment or command line always wins; otherwise prefer the
# aarch64-unknown-linux-musl cross gcc when present (nix shell
# nixpkgs#pkgsCross.aarch64-multiplatform-musl.stdenv.cc), else host cc
# (Phase 0 sources are host-portable for syntax verification).
ifeq ($(origin CC),default)
  ifneq ($(shell command -v aarch64-unknown-linux-musl-gcc 2>/dev/null),)
    CC := aarch64-unknown-linux-musl-gcc
  else
    CC := cc
  endif
endif
HOST_CC ?= cc
# src/main.c calls setenv(3), which musl hides under strict -std=c11 unless a
# POSIX feature-test macro is visible; expose exactly that on Linux (keeps
# -pedantic and every prescribed warning intact). On macOS the macro would
# hide MAP_ANONYMOUS, so it stays Linux-only.
CFLAGS  ?= -std=c11 -Wall -Wextra -Werror=vla -pedantic -Os -fPIE -Iinclude -Isrc -Isrc/rt32
ifeq ($(shell uname -s),Linux)
  CFLAGS += -D_POSIX_C_SOURCE=200809L
endif
LDFLAGS ?= -static-pie

# CLI entry, vendored rt32 substrate, reference interpreter, syscall
# layer (src/os/), and AArch64 DBT (src/dbt/, Phase 2: no NO_DBT flag;
# vm_invalidate_jit calls sparc32_dbt_invalidate_range).
SRCS_C := src/main.c $(wildcard src/rt32/*.c) $(wildcard src/interp/*.c) \
          $(wildcard src/os/*.c) $(wildcard src/dbt/*.c) \
          $(wildcard src/vm/*.c) $(wildcard src/dbt/aot/*.c)
SRCS_S := $(wildcard src/rt32/*.S) $(wildcard src/dbt/*.S)
HDRS   := src/sparc32rt.h include/a32host.h src/os/syscall_nr.h \
          $(wildcard src/rt32/*.h) $(wildcard src/interp/*.h) \
          $(wildcard src/dbt/*.h) $(wildcard src/os/*.h) \
          $(wildcard src/vm/*.h) $(wildcard src/dbt/aot/*.h)

OBJ_DIR      := $(BUILD_DIR)/obj
OBJS         := $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(SRCS_C)) \
                $(patsubst src/%.S,$(OBJ_DIR)/%.o,$(SRCS_S))
SPARC32RT_BIN := $(BUILD_DIR)/sparc32rt

help: ## Show available build and verification targets
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} \
		/^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

all: build ## Build everything (currently just the sparc32rt binary)

build: $(SPARC32RT_BIN) ## Build static-PIE sparc32rt binary (cross: aarch64-unknown-linux-musl-gcc)

$(SPARC32RT_BIN): $(OBJS)
	@printf "\033[32m▸ Linking\033[0m $@ (CC=$(CC))\n"
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@

$(OBJ_DIR)/%.o: src/%.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: src/%.S $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

check: build check-line-limits check-abi-invariants ## Phase 0 gate: build + line limits + ABI invariants

check-line-limits: ## Every .c/.h/.S source file must stay <= 900 lines
	@fail=0; \
	for f in $$(find src include -name '*.c' -o -name '*.h' -o -name '*.S'); do \
	  n=$$(wc -l < "$$f"); \
	  if [ "$$n" -gt 900 ]; then echo "LIMIT FAIL: $$f has $$n lines (> 900)"; fail=1; fi; \
	done; \
	if [ "$$fail" -ne 0 ]; then exit 1; fi; \
	echo "line limits OK (all src/include .c/.h/.S <= 900 lines)"

check-abi-invariants: ## Build+run tests/check_abi_invariants.c with the host cc (L0b; skip if absent)
	@if [ -f tests/check_abi_invariants.c ]; then \
	  $(HOST_CC) -std=c11 -D_POSIX_C_SOURCE=200809L -Werror=vla -pedantic -Wall -Wextra -Werror \
	    -Iinclude -Isrc tests/check_abi_invariants.c -o $(BUILD_DIR)/check_abi_invariants && \
	  ./$(BUILD_DIR)/check_abi_invariants; \
	else \
	  echo "check-abi-invariants: tests/check_abi_invariants.c absent (L0b lane), SKIP"; \
	fi

clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR)
