# Makefile for building the eBPF program

# --- Configuration ---
BPF_SRC = nomad_watcher.bpf.c
BPF_OBJ = $(BPF_SRC:.bpf.c=.bpf.o)
TARGET_ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Tools - Ensure clang, llc, and bpftool are in your PATH
CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool

# Include directories for clang
# The path *containing* the 'bpf' subdirectory (from libbpf-dev installation)
# Usually /usr/include, based on find results.
LIBBPF_BASE_INCLUDE_PATH ?= /usr/include # <--- CORRECTED PATH

# Includes clang built-in headers
CLANG_RESOURCE_DIR := $(shell $(CLANG) -print-resource-dir 2>/dev/null)
ifeq ($(CLANG_RESOURCE_DIR),)
    $(error Cannot determine clang resource directory. Please ensure clang is installed and accessible.)
endif
CLANG_BUILTIN_INCLUDE_PATH := $(CLANG_RESOURCE_DIR)/include

# Include paths: Current dir, libbpf base path, clang built-in headers path
# Now -I/usr/include will allow finding <bpf/bpf_helpers.h>
C_INCLUDE_PATHS = -I. \
                  -I$(LIBBPF_BASE_INCLUDE_PATH) \
                  -I$(CLANG_BUILTIN_INCLUDE_PATH)

# Clang flags for BPF compilation
# -nostdinc: Don't search the *default* standard system directories.
#            We explicitly add back the necessary base path for libbpf headers (/usr/include).
#            This prevents conflicts with vmlinux.h types from broader system headers,
#            while allowing libbpf includes like <bpf/bpf_helpers.h> to be found.
CLANG_FLAGS = -g -O2 -target bpf \
              -D__TARGET_ARCH_$(TARGET_ARCH) \
              -nostdinc \
              $(C_INCLUDE_PATHS)

# --- Files ---
VMLINUX_H = vmlinux.h

# --- Rules ---

.PHONY: all clean help vmlinux.h

all: $(BPF_OBJ)

# Rule to generate vmlinux.h (remains the same)
$(VMLINUX_H):
	@echo "Attempting to generate $(VMLINUX_H) using bpftool..."
	@# Try system BTF first
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H); \
		echo "Generated $(VMLINUX_H) from /sys/kernel/btf/vmlinux"; \
	elif [ -f /boot/vmlinuz-$(shell uname -r) ]; then \
		echo "WARNING: /sys/kernel/btf/vmlinux not found."; \
		echo "Attempting to generate from /boot/vmlinuz-$(shell uname -r) (may require root or specific permissions)"; \
		set -o pipefail; $(BPFTOOL) btf dump file /boot/vmlinuz-$(shell uname -r) format c > $(VMLINUX_H); \
		echo "Generated $(VMLINUX_H) from /boot/vmlinuz-$(shell uname -r)"; \
	else \
		echo "ERROR: Could not find kernel BTF information."; \
		echo "Please ensure your kernel is compiled with CONFIG_DEBUG_INFO_BTF=y"; \
		echo "or install kernel debug symbols for your distribution."; \
		echo "Cannot generate $(VMLINUX_H). You might need to install libbpf-dev and linux-headers-generic"; \
		echo "and potentially skip CO-RE by removing the $(VMLINUX_H) dependency and include."; \
		rm -f $(VMLINUX_H); \
		exit 1; \
	fi

# Rule to compile the BPF C code to an object file (remains the same)
$(BPF_OBJ): $(BPF_SRC) $(VMLINUX_H) Makefile
	@echo "Compiling $(BPF_SRC) -> $(BPF_OBJ)"
	$(CLANG) $(CLANG_FLAGS) -c $(BPF_SRC) -o $@

clean:
	@echo "Cleaning up..."
	rm -f $(BPF_OBJ)
	rm -f $(VMLINUX_H)
	@echo "Done."

# Help target (updated variable name in comment)
help:
	@echo "Available targets:"
	@echo "  all       - Build the BPF object file ($(BPF_OBJ))"
	@echo "  vmlinux.h - Generate kernel type definitions (requires bpftool and BTF)"
	@echo "  clean     - Remove generated files"
	@echo ""
	@echo "Variables:"
	@echo "  CLANG=[path]      (default: clang)"
	@echo "  LLC=[path]        (default: llc)"
	@echo "  BPFTOOL=[path]    (default: bpftool)"
	@echo "  LIBBPF_BASE_INCLUDE_PATH=[path] (default: /usr/include)" # Updated help text