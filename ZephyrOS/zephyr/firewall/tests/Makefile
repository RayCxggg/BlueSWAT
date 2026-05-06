# Host-side build for the BlueSWAT eBPF policy test harness.
#
# Compiles the firmware's own uBPF interpreter natively and links it against
# host_runner.c, which loads each policy bytecode and runs benign+malicious
# inputs through the VM. No Zephyr toolchain or hardware required.

CC      ?= gcc
CFLAGS  ?= -O0 -g -Wall -Wno-unused -Wno-pointer-to-int-cast \
           -Wno-int-to-pointer-cast -Wno-discarded-qualifiers \
           -Wno-incompatible-pointer-types -Wno-address-of-packed-member \
           -Wno-implicit-function-declaration
DEFS    := -DLINUX_TEST -D__BYTE_ORDER=__LITTLE_ENDIAN

EBPF_DIR     := ../libebpf/ebpf-src
FIREWALL_DIR := ..
INCS_HOST    := -I$(EBPF_DIR) -I.
INCS_INT     := -I$(EBPF_DIR) -I. -I$(FIREWALL_DIR) -I$(FIREWALL_DIR)/include \
                -I$(FIREWALL_DIR)/policy -I$(FIREWALL_DIR)/policy/include

# host_runner: bytecode-only harness (no Zephyr structs)
HOST_SRCS := host_runner.c \
             $(EBPF_DIR)/ebpf_vm.c \
             $(EBPF_DIR)/ebpf_allocator.c

# integration_runner: drives the actual firewall hook code with synthetic
# packets, using zephyr_mocks.h pre-included to short-circuit Zephyr deps.
INT_FIREWALL_SRCS := $(FIREWALL_DIR)/core/fsm_core.c \
                     $(FIREWALL_DIR)/core/fsm_handle.c \
                     $(FIREWALL_DIR)/core/fsm_ll_pkt_parser.c \
                     $(FIREWALL_DIR)/policy/src/fsm_policy_cache.c \
                     $(EBPF_DIR)/ebpf_vm.c \
                     $(EBPF_DIR)/ebpf_allocator.c

INT_SRCS := integration_runner.c $(INT_FIREWALL_SRCS)
INT_DEFS := $(DEFS) -include zephyr_mocks.h

all: host_runner integration_runner

host_runner: $(HOST_SRCS)
	$(CC) $(CFLAGS) $(DEFS) $(INCS_HOST) $(HOST_SRCS) -o host_runner

integration_runner: $(INT_SRCS) zephyr_mocks.h
	$(CC) $(CFLAGS) $(INT_DEFS) $(INCS_INT) $(INT_SRCS) -o integration_runner

run: all
	@echo "=== host_runner (bytecode-only) ==="; ./host_runner; \
	echo; echo "=== integration_runner (Zephyr-stack mock) ==="; ./integration_runner

clean:
	rm -f host_runner integration_runner

.PHONY: all run clean
