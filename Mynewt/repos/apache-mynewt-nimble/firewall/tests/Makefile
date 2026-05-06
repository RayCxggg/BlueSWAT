# Host-side test harness for the Mynewt/NimBLE BlueSWAT firewall.
#
# Compiles the firmware's own uBPF interpreter natively and links it
# against host_runner.c, which exercises the runtime install API + the
# structural verifier. No `newt` toolchain or apache-mynewt-core
# checkout required — same approach as the Zephyr-side tests/.

CC      ?= gcc
CFLAGS  ?= -O0 -g -Wall -Wno-unused -Wno-pointer-to-int-cast \
           -Wno-int-to-pointer-cast -Wno-discarded-qualifiers \
           -Wno-incompatible-pointer-types -Wno-address-of-packed-member \
           -Wno-implicit-function-declaration
DEFS    := -DLINUX_TEST -D__BYTE_ORDER=__LITTLE_ENDIAN -include mynewt_mocks.h

EBPF_DIR     := ../libebpf
EBPF_INC     := $(EBPF_DIR)/include
EBPF_SRC     := $(EBPF_DIR)/src
FIREWALL_DIR := ..

INCS := -I$(EBPF_INC) -I. -I$(FIREWALL_DIR)/include \
        -I$(FIREWALL_DIR)/policy -I$(FIREWALL_DIR)/policy/include \
        -I$(FIREWALL_DIR)/policy/specification/include

SRCS := host_runner.c \
        $(FIREWALL_DIR)/policy/src/fsm_policy_cache.c \
        $(EBPF_SRC)/ebpf_vm.c \
        $(EBPF_SRC)/ebpf_allocator.c

all: host_runner

host_runner: $(SRCS) mynewt_mocks.h
	$(CC) $(CFLAGS) $(DEFS) $(INCS) $(SRCS) -o host_runner

run: all
	@echo "=== mynewt host_runner (verifier + ifw_install_policy) ==="
	@./host_runner

clean:
	rm -f host_runner

.PHONY: all run clean
