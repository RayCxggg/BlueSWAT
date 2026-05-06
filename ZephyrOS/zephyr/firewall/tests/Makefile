# Host-side build for the BlueSWAT eBPF policy test harness.
#
# Compiles the firmware's own uBPF interpreter natively and links it against
# host_runner.c, which loads each policy bytecode and runs benign+malicious
# inputs through the VM. No Zephyr toolchain or hardware required.

CC      ?= gcc
CFLAGS  ?= -O0 -g -Wall -Wno-unused -Wno-pointer-to-int-cast \
           -Wno-int-to-pointer-cast -Wno-discarded-qualifiers \
           -Wno-incompatible-pointer-types
DEFS    := -DLINUX_TEST -D__BYTE_ORDER=__LITTLE_ENDIAN

EBPF_DIR := ../libebpf/ebpf-src
INCS     := -I$(EBPF_DIR) -I.

SRCS := host_runner.c \
        $(EBPF_DIR)/ebpf_vm.c \
        $(EBPF_DIR)/ebpf_allocator.c

BIN := host_runner

all: $(BIN)

$(BIN): $(SRCS)
	$(CC) $(CFLAGS) $(DEFS) $(INCS) $(SRCS) -o $(BIN)

run: $(BIN)
	./$(BIN)

clean:
	rm -f $(BIN)

.PHONY: all run clean
