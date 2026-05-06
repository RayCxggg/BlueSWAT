// load FSM policy eBPF code from cache
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "ebpf.h"
#include "ebpf_allocator.h"

#include "include/fsm_policy_cache.h"
#include "fsm_core.h"
// #include "include/ebpf_helper.h"
#include "utils.h"

// import policy eBPF bytecode
#include "ebpf_bytecode/conn_chan_map.h"
#include "ebpf_bytecode/conn_chan_hop.h"
#include "ebpf_bytecode/dc_nesn.h"
#include "ebpf_bytecode/scan_rsp_len.h"
#include "ebpf_bytecode/llcp_len_req.h"
#include "ebpf_bytecode/llcp_conn_param_req.h"
#include "ebpf_bytecode/lll_interval.h"
#include "ebpf_bytecode/smp_ident_check.h"

uint32_t core_policy_mask = 0;
uint32_t shared_policy_mask = 0;
uint32_t conn_policy_mask = 0;
uint32_t dc_policy_mask = 0;
uint32_t spi_policy_mask = 0;
uint32_t hci_policy_mask = 0;

bool policy_mgr_init = false;

struct fsm_policy_manager policy_manager = { 0 };

struct policy_cache policy_arr[PID_NUM] = { 0 };

/* Runtime-installed policy slots.  Pids in [PID_NUM, PID_NUM +
 * IFW_MAX_RUNTIME_POLICIES) index into this array.  See get_policy_slot()
 * for the dispatch. */
static struct policy_cache runtime_policy_arr[IFW_MAX_RUNTIME_POLICIES] = { 0 };
static int runtime_policy_count;

static struct policy_cache *get_policy_slot(int pid)
{
	if (pid < 0) {
		return NULL;
	}
	if (pid < PID_NUM) {
		return &policy_arr[pid];
	}
	int rt_idx = pid - PID_NUM;
	if (rt_idx >= IFW_MAX_RUNTIME_POLICIES) {
		return NULL;
	}
	return &runtime_policy_arr[rt_idx];
}

// pid: policy id
#define ADD_POLICY(policy_index, class, type)                                  \
	do {                                                                   \
		int pid = PID_##policy_index;                                  \
		policy_arr[pid].size = sizeof(policy_index);                   \
		policy_arr[pid].code = (uint8_t *)policy_index;                \
		policy_arr[pid].jit = false;                                   \
		register_policy(class, type, pid);                             \
	} while (0)

void load_all_policies()
{
	ADD_POLICY(conn_chan_map,        CONN, CHANNEL_MAP);
	ADD_POLICY(conn_chan_hop,        CONN, CHANNEL_HOP);
	ADD_POLICY(lll_interval,         CONN, LLL_INTERVAL);
	ADD_POLICY(dc_nesn,              DC,   NESN);
	ADD_POLICY(llcp_len_req,         DC,   LLCP_LEN_REQ);
	ADD_POLICY(llcp_conn_param_req,  DC,   LLCP_CONN_PARAM_REQ);
	ADD_POLICY(scan_rsp_len,         CONN, SCAN_RSP_LEN);
	ADD_POLICY(smp_ident_check,      DC,   SMP_KEYS);
}

void set_policy_jit_on(int pid)
{
	if (pid >= 0 && pid < PID_NUM) {
		policy_arr[pid].jit = true;
	} else {
		DEBUG_LOG("Wrong PID for enabling JIT.");
	}
}

void set_all_policy_jit_on()
{
	for (int pid = 0; pid < PID_NUM; pid++) {
		policy_arr[pid].jit = true;
	}

	DEBUG_LOG("Set JIT on for all policies.");
}

// init policy manager
static void init_policy_manager()
{
	memset(&policy_manager, 0, sizeof(policy_manager));
	policy_mgr_init = true;
}

// class: state class, e.g.. core / shared state
// type: state type, e.g.. BLE_ROLE
// pid: policy id, e.g.. PID_CVE_2020_10069
void register_policy(int class, int type, int pid)
{
	if (!policy_mgr_init) {
		init_policy_manager();
	}

	switch (class) {
	case CORE:
		core_policy_mask |= (1 << type);
		break;
	case SHARED:
		shared_policy_mask |= (1 << type);
		break;
	case CONN:
		conn_policy_mask |= (1 << type);
		break;
	case DC:
		dc_policy_mask |= (1 << type);
		break;
	case SPI:
		spi_policy_mask |= (1 << type);
		break;
	case HCI:
		hci_policy_mask |= (1 << type);
		break;
	}

	if (policy_manager.policy[class][type] == NULL) {
		// add a new policy to manager
		// IFW_DEBUG_LOG("Add a new policy to manager");

		// printf("Register new policy PID: %d\n", pid);

		struct fsm_policy_list *new_policy =
			ebpf_malloc(sizeof(struct fsm_policy_list));

		new_policy->index = pid;
		new_policy->policy_next = NULL;

		policy_manager.policy[class][type] = new_policy;

	} else {
		// add new policy into list
		// IFW_DEBUG_LOG("Add new policy into list.");

		// printf("Register old policy PID: %d\n", pid);

		struct fsm_policy_list *policy =
			policy_manager.policy[class][type];

		while (policy->policy_next != NULL) {
			policy = policy->policy_next;
		}

		policy->policy_next =
			ebpf_malloc(sizeof(struct fsm_policy_list));
		policy->policy_next->index = pid;
		policy->policy_next->policy_next = NULL;
	}
}

ebpf_vm *g_vm = NULL, *g_jit_vm = NULL;

static ebpf_vm *get_default_vm(bool use_jit)
{
	ebpf_vm *vm;

	if (use_jit) {
		if (g_jit_vm == NULL) {
			g_jit_vm = ebpf_create();

			// ebpf_register(g_jit_vm, 1, "print_log",
			// 	      ebpf_helper_print);
			// ebpf_register(g_jit_vm, 3, "dump_num",
			// 	      ebpf_helper_dump_num);
			// ebpf_register(g_jit_vm, 4, "fsm_add_state",
			// 	      ebpf_helper_add_state);

			g_jit_vm->use_jit = true;
		}
		vm = g_jit_vm;
	} else {
		if (g_vm == NULL) {
			g_vm = ebpf_create();

			// ebpf_register(g_vm, 1, "print_log", ebpf_helper_print);
			// ebpf_register(g_vm, 3, "dump_num",
			// 	      ebpf_helper_dump_num);
			// ebpf_register(g_vm, 4, "fsm_add_state",
			// 	      ebpf_helper_add_state);
		}
		vm = g_vm;
	}

	return vm;
}

static struct ebpf_vm *load_ebpf_code(int ebpf_idx, bool use_jit)
{
	struct policy_cache *slot = get_policy_slot(ebpf_idx);
	if (slot == NULL || slot->size == 0) {
		return NULL;
	}

	ebpf_vm *vm = get_default_vm(use_jit);

	ebpf_vm_set_inst(vm, slot->code, slot->size);

	if (use_jit) {
		gen_jit_code(vm);
	}

	return vm;
}

static ebpf_vm *get_vm_from_cache(int ebpf_idx)
{
	struct policy_cache *slot = get_policy_slot(ebpf_idx);
	if (slot == NULL || slot->size == 0) {
		return NULL;
	}

	return load_ebpf_code(ebpf_idx, slot->jit);
}

static uint64_t run_fsm_ebpf_policy(int ebpf_policy_idx, void *newState,
				    int dsize)
{
	ebpf_vm *vm = get_vm_from_cache(ebpf_policy_idx);
	if (vm == NULL) {
		return 0;
	}

	// JIT interpretion
	if (vm->use_jit) {
		return vm->jit_func(newState, dsize);
	}

	// VM interpretion
	return ebpf_vm_exec(vm, newState, dsize);
}

/* Install a new eBPF policy at runtime.  See fsm_policy_cache.h for the
 * contract.  The bytecode is copied via ebpf_malloc (k_malloc on Zephyr)
 * and the runtime slot is registered for (class, type) so that the next
 * IFW_RUN_VERIFIER for that slot picks it up.
 *
 * This is the C-level capability the paper relies on for OTA patching
 * ("vendors can transmit eBPF programs to victims via BLE and directly
 *  integrate them into BlueSWAT"); a higher-level transport — e.g. a
 * vendor-specific GATT characteristic — calls this once a complete
 * bytecode payload has been received from the peer. */
/* Maximum instruction count for runtime-installed policies.  The largest
 * compile-time policy in the tree is ~9 instructions (smp_ident_check);
 * 64 leaves headroom for richer custom policies without giving an
 * attacker millions of instructions to burn. */
#define IFW_RUNTIME_MAX_INSTS 64

/* Lightweight structural verifier for runtime-installed eBPF policies.
 * Returns 0 on success, a negative diagnostic code on rejection.
 *
 * The Linux kernel verifier does full type tracking (~3 KLOC); this is
 * not that.  It catches the realistic abuse vectors when accepting an
 * untrusted bytecode payload over the GATT patch service:
 *
 *   - infinite loops      → reject any negative jump offset
 *   - out-of-range PC     → check every jump target is < num_insts
 *   - foreign helper call → reject EBPF_OP_CALL outright
 *   - write-anywhere      → reject every ST/STX (policies should be
 *                            read-only over the FsmState input)
 *   - OOB FSM read        → bounds-check LDX[BHWDW] against mem_size
 *   - no return path      → require at least one EXIT
 *   - corrupt opcode/regs → range-check dst/src
 *   - LDDW immediate half → skip its second slot so opcode 0 in that
 *                            slot doesn't trigger "unknown opcode"
 *
 * Anything the interpreter handles defensively at runtime (div-by-zero,
 * unknown opcode → break out) is left to it. */
static int ifw_verify_policy(const uint8_t *code, uint32_t len, size_t mem_size)
{
	if (code == NULL || len == 0 || (len % 8) != 0) {
		return -10;
	}

	uint32_t num_insts = len / 8u;
	if (num_insts > IFW_RUNTIME_MAX_INSTS) {
		return -11;
	}

	bool seen_exit = false;
	const struct ebpf_inst *insts = (const struct ebpf_inst *)code;

	for (uint32_t pc = 0; pc < num_insts; pc++) {
		const struct ebpf_inst *inst = &insts[pc];
		uint8_t op = inst->opcode;

		if (inst->dst >= MAX_BPF_REG || inst->src >= MAX_BPF_REG) {
			return -12;
		}

		if (op == EBPF_OP_CALL) {
			return -13;
		}

		if (op == EBPF_OP_EXIT) {
			seen_exit = true;
			continue;
		}

		/* Stores forbidden — runtime policies are pure readers. */
		switch (op) {
		case EBPF_OP_STDW: case EBPF_OP_STW:
		case EBPF_OP_STH:  case EBPF_OP_STB:
		case EBPF_OP_STXDW: case EBPF_OP_STXW:
		case EBPF_OP_STXH:  case EBPF_OP_STXB:
			return -14;
		}

		/* Memory loads: only from r1 (input mem ptr) or r10 (stack). */
		size_t load_sz = 0;
		switch (op) {
		case EBPF_OP_LDXDW: load_sz = 8; break;
		case EBPF_OP_LDXW:  load_sz = 4; break;
		case EBPF_OP_LDXH:  load_sz = 2; break;
		case EBPF_OP_LDXB:  load_sz = 1; break;
		}
		if (load_sz != 0) {
			int16_t off = inst->offset;
			if (inst->src == 1) {
				if (off < 0 ||
				    (size_t)off + load_sz > mem_size) {
					return -15;
				}
			} else if (inst->src == 10) {
				/* r10 is stack frame top; valid offsets are
				 * in [-STACK_SIZE, 0). */
				if (off >= 0 ||
				    (int)load_sz + off > 0 ||
				    (size_t)(-off) > STACK_SIZE) {
					return -16;
				}
			} else {
				return -17;
			}
		}

		/* LDDW occupies two slots; the second slot's `imm` carries the
		 * upper 32 bits of the immediate.  Skip it so we don't try to
		 * decode opcode==0 as a real instruction. */
		if (op == EBPF_OP_LDDW) {
			if (pc + 1 >= num_insts) {
				return -18;
			}
			pc++;
			continue;
		}

		/* Forward-only jumps. */
		if ((op & EBPF_CLS_MASK) == EBPF_CLS_JMP) {
			int16_t off = inst->offset;
			if (off < 0) {
				return -19;
			}
			uint32_t target = pc + 1u + (uint32_t)off;
			if (target >= num_insts) {
				return -20;
			}
		}
	}

	return seen_exit ? 0 : -21;
}

int ifw_install_policy(int class, int type,
		       const uint8_t *code, uint32_t len)
{
	if (code == NULL || len == 0 || (len % 8) != 0) {
		return -1; /* eBPF instructions are 8 bytes each */
	}
	if (class < 0 || class >= IFW_STATE_CLASS_NUM ||
	    type  < 0 || type  >= IFW_DC_PARAM_NUM) {
		return -2;
	}
	if (runtime_policy_count >= IFW_MAX_RUNTIME_POLICIES) {
		return -3;
	}

	int verr = ifw_verify_policy(code, len, sizeof(struct FsmState));
	if (verr != 0) {
		return verr;
	}

	uint8_t *copy = (uint8_t *)ebpf_malloc(len);
	if (copy == NULL) {
		return -4;
	}
	memcpy(copy, code, len);

	int rt_idx = runtime_policy_count;
	int pid    = PID_NUM + rt_idx;

	runtime_policy_arr[rt_idx].size = (int)len;
	runtime_policy_arr[rt_idx].code = copy;
	runtime_policy_arr[rt_idx].jit  = false;
	runtime_policy_count++;

	register_policy(class, type, pid);
	return 0;
}

// FSM policy cache entrance
int run_fsm_check_policy(int type, int class, void *newState)
{
	// int tick = 0;
	// check whether policy exists
	// switch (class) {
	// case CORE:
	// 	if (!(core_policy_mask & (1 << type))) {
	// 		return IFW_OPERATION_PASS;
	// 	}
	// 	break;
	// case SHARED:
	// 	if (!(shared_policy_mask & (1 << type))) {
	// 		return IFW_OPERATION_PASS;
	// 	}
	// 	break;
	// case CONN:
	// 	if (!(conn_policy_mask & (1 << type))) {
	// 		return IFW_OPERATION_PASS;
	// 	}
	// 	break;
	// case DC:
	// 	if (!(dc_policy_mask & (1 << type))) {
	// 		return IFW_OPERATION_PASS;
	// 	}
	// 	break;
	// case SPI:
	// 	if (!(spi_policy_mask & (1 << type))) {
	// 		return IFW_OPERATION_PASS;
	// 	}
	// 	break;
	// case HCI:
	// 	if (!(hci_policy_mask & (1 << type))) {
	// 		return IFW_OPERATION_PASS;
	// 	}
	// 	break;
	// }

	struct fsm_policy_list *policy = policy_manager.policy[class][type];

	while (policy != NULL) {
		// tick++;
		// printf("tick: %d\n", tick);

		// printf("policy index: %d\n", policy->index);

		uint64_t result = 0;

		result = run_fsm_ebpf_policy(policy->index, newState, 64);

		if (result == IFW_OPERATION_REJECT) {
			return IFW_OPERATION_REJECT;
		}

		policy = policy->policy_next;
	}

	// IFW_DEBUG_LOG("Policy_cache function right!");

	return IFW_OPERATION_PASS;
}