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
#include "ebpf_bytecode/spi_evt_len.h"
#include "ebpf_bytecode/spi_acl_len.h"
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
	ADD_POLICY(conn_chan_map, CONN, CHANNEL_MAP);
	ADD_POLICY(conn_chan_hop, CONN, CHANNEL_HOP);
	ADD_POLICY(dc_nesn, DC, NESN);
	ADD_POLICY(spi_acl_len, SPI, HCI_ACL_LEN);
	ADD_POLICY(spi_evt_len, SPI, HCI_EVT_LEN);
	ADD_POLICY(scan_rsp_len, CONN, SCAN_RSP_LEN);
	ADD_POLICY(llcp_len_req, DC, LLCP_LEN_REQ);
	ADD_POLICY(llcp_conn_param_req, DC, LLCP_CONN_PARAM_REQ);
	ADD_POLICY(lll_interval, CONN, LLL_INTERVAL);
	ADD_POLICY(smp_ident_check, DC, SMP_KEYS);
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
	if (policy_arr[ebpf_idx].size == 0) {
		return NULL;
	}

	ebpf_vm *vm = get_default_vm(use_jit);

	int ebpf_sz = policy_arr[ebpf_idx].size;
	uint8_t *ebpf_inst = policy_arr[ebpf_idx].code;

	ebpf_vm_set_inst(vm, ebpf_inst, ebpf_sz);

	if (use_jit) {
		gen_jit_code(vm);
	}

	return vm;
}

static ebpf_vm *get_vm_from_cache(int ebpf_idx)
{
	if (policy_arr[ebpf_idx].size == 0) {
		return NULL;
	}

	bool use_jit = policy_arr[ebpf_idx].jit;
	return load_ebpf_code(ebpf_idx, use_jit);
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