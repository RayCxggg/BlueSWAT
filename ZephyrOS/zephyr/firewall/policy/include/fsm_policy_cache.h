#ifndef FSM_POLICY_H
#define FSM_POLICY_H

#include <stdint.h>
#include <stdbool.h>
#include "fsm_core.h"

// #define POLICY_ID(name) PID_##name

enum fsm_policy_tag {
	PID_conn_chan_map,
	PID_conn_chan_hop,
	PID_dc_nesn,
	PID_spi_acl_len,
	PID_spi_evt_len,
	PID_scan_rsp_len,
	PID_llcp_len_req,
	PID_llcp_conn_param_req,
	PID_lll_interval,
	PID_smp_ident_check,

	// FSM policy num
	PID_NUM,
};

// list to store FSM policy
struct fsm_policy_list {
	struct fsm_policy_list *policy_next;
	int index; // ebpf policy index, eg. PID_conn_chan_map
};

// FSM policy cache
// NOTE: second index of policy should be
// max{IFW_CORE_STATE_NUM, IFW_SHARED_STATE_NUM, IFW_CONN_PARAM_NUM, IFW_DC_PARAM_NUM}
struct fsm_policy_manager {
	struct fsm_policy_list *policy[IFW_STATE_CLASS_NUM][IFW_DC_PARAM_NUM];
};

// policy attributes
struct policy_cache {
	int size;
	uint8_t *code;

	// whether to use JIT interpretation for eBPF code
	bool jit;
};

void load_all_policies();
void set_policy_jit_on(int pid);
void set_all_policy_jit_on();

int run_fsm_check_policy(int type, int class, void *newState);

#endif // FSM_POLICY_H