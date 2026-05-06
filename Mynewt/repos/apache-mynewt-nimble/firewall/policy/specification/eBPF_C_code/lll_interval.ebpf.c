// CVE-2021-3432

// #include "../include/ebpf_helper.h"
#include "../include/fsm_for_ebpf.h"

uint64_t zephyr_filter(uint8_t *newState)
{
	struct FsmState *fsm = (struct FsmState *)newState;

	// check chan map
	if (!fsm->conn_param[LLL_INTERVAL]) {
		return IFW_OPERATION_REJECT;
	}

	return IFW_OPERATION_PASS;
}