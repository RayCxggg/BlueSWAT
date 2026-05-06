// #include "../include/ebpf_helper.h"
#include "../include/fsm_for_ebpf.h"

uint64_t zephyr_filter(uint8_t *newState)
{
	struct FsmState *fsm = (struct FsmState *)newState;

	if ((fsm->conn_param[CHANNEL_HOP] < 5) ||
	    (fsm->conn_param[CHANNEL_HOP] > 16)) {
		return IFW_OPERATION_REJECT;
	}

	return IFW_OPERATION_PASS;
}