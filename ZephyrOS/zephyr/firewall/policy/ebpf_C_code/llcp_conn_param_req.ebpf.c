// CVE-2021-3430: duplicate LL_CONNECTION_PARAM_REQ before
// LL_CONNECTION_PARAM_RSP.
//
// The LL RX hook keeps a count of in-flight CPRs in
// fsm->dc_param[LLCP_CONN_PARAM_REQ]: incremented on each REQ, decremented
// on each RSP, reset on every CONNECT_IND.  Reject the moment more than
// one is outstanding.

#include "../include/fsm_for_ebpf.h"

uint64_t zephyr_filter(uint8_t *newState)
{
	struct FsmState *fsm = (struct FsmState *)newState;

	if (fsm->dc_param[LLCP_CONN_PARAM_REQ] > 1) {
		return IFW_OPERATION_REJECT;
	}

	return IFW_OPERATION_PASS;
}
