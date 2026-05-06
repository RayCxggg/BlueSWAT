// CVE-2020-10068: duplicate LL_LENGTH_REQ before LL_LENGTH_RSP.
//
// The LL RX hook (firewall/core/fsm_ll_pkt_parser.c) maintains a count of
// in-flight LL_LENGTH_REQs in fsm->dc_param[LLCP_LEN_REQ]: incremented on
// each REQ, decremented on each RSP, reset on every CONNECT_IND.  Reject
// as soon as more than one request is outstanding (the vulnerable Zephyr
// stack would dereference an uninitialized buffer the second time around).

#include "../include/fsm_for_ebpf.h"

uint64_t zephyr_filter(uint8_t *newState)
{
	struct FsmState *fsm = (struct FsmState *)newState;

	if (fsm->dc_param[LLCP_LEN_REQ] > 1) {
		return IFW_OPERATION_REJECT;
	}

	return IFW_OPERATION_PASS;
}
