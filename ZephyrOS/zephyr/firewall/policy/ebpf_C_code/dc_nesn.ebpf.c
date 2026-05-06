// CVE-2020-10060/10061 — anchor-point NESN/SN crash.
//
// The vulnerable byte pattern (NESN=1, SN=1) is only an attack at the
// connection's *anchor* point — the first DC PDU after CONNECT_IND.
// Post-anchor, the same combination is normal retransmission traffic.
//
// The LL RX hook drives a state-aware lifecycle in core_state[LL_STATE]:
//   IFW_BLE_LL_CONNECTION_STATE (0)  : just-established, anchor pending
//   IFW_BLE_LL_STANDBY_STATE     (1) : post-anchor, steady-state
// The policy fires only in the anchor-pending state, so legitimate
// retransmits cannot be false-positively dropped.

#include "../include/fsm_for_ebpf.h"

uint64_t zephyr_filter(uint8_t *newState)
{
	struct FsmState *fsm = (struct FsmState *)newState;

	if (fsm->core_state[LL_STATE] == IFW_BLE_LL_CONNECTION_STATE &&
	    fsm->dc_param[NESN] == 1 &&
	    fsm->dc_param[SN] == 1) {
		return IFW_OPERATION_REJECT;
	}

	return IFW_OPERATION_PASS;
}
