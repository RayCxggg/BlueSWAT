// CVE-2020-10060/10061 — anchor-point NESN/SN crash.
//
// The vulnerable byte pattern (NESN=1, SN=1) is only an attack at the
// connection's *anchor* point — the first DC PDU after CONNECT_IND.
// Post-anchor, the same combination is normal retransmission traffic.
//
// The LL RX hook drives a per-policy parameter in the FSM:
//   dc_param[DC_ANCHOR_STATE] = 1  on every CONNECT_IND (anchor pending)
//                              = 0  after the first DC PDU clears the
//                                   verifier (anchor consumed)
// The policy fires only while the slot is 1, so legitimate retransmits
// post-anchor are not false-positively dropped.  No core_state field is
// touched — that class belongs to the global LL state machine.

#include "../include/fsm_for_ebpf.h"

uint64_t zephyr_filter(uint8_t *newState)
{
	struct FsmState *fsm = (struct FsmState *)newState;

	if (fsm->dc_param[DC_ANCHOR_STATE] == 1 &&
	    fsm->dc_param[NESN] == 1 &&
	    fsm->dc_param[SN] == 1) {
		return IFW_OPERATION_REJECT;
	}

	return IFW_OPERATION_PASS;
}
