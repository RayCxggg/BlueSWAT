// CVE-2021-3581

// #include "../include/ebpf_helper.h"
#include "../include/fsm_for_ebpf.h"

#define PDU_AC_SIZE_MAX 80

uint64_t zephyr_filter(uint8_t *newState)
{
	struct FsmState *fsm = (struct FsmState *)newState;

	// check Scan Response Length
	if (fsm->conn_param[SCAN_RSP_LEN] > PDU_AC_SIZE_MAX) {
		return IFW_OPERATION_REJECT;
	}

	return IFW_OPERATION_PASS;
}