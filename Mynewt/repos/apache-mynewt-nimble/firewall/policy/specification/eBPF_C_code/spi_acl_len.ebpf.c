// CVE-2020-10065

// #include "../include/ebpf_helper.h"
#include "../include/fsm_for_ebpf.h"

#define BT_BUF_RX_SIZE 76

uint64_t zephyr_filter(uint8_t *newState)
{
	struct FsmState *fsm = (struct FsmState *)newState;

	// check SPI HCI_EVT length
	if (fsm->spi_param[HCI_ACL_LEN] > BT_BUF_RX_SIZE) {
		return IFW_OPERATION_REJECT;
	}

	return IFW_OPERATION_PASS;
}