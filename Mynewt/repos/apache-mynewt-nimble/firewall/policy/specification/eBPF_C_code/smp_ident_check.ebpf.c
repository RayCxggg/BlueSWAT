// #include "../include/ebpf_helper.h"
#include "../include/fsm_for_ebpf.h"

#define BT_KEYS_LTK_P256 32
#define BT_KEYS_LTK 4
#define BT_KEYS_AUTHENTICATED 1

enum pairing_method {
	JUST_WORKS, /* JustWorks pairing */
	PASSKEY_INPUT, /* Passkey Entry input */
	PASSKEY_DISPLAY, /* Passkey Entry display */
	PASSKEY_CONFIRM, /* Passkey confirm */
	PASSKEY_ROLE, /* Passkey Entry depends on role */
	LE_SC_OOB, /* LESC Out of Band */
};

uint64_t zephyr_filter(uint8_t *newState)
{
	struct FsmState *fsm = (struct FsmState *)newState;

	//   Check that if a new pairing procedure with an existing bond will not lower the established security level of the bond.

	if (!(fsm->dc_param[SMP_KEYS] & (BT_KEYS_LTK_P256 | BT_KEYS_LTK))) {
		return IFW_OPERATION_PASS;
	}

	if (fsm->dc_param[SMP_ENC_SIZE] > fsm->dc_param[SMP_ENC_SIZE_PREV]) {
		return IFW_OPERATION_REJECT;
	}

	if ((fsm->dc_param[SMP_KEYS_FLAGS] & BT_KEYS_AUTHENTICATED) &&
	    fsm->dc_param[SMP_METHOD_PREV] == JUST_WORKS) {
		return IFW_OPERATION_REJECT;
	}

	return IFW_OPERATION_PASS;
}