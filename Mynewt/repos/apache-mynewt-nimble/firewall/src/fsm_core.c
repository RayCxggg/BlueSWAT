#include <stdio.h>
#include <string.h>

#include "fsm_core.h"
#include "fsm_policy_cache.h"
#include "utils.h"
#include "fsm_lib_hdr.h"

static int ifw_core_state_num[IFW_CORE_STATE_NUM] = {
    IFW_BLE_LL_STATE_NUM,
    IFW_BLE_PAIRING_MODE_NUM,
    IFW_BLE_PAIRING_METHOD_NUM,
    IFW_BLE_ROLE_NUM,
    IFW_IO_CAPACITY_NUM,
};

static struct FsmState curFSMState;
static struct FsmState newFSMState;

extern int ifw_fcb_init(void);

void ifw_fsm_init()
{
    memset(&curFSMState, 0, sizeof(curFSMState));
    memset(&newFSMState, 0, sizeof(newFSMState));

    /* Init core state slots to "unknown" (==NUM sentinel). */
    for (int i = 0; i < IFW_CORE_STATE_NUM; i++) {
        curFSMState.core_state[i] = ifw_core_state_num[i];
    }

    if (ifw_fcb_init()) {
        MODLOG_DFLT(INFO, "IFW FCB init failed.\n");
        return;
    }
}

/* Refresh the staging FsmState from the canonical state.
 *
 * The legacy implementation guarded this with a `fsm_new_init` flag that
 * was set to 1 then immediately written back to 0 (so the staging state
 * was never refreshed and policies inspected stale data). Just refresh
 * unconditionally — the cost is one struct copy per packet, well below
 * the eBPF VM dispatch overhead. */
static inline void ifw_stage_refresh(void)
{
    newFSMState = curFSMState;
}

void ifw_fsm_state_update(uint16_t state, uint16_t type, uint16_t class)
{
    switch (class)
    {
    case SHARED:
        if (type < IFW_SHARED_STATE_NUM) {
            curFSMState.shared_state[type] = state;
        }
        break;
    case CORE:
        if (type < IFW_CORE_STATE_NUM) {
            curFSMState.core_state[type] = state;
        }
        break;
    case CONN:
        if (type < IFW_CONN_PARAM_NUM) {
            curFSMState.conn_param[type] = state;
        }
        break;
    case DC:
        if (type < IFW_DC_PARAM_NUM) {
            curFSMState.dc_param[type] = state;
        }
        break;
    case SPI:
        if (type < IFW_SPI_PARAM_NUM) {
            curFSMState.spi_param[type] = state;
        }
        break;
    case HCI:
        if (type < IFW_HCI_PARAM_NUM) {
            curFSMState.hci_param[type] = state;
        }
        break;
    default:
        break;
    }
}

uint8_t ifw_fsm_check_update(uint16_t state, uint16_t type, uint16_t class)
{
    ifw_stage_refresh();

    switch (class)
    {
    case SHARED:
        if (type >= IFW_SHARED_STATE_NUM) {
            return IFW_OPERATION_REJECT;
        }
        newFSMState.shared_state[type] = state;
        break;

    case CORE:
        if (type >= IFW_CORE_STATE_NUM ||
            state >= ifw_core_state_num[type]) {
            return IFW_OPERATION_REJECT;
        }
        newFSMState.core_state[type] = state;
        break;

    case CONN:
        if (type >= IFW_CONN_PARAM_NUM) {
            return IFW_OPERATION_REJECT;
        }
        newFSMState.conn_param[type] = state;
        break;

    case DC:
        if (type >= IFW_DC_PARAM_NUM) {
            return IFW_OPERATION_REJECT;
        }
        newFSMState.dc_param[type] = state;
        break;

    case SPI:
        if (type >= IFW_SPI_PARAM_NUM) {
            return IFW_OPERATION_REJECT;
        }
        newFSMState.spi_param[type] = state;
        break;

    case HCI:
        if (type >= IFW_HCI_PARAM_NUM) {
            return IFW_OPERATION_REJECT;
        }
        newFSMState.hci_param[type] = state;
        break;

    default:
        return IFW_OPERATION_REJECT;
    }

    if (run_fsm_check_policy(type, class, &newFSMState) == IFW_OPERATION_REJECT) {
        return IFW_OPERATION_REJECT;
    }

    /* Verifier passed — commit. */
    ifw_fsm_state_update(state, type, class);
    return IFW_OPERATION_PASS;
}

uint8_t ifw_run_verifier(uint16_t type, uint16_t class)
{
    if (run_fsm_check_policy(type, class, &newFSMState) == IFW_OPERATION_REJECT) {
        return IFW_OPERATION_REJECT;
    }
    return IFW_OPERATION_PASS;
}
