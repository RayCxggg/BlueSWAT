#include <stdio.h>
#include <string.h>

#include "fsm_lib_hdr.h"
#include "fsm_handle.h"

#include "utils.h"

static bool result = 0;

bool ifw_ll_dc_ctrl_parser(struct ble_ll_conn_sm *connsm, struct os_mbuf *rxpdu)
{
    result = IFW_OPERATION_PASS;

    return result;
}
