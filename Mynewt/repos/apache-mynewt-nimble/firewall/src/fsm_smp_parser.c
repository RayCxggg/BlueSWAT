#include <stdio.h>
#include <string.h>

#include "fsm_lib_hdr.h"
#include "fsm_core.h"
#include "utils.h"

/* Mynewt-side SMP/L2CAP-host parser. Drives the keysize_confusion /
 * key_entropy_downgrade policies registered by load_all_policies(). */
bool ifw_smp_parser(void *chan_in)
{
    struct ifw_ble_sm_pair_cmd *req;
    struct os_mbuf **om;
    uint8_t op;
    int rc;

    struct ifw_ble_l2cap_chan *chan = (struct ifw_ble_l2cap_chan *)chan_in;

    om = &chan->rx_buf;
    if (om == NULL || *om == NULL) {
        return IFW_OPERATION_PASS;
    }

    rc = os_mbuf_copydata(*om, 0, 1, &op);
    if (rc != 0)
    {
        return IFW_OPERATION_PASS;
    }

    if (op == 0x01) /* SMP pairing request */
    {
        req = (struct ifw_ble_sm_pair_cmd *)((uint8_t *)(*om)->om_data + 1);

        if (IFW_FSM_CHECK_UPDATE(req->max_enc_key_size, SMP_MAX_ENC_SIZE, DC))
        {
            MODLOG_DFLT(INFO, "Invalid SMP_MAX_ENC_SIZE detected! Abort!\n");
            return IFW_OPERATION_REJECT;
        }

        IFW_FSM_STATE_UPDATE(req->max_enc_key_size, SMP_MAX_ENC_SIZE_PREV, DC);
    }

    return IFW_OPERATION_PASS;
}
