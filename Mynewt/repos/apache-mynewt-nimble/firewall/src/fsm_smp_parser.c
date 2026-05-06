#include <stdio.h>
#include <string.h>

#include "fsm_lib_hdr.h"
#include "fsm_core.h"
#include "utils.h"

/* SMP packet codes (subset). Aligned with NimBLE host BLE_SM_OP_*. */
#define IFW_SMP_OP_PAIRING_REQUEST  0x01
#define IFW_SMP_OP_IDENT_INFO       0x08
#define IFW_SMP_OP_IDENT_ADDR_INFO  0x09

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

    switch (op) {
    case IFW_SMP_OP_PAIRING_REQUEST: {
        /* Legacy keysize-confusion check (CVE-2020-13593-style): the peer
         * may not silently downgrade max_enc_key_size between sessions. */
        req = (struct ifw_ble_sm_pair_cmd *)((uint8_t *)(*om)->om_data + 1);

        if (IFW_FSM_CHECK_UPDATE(req->max_enc_key_size, SMP_MAX_ENC_SIZE, DC))
        {
            MODLOG_DFLT(INFO, "Invalid SMP_MAX_ENC_SIZE detected! Abort!\n");
            return IFW_OPERATION_REJECT;
        }
        IFW_FSM_STATE_UPDATE(req->max_enc_key_size, SMP_MAX_ENC_SIZE_PREV, DC);
        break;
    }

    case IFW_SMP_OP_IDENT_ADDR_INFO: {
        /* CVE-class: SMP key/identity downgrade across re-bond. The
         * smp_ident_check policy reads SMP_KEYS / SMP_ENC_SIZE /
         * SMP_KEYS_FLAGS together with the *_PREV slots to detect a
         * weaker re-bond. We surface the observable bytes from the
         * incoming PDU; richer fields (keys flags etc.) are filled in
         * once the host stack hooks up the bond record. */
        uint8_t addr_type = 0;
        uint8_t addr0 = 0;
        (void)os_mbuf_copydata(*om, 1, 1, &addr_type);
        (void)os_mbuf_copydata(*om, 2, 1, &addr0);

        IFW_FSM_STATE_UPDATE(addr_type, SMP_KEYS_FLAGS, DC);
        IFW_FSM_STATE_UPDATE(addr0,     SMP_KEYS, DC);

        if (IFW_RUN_VERIFIER(SMP_KEYS, DC)) {
            MODLOG_DFLT(INFO, "SMP key downgrade detected! Abort!\n");
            return IFW_OPERATION_REJECT;
        }
        break;
    }

    default:
        break;
    }

    return IFW_OPERATION_PASS;
}
