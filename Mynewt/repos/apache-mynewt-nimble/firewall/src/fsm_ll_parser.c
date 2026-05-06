#include <stdio.h>
#include <string.h>

#include "fsm_lib_hdr.h"
#include "fsm_core.h"
#include "utils.h"

bool ifw_ble_ll_conn_periph_start(uint8_t *rxbuf);

bool ifw_dc_ll_ctrl_parser(struct ble_ll_conn_sm *connsm, struct os_mbuf *rxpdu)
{
    /* DC PDU parser hook on the NimBLE controller path. NimBLE-specific
     * LLCP rules (when added) belong here; the Zephyr port enforces a
     * different set of LLCP-driven CVEs at its own LL hook point. */
    return IFW_OPERATION_PASS;
}

bool ifw_adv_ll_parser(uint8_t ptype, uint8_t *rxbuf, struct ble_mbuf_hdr *hdr)
{
    uint8_t *dptr;
    uint8_t chan_map[BLE_LL_CHAN_MAP_LEN];
    uint16_t chan_map_check;

    /* Set the pointer at the start of the connection data. */
    dptr = rxbuf + IFW_BLE_LL_CONN_REQ_ADVA_OFF + IFW_BLE_DEV_ADDR_LEN;

    if (ptype == BLE_ADV_PDU_TYPE_CONNECT_IND)
    {
        memcpy(&chan_map, dptr + 16, BLE_LL_CHAN_MAP_LEN);
        chan_map_check = (uint16_t)(chan_map[1] << 8 | chan_map[0]);

        if (IFW_FSM_CHECK_UPDATE(chan_map_check, CHANNEL_MAP, CONN))
        {
            MODLOG_DFLT(INFO, "Invalid channel map detected! Abort!\n");
            return IFW_OPERATION_REJECT;
        }

        if (ifw_ble_ll_conn_periph_start(rxbuf) == IFW_OPERATION_REJECT)
        {
            return IFW_OPERATION_REJECT;
        }
    }

    return IFW_OPERATION_PASS;
}

bool ifw_ble_ll_conn_periph_start(uint8_t *rxbuf)
{
    uint8_t *inita;
    uint8_t peer_addr[IFW_BLE_DEV_ADDR_LEN];

    inita = rxbuf + IFW_BLE_LL_PDU_HDR_LEN;
    memcpy(&peer_addr, inita, IFW_BLE_DEV_ADDR_LEN);

    /* shared_state[BD_ADDR..BD_ADDR+5] holds the 6 peer-address bytes
     * (Mynewt layout — the Zephyr port collapses BD_ADDR to a single
     * slot and uses different shared-state semantics). */
    for (int i = 0; i < IFW_BLE_DEV_ADDR_LEN; i++) {
        IFW_FSM_STATE_UPDATE(peer_addr[i], BD_ADDR + i, SHARED);
    }

    return IFW_OPERATION_PASS;
}
