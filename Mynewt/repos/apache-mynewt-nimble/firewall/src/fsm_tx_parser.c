#include <stdio.h>
#include <string.h>

#include "fsm_lib_hdr.h"
#include "fsm_core.h"
#include "utils.h"
#include "controller/ble_ll.h"

void ifw_ll_tx_parser(struct ble_mbuf_hdr *ble_hdr, struct os_mbuf *m, struct ble_ll_conn_sm *connsm)
{
    uint8_t llid;
    uint16_t cur_offset;
    uint8_t cur_txlen;
    uint16_t next_txlen;
    uint8_t opcode;
    uint16_t pktlen;
    int is_ctrl;

    llid = ble_hdr->txinfo.hdr_byte & BLE_LL_DATA_HDR_LLID_MASK;
    if (llid == BLE_LL_LLID_CTRL)
    {
        is_ctrl = 1;
        opcode = m->om_data[0];
    }
    else
    {
        is_ctrl = 0;
        opcode = 0;
    }

    IFW_FSM_STATE_UPDATE(is_ctrl, TX_IS_CTRL, CONN);
    IFW_FSM_STATE_UPDATE(opcode, TX_OPCODE, CONN);

    pktlen = OS_MBUF_PKTLEN(m);

    cur_txlen = ble_hdr->txinfo.pyld_len;
    cur_offset = ble_hdr->txinfo.offset;

    if ((cur_offset + cur_txlen) < pktlen)
    {
        next_txlen = pktlen - (cur_offset + cur_txlen);
    }
    else
    {
        next_txlen = connsm->eff_max_tx_octets;
    }
    if (next_txlen > connsm->eff_max_tx_octets)
    {
        next_txlen = connsm->eff_max_tx_octets;
    }

    return;
}

/* LL TX hook for advertising-channel PDUs (the "1 LL TX hook" the paper
 * refers to, on the adv-role side). Mirror of the Zephyr port's
 * ifw_ll_packet_parser_tx. Currently enforces CVE-2021-3581
 * (SCAN_RSP_LEN); other adv types fall through. The adv role state
 * machine in ble_ll_adv.c should call this just before staging the PDU
 * to the radio, returning IFW_OPERATION_REJECT to drop it. */
bool ifw_ll_adv_tx_parser(uint8_t adv_type, uint8_t pdu_len)
{
    switch (adv_type) {
    case BLE_ADV_PDU_TYPE_SCAN_RSP:
        if (IFW_FSM_CHECK_UPDATE(pdu_len, SCAN_RSP_LEN, CONN)) {
            MODLOG_DFLT(INFO, "Malicious scan response dropped at LL TX.\n");
            return IFW_OPERATION_REJECT;
        }
        break;

    default:
        break;
    }

    return IFW_OPERATION_PASS;
}
