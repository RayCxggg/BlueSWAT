#include <stdio.h>
#include <string.h>

#include "fsm_lib_hdr.h"
#include "fsm_core.h"
#include "utils.h"
#include "controller/ble_ll_ctrl.h"

bool ifw_ble_ll_conn_periph_start(uint8_t *rxbuf);

/* Per-connection counters, mirrored into the FSM through
 * IFW_FSM_CHECK_UPDATE so the eBPF policies can read them.  Same design
 * as the Zephyr port — see ZephyrOS/zephyr/firewall/core/fsm_ll_pkt_parser.c. */
static int llcp_len_req_pending;
static int llcp_cpr_pending;

static inline uint8_t ifw_count_one(const uint8_t *octets)
{
    uint8_t one_count = 0u;
    int octets_len = BLE_LL_CHAN_MAP_LEN;

    while (octets_len--) {
        uint8_t bite = *octets;
        while (bite) {
            bite &= (bite - 1);
            one_count++;
        }
        octets++;
    }

    return one_count;
}

bool ifw_dc_ll_ctrl_parser(struct ble_ll_conn_sm *connsm, struct os_mbuf *rxpdu)
{
    /* CVE-2020-10068 / CVE-2021-3430 / CVE-2020-10069 / CVE-2021-3432 mid-session
     * coverage.  The first byte of the LLCP PDU body is the LL opcode. */
    if (rxpdu == NULL) {
        return IFW_OPERATION_PASS;
    }

    uint8_t opcode = 0;
    if (os_mbuf_copydata(rxpdu, 0, 1, &opcode) != 0) {
        return IFW_OPERATION_PASS;
    }

    switch (opcode) {
    case BLE_LL_CTRL_LENGTH_REQ:
        llcp_len_req_pending++;
        if (IFW_FSM_CHECK_UPDATE(llcp_len_req_pending, LLCP_LEN_REQ, DC)) {
            MODLOG_DFLT(INFO, "Duplicate LL_LENGTH_REQ detected! Abort!\n");
            return IFW_OPERATION_REJECT;
        }
        break;

    case BLE_LL_CTRL_LENGTH_RSP:
        if (llcp_len_req_pending > 0) {
            llcp_len_req_pending--;
        }
        break;

    case BLE_LL_CTRL_CONN_PARM_REQ:
        llcp_cpr_pending++;
        if (IFW_FSM_CHECK_UPDATE(llcp_cpr_pending, LLCP_CONN_PARAM_REQ, DC)) {
            MODLOG_DFLT(INFO, "Duplicate LL_CONN_PARAM_REQ detected! Abort!\n");
            return IFW_OPERATION_REJECT;
        }
        break;

    case BLE_LL_CTRL_CONN_PARM_RSP:
        if (llcp_cpr_pending > 0) {
            llcp_cpr_pending--;
        }
        break;

    case BLE_LL_CTRL_CHANNEL_MAP_REQ: {
        /* CVE-2020-10069 mid-session: an attacker post-CONNECT can issue
         * LL_CHANNEL_MAP_REQ (a.k.a. LL_CHANNEL_MAP_IND) with too few
         * enabled channels, replicating the same data_chan_count==0 hazard
         * as the CONNECT_IND path. Body layout: 5-byte channel map. */
        uint8_t chm[BLE_LL_CHAN_MAP_LEN];
        if (os_mbuf_copydata(rxpdu, 1, BLE_LL_CHAN_MAP_LEN, chm) == 0) {
            uint8_t new_count = ifw_count_one(chm);
            if (IFW_FSM_CHECK_UPDATE(new_count, CHANNEL_MAP, CONN)) {
                MODLOG_DFLT(INFO, "Mid-session bad channel map! Abort!\n");
                return IFW_OPERATION_REJECT;
            }
        }
        break;
    }

    case BLE_LL_CTRL_CONN_UPDATE_IND: {
        /* CVE-2021-3432 mid-session: zero-interval delivered via
         * LL_CONN_UPDATE_IND. Body layout (LL_CONNECTION_UPDATE_IND PDU):
         *   [0] win_size, [1..2] win_offset, [3..4] interval, ... */
        uint8_t buf[5];
        if (os_mbuf_copydata(rxpdu, 1, sizeof(buf), buf) == 0) {
            uint16_t new_interval = (uint16_t)(buf[3] | ((uint16_t)buf[4] << 8));
            if (IFW_FSM_CHECK_UPDATE(new_interval, LLL_INTERVAL, CONN)) {
                MODLOG_DFLT(INFO, "Mid-session bad interval! Abort!\n");
                return IFW_OPERATION_REJECT;
            }
        }
        break;
    }

    default:
        break;
    }

    return IFW_OPERATION_PASS;
}

bool ifw_adv_ll_parser(uint8_t ptype, uint8_t *rxbuf, struct ble_mbuf_hdr *hdr)
{
    uint8_t *dptr;
    uint8_t chan_map[BLE_LL_CHAN_MAP_LEN];
    uint8_t chan_count;
    uint8_t hop;
    uint16_t interval;

    /* Set the pointer at the start of the connection data */
    dptr = rxbuf + IFW_BLE_LL_CONN_REQ_ADVA_OFF + IFW_BLE_DEV_ADDR_LEN;

    if (ptype == BLE_ADV_PDU_TYPE_CONNECT_IND)
    {
        /* CONNECT_IND PDU layout (after the InitA/AdvA header that dptr
         * already skips):
         *   AccessAddress(4) CRCInit(3) WinSize(1) WinOffset(2) Interval(2)
         *   Latency(2) Timeout(2) ChM(5) Hop(5b)+SCA(3b)
         *
         * Offsets relative to dptr:
         *   AA   = 0   CRCInit = 4   WinSize = 7   WinOffset = 8
         *   Interval = 10   Latency = 12   Timeout = 14
         *   ChM  = 16   Hop+SCA = 21
         */
        memcpy(chan_map, dptr + 16, BLE_LL_CHAN_MAP_LEN);
        chan_count = ifw_count_one(chan_map);

        if (IFW_FSM_CHECK_UPDATE(chan_count, CHANNEL_MAP, CONN))
        {
            MODLOG_DFLT(INFO, "Invalid channel map detected! Abort!\n");
            return IFW_OPERATION_REJECT;
        }

        hop = dptr[21] & 0x1f;
        if (IFW_FSM_CHECK_UPDATE(hop, CHANNEL_HOP, CONN))
        {
            MODLOG_DFLT(INFO, "Invalid channel hop detected! Abort!\n");
            return IFW_OPERATION_REJECT;
        }

        interval = (uint16_t)(dptr[10] | ((uint16_t)dptr[11] << 8));
        if (IFW_FSM_CHECK_UPDATE(interval, LLL_INTERVAL, CONN))
        {
            MODLOG_DFLT(INFO, "Invalid interval detected! Abort!\n");
            return IFW_OPERATION_REJECT;
        }

        /* Fresh connection: reset per-connection counters and arm the
         * dc_nesn anchor gate. The dc_nesn policy reads
         * dc_param[DC_ANCHOR_STATE] alongside NESN/SN; the first DC PDU
         * clears the gate (see ifw_dc_ll_ctrl_parser-driven hooks). */
        llcp_len_req_pending = 0;
        llcp_cpr_pending = 0;
        IFW_FSM_STATE_UPDATE(1, DC_ANCHOR_STATE, DC);

        if (ifw_ble_ll_conn_periph_start(rxbuf) == IFW_OPERATION_REJECT)
        {
            return IFW_OPERATION_REJECT;
        }
    }

    return IFW_OPERATION_PASS;
}

bool ifw_ble_ll_conn_periph_start(uint8_t *rxbuf)
{
    uint8_t *inita = rxbuf + IFW_BLE_LL_PDU_HDR_LEN;
    uint32_t bd_hash = 0;

    /* shared_state[BD_ADDR] is now a single int slot (Zephyr-aligned struct
     * layout). Fold the 6-byte address down to a 32-bit FNV hash so the
     * single-slot value still moves whenever the peer changes. */
    for (int i = 0; i < IFW_BLE_DEV_ADDR_LEN; i++)
    {
        bd_hash ^= inita[i];
        bd_hash *= 16777619u;
    }

    IFW_FSM_STATE_UPDATE((uint16_t)bd_hash, BD_ADDR, SHARED);

    return IFW_OPERATION_PASS;
}
