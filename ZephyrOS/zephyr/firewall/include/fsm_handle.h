#ifndef FSM_HANDLE_H
#define FSM_HANDLE_H

#include "fsm_core.h"
#include "fsm_lib_hdr.h"

// whether to use JIT interpretation
#define JIT_OFF 0
#define JIT_ON 1

void ifw_fsm_enable(bool jit);
bool ifw_ll_packet_parser_rx(memq_link_t *link, struct node_rx_hdr *rx);
bool ifw_ll_packet_parser_tx(struct pdu_adv *pdu);
bool ifw_l2cap_packet_parser_recv(struct bt_conn *conn, struct net_buf *buf);
int ifw_fsm_check_update(uint16_t state, uint16_t type, uint16_t class);
int ifw_run_verifier(uint16_t type, uint16_t class);
int ifw_fsm_state_update(uint16_t state, uint16_t type, uint16_t class);

#define IFW_LL_PACKET_PARSER(link, rx)                                         \
	(ifw_ll_packet_parser_rx(link, rx) == IFW_OPERATION_REJECT)

#define IFW_LL_TX_PARSER(pdu)                                                  \
	(ifw_ll_packet_parser_tx(pdu) == IFW_OPERATION_REJECT)

#define IFW_L2CAP_PACKET_PARSER(conn, buf)                                     \
	(ifw_l2cap_packet_parser_recv(conn, buf) == IFW_OPERATION_REJECT)

// #define IFW_INVALID_RELEASE(hdr, lll, link, rx)                                \
// 	ifw_invalid_release(hdr, lll, link, rx)

#define IFW_FSM_CHECK_UPDATE(state, type, class)                               \
	(ifw_fsm_check_update(state, type, class) == IFW_UPDATE_ERROR)

#define IFW_RUN_VERIFIER(type, class)                                          \
	(ifw_run_verifier(type, class) == IFW_OPERATION_REJECT)

#define IFW_FSM_STATE_UPDATE(state, type, class)                               \
	(ifw_fsm_state_update(state, type, class) == IFW_UPDATE_ERROR)

// extern void bt_le_adv_resume(void);
// extern void ll_reset(void);

#endif // FSM_HANDLE_H