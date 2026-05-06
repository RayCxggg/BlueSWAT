/*
 * Mock subset of Zephyr v2.2 BLE-stack types and helpers, sufficient to
 * compile firewall/core/*.c natively on a Linux host without Zephyr
 * installed.  We pre-define FSM_LIB_HDR_H_ to short-circuit the firewall's
 * own kitchen-sink-include header, then re-declare exactly the structs and
 * symbols its .c files reference.  Layout fidelity is not the goal — we
 * call the firewall by field name, never by raw offset.
 */
#ifndef ZEPHYR_MOCKS_H_
#define ZEPHYR_MOCKS_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

/* Block fsm_lib_hdr.h's Zephyr include cascade. */
#define FSM_LIB_HDR_H_

/* Zephyr scalar typedefs (in real builds these come from include/zephyr/types.h). */
typedef uint8_t  u8_t;
typedef uint16_t u16_t;
typedef uint32_t u32_t;
typedef uint64_t u64_t;
typedef int8_t   s8_t;
typedef int16_t  s16_t;
typedef int32_t  s32_t;

#define sys_le16_to_cpu(x) ((u16_t)(x))
#define ENOBUFS 105

/* ------------------------------------------------------------------ */
/* Controller link-layer types                                          */
/* ------------------------------------------------------------------ */

typedef struct memq_link memq_link_t;
struct memq_link { void *next; };

struct ccm { u8_t pad[16]; };

struct lll_hdr {
	void *parent;
	u8_t is_stop : 1;
};

struct lll_conn {
	struct lll_hdr hdr;

	u8_t access_addr[4];
	u8_t crc_init[3];

	u16_t handle;
	u16_t interval;
	u16_t latency;

	u8_t data_chan_map[5];
	u8_t data_chan_count;
	u8_t data_chan_hop;

	u8_t role;

	u8_t sn : 1;
	u8_t nesn : 1;
};

enum node_rx_type {
	NODE_RX_TYPE_NONE = 0x00,
	NODE_RX_TYPE_EVENT_DONE = 0x01,
	NODE_RX_TYPE_DC_PDU = 0x02,
	NODE_RX_TYPE_DC_PDU_RELEASE = 0x03,
	NODE_RX_TYPE_CONNECTION = 0x08,
};

struct node_rx_ftr {
	void *param;
	void *extra;
	u32_t ticks_anchor;
	u32_t us_radio_end;
	u32_t us_radio_rdy;
	u8_t  rssi;
};

struct node_rx_hdr {
	void *next;
	enum node_rx_type type;
	u8_t  user_meta;
	u16_t handle;
	struct node_rx_ftr rx_ftr;
};

struct node_rx_pdu {
	struct node_rx_hdr hdr;
	u8_t pdu[256];
};

struct node_tx { void *next; u8_t pdu[]; };

/* ------------------------------------------------------------------ */
/* PDU formats                                                          */
/* ------------------------------------------------------------------ */

struct pdu_adv_connect_ind {
	u8_t init_addr[6];
	u8_t adv_addr[6];
	u8_t access_addr[4];
	u8_t crc_init[3];
	u8_t win_size;
	u16_t win_offset;
	u16_t interval;
	u16_t latency;
	u16_t timeout;
	u8_t chan_map[5];
	u8_t hop : 5;
	u8_t sca : 3;
} __attribute__((packed));

enum pdu_adv_type {
	PDU_ADV_TYPE_ADV_IND = 0x00,
	PDU_ADV_TYPE_DIRECT_IND = 0x01,
	PDU_ADV_TYPE_NONCONN_IND = 0x02,
	PDU_ADV_TYPE_SCAN_REQ = 0x03,
	PDU_ADV_TYPE_SCAN_RSP = 0x04,
	PDU_ADV_TYPE_CONNECT_IND = 0x05,
	PDU_ADV_TYPE_SCAN_IND = 0x06,
};

struct pdu_adv {
	u8_t type : 4;
	u8_t rfu : 1;
	u8_t chan_sel : 1;
	u8_t tx_addr : 1;
	u8_t rx_addr : 1;
	u8_t len;
	union {
		u8_t payload[0];
		struct pdu_adv_connect_ind connect_ind;
	};
} __attribute__((packed));

enum pdu_data_llid {
	PDU_DATA_LLID_RESV = 0x00,
	PDU_DATA_LLID_DATA_CONTINUE = 0x01,
	PDU_DATA_LLID_DATA_START = 0x02,
	PDU_DATA_LLID_CTRL = 0x03,
};

enum pdu_data_llctrl_type {
	PDU_DATA_LLCTRL_TYPE_CHAN_MAP_IND = 0x01,
	PDU_DATA_LLCTRL_TYPE_CONN_PARAM_REQ = 0x0F,
	PDU_DATA_LLCTRL_TYPE_CONN_PARAM_RSP = 0x10,
	PDU_DATA_LLCTRL_TYPE_LENGTH_REQ = 0x14,
	PDU_DATA_LLCTRL_TYPE_LENGTH_RSP = 0x15,
};

struct pdu_data_llctrl_chan_map_ind {
	u8_t chm[5];
	u16_t instant;
} __attribute__((packed));

struct pdu_data_llctrl {
	u8_t opcode;
	union {
		u8_t payload[64];
		struct pdu_data_llctrl_chan_map_ind chan_map_ind;
	};
} __attribute__((packed));

struct pdu_data {
	u8_t ll_id : 2;
	u8_t nesn : 1;
	u8_t sn : 1;
	u8_t md : 1;
	u8_t rfu : 3;
	u8_t len;
	u8_t resv;
	struct pdu_data_llctrl llctrl;
} __attribute__((packed));

/* ------------------------------------------------------------------ */
/* Host (L2CAP / SMP) types                                             */
/* ------------------------------------------------------------------ */

struct ll_conn {
	struct {
		u8_t role;
	} lll;
	struct {
		u8_t req;
		u8_t ack;
		u8_t state;
	} llcp_length;
	struct {
		u8_t req;
		u8_t ack;
		u8_t state;
	} llcp_conn_param;
};

struct net_buf_simple {
	u8_t *data;
	u16_t len;
	u16_t size;
	u8_t *__buf;
};

struct net_buf {
	u8_t *data;
	u16_t len;
	u16_t size;
	u8_t *__buf;
};

struct bt_l2cap_hdr { u16_t len; u16_t cid; } __attribute__((packed));

#define BT_L2CAP_CONN_PARAM_REQ 0x12
#define BT_L2CAP_CONN_PARAM_RSP 0x13
#define BT_L2CAP_CMD_REJECT     0x01
#define BT_L2CAP_DISCONN_REQ    0x06
#define BT_L2CAP_DISCONN_RSP    0x07
#define BT_L2CAP_LE_CONN_REQ    0x14
#define BT_L2CAP_LE_CONN_RSP    0x15
#define BT_L2CAP_LE_CREDITS     0x16

struct bt_l2cap_chan { void *conn; };

struct bt_smp_hdr { u8_t code; } __attribute__((packed));

struct bt_addr_le { u8_t type; u8_t a[6]; } __attribute__((packed));

struct bt_smp_ident_addr_info { struct bt_addr_le addr; } __attribute__((packed));

struct bt_smp {
	struct {
		struct bt_l2cap_chan chan;  /* smp->chan.chan */
	} chan;
	u8_t method;
};

struct bt_keys {
	u8_t  keys;
	u8_t  enc_size;
	u8_t  flags;
};

struct bt_conn {
	struct {
		struct bt_addr_le dst;
	} le;
	u8_t id;
};

/* ------------------------------------------------------------------ */
/* Externs the firewall calls — provided as test stubs in the runner.   */
/* ------------------------------------------------------------------ */

void *mem_acquire(void **mem_head);
extern struct mem_conn_tx_ctrl_t { void *free; } mem_conn_tx_ctrl;

struct bt_l2cap_chan *bt_l2cap_le_lookup_rx_cid(struct bt_conn *conn,
						u16_t cid);
u8_t  get_encryption_key_size(struct bt_smp *smp);
int   bt_addr_le_cmp(const struct bt_addr_le *a, const struct bt_addr_le *b);
struct bt_keys *bt_keys_find_addr(u8_t id, const struct bt_addr_le *addr);

/* MPU disable used by JIT path — never invoked because we run JIT off. */
static inline void arm_core_mpu_disable(void) { }

#endif /* ZEPHYR_MOCKS_H_ */
