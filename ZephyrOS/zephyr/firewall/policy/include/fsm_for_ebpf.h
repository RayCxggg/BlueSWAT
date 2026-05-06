#ifndef FSM_MONITOR_H_
#define FSM_MONITOR_H_

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

#define uptr uint32_t
#define u8_t uint8_t
#define u16_t uint16_t
#define u32_t uint32_t

typedef enum {
	IFW_BLE_LL_CONNECTION_STATE = 0,
	IFW_BLE_LL_STANDBY_STATE,
	IFW_BLE_LL_ADVERTISING_STATE,
	IFW_BLE_LL_SCANNING_STATE,
	IFW_BLE_LL_INITIATING_STATE,
	IFW_BLE_LL_SYNCHRONIZATION_STATE,
	IFW_BLE_LL_ISOCHRONOUS_BROADCASTING_STATE,

	// end
	IFW_BLE_LL_STATE_NUM,
} IFW_FSM_LL_STATE;

// pairing mode actually used
typedef enum {
	IFW_BLE_SSP = 0,
	IFW_BLE_SC,

	// end
	IFW_BLE_PAIRING_MODE_NUM,
} IFW_FSM_PAIRING_MODE;

typedef enum {
	IFW_BLE_JUST_WORKS = 0,
	IFW_BLE_OOB,
	IFW_BLE_NUMERIC_COMPAIRISON,
	IFW_BLE_PASSKEY_ENTRY,

	//end
	IFW_BLE_PAIRING_METHOD_NUM,
} IFW_FSM_PAIRING_METHOD;

typedef enum {
	IFW_BLE_ROLE_OBSERVER = 0,
	IFW_BLE_ROLE_BROADCASTER,
	IFW_BLE_ROLE_CENTRAL,
	IFW_BLE_ROLE_PERIPHERAL,
	IFW_BLE_ROLE_INITIATOR,
	IFW_BLE_ROLE_SCANNER,
	IFW_BLE_ROLE_ADVERTISER,

	// end
	IFW_BLE_ROLE_NUM,
} IFW_FSM_BLE_ROLE;

typedef enum {
	DISPLAY_ONLY = 0,
	DISPLAY_YESNO,
	KEYBOARD_ONLY,
	NOINPUT_NOOUTPUT,
	KEYBOARD_DISPLAY,
	RESERVED,

	// end
	IFW_IO_CAPACITY_NUM,
} IFW_IO_CAPACITY;

// FSM core state index
enum ifw_core_state_type {
	LL_STATE = 0,
	PAIRING_MODE,
	PAIRING_METHOD,
	BLE_ROLE,
	IO_CAPACITY,

	// end
	IFW_CORE_STATE_NUM,
};

// FSM shared state index
typedef enum {
	BD_ADDR = 0,
	BONDING,

	// whether peer supports SC
	SC,

	// end
	IFW_SHARED_STATE_NUM,
} IFW_SHARED_STATE;

// FSM conn parameters
typedef enum {
	CHANNEL_MAP = 0,
	CHANNEL_HOP,

	SCAN_RSP_LEN,
	LLL_INTERVAL,

	// end
	IFW_CONN_PARAM_NUM,
} IFW_CONN_PARAM;

// FSM Data Connection parameters
typedef enum {
	SN = 0,
	NESN,

	LLCP_LEN_REQ,
	LLCP_LEN_ACK,
	LLCP_LEN_RSP_TX,
	LLCP_LEN_STATE,

	LLCP_CONN_PARAM_REQ,
	LLCP_CONN_PARAM_ACK,
	LLCP_CONN_PARAM_STATE,

	SMP_ENC_SIZE_PREV,
	SMP_METHOD_PREV,
	SMP_KEYS,
	SMP_ENC_SIZE,
	SMP_KEYS_FLAGS,

	// end
	IFW_DC_PARAM_NUM,
} IFW_DC_PARAM;

// FSM para of SPI and BLE
typedef enum {
	HCI_EVT_LEN = 0,
	HCI_ACL_LEN,

	// end
	IFW_SPI_PARAM_NUM,
} IFW_SPI_PARAM;

// FSM param of HCI core (mirrors fsm_core.h on the kernel side so that the
// FsmState struct below has every field defined). Without this the .ebpf.c
// programs fail to compile with clang -target bpf.
typedef enum {
	HCI_CMD_BUF = 0,

	// end
	IFW_HCI_PARAM_NUM,
} IFW_HCI_PARAM;

enum ifw_state_class {
	SHARED = 0,
	CORE,
	CONN,
	DC,
	SPI,

	// end
	IFW_STATE_CLASS_NUM,
};

// FSM
struct FsmState {
	int core_state[IFW_CORE_STATE_NUM];
	int shared_state[IFW_SHARED_STATE_NUM];
	int conn_param[IFW_CONN_PARAM_NUM];
	int dc_param[IFW_DC_PARAM_NUM];

	int spi_param[IFW_STATE_CLASS_NUM];
	int hci_param[IFW_HCI_PARAM_NUM];
};

// firewall macro
#define IFW_OPERATION_PASS 0
#define IFW_OPERATION_REJECT 1

#define IFW_UPDATE_SUCCESS 0
#define IFW_UPDATE_ERROR 1

#endif // FSM_MONITOR_H_