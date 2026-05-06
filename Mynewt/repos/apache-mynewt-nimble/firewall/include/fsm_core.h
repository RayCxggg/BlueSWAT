#ifndef FSM_MONITOR_H_
#define FSM_MONITOR_H_

#include <stdint.h>

/* firewall macro */
#define IFW_OPERATION_PASS 0
#define IFW_OPERATION_REJECT 1

#define IFW_UPDATE_SUCCESS 2
#define IFW_UPDATE_ERROR 3

/* BlueSWAT FSM state */
typedef enum
{
    IFW_BLE_LL_CONNECTION_STATE = 0,
    IFW_BLE_LL_STANDBY_STATE,
    IFW_BLE_LL_ADVERTISING_STATE,
    IFW_BLE_LL_SCANNING_STATE,
    IFW_BLE_LL_INITIATING_STATE,
    IFW_BLE_LL_SYNCHRONIZATION_STATE,
    IFW_BLE_LL_ISOCHRONOUS_BROADCASTING_STATE,

    /* end */
    IFW_BLE_LL_STATE_NUM,
} IFW_FSM_LL_STATE;

/* pairing mode actually used */
typedef enum
{
    IFW_BLE_SSP = 0,
    IFW_BLE_SC,

    /* end */
    IFW_BLE_PAIRING_MODE_NUM,
} IFW_FSM_PAIRING_MODE;

typedef enum
{
    IFW_BLE_JUST_WORKS = 0,
    IFW_BLE_OOB,
    IFW_BLE_NUMERIC_COMPAIRISON,
    IFW_BLE_PASSKEY_ENTRY,

    /* end */
    IFW_BLE_PAIRING_METHOD_NUM,
} IFW_FSM_PAIRING_METHOD;

typedef enum
{
    IFW_BLE_ROLE_OBSERVER = 0,
    IFW_BLE_ROLE_BROADCASTER,
    IFW_BLE_ROLE_CENTRAL,
    IFW_BLE_ROLE_PERIPHERAL,
    IFW_BLE_ROLE_INITIATOR,
    IFW_BLE_ROLE_SCANNER,
    IFW_BLE_ROLE_ADVERTISER,

    /* end */
    IFW_BLE_ROLE_NUM,
} IFW_FSM_BLE_ROLE;

typedef enum
{
    DISPLAY_ONLY = 0,
    DISPLAY_YESNO,
    KEYBOARD_ONLY,
    NOINPUT_NOOUTPUT,
    KEYBOARD_DISPLAY,
    RESERVED,

    /* end */
    IFW_IO_CAPACITY_NUM,
} IFW_IO_CAPACITY;

/* FSM core state index */
enum ifw_core_state_type
{
    LL_STATE = 0,
    PAIRING_MODE,
    PAIRING_METHOD,
    BLE_ROLE,
    IO_CAPACITY,

    /* end */
    IFW_CORE_STATE_NUM,
};

/* FSM shared state index — layout matches Zephyr port so that compiled
 * eBPF bytecodes (which reference fixed struct offsets) are portable.
 * BD_ADDR occupies a single int slot (was 6 bytes in the legacy Mynewt
 * port); the LL parser now folds the address into a single 32-bit hash. */
typedef enum
{
    BD_ADDR = 0,
    BONDING,
    SC,

    /* end */
    IFW_SHARED_STATE_NUM,
} IFW_SHARED_STATE;

/* FSM conn parameters */
typedef enum
{
    CHANNEL_MAP = 0,
    CHANNEL_HOP,
    SCAN_RSP_LEN,
    LLL_INTERVAL,

    /* Mynewt-specific TX bookkeeping (slots used by fsm_tx_parser only,
     * not referenced by any ported Zephyr bytecode). Keep AFTER the
     * Zephyr-aligned slots so existing bytecode offsets stay valid. */
    TX_OPCODE,
    TX_IS_CTRL,

    /* end */
    IFW_CONN_PARAM_NUM,
} IFW_CONN_PARAM;

/* FSM Data Connection parameters */
typedef enum
{
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

    /* Per-policy parameter consumed by dc_nesn (CVE-2020-10060/10061).
     * 1 = anchor PDU pending after a fresh CONNECT_IND, 0 otherwise. */
    DC_ANCHOR_STATE,

    /* Mynewt-specific compat slots used by the legacy SMP parser. */
    SMP_MAX_ENC_SIZE,
    SMP_MAX_ENC_SIZE_PREV,

    /* end */
    IFW_DC_PARAM_NUM,
} IFW_DC_PARAM;

/* FSM param of SPI and BLE */
typedef enum
{
    HCI_EVT_LEN = 0,
    HCI_ACL_LEN,

    /* end */
    IFW_SPI_PARAM_NUM,
} IFW_SPI_PARAM;

/* FSM param of HCI core */
typedef enum
{
    HCI_CMD_BUF = 0,

    /* end */
    IFW_HCI_PARAM_NUM,
} IFW_HCI_PARAM;

enum ifw_state_class
{
    SHARED = 0,
    CORE,
    CONN,
    DC,
    SPI,
    HCI,

    /* end */
    IFW_STATE_CLASS_NUM,
};

/* FSM — int slots so the struct layout matches the Zephyr port byte for
 * byte (modulo IFW_*_NUM tail extensions). The compiled eBPF bytecodes
 * load 4-byte words at these offsets; switching from uint8_t (legacy)
 * to int is what makes the ported bytecodes correct. */
struct FsmState
{
    int core_state[IFW_CORE_STATE_NUM];
    int shared_state[IFW_SHARED_STATE_NUM];
    int conn_param[IFW_CONN_PARAM_NUM];
    int dc_param[IFW_DC_PARAM_NUM];

    int spi_param[IFW_SPI_PARAM_NUM];
    int hci_param[IFW_HCI_PARAM_NUM];
};

/* firewall trace hooks */
uint8_t ifw_fsm_check_update(uint16_t state, uint16_t type, uint16_t class);
uint8_t ifw_run_verifier(uint16_t type, uint16_t class);
void ifw_fsm_state_update(uint16_t state, uint16_t type, uint16_t class);

#define IFW_FSM_CHECK_UPDATE(state, type, class) \
    (ifw_fsm_check_update(state, type, class) == IFW_OPERATION_REJECT)

#define IFW_RUN_VERIFIER(type, class) \
    (ifw_run_verifier(type, class) == IFW_OPERATION_REJECT)

#define IFW_FSM_STATE_UPDATE(state, type, class) \
    ifw_fsm_state_update(state, type, class)

#endif /* FSM_MONITOR_H_ */
