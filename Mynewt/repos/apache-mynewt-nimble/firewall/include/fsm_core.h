#ifndef FSM_MONITOR_H_
#define FSM_MONITOR_H_

#include <stdint.h>

/* firewall macro */
#define IFW_OPERATION_PASS 0
#define IFW_OPERATION_REJECT 1

#define IFW_UPDATE_SUCCESS 2
#define IFW_UPDATE_ERROR 3

/* ---- Common core FSM (shared with the Zephyr port by design) ----
 *
 * Two BlueSWAT implementations exist (Zephyr / NimBLE) because the BLE
 * stacks are different: hooks live at different points in each stack
 * (both at the link layer) and the security policies they enforce
 * target stack-specific vulnerabilities. The *core* of the FSM —
 * roles, link-layer states, IO capabilities, pairing methods, state
 * classes — is the same on both ports. Per-stack divergence lives in
 * IFW_CONN_PARAM / IFW_DC_PARAM and the policy registry.
 */

typedef enum
{
    IFW_BLE_LL_CONNECTION_STATE = 0,
    IFW_BLE_LL_STANDBY_STATE,
    IFW_BLE_LL_ADVERTISING_STATE,
    IFW_BLE_LL_SCANNING_STATE,
    IFW_BLE_LL_INITIATING_STATE,
    IFW_BLE_LL_SYNCHRONIZATION_STATE,
    IFW_BLE_LL_ISOCHRONOUS_BROADCASTING_STATE,

    IFW_BLE_LL_STATE_NUM,
} IFW_FSM_LL_STATE;

typedef enum
{
    IFW_BLE_SSP = 0,
    IFW_BLE_SC,

    IFW_BLE_PAIRING_MODE_NUM,
} IFW_FSM_PAIRING_MODE;

typedef enum
{
    IFW_BLE_JUST_WORKS = 0,
    IFW_BLE_OOB,
    IFW_BLE_NUMERIC_COMPAIRISON,
    IFW_BLE_PASSKEY_ENTRY,

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

    IFW_IO_CAPACITY_NUM,
} IFW_IO_CAPACITY;

enum ifw_core_state_type
{
    LL_STATE = 0,
    PAIRING_MODE,
    PAIRING_METHOD,
    BLE_ROLE,
    IO_CAPACITY,

    IFW_CORE_STATE_NUM,
};

/* ---- Mynewt/NimBLE-specific shared / conn / dc parameters ----
 *
 * The slot layout below is the Mynewt-side design. It deliberately
 * differs from the Zephyr port (which has its own DC_PARAM + SHARED
 * layout for Zephyr-controller-specific CVEs) — see the BlueSWAT paper
 * and ZephyrOS/zephyr/firewall/include/fsm_core.h. */

typedef enum
{
    /* Mynewt stores the 6-byte peer address as 6 consecutive shared-
     * state slots so per-byte rules can be expressed cleanly. */
    BD_ADDR = 0,
    BONDING = 6,
    SC,

    IFW_SHARED_STATE_NUM,
} IFW_SHARED_STATE;

typedef enum
{
    CHANNEL_MAP = 0,
    CHANNEL_HOP,
    SCAN_RSP_LEN,
    LLL_INTERVAL,
    TX_OPCODE,
    TX_IS_CTRL,

    IFW_CONN_PARAM_NUM,
} IFW_CONN_PARAM;

typedef enum
{
    SN = 0,
    NESN,

    SMP_MAX_ENC_SIZE,
    SMP_MAX_ENC_SIZE_PREV,

    IFW_DC_PARAM_NUM,
} IFW_DC_PARAM;

typedef enum
{
    HCI_EVT_LEN = 0,
    HCI_ACL_LEN,

    IFW_SPI_PARAM_NUM,
} IFW_SPI_PARAM;

typedef enum
{
    HCI_CMD_BUF = 0,

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

    IFW_STATE_CLASS_NUM,
};

/* FSM state — int slots so eBPF LDXW (4-byte word loads) addresses
 * the struct correctly. The eBPF VM in `firewall/libebpf/` operates
 * on this layout; bytecodes for the Mynewt port should be regenerated
 * via firewall/policy/compile.sh against this struct. */
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
