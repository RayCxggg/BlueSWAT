#ifndef FSM_POLICY_H
#define FSM_POLICY_H

#include <stdint.h>
#include <stdbool.h>
#include "fsm_core.h"

/* Policy ids — aligned with the Zephyr port. The legacy Mynewt-only
 * keysize_confusion / key_entropy_downgrade pids are kept at the tail
 * for backwards compatibility with the existing specification/ tree. */
enum fsm_policy_tag
{
    /* LL RX policies (CONNECT_IND inspection). */
    PID_conn_chan_map,        /* CVE-2020-10069 */
    PID_conn_chan_hop,        /* spec-compliance: hop in [5,16]   */
    PID_lll_interval,         /* CVE-2021-3432                    */

    /* LL RX policies (DC PDU inspection). */
    PID_dc_nesn,              /* CVE-2020-10060/10061             */
    PID_llcp_len_req,         /* CVE-2020-10068                   */
    PID_llcp_conn_param_req,  /* CVE-2021-3430                    */

    /* LL TX policy. */
    PID_scan_rsp_len,         /* CVE-2021-3581                    */

    /* SMP host hook. */
    PID_smp_ident_check,

    /* SPI HCI policies (CVE-2020-10065) — bytecodes carried in the
     * tree but unregistered on the single-chip nrf52840 target. */

    /* Legacy Mynewt-only policies retained for compatibility with the
     * pre-existing legacy SMP parser path. Not registered by default. */
    PID_keysize_confusion,
    PID_key_entropy_downgrade,

    /* FSM policy num */
    PID_NUM,
};

/* list to store FSM policy */
struct fsm_policy_list
{
    struct fsm_policy_list *policy_next;
    int index;
};

/* FSM policy cache.
 * Second index size = max{IFW_CORE_STATE_NUM, IFW_SHARED_STATE_NUM,
 *                         IFW_CONN_PARAM_NUM, IFW_DC_PARAM_NUM}. */
struct fsm_policy_manager
{
    struct fsm_policy_list *policy[IFW_STATE_CLASS_NUM][IFW_DC_PARAM_NUM];
};

/* policy attributes */
struct policy_cache
{
    int size;
    uint8_t *code;

    /* whether to use JIT interpretation for eBPF code */
    bool jit;
};

/* Maximum number of runtime-installed policies. Pids in
 * [PID_NUM, PID_NUM + IFW_MAX_RUNTIME_POLICIES) index into a separate
 * array so the compile-time policy_arr is left untouched. */
#define IFW_MAX_RUNTIME_POLICIES 8

void load_all_policies();
void set_policy_jit_on(int pid);
void set_all_policy_jit_on();

/* Install a new eBPF policy at runtime. The bytecode is structurally
 * verified, copied (caller may free its buffer immediately) and
 * registered for (class, type) so that the next IFW_RUN_VERIFIER on
 * that slot picks it up. Returns 0 on success, negative on failure. */
int ifw_install_policy(int class, int type,
                       const uint8_t *code, uint32_t len);

void register_policy(int class, int type, int pid);
void remove_policy(int class, int type, int pid);

int run_fsm_check_policy(int type, int class, void *newState);

#endif /* FSM_POLICY_H */
