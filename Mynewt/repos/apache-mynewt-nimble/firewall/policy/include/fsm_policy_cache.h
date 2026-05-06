#ifndef FSM_POLICY_H
#define FSM_POLICY_H

#include <stdint.h>
#include <stdbool.h>
#include "fsm_core.h"

/* Mynewt/NimBLE policy ids.
 *
 * BlueSWAT ships as two separate per-stack ports because the BLE
 * stacks differ: vulnerabilities are stack-specific, hooks attach at
 * different code points (both at the link layer), and each port
 * carries its own policy set. The Zephyr port's policy set lives in
 * ZephyrOS/zephyr/firewall/policy/include/fsm_policy_cache.h and is
 * intentionally independent of this list. */
enum fsm_policy_tag
{
    PID_conn_chan_map,
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
 * runtime array so the compile-time policy_arr is left untouched. */
#define IFW_MAX_RUNTIME_POLICIES 8

void load_all_policies(void);
void set_policy_jit_on(int pid);
void set_all_policy_jit_on(void);

/* Install a new eBPF policy at runtime. The bytecode is structurally
 * verified, copied (caller may free its buffer immediately) and
 * registered for (class, type) so that the next IFW_RUN_VERIFIER on
 * that slot picks it up. Returns 0 on success, negative on failure.
 *
 * This is the stack-agnostic "transmit eBPF programs to victims via
 * BLE" capability — it is shared in design with the Zephyr port but
 * lives in this Mynewt-only translation unit. */
int ifw_install_policy(int class, int type,
                       const uint8_t *code, uint32_t len);

void register_policy(int class, int type, int pid);
void remove_policy(int class, int type, int pid);

int run_fsm_check_policy(int type, int class, void *newState);

#endif /* FSM_POLICY_H */
