#ifndef FSM_POLICY_H
#define FSM_POLICY_H

#include <stdint.h>
#include <stdbool.h>
#include "fsm_core.h"

// #define POLICY_ID(name) PID_##name

enum fsm_policy_tag {
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

	/* L2CAP host hook (paper-adjacent extra coverage, no LL hook). */
	PID_smp_ident_check,

	/* SPI HCI policies (CVE-2020-10065) require a split-SoC build with
	 * an SPI HCI driver.  The nRF52840 single-chip target the artifact
	 * ships for has no SPI HCI path, so these are not registered.
	 *
	 *   PID_spi_acl_len,
	 *   PID_spi_evt_len,
	 */

	// FSM policy num
	PID_NUM,
};

// list to store FSM policy
struct fsm_policy_list {
	struct fsm_policy_list *policy_next;
	int index; // ebpf policy index, eg. PID_conn_chan_map
};

// FSM policy cache
// NOTE: second index of policy should be
// max{IFW_CORE_STATE_NUM, IFW_SHARED_STATE_NUM, IFW_CONN_PARAM_NUM, IFW_DC_PARAM_NUM}
struct fsm_policy_manager {
	struct fsm_policy_list *policy[IFW_STATE_CLASS_NUM][IFW_DC_PARAM_NUM];
};

// policy attributes
struct policy_cache {
	int size;
	uint8_t *code;

	// whether to use JIT interpretation for eBPF code
	bool jit;
};

void load_all_policies();
void set_policy_jit_on(int pid);
void set_all_policy_jit_on();

int run_fsm_check_policy(int type, int class, void *newState);

#endif // FSM_POLICY_H