/*
 * Host-side test harness for BlueSWAT eBPF policies.
 *
 * Loads each prebuilt policy bytecode shipped under
 * firewall/policy/ebpf_bytecode/ and runs it inside the same uBPF-style
 * interpreter that the firmware uses (firewall/libebpf/ebpf-src/ebpf_vm.c),
 * with a synthetic FsmState as the input "packet/state" memory.
 *
 * For every policy we run one benign and one malicious case; PASS = the
 * policy returns the verdict we expected.
 *
 * Build: make -C firewall/tests
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "ebpf.h"
#include "ebpf_vm.h"

/* FsmState layout matches firewall/include/fsm_core.h (the kernel side).
 * The .ebpf.c programs were compiled against firewall/policy/include/
 * fsm_for_ebpf.h, but the byte offsets for everything up to and including
 * spi_param[] coincide, which is all the policies dereference. */
#define IFW_CORE_STATE_NUM   5
#define IFW_SHARED_STATE_NUM 3
#define IFW_CONN_PARAM_NUM   4
#define IFW_DC_PARAM_NUM     15
#define IFW_SPI_PARAM_NUM    2

/* core_state index */
enum { LL_STATE = 0, PAIRING_MODE, PAIRING_METHOD, BLE_ROLE, IO_CAPACITY };
/* shared_state index */
enum { BD_ADDR = 0, BONDING, SC };
/* conn_param index */
enum { CHANNEL_MAP = 0, CHANNEL_HOP, SCAN_RSP_LEN, LLL_INTERVAL };
/* dc_param index */
enum {
	SN = 0, NESN,
	LLCP_LEN_REQ, LLCP_LEN_ACK, LLCP_LEN_RSP_TX, LLCP_LEN_STATE,
	LLCP_CONN_PARAM_REQ, LLCP_CONN_PARAM_ACK, LLCP_CONN_PARAM_STATE,
	SMP_ENC_SIZE_PREV, SMP_METHOD_PREV, SMP_KEYS, SMP_ENC_SIZE,
	SMP_KEYS_FLAGS,
	DC_ANCHOR_STATE,
};
/* spi_param index */
enum { HCI_EVT_LEN = 0, HCI_ACL_LEN };

struct FsmState {
	int core_state[IFW_CORE_STATE_NUM];
	int shared_state[IFW_SHARED_STATE_NUM];
	int conn_param[IFW_CONN_PARAM_NUM];
	int dc_param[IFW_DC_PARAM_NUM];
	int spi_param[IFW_SPI_PARAM_NUM];
	int hci_param[1];
};

#define IFW_OPERATION_PASS   0
#define IFW_OPERATION_REJECT 1

/* --- bytecode (pulled in directly from the shipped headers) --- */
#include "../policy/ebpf_bytecode/conn_chan_map.h"
#include "../policy/ebpf_bytecode/conn_chan_hop.h"
#include "../policy/ebpf_bytecode/dc_nesn.h"
#include "../policy/ebpf_bytecode/spi_acl_len.h"
#include "../policy/ebpf_bytecode/spi_evt_len.h"
#include "../policy/ebpf_bytecode/scan_rsp_len.h"
#include "../policy/ebpf_bytecode/llcp_len_req.h"
#include "../policy/ebpf_bytecode/llcp_conn_param_req.h"
#include "../policy/ebpf_bytecode/lll_interval.h"
#include "../policy/ebpf_bytecode/smp_ident_check.h"

/* run one policy and report */
static int run_policy(const char *policy_name,
		      const unsigned char *code, size_t code_len,
		      const char *case_name,
		      const struct FsmState *st,
		      uint64_t expected)
{
	struct ebpf_vm *vm = ebpf_create();
	ebpf_vm_set_inst(vm, code, (uint32_t)code_len);

	uint64_t r = ebpf_vm_exec(vm, (void *)st, sizeof(*st));
	bool ok = (r == expected);

	printf("  [%s] %-22s -> verdict=%llu expected=%llu  %s\n",
	       ok ? "PASS" : "FAIL",
	       case_name,
	       (unsigned long long)r,
	       (unsigned long long)expected,
	       policy_name);

	ebpf_vm_destroy(vm);
	return ok ? 0 : 1;
}

/* shipped headers include a trailing string-literal NUL that sizeof() counts.
 * The interpreter rounds num_insts down to a whole 8-byte instruction, so the
 * extra byte is dropped — but pass the raw sizeof to mirror the firmware. */
#define POLICY_RUN(name, case_name, st_ptr, expected) \
	failures += run_policy(#name, (name), sizeof(name), \
			       (case_name), (st_ptr), (expected))

int main(void)
{
	int failures = 0;

	struct FsmState s;

	/* ----- conn_chan_map (CVE-2020-10069) -----
	 * Policy: reject if conn_param[CHANNEL_MAP] < 2 (too few enabled channels). */
	puts("conn_chan_map (CVE-2020-10069 — Invalid Channel Map)");
	memset(&s, 0, sizeof(s));
	s.conn_param[CHANNEL_MAP] = 37;
	POLICY_RUN(conn_chan_map, "benign: 37 channels", &s, IFW_OPERATION_PASS);
	memset(&s, 0, sizeof(s));
	s.conn_param[CHANNEL_MAP] = 1;
	POLICY_RUN(conn_chan_map, "malicious: 1 channel", &s, IFW_OPERATION_REJECT);

	/* ----- conn_chan_hop -----
	 * Policy: reject if hop < 5 || hop > 16 (BLE spec mandates 5..16). */
	puts("conn_chan_hop");
	memset(&s, 0, sizeof(s));
	s.conn_param[CHANNEL_HOP] = 7;
	POLICY_RUN(conn_chan_hop, "benign: hop=7", &s, IFW_OPERATION_PASS);
	memset(&s, 0, sizeof(s));
	s.conn_param[CHANNEL_HOP] = 4;
	POLICY_RUN(conn_chan_hop, "malicious: hop=4", &s, IFW_OPERATION_REJECT);
	memset(&s, 0, sizeof(s));
	s.conn_param[CHANNEL_HOP] = 17;
	POLICY_RUN(conn_chan_hop, "malicious: hop=17", &s, IFW_OPERATION_REJECT);

	/* ----- dc_nesn (CVE-2020-10061) -----
	 * Policy: reject only when DC_ANCHOR_STATE==1 (anchor pending) AND
	 * NESN==1 && SN==1.  Post-anchor (DC_ANCHOR_STATE==0) the same byte
	 * pattern is legitimate retransmission. */
	puts("dc_nesn (CVE-2020-10060/10061)");
	memset(&s, 0, sizeof(s));
	s.dc_param[DC_ANCHOR_STATE] = 1;
	s.dc_param[NESN] = 0; s.dc_param[SN] = 1;
	POLICY_RUN(dc_nesn, "benign: anchor+NESN=0 SN=1", &s, IFW_OPERATION_PASS);
	memset(&s, 0, sizeof(s));
	s.dc_param[DC_ANCHOR_STATE] = 1;
	s.dc_param[NESN] = 1; s.dc_param[SN] = 1;
	POLICY_RUN(dc_nesn, "malicious: anchor+NESN=1 SN=1",
		   &s, IFW_OPERATION_REJECT);
	memset(&s, 0, sizeof(s));
	s.dc_param[DC_ANCHOR_STATE] = 0; /* post-anchor */
	s.dc_param[NESN] = 1; s.dc_param[SN] = 1;
	POLICY_RUN(dc_nesn, "benign: post-anchor NESN=1 SN=1 (legit retransmit)",
		   &s, IFW_OPERATION_PASS);

	/* ----- spi_acl_len (CVE-2020-10065 ACL) -----
	 * Policy: reject if spi_param[HCI_ACL_LEN] > 76 (overflows BT_BUF_RX_SIZE). */
	puts("spi_acl_len (CVE-2020-10065 ACL)");
	memset(&s, 0, sizeof(s));
	s.spi_param[HCI_ACL_LEN] = 60;
	POLICY_RUN(spi_acl_len, "benign: 60 bytes", &s, IFW_OPERATION_PASS);
	memset(&s, 0, sizeof(s));
	s.spi_param[HCI_ACL_LEN] = 200;
	POLICY_RUN(spi_acl_len, "malicious: 200 bytes", &s, IFW_OPERATION_REJECT);

	/* ----- spi_evt_len (CVE-2020-10065 EVT) ----- */
	puts("spi_evt_len (CVE-2020-10065 EVT)");
	memset(&s, 0, sizeof(s));
	s.spi_param[HCI_EVT_LEN] = 60;
	POLICY_RUN(spi_evt_len, "benign: 60 bytes", &s, IFW_OPERATION_PASS);
	memset(&s, 0, sizeof(s));
	s.spi_param[HCI_EVT_LEN] = 200;
	POLICY_RUN(spi_evt_len, "malicious: 200 bytes", &s, IFW_OPERATION_REJECT);

	/* ----- scan_rsp_len (CVE-2021-3581) -----
	 * Policy: reject if SCAN_RSP_LEN > 80 (PDU_AC_SIZE_MAX). */
	puts("scan_rsp_len (CVE-2021-3581)");
	memset(&s, 0, sizeof(s));
	s.conn_param[SCAN_RSP_LEN] = 31;
	POLICY_RUN(scan_rsp_len, "benign: 31 bytes", &s, IFW_OPERATION_PASS);
	memset(&s, 0, sizeof(s));
	s.conn_param[SCAN_RSP_LEN] = 200;
	POLICY_RUN(scan_rsp_len, "malicious: 200 bytes", &s, IFW_OPERATION_REJECT);

	/* ----- lll_interval (CVE-2021-3432) -----
	 * Policy: reject if !conn_param[LLL_INTERVAL] (0 means invalid). */
	puts("lll_interval (CVE-2021-3432)");
	memset(&s, 0, sizeof(s));
	s.conn_param[LLL_INTERVAL] = 24;
	POLICY_RUN(lll_interval, "benign: interval=24", &s, IFW_OPERATION_PASS);
	memset(&s, 0, sizeof(s));
	s.conn_param[LLL_INTERVAL] = 0;
	POLICY_RUN(lll_interval, "malicious: interval=0", &s, IFW_OPERATION_REJECT);

	/* ----- llcp_len_req (CVE-2020-10068) -----
	 * Policy: reject when more than one LL_LENGTH_REQ is in flight.
	 * The LL RX hook tracks the in-flight count in dc_param[LLCP_LEN_REQ]. */
	puts("llcp_len_req (CVE-2020-10068)");
	memset(&s, 0, sizeof(s));
	s.dc_param[LLCP_LEN_REQ] = 1;
	POLICY_RUN(llcp_len_req, "benign: 1 in-flight req", &s, IFW_OPERATION_PASS);
	memset(&s, 0, sizeof(s));
	s.dc_param[LLCP_LEN_REQ] = 2;
	POLICY_RUN(llcp_len_req, "malicious: 2 in-flight reqs (duplicate)",
		   &s, IFW_OPERATION_REJECT);

	/* ----- llcp_conn_param_req (CVE-2021-3430) -----
	 * Same shape: reject when more than one LL_CONNECTION_PARAM_REQ is
	 * in flight. */
	puts("llcp_conn_param_req (CVE-2021-3430)");
	memset(&s, 0, sizeof(s));
	s.dc_param[LLCP_CONN_PARAM_REQ] = 1;
	POLICY_RUN(llcp_conn_param_req, "benign: 1 in-flight CPR",
		   &s, IFW_OPERATION_PASS);
	memset(&s, 0, sizeof(s));
	s.dc_param[LLCP_CONN_PARAM_REQ] = 2;
	POLICY_RUN(llcp_conn_param_req, "malicious: 2 in-flight CPRs (duplicate)",
		   &s, IFW_OPERATION_REJECT);

	/* ----- smp_ident_check -----
	 * BT_KEYS_LTK_P256=32, BT_KEYS_LTK=4, BT_KEYS_AUTHENTICATED=1
	 * Pass if no LTK bits set, OR if upgrade-not-downgrade.
	 * Reject if enc_size > prev_enc_size, or authenticated && prev was JustWorks. */
	puts("smp_ident_check");
	/* No LTK bits → policy returns PASS early */
	memset(&s, 0, sizeof(s));
	s.dc_param[SMP_KEYS] = 0;
	POLICY_RUN(smp_ident_check, "benign: no LTK bits", &s, IFW_OPERATION_PASS);
	/* LTK present, enc_size shrinks → PASS (no downgrade) */
	memset(&s, 0, sizeof(s));
	s.dc_param[SMP_KEYS] = 4; /* LTK */
	s.dc_param[SMP_ENC_SIZE_PREV] = 16;
	s.dc_param[SMP_ENC_SIZE]      = 16;
	s.dc_param[SMP_KEYS_FLAGS]    = 0;
	s.dc_param[SMP_METHOD_PREV]   = 0; /* JustWorks but not authenticated */
	POLICY_RUN(smp_ident_check, "benign: same enc_size",
		   &s, IFW_OPERATION_PASS);
	/* Reject path 1: enc_size grows (downgrade attack) */
	memset(&s, 0, sizeof(s));
	s.dc_param[SMP_KEYS] = 4;
	s.dc_param[SMP_ENC_SIZE_PREV] = 7;
	s.dc_param[SMP_ENC_SIZE]      = 16;
	POLICY_RUN(smp_ident_check, "malicious: enc_size grew",
		   &s, IFW_OPERATION_REJECT);
	/* Reject path 2: authenticated && previous method was JustWorks */
	memset(&s, 0, sizeof(s));
	s.dc_param[SMP_KEYS] = 4;
	s.dc_param[SMP_ENC_SIZE_PREV] = 16;
	s.dc_param[SMP_ENC_SIZE]      = 16;
	s.dc_param[SMP_KEYS_FLAGS]    = 1; /* AUTHENTICATED */
	s.dc_param[SMP_METHOD_PREV]   = 0; /* JUST_WORKS */
	POLICY_RUN(smp_ident_check, "malicious: auth-on-JW bond",
		   &s, IFW_OPERATION_REJECT);

	puts("");
	if (failures == 0) {
		puts("ALL POLICY TESTS PASSED");
	} else {
		printf("%d POLICY TEST(S) FAILED\n", failures);
	}
	return failures ? 1 : 0;
}
