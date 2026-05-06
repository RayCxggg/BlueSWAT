/*
 * BlueSWAT Zephyr-stack integration test.
 *
 * Compiles firewall/core/*.c and firewall/policy/src/*.c natively (against
 * zephyr_mocks.h) and drives synthetic CVE attack packets through the
 * actual hook functions (ifw_ll_packet_parser_rx / ifw_ll_packet_parser_tx).
 * Asserts that each malicious packet is rejected (IFW_OPERATION_REJECT) and
 * that benign packets pass.
 *
 * This is the "do they actually mitigate the CVE in the Zephyr stack" test
 * — it exercises FSM update + policy lookup + eBPF execution + the hook
 * dispatch logic, end-to-end, with no Zephyr SDK or hardware required.
 */

#include "zephyr_mocks.h"
#include "fsm_handle.h"
#include "fsm_core.h"
#include "include/fsm_policy_cache.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* ----- Stubs the firewall calls ----- */
struct mem_conn_tx_ctrl_t mem_conn_tx_ctrl;
static struct node_tx fake_tx_node;

/* JIT path is unused in this harness (we always pass jit=false). */
struct ebpf_vm;
void gen_jit_code(struct ebpf_vm *vm) { (void)vm; }
void *mem_acquire(void **mem_head)
{
	/* return non-null so the LLCP_LEN_REQ branch in ifw_ctrl_rx proceeds */
	return &fake_tx_node;
}

static struct bt_l2cap_chan g_fake_chan;
struct bt_l2cap_chan *bt_l2cap_le_lookup_rx_cid(struct bt_conn *conn, u16_t cid)
{
	return &g_fake_chan;
}
u8_t get_encryption_key_size(struct bt_smp *smp) { return 16; }
int bt_addr_le_cmp(const struct bt_addr_le *a, const struct bt_addr_le *b)
{
	return memcmp(a, b, sizeof(*a));
}
struct bt_keys g_fake_keys;
struct bt_keys *bt_keys_find_addr(u8_t id, const struct bt_addr_le *addr)
{
	return &g_fake_keys;
}

/* ----- Helpers to build synthetic packets ----- */

/* The firewall fishes lll_conn out of ftr->param via:
 *   lll = *((struct lll_conn **)((u8_t *)ftr->param + sizeof(struct lll_hdr)));
 * so we set ftr->param to a buffer with [lll_hdr | lll_conn*]. */
struct fake_param_layout {
	struct lll_hdr hdr;
	struct lll_conn *lll;
};

static struct lll_conn g_lll;
static struct fake_param_layout g_param_layout;
static u8_t g_rx_buf[sizeof(struct node_rx_hdr) + sizeof(struct pdu_adv) + 32];
static u8_t g_dc_buf[sizeof(struct node_rx_hdr) + sizeof(struct pdu_data) + 32];

static struct node_rx_hdr *
build_connect_ind_rx(u8_t chan_map[5], u8_t hop, u16_t interval)
{
	memset(g_rx_buf, 0, sizeof(g_rx_buf));
	memset(&g_lll, 0, sizeof(g_lll));
	g_lll.role = 1; /* peripheral — only role the firewall covers */
	g_param_layout.lll = &g_lll;

	struct node_rx_hdr *rx = (struct node_rx_hdr *)g_rx_buf;
	rx->type = NODE_RX_TYPE_CONNECTION;
	rx->rx_ftr.param = &g_param_layout;

	struct pdu_adv *pdu = (struct pdu_adv *)((u8_t *)rx + sizeof(*rx));
	pdu->type = PDU_ADV_TYPE_CONNECT_IND;
	pdu->len = sizeof(struct pdu_adv_connect_ind);
	memcpy(pdu->connect_ind.chan_map, chan_map, 5);
	pdu->connect_ind.hop = hop;
	pdu->connect_ind.interval = interval;
	return rx;
}

static struct node_rx_hdr *
build_dc_pdu_rx(u8_t ll_id, u8_t nesn, u8_t sn, u8_t ctrl_opcode)
{
	memset(g_dc_buf, 0, sizeof(g_dc_buf));

	struct node_rx_hdr *rx = (struct node_rx_hdr *)g_dc_buf;
	rx->type = NODE_RX_TYPE_DC_PDU;

	struct pdu_data *pdu = (struct pdu_data *)((u8_t *)rx + sizeof(*rx));
	pdu->ll_id = ll_id;
	pdu->nesn = nesn;
	pdu->sn = sn;
	pdu->llctrl.opcode = ctrl_opcode;
	pdu->len = 1;
	return rx;
}

/* Build an LL_CHANNEL_MAP_IND CTRL PDU with a caller-supplied chan_map. */
static struct node_rx_hdr *
build_chan_map_ind_rx(u8_t chm[5])
{
	struct node_rx_hdr *rx = build_dc_pdu_rx(
		PDU_DATA_LLID_CTRL, 0, 0, PDU_DATA_LLCTRL_TYPE_CHAN_MAP_IND);
	struct pdu_data *pdu = (struct pdu_data *)((u8_t *)rx + sizeof(*rx));
	memcpy(pdu->llctrl.chan_map_ind.chm, chm, 5);
	return rx;
}

/* Build an LL_CONNECTION_UPDATE_IND CTRL PDU. */
static struct node_rx_hdr *
build_conn_update_ind_rx(u16_t interval)
{
	struct node_rx_hdr *rx = build_dc_pdu_rx(
		PDU_DATA_LLID_CTRL, 0, 0, PDU_DATA_LLCTRL_TYPE_CONN_UPDATE_IND);
	struct pdu_data *pdu = (struct pdu_data *)((u8_t *)rx + sizeof(*rx));
	pdu->llctrl.conn_update_ind.interval = interval;
	return rx;
}

/* Build a benign DC PDU (LLID_DATA_START) — not a CTRL PDU. */
static struct node_rx_hdr *build_data_pdu_rx(u8_t nesn, u8_t sn)
{
	return build_dc_pdu_rx(PDU_DATA_LLID_DATA_START, nesn, sn, 0);
}

/* ----- Test driver ----- */

static int failures;
static int total;

#define ASSERT_VERDICT(label, verdict, expected) do {                         \
	const char *_e = (expected) ? "REJECT" : "PASS";                      \
	const char *_g = (verdict) ? "REJECT" : "PASS";                       \
	bool _ok = ((bool)(verdict)) == ((bool)(expected));                   \
	total++;                                                              \
	if (!_ok) failures++;                                                 \
	printf("  [%s] %-55s expected=%s got=%s\n",                           \
	       _ok ? "PASS" : "FAIL", (label), _e, _g);                       \
} while (0)

int main(void)
{
	puts("BlueSWAT Zephyr-stack integration tests");
	puts("=======================================");

	/* Initialize the FSM and load all policies, like the firmware does. */
	ifw_fsm_init();
	ifw_fsm_enable(false);

	/* ----- CVE-2020-10069: Invalid Channel Map (LL ADV RX) ----- */
	puts("\nCVE-2020-10069: Invalid Channel Map (CONNECT_IND, LL RX)");
	{
		u8_t good_map[5] = {0xff, 0xff, 0xff, 0xff, 0x1f}; /* 37 chans */
		struct node_rx_hdr *rx = build_connect_ind_rx(good_map, 7, 24);
		bool dropped = ifw_ll_packet_parser_rx(NULL, rx);
		ASSERT_VERDICT("benign: 37 channels, hop=7, interval=24",
			       dropped, false);
	}
	{
		u8_t bad_map[5] = {0x01, 0x00, 0x00, 0x00, 0x00}; /* 1 chan */
		struct node_rx_hdr *rx = build_connect_ind_rx(bad_map, 7, 24);
		bool dropped = ifw_ll_packet_parser_rx(NULL, rx);
		ASSERT_VERDICT("malicious: 1 channel (Sweyntooth)",
			       dropped, true);
	}

	/* ----- conn_chan_hop policy (paired with above hook) ----- */
	puts("\nconn_chan_hop (CONNECT_IND, LL RX)");
	{
		u8_t map[5] = {0xff, 0xff, 0xff, 0xff, 0x1f};
		struct node_rx_hdr *rx = build_connect_ind_rx(map, 4, 24);
		bool dropped = ifw_ll_packet_parser_rx(NULL, rx);
		ASSERT_VERDICT("malicious: hop=4 (below spec minimum 5)",
			       dropped, true);
	}
	{
		u8_t map[5] = {0xff, 0xff, 0xff, 0xff, 0x1f};
		struct node_rx_hdr *rx = build_connect_ind_rx(map, 17, 24);
		bool dropped = ifw_ll_packet_parser_rx(NULL, rx);
		ASSERT_VERDICT("malicious: hop=17 (above spec maximum 16)",
			       dropped, true);
	}

	/* ----- CVE-2021-3432: Zero LL interval (CONNECT_IND, LL RX) ----- */
	puts("\nCVE-2021-3432: Zero LL interval (CONNECT_IND, LL RX)");
	{
		u8_t map[5] = {0xff, 0xff, 0xff, 0xff, 0x1f};
		struct node_rx_hdr *rx = build_connect_ind_rx(map, 7, 0);
		bool dropped = ifw_ll_packet_parser_rx(NULL, rx);
		ASSERT_VERDICT("malicious: interval=0", dropped, true);
	}

	/* ----- CVE-2020-10060/10061: anchor-point NESN/SN attack -----
	 *
	 * The dc_nesn policy reads core_state[LL_STATE] alongside NESN/SN.
	 * On CONNECT_IND the LL hook drives LL_STATE to CONNECTION_STATE;
	 * after a successful anchor verifier it transitions to STANDBY.  A
	 * post-anchor NESN=1/SN=1 pair therefore reads (LL_STATE=STANDBY,
	 * NESN=1, SN=1) and the policy returns PASS — no false positives on
	 * legitimate retransmits.
	 */
	u8_t good_map[5] = {0xff, 0xff, 0xff, 0xff, 0x1f};
	puts("\nCVE-2020-10060/10061: NESN/SN anchor attack (DC PDU, LL RX)");
	{
		/* Fresh connection, benign anchor → policy PASSes and the
		 * hook transitions LL_STATE from CONNECTION to STANDBY. */
		ifw_ll_packet_parser_rx(NULL, build_connect_ind_rx(good_map, 7, 24));
		bool dropped = ifw_ll_packet_parser_rx(NULL, build_data_pdu_rx(0, 0));
		ASSERT_VERDICT("benign: anchor PDU NESN=0 SN=0", dropped, false);
	}
	{
		/* Same connection (LL_STATE now == STANDBY).  NESN=1 SN=1 is
		 * normal retransmission traffic post-anchor. */
		bool dropped = ifw_ll_packet_parser_rx(NULL, build_data_pdu_rx(1, 1));
		ASSERT_VERDICT("benign: post-anchor NESN=1 SN=1 (legit retransmit)",
			       dropped, false);
	}
	{
		/* Fresh connection, malicious anchor — re-arms LL_STATE to
		 * CONNECTION_STATE so the policy fires again. */
		ifw_ll_packet_parser_rx(NULL, build_connect_ind_rx(good_map, 7, 24));
		bool dropped = ifw_ll_packet_parser_rx(NULL, build_data_pdu_rx(1, 1));
		ASSERT_VERDICT("malicious: anchor PDU NESN=1 SN=1", dropped, true);
	}
	{
		/* Reconnect after the rejection: another fresh CONNECT_IND
		 * re-arms the FSM regardless of where it was left. */
		ifw_ll_packet_parser_rx(NULL, build_connect_ind_rx(good_map, 7, 24));
		bool dropped = ifw_ll_packet_parser_rx(NULL, build_data_pdu_rx(1, 1));
		ASSERT_VERDICT("malicious: anchor of 2nd connection NESN=1 SN=1",
			       dropped, true);
	}

	/* ----- CVE-2021-3432 (post-connection): zero interval via LL_CONN_UPDATE_IND -----
	 *
	 * Same vulnerability as the CONNECT_IND check (zero interval crashes
	 * the LL scheduler) but reachable mid-session.  The same lll_interval
	 * policy now fires from the LL_CONN_UPDATE_IND case in ifw_ctrl_rx. */
	puts("\nCVE-2021-3432 (post-connection): zero interval via LL_CONN_UPDATE_IND");
	{
		ifw_ll_packet_parser_rx(NULL, build_connect_ind_rx(good_map, 7, 24));
		ifw_ll_packet_parser_rx(NULL, build_data_pdu_rx(0, 0));

		bool dropped = ifw_ll_packet_parser_rx(NULL,
			build_conn_update_ind_rx(40));
		ASSERT_VERDICT("benign: CONN_UPDATE_IND interval=40",
			       dropped, false);
	}
	{
		bool dropped = ifw_ll_packet_parser_rx(NULL,
			build_conn_update_ind_rx(0));
		ASSERT_VERDICT("malicious: CONN_UPDATE_IND interval=0",
			       dropped, true);
	}

	/* ----- CVE-2020-10069 (post-connection variant) -----
	 *
	 * The same channel-map vulnerability as the CONNECT_IND case can be
	 * triggered mid-session by an attacker who lets a benign CONNECT_IND
	 * through and then sends an LL_CHANNEL_MAP_IND with an all-zero map.
	 * Without a hook on CHAN_MAP_IND, only the CONNECT_IND-time check
	 * runs and the device crashes when the instant arrives. */
	puts("\nCVE-2020-10069 (post-connection): malicious LL_CHANNEL_MAP_IND");
	{
		ifw_ll_packet_parser_rx(NULL, build_connect_ind_rx(good_map, 7, 24));
		ifw_ll_packet_parser_rx(NULL, build_data_pdu_rx(0, 0));

		u8_t benign_update[5] = {0xff, 0xff, 0xff, 0xff, 0x1f};
		bool dropped = ifw_ll_packet_parser_rx(NULL,
			build_chan_map_ind_rx(benign_update));
		ASSERT_VERDICT("benign: CHAN_MAP_IND with full 37-channel map",
			       dropped, false);
	}
	{
		u8_t kill_map[5] = {0x00, 0x00, 0x00, 0x00, 0x00};
		bool dropped = ifw_ll_packet_parser_rx(NULL,
			build_chan_map_ind_rx(kill_map));
		ASSERT_VERDICT("malicious: CHAN_MAP_IND with all-zero map (div-by-zero)",
			       dropped, true);
	}
	{
		u8_t one_chan[5] = {0x01, 0x00, 0x00, 0x00, 0x00};
		bool dropped = ifw_ll_packet_parser_rx(NULL,
			build_chan_map_ind_rx(one_chan));
		ASSERT_VERDICT("malicious: CHAN_MAP_IND with 1-channel map",
			       dropped, true);
	}

	/* ----- CVE-2020-10068: duplicate LL_LENGTH_REQ ----- */
	puts("\nCVE-2020-10068: duplicate LL_LENGTH_REQ (LL CTRL RX)");
	{
		u8_t map[5] = {0xff, 0xff, 0xff, 0xff, 0x1f};
		ifw_ll_packet_parser_rx(NULL, build_connect_ind_rx(map, 7, 24));
		/* Skip past the anchor check with a benign anchor PDU. */
		ifw_ll_packet_parser_rx(NULL, build_data_pdu_rx(0, 0));

		struct node_rx_hdr *rx = build_dc_pdu_rx(
			PDU_DATA_LLID_CTRL, 0, 0,
			PDU_DATA_LLCTRL_TYPE_LENGTH_REQ);
		bool dropped = ifw_ll_packet_parser_rx(NULL, rx);
		ASSERT_VERDICT("benign: 1st LENGTH_REQ", dropped, false);
	}
	{
		struct node_rx_hdr *rx = build_dc_pdu_rx(
			PDU_DATA_LLID_CTRL, 0, 0,
			PDU_DATA_LLCTRL_TYPE_LENGTH_REQ);
		bool dropped = ifw_ll_packet_parser_rx(NULL, rx);
		ASSERT_VERDICT("malicious: 2nd LENGTH_REQ (no RSP yet)",
			       dropped, true);
	}
	{
		/* Now the response arrives — pending count drops back to 1
		 * (we'd already incremented past 2 above; the increment is
		 * non-reversible in the test).  Send a RSP, then a fresh REQ
		 * after another reconnect to confirm reset works. */
		u8_t map[5] = {0xff, 0xff, 0xff, 0xff, 0x1f};
		ifw_ll_packet_parser_rx(NULL, build_connect_ind_rx(map, 7, 24));
		ifw_ll_packet_parser_rx(NULL, build_data_pdu_rx(0, 0));

		struct node_rx_hdr *rx = build_dc_pdu_rx(
			PDU_DATA_LLID_CTRL, 0, 0,
			PDU_DATA_LLCTRL_TYPE_LENGTH_REQ);
		bool dropped = ifw_ll_packet_parser_rx(NULL, rx);
		ASSERT_VERDICT("benign: LENGTH_REQ after reconnect (counter reset)",
			       dropped, false);
	}

	/* ----- CVE-2021-3430: duplicate LL_CONNECTION_PARAM_REQ ----- */
	puts("\nCVE-2021-3430: duplicate LL_CONNECTION_PARAM_REQ (LL CTRL RX)");
	{
		u8_t map[5] = {0xff, 0xff, 0xff, 0xff, 0x1f};
		ifw_ll_packet_parser_rx(NULL, build_connect_ind_rx(map, 7, 24));
		ifw_ll_packet_parser_rx(NULL, build_data_pdu_rx(0, 0));

		struct node_rx_hdr *rx = build_dc_pdu_rx(
			PDU_DATA_LLID_CTRL, 0, 0,
			PDU_DATA_LLCTRL_TYPE_CONN_PARAM_REQ);
		bool dropped = ifw_ll_packet_parser_rx(NULL, rx);
		ASSERT_VERDICT("benign: 1st CONN_PARAM_REQ", dropped, false);
	}
	{
		struct node_rx_hdr *rx = build_dc_pdu_rx(
			PDU_DATA_LLID_CTRL, 0, 0,
			PDU_DATA_LLCTRL_TYPE_CONN_PARAM_REQ);
		bool dropped = ifw_ll_packet_parser_rx(NULL, rx);
		ASSERT_VERDICT("malicious: 2nd CONN_PARAM_REQ (no RSP yet)",
			       dropped, true);
	}
	{
		/* RSP clears the pending count; a subsequent REQ is OK. */
		ifw_ll_packet_parser_rx(NULL,
			build_dc_pdu_rx(PDU_DATA_LLID_CTRL, 0, 0,
					PDU_DATA_LLCTRL_TYPE_CONN_PARAM_RSP));
		ifw_ll_packet_parser_rx(NULL,
			build_dc_pdu_rx(PDU_DATA_LLID_CTRL, 0, 0,
					PDU_DATA_LLCTRL_TYPE_CONN_PARAM_RSP));
		struct node_rx_hdr *rx = build_dc_pdu_rx(
			PDU_DATA_LLID_CTRL, 0, 0,
			PDU_DATA_LLCTRL_TYPE_CONN_PARAM_REQ);
		bool dropped = ifw_ll_packet_parser_rx(NULL, rx);
		ASSERT_VERDICT("benign: CONN_PARAM_REQ after RSPs cleared pending",
			       dropped, false);
	}

	/* ----- CVE-2021-3581: Oversized scan response (LL TX) ----- */
	puts("\nCVE-2021-3581: Oversized scan response (LL TX hook)");
	{
		struct pdu_adv pdu = { .type = PDU_ADV_TYPE_SCAN_RSP, .len = 31 };
		bool dropped = ifw_ll_packet_parser_tx(&pdu);
		ASSERT_VERDICT("benign: scan_rsp len=31", dropped, false);
	}
	{
		struct pdu_adv pdu = { .type = PDU_ADV_TYPE_SCAN_RSP, .len = 200 };
		bool dropped = ifw_ll_packet_parser_tx(&pdu);
		ASSERT_VERDICT("malicious: scan_rsp len=200", dropped, true);
	}
	{
		/* TX hook only inspects scan responses; other adv types pass. */
		struct pdu_adv pdu = { .type = PDU_ADV_TYPE_ADV_IND, .len = 200 };
		bool dropped = ifw_ll_packet_parser_tx(&pdu);
		ASSERT_VERDICT("benign: ADV_IND len=200 (not a scan rsp, ignored)",
			       dropped, false);
	}

	/* ----- Note on LLCP_LEN_REQ / LLCP_CONN_PARAM_REQ -----
	 * The current LL DC RX path in ifw_conn_rx -> ifw_ctrl_rx passes an
	 * uninitialized `struct ll_conn *conn` into the LLCP CTRL handlers,
	 * so feeding a real CTRL PDU at this layer reads garbage memory.
	 * We don't drive that path here; it would need the FSM to obtain the
	 * connection state from `lll` (which is already chased) rather than
	 * a never-set local variable.  Leaving this gap as a separate finding. */

	/* ----- SMP downgrade -----
	 * Lives behind the L2CAP host-side hook (ifw_l2cap_packet_parser_recv);
	 * the paper's pure-LL claim does not extend here because SMP key
	 * state is host-only. Tested in isolation via the bytecode-level
	 * harness (host_runner). */

	/* ----- Runtime policy install (paper's OTA-patch capability) -----
	 *
	 * The paper sells eBPF as the way to deploy security patches without
	 * a firmware reflash:
	 *   "Vendors can transmit eBPF programs to victims via BLE and
	 *    directly integrate them into BlueSWAT. … It avoids device reboot
	 *    and firmware recompilation when installing new patches."
	 *
	 * The C-level capability for that is ifw_install_policy().  Here we
	 * verify it works end-to-end against the real verifier:
	 *
	 *   1. A benign CONNECT_IND with role=peripheral passes today (no
	 *      policy is registered for the (CORE, BLE_ROLE) slot).
	 *   2. We hand-craft a 16-byte "always reject" eBPF program
	 *      (mov r0,1 ; exit) and install it on (CORE, BLE_ROLE).
	 *   3. The same benign CONNECT_IND now drops because the runtime-
	 *      installed policy fires from inside ifw_conn_setup ->
	 *      IFW_RUN_VERIFIER(BLE_ROLE, CORE).
	 *
	 * This test must run last because the installed policy persists for
	 * the rest of the process lifetime — there is no uninstall API. */
	puts("\nRuntime policy install (paper's OTA-patch capability)");
	{
		u8_t map[5] = {0xff, 0xff, 0xff, 0xff, 0x1f};
		bool dropped = ifw_ll_packet_parser_rx(NULL,
			build_connect_ind_rx(map, 7, 24));
		ASSERT_VERDICT("baseline: benign CONNECT_IND passes",
			       dropped, false);
	}
	{
		/* eBPF: r0 = 1 (REJECT); exit. */
		static const uint8_t reject_all_bytecode[] = {
			0xb7, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
			0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		};
		int rc = ifw_install_policy(CORE, BLE_ROLE,
					    reject_all_bytecode,
					    sizeof(reject_all_bytecode));
		printf("  [%s] ifw_install_policy(CORE, BLE_ROLE, ...) rc=%d\n",
		       rc == 0 ? "PASS" : "FAIL", rc);
		total++;
		if (rc != 0) failures++;
	}
	{
		u8_t map[5] = {0xff, 0xff, 0xff, 0xff, 0x1f};
		bool dropped = ifw_ll_packet_parser_rx(NULL,
			build_connect_ind_rx(map, 7, 24));
		ASSERT_VERDICT("hot-loaded policy rejects same CONNECT_IND",
			       dropped, true);
	}

	/* ----- eBPF verifier rejection cases -----
	 *
	 * The GATT patch service feeds untrusted bytecode straight into
	 * ifw_install_policy().  Without a verifier a malicious peer could
	 * loop forever, read OOB, or call non-existent helpers.  These
	 * cases check that the structural verifier rejects each obvious
	 * abuse pattern.  The benign "always reject" case above already
	 * proves a well-formed program is accepted. */
	puts("\nVerifier (rejects abusive runtime patches)");
	{
		int rc = ifw_install_policy(CORE, BLE_ROLE,
					    (const u8_t *)"", 0);
		printf("  [%s] empty bytecode rejected (rc=%d)\n",
		       rc != 0 ? "PASS" : "FAIL", rc);
		total++; if (rc == 0) failures++;
	}
	{
		/* Backward jump (loop): JA -1, exit. */
		static const u8_t backjump[] = {
			0x05, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
			0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		};
		int rc = ifw_install_policy(CORE, BLE_ROLE,
					    backjump, sizeof(backjump));
		printf("  [%s] backward jump rejected (rc=%d)\n",
		       rc != 0 ? "PASS" : "FAIL", rc);
		total++; if (rc == 0) failures++;
	}
	{
		/* CALL helper #0 — no helpers exposed for runtime patches. */
		static const u8_t call_inst[] = {
			0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		};
		int rc = ifw_install_policy(CORE, BLE_ROLE,
					    call_inst, sizeof(call_inst));
		printf("  [%s] CALL instruction rejected (rc=%d)\n",
		       rc != 0 ? "PASS" : "FAIL", rc);
		total++; if (rc == 0) failures++;
	}
	{
		/* Store to memory: STXW [r1+0] = r0. */
		static const u8_t store_inst[] = {
			0x63, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		};
		int rc = ifw_install_policy(CORE, BLE_ROLE,
					    store_inst, sizeof(store_inst));
		printf("  [%s] store rejected (rc=%d)\n",
		       rc != 0 ? "PASS" : "FAIL", rc);
		total++; if (rc == 0) failures++;
	}
	{
		/* OOB FSM read: LDXW r0, [r1 + 9999]. */
		static const u8_t oob_load[] = {
			0x61, 0x10, 0x0f, 0x27, 0x00, 0x00, 0x00, 0x00,
			0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		};
		int rc = ifw_install_policy(CORE, BLE_ROLE,
					    oob_load, sizeof(oob_load));
		printf("  [%s] OOB load rejected (rc=%d)\n",
		       rc != 0 ? "PASS" : "FAIL", rc);
		total++; if (rc == 0) failures++;
	}
	{
		/* No EXIT — just one MOV. */
		static const u8_t no_exit[] = {
			0xb7, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		};
		int rc = ifw_install_policy(CORE, BLE_ROLE,
					    no_exit, sizeof(no_exit));
		printf("  [%s] missing EXIT rejected (rc=%d)\n",
		       rc != 0 ? "PASS" : "FAIL", rc);
		total++; if (rc == 0) failures++;
	}

	/* ----- Summary ----- */
	puts("\n=======================================");
	if (failures == 0) {
		printf("ALL %d INTEGRATION TESTS PASSED\n", total);
	} else {
		printf("%d / %d INTEGRATION TESTS FAILED\n", failures, total);
	}
	return failures ? 1 : 0;
}
