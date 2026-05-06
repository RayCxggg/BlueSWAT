/*
 * BlueSWAT firewall patch service.
 *
 * Vendor-specific GATT service that lets a peer push an eBPF policy over
 * BLE and have it installed at runtime — the BLE-side transport for the
 * paper's claim that "vendors can transmit eBPF programs to victims via
 * BLE and directly integrate them into BlueSWAT … without firmware
 * recompilation."
 *
 * Wire protocol (one connection at a time):
 *
 *   1. Write 2 bytes [class, type] to the Header characteristic.
 *      This resets the staging buffer and locks in the target FSM slot.
 *
 *   2. Write the eBPF bytecode to the Body characteristic.  Multiple
 *      writes append; the BLE peer is expected to negotiate a usable ATT
 *      MTU (default 23 bytes carries 20 of payload — small policies fit
 *      in 1-2 writes, larger ones in several).
 *
 *   3. Write any byte to the Commit characteristic.  The service calls
 *      ifw_install_policy(class, type, staging_buf, staging_len), stores
 *      the return code, and clears the staging buffer.
 *
 *   4. Read the Status characteristic to fetch the last install return
 *      code (0 == success; negative == ifw_install_policy error code).
 *
 * Security caveats (not addressed here, intentional for the demo):
 *   - No authentication.  A production deployment must require LE Secure
 *     Connections + a signed payload before accepting a patch.
 *   - No bytecode verifier.  The eBPF VM in this artifact does not have
 *     a verifier (Linux kernel does); a malicious payload can hang the
 *     interpreter or read out-of-bounds.  For real OTA deployment the
 *     bytecode should be signed and statically validated before this
 *     service is exposed.
 */

#include <zephyr/types.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <sys/printk.h>
#include <zephyr.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>

#include "include/fsm_policy_cache.h"

/* Staging buffer big enough for any policy currently in the tree
 * (smp_ident_check is the largest at ~150 bytes).  Lives in BSS, ~96 B
 * of overhead per the linker map. */
#define BSWAT_STAGING_MAX 256

static u8_t  staging_buf[BSWAT_STAGING_MAX];
static u16_t staging_len;
static u8_t  target_class;
static u8_t  target_type;
static s32_t last_install_rc = -100; /* "no install attempted yet" */

/* ---- Vendor UUIDs ---- */
/* 128-bit base, suffix .._f1ed; chars increment the 4th word.  Pure
 * test/demo UUIDs — replace with a vendor-allocated namespace before
 * deploying. */

#define BSWAT_SVC_UUID    BT_UUID_128_ENCODE( \
	0xbd000001, 0x7e57, 0x49a1, 0xa0bd, 0xe6cf8d00f1ed)
#define BSWAT_HDR_UUID    BT_UUID_128_ENCODE( \
	0xbd000002, 0x7e57, 0x49a1, 0xa0bd, 0xe6cf8d00f1ed)
#define BSWAT_BODY_UUID   BT_UUID_128_ENCODE( \
	0xbd000003, 0x7e57, 0x49a1, 0xa0bd, 0xe6cf8d00f1ed)
#define BSWAT_COMMIT_UUID BT_UUID_128_ENCODE( \
	0xbd000004, 0x7e57, 0x49a1, 0xa0bd, 0xe6cf8d00f1ed)
#define BSWAT_STAT_UUID   BT_UUID_128_ENCODE( \
	0xbd000005, 0x7e57, 0x49a1, 0xa0bd, 0xe6cf8d00f1ed)

static struct bt_uuid_128 bswat_svc    = BT_UUID_INIT_128(BSWAT_SVC_UUID);
static struct bt_uuid_128 bswat_hdr    = BT_UUID_INIT_128(BSWAT_HDR_UUID);
static struct bt_uuid_128 bswat_body   = BT_UUID_INIT_128(BSWAT_BODY_UUID);
static struct bt_uuid_128 bswat_commit = BT_UUID_INIT_128(BSWAT_COMMIT_UUID);
static struct bt_uuid_128 bswat_stat   = BT_UUID_INIT_128(BSWAT_STAT_UUID);

/* ---- Write callbacks ---- */

static ssize_t write_header(struct bt_conn *conn,
			    const struct bt_gatt_attr *attr,
			    const void *buf, u16_t len, u16_t offset,
			    u8_t flags)
{
	const u8_t *p = buf;

	if (offset != 0) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}
	if (len != 2) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}

	target_class = p[0];
	target_type  = p[1];
	staging_len  = 0;
	return len;
}

static ssize_t write_body(struct bt_conn *conn,
			  const struct bt_gatt_attr *attr,
			  const void *buf, u16_t len, u16_t offset,
			  u8_t flags)
{
	if (offset != 0) {
		/* Long-write reassembly is left to the peer: each write is
		 * a fresh chunk appended to staging. */
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}
	if (staging_len + len > BSWAT_STAGING_MAX) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}

	memcpy(&staging_buf[staging_len], buf, len);
	staging_len += len;
	return len;
}

static ssize_t write_commit(struct bt_conn *conn,
			    const struct bt_gatt_attr *attr,
			    const void *buf, u16_t len, u16_t offset,
			    u8_t flags)
{
	if (offset != 0 || len < 1) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}

	last_install_rc = ifw_install_policy(target_class, target_type,
					     staging_buf, staging_len);
	staging_len = 0;
	return len;
}

static ssize_t read_status(struct bt_conn *conn,
			   const struct bt_gatt_attr *attr,
			   void *buf, u16_t len, u16_t offset)
{
	return bt_gatt_attr_read(conn, attr, buf, len, offset,
				 &last_install_rc, sizeof(last_install_rc));
}

/* ---- Service definition ---- */

BT_GATT_SERVICE_DEFINE(bswat_patch_svc,
	BT_GATT_PRIMARY_SERVICE(&bswat_svc),

	BT_GATT_CHARACTERISTIC(&bswat_hdr.uuid,
			       BT_GATT_CHRC_WRITE,
			       BT_GATT_PERM_WRITE,
			       NULL, write_header, NULL),

	BT_GATT_CHARACTERISTIC(&bswat_body.uuid,
			       BT_GATT_CHRC_WRITE,
			       BT_GATT_PERM_WRITE,
			       NULL, write_body, NULL),

	BT_GATT_CHARACTERISTIC(&bswat_commit.uuid,
			       BT_GATT_CHRC_WRITE,
			       BT_GATT_PERM_WRITE,
			       NULL, write_commit, NULL),

	BT_GATT_CHARACTERISTIC(&bswat_stat.uuid,
			       BT_GATT_CHRC_READ,
			       BT_GATT_PERM_READ,
			       read_status, NULL, NULL),
);
