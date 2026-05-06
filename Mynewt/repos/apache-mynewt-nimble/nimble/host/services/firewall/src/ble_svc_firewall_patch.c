/*
 * BlueSWAT firewall patch service.
 *
 * Mynewt/NimBLE port of the Zephyr peripheral/src/firewall_patch.c
 * vendor service. Same wire protocol, same UUID base — see the header
 * for the protocol description.
 *
 * Security caveats (intentional for the demo, mirroring the Zephyr port):
 *   - No authentication.  A production deployment must require LE Secure
 *     Connections + a signed payload before accepting a patch.
 *   - The eBPF interpreter has only the structural verifier in
 *     ifw_install_policy(); a malicious payload can still produce
 *     div-by-zero or unknown-opcode escapes from the VM that the verifier
 *     leaves to the interpreter to handle defensively.
 */

#include <assert.h>
#include <string.h>
#include <stdint.h>

#include "sysinit/sysinit.h"
#include "host/ble_hs.h"
#include "host/ble_uuid.h"

#include "services/firewall/ble_svc_firewall_patch.h"
#include "fsm_policy_cache.h"

/* 128-bit base bd00****-7e57-49a1-a0bd-e6cf8d00f1ed (little-endian
 * encoded). Last 4 bytes are the per-attribute discriminator: 01 svc,
 * 02 hdr, 03 body, 04 commit, 05 status. */

/* Service: bd000001-7e57-49a1-a0bd-e6cf8d00f1ed */
static const ble_uuid128_t firewall_patch_svc_uuid =
    BLE_UUID128_INIT(0xed, 0xf1, 0x00, 0x8d, 0xcf, 0xe6, 0xbd, 0xa0,
                     0xa1, 0x49, 0x57, 0x7e, 0x01, 0x00, 0x00, 0xbd);

/* Header chr: bd000002-... */
static const ble_uuid128_t firewall_patch_hdr_uuid =
    BLE_UUID128_INIT(0xed, 0xf1, 0x00, 0x8d, 0xcf, 0xe6, 0xbd, 0xa0,
                     0xa1, 0x49, 0x57, 0x7e, 0x02, 0x00, 0x00, 0xbd);

/* Body chr: bd000003-... */
static const ble_uuid128_t firewall_patch_body_uuid =
    BLE_UUID128_INIT(0xed, 0xf1, 0x00, 0x8d, 0xcf, 0xe6, 0xbd, 0xa0,
                     0xa1, 0x49, 0x57, 0x7e, 0x03, 0x00, 0x00, 0xbd);

/* Commit chr: bd000004-... */
static const ble_uuid128_t firewall_patch_commit_uuid =
    BLE_UUID128_INIT(0xed, 0xf1, 0x00, 0x8d, 0xcf, 0xe6, 0xbd, 0xa0,
                     0xa1, 0x49, 0x57, 0x7e, 0x04, 0x00, 0x00, 0xbd);

/* Status chr: bd000005-... */
static const ble_uuid128_t firewall_patch_status_uuid =
    BLE_UUID128_INIT(0xed, 0xf1, 0x00, 0x8d, 0xcf, 0xe6, 0xbd, 0xa0,
                     0xa1, 0x49, 0x57, 0x7e, 0x05, 0x00, 0x00, 0xbd);

static uint8_t  staging_buf[BSWAT_STAGING_MAX];
static uint16_t staging_len;
static uint8_t  target_class;
static uint8_t  target_type;
static int32_t  last_install_rc = -100; /* "no install attempted yet" */

static int
firewall_patch_access(uint16_t conn_handle, uint16_t attr_handle,
                      struct ble_gatt_access_ctxt *ctxt, void *arg);

static const struct ble_gatt_svc_def firewall_patch_svc_defs[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &firewall_patch_svc_uuid.u,
        .characteristics = (struct ble_gatt_chr_def[]) { {
            /* Header — write 2 bytes [class, type]. */
            .uuid = &firewall_patch_hdr_uuid.u,
            .access_cb = firewall_patch_access,
            .flags = BLE_GATT_CHR_F_WRITE,
        }, {
            /* Body — write N bytes, appended. */
            .uuid = &firewall_patch_body_uuid.u,
            .access_cb = firewall_patch_access,
            .flags = BLE_GATT_CHR_F_WRITE,
        }, {
            /* Commit — write any byte to trigger ifw_install_policy. */
            .uuid = &firewall_patch_commit_uuid.u,
            .access_cb = firewall_patch_access,
            .flags = BLE_GATT_CHR_F_WRITE,
        }, {
            /* Status — read int32 install rc. */
            .uuid = &firewall_patch_status_uuid.u,
            .access_cb = firewall_patch_access,
            .flags = BLE_GATT_CHR_F_READ,
        }, {
            0, /* end of characteristics */
        } },
    },

    {
        0, /* end of services */
    },
};

static int
firewall_patch_handle_header(struct os_mbuf *om)
{
    uint8_t hdr[2];
    uint16_t len;
    int rc;

    rc = ble_hs_mbuf_to_flat(om, hdr, sizeof(hdr), &len);
    if (rc != 0) {
        return BLE_ATT_ERR_UNLIKELY;
    }
    if (len != 2) {
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }

    target_class = hdr[0];
    target_type  = hdr[1];
    staging_len  = 0;
    return 0;
}

static int
firewall_patch_handle_body(struct os_mbuf *om)
{
    uint16_t chunk_len;
    int rc;

    chunk_len = OS_MBUF_PKTLEN(om);
    if ((uint32_t)staging_len + chunk_len > BSWAT_STAGING_MAX) {
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }

    uint16_t copied = 0;
    rc = ble_hs_mbuf_to_flat(om, &staging_buf[staging_len],
                             chunk_len, &copied);
    if (rc != 0) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    staging_len += copied;
    return 0;
}

static int
firewall_patch_handle_commit(struct os_mbuf *om)
{
    uint16_t plen = OS_MBUF_PKTLEN(om);
    if (plen < 1) {
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }

    last_install_rc = ifw_install_policy(target_class, target_type,
                                         staging_buf, staging_len);
    staging_len = 0;
    return 0;
}

static int
firewall_patch_handle_status_read(struct ble_gatt_access_ctxt *ctxt)
{
    int rc = os_mbuf_append(ctxt->om, &last_install_rc,
                            sizeof(last_install_rc));
    return (rc == 0) ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
}

static int
firewall_patch_access(uint16_t conn_handle, uint16_t attr_handle,
                      struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    const ble_uuid_t *uuid = ctxt->chr->uuid;

    switch (ctxt->op) {
    case BLE_GATT_ACCESS_OP_WRITE_CHR:
        if (ble_uuid_cmp(uuid, &firewall_patch_hdr_uuid.u) == 0) {
            return firewall_patch_handle_header(ctxt->om);
        }
        if (ble_uuid_cmp(uuid, &firewall_patch_body_uuid.u) == 0) {
            return firewall_patch_handle_body(ctxt->om);
        }
        if (ble_uuid_cmp(uuid, &firewall_patch_commit_uuid.u) == 0) {
            return firewall_patch_handle_commit(ctxt->om);
        }
        return BLE_ATT_ERR_UNLIKELY;

    case BLE_GATT_ACCESS_OP_READ_CHR:
        if (ble_uuid_cmp(uuid, &firewall_patch_status_uuid.u) == 0) {
            return firewall_patch_handle_status_read(ctxt);
        }
        return BLE_ATT_ERR_UNLIKELY;

    default:
        return BLE_ATT_ERR_UNLIKELY;
    }
}

int
ble_svc_firewall_patch_init(void)
{
    int rc;

    rc = ble_gatts_count_cfg(firewall_patch_svc_defs);
    if (rc != 0) {
        return rc;
    }

    rc = ble_gatts_add_svcs(firewall_patch_svc_defs);
    return rc;
}
