/*
 * BlueSWAT firewall patch service — public API.
 *
 * Vendor-specific GATT service that lets a peer push an eBPF policy
 * over BLE and have it installed at runtime via ifw_install_policy().
 *
 * Wire protocol (one connection at a time):
 *   1. Write 2 bytes [class, type] to Header   (UUID bd000002).
 *   2. Write the eBPF bytecode to Body         (UUID bd000003); each
 *      write appends to a staging buffer (max BSWAT_STAGING_MAX bytes).
 *   3. Write any byte to Commit                (UUID bd000004); the
 *      service calls ifw_install_policy(class, type, staging, len).
 *   4. Read Status                             (UUID bd000005) for the
 *      last install rc (0 == success, negative == error code).
 */

#ifndef H_BLE_SVC_FIREWALL_PATCH_
#define H_BLE_SVC_FIREWALL_PATCH_

#ifdef __cplusplus
extern "C" {
#endif

#define BSWAT_STAGING_MAX 256

/* Register the GATT service with the host. Must be called from
 * application init after ble_hs_init(). Returns 0 on success. */
int ble_svc_firewall_patch_init(void);

#ifdef __cplusplus
}
#endif

#endif /* H_BLE_SVC_FIREWALL_PATCH_ */
