#include <stdio.h>
#include <stdint.h>

#include "utils.h"
#include "fsm_policy_cache.h"
#include "fsm_lib_hdr.h"

/* Thin wrapper around ifw_install_policy() kept for any legacy call
 * sites that referenced the previous (broken) ifw_add_policy() API.
 *
 * The previous implementation in this file used `PID_##policy.index`
 * outside of a macro definition (which is a syntax error) and assumed
 * a struct field that was never populated. The actual runtime-install
 * path now lives in fsm_policy_cache.c — see ifw_install_policy(). */

struct fsm_policy
{
    const void *policy;     /* unused */
    const unsigned char *index;
    uint16_t len;

    uint16_t type;
    uint16_t class;
};

int ifw_add_policy(struct fsm_policy policy)
{
    return ifw_install_policy(policy.class, policy.type,
                              (const uint8_t *)policy.index, policy.len);
}

/* The NimBLE FCB (flash circular buffer) backing for persisted patches
 * is left as future work, mirroring the Zephyr port. The build-time
 * dependency on ifw_fcb_init() in fsm_core.c is satisfied by this stub. */
int ifw_fcb_init(void)
{
    return 0;
}
