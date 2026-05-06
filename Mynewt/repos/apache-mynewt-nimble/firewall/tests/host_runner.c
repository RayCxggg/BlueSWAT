/*
 * Host-side test harness for the Mynewt/NimBLE firewall.
 *
 * Drives the cross-stack infrastructure (structural verifier +
 * ifw_install_policy + run_fsm_check_policy) on the Mynewt port using
 * the same uBPF interpreter the firmware uses. The full LL/SMP/TX
 * parser path needs real NimBLE controller types and is not exercised
 * here — this harness covers the stack-agnostic pieces.
 *
 * Build: make -C firewall/tests
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "fsm_core.h"
#include "fsm_policy_cache.h"
#include "ebpf_vm.h"

/* Stub for the JIT codegen path — the policy cache references it from a
 * branch we never take (we don't enable JIT in the host harness). */
void gen_jit_code(struct ebpf_vm *vm) { (void)vm; }

/* Bytecode for a tiny "always reject" eBPF program — used by the
 * runtime-install integration test to prove the slot is reachable.
 *
 * Program (8 bytes per instruction, little-endian):
 *   mov64 r0, 1   ; b7 00 00 00 01 00 00 00
 *   exit          ; 95 00 00 00 00 00 00 00
 */
static const uint8_t reject_program[] = {
    0xb7, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* Same shape as reject_program but with an unconditional backward jump
 * (offset = -1) — should be rejected by the verifier. */
static const uint8_t backjump_program[] = {
    0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x05, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,  /* JA -1 → loop */
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* Program with an EBPF_OP_CALL — should be rejected (no helpers). */
static const uint8_t call_program[] = {
    0x85, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,  /* CALL #1 */
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* Program that issues a store — should be rejected. */
static const uint8_t store_program[] = {
    0x72, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* STXB [r1+0] = r0 */
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* LDXW from r1 with an out-of-range offset — should be rejected. */
static const uint8_t oob_program[] = {
    0x61, 0x10, 0xf0, 0x7f, 0x00, 0x00, 0x00, 0x00,  /* LDXW r0,[r1+32752] */
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* Missing EXIT. */
static const uint8_t no_exit_program[] = {
    0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* MOV r0, 0 */
};

static int total_tests;
static int passed_tests;

#define EXPECT(cond, label) do {                            \
    total_tests++;                                          \
    if (cond) {                                             \
        passed_tests++;                                     \
        printf("  [PASS] %s\n", label);                     \
    } else {                                                \
        printf("  [FAIL] %s\n", label);                     \
    }                                                       \
} while (0)

static void test_verifier_rejects(void)
{
    printf("Verifier (rejects abusive runtime patches)\n");

    int rc;

    rc = ifw_install_policy(CONN, CHANNEL_HOP, NULL, 8);
    EXPECT(rc == -1, "NULL bytecode rejected (rc=-1)");

    rc = ifw_install_policy(CONN, CHANNEL_HOP, reject_program, 7);
    EXPECT(rc == -1, "non-multiple-of-8 length rejected (rc=-1)");

    rc = ifw_install_policy(-1, CHANNEL_HOP, reject_program, 8);
    EXPECT(rc == -2, "out-of-range class rejected (rc=-2)");

    rc = ifw_install_policy(CONN, CHANNEL_HOP, backjump_program,
                            sizeof(backjump_program));
    EXPECT(rc == -19, "backward jump rejected (rc=-19)");

    rc = ifw_install_policy(CONN, CHANNEL_HOP, call_program,
                            sizeof(call_program));
    EXPECT(rc == -13, "CALL instruction rejected (rc=-13)");

    rc = ifw_install_policy(CONN, CHANNEL_HOP, store_program,
                            sizeof(store_program));
    EXPECT(rc == -14, "store rejected (rc=-14)");

    rc = ifw_install_policy(CONN, CHANNEL_HOP, oob_program,
                            sizeof(oob_program));
    EXPECT(rc == -15, "OOB load rejected (rc=-15)");

    rc = ifw_install_policy(CONN, CHANNEL_HOP, no_exit_program,
                            sizeof(no_exit_program));
    EXPECT(rc == -21, "missing EXIT rejected (rc=-21)");
}

static void test_install_and_dispatch(void)
{
    printf("\nRuntime install + dispatch (paper's OTA-patch capability)\n");

    /* Baseline: no policy on (CONN, CHANNEL_HOP), so the dispatcher
     * returns PASS. */
    struct FsmState state = { 0 };
    int verdict = run_fsm_check_policy(CHANNEL_HOP, CONN, &state);
    EXPECT(verdict == IFW_OPERATION_PASS,
           "baseline: empty slot returns PASS");

    /* Hot-load the always-reject policy on (CONN, CHANNEL_HOP). */
    int rc = ifw_install_policy(CONN, CHANNEL_HOP, reject_program,
                                sizeof(reject_program));
    EXPECT(rc == 0, "ifw_install_policy(CONN, CHANNEL_HOP) returns 0");

    /* Now the same dispatch should reject. */
    verdict = run_fsm_check_policy(CHANNEL_HOP, CONN, &state);
    EXPECT(verdict == IFW_OPERATION_REJECT,
           "hot-loaded policy rejects subsequent CHANNEL_HOP check");

    /* An unrelated slot is still untouched. */
    verdict = run_fsm_check_policy(SCAN_RSP_LEN, CONN, &state);
    EXPECT(verdict == IFW_OPERATION_PASS,
           "unrelated slot (SCAN_RSP_LEN) still PASS");
}

static void test_install_capacity(void)
{
    printf("\nRuntime install capacity (IFW_MAX_RUNTIME_POLICIES)\n");

    /* One slot was consumed by test_install_and_dispatch above.
     * Fill the rest, then expect the next install to return -3. */
    int installed_ok = 0;
    int rc;
    while ((rc = ifw_install_policy(CONN, LLL_INTERVAL,
                                    reject_program,
                                    sizeof(reject_program))) == 0) {
        installed_ok++;
        if (installed_ok > IFW_MAX_RUNTIME_POLICIES + 2) {
            break; /* runaway guard */
        }
    }

    EXPECT(rc == -3, "exhausting runtime slots returns -3");
    EXPECT(installed_ok >= 1 &&
           installed_ok <= IFW_MAX_RUNTIME_POLICIES,
           "at least one and at most IFW_MAX_RUNTIME_POLICIES installs succeeded");
}

int main(void)
{
    test_verifier_rejects();
    test_install_and_dispatch();
    test_install_capacity();

    printf("\n=======================================\n");
    if (passed_tests == total_tests) {
        printf("ALL %d MYNEWT INFRASTRUCTURE TESTS PASSED\n", total_tests);
        return 0;
    }
    printf("FAIL: %d / %d passed\n", passed_tests, total_tests);
    return 1;
}
