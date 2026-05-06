/*
 * Mock header for host-side compilation of the Mynewt/NimBLE firewall.
 * Pre-included via -include to short-circuit NimBLE/Mynewt stack
 * headers that aren't available in this environment (no apache-mynewt-
 * core checkout). Same idea as ZephyrOS/zephyr/firewall/tests/
 * zephyr_mocks.h.
 *
 * Only the symbols the runtime-install + verifier code references are
 * stubbed; the LL/SMP/TX parsers (which need real NimBLE types) are not
 * covered by this harness.
 */

#ifndef MYNEWT_MOCKS_H_
#define MYNEWT_MOCKS_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* Pretend we already pulled in fsm_lib_hdr.h. */
#define FSM_LIB_HDR_H_

/* MODLOG_DFLT(LEVEL, fmt, ...) → printf */
#define MODLOG_DFLT(level, ...) printf(__VA_ARGS__)

/* SLIST_ENTRY / SLIST_NEXT — only referenced from struct
 * ifw_ble_l2cap_chan inside the original fsm_lib_hdr.h; we don't use
 * those structs in the verifier tests. Provide harmless stubs so any
 * stray reference compiles. */
#ifndef SLIST_ENTRY
#define SLIST_ENTRY(type) struct { struct type *sle_next; }
#endif
#ifndef SLIST_NEXT
#define SLIST_NEXT(elm, field) ((elm)->field.sle_next)
#endif

#endif /* MYNEWT_MOCKS_H_ */
