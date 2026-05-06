/* load FSM policy eBPF code from cache */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ebpf.h"
#include "ebpf_inst.h"
#include "ebpf_vm.h"
#include "ebpf_allocator.h"
#include "ebpf_porting.h"

#include "fsm_policy_cache.h"
#include "fsm_core.h"
#include "utils.h"
#include "fsm_lib_hdr.h"

/* Compile-time policy bytecodes — full Zephyr-aligned set. Legacy
 * keysize_confusion / key_entropy_downgrade kept available for the
 * legacy SMP parser path but not auto-registered. */
#include "conn_chan_map.h"
#include "conn_chan_hop.h"
#include "lll_interval.h"
#include "dc_nesn.h"
#include "llcp_len_req.h"
#include "llcp_conn_param_req.h"
#include "scan_rsp_len.h"
#include "smp_ident_check.h"
#include "keysize_confusion.h"
#include "key_entropy_downgrade.h"

uint32_t core_policy_mask = 0;
uint32_t shared_policy_mask = 0;
uint32_t conn_policy_mask = 0;
uint32_t dc_policy_mask = 0;
uint32_t spi_policy_mask = 0;
uint32_t hci_policy_mask = 0;

bool policy_mgr_init = false;
struct fsm_policy_manager policy_manager = { 0 };
struct policy_cache policy_arr[PID_NUM] = { 0 };

/* Runtime-installed policy slots. */
static struct policy_cache runtime_policy_arr[IFW_MAX_RUNTIME_POLICIES] = { 0 };
static int runtime_policy_count;

static struct policy_cache *get_policy_slot(int pid)
{
    if (pid < 0) {
        return NULL;
    }
    if (pid < PID_NUM) {
        return &policy_arr[pid];
    }
    int rt_idx = pid - PID_NUM;
    if (rt_idx >= IFW_MAX_RUNTIME_POLICIES) {
        return NULL;
    }
    return &runtime_policy_arr[rt_idx];
}

#define ADD_POLICY(policy_index, class, type)               \
    do {                                                    \
        int pid = PID_##policy_index;                       \
        policy_arr[pid].size = sizeof(policy_index);        \
        policy_arr[pid].code = (uint8_t *)policy_index;     \
        policy_arr[pid].jit = false;                        \
        register_policy(class, type, pid);                  \
    } while (0)

void load_all_policies()
{
    /* Full Zephyr-aligned set. The split-SoC SPI HCI policies
     * (CVE-2020-10065) are deliberately not registered on this
     * single-chip target — bytecodes remain in the tree. */
    ADD_POLICY(conn_chan_map,        CONN, CHANNEL_MAP);
    ADD_POLICY(conn_chan_hop,        CONN, CHANNEL_HOP);
    ADD_POLICY(lll_interval,         CONN, LLL_INTERVAL);
    ADD_POLICY(dc_nesn,              DC,   NESN);
    ADD_POLICY(llcp_len_req,         DC,   LLCP_LEN_REQ);
    ADD_POLICY(llcp_conn_param_req,  DC,   LLCP_CONN_PARAM_REQ);
    ADD_POLICY(scan_rsp_len,         CONN, SCAN_RSP_LEN);
    ADD_POLICY(smp_ident_check,      DC,   SMP_KEYS);
}

void set_policy_jit_on(int pid)
{
    if (pid >= 0 && pid < PID_NUM) {
        policy_arr[pid].jit = true;
    }
}

void set_all_policy_jit_on()
{
    for (int pid = 0; pid < PID_NUM; pid++) {
        policy_arr[pid].jit = true;
    }
}

void ifw_fsm_enable(bool jit)
{
    load_all_policies();

    if (jit) {
        set_all_policy_jit_on();
    }
}

static void init_policy_manager()
{
    memset(&policy_manager, 0, sizeof(policy_manager));
    policy_mgr_init = true;
}

void register_policy(int class, int type, int pid)
{
    if (!policy_mgr_init) {
        init_policy_manager();
    }

    switch (class) {
    case CORE:   core_policy_mask   |= (1u << type); break;
    case SHARED: shared_policy_mask |= (1u << type); break;
    case CONN:   conn_policy_mask   |= (1u << type); break;
    case DC:     dc_policy_mask     |= (1u << type); break;
    case SPI:    spi_policy_mask    |= (1u << type); break;
    case HCI:    hci_policy_mask    |= (1u << type); break;
    }

    if (policy_manager.policy[class][type] == NULL) {
        struct fsm_policy_list *new_policy =
            ebpf_malloc(sizeof(struct fsm_policy_list));
        if (new_policy == NULL) {
            return;
        }
        new_policy->index = pid;
        new_policy->policy_next = NULL;
        policy_manager.policy[class][type] = new_policy;
    } else {
        struct fsm_policy_list *policy =
            policy_manager.policy[class][type];

        while (policy->policy_next != NULL) {
            policy = policy->policy_next;
        }

        struct fsm_policy_list *new_node =
            ebpf_malloc(sizeof(struct fsm_policy_list));
        if (new_node == NULL) {
            return;
        }
        new_node->index = pid;
        new_node->policy_next = NULL;
        policy->policy_next = new_node;
    }
}

void remove_policy(int class, int type, int pid)
{
    struct fsm_policy_list *policy = policy_manager.policy[class][type];
    if (policy == NULL) {
        return;
    }

    if (policy->index == pid) {
        policy_manager.policy[class][type] = policy->policy_next;
        my_os_free(policy);
        return;
    }

    while (policy->policy_next != NULL) {
        if (policy->policy_next->index == pid) {
            struct fsm_policy_list *tmp = policy->policy_next;
            policy->policy_next = policy->policy_next->policy_next;
            my_os_free(tmp);
            return;
        }
        policy = policy->policy_next;
    }
}

ebpf_vm *g_vm = NULL, *g_jit_vm = NULL;

static ebpf_vm *get_default_vm(bool use_jit)
{
    ebpf_vm *vm;

    if (use_jit) {
        if (g_jit_vm == NULL) {
            g_jit_vm = ebpf_create();
            g_jit_vm->use_jit = true;
        }
        vm = g_jit_vm;
    } else {
        if (g_vm == NULL) {
            g_vm = ebpf_create();
        }
        vm = g_vm;
    }

    return vm;
}

static struct ebpf_vm *load_ebpf_code(int ebpf_idx, bool use_jit)
{
    struct policy_cache *slot = get_policy_slot(ebpf_idx);
    if (slot == NULL || slot->size == 0) {
        return NULL;
    }

    ebpf_vm *vm = get_default_vm(use_jit);

    ebpf_vm_set_inst(vm, slot->code, slot->size);

    if (use_jit) {
        gen_jit_code(vm);
    }

    return vm;
}

static ebpf_vm *get_vm_from_cache(int ebpf_idx)
{
    struct policy_cache *slot = get_policy_slot(ebpf_idx);
    if (slot == NULL || slot->size == 0) {
        return NULL;
    }
    return load_ebpf_code(ebpf_idx, slot->jit);
}

static uint64_t run_fsm_ebpf_policy(int ebpf_policy_idx, void *newState,
                                    int dsize)
{
    ebpf_vm *vm = get_vm_from_cache(ebpf_policy_idx);
    if (vm == NULL) {
        return 0;
    }

    if (vm->use_jit) {
        return vm->jit_func(newState, dsize);
    }

    return ebpf_vm_exec(vm, newState, dsize);
}

/* Maximum instruction count for runtime-installed policies. The largest
 * compile-time policy is ~9 instructions (smp_ident_check); 64 leaves
 * headroom for richer custom policies without giving an attacker
 * millions of instructions to burn. */
#define IFW_RUNTIME_MAX_INSTS 64

/* Lightweight structural verifier for runtime-installed eBPF policies.
 * Returns 0 on success, a negative diagnostic code on rejection.
 *
 * Catches the realistic abuse vectors when accepting an untrusted
 * bytecode payload over the GATT patch service:
 *   -10..-11 length / instruction-count caps
 *   -12      register out of range
 *   -13      foreign helper CALL
 *   -14      any store op (policies are pure readers)
 *   -15..-17 OOB/out-of-stack memory load
 *   -18      LDDW missing second slot
 *   -19..-20 negative or out-of-range jump
 *   -21      no EXIT in program
 */
static int ifw_verify_policy(const uint8_t *code, uint32_t len, size_t mem_size)
{
    if (code == NULL || len == 0 || (len % 8) != 0) {
        return -10;
    }

    uint32_t num_insts = len / 8u;
    if (num_insts > IFW_RUNTIME_MAX_INSTS) {
        return -11;
    }

    bool seen_exit = false;
    const struct ebpf_inst *insts = (const struct ebpf_inst *)code;

    for (uint32_t pc = 0; pc < num_insts; pc++) {
        const struct ebpf_inst *inst = &insts[pc];
        uint8_t op = inst->opcode;

        if (inst->dst >= MAX_BPF_REG || inst->src >= MAX_BPF_REG) {
            return -12;
        }

        if (op == EBPF_OP_CALL) {
            return -13;
        }

        if (op == EBPF_OP_EXIT) {
            seen_exit = true;
            continue;
        }

        switch (op) {
        case EBPF_OP_STDW: case EBPF_OP_STW:
        case EBPF_OP_STH:  case EBPF_OP_STB:
        case EBPF_OP_STXDW: case EBPF_OP_STXW:
        case EBPF_OP_STXH:  case EBPF_OP_STXB:
            return -14;
        }

        size_t load_sz = 0;
        switch (op) {
        case EBPF_OP_LDXDW: load_sz = 8; break;
        case EBPF_OP_LDXW:  load_sz = 4; break;
        case EBPF_OP_LDXH:  load_sz = 2; break;
        case EBPF_OP_LDXB:  load_sz = 1; break;
        }
        if (load_sz != 0) {
            int16_t off = inst->offset;
            if (inst->src == 1) {
                if (off < 0 ||
                    (size_t)off + load_sz > mem_size) {
                    return -15;
                }
            } else if (inst->src == 10) {
                if (off >= 0 ||
                    (int)load_sz + off > 0 ||
                    (size_t)(-off) > STACK_SIZE) {
                    return -16;
                }
            } else {
                return -17;
            }
        }

        if (op == EBPF_OP_LDDW) {
            if (pc + 1 >= num_insts) {
                return -18;
            }
            pc++;
            continue;
        }

        if ((op & EBPF_CLS_MASK) == EBPF_CLS_JMP) {
            int16_t off = inst->offset;
            if (off < 0) {
                return -19;
            }
            uint32_t target = pc + 1u + (uint32_t)off;
            if (target >= num_insts) {
                return -20;
            }
        }
    }

    return seen_exit ? 0 : -21;
}

int ifw_install_policy(int class, int type,
                       const uint8_t *code, uint32_t len)
{
    if (code == NULL || len == 0 || (len % 8) != 0) {
        return -1; /* eBPF instructions are 8 bytes each */
    }
    if (class < 0 || class >= IFW_STATE_CLASS_NUM ||
        type  < 0 || type  >= IFW_DC_PARAM_NUM) {
        return -2;
    }
    if (runtime_policy_count >= IFW_MAX_RUNTIME_POLICIES) {
        return -3;
    }

    int verr = ifw_verify_policy(code, len, sizeof(struct FsmState));
    if (verr != 0) {
        return verr;
    }

    uint8_t *copy = (uint8_t *)ebpf_malloc(len);
    if (copy == NULL) {
        return -4;
    }
    memcpy(copy, code, len);

    int rt_idx = runtime_policy_count;
    int pid    = PID_NUM + rt_idx;

    runtime_policy_arr[rt_idx].size = (int)len;
    runtime_policy_arr[rt_idx].code = copy;
    runtime_policy_arr[rt_idx].jit  = false;
    runtime_policy_count++;

    register_policy(class, type, pid);
    return 0;
}

int run_fsm_check_policy(int type, int class, void *newState)
{
    /* Note: the early-out on the *_policy_mask bits is intentionally
     * NOT used here (matches the Zephyr port). The mask flags can race
     * with register_policy when a runtime install adds a new (class,
     * type) slot; the linked-list walk below always sees the up-to-date
     * head pointer. */

    struct fsm_policy_list *policy = policy_manager.policy[class][type];

    while (policy != NULL) {
        uint64_t result = run_fsm_ebpf_policy(policy->index, newState, 64);
        if (result == IFW_OPERATION_REJECT) {
            return IFW_OPERATION_REJECT;
        }
        policy = policy->policy_next;
    }

    return IFW_OPERATION_PASS;
}
