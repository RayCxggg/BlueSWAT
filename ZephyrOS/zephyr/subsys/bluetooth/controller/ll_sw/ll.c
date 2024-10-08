/*
 * Copyright (c) 2016-2018 Nordic Semiconductor ASA
 * Copyright (c) 2016 Vinayak Kariappa Chettimada
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/types.h>
#include <string.h>

#include <soc.h>
#include <device.h>
#include <drivers/clock_control.h>
#include <drivers/clock_control/nrf_clock_control.h>
#include <bluetooth/hci.h>

#define BT_DBG_ENABLED IS_ENABLED(CONFIG_BT_DEBUG_HCI_DRIVER)
#define LOG_MODULE_NAME bt_ctlr_ll
#include "common/log.h"

#include "hal/cpu.h"
#include "hal/cntr.h"
#include "hal/ccm.h"
#include "hal/radio.h"
#include "hal/ticker.h"
#include "hal/debug.h"

#include "util/util.h"
#include "util/mem.h"
#include "util/memq.h"
#include "util/mayfly.h"

#include "ticker/ticker.h"

#include "pdu.h"
#include "lll.h"
#include "ctrl.h"
#include "ctrl_internal.h"
#include "ll.h"
#include "ll_feat.h"
#include "ll_filter.h"
#include "ll_settings.h"

/* Global singletons */

#if defined(CONFIG_SOC_FLASH_NRF_RADIO_SYNC)
#define FLASH_TICKER_NODES 1 /* No. of tickers reserved for flashing */
#define FLASH_TICKER_USER_APP_OPS 1 /* No. of additional ticker operations */
#else
#define FLASH_TICKER_NODES 0
#define FLASH_TICKER_USER_APP_OPS 0
#endif

#define TICKER_NODES (RADIO_TICKER_NODES + FLASH_TICKER_NODES)
#define TICKER_USER_APP_OPS                                                    \
	(RADIO_TICKER_USER_APP_OPS + FLASH_TICKER_USER_APP_OPS)
#define TICKER_USER_OPS (RADIO_TICKER_USER_OPS + FLASH_TICKER_USER_APP_OPS)

/* memory for ticker nodes/instances */
static u8_t MALIGN(4) _ticker_nodes[TICKER_NODES][TICKER_NODE_T_SIZE];

/* memory for users/contexts operating on ticker module */
static u8_t MALIGN(4) _ticker_users[MAYFLY_CALLER_COUNT][TICKER_USER_T_SIZE];

/* memory for user/context simultaneous API operations */
static u8_t MALIGN(4) _ticker_user_ops[TICKER_USER_OPS][TICKER_USER_OP_T_SIZE];

/* memory for Bluetooth Controller (buffers, queues etc.) */
static u8_t MALIGN(4) _radio[LL_MEM_TOTAL];

static struct k_sem *sem_recv;

void radio_active_callback(u8_t active)
{
}

void radio_event_callback(void)
{
	k_sem_give(sem_recv);
}

ISR_DIRECT_DECLARE(radio_nrf5_isr)
{
	DEBUG_RADIO_ISR(1);

	isr_radio();

	ISR_DIRECT_PM();

	DEBUG_RADIO_ISR(0);
	return 1;
}

static void rtc0_nrf5_isr(void *arg)
{
	DEBUG_TICKER_ISR(1);

	/* On compare0 run ticker worker instance0 */
	if (NRF_RTC0->EVENTS_COMPARE[0]) {
		NRF_RTC0->EVENTS_COMPARE[0] = 0;

		ticker_trigger(0);
	}

	mayfly_run(MAYFLY_CALL_ID_0);

	DEBUG_TICKER_ISR(0);
}

static void swi5_nrf5_isr(void *arg)
{
	DEBUG_TICKER_JOB(1);

	mayfly_run(MAYFLY_CALL_ID_1);

	DEBUG_TICKER_JOB(0);
}

int ll_init(struct k_sem *sem_rx)
{
	struct device *clk;
	struct device *entropy;
	u32_t err;

	sem_recv = sem_rx;

	clk = device_get_binding(DT_INST_0_NORDIC_NRF_CLOCK_LABEL);
	if (!clk) {
		return -ENODEV;
	}

	clock_control_on(clk, CLOCK_CONTROL_NRF_SUBSYS_LF);

	entropy = device_get_binding(CONFIG_ENTROPY_NAME);
	if (!entropy) {
		return -ENODEV;
	}

	/* TODO: bind and use counter driver */
	cntr_init();

	mayfly_init();

	_ticker_users[MAYFLY_CALL_ID_0][0] = RADIO_TICKER_USER_WORKER_OPS;
	_ticker_users[MAYFLY_CALL_ID_1][0] = RADIO_TICKER_USER_JOB_OPS;
	_ticker_users[MAYFLY_CALL_ID_2][0] = 0;
	_ticker_users[MAYFLY_CALL_ID_PROGRAM][0] = TICKER_USER_APP_OPS;

	err = ticker_init(
		RADIO_TICKER_INSTANCE_ID_RADIO, TICKER_NODES, &_ticker_nodes[0],
		MAYFLY_CALLER_COUNT, &_ticker_users[0], TICKER_USER_OPS,
		&_ticker_user_ops[0], hal_ticker_instance0_caller_id_get,
		hal_ticker_instance0_sched, hal_ticker_instance0_trigger_set);
	LL_ASSERT(!err);

	err = radio_init(clk, CLOCK_CONTROL_NRF_K32SRC_ACCURACY, entropy,
			 RADIO_CONNECTION_CONTEXT_MAX,
			 RADIO_PACKET_COUNT_RX_MAX, RADIO_PACKET_COUNT_TX_MAX,
			 LL_LENGTH_OCTETS_RX_MAX, RADIO_PACKET_TX_DATA_SIZE,
			 &_radio[0], sizeof(_radio));
	if (err) {
		BT_ERR("Required RAM size: %d, supplied: %u.", err,
		       sizeof(_radio));
		return -ENOMEM;
	}

	/* reset whitelist, resolving list and initialise RPA timeout*/
	if (IS_ENABLED(CONFIG_BT_CTLR_FILTER)) {
		ll_filter_reset(true);
	}

	IRQ_DIRECT_CONNECT(RADIO_IRQn, CONFIG_BT_CTLR_WORKER_PRIO,
			   radio_nrf5_isr, 0);
	IRQ_CONNECT(RTC0_IRQn, CONFIG_BT_CTLR_WORKER_PRIO, rtc0_nrf5_isr, NULL,
		    0);
	IRQ_CONNECT(SWI5_IRQn, CONFIG_BT_CTLR_JOB_PRIO, swi5_nrf5_isr, NULL, 0);

	irq_enable(RADIO_IRQn);
	irq_enable(RTC0_IRQn);
	irq_enable(SWI5_IRQn);

	return 0;
}

void ll_timeslice_ticker_id_get(u8_t *const instance_index, u8_t *const user_id)
{
	*user_id =
		(TICKER_NODES -
		 FLASH_TICKER_NODES); /* The last index in the total tickers */
	*instance_index = RADIO_TICKER_INSTANCE_ID_RADIO;
}
