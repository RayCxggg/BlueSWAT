/*
 * Copyright (c) 2016 Linaro Limited.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <drivers/counter.h>
#include <device.h>
#include <errno.h>
#include <init.h>
#include <soc.h>
#include <drivers/clock_control/arm_clock_control.h>

#include "dualtimer_cmsdk_apb.h"

typedef void (*dtimer_config_func_t)(struct device *dev);

struct dtmr_cmsdk_apb_cfg {
	struct counter_config_info info;
	volatile struct dualtimer_cmsdk_apb *dtimer;
	dtimer_config_func_t dtimer_config_func;
	/* Dualtimer Clock control in Active State */
	const struct arm_clock_control_t dtimer_cc_as;
	/* Dualtimer Clock control in Sleep State */
	const struct arm_clock_control_t dtimer_cc_ss;
	/* Dualtimer Clock control in Deep Sleep State */
	const struct arm_clock_control_t dtimer_cc_dss;
};

struct dtmr_cmsdk_apb_dev_data {
	counter_top_callback_t top_callback;
	void *top_user_data;
	u32_t load;
};

static int dtmr_cmsdk_apb_start(struct device *dev)
{
	const struct dtmr_cmsdk_apb_cfg * const cfg =
						dev->config->config_info;
	struct dtmr_cmsdk_apb_dev_data *data = dev->driver_data;

	/* Set the timer reload to count */
	cfg->dtimer->timer1load = data->load;

	/* Enable the dualtimer in 32 bit mode */
	cfg->dtimer->timer1ctrl = (DUALTIMER_CTRL_EN | DUALTIMER_CTRL_SIZE_32);

	return 0;
}

static int dtmr_cmsdk_apb_stop(struct device *dev)
{
	const struct dtmr_cmsdk_apb_cfg * const cfg =
						dev->config->config_info;

	/* Disable the dualtimer */
	cfg->dtimer->timer1ctrl = 0x0;

	return 0;
}

static int dtmr_cmsdk_apb_get_value(struct device *dev, u32_t *ticks)
{
	const struct dtmr_cmsdk_apb_cfg * const cfg =
						dev->config->config_info;
	struct dtmr_cmsdk_apb_dev_data *data = dev->driver_data;

	*ticks = data->load - cfg->dtimer->timer1value;
	return 0;
}

static int dtmr_cmsdk_apb_set_top_value(struct device *dev,
					const struct counter_top_cfg *top_cfg)
{
	const struct dtmr_cmsdk_apb_cfg * const cfg =
						dev->config->config_info;
	struct dtmr_cmsdk_apb_dev_data *data = dev->driver_data;

	data->top_callback = top_cfg->callback;
	data->top_user_data = top_cfg->user_data;

	/* Store the reload value */
	data->load = top_cfg->ticks;

	/* Set the timer to count */
	if (top_cfg->flags & COUNTER_TOP_CFG_DONT_RESET) {
		/*
		 * Write to background load register will not affect
		 * the current value of the counter.
		 */
		cfg->dtimer->timer1bgload = top_cfg->ticks;
	} else {
		/*
		 * Write to load register will also set
		 * the current value of the counter.
		 */
		cfg->dtimer->timer1load = top_cfg->ticks;
	}

	/* Enable IRQ */
	cfg->dtimer->timer1ctrl |= (DUALTIMER_CTRL_INTEN
				    | DUALTIMER_CTRL_MODE);

	return 0;
}

static u32_t dtmr_cmsdk_apb_get_top_value(struct device *dev)
{
	struct dtmr_cmsdk_apb_dev_data *data = dev->driver_data;

	u32_t ticks = data->load;

	return ticks;
}

static u32_t dtmr_cmsdk_apb_get_pending_int(struct device *dev)
{
	const struct dtmr_cmsdk_apb_cfg * const cfg =
						dev->config->config_info;

	return cfg->dtimer->timer1ris;
}

static const struct counter_driver_api dtmr_cmsdk_apb_api = {
	.start = dtmr_cmsdk_apb_start,
	.stop = dtmr_cmsdk_apb_stop,
	.get_value = dtmr_cmsdk_apb_get_value,
	.set_top_value = dtmr_cmsdk_apb_set_top_value,
	.get_pending_int = dtmr_cmsdk_apb_get_pending_int,
	.get_top_value = dtmr_cmsdk_apb_get_top_value,
};

static void dtmr_cmsdk_apb_isr(void *arg)
{
	struct device *dev = (struct device *)arg;
	struct dtmr_cmsdk_apb_dev_data *data = dev->driver_data;
	const struct dtmr_cmsdk_apb_cfg * const cfg =
						dev->config->config_info;

	cfg->dtimer->timer1intclr = DUALTIMER_INTCLR;
	if (data->top_callback) {
		data->top_callback(dev, data->top_user_data);
	}
}

static int dtmr_cmsdk_apb_init(struct device *dev)
{
	const struct dtmr_cmsdk_apb_cfg * const cfg =
						dev->config->config_info;

#ifdef CONFIG_CLOCK_CONTROL
	/* Enable clock for subsystem */
	struct device *clk =
		device_get_binding(CONFIG_ARM_CLOCK_CONTROL_DEV_NAME);

#ifdef CONFIG_SOC_SERIES_BEETLE
	clock_control_on(clk, (clock_control_subsys_t *) &cfg->dtimer_cc_as);
	clock_control_on(clk, (clock_control_subsys_t *) &cfg->dtimer_cc_ss);
	clock_control_on(clk, (clock_control_subsys_t *) &cfg->dtimer_cc_dss);
#endif /* CONFIG_SOC_SERIES_BEETLE */
#endif /* CONFIG_CLOCK_CONTROL */

	cfg->dtimer_config_func(dev);

	return 0;
}

/* TIMER 0 */
#ifdef DT_INST_0_ARM_CMSDK_DTIMER
static void dtimer_cmsdk_apb_config_0(struct device *dev);

static const struct dtmr_cmsdk_apb_cfg dtmr_cmsdk_apb_cfg_0 = {
	.info = {
			.max_top_value = UINT32_MAX,
			.freq = 24000000U,
			.flags = 0,
			.channels = 0U,
	},
	.dtimer = ((volatile struct dualtimer_cmsdk_apb *)DT_INST_0_ARM_CMSDK_DTIMER_BASE_ADDRESS),
	.dtimer_config_func = dtimer_cmsdk_apb_config_0,
	.dtimer_cc_as = {.bus = CMSDK_APB, .state = SOC_ACTIVE,
			 .device = DT_INST_0_ARM_CMSDK_DTIMER_BASE_ADDRESS,},
	.dtimer_cc_ss = {.bus = CMSDK_APB, .state = SOC_SLEEP,
			 .device = DT_INST_0_ARM_CMSDK_DTIMER_BASE_ADDRESS,},
	.dtimer_cc_dss = {.bus = CMSDK_APB, .state = SOC_DEEPSLEEP,
			  .device = DT_INST_0_ARM_CMSDK_DTIMER_BASE_ADDRESS,},
};

static struct dtmr_cmsdk_apb_dev_data dtmr_cmsdk_apb_dev_data_0 = {
	.load = UINT_MAX,
};

DEVICE_AND_API_INIT(dtmr_cmsdk_apb_0,
		    DT_INST_0_ARM_CMSDK_DTIMER_LABEL,
		    dtmr_cmsdk_apb_init,
		    &dtmr_cmsdk_apb_dev_data_0,
		    &dtmr_cmsdk_apb_cfg_0, POST_KERNEL,
		    CONFIG_KERNEL_INIT_PRIORITY_DEVICE,
		    &dtmr_cmsdk_apb_api);

static void dtimer_cmsdk_apb_config_0(struct device *dev)
{
	IRQ_CONNECT(DT_INST_0_ARM_CMSDK_DTIMER_IRQ_0,
		    DT_INST_0_ARM_CMSDK_DTIMER_IRQ_0_PRIORITY,
		    dtmr_cmsdk_apb_isr,
		    DEVICE_GET(dtmr_cmsdk_apb_0), 0);
	irq_enable(DT_INST_0_ARM_CMSDK_DTIMER_IRQ_0);
}
#endif /* DT_INST_0_ARM_CMSDK_DTIMER */
