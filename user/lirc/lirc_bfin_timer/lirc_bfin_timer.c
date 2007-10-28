/*
 * lirc_bfin_timer.c - LIRC driver using Blackfin timers
 *
 * Enter bugs at http://blackfin.uclinux.org/
 *
 * Copyright 2007 Analog Devices Inc.
 * Licensed under the GPL-2 or later.
 */

#define DEBUG

#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>

#include "drivers/lirc.h"
#include "drivers/lirc_dev/lirc_dev.h"

#include <asm/gptimers.h>
#include <asm/portmux.h>

#define SWAP(x,y) \
	do { \
		typeof(x) __tmp = x; \
		x = y; \
		y = __tmp; \
	} while (0);

static unsigned long clamp_usecs_hi = 5000, clamp_sclk_hi;
module_param(clamp_usecs_hi, ulong, 0644);
MODULE_PARM_DESC(clamp_usecs_hi, "Max time in usecs for sample (default = 5000)");

static unsigned long clamp_usecs_lo = 5, clamp_sclk_lo;
module_param(clamp_usecs_lo, ulong, 0644);
MODULE_PARM_DESC(clamp_usecs_lo, "Min time in usecs for sample (default = 5)");

static int sense = 0;
module_param(sense, bool, 0444);
MODULE_PARM_DESC(sense, "Active IR level (0 = active high, 1 = active low)");

/* BF537-EZKIT Timers Header:
 *   PIN      FUNCTION
 *    1        PF2 (Timer 7)
 *    2        5V
 *    3        PF3 (Timer 6)
 *    4        3.3V
 *    5        PF4 (Timer 5)
 *    6        PF9 (Timer 0)
 *    7        nothing
 *    8        PF8 (Timer 1)
 *    9        Ground
 *   10        PF7 (Timer 2)
 */

#define DRIVER_NAME "lirc_bfin_gptimers"

#define pr_stamp() pr_debug(DRIVER_NAME ":%i:%s: here i am\n", __LINE__, __func__)

struct bfin_gptimer {
	const char *name;
	int irq, id, bit, mux;
	uint32_t width, period;
	bool opened, skip_next_sample;
	struct lirc_plugin plugin;
	struct lirc_buffer lirc_buf;
};

static void gptimer_queue_sample(struct bfin_gptimer *g)
{
	lirc_t code[2];

	pr_stamp();

	code[0] = PULSE_BIT | (sclk_to_usecs(g->width) & PULSE_MASK);
	code[1] = sclk_to_usecs(g->period - g->width) & PULSE_MASK;

	if (lirc_buffer_full(&g->lirc_buf))
		printk(KERN_NOTICE DRIVER_NAME ": buffer full, throwing away sample\n");
	else
		lirc_buffer_write_n(&g->lirc_buf, (void *)code, ARRAY_SIZE(code));

	wake_up(&g->lirc_buf.wait_poll);
}

static irqreturn_t gptimer_irq(int irq, void *dev_id)
{
	struct bfin_gptimer *g = dev_id;

	pr_stamp();

	/* see if it was our timer */
	if (!get_gptimer_intr(g->id))
		return IRQ_NONE;

	/* check for overflow and queue ignore */
	if (get_gptimer_over(g->id)) {
		clear_gptimer_over(g->id);
		g->skip_next_sample = true;
		goto finish;
	}

	/* if previous irq was an overflow, skip this */
	if (g->skip_next_sample == true) {
		g->skip_next_sample = false;
		goto finish;
	}

	/* record this sample ! */
	g->width = get_gptimer_pwidth(g->id);
	g->period = get_gptimer_period(g->id);

	pr_debug(DRIVER_NAME ":irq: "
		"sclk = 0x%08lx, "
		"period = 0x%08x (%li usecs), "
		"width = 0x%08x (%li usecs), "
		"space = %li usecs\n",
		get_sclk(),
		g->period, sclk_to_usecs(g->period),
		g->width, sclk_to_usecs(g->width),
		sclk_to_usecs(g->period) - sclk_to_usecs(g->width));

	/* only queue up good samples */
	if (g->period <= clamp_sclk_hi && g->period >= clamp_sclk_lo)
		gptimer_queue_sample(g);

 finish:
	clear_gptimer_intr(g->id);

	return IRQ_HANDLED;
}

static int gptimer_ioctl(struct inode *node, struct file *filep,
                         unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
		case LIRC_GET_REC_RESOLUTION:
			return put_user(sclk_to_usecs(1), (unsigned long *)arg);
		default:
			return -ENOIOCTLCMD;
	}
}

/* Called when userspace opens up our device */
static int gptimer_set_use_inc(void *data)
{
	struct bfin_gptimer *g = data;
	int ret;

	pr_stamp();

	if (g->opened == true)
		return -EBUSY;

	/* request the timer peripheral */
	ret = peripheral_request(g->mux, g->name);
	if (ret) {
		printk(KERN_NOTICE DRIVER_NAME " peripheral_request() failed\n");
		return ret;
	}

	/* grab the irq for this timer */
	ret = request_irq(g->irq, gptimer_irq, IRQF_SHARED, g->name, g);
	if (ret) {
		printk(KERN_NOTICE DRIVER_NAME ": request_irq() failed\n");
		peripheral_free(g->mux);
		return ret;
	}

	/* configure the timer and enable it */
	g->skip_next_sample = false;
	set_gptimer_config(g->id, WDTH_CAP | (sense ? PULSE_HI : 0) | PERIOD_CNT | IRQ_ENA);
	enable_gptimers(g->bit);

	g->opened = true;

	return 0;
}

/* Called when userspace closes our device */
static void gptimer_set_use_dec(void *data)
{
	struct bfin_gptimer *g = data;

	pr_stamp();

	disable_gptimers(g->bit);

	free_irq(g->irq, g);

	peripheral_free(g->mux);

	g->opened = false;
}

/* XXX: move this to platform data in a boards file */
static struct bfin_gptimer timer5 = {
	.name   = DRIVER_NAME "5",
	.irq    = IRQ_TMR5,
	.id     = TIMER5_id,
	.bit    = TIMER5bit,
	.mux    = P_TMR5,
};
static struct lirc_plugin __initdata plugin_template = {
	.name         = DRIVER_NAME,
	.minor        = -1,
	.code_length  = sizeof(lirc_t) * 8,
	.sample_rate  = 0,
	.features     = LIRC_CAN_REC_MODE2,
	.data         = NULL,
	.add_to_buf   = NULL,
	.get_queue    = NULL,
	.rbuf         = NULL,
	.set_use_inc  = gptimer_set_use_inc,
	.set_use_dec  = gptimer_set_use_dec,
	.ioctl        = gptimer_ioctl,
	.fops         = NULL,
	.dev          = NULL,
	.owner        = THIS_MODULE,
};

static int __init lirc_bfin_timer_init(void)
{
	struct bfin_gptimer *g = &timer5;
	int ret;

	pr_stamp();

	/* this optimization will not fair well with changing of
	 * kernel clocks on the fly ...
	 */
	clamp_sclk_hi = usecs_to_sclk(clamp_usecs_hi);
	clamp_sclk_lo = usecs_to_sclk(clamp_usecs_lo);

	/* init the plugin data */
	g->opened = false;
	g->plugin = plugin_template;
	g->plugin.data = g;
	g->plugin.rbuf = &g->lirc_buf;
	ret = lirc_buffer_init(&g->lirc_buf, sizeof(lirc_t), 64);
	if (ret) {
		printk(KERN_NOTICE DRIVER_NAME ": lirc_buffer_init() failed\n");
		return ret;
	}

	/* register the lirq plugin */
	ret = lirc_register_plugin(&g->plugin);
	if (ret < 0) {
		printk(KERN_NOTICE DRIVER_NAME ": lirc_register_plugin() failed\n");
		lirc_buffer_free(&g->lirc_buf);
		return ret;
	}

	printk(KERN_INFO DRIVER_NAME ": driver registered\n");

	return 0;
}
module_init(lirc_bfin_timer_init);

static void __exit lirc_bfin_timer_exit(void)
{
	struct bfin_gptimer *g = &timer5;

	pr_stamp();

	lirc_buffer_free(&g->lirc_buf);
	lirc_unregister_plugin(g->plugin.minor);
}
module_exit(lirc_bfin_timer_exit);

MODULE_AUTHOR("Mike Frysinger <vapier@gentoo.org>");
MODULE_DESCRIPTION("LIRC driver using Blackfin general purpose timers");
MODULE_LICENSE("GPL");
