/*
 * File:         drivers/char/bfin_timer_latency.c
 * Based on:
 * Author:       Luke Yang
 *
 * Created:
 * Description:  Simple driver for testing interrupt latencies.
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright 2005-2006 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see the file COPYING, or write
 * to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <asm/blackfin.h>
#include <asm/irq.h>

#undef DEBUG

#ifdef DEBUG
# define DPRINTK(x...)	printk(KERN_DEBUG x)
#else
# define DPRINTK(x...)	do { } while (0)
#endif

struct timer_latency_data_t {
	char value;
	unsigned long  latency;
};

struct proc_dir_entry *timer_latency_file;
struct timer_latency_data_t timer_latency_data;

static int read_timer_latency(char *page, char **start,
			      off_t offset, int count, int *eof,
			      void *data)
{
	return sprintf(page, "%lu", timer_latency_data.latency);
}


static int write_timer_latency(struct file *file, const char *buffer,
			   unsigned long count, void *data)
{
	unsigned long sclk;
	char user_value;

	copy_from_user(&(user_value), buffer, 1);

	if ((user_value == '1') && (timer_latency_data.value == 0)) {
		DPRINTK("start timer_latency\n");
		timer_latency_data.value = 1;
		sclk = get_sclk();
		bfin_write_WDOG_CNT(5 * sclk); /* set count time to 5 seconds */
		/* set CYCLES counter to 0 and start it*/
		__asm__(
			"R2 = 0;\n\t"
			"CYCLES = R2;\n\t"
			"CYCLES2 = R2;\n\t"
			"R2 = SYSCFG;\n\t"
			"BITSET(R2,1);\n\t"

			"P2.H = 0xffc0;\n\t"
			"P2.L = 0x0200;\n\t"
			"R3 = 0x0004;\n\t"
			"W[P2] = R3;\n\t"
			"SYSCFG = R2;\n\t"    /* start cycles counter */
		);

	}

	return 1;  /* always write 1 byte*/
}


static irqreturn_t timer_latency_irq(int irq, void *dev_id, struct pt_regs *regs)
{
	struct timer_latency_data_t *data = dev_id;

	unsigned long cycles_past, cclk;
	unsigned long latency;

	/* unsigned long first_latency, second_latency, third_latency; */


	/* get current cycle counter */
	/*
	asm("%0 = CYCLES; p2 = 0xFFE07040; %1 = [p2]; p2 = 0xFFE07044; %2 = [p2]; p2 = 0xFFE07048; %3 = [p2];"
	: "=d" (cycles_past), "=d" (first_latency), "=d" (second_latency), "=d" (third_latency):); */

	asm("%0 = CYCLES;"
	    : "=d" (cycles_past));

	bfin_write_WDOG_CTL(0x8AD6);  /* close counter */
	bfin_write_WDOG_CTL(0x8AD6);  /* have to write it twice to disable the timer */

	__asm__(                      /* stop CYCLES counter */
		"R2 = SYSCFG;\n\t"
		"BITCLR(R2,1);\n\t"
		"SYSCFG = R2;\n\t"
	);

	cclk = get_cclk();

	/* printk("first_latency is %lu, second is %lu, third is %lu, latency is %lu\n", first_latency, second_latency, third_latency, cycles_past); */

	latency = cycles_past - (cclk * 5);    /* latency in us */
	DPRINTK("latecy is %lu\n",latency);

	if (bfin_read_WDOG_STAT() != 0) {
		DPRINTK("timer_latency error!\n");
		return IRQ_HANDLED;
	}

	data->latency = latency;
	timer_latency_data.value = 0;

	return IRQ_HANDLED;
}


static int __init timer_latency_init(void)
{
	DPRINTK("timer_latency start!\n");

	timer_latency_file = create_proc_entry("timer_latency", 0666, NULL);
	if (timer_latency_file == NULL)
		return -ENOMEM;

	/* default value is 0 (timer is stopped) */
	timer_latency_data.value = 0;
	timer_latency_data.latency = 0;

	timer_latency_file->data = &timer_latency_data;
	timer_latency_file->read_proc = &read_timer_latency;
	timer_latency_file->write_proc = &write_timer_latency;
	timer_latency_file->owner = THIS_MODULE;

	request_irq(IRQ_WATCH, timer_latency_irq, SA_INTERRUPT, "timer_latency", &timer_latency_data);

	printk(KERN_INFO "timer_latency module loaded\n");

	return 0; /* everything's OK */
}


static void __exit timer_latency_exit(void)
{
	remove_proc_entry("timer_latency", NULL);
	free_irq(IRQ_WATCH, NULL);
	printk(KERN_INFO "timer_latency module removed\n");
}

module_init(timer_latency_init);
module_exit(timer_latency_exit);

MODULE_AUTHOR("Luke Yang");
MODULE_DESCRIPTION("Timer Latency testing module");
MODULE_LICENSE("GPL");
