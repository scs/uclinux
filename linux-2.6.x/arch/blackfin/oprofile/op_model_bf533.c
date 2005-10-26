/*
 * Copyright (C) 2004 Anton Blanchard <anton@au.ibm.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/oprofile.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <asm/ptrace.h>
#include <asm/system.h>
#include <asm/processor.h>
#include <asm/blackfin.h>
#include <asm/irq.h>
#include <asm/io.h>

#include "op_blackfin.h"

#define dbg(args...) printk(args)
#define PM_ENABLE 0x01;
#define PM_CTL1_ENABLE  0x18
#define PM_CTL0_ENABLE  0xC000
#define COUNT_EDGE_ONLY 0x3000000

static int oprofile_running;

unsigned curr_pfctl, curr_count[2];

static int bfin533_handle_interrupt(int irq, void *dummy, struct pt_regs *regs);

static int bfin533_reg_setup(struct op_counter_config *ctr)
{
	unsigned int pfctl = ctr_read();
	unsigned int count[2];

	/* set Blackfin perf monitor regs with ctr */
	if (ctr[0].enabled) {
		pfctl |= (PM_CTL0_ENABLE | ((char)ctr[0].event << 5));
		count[0] = 0xFFFFFFFF - ctr[0].count;
		curr_count[0] = count[0];
	}
	if (ctr[1].enabled) {
		pfctl |= (PM_CTL1_ENABLE | ((char)ctr[1].event << 16));
		count[1] = 0xFFFFFFFF - ctr[1].count;
		curr_count[1] = count[1];
	}

	pfctl |= COUNT_EDGE_ONLY;
	curr_pfctl = pfctl;

	ctr_write(pfctl);
	count_write(count);

	return 0;
}

static int bfin533_start(struct op_counter_config *ctr)
{
	int ret;
	unsigned int pfctl = ctr_read();

	/* Install our interrupt handler into the existing hook.  */
	ret = request_irq(IRQ_HWERR, bfin533_handle_interrupt, IRQ_FLG_STD,
			  "Blackfin Perfmon", NULL);
	if (ret < 0) {
		dbg(KERN_ERR "oprofile: unable to request IRQ for perfmon.\n");
		return ret;
	} else {
		dbg("requested hardware errorr IRQ. \n");
	}

	pfctl |= PM_ENABLE;
	curr_pfctl = pfctl;

	ctr_write(pfctl);

	oprofile_running = 1;
	dbg("start oprofile counter \n");

	enable_irq(IRQ_HWERR);

	return 0;
}

static void bfin533_stop(void)
{
	int pfctl;

	pfctl = ctr_read();
	pfctl &= ~PM_ENABLE;
	/* freeze counters */
	ctr_write(pfctl);

	oprofile_running = 0;
	free_irq(IRQ_HWERR, NULL);
	dbg("stop oprofile counter \n");
}

static int get_kernel(void)
{
	int ipend, is_kernel;

	ipend = *pIPEND;

	/* test bit 15 */
	is_kernel = ((ipend & 0x8000) != 0);

	return is_kernel;
}

static int bfin533_handle_interrupt(int irq, void *dummy, struct pt_regs *regs)
{
	int is_kernel;
	int i, cpu;
	unsigned int pc, pfctl;
	unsigned int count[2];

	if (oprofile_running == 0) {
		dbg("error: entering interrupt when oprofile is stopped.\n\r");
		return -1;
	}

	is_kernel = get_kernel();
	cpu = smp_processor_id();
	pc = regs->pc;
	pfctl = ctr_read();

	/* read the two event counter regs */
	count_read(count);

	/* if the counter overflows, add sample to oprofile buffer */
	for (i = 0; i < 2; ++i) {
		if (oprofile_running && (count[i] == 0xFFFFFFFF)) {
			oprofile_add_sample(pc, is_kernel, i, cpu);
		}
	}

	/* reset the perfmon counter */
	ctr_write(curr_pfctl);
	count_write(curr_count);
	return 0;
}

struct op_bfin533_model op_model_bfin533 = {
	.reg_setup = bfin533_reg_setup,
	.start = bfin533_start,
	.stop = bfin533_stop,
	.num_counters = 2,
	.name = "Blackfin 533"
};
