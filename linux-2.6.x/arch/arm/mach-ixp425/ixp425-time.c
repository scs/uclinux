/*
 * arch/arm/mach-ixp425/ixp425-time.c
 *
 * Timer tick for IXP425 based sytems. We use OS timer1 on the CPU for
 * the timer tick and the timestamp counter to account for missed jiffies.
 *
 * Author:  Peter Barry
 * Copyright:   (C) 2001 Intel Corporation.
 * 		(C) 2002-2003 MontaVista Software, Inc.
 *
 * Maintainer: Deepak Saxena <dsaxena@mvista.com>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */


#include <linux/config.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/smp.h>

#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/irq.h>

#include <linux/timex.h>
#include <asm/hardware.h>

static unsigned volatile last_jiffy_time;

#define CLOCK_TICKS_PER_USEC	(CLOCK_TICK_RATE / USEC_PER_SEC)

/* IRQs are disabled before entering here from do_gettimeofday() */
static unsigned long ixp425_gettimeoffset(void)
{
	u32 elapsed;

	elapsed = *IXP425_OSTS - last_jiffy_time;

	return elapsed / CLOCK_TICKS_PER_USEC;
}

static irqreturn_t ixp425_timer_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	unsigned long flags;

	/* Clear Pending Interrupt by writing '1' to it */
	*IXP425_OSST = IXP425_OSST_TIMER_1_PEND;

	/*
	 * Catch up with the real idea of time
	 */
	do {	
		local_irq_save(flags);
		do_timer(regs);
		last_jiffy_time += LATCH;
		local_irq_restore(flags);
	} while((*IXP425_OSTS - last_jiffy_time) > LATCH);

	return IRQ_HANDLED;
}

extern unsigned long (*gettimeoffset)(void);

static struct irqaction timer_irq = {
	name: "Timer Tick"
};

void __init time_init(void)
{
	gettimeoffset = ixp425_gettimeoffset;
	timer_irq.handler = ixp425_timer_interrupt;

	/* Clear Pending Interrupt by writing '1' to it */
	*IXP425_OSST = IXP425_OSST_TIMER_1_PEND;

	/* Setup the Timer counter value */
	*IXP425_OSRT1 = (LATCH & ~IXP425_OST_RELOAD_MASK) | IXP425_OST_ENABLE;

	/* Reset time-stamp counter */
	*IXP425_OSTS = 0;
	last_jiffy_time = 0;

	/* Connect the interrupt handler and enable the interrupt */
	setup_irq(IRQ_IXP425_TIMER1, &timer_irq);
}


