/*
 *  arch/bfinnommu/mach-bf533/config.c
 *
 *  Copyright (C) 1999 D. Jeff Dionne
 *  Copyright (C) 2004 LG Soft India (Blackfin support)
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of this archive
 * for more details.
 */

#include <stdarg.h>
#include <linux/config.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/console.h>
#include <linux/interrupt.h>  
#include <asm/current.h>

#include <asm/setup.h>
#include <asm/system.h>
#include <asm/pgtable.h>
#include <asm/irq.h>
#include <asm/blackfin.h>

#include <asm/bf533_rtc.h>

/*
 * By setting TSCALE such that TCOUNT counts a binary fraction
 * of microseconds, we can read TCOUNT directly and then with
 * a logical shift trivially calculate how many microseconds 
 * since the last tick, allowing do_gettimeofday() to yield
 * far better time resolution for real time benchmarking.
 */

extern u_long get_cclk(void);

#define TSCALE_SHIFT 2	/* 0.25 microseconds */
#define TSCALE_COUNT ((get_cclk()/1000000) >> TSCALE_SHIFT)
#define CLOCKS_PER_JIFFY ((1000*1000/HZ) << TSCALE_SHIFT)


void time_sched_init(irqreturn_t (*timer_routine)(int, void *, struct pt_regs *))
{
	/* power up the timer, but don't enable it just yet */

	*pTCNTL = 1;
	asm("csync;");

	/* make TCOUNT a binary fraction of microseconds using
	* the TSCALE prescaler counter.
	*/

	*pTSCALE = TSCALE_COUNT - 1;
	asm("csync;");
	*pTCOUNT = *pTPERIOD = CLOCKS_PER_JIFFY - 1;
	asm("csync;");

	/* now enable the timer */
	
	*pTCNTL = 7;
	asm("csync;");

	/* set up the timer irq */

	request_irq(IRQ_CORETMR, timer_routine, IRQ_FLG_LOCK, "timer", NULL);
	enable_irq(IRQ_CORETMR);
}

unsigned long gettimeoffset (void)
{
	return (CLOCKS_PER_JIFFY - *pTCOUNT) >> TSCALE_SHIFT;
}
