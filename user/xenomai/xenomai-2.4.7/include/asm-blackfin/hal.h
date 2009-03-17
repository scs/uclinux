/**
 *   @ingroup hal
 *   @file
 *
 *   Real-Time Hardware Abstraction Layer for the Blackfin.
 *
 *   Copyright &copy; 2005 Philippe Gerum.
 *
 *   Xenomai is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License as
 *   published by the Free Software Foundation, Inc., 675 Mass Ave,
 *   Cambridge MA 02139, USA; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   Xenomai is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Xenomai; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 *   02111-1307, USA.
 */

#ifndef _XENO_ASM_BLACKFIN_HAL_H
#define _XENO_ASM_BLACKFIN_HAL_H

#include <asm-generic/xenomai/hal.h>	/* Read the generic bits. */
#include <asm/div64.h>

#define RTHAL_TIMER_DEVICE	"coretmr"
#define RTHAL_CLOCK_DEVICE	"cyclectr"

typedef unsigned long long rthal_time_t;

static inline __attribute_const__ unsigned long ffnz(unsigned long ul)
{
	return ffs(ul) - 1;
}

#ifndef __cplusplus
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
#include <asm/irqchip.h>
#else
#include <linux/irq.h>
#endif
#include <asm/system.h>
#include <asm/blackfin.h>
#include <asm/processor.h>
#include <asm/xenomai/atomic.h>

#define RTHAL_TIMER_IRQ		IRQ_CORETMR
/* The NMI watchdog timer is clocked by the system clock. */
#define RTHAL_NMICLK_FREQ	get_sclk()

#define rthal_irq_descp(irq)	(&irq_desc[(irq)])

#define rthal_grab_control()     do { } while(0)
#define rthal_release_control()  do { } while(0)

static inline unsigned long long rthal_rdtsc(void)
{
	unsigned long long t;
	rthal_read_tsc(t);
	return t;
}

static inline void rthal_timer_program_shot(unsigned long delay)
{
	if (delay < 2)
		rthal_trigger_irq(RTHAL_TIMER_IRQ);
	else {
		bfin_write_TCOUNT(delay - 1);
		CSYNC();
		bfin_write_TCNTL(3);	/* Oneshot mode, no auto-reload. */
		CSYNC();
	}
}

    /* Private interface -- Internal use only */

#ifdef CONFIG_XENO_OPT_TIMING_PERIODIC
extern int rthal_periodic_p;
#else /* !CONFIG_XENO_OPT_TIMING_PERIODIC */
#define rthal_periodic_p  0
#endif /* CONFIG_XENO_OPT_TIMING_PERIODIC */

asmlinkage struct task_struct *rthal_thread_switch(struct thread_struct *prev,
						   struct thread_struct *next);

asmlinkage void rthal_thread_trampoline(void);

asmlinkage int rthal_defer_switch_p(void);

static const char *const rthal_fault_labels[] = {
	[1] = "Single step",
	[4] = "TAS",
	[17] = "Performance Monitor Overflow",
	[33] = "Undefined instruction",
	[34] = "Illegal instruction",
	[36] = "Data access misaligned",
	[35] = "DCPLB fault",
	[37] = "Unrecoverable event",
	[38] = "DCPLB fault",
	[39] = "DCPLB fault",
	[40] = "Watchpoint",
	[42] = "Instruction fetch misaligned",
	[41] = "Undef",
	[43] = "ICPLB fault",
	[44] = "ICPLB fault",
	[45] = "ICPLB fault",
	[46] = "Illegal resource",
	[47] = NULL
};

#endif /* !__cplusplus */

#endif /* !_XENO_ASM_BLACKFIN_HAL_H */
