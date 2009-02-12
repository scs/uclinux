/*
 * Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
 *
 * Xenomai is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _XENO_ASM_X86_BITS_INIT_32_H
#define _XENO_ASM_X86_BITS_INIT_32_H
#define _XENO_ASM_X86_BITS_INIT_H

#ifndef __KERNEL__
#error "Pure kernel header included from user-space!"
#endif

#include <linux/init.h>
#include <asm/xenomai/calibration.h>

int xnarch_escalation_virq;

int xnpod_trap_fault(xnarch_fltinfo_t *fltinfo);

void xnpod_schedule_handler(void);

static rthal_trap_handler_t xnarch_old_trap_handler;

static int xnarch_trap_fault(unsigned event, unsigned domid, void *data)
{
	struct pt_regs *regs = (struct pt_regs *)data;
	xnarch_fltinfo_t fltinfo;

	fltinfo.vector = event;
	fltinfo.errcode = regs->x86reg_origax;
	fltinfo.regs = regs;

	return xnpod_trap_fault(&fltinfo);
}

static inline unsigned long xnarch_calibrate_timer(void)
{
	/* Compute the time needed to program the PIT in aperiodic
	   mode. The return value is expressed in CPU ticks. Depending
	   on whether CONFIG_X86_LOCAL_APIC is enabled or not in the
	   kernel configuration Xenomai is compiled against, the
	   calibrated value will either refer to the local APIC or
	   8254 timer latency value. */
	return xnarch_ns_to_tsc(rthal_timer_calibrate())? : 1;
}

int xnarch_calibrate_sched(void)
{
	nktimerlat = xnarch_calibrate_timer();

	if (!nktimerlat)
		return -ENODEV;

	nklatency = xnarch_ns_to_tsc(xnarch_get_sched_latency()) + nktimerlat;

	return 0;
}

static inline int xnarch_init(void)
{
	extern unsigned xnarch_tsc_scale, xnarch_tsc_shift, xnarch_tsc_divide;
	int err;

	err = rthal_init();

	if (err)
		return err;

#if defined(CONFIG_SMP) && defined(MODULE)
	/* Make sure the init sequence is kept on the same CPU when
	   running as a module. */
	set_cpus_allowed(current, cpumask_of_cpu(0));
#endif /* CONFIG_SMP && MODULE */

	xnarch_init_llmulshft(1000000000, RTHAL_CPU_FREQ,
			      &xnarch_tsc_scale, &xnarch_tsc_shift);
	xnarch_tsc_divide = 1 << xnarch_tsc_shift;

	err = xnarch_calibrate_sched();

	if (err)
		return err;

	xnarch_escalation_virq = rthal_alloc_virq();

	if (xnarch_escalation_virq == 0)
		return -ENOSYS;

	rthal_virtualize_irq(&rthal_domain,
			     xnarch_escalation_virq,
			     (rthal_irq_handler_t) & xnpod_schedule_handler,
			     NULL, NULL, IPIPE_HANDLE_MASK | IPIPE_WIRED_MASK);

	xnarch_old_trap_handler = rthal_trap_catch(&xnarch_trap_fault);

	return 0;
}

static inline void xnarch_exit(void)
{
	rthal_trap_catch(xnarch_old_trap_handler);
	rthal_free_virq(xnarch_escalation_virq);
	rthal_exit();
}

#endif /* !_XENO_ASM_X86_BITS_INIT_32_H */
