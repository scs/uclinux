/*
 * Copyright (C) 2001,2002,2003,2004,2005 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef _XENO_ASM_X86_CALIBRATION_H
#define _XENO_ASM_X86_CALIBRATION_H

#ifndef _XENO_ASM_X86_BITS_INIT_H
#error "please don't include asm/calibration.h directly"
#endif

#include <asm/processor.h>

static inline unsigned long xnarch_get_sched_latency (void)
{
	unsigned long sched_latency;

#if CONFIG_XENO_OPT_TIMING_SCHEDLAT != 0
	sched_latency = CONFIG_XENO_OPT_TIMING_SCHEDLAT;
#else
#ifdef CONFIG_X86_LOCAL_APIC
	sched_latency = 1000;
#else /* !CONFIG_X86_LOCAL_APIC */
	/*
	 * Use the bogomips formula to identify low-end x86 boards when using
	 * the 8254 PIT. The following is still grossly experimental and needs
	 * work (i.e. more specific cases), but the approach is definitely
	 * saner than previous attempts to guess such value dynamically.
	 */
#define __bogomips (current_cpu_data.loops_per_jiffy/(500000/HZ))
	sched_latency = (__bogomips < 250 ? 17000 :
                         __bogomips < 2500 ? 4200 :
			 3500);
#undef __bogomips
#endif /* CONFIG_X86_LOCAL_APIC */
#endif /* CONFIG_XENO_OPT_TIMING_SCHEDLAT */

	return sched_latency;
}

#endif /* !_XENO_ASM_X86_CALIBRATION_H */
