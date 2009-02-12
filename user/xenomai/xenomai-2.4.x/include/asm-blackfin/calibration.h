/*
 * Copyright (C) 2005 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef _XENO_ASM_BLACKFIN_CALIBRATION_H
#define _XENO_ASM_BLACKFIN_CALIBRATION_H

#ifndef _XENO_ASM_BLACKFIN_BITS_INIT_H
#error "please don't include asm/calibration.h directly"
#endif

static inline unsigned long xnarch_get_sched_latency (void)

{
#if CONFIG_XENO_OPT_TIMING_SCHEDLAT != 0
#define __sched_latency CONFIG_XENO_OPT_TIMING_SCHEDLAT
#else
#ifdef CONFIG_BF533
#define __sched_latency 20000
#elif defined(CONFIG_BF537)
#define __sched_latency 7500
#elif defined(CONFIG_BF561)
#define __sched_latency 3000
#elif defined(CONFIG_BF54x)
#define __sched_latency 3000
#elif defined(CONFIG_BF52x)
#define __sched_latency 3000
#else
#error "unsupported Blackfin processor"
#endif
#endif /* CONFIG_XENO_OPT_TIMING_SCHEDLAT */

    return __sched_latency;
}

#undef __sched_latency

#endif /* !_XENO_ASM_BLACKFIN_CALIBRATION_H */
