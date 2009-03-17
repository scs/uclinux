/*
 * Copyright (C) 2001-2007 Philippe Gerum <rpm@xenomai.org>.
 *
 * Xenomai is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
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
 *
 * Core pod definitions. The core pod supports all APIs. Core APIs,
 * namely POSIX, native and RTDM, only use a sub-range of the
 * available priority levels of the core pod, in order to have them
 * exhibit a 1:1 mapping with Linux's SCHED_FIFO ascending priority
 * scale [1..99]. Non-core APIs which exhibit inverted priority scales
 * (e.g. VxWorks, VRTX), should normalize the priority values
 * internally when calling the priority-sensitive services of the
 * nucleus, so that they fit in the available range provided by the
 * latter.
 */

#ifndef _XENO_NUCLEUS_CORE_H
#define _XENO_NUCLEUS_CORE_H

/* Visible priority range supported by the core pod. */
#define XNCORE_MIN_PRIO     0
#define XNCORE_MAX_PRIO     257
/* Idle priority of the root thread scheduled within the core pod. */
#define XNCORE_IDLE_PRIO    -1

/* Total number of priority levels (including the hidden root one) */
#define XNCORE_NR_PRIO      (XNCORE_MAX_PRIO - XNCORE_IDLE_PRIO + 1)

/* Priority sub-range used by core APIs. */
#define XNCORE_LOW_PRIO     0
#define XNCORE_HIGH_PRIO    99

/* Priority of IRQ servers in user-space. */
#define XNCORE_IRQ_PRIO     XNCORE_MAX_PRIO

#define XNCORE_PAGE_SIZE		512 /* A reasonable value for the xnheap page size */
#define XNCORE_PAGE_MASK  		(~(XNCORE_PAGE_SIZE-1))
#define XNCORE_PAGE_ALIGN(addr)	(((addr)+XNCORE_PAGE_SIZE-1)&XNCORE_PAGE_MASK)

#endif /* !_XENO_NUCLEUS_CORE_H */
