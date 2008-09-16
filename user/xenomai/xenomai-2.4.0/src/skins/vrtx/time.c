/*
 * Copyright (C) 2006 Philippe Gerum <rpm@xenomai.org>.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 */

#include <vrtx/vrtx.h>

extern int __vrtx_muxid;

void sc_delay(long timeout)
{
	XENOMAI_SKINCALL1(__vrtx_muxid, __vrtx_delay, timeout);
}

void sc_adelay(struct timespec time, int *errp)
{
	*errp = XENOMAI_SKINCALL1(__vrtx_muxid, __vrtx_adelay, &time);
}

void sc_stime(unsigned long ticks)
{
	XENOMAI_SKINCALL1(__vrtx_muxid, __vrtx_stime, ticks);
}

unsigned long sc_gtime(void)
{
	unsigned long ticks;

	XENOMAI_SKINCALL1(__vrtx_muxid, __vrtx_gtime, &ticks);
	return ticks;
}

void sc_sclock(struct timespec time, unsigned long ns, int *errp)
{
	*errp = XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_sclock, &time, ns);
}

void sc_gclock(struct timespec *timep, unsigned long *nsp, int *errp)
{
	*errp = XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_gclock, timep, nsp);
}
