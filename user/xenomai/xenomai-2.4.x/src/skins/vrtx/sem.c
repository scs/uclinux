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

int sc_screate(unsigned initval, int opt, int *errp)
{
	int semid = -1;

	*errp = XENOMAI_SKINCALL3(__vrtx_muxid,
				  __vrtx_screate, initval, opt, &semid);
	return semid;
}

void sc_sdelete(int semid, int opt, int *errp)
{
	*errp = XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_sdelete, semid, opt);
}

void sc_spost(int semid, int *errp)
{
	*errp = XENOMAI_SKINCALL1(__vrtx_muxid, __vrtx_spost, semid);
}

void sc_spend(int semid, long timeout, int *errp)
{
	*errp = XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_spend, semid, timeout);
}

void sc_saccept(int semid, int *errp)
{
	*errp = XENOMAI_SKINCALL1(__vrtx_muxid, __vrtx_saccept, semid);
}

int sc_sinquiry(int semid, int *errp)
{
	int count_r = -1;

	*errp = XENOMAI_SKINCALL2(__vrtx_muxid,
				  __vrtx_sinquiry, semid, &count_r);
	return count_r;
}
