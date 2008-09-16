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

int sc_mcreate(unsigned int opt, int *errp)
{
	int mid = -1;

	*errp = XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_mcreate, opt, &mid);
	return mid;
}

void sc_mdelete(int mid, int opt, int *errp)
{
	*errp = XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_mdelete, mid, opt);
}

void sc_mpost(int mid, int *errp)
{
	*errp = XENOMAI_SKINCALL1(__vrtx_muxid, __vrtx_mpost, mid);
}

void sc_maccept(int mid, int *errp)
{
	*errp = XENOMAI_SKINCALL1(__vrtx_muxid, __vrtx_maccept, mid);
}

void sc_mpend(int mid, unsigned long timeout, int *errp)
{
	*errp = XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_mpend, mid, timeout);
}

int sc_minquiry(int mid, int *errp)
{
	int status = 0;

	*errp = XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_minquiry, mid, &status);
	return status;
}
