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

#include <psos+/psos.h>

extern int __psos_muxid;

u_long sm_create(const char name[4], u_long icount, u_long flags, u_long *smid_r)
{
	return XENOMAI_SKINCALL4(__psos_muxid, __psos_sm_create,
				 name, icount, flags, smid_r);
}

u_long sm_delete(u_long smid)
{
	return XENOMAI_SKINCALL1(__psos_muxid, __psos_sm_delete, smid);
}

u_long sm_p(u_long smid, u_long flags, u_long timeout)
{
	return XENOMAI_SKINCALL3(__psos_muxid, __psos_sm_p, smid, 
				 flags, timeout);
}

u_long sm_v(u_long smid)
{
	return XENOMAI_SKINCALL1(__psos_muxid, __psos_sm_v, smid);
}
