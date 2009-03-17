/*
 * Copyright (C) 2005 Philippe Gerum <rpm@xenomai.org>.
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

#include <sys/types.h>
#include <stdio.h>
#include <native/syscall.h>
#include <native/intr.h>

extern int __native_muxid;

int rt_intr_create(RT_INTR *intr, const char *name, unsigned irq, int mode)
{
	return XENOMAI_SKINCALL4(__native_muxid,
				 __native_intr_create, intr, name, irq, mode);
}

int rt_intr_bind(RT_INTR *intr, const char *name, RTIME timeout)
{
	return XENOMAI_SKINCALL3(__native_muxid,
				 __native_intr_bind, intr, name, &timeout);
}

int rt_intr_delete(RT_INTR *intr)
{
	return XENOMAI_SKINCALL1(__native_muxid, __native_intr_delete, intr);
}

int rt_intr_wait(RT_INTR *intr, RTIME timeout)
{
	return XENOMAI_SKINCALL2(__native_muxid,
				 __native_intr_wait, intr, &timeout);
}

int rt_intr_enable(RT_INTR *intr)
{
	return XENOMAI_SKINCALL1(__native_muxid, __native_intr_enable, intr);
}

int rt_intr_disable(RT_INTR *intr)
{
	return XENOMAI_SKINCALL1(__native_muxid, __native_intr_disable, intr);
}

int rt_intr_inquire(RT_INTR *intr, RT_INTR_INFO *info)
{
	return XENOMAI_SKINCALL2(__native_muxid, __native_intr_inquire, intr,
				 info);
}
