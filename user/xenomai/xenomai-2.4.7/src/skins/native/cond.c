/*
 * Copyright (C) 2001,2002,2003,2004 Philippe Gerum <rpm@xenomai.org>.
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

#include <native/syscall.h>
#include <native/mutex.h>
#include <native/cond.h>

extern int __native_muxid;

int rt_cond_create(RT_COND *cond, const char *name)
{
	return XENOMAI_SKINCALL2(__native_muxid, __native_cond_create, cond,
				 name);
}

int rt_cond_bind(RT_COND *cond, const char *name, RTIME timeout)
{
	return XENOMAI_SKINCALL3(__native_muxid,
				 __native_cond_bind, cond, name, &timeout);
}

int rt_cond_delete(RT_COND *cond)
{
	return XENOMAI_SKINCALL1(__native_muxid, __native_cond_delete, cond);
}

int rt_cond_wait(RT_COND *cond, RT_MUTEX *mutex, RTIME timeout)
{
	return XENOMAI_SKINCALL3(__native_muxid,
				 __native_cond_wait, cond, mutex, &timeout);
}

int rt_cond_signal(RT_COND *cond)
{
	return XENOMAI_SKINCALL1(__native_muxid, __native_cond_signal, cond);
}

int rt_cond_broadcast(RT_COND *cond)
{
	return XENOMAI_SKINCALL1(__native_muxid, __native_cond_broadcast, cond);
}

int rt_cond_inquire(RT_COND *cond, RT_COND_INFO *info)
{
	return XENOMAI_SKINCALL2(__native_muxid, __native_cond_inquire, cond,
				 info);
}
