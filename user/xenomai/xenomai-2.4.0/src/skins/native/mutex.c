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

extern int __native_muxid;

int rt_mutex_create(RT_MUTEX *mutex, const char *name)
{
	return XENOMAI_SKINCALL2(__native_muxid,
				 __native_mutex_create, mutex, name);
}

int rt_mutex_bind(RT_MUTEX *mutex, const char *name, RTIME timeout)
{
	return XENOMAI_SKINCALL3(__native_muxid,
				 __native_mutex_bind, mutex, name, &timeout);
}

int rt_mutex_delete(RT_MUTEX *mutex)
{
	return XENOMAI_SKINCALL1(__native_muxid, __native_mutex_delete, mutex);
}

int rt_mutex_acquire(RT_MUTEX *mutex, RTIME timeout)
{
	return XENOMAI_SKINCALL2(__native_muxid,
				 __native_mutex_acquire, mutex, &timeout);
}

int rt_mutex_release(RT_MUTEX *mutex)
{
	return XENOMAI_SKINCALL1(__native_muxid, __native_mutex_release, mutex);
}

int rt_mutex_inquire(RT_MUTEX *mutex, RT_MUTEX_INFO *info)
{
	return XENOMAI_SKINCALL2(__native_muxid,
				 __native_mutex_inquire, mutex, info);
}

/* Compatibility wrappers for pre-2.3 builds. */

int rt_mutex_lock(RT_MUTEX *mutex, RTIME timeout)
{
    return rt_mutex_acquire(mutex, timeout);
}

int rt_mutex_unlock(RT_MUTEX *mutex)
{
    return rt_mutex_release(mutex);
}
