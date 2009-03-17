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
#include <native/sem.h>

extern int __native_muxid;

int rt_sem_create(RT_SEM *sem, const char *name, unsigned long icount, int mode)
{
	return XENOMAI_SKINCALL4(__native_muxid,
				 __native_sem_create, sem, name, icount, mode);
}

int rt_sem_bind(RT_SEM *sem, const char *name, RTIME timeout)
{
	return XENOMAI_SKINCALL3(__native_muxid,
				 __native_sem_bind, sem, name, &timeout);
}

int rt_sem_delete(RT_SEM *sem)
{
	return XENOMAI_SKINCALL1(__native_muxid, __native_sem_delete, sem);
}

int rt_sem_p(RT_SEM *sem, RTIME timeout)
{
	return XENOMAI_SKINCALL2(__native_muxid, __native_sem_p, sem, &timeout);
}

int rt_sem_v(RT_SEM *sem)
{
	return XENOMAI_SKINCALL1(__native_muxid, __native_sem_v, sem);
}

int rt_sem_broadcast(RT_SEM *sem)
{
	return XENOMAI_SKINCALL1(__native_muxid, __native_sem_broadcast, sem);
}

int rt_sem_inquire(RT_SEM *sem, RT_SEM_INFO *info)
{
	return XENOMAI_SKINCALL2(__native_muxid, __native_sem_inquire, sem,
				 info);
}
