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
#include <native/alarm.h>

extern int __native_muxid;

int rt_alarm_create(RT_ALARM *alarm, const char *name)
{
	return XENOMAI_SKINCALL2(__native_muxid,
				 __native_alarm_create, alarm, name);
}

int rt_alarm_delete(RT_ALARM *alarm)
{
	return XENOMAI_SKINCALL1(__native_muxid, __native_alarm_delete, alarm);
}

int rt_alarm_wait(RT_ALARM *alarm)
{
	return XENOMAI_SKINCALL1(__native_muxid, __native_alarm_wait, alarm);
}

int rt_alarm_start(RT_ALARM *alarm, RTIME value, RTIME interval)
{
	return XENOMAI_SKINCALL3(__native_muxid,
				 __native_alarm_start, alarm, &value,
				 &interval);
}

int rt_alarm_stop(RT_ALARM *alarm)
{
	return XENOMAI_SKINCALL1(__native_muxid, __native_alarm_stop, alarm);
}

int rt_alarm_inquire(RT_ALARM *alarm, RT_ALARM_INFO *info)
{
	return XENOMAI_SKINCALL2(__native_muxid,
				 __native_alarm_inquire, alarm, info);
}
