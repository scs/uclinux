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

#include <sys/time.h>
#include <time.h>
#include <psos+/psos.h>

extern int __psos_muxid;

extern xnsysinfo_t __psos_sysinfo;

u_long tm_wkafter(u_long ticks)
{
	return XENOMAI_SKINCALL1(__psos_muxid, __psos_tm_wkafter, ticks);
}

u_long tm_cancel(u_long tmid)
{
	return XENOMAI_SKINCALL1(__psos_muxid, __psos_tm_cancel, tmid);
}

u_long tm_evafter(u_long ticks, u_long events, u_long *tmid_r)
{
	return XENOMAI_SKINCALL3(__psos_muxid, __psos_tm_evafter, ticks, events, tmid_r);
}

u_long tm_get(u_long *date_r, u_long *time_r, u_long *ticks_r)
{
	return XENOMAI_SKINCALL3(__psos_muxid, __psos_tm_get, date_r, time_r, ticks_r);
}

u_long tm_set(u_long date, u_long time, u_long ticks)
{
	if (date == 0 && time == 0 && ticks == 0) {
		struct timeval tv;
		struct tm tm;
		gettimeofday(&tv, NULL);
		localtime_r(&tv.tv_sec, &tm);
		date = ((tm.tm_year + 1900) << 16)|((tm.tm_mon + 1) << 8)|tm.tm_mday;
		time = (tm.tm_hour << 16)|(tm.tm_min << 8)|tm.tm_sec;
		ticks = tv.tv_usec / ((__psos_sysinfo.tickval ?: 1) / 1000);
	}

	return XENOMAI_SKINCALL3(__psos_muxid, __psos_tm_set, date, time, ticks);
}

u_long tm_evwhen(u_long date, u_long time, u_long ticks, u_long events, u_long *tmid_r)
{
	return XENOMAI_SKINCALL5(__psos_muxid, __psos_tm_evwhen, date, time, ticks, events, tmid_r);
}

u_long tm_wkwhen(u_long date, u_long time, u_long ticks)
{
	return XENOMAI_SKINCALL3(__psos_muxid, __psos_tm_wkwhen, date, time, ticks);
}

u_long tm_evevery(u_long ticks, u_long events, u_long *tmid_r)
{
	return XENOMAI_SKINCALL3(__psos_muxid, __psos_tm_evevery, ticks, events, tmid_r);
}

u_long tm_getm(unsigned long long *ns_r) /* Xenomai extension. */
{
	return XENOMAI_SKINCALL1(__psos_muxid, __psos_tm_getm, ns_r);
}

u_long tm_signal(u_long value, u_long interval, int signo, u_long *tmid_r) /* Xenomai extension. */
{
	return XENOMAI_SKINCALL4(__psos_muxid, __psos_tm_signal, value, interval, signo, tmid_r);
}

u_long tm_getc(unsigned long long *ticks_r) /* Xenomai extension. */
{
	return XENOMAI_SKINCALL1(__psos_muxid, __psos_tm_getc, ticks_r);
}
