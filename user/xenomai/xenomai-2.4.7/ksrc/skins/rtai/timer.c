/**
 *
 * @note Copyright (C) 2004 Philippe Gerum <rpm@xenomai.org> 
 * @note Copyright (C) 2005 Nextream France S.A.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <nucleus/pod.h>
#include <rtai/task.h>
#include <rtai/timer.h>

void rt_set_oneshot_mode(void)
{
	xntbase_switch("rtai", XN_APERIODIC_TICK, &rtai_tbase);
	/* The master aperiodic time base is already (and always)
	   started. */
}

void rt_set_periodic_mode(void)
{
}

RTIME start_rt_timer(int period)
{
	/* count2nano() and nano2count() are no-ops, so we should have
	   been passed nanoseconds. */
	xntbase_switch("rtai", period, &rtai_tbase);
	xntbase_start(rtai_tbase);
	return period;
}

void stop_rt_timer(void)
{
	xntbase_stop(rtai_tbase);
}

void rt_sleep(RTIME delay)
{
	if (delay <= 0)
		return;

	xnpod_suspend_thread(&rtai_current_task()->thread_base,
			     XNDELAY, delay, XN_RELATIVE, NULL);
}

RTIME rt_get_time_ns(void)
{
	RTIME ticks = xntbase_get_time(rtai_tbase);
	return xntbase_ticks2ns(rtai_tbase, ticks);
}

EXPORT_SYMBOL(rt_set_oneshot_mode);
EXPORT_SYMBOL(rt_set_periodic_mode);
EXPORT_SYMBOL(start_rt_timer);
EXPORT_SYMBOL(stop_rt_timer);
EXPORT_SYMBOL(rt_sleep);
EXPORT_SYMBOL(rt_get_time_ns);
