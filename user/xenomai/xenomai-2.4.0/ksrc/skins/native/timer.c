/**
 * @file
 * This file is part of the Xenomai project.
 *
 * @note Copyright (C) 2004 Philippe Gerum <rpm@xenomai.org> 
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
 *
 * \ingroup native_timer
 */

/*!
 * \ingroup native
 * \defgroup native_timer Timer management services.
 *
 * Timer-related services allow to control the Xenomai system timer which
 * is used in all timed operations.
 *
 *@{*/

#include <nucleus/pod.h>
#include <native/timer.h>

/*!
 * @fn int rt_timer_inquire(RT_TIMER_INFO *info)
 * @brief Inquire about the timer.
 *
 * Return various information about the status of the system timer.
 *
 * @param info The address of a structure the timer information will
 * be written to.
 *
 * @return This service always returns 0.
 *
 * The information block returns the period and the current system
 * date. The period can have the following values:
 *
 * - TM_UNSET is a special value indicating that the system timer is
 * inactive. A call to rt_timer_set_mode() re-activates it.
 *
 * - TM_ONESHOT is a special value indicating that the timer has been
 * set up in oneshot mode.
 *
 * - Any other period value indicates that the system timer is
 * currently running in periodic mode; it is a count of nanoseconds
 * representing the period of the timer, i.e. the duration of a
 * periodic tick or "jiffy".
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 */

int rt_timer_inquire(RT_TIMER_INFO *info)
{
	RTIME period, tsc;

	if (xntbase_periodic_p(__native_tbase))
		period = xntbase_get_tickval(__native_tbase);
	else
		period = TM_ONESHOT;

	tsc = xnarch_get_cpu_tsc();
	info->period = period;
	info->tsc = tsc;

#ifdef CONFIG_XENO_OPT_TIMING_PERIODIC
	if (period != TM_ONESHOT)
		info->date = xntbase_get_time(__native_tbase);
	else
#endif /* CONFIG_XENO_OPT_TIMING_PERIODIC */
		/* In aperiodic mode, our idea of time is the same as the
		   CPU's, and a tick equals a nanosecond. */
		info->date = xnarch_tsc_to_ns(tsc) + __native_tbase->wallclock_offset;

	return 0;
}

/**
 * @fn void rt_timer_spin(RTIME ns)
 * @brief Busy wait burning CPU cycles.
 *
 * Enter a busy waiting loop for a count of nanoseconds. The precision
 * of this service largely depends on the availability of a time stamp
 * counter on the current CPU.
 *
 * Since this service is usually called with interrupts enabled, the
 * caller might be preempted by other real-time activities, therefore
 * the actual delay might be longer than specified.
 *
 * @param ns The time to wait expressed in nanoseconds.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 */

void rt_timer_spin(RTIME ns)
{
	RTIME etime = xnarch_get_cpu_tsc() + xnarch_ns_to_tsc(ns);

	while ((SRTIME)(xnarch_get_cpu_tsc() - etime) < 0)
		cpu_relax();
}

/**
 * @fn int rt_timer_set_mode(RTIME nstick)
 * @brief Set the system clock rate.
 *
 * This routine switches to periodic timing mode and sets the clock
 * tick rate, or resets the current timing mode to aperiodic/oneshot
 * mode depending on the value of the @a nstick parameter. Since the
 * native skin automatically sets its time base according to the
 * configured policy and period at load time (see
 * CONFIG_XENO_OPT_NATIVE_PERIOD), calling rt_timer_set_mode() is not
 * required from applications unless the pre-defined mode and period
 * need to be changed dynamically.
 *
 * This service sets the time unit which will be relevant when
 * specifying time intervals to the services taking timeout or delays
 * as input parameters. In periodic mode, clock ticks will represent
 * periodic jiffies. In oneshot mode, clock ticks will represent
 * nanoseconds.
 *
 * @param nstick The time base period in nanoseconds. If this
 * parameter is equal to the special TM_ONESHOT value, the time base
 * is set to operate in a tick-less fashion (i.e. oneshot mode). Other
 * values are interpreted as the time between two consecutive clock
 * ticks in periodic timing mode (i.e. clock HZ = 1e9 / nstick).
 *
 * @return 0 is returned on success. Otherwise:
 *
 * - -ENODEV is returned if the underlying architecture does not
 * support the requested periodic timing. Aperiodic/oneshot timing is
 * always supported.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - User-space task
 *
 * Rescheduling: never.
 */

int rt_timer_set_mode(RTIME nstick)
{
	return xntbase_switch("native", nstick, &__native_tbase);
}

/*@}*/

EXPORT_SYMBOL(rt_timer_ns2ticks);
EXPORT_SYMBOL(rt_timer_ticks2ns);
EXPORT_SYMBOL(rt_timer_inquire);
EXPORT_SYMBOL(rt_timer_spin);
EXPORT_SYMBOL(rt_timer_set_mode);
EXPORT_SYMBOL(__native_tbase);
