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
 * \addtogroup native_timer
 *@{*/

#ifndef _XENO_TIMER_H
#define _XENO_TIMER_H

#include <native/types.h>

#define TM_ONESHOT XN_APERIODIC_TICK

/** Structure containing timer-information useful to users.
 *
 *  @see rt_timer_inquire()
 */
typedef struct rt_timer_info {

    RTIME period;	/* !< Current status (unset, aperiodic, period). */
    RTIME date;		/* !< Current wallclock time. */
    RTIME tsc;          /* !< Current tsc count. */

} RT_TIMER_INFO;

#if defined(__KERNEL__) || defined(__XENO_SIM__)

#include <nucleus/timer.h>

extern xntbase_t *__native_tbase;

#endif /* __KERNEL__ || __XENO_SIM__ */

#ifdef __cplusplus
extern "C" {
#endif

#if (defined(__KERNEL__)  || defined(__XENO_SIM__)) && !defined(DOXYGEN_CPP)
static inline SRTIME rt_timer_ns2tsc(SRTIME ns)
{
	return xnarch_ns_to_tsc(ns);
}

static inline SRTIME rt_timer_tsc2ns(SRTIME ticks)
{
	return xnarch_tsc_to_ns(ticks);
}

static inline RTIME rt_timer_tsc(void)
{
	return xnarch_get_cpu_tsc();
}

static inline RTIME rt_timer_read(void)
{
	return xntbase_get_time(__native_tbase);
}

static inline SRTIME rt_timer_ns2ticks(SRTIME ns)
{
	return xntbase_ns2ticks(__native_tbase, ns);
}

static inline SRTIME rt_timer_ticks2ns(SRTIME ticks)
{
	return xntbase_ticks2ns(__native_tbase, ticks);
}

#else /* !(__KERNEL__ || __XENO_SIM__) */

/**
 * @fn SRTIME rt_timer_ns2tsc(SRTIME ns)
 * @brief Convert nanoseconds to local CPU clock ticks.
 *
 * Convert a count of nanoseconds to local CPU clock ticks.
 * This routine operates on signed nanosecond values.
 *
 * @param ns The count of nanoseconds to convert.
 *
 * @return The corresponding value expressed in CPU clock ticks.
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

SRTIME rt_timer_ns2tsc(SRTIME ns);

/*!
 * @fn SRTIME rt_timer_tsc2ns(SRTIME ticks)
 * @brief Convert local CPU clock ticks to nanoseconds.
 *
 * Convert a local CPU clock ticks to nanoseconds.
 * This routine operates on signed tick values.
 *
 * @param ticks The count of local CPU clock ticks to convert.
 *
 * @return The corresponding value expressed in nanoseconds.
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

SRTIME rt_timer_tsc2ns(SRTIME ticks);

/*!
 * @fn RTIME rt_timer_tsc(void)
 * @brief Return the current TSC value.
 *
 * Return the value of the time stamp counter (TSC) maintained by the
 * CPU of the underlying architecture.
 *
 * @return The current value of the TSC.
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

RTIME rt_timer_tsc(void);

/*!
 * @fn RTIME rt_timer_read(void)
 * @brief Return the current system time.
 *
 * Return the current time maintained by the master time base.
 *
 * @return The current time expressed in clock ticks (see note).
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
 *
 * @note The value returned will represent a count of jiffies if the
 * native skin is bound to a periodic time base (see
 * CONFIG_XENO_OPT_NATIVE_PERIOD), or nanoseconds otherwise.
 */

RTIME rt_timer_read(void);

/**
 * @fn SRTIME rt_timer_ns2ticks(SRTIME ns)
 * @brief Convert nanoseconds to internal clock ticks.
 *
 * Convert a count of nanoseconds to internal clock ticks.
 * This routine operates on signed nanosecond values.
 *
 * @param ns The count of nanoseconds to convert.
 *
 * @return The corresponding value expressed in internal clock ticks.
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

SRTIME rt_timer_ns2ticks(SRTIME ns);

/*!
 * @fn SRTIME rt_timer_ticks2ns(SRTIME ticks)
 * @brief Convert internal clock ticks to nanoseconds.
 *
 * Convert a count of internal clock ticks to nanoseconds.
 * This routine operates on signed tick values.
 *
 * @param ticks The count of internal clock ticks to convert.
 *
 * @return The corresponding value expressed in nanoseconds.
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

SRTIME rt_timer_ticks2ns(SRTIME ticks);

#endif /* !(__KERNEL__ || __XENO_SIM__) */

int rt_timer_inquire(RT_TIMER_INFO *info);

RTIME rt_timer_read(void);

void rt_timer_spin(RTIME ns);

int rt_timer_set_mode(RTIME nstick);

static inline int __deprecated_call__
rt_timer_start(RTIME nstick __attribute__((unused)))
{
    return 0;
}

static inline void __deprecated_call__ rt_timer_stop(void)
{
}

#ifdef __cplusplus
}
#endif

/*@}*/

#endif /* !_XENO_TIMER_H */
