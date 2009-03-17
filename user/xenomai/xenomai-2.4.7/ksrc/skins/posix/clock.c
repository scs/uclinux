/*
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>.
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

/**
 * @ingroup posix
 * @defgroup posix_time Clocks and timers services.
 *
 * Clocks and timers services.
 *
 * Xenomai POSIX skin supports two clocks:
 *
 * CLOCK_REALTIME maps to the nucleus system clock, keeping time as the amount
 * of time since the Epoch, with a resolution of one system clock tick.
 *
 * CLOCK_MONOTONIC maps to an architecture-dependent high resolution counter, so
 * is suitable for measuring short time intervals. However, when used for
 * sleeping (with clock_nanosleep()), the CLOCK_MONOTONIC clock has a resolution
 * of one system clock tick, like the CLOCK_REALTIME clock.
 *
 * Timer objects may be created with the timer_create() service using either of
 * the two clocks, but the resolution of these timers is one system clock tick,
 * as is the case for clock_nanosleep().
 *
 * @note The duration of the POSIX clock tick depends on the active
 * time base (configurable at compile-time with the constant @a
 * CONFIG_XENO_OPT_POSIX_PERIOD, and at run-time with the @a
 * xeno_posix module parameter @a tick_arg). When the time base is
 * aperiodic (which is the default) the system clock tick is one
 * nanosecond.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/xsh_chap02_08.html#tag_02_08_05">
 * Specification.</a>
 *
 *@{*/

#include <posix/thread.h>

/**
 * Get the resolution of the specified clock.
 *
 * This service returns, at the address @a res, if it is not @a NULL, the
 * resolution of the clock @a clock_id.
 *
 * For both CLOCK_REALTIME and CLOCK_MONOTONIC, this resolution is the duration
 * of one system clock tick. No other clock is supported.
 *
 * @param clock_id clock identifier, either CLOCK_REALTIME or CLOCK_MONOTONIC;
 *
 * @param res the address where the resolution of the specified clock will be
 * stored on success.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - EINVAL, @a clock_id is invalid;
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/clock_getres.html">
 * Specification.</a>
 * 
 */
int clock_getres(clockid_t clock_id, struct timespec *res)
{
	if (clock_id != CLOCK_MONOTONIC && clock_id != CLOCK_REALTIME) {
		thread_set_errno(EINVAL);
		return -1;
	}

	if (res)
		ticks2ts(res, 1);

	return 0;
}

/**
 * Read the specified clock. 
 *
 * This service returns, at the address @a tp the current value of the clock @a
 * clock_id. If @a clock_id is:
 * - CLOCK_REALTIME, the clock value represents the amount of time since the
 *   Epoch, with a precision of one system clock tick;
 * - CLOCK_MONOTONIC, the clock value is given by an architecture-dependent high
 *   resolution counter, with a precision independent from the system clock tick
 *   duration.
 *
 * @param clock_id clock identifier, either CLOCK_REALTIME or CLOCK_MONOTONIC;
 *
 * @param tp the address where the value of the specified clock will be stored.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - EINVAL, @a clock_id is invalid.
 * 
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/clock_gettime.html">
 * Specification.</a>
 * 
 */
int clock_gettime(clockid_t clock_id, struct timespec *tp)
{
	xnticks_t cpu_time;

	switch (clock_id) {
	case CLOCK_REALTIME:
		ticks2ts(tp, xntbase_get_time(pse51_tbase));
		break;

	case CLOCK_MONOTONIC:
		cpu_time = xnpod_get_cpu_time();
		tp->tv_sec =
		    xnarch_uldivrem(cpu_time, ONE_BILLION, &tp->tv_nsec);
		break;

	default:
		thread_set_errno(EINVAL);
		return -1;
	}

	return 0;
}

/**
 * Set the specified clock.
 *
 * This allow setting the CLOCK_REALTIME clock.
 *
 * @param clock_id the id of the clock to be set, only CLOCK_REALTIME is
 * supported.
 *
 * @param tp the address of a struct timespec specifying the new date.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - EINVAL, @a clock_id is not CLOCK_REALTIME;
 * - EINVAL, the date specified by @a tp is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/clock_settime.html">
 * Specification.</a>
 * 
 */
int clock_settime(clockid_t clock_id, const struct timespec *tp)
{
	xnticks_t now, new_date;
	spl_t s;

	if (clock_id != CLOCK_REALTIME
	    || (unsigned long)tp->tv_nsec >= ONE_BILLION) {
		thread_set_errno(EINVAL);
		return -1;
	}

	new_date = ts2ticks_floor(tp);

	xnlock_get_irqsave(&nklock, s);
	now = xntbase_get_time(pse51_tbase);
	xntbase_adjust_time(pse51_tbase, (xnsticks_t) (new_date - now));
	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Sleep some amount of time.
 *
 * This service suspends the calling thread until the wakeup time specified by
 * @a rqtp, or a signal is delivered to the caller. If the flag TIMER_ABSTIME is
 * set in the @a flags argument, the wakeup time is specified as an absolute
 * value of the clock @a clock_id. If the flag TIMER_ABSTIME is not set, the
 * wakeup time is specified as a time interval.
 *
 * If this service is interrupted by a signal, the flag TIMER_ABSTIME is not
 * set, and @a rmtp is not @a NULL, the time remaining until the specified
 * wakeup time is returned at the address @a rmtp.
 *
 * The resolution of this service is one system clock tick.
 *
 * @param clock_id clock identifier, either CLOCK_REALTIME or CLOCK_MONOTONIC.
 *
 * @param flags one of:
 * - 0 meaning that the wakeup time @a rqtp is a time interval;
 * - TIMER_ABSTIME, meaning that the wakeup time is an absolute value of the
 *   clock @a clock_id.
 *
 * @param rqtp address of the wakeup time.
 *
 * @param rmtp address where the remaining time before wakeup will be stored if
 * the service is interrupted by a signal.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EPERM, the caller context is invalid;
 * - ENOTSUP, the specified clock is unsupported;
 * - EINVAL, the specified wakeup time is invalid;
 * - EINTR, this service was interrupted by a signal.
 *
 * @par Valid contexts:
 * - Xenomai kernel-space thread,
 * - Xenomai user-space thread (switches to primary mode).
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/clock_nanosleep.html">
 * Specification.</a>
 * 
 */
int clock_nanosleep(clockid_t clock_id,
		    int flags,
		    const struct timespec *rqtp, struct timespec *rmtp)
{
	xnthread_t *cur;
	spl_t s;
	int err = 0;

	if (xnpod_unblockable_p())
		return EPERM;

	if (clock_id != CLOCK_MONOTONIC && clock_id != CLOCK_REALTIME)
		return ENOTSUP;

	if ((unsigned long)rqtp->tv_nsec >= ONE_BILLION)
		return EINVAL;

	if (flags & ~TIMER_ABSTIME)
		return EINVAL;

	cur = xnpod_current_thread();

	xnlock_get_irqsave(&nklock, s);

	thread_cancellation_point(cur);

	xnpod_suspend_thread(cur, XNDELAY, ts2ticks_ceil(rqtp) + 1,
			     clock_flag(flags, clock_id), NULL);

	thread_cancellation_point(cur);

	if (xnthread_test_info(cur, XNBREAK)) {

		if (flags == 0 && rmtp) {
			xnticks_t now, expiry;
			xnsticks_t rem;

			now = clock_get_ticks(clock_id);
			expiry = xntimer_get_date(&cur->rtimer);
			xnlock_put_irqrestore(&nklock, s);
			rem = expiry - now;

			ticks2ts(rmtp, rem > 0 ? rem : 0);
		} else
			xnlock_put_irqrestore(&nklock, s);

		return EINTR;
	}

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * Sleep some amount of time.
 *
 * This service suspends the calling thread until the wakeup time specified by
 * @a rqtp, or a signal is delivered. The wakeup time is specified as a time
 * interval.
 *
 * If this service is interrupted by a signal and @a rmtp is not @a NULL, the
 * time remaining until the specified wakeup time is returned at the address @a
 * rmtp.
 *
 * The resolution of this service is one system clock tick.
 *
 * @param rqtp address of the wakeup time.
 *
 * @param rmtp address where the remaining time before wakeup will be stored if
 * the service is interrupted by a signal.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - EPERM, the caller context is invalid;
 * - EINVAL, the specified wakeup time is invalid;
 * - EINTR, this service was interrupted by a signal.
 *
 * @par Valid contexts:
 * - Xenomai kernel-space thread,
 * - Xenomai user-space thread (switches to primary mode).
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/nanosleep.html">
 * Specification.</a>
 * 
 */
int nanosleep(const struct timespec *rqtp, struct timespec *rmtp)
{
	int err = clock_nanosleep(CLOCK_REALTIME, 0, rqtp, rmtp);

	if (!err)
		return 0;

	thread_set_errno(err);
	return -1;
}

/*@}*/

EXPORT_SYMBOL(clock_getres);
EXPORT_SYMBOL(clock_gettime);
EXPORT_SYMBOL(clock_settime);
EXPORT_SYMBOL(clock_nanosleep);
EXPORT_SYMBOL(nanosleep);
