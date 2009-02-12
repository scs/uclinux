/*
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@laposte.net>.
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
 * @ingroup posix_thread
 * @defgroup posix_sched Threads scheduling services.
 *
 * Thread scheduling services.
 *
 * Xenomai POSIX skin supports the scheduling policies SCHED_FIFO, SCHED_RR and
 * SCHED_OTHER.
 *
 * The SCHED_OTHER policy is mainly useful for user-space non-realtime
 * activities that need to synchronize with real-time activities.
 *
 * The SCHED_RR policy is only effective if the time base is periodic
 * (i.e. if configured with the compilation constant @a
 * CONFIG_XENO_OPT_POSIX_PERIOD or the @a xeno_nucleus module
 * parameter @a tick_arg set to a non null value). The SCHED_RR
 * round-robin time slice is configured with the @a xeno_posix module
 * parameter @a time_slice, as a count of system timer clock ticks.
 *
 * The SCHED_SPORADIC policy is not supported.
 *
 * The scheduling policy and priority of a thread is set when creating a thread,
 * by using thread creation attributes (see pthread_attr_setinheritsched(),
 * pthread_attr_setschedpolicy() and pthread_attr_setschedparam()), or when the
 * thread is already running by using the service pthread_setschedparam().
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/xsh_chap02_08.html#tag_02_08_04">
 * Specification.</a>
 *
 *@{*/

#include <posix/thread.h>

/**
 * Get minimum priority of the specified scheduling policy.
 *
 * This service returns the minimum priority of the scheduling policy @a
 * policy.
 *
 * @param policy scheduling policy, one of SCHED_FIFO, SCHED_RR, or
 * SCHED_OTHER.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - EINVAL, @a policy is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/sched_get_priority_min.html">
 * Specification.</a>
 * 
 */
int sched_get_priority_min(int policy)
{
	switch (policy) {
	case SCHED_FIFO:
	case SCHED_RR:
		return PSE51_MIN_PRIORITY;

	case SCHED_OTHER:
		return 0;

	default:
		thread_set_errno(EINVAL);
		return -1;
	}
}

/**
 * Get maximum priority of the specified scheduling policy.
 *
 * This service returns the maximum priority of the scheduling policy @a
 * policy.
 *
 * @param policy scheduling policy, one of SCHED_FIFO, SCHED_RR, or
 * SCHED_OTHER.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - EINVAL, @a policy is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/sched_get_priority_max.html">
 * Specification.</a>
 *
 */
int sched_get_priority_max(int policy)
{
	switch (policy) {
	case SCHED_FIFO:
	case SCHED_RR:
		return PSE51_MAX_PRIORITY;

	case SCHED_OTHER:
		return 0;

	default:
		thread_set_errno(EINVAL);
		return -1;
	}
}

/**
 * Get the round-robin scheduling time slice.
 *
 * This service returns the time quantum used by Xenomai POSIX skin SCHED_RR
 * scheduling policy.
 *
 * In kernel-space, this service only works if pid is zero, in user-space,
 * round-robin scheduling policy is not supported, and this service not
 * implemented.
 *
 * @param pid must be zero;
 *
 * @param interval address where the round-robin scheduling time quantum will
 * be returned on success.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - ESRCH, @a pid is invalid (not 0).
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/sched_rr_get_interval.html">
 * Specification.</a>
 * 
 */
int sched_rr_get_interval(int pid, struct timespec *interval)
{
	/* The only valid pid is 0. */
	if (pid) {
		thread_set_errno(ESRCH);
		return -1;
	}

	ticks2ts(interval, pse51_time_slice);

	return 0;
}

/**
 * Get the scheduling policy and parameters of the specified thread.
 *
 * This service returns, at the addresses @a pol and @a par, the current
 * scheduling policy and scheduling parameters (i.e. priority) of the Xenomai
 * POSIX skin thread @a tid. If this service is called from user-space and @a
 * tid is not the identifier of a Xenomai POSIX skin thread, this service
 * fallback to Linux regular pthread_getschedparam service.
 *
 * @param tid target thread;
 *
 * @param pol address where the scheduling policy of @a tid is stored on
 * success;
 *
 * @param par address where the scheduling parameters of @a tid is stored on
 * success.
 *
 * @return 0 on success;
 * @return an error number if:
 * - ESRCH, @a tid is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_getschedparam.html">
 * Specification.</a>
 * 
 */
int pthread_getschedparam(pthread_t tid, int *pol, struct sched_param *par)
{
	int prio;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(tid, PSE51_THREAD_MAGIC, struct pse51_thread)) {
		xnlock_put_irqrestore(&nklock, s);
		return ESRCH;
	}

	prio = xnthread_base_priority(&tid->threadbase);
	par->sched_priority = prio;
	*pol = (prio
		? (!xnthread_test_state(&tid->threadbase, XNRRB)
		   ? SCHED_FIFO : SCHED_RR) : SCHED_OTHER);

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Set the scheduling policy and parameters of the specified thread.
 *
 * This service set the scheduling policy of the Xenomai POSIX skin thread @a
 * tid to the value @a  pol, and its scheduling parameters (i.e. its priority)
 * to the value pointed to by @a par.
 *
 * When used in user-space, passing the current thread ID as @a tid argument,
 * this service turns the current thread into a Xenomai POSIX skin thread. If @a
 * tid is neither the identifier of the current thread nor the identifier of a
 * Xenomai POSIX skin thread this service falls back to the regular
 * pthread_setschedparam() service, hereby causing the current thread to switch
 * to secondary mode if it is Xenomai thread.
 *
 * @param tid target thread;
 *
 * @param pol scheduling policy, one of SCHED_FIFO, SCHED_RR or SCHED_OTHER;
 *
 * @param par scheduling parameters address.
 *
 * @return 0 on success;
 * @return an error number if:
 * - ESRCH, @a tid is invalid;
 * - EINVAL, @a pol or @a par->sched_priority is invalid;
 * - EAGAIN, in user-space, insufficient memory exists in the system heap,
 *   increase CONFIG_XENO_OPT_SYS_HEAPSZ;
 * - EFAULT, in user-space, @a par is an invalid address;
 * - EPERM, in user-space, the calling process does not have superuser
 *   permissions.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_setschedparam.html">
 * Specification.</a>
 * 
 */
int pthread_setschedparam(pthread_t tid, int pol, const struct sched_param *par)
{
	xnflags_t clrmask, setmask;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(tid, PSE51_THREAD_MAGIC, struct pse51_thread)) {
		xnlock_put_irqrestore(&nklock, s);
		return ESRCH;
	}

	switch (pol) {
	default:

		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;

	case SCHED_OTHER:
	case SCHED_FIFO:
		setmask = 0;
		clrmask = XNRRB;
		break;


	case SCHED_RR:
		xnthread_time_slice(&tid->threadbase) = pse51_time_slice;
		setmask = XNRRB;
		clrmask = 0;
	}

	if ((pol != SCHED_OTHER && (par->sched_priority < PSE51_MIN_PRIORITY
				    || par->sched_priority >
				    PSE51_MAX_PRIORITY))
	    || (pol == SCHED_OTHER && par->sched_priority != 0)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	xnpod_renice_thread(&tid->threadbase, par->sched_priority);
	xnpod_set_thread_mode(&tid->threadbase, clrmask, setmask);

	xnpod_schedule();

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Yield the processor.
 *
 * This function move the current thread at the end of its priority group.
 *
 * @retval 0
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/sched_yield.html">
 * Specification.</a>
 *
 */
int sched_yield(void)
{
	xnpod_yield();
	return 0;
}

/*@}*/

EXPORT_SYMBOL(sched_get_priority_min);
EXPORT_SYMBOL(sched_get_priority_max);
EXPORT_SYMBOL(sched_rr_get_interval);
EXPORT_SYMBOL(pthread_getschedparam);
EXPORT_SYMBOL(pthread_setschedparam);
EXPORT_SYMBOL(sched_yield);
