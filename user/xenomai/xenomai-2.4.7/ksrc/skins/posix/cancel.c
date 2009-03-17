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
 * @ingroup posix_thread
 * @defgroup posix_cancel Thread cancellation.
 *
 * Thread cancellation.
 *
 * Cancellation is the mechanism by which a thread can terminate the execution
 * of a Xenomai POSIX skin thread (created with pthread_create()). More
 * precisely, a thread can send a cancellation request to a Xenomai POSIX skin
 * thread and depending on its cancelability type (see pthread_setcanceltype())
 * and state (see pthread_setcancelstate()), the target thread can then either
 * ignore the request, honor it immediately, or defer it till it reaches a
 * cancellation point. When threads are first created by pthread_create(), they
 * always defer cancellation requests.
 *
 * When a thread eventually honors a cancellation request, it behaves as if
 * @a pthread_exit(PTHREAD_CANCELED) was called.  All cleanup handlers are
 * executed in reverse order, finalization functions for thread-specific data
 * are called, and finally the thread stops executing. If the canceled thread
 * was joinable, the return value PTHREAD_CANCELED is provided to whichever
 * thread calls pthread_join() on it. See pthread_exit() for more information.
 *
 * Cancellation points are the points where the thread checks for pending
 * cancellation requests and performs them.  The POSIX threads functions
 * pthread_join(), pthread_cond_wait(), pthread_cond_timedwait(),
 * pthread_testcancel(), sem_wait(), sem_timedwait(), sigwait(), sigwaitinfo()
 * and sigtimedwait() are cancellation points.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/xsh_chap02_09.html#tag_02_09_05">
 * Specification.</a>
 *
 *@{*/

#include <posix/thread.h>
#include <posix/cancel.h>

typedef void cleanup_routine_t(void *);

typedef struct {
	cleanup_routine_t *routine;
	void *arg;
	xnholder_t link;

#define link2cleanup_handler(laddr) container_of(laddr, cleanup_handler_t, link)

} cleanup_handler_t;

/**
 * Cancel a thread.
 *
 * This service sends a cancellation request to the thread @a thread and returns
 * immediately. Depending on the target thread cancelability state (see
 * pthread_setcancelstate()) and type (see pthread_setcanceltype()), its
 * termination is either immediate, deferred or ignored.
 *
 * When the cancellation request is handled and before the thread is terminated,
 * the cancellation cleanup handlers (registered with the pthread_cleanup_push()
 * service) are called, then the thread-specific data destructor functions
 * (registered with pthread_key_create()).
 *
 * @return 0 on success;
 * @return an error number if:
 * - ESRCH, the thread @a thread was not found.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_cancel.html">
 * Specification.</a>
 *
 */
int pthread_cancel(pthread_t thread)
{
	int cancel_enabled;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(thread, PSE51_THREAD_MAGIC, struct pse51_thread)) {
		xnlock_put_irqrestore(&nklock, s);
		return ESRCH;
	}

	cancel_enabled = thread_getcancelstate(thread) == PTHREAD_CANCEL_ENABLE;

	if (cancel_enabled
	    && thread_getcanceltype(thread) == PTHREAD_CANCEL_ASYNCHRONOUS)
		pse51_thread_abort(thread, PTHREAD_CANCELED);
	else {
		/* pthread_cancel is not a cancellation point, so
		   thread == pthread_self() is not a special case. */

		thread_setcancel(thread);

		if (cancel_enabled) {
			/* Unblock thread, so that it can honor the cancellation request. */
			xnpod_unblock_thread(&thread->threadbase);
			xnpod_schedule();
		}
	}

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Register a cleanup handler to be executed at the time of cancellation.
 *
 * This service registers the given @a routine to be executed a the time of
 * cancellation of the calling thread, if this thread is a Xenomai POSIX skin
 * thread (i.e. created with the pthread_create() service). If the caller
 * context is invalid (not a Xenomai POSIX skin thread), this service has no
 * effect.
 *
 * If allocation from the system heap fails (because the system heap size is to
 * small), this service fails silently.
 *
 * The routines registered with this service get called in LIFO order when the
 * calling thread calls pthread_exit() or is canceled, or when it calls the
 * pthread_cleanup_pop() service with a non null argument.
 *
 * @param routine the cleanup routine to be registered;
 *
 * @param arg the argument associated with this routine.
 *
 * @par Valid contexts:
 * - Xenomai POSIX skin kernel-space thread,
 * - Xenomai POSIX skin user-space thread (switches to primary mode).
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_cleanup_push.html">
 * Specification.</a>
 * 
 */
void pthread_cleanup_push(cleanup_routine_t * routine, void *arg)
{
	pthread_t cur = pse51_current_thread();
	cleanup_handler_t *handler;
	spl_t s;

	if (!routine || !cur || xnpod_interrupt_p() || xnpod_callout_p())
		return;

	/* The allocation is inside the critical section in order to make the
	   function async-signal safe, that is in order to avoid leaks if an
	   asynchronous cancellation request could occur between the call to
	   xnmalloc and xnlock_get_irqsave. */

	xnlock_get_irqsave(&nklock, s);

	handler = xnmalloc(sizeof(*handler));

	if (!handler) {
		xnlock_put_irqrestore(&nklock, s);
		return;
	}

	handler->routine = routine;
	handler->arg = arg;
	inith(&handler->link);

	prependq(thread_cleanups(cur), &handler->link);

	xnlock_put_irqrestore(&nklock, s);
}

/**
 * Unregister the last registered cleanup handler.
 *
 * If the calling thread is a Xenomai POSIX skin thread (i.e. created with
 * pthread_create()), this service unregisters the last routine which was
 * registered with pthread_cleanup_push() and call it if @a execute is not null.
 *
 * If the caller context is invalid (not a Xenomai POSIX skin thread), this
 * service has no effect.
 *
 * This service may be called at any place, but for maximal portability, should
 * only called in the same lexical scope as the matching call to
 * pthread_cleanup_push().
 *
 * @param execute if non zero, the last registered cleanup handler should be
 * executed before it is unregistered.
 *
 * @par Valid contexts:
 * - Xenomai POSIX skin kernel-space thread,
 * - Xenomai POSIX skin user-space thread (switches to primary mode).
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_cleanup_pop.html">
 * Specification.</a>
 * 
 */
void pthread_cleanup_pop(int execute)
{
	pthread_t cur = pse51_current_thread();
	cleanup_handler_t *handler;
	cleanup_routine_t *routine;
	xnholder_t *holder;
	void *arg;
	spl_t s;

	if (!cur || xnpod_interrupt_p() || xnpod_callout_p())
		return;

	xnlock_get_irqsave(&nklock, s);

	holder = getq(thread_cleanups(cur));

	if (!holder) {
		xnlock_put_irqrestore(&nklock, s);
		return;
	}

	handler = link2cleanup_handler(holder);

	routine = handler->routine;
	arg = handler->arg;

	/* Same remark as xnmalloc in pthread_cleanup_push */
	xnfree(handler);

	xnlock_put_irqrestore(&nklock, s);

	if (execute)
		routine(arg);
}

/**
 * Set cancelability type of the current thread.
 *
 * This service atomically sets the cancelability type of the calling thread,
 * and return its previous value at the address @a oldtype_ptr, if this thread
 * is a Xenomai POSIX skin thread (i.e. was created with the pthread_create()
 * service).
 *
 * The cancelability type of a POSIX thread may be:
 * - PTHREAD_CANCEL_DEFERRED, meaning that cancellation requests are only
 *   handled in services which are cancellation points;
 * - PTHREAD_CANCEL_ASYNCHRONOUS, meaning that cancellation requests are handled
 *   as soon as they are sent.
 *
 * @param type new cancelability type of the calling thread;
 *
 * @param oldtype_ptr address where the old cancelability type will be stored on
 * success.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, @a type is not a valid cancelability type;
 * - EPERM, the caller context is invalid.
 *
 * @par Valid contexts:
 * - Xenomai POSIX skin kernel-space thread,
 * - Xenomai POSIX skin user-space thread (switches to primary mode).
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_setcanceltype.html">
 * Specification.</a>
 * 
 */
int pthread_setcanceltype(int type, int *oldtype_ptr)
{
	pthread_t cur;
	int oldtype;
	spl_t s;

	switch (type) {
	default:

		return EINVAL;

	case PTHREAD_CANCEL_DEFERRED:
	case PTHREAD_CANCEL_ASYNCHRONOUS:

		break;
	}

	cur = pse51_current_thread();

	if (!cur || xnpod_interrupt_p())
		return EPERM;

	xnlock_get_irqsave(&nklock, s);

	oldtype = thread_getcanceltype(cur);

	thread_setcanceltype(cur, type);

	if (type == PTHREAD_CANCEL_ASYNCHRONOUS
	    && thread_getcancelstate(cur) == PTHREAD_CANCEL_ENABLE)
		thread_cancellation_point(&cur->threadbase);

	if (oldtype_ptr)
		*oldtype_ptr = oldtype;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Set cancelability state of the current thread.
 *
 * This service atomically set the cancelability state of the calling thread and
 * returns its previous value at the address @a oldstate_ptr, if the calling
 * thread is a Xenomai POSIX skin thread (i.e. created with the pthread_create
 * service).
 *
 * The cancelability state of a POSIX thread may be:
 * - PTHREAD_CANCEL_ENABLE, meaning that cancellation requests will be handled
 *   if received;
 * - PTHREAD_CANCEL_DISABLE, meaning that cancellation requests will not be
 *   handled if received.
 *
 * @param state new cancelability state of the calling thread;
 *
 * @param oldstate_ptr address where the old cancelability state will be stored
 * on success.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, @a state is not a valid cancelability state;
 * - EPERM, the caller context is invalid.
 *
 * @par Valid contexts:
 * - Xenomai POSIX skin kernel-space thread,
 * - Xenomai POSIX skin user-space thread (switches to primary mode).
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_setcancelstate.html">
 * Specification.</a>
 * 
 */
int pthread_setcancelstate(int state, int *oldstate_ptr)
{
	pthread_t cur;
	int oldstate;
	spl_t s;

	switch (state) {
	default:

		return EINVAL;

	case PTHREAD_CANCEL_ENABLE:
	case PTHREAD_CANCEL_DISABLE:

		break;
	}

	cur = pse51_current_thread();

	if (!cur || xnpod_interrupt_p())
		return EPERM;

	xnlock_get_irqsave(&nklock, s);

	oldstate = thread_getcancelstate(cur);
	thread_setcancelstate(cur, state);

	if (state == PTHREAD_CANCEL_ENABLE
	    && thread_getcanceltype(cur) == PTHREAD_CANCEL_ASYNCHRONOUS)
		thread_cancellation_point(&cur->threadbase);

	if (oldstate_ptr)
		*oldstate_ptr = oldstate;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Test if a cancellation request is pending.
 *
 * This function creates a cancellation point if the calling thread is a Xenomai
 * POSIX skin thread (i.e. created with the pthread_create() service).
 *
 * This function is a cancellation point. It has no effect if cancellation is
 * disabled.
 *
 * @par Valid contexts:
 * - Xenomai POSIX skin kernel-space thread,
 * - Xenomai POSIX skin user-space thread (switches to primary mode).
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_testcancel.html">
 * Specification.</a>
 * 
 */
void pthread_testcancel(void)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	thread_cancellation_point(xnpod_current_thread());
	xnlock_put_irqrestore(&nklock, s);
}

void pse51_cancel_init_thread(pthread_t thread)
{
	thread_setcancelstate(thread, PTHREAD_CANCEL_ENABLE);
	thread_setcanceltype(thread, PTHREAD_CANCEL_DEFERRED);
	thread_clrcancel(thread);
	initq(thread_cleanups(thread));
}

void pse51_cancel_cleanup_thread(pthread_t thread)
{
	xnholder_t *holder;

	while ((holder = getq(thread_cleanups(thread)))) {
		cleanup_handler_t *handler = link2cleanup_handler(holder);
		handler->routine(handler->arg);
		xnfree(handler);
	}
}

/*@}*/

EXPORT_SYMBOL(pthread_cancel);
EXPORT_SYMBOL(pthread_cleanup_push);
EXPORT_SYMBOL(pthread_cleanup_pop);
EXPORT_SYMBOL(pthread_setcancelstate);
EXPORT_SYMBOL(pthread_setcanceltype);
EXPORT_SYMBOL(pthread_testcancel);
