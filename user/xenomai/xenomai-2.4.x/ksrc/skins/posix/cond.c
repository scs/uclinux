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
 * @ingroup posix
 * @defgroup posix_cond Condition variables services.
 *
 * Condition variables services.
 *
 * A condition variable is a synchronization object that allows threads to
 * suspend execution until some predicate on shared data is satisfied. The basic
 * operations on conditions are: signal the condition (when the predicate
 * becomes true), and wait for the condition, suspending the thread execution
 * until another thread signals the condition.
 *
 * A condition variable must always be associated with a mutex, to avoid the
 * race condition where a thread prepares to wait on a condition variable and
 * another thread signals the condition just before the first thread actually
 * waits on it.
 *
 * Before it can be used, a condition variable has to be initialized with
 * pthread_cond_init(). An attribute object, which reference may be passed to
 * this service, allows to select the features of the created condition
 * variable, namely the @a clock used by the pthread_cond_timedwait() service
 * (@a CLOCK_REALTIME is used by default), and whether it may be shared between
 * several processes (it may not be shared by default, see
 * pthread_condattr_setpshared()).
 *
 * Note that only pthread_cond_init() may be used to initialize a condition
 * variable, using the static initializer @a PTHREAD_COND_INITIALIZER is
 * not supported.
 *
 *@{*/

#include <posix/mutex.h>
#include <posix/cond.h>

typedef struct pse51_cond {
	xnsynch_t synchbase;
	xnholder_t link;	/* Link in pse51_condq */

#define link2cond(laddr)                                                \
    ((pse51_cond_t *)(((char *)laddr) - offsetof(pse51_cond_t, link)))

	pthread_condattr_t attr;
	struct pse51_mutex *mutex;
	pse51_kqueues_t *owningq;
} pse51_cond_t;

static pthread_condattr_t default_cond_attr;

static void cond_destroy_internal(pse51_cond_t * cond, pse51_kqueues_t *q)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	removeq(&q->condq, &cond->link);
	/* synchbase wait queue may not be empty only when this function is
	   called from pse51_cond_pkg_cleanup, hence the absence of
	   xnpod_schedule(). */
	xnsynch_destroy(&cond->synchbase);
	xnlock_put_irqrestore(&nklock, s);
	xnfree(cond);
}

/**
 * Initialize a condition variable.
 *
 * This service initializes the condition variable @a cnd, using the condition
 * variable attributes object @a attr. If @a attr is @a NULL or this service is
 * called from user-space, default attributes are used (see
 * pthread_condattr_init()).
 *
 * @param cnd the condition variable to be initialized;
 *
 * @param attr the condition variable attributes object.
 *
 * @return 0 on succes,
 * @return an error number if:
 * - EINVAL, the condition variable attributes object @a attr is invalid or
 *   uninitialized;
 * - EBUSY, the condition variable @a cnd was already initialized;
 * - ENOMEM, insufficient memory exists in the system heap to initialize the
 *   condition variable, increase CONFIG_XENO_OPT_SYS_HEAPSZ.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_cond_init.html">
 * Specification.</a>
 * 
 */
int pthread_cond_init(pthread_cond_t * cnd, const pthread_condattr_t * attr)
{
	struct __shadow_cond *shadow = &((union __xeno_cond *)cnd)->shadow_cond;
	xnflags_t synch_flags = XNSYNCH_PRIO | XNSYNCH_NOPIP;
	pse51_cond_t *cond;
	xnqueue_t *condq;
	spl_t s;
	int err;

	if (!attr)
		attr = &default_cond_attr;

	cond = (pse51_cond_t *) xnmalloc(sizeof(*cond));
	if (!cond)
		return ENOMEM;

	xnlock_get_irqsave(&nklock, s);

	if (attr->magic != PSE51_COND_ATTR_MAGIC) {
		err = EINVAL;
		goto error;
	}

	condq = &pse51_kqueues(attr->pshared)->condq;

	if (shadow->magic == PSE51_COND_MAGIC) {
		xnholder_t *holder;
		for (holder = getheadq(condq); holder;
		     holder = nextq(condq, holder))
			if (holder == &shadow->cond->link) {
				/* cond is already in the queue. */
				err = EBUSY;
				goto error;
			}
	}

	shadow->magic = PSE51_COND_MAGIC;
	shadow->cond = cond;

	xnsynch_init(&cond->synchbase, synch_flags);
	inith(&cond->link);
	cond->attr = *attr;
	cond->mutex = NULL;
	cond->owningq = pse51_kqueues(attr->pshared);

	appendq(condq, &cond->link);

	xnlock_put_irqrestore(&nklock, s);

	return 0;

  error:
	xnlock_put_irqrestore(&nklock, s);
	return err;
}

/**
 * Destroy a condition variable.
 *
 * This service destroys the condition variable @a cnd, if no thread is
 * currently blocked on it. The condition variable becomes invalid for all
 * condition variable services (they all return the EINVAL error) except
 * pthread_cond_init().
 *
 * @param cnd the condition variable to be destroyed.
 *
 * @return 0 on succes,
 * @return an error number if:
 * - EINVAL, the condition variable @a cnd is invalid;
 * - EPERM, the condition variable is not process-shared and does not belong to
 *   the current process;
 * - EBUSY, some thread is currently using the condition variable.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_cond_destroy.html">
 * Specification.</a>
 * 
 */
int pthread_cond_destroy(pthread_cond_t * cnd)
{
	struct __shadow_cond *shadow = &((union __xeno_cond *)cnd)->shadow_cond;
	pse51_cond_t *cond;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(shadow, PSE51_COND_MAGIC, struct __shadow_cond)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	cond = shadow->cond;
	if (cond->owningq != pse51_kqueues(cond->attr.pshared)) {
		xnlock_put_irqrestore(&nklock, s);
		return EPERM;
	}

	if (xnsynch_nsleepers(&cond->synchbase) || cond->mutex) {
		xnlock_put_irqrestore(&nklock, s);
		return EBUSY;
	}

	pse51_mark_deleted(shadow);

	xnlock_put_irqrestore(&nklock, s);

	cond_destroy_internal(cond, pse51_kqueues(cond->attr.pshared));

	return 0;
}

/* must be called with nklock locked, interrupts off.

   Note: this function is very similar to mutex_unlock_internal() in mutex.c.
*/
static inline int mutex_save_count(xnthread_t *cur,
				   struct __shadow_mutex *shadow,
				   unsigned *count_ptr)
{
	pse51_mutex_t *mutex;

	if (!pse51_obj_active(shadow, PSE51_MUTEX_MAGIC, struct __shadow_mutex))
		 return EINVAL;

	mutex = shadow->mutex;

	if (xnsynch_owner(&mutex->synchbase) != cur || mutex->count == 0)
		return EPERM;

	*count_ptr = mutex->count;

	if (xnsynch_wakeup_one_sleeper(&mutex->synchbase))
		mutex->count = 1;
	else
		mutex->count = 0;
	/* Do not reschedule here, releasing the mutex and suspension must be
	   done atomically in pthread_cond_*wait. */

	return 0;
}

int pse51_cond_timedwait_prologue(xnthread_t *cur,
				  struct __shadow_cond *shadow,
				  struct __shadow_mutex *mutex,
				  unsigned *count_ptr,
				  int timed,
				  xnticks_t abs_to)
{
	pse51_cond_t *cond;
	spl_t s;
	int err;

	if (!shadow || !mutex)
		return EINVAL;

	if (xnpod_unblockable_p())
		return EPERM;

	xnlock_get_irqsave(&nklock, s);

	thread_cancellation_point(cur);

	cond = shadow->cond;

	/* If another thread waiting for cond does not use the same mutex */
	if (!pse51_obj_active(shadow, PSE51_COND_MAGIC, struct __shadow_cond)
	    || (cond->mutex && cond->mutex != mutex->mutex)) {
		err = EINVAL;
		goto unlock_and_return;
	}

	if (cond->owningq != pse51_kqueues(cond->attr.pshared)) {
		err = EPERM;
		goto unlock_and_return;
	}

	/* Unlock mutex, with its previous recursive lock count stored
	   in "*count_ptr". */
	err = mutex_save_count(cur, mutex, count_ptr);

	if (err)
		goto unlock_and_return;

	/* Bind mutex to cond. */
	if (cond->mutex == NULL) {
		cond->mutex = mutex->mutex;
		++mutex->mutex->condvars;
	}

	/* Wait for another thread to signal the condition. */
	if (timed)
		xnsynch_sleep_on(&cond->synchbase, abs_to,
				 clock_flag(TIMER_ABSTIME, cond->attr.clock));
	else
		xnsynch_sleep_on(&cond->synchbase, XN_INFINITE, XN_RELATIVE);

	/* There are four possible wakeup conditions :
	   - cond_signal / cond_broadcast, no status bit is set, and the function
	     should return 0 ;
	   - timeout, the status XNTIMEO is set, and the function should return
	     ETIMEDOUT ;
	   - pthread_kill, the status bit XNBREAK is set, but ignored, the
	     function simply returns EINTR (used only by the user-space
	     interface, replaced by 0 anywhere else), causing a wakeup, spurious
	     or not whether pthread_cond_signal was called between pthread_kill
	     and the moment when xnsynch_sleep_on returned ;
	   - pthread_cancel, no status bit is set, but cancellation specific
	     bits are set, and tested only once the mutex is reacquired in
	     pse51_cond_timedwait_epilogue, so that the cancellation handler can
	     be called with the mutex locked, as required by the specification.
	 */

	err = 0;

	if (xnthread_test_info(cur, XNBREAK))
		err = EINTR;
	else if (xnthread_test_info(cur, XNTIMEO))
		err = ETIMEDOUT;

      unlock_and_return:
	xnlock_put_irqrestore(&nklock, s);

	return err;
}

int pse51_cond_timedwait_epilogue(xnthread_t *cur,
				  struct __shadow_cond *shadow,
				  struct __shadow_mutex *mutex, unsigned count)
{
	pse51_cond_t *cond;
	int err;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	cond = shadow->cond;

	err = pse51_mutex_timedlock_internal(cur, mutex, count, 0, XN_INFINITE);

	if (err == EINTR)
		goto unlock_and_return;


	/* Unbind mutex and cond, if no other thread is waiting, if the job was
	   not already done. */
	if (!xnsynch_nsleepers(&cond->synchbase)
	    && cond->mutex == mutex->mutex) {
	
		--mutex->mutex->condvars;
		cond->mutex = NULL;
	}

	thread_cancellation_point(cur);

      unlock_and_return:
	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * Wait on a condition variable.
 *
 * This service atomically unlocks the mutex @a mx, and block the calling thread
 * until the condition variable @a cnd is signalled using pthread_cond_signal()
 * or pthread_cond_broadcast(). When the condition is signaled, this service
 * re-acquire the mutex before returning.
 *
 * Spurious wakeups occur if a signal is delivered to the blocked thread, so, an
 * application should not assume that the condition changed upon successful
 * return from this service.
 *
 * Even if the mutex @a mx is recursive and its recursion count is greater than
 * one on entry, it is unlocked before blocking the caller, and the recursion
 * count is restored once the mutex is re-acquired by this service before
 * returning.
 *
 * Once a thread is blocked on a condition variable, a dynamic binding is formed
 * between the condition vairable @a cnd and the mutex @a mx; if another thread
 * calls this service specifying @a cnd as a condition variable but another
 * mutex than @a mx, this service returns immediately with the EINVAL status.
 *
 * This service is a cancellation point for Xenomai POSIX skin threads
 * (created with the pthread_create() service). When such a thread is cancelled
 * while blocked in a call to this service, the mutex @a mx is re-acquired
 * before the cancellation cleanup handlers are called.
 *
 * @param cnd the condition variable to wait for;
 *
 * @param mx the mutex associated with @a cnd.
 *
 * @return 0 on success,
 * @return an error number if:
 * - EPERM, the caller context is invalid;
 * - EINVAL, the specified condition variable or mutex is invalid;
 * - EPERM, the specified condition variable is not process-shared and does not
 *   belong to the current process;
 * - EINVAL, another thread is currently blocked on @a cnd using another mutex
 *   than @a mx;
 * - EPERM, the specified mutex is not owned by the caller.
 *
 * @par Valid contexts:
 * - Xenomai kernel-space thread;
 * - Xenomai user-space thread (switches to primary mode).
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_cond_wait.html">
 * Specification.</a>
 * 
 */
int pthread_cond_wait(pthread_cond_t * cnd, pthread_mutex_t * mx)
{
	struct __shadow_cond *cond = &((union __xeno_cond *)cnd)->shadow_cond;
	struct __shadow_mutex *mutex =
	    &((union __xeno_mutex *)mx)->shadow_mutex;
	xnthread_t *cur = xnpod_current_thread();
	unsigned count;
	int err;

	err = pse51_cond_timedwait_prologue(cur, cond, mutex,
					    &count, 0, XN_INFINITE);

	if (!err || err == EINTR)
		while (EINTR == pse51_cond_timedwait_epilogue(cur, cond,
							      mutex, count))
			;

	return err != EINTR ? err : 0;
}

/**
 * Wait a bounded time on a condition variable.
 *
 * This service is equivalent to pthread_cond_wait(), except that the calling
 * thread remains blocked on the condition variable @a cnd only until the
 * timeout specified by @a abstime expires.
 *
 * The timeout @a abstime is expressed as an absolute value of the @a clock
 * attribute passed to pthread_cond_init(). By default, @a CLOCK_REALTIME is
 * used.
 *
 * @param cnd the condition variable to wait for;
 *
 * @param mx the mutex associated with @a cnd;
 *
 * @param abstime the timeout, expressed as an absolute value of the clock
 * attribute passed to pthread_cond_init().
 *
 * @return 0 on success,
 * @return an error number if:
 * - EPERM, the caller context is invalid;
 * - EPERM, the specified condition variable is not process-shared and does not
 *   belong to the current process;
 * - EINVAL, the specified condition variable, mutex or timeout is invalid;
 * - EINVAL, another thread is currently blocked on @a cnd using another mutex
 *   than @a mx;
 * - EPERM, the specified mutex is not owned by the caller;
 * - ETIMEDOUT, the specified timeout expired.
 *
 * @par Valid contexts:
 * - Xenomai kernel-space thread;
 * - Xenomai user-space thread (switches to primary mode).
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_cond_timedwait.html">
 * Specification.</a>
 * 
 */
int pthread_cond_timedwait(pthread_cond_t * cnd,
			   pthread_mutex_t * mx, const struct timespec *abstime)
{
	struct __shadow_cond *cond = &((union __xeno_cond *)cnd)->shadow_cond;
	struct __shadow_mutex *mutex =
	    &((union __xeno_mutex *)mx)->shadow_mutex;
	xnthread_t *cur = xnpod_current_thread();
	unsigned count;
	int err;

	err = pse51_cond_timedwait_prologue(cur, cond, mutex, &count, 1,
					    ts2ticks_ceil(abstime) + 1);

	if (!err || err == EINTR || err == ETIMEDOUT)
		while (EINTR == pse51_cond_timedwait_epilogue(cur, cond,
							      mutex, count))
			;

	return err != EINTR ? err : 0;
}

/**
 * Signal a condition variable.
 *
 * This service unblocks one thread blocked on the condition variable @a cnd.
 *
 * If more than one thread is blocked on the specified condition variable, the
 * highest priority thread is unblocked.
 *
 * @param cnd the condition variable to be signalled.
 *
 * @return 0 on succes,
 * @return an error number if:
 * - EINVAL, the condition variable is invalid;
 * - EPERM, the condition variable is not process-shared and does not belong to
 *   the current process.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_cond_signal.html.">
 * Specification.</a>
 * 
 */
int pthread_cond_signal(pthread_cond_t * cnd)
{
	struct __shadow_cond *shadow = &((union __xeno_cond *)cnd)->shadow_cond;
	pse51_cond_t *cond;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(shadow, PSE51_COND_MAGIC, struct __shadow_cond)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	cond = shadow->cond;
#if XENO_DEBUG(POSIX)
	if (cond->owningq != pse51_kqueues(cond->attr.pshared)) {
		xnlock_put_irqrestore(&nklock, s);
		return EPERM;
	}
#endif /* XENO_DEBUG(POSIX) */

	/* FIXME: If the mutex associated with cnd is owned by the current
	   thread, we could postpone rescheduling until pthread_mutex_unlock is
	   called, this would save two useless context switches. */
	if (xnsynch_wakeup_one_sleeper(&cond->synchbase) != NULL)
		xnpod_schedule();

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Broadcast a condition variable.
 *
 * This service unblocks all threads blocked on the condition variable @a cnd.
 *
 * @param cnd the condition variable to be signalled.
 *
 * @return 0 on succes,
 * @return an error number if:
 * - EINVAL, the condition variable is invalid;
 * - EPERM, the condition variable is not process-shared and does not belong to
 *   the current process.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_cond_broadcast.html">
 * Specification.</a>
 * 
 */
int pthread_cond_broadcast(pthread_cond_t * cnd)
{
	struct __shadow_cond *shadow = &((union __xeno_cond *)cnd)->shadow_cond;
	pse51_cond_t *cond;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(shadow, PSE51_COND_MAGIC, struct __shadow_cond)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	cond = shadow->cond;
	if (cond->owningq != pse51_kqueues(cond->attr.pshared)) {
		xnlock_put_irqrestore(&nklock, s);
		return EPERM;
	}

	if (xnsynch_flush(&cond->synchbase, 0) == XNSYNCH_RESCHED)
		xnpod_schedule();

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

void pse51_condq_cleanup(pse51_kqueues_t *q)
{
	xnholder_t *holder;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	while ((holder = getheadq(&q->condq)) != NULL) {
		xnlock_put_irqrestore(&nklock, s);
		cond_destroy_internal(link2cond(holder), q);
#if XENO_DEBUG(POSIX)
		xnprintf("Posix: destroying condition variable %p.\n",
			 link2cond(holder));
#endif /* XENO_DEBUG(POSIX) */
		xnlock_get_irqsave(&nklock, s);
	}

	xnlock_put_irqrestore(&nklock, s);
}

void pse51_cond_pkg_init(void)
{
	initq(&pse51_global_kqueues.condq);
	pthread_condattr_init(&default_cond_attr);
}

void pse51_cond_pkg_cleanup(void)
{
	pse51_condq_cleanup(&pse51_global_kqueues);
}

/*@}*/

EXPORT_SYMBOL(pthread_cond_init);
EXPORT_SYMBOL(pthread_cond_destroy);
EXPORT_SYMBOL(pthread_cond_wait);
EXPORT_SYMBOL(pthread_cond_timedwait);
EXPORT_SYMBOL(pthread_cond_signal);
EXPORT_SYMBOL(pthread_cond_broadcast);
