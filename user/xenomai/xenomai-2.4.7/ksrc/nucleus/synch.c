/*!\file synch.c
 * \brief Thread synchronization services.
 * \author Philippe Gerum
 *
 * Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
 *
 * Xenomai is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * \ingroup synch
 */

/*!
 * \ingroup nucleus
 * \defgroup synch Thread synchronization services.
 *
 * Thread synchronization services.
 *
 *@{*/

#include <stdarg.h>
#include <nucleus/pod.h>
#include <nucleus/synch.h>
#include <nucleus/thread.h>
#include <nucleus/module.h>

/*! 
 * \fn void xnsynch_init(xnsynch_t *synch, xnflags_t flags);
 * \brief Initialize a synchronization object.
 *
 * Initializes a new specialized object which can subsequently be used
 * to synchronize real-time activities. The Xenomai nucleus
 * provides a basic synchronization object which can be used to build
 * higher resource objects. Nucleus threads can wait for and signal
 * such objects in order to synchronize their activities.
 *
 * This object has built-in support for priority inheritance.
 *
 * @param synch The address of a synchronization object descriptor the
 * nucleus will use to store the object-specific data.  This
 * descriptor must always be valid while the object is active
 * therefore it must be allocated in permanent memory.
 *
 * @param flags A set of creation flags affecting the operation. The
 * valid flags are:
 *
 * - XNSYNCH_PRIO causes the threads waiting for the resource to pend
 * in priority order. Otherwise, FIFO ordering is used (XNSYNCH_FIFO).
 *
 * - XNSYNCH_PIP causes the priority inheritance mechanism to be
 * automatically activated when a priority inversion is detected among
 * threads using this object. Otherwise, no priority inheritance takes
 * place upon priority inversion (XNSYNCH_NOPIP).
 *
 * - XNSYNCH_DREORD (Disable REORDering) tells the nucleus that the
 * wait queue should not be reordered whenever the priority of a
 * blocked thread it holds is changed. If this flag is not specified,
 * changing the priority of a blocked thread using
 * xnpod_renice_thread() will cause this object's wait queue to be
 * reordered according to the new priority level, provided the
 * synchronization object makes the waiters wait by priority order on
 * the awaited resource (XNSYNCH_PRIO).
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 */

void xnsynch_init(xnsynch_t *synch, xnflags_t flags)
{
	initph(&synch->link);

	if (flags & XNSYNCH_PIP)
		flags |= XNSYNCH_PRIO;	/* Obviously... */

	synch->status = flags & ~XNSYNCH_CLAIMED;
	synch->owner = NULL;
	synch->cleanup = NULL;	/* Only works for PIP-enabled objects. */
	initpq(&synch->pendq);
	xnarch_init_display_context(synch);
}

/*
 * xnsynch_renice_thread() -- This service is used by the PIP code to
 * raise/lower a thread's priority. The thread's base priority value
 * is _not_ changed and if ready, the thread is always moved at the
 * end of its priority group.
 */

static void xnsynch_renice_thread(xnthread_t *thread, int prio)
{
	thread->cprio = prio;

	if (thread->wchan)
		/* Ignoring the XNSYNCH_DREORD flag on purpose here. */
		xnsynch_renice_sleeper(thread);
	else if (thread != xnpod_current_thread() &&
		 xnthread_test_state(thread, XNREADY))
		/* xnpod_resume_thread() must be called for runnable
		   threads but the running one. */
		xnpod_resume_thread(thread, 0);

#ifdef CONFIG_XENO_OPT_PERVASIVE
	if (xnthread_test_state(thread, XNRELAX))
		xnshadow_renice(thread);
#endif /* CONFIG_XENO_OPT_PERVASIVE */
}

/*! 
 * \fn void xnsynch_sleep_on(xnsynch_t *synch, xnticks_t timeout,
 *                           xntmode_t timeout_mode)
 *
 * \brief Sleep on a synchronization object.
 *
 * Makes the calling thread sleep on the specified synchronization
 * object, waiting for it to be signaled.
 *
 * This service should be called by upper interfaces wanting the
 * current thread to pend on the given resource.
 *
 * @param synch The descriptor address of the synchronization object
 * to sleep on.
 *
 * @param timeout The timeout which may be used to limit the time the
 * thread pends on the resource. This value is a wait time given in
 * ticks (see note). It can either be relative, absolute monotonic, or
 * absolute adjustable depending on @a timeout_mode. Passing XN_INFINITE
 * @b and setting @a mode to XN_RELATIVE specifies an unbounded wait. All
 * other values are used to initialize a watchdog timer.
 *
 * @param timeout_mode The mode of the @a timeout parameter. It can
 * either be set to XN_RELATIVE, XN_ABSOLUTE, or XN_REALTIME (see also
 * xntimer_start()).
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: always.
 *
 * @note The @a timeout value will be interpreted as jiffies if the
 * current thread is bound to a periodic time base (see
 * xnpod_init_thread), or nanoseconds otherwise.
 */

void xnsynch_sleep_on(xnsynch_t *synch, xnticks_t timeout,
		      xntmode_t timeout_mode)
{
	xnthread_t *thread = xnpod_current_thread(), *owner;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	trace_mark(xn_nucleus_synch_sleepon,
		   "thread %p thread_name %s synch %p",
		   thread, xnthread_name(thread), synch);

	if (!testbits(synch->status, XNSYNCH_PRIO)) { /* i.e. FIFO */
		appendpq(&synch->pendq, &thread->plink);
		xnpod_suspend_thread(thread, XNPEND, timeout, timeout_mode, synch);
		goto unlock_and_exit;
	}

	if (!testbits(synch->status, XNSYNCH_PIP)) { /* i.e. no ownership */
		insertpqf(&synch->pendq, &thread->plink, thread->cprio);
		xnpod_suspend_thread(thread, XNPEND, timeout, timeout_mode, synch);
		goto unlock_and_exit;
	}

redo:
	owner = synch->owner;

	if (!owner) {
		synch->owner = thread;
		xnthread_clear_info(thread, XNRMID | XNTIMEO | XNBREAK);
		goto unlock_and_exit;
	}

	if (thread->cprio > owner->cprio) {
		if (xnthread_test_info(owner, XNWAKEN) && owner->wwake == synch) {
			/* Ownership is still pending, steal the resource. */
			synch->owner = thread;
			xnthread_clear_info(thread, XNRMID | XNTIMEO | XNBREAK);
			xnthread_set_info(owner, XNROBBED);
			goto unlock_and_exit;
		}

		if (!xnthread_test_state(owner, XNBOOST)) {
			owner->bprio = owner->cprio;
			xnthread_set_state(owner, XNBOOST);
		}

		if (testbits(synch->status, XNSYNCH_CLAIMED))
			removepq(&owner->claimq, &synch->link);
		else
			__setbits(synch->status, XNSYNCH_CLAIMED);

		insertpqf(&owner->claimq, &synch->link, thread->cprio);
		insertpqf(&synch->pendq, &thread->plink, thread->cprio);
		xnsynch_renice_thread(owner, thread->cprio);
	} else
		insertpqf(&synch->pendq, &thread->plink, thread->cprio);

	xnpod_suspend_thread(thread, XNPEND, timeout, timeout_mode, synch);

	if (xnthread_test_info(thread, XNRMID | XNTIMEO | XNBREAK))
		goto unlock_and_exit;

	if (xnthread_test_info(thread, XNROBBED)) {
		/* Somebody stole us the ownership while we were ready
		   to run, waiting for the CPU: we need to wait again
		   for the resource. */
		if (timeout_mode != XN_RELATIVE || timeout == XN_INFINITE)
			goto redo;
		timeout = xntimer_get_timeout_stopped(&thread->rtimer);
		if (timeout > 1) /* Otherwise, it's too late. */
			goto redo;
		xnthread_set_info(thread, XNTIMEO);
	}

      unlock_and_exit:

	thread->wwake = NULL;
	xnthread_clear_info(thread, XNWAKEN);

	xnlock_put_irqrestore(&nklock, s);
}

/*! 
 * @internal
 * \fn void xnsynch_clear_boost(xnsynch_t *synch, xnthread_t *owner);
 * \brief Clear the priority boost.
 *
 * This service is called internally whenever a synchronization object
 * is not claimed anymore by sleepers to reset the object owner's
 * priority to its initial level.
 *
 * @param synch The descriptor address of the synchronization object.
 *
 * @param owner The descriptor address of the thread which
 * currently owns the synchronization object.
 *
 * @note This routine must be entered nklock locked, interrupts off.
 */

static void xnsynch_clear_boost(xnsynch_t *synch, xnthread_t *lastowner)
{
	int downprio;

	removepq(&lastowner->claimq, &synch->link);
	downprio = lastowner->bprio;
	__clrbits(synch->status, XNSYNCH_CLAIMED);

	if (emptypq_p(&lastowner->claimq))
		xnthread_clear_state(lastowner, XNBOOST);
	else {
		/* Find the highest priority needed to enforce the PIP. */
		int rprio = getheadpq(&lastowner->claimq)->prio;

		if (rprio > downprio)
			downprio = rprio;
	}

	if (lastowner->cprio != downprio)
		xnsynch_renice_thread(lastowner, downprio);
}

/*! 
 * @internal
 * \fn void xnsynch_renice_sleeper(xnthread_t *thread);
 * \brief Change a sleeper's priority.
 *
 * This service is used by the PIP code to update the pending priority
 * of a sleeping thread.
 *
 * @param thread The descriptor address of the affected thread.
 *
 * @note This routine must be entered nklock locked, interrupts off.
 */

void xnsynch_renice_sleeper(xnthread_t *thread)
{
	xnsynch_t *synch = thread->wchan;
	xnthread_t *owner;

	if (!testbits(synch->status, XNSYNCH_PRIO))
		return;

	removepq(&synch->pendq, &thread->plink);
	insertpqf(&synch->pendq, &thread->plink, thread->cprio);
	owner = synch->owner;

	if (owner != NULL && thread->cprio > owner->cprio) {
		/* The new priority of the sleeping thread is higher
		 * than the priority of the current owner of the
		 * resource: we need to update the PI state. */
		if (testbits(synch->status, XNSYNCH_CLAIMED)) {
			/* The resource is already claimed, just
			   reorder the claim queue. */
			removepq(&owner->claimq, &synch->link);
			insertpqf(&owner->claimq, &synch->link, thread->cprio);
		} else {
			/* The resource was NOT claimed, claim it now
			 * and boost the owner. */
			__setbits(synch->status, XNSYNCH_CLAIMED);
			insertpqf(&owner->claimq, &synch->link, thread->cprio);
			owner->bprio = owner->cprio;
			xnthread_set_state(owner, XNBOOST);
		}
		/* Renice the owner thread, progressing in the PI
		   chain as needed. */
		xnsynch_renice_thread(owner, thread->cprio);
	}
}

/*! 
 * \fn xnthread_t *xnsynch_wakeup_one_sleeper(xnsynch_t *synch);
 * \brief Give the resource ownership to the next waiting thread.
 *
 * This service gives the ownership of a synchronization object to the
 * thread which is currently leading the object's pending list. The
 * sleeping thread is unblocked, but no action is taken regarding the
 * previous owner of the resource.
 *
 * This service should be called by upper interfaces wanting to signal
 * the given resource so that a single waiter is resumed.
 *
 * @param synch The descriptor address of the synchronization object
 * whose ownership is changed.
 *
 * @return The descriptor address of the unblocked thread.
 *
 * Side-effects:
 *
 * - The effective priority of the previous resource owner might be
 * lowered to its base priority value as a consequence of the priority
 * inheritance boost being cleared.
 *
 * - The synchronization object ownership is transfered to the
 * unblocked thread.
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

xnthread_t *xnsynch_wakeup_one_sleeper(xnsynch_t *synch)
{
	xnthread_t *thread = NULL, *lastowner;
	xnpholder_t *holder;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	lastowner = synch->owner;
	holder = getpq(&synch->pendq);

	if (holder) {
		thread = link2thread(holder, plink);
		thread->wchan = NULL;
		thread->wwake = synch;
		synch->owner = thread;
		xnthread_set_info(thread, XNWAKEN);
		trace_mark(xn_nucleus_synch_wakeup_one,
			   "thread %p thread_name %s synch %p",
			   thread, xnthread_name(thread), synch);
		xnpod_resume_thread(thread, XNPEND);
	} else
		synch->owner = NULL;

	if (testbits(synch->status, XNSYNCH_CLAIMED))
		xnsynch_clear_boost(synch, lastowner);

	xnlock_put_irqrestore(&nklock, s);

	xnarch_post_graph_if(synch, 0, emptypq_p(&synch->pendq));

	return thread;
}

/*! 
 * \fn xnthread_t *xnsynch_peek_pendq(xnsynch_t *synch);
 * \brief Access the thread leading a synch object wait queue.
 *
 * This services returns the descriptor address of to the thread leading a
 * synchronization object wait queue.
 *
 * @param synch The descriptor address of the target synchronization object.
 *
 * @return The descriptor address of the unblocked thread.
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
xnthread_t *xnsynch_peek_pendq(xnsynch_t *synch)
{
	xnthread_t *thread = NULL;
	xnpholder_t *holder;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	holder = getheadpq(&synch->pendq);
	if (holder)
		thread = link2thread(holder, plink);
	xnlock_put_irqrestore(&nklock, s);

	return thread;
}

/*! 
 * \fn xnpholder_t *xnsynch_wakeup_this_sleeper(xnsynch_t *synch, xnpholder_t *holder);
 * \brief Give the resource ownership to a given waiting thread.
 *
 * This service gives the ownership of a given synchronization object
 * to a specific thread which is currently pending on it. The sleeping
 * thread is unblocked from its pending state. No action is taken
 * regarding the previous resource owner.
 *
 * This service should be called by upper interfaces wanting to signal
 * the given resource so that a specific waiter is resumed.
 *
 * @param synch The descriptor address of the synchronization object
 * whose ownership is changed.
 *
 * @param holder The link holder address of the thread to unblock
 * (&thread->plink) which MUST be currently linked to the
 * synchronization object's pending queue (i.e. synch->pendq).
 *
 * @return The link address of the next waiting thread in the
 * synchronization object's pending queue.
 *
 * Side-effects:
 *
 * - The effective priority of the previous resource owner might be
 * lowered to its base priority value as a consequence of the priority
 * inheritance boost being cleared.
 *
 * - The synchronization object ownership is transfered to the
 * unblocked thread.
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

xnpholder_t *xnsynch_wakeup_this_sleeper(xnsynch_t *synch, xnpholder_t *holder)
{
	xnthread_t *thread, *lastowner;
	xnpholder_t *nholder;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	lastowner = synch->owner;
	nholder = poppq(&synch->pendq, holder);

	thread = link2thread(holder, plink);
	thread->wchan = NULL;
	thread->wwake = synch;
	synch->owner = thread;
	xnthread_set_info(thread, XNWAKEN);
	trace_mark(xn_nucleus_synch_wakeup_all,
		   "thread %p thread_name %s synch %p",
		   thread, xnthread_name(thread), synch);
	xnpod_resume_thread(thread, XNPEND);

	if (testbits(synch->status, XNSYNCH_CLAIMED))
		xnsynch_clear_boost(synch, lastowner);

	xnlock_put_irqrestore(&nklock, s);

	xnarch_post_graph_if(synch, 0, emptypq_p(&synch->pendq));

	return nholder;
}

/*! 
 * \fn void xnsynch_flush(xnsynch_t *synch, xnflags_t reason);
 * \brief Unblock all waiters pending on a resource.
 *
 * This service atomically releases all threads which currently sleep
 * on a given resource.
 *
 * This service should be called by upper interfaces under
 * circumstances requiring that the pending queue of a given resource
 * is cleared, such as before the resource is deleted.
 *
 * @param synch The descriptor address of the synchronization object
 * to be flushed.
 *
 * @param reason Some flags to set in the information mask of every
 * unblocked thread. Zero is an acceptable value. The following bits
 * are pre-defined by the nucleus:
 *
 * - XNRMID should be set to indicate that the synchronization object
 * is about to be destroyed (see xnpod_resume_thread()).
 *
 * - XNBREAK should be set to indicate that the wait has been forcibly
 * interrupted (see xnpod_unblock_thread()).
 *
 * @return XNSYNCH_RESCHED is returned if at least one thread
 * is unblocked, which means the caller should invoke xnpod_schedule()
 * for applying the new scheduling state. Otherwise, XNSYNCH_DONE is
 * returned.
 *
 * Side-effects:
 *
 * - The effective priority of the previous resource owner might be
 * lowered to its base priority value as a consequence of the priority
 * inheritance boost being cleared.
 *
 * - The synchronization object is no more owned by any thread.
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

int xnsynch_flush(xnsynch_t *synch, xnflags_t reason)
{
	xnpholder_t *holder;
	int status;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	trace_mark(xn_nucleus_synch_flush, "synch %p reason %lu",
		   synch, reason);

	status = emptypq_p(&synch->pendq) ? XNSYNCH_DONE : XNSYNCH_RESCHED;

	while ((holder = getpq(&synch->pendq)) != NULL) {
		xnthread_t *sleeper = link2thread(holder, plink);
		xnthread_set_info(sleeper, reason);
		sleeper->wchan = NULL;
		xnpod_resume_thread(sleeper, XNPEND);
	}

	if (testbits(synch->status, XNSYNCH_CLAIMED)) {
		xnsynch_clear_boost(synch, synch->owner);
		status = XNSYNCH_RESCHED;
	}

	xnlock_put_irqrestore(&nklock, s);

	xnarch_post_graph_if(synch, 0, emptypq_p(&synch->pendq));

	return status;
}

/*! 
 * @internal
 * \fn void xnsynch_forget_sleeper(xnthread_t *thread);
 * \brief Abort a wait for a resource.
 *
 * Performs all the necessary housekeeping chores to stop a thread
 * from waiting on a given synchronization object.
 *
 * @param thread The descriptor address of the affected thread.
 *
 * When the trace support is enabled (i.e. MVM), the idle state is
 * posted to the synchronization object's state diagram (if any)
 * whenever no thread remains blocked on it. The real-time interfaces
 * must ensure that such condition (i.e. EMPTY/IDLE) is mapped to
 * state #0.
 *
 * @note This routine must be entered nklock locked, interrupts off.
 */

void xnsynch_forget_sleeper(xnthread_t *thread)
{
	xnsynch_t *synch = thread->wchan;

	trace_mark(xn_nucleus_synch_forget,
		   "thread %p thread_name %s synch %p",
		   thread, xnthread_name(thread), synch);

	xnthread_clear_state(thread, XNPEND);
	thread->wchan = NULL;
	removepq(&synch->pendq, &thread->plink);

	if (testbits(synch->status, XNSYNCH_CLAIMED)) {
		/* Find the highest priority needed to enforce the PIP. */
		xnthread_t *owner = synch->owner;
		int rprio;

		if (emptypq_p(&synch->pendq))
			/* No more sleepers: clear the boost. */
			xnsynch_clear_boost(synch, owner);
		else if (getheadpq(&synch->pendq)->prio !=
			 getheadpq(&owner->claimq)->prio) {
			/* Reorder the claim queue, and lower the priority to the
			   required minimum needed to prevent priority
			   inversion. */
			removepq(&owner->claimq, &synch->link);

			insertpqf(&owner->claimq,
				  &synch->link, getheadpq(&synch->pendq)->prio);

			rprio = getheadpq(&owner->claimq)->prio;

			if (rprio < owner->cprio)
				xnsynch_renice_thread(owner, rprio);
		}
	}

	xnarch_post_graph_if(synch, 0, emptypq_p(&synch->pendq));
}

/*! 
 * @internal
 * \fn void xnsynch_release_all_ownerships(xnthread_t *thread);
 * \brief Release all ownerships.
 *
 * This call is used internally to release all the ownerships obtained
 * by a thread on synchronization objects. This routine must be
 * entered interrupts off.
 *
 * @param thread The descriptor address of the affected thread.
 *
 * @note This routine must be entered nklock locked, interrupts off.
 */

void xnsynch_release_all_ownerships(xnthread_t *thread)
{
	xnpholder_t *holder, *nholder;

	for (holder = getheadpq(&thread->claimq); holder != NULL;
	     holder = nholder) {
		/* Since xnsynch_wakeup_one_sleeper() alters the claim
		   queue, we need to be conservative while scanning
		   it. */
		xnsynch_t *synch = link2synch(holder);
		nholder = nextpq(&thread->claimq, holder);
		xnsynch_wakeup_one_sleeper(synch);
		if (synch->cleanup)
			synch->cleanup(synch);
	}
}

/*@}*/

EXPORT_SYMBOL(xnsynch_flush);
EXPORT_SYMBOL(xnsynch_forget_sleeper);
EXPORT_SYMBOL(xnsynch_init);
EXPORT_SYMBOL(xnsynch_release_all_ownerships);
EXPORT_SYMBOL(xnsynch_renice_sleeper);
EXPORT_SYMBOL(xnsynch_sleep_on);
EXPORT_SYMBOL(xnsynch_wakeup_one_sleeper);
EXPORT_SYMBOL(xnsynch_wakeup_this_sleeper);
EXPORT_SYMBOL(xnsynch_peek_pendq);
