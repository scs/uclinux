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
 * \ingroup event
 */

/*!
 * \ingroup native
 * \defgroup event Event flag group services.
 *
 * An event flag group is a synchronization object represented by a
 * long-word structure; every available bit in such word can be used
 * to map a user-defined event flag.  When a flag is set, the
 * associated event is said to have occurred. Xenomai tasks and interrupt
 * handlers can use event flags to signal the occurrence of events to
 * other tasks; those tasks can either wait for the events to occur in
 * a conjunctive manner (all awaited events must have occurred to wake
 * up), or in a disjunctive way (at least one of the awaited events
 * must have occurred to wake up).
 *
 *@{*/

/** @example event_flags.c */

#include <nucleus/pod.h>
#include <nucleus/registry.h>
#include <nucleus/heap.h>
#include <native/task.h>
#include <native/event.h>

#ifdef CONFIG_XENO_EXPORT_REGISTRY

static int __event_read_proc(char *page,
			     char **start,
			     off_t off, int count, int *eof, void *data)
{
	RT_EVENT *event = (RT_EVENT *)data;
	char *p = page;
	int len;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	p += sprintf(p, "=0x%lx\n", event->value);

	if (xnsynch_nsleepers(&event->synch_base) > 0) {
		xnpholder_t *holder;

		/* Pended event -- dump waiters. */

		holder = getheadpq(xnsynch_wait_queue(&event->synch_base));

		while (holder) {
			xnthread_t *sleeper = link2thread(holder, plink);
			RT_TASK *task = thread2rtask(sleeper);
			const char *mode =
			    (task->wait_args.event.
			     mode & EV_ANY) ? "any" : "all";
			unsigned long mask = task->wait_args.event.mask;
			p += sprintf(p, "+%s (mask=0x%lx, %s)\n",
				     xnthread_name(sleeper), mask, mode);
			holder =
			    nextpq(xnsynch_wait_queue(&event->synch_base),
				   holder);
		}
	}

	xnlock_put_irqrestore(&nklock, s);

	len = (p - page) - off;
	if (len <= off + count)
		*eof = 1;
	*start = page + off;
	if (len > count)
		len = count;
	if (len < 0)
		len = 0;

	return len;
}

extern xnptree_t __native_ptree;

static xnpnode_t __event_pnode = {

	.dir = NULL,
	.type = "events",
	.entries = 0,
	.read_proc = &__event_read_proc,
	.write_proc = NULL,
	.root = &__native_ptree,
};

#elif defined(CONFIG_XENO_OPT_REGISTRY)

static xnpnode_t __event_pnode = {

	.type = "events"
};

#endif /* CONFIG_XENO_EXPORT_REGISTRY */

/**
 * @fn int rt_event_create(RT_EVENT *event,const char *name,unsigned long ivalue,int mode)
 * @brief Create an event group.
 *
 * Event groups provide for task synchronization by allowing a set of
 * flags (or "events") to be waited for and posted atomically. An
 * event group contains a mask of received events; any set of bits
 * from the event mask can be pended or posted in a single operation.
 *
 * Tasks can wait for a conjunctive (AND) or disjunctive (OR) set of
 * events to occur.  A task pending on an event group in conjunctive
 * mode is woken up as soon as all awaited events are set in the event
 * mask. A task pending on an event group in disjunctive mode is woken
 * up as soon as any awaited event is set in the event mask.

 * @param event The address of an event group descriptor Xenomai will
 * use to store the event-related data.  This descriptor must always
 * be valid while the group is active therefore it must be allocated
 * in permanent memory.
 *
 * @param name An ASCII string standing for the symbolic name of the
 * group. When non-NULL and non-empty, this string is copied to a
 * safe place into the descriptor, and passed to the registry package
 * if enabled for indexing the created event group.
 *
 * @param ivalue The initial value of the group's event mask.
 *
 * @param mode The event group creation mode. The following flags can
 * be OR'ed into this bitmask, each of them affecting the new group:
 *
 * - EV_FIFO makes tasks pend in FIFO order on the event group.
 *
 * - EV_PRIO makes tasks pend in priority order on the event group.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EEXIST is returned if the @a name is already in use by some
 * registered object.
 *
 * - -EPERM is returned if this service was called from an
 * asynchronous context.
 *
 * - -ENOMEM is returned if the system fails to get enough dynamic
 * memory from the global real-time heap in order to register the
 * event group.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: possible.
 */

int rt_event_create(RT_EVENT *event,
		    const char *name, unsigned long ivalue, int mode)
{
	int err = 0;
	spl_t s;

	if (xnpod_asynch_p())
		return -EPERM;

	xnsynch_init(&event->synch_base, mode & EV_PRIO);
	event->value = ivalue;
	event->handle = 0;	/* i.e. (still) unregistered event. */
	event->magic = XENO_EVENT_MAGIC;
	xnobject_copy_name(event->name, name);
	inith(&event->rlink);
	event->rqueue = &xeno_get_rholder()->eventq;
	xnlock_get_irqsave(&nklock, s);
	appendq(event->rqueue, &event->rlink);
	xnlock_put_irqrestore(&nklock, s);

#ifdef CONFIG_XENO_OPT_PERVASIVE
	event->cpid = 0;
#endif /* CONFIG_XENO_OPT_PERVASIVE */

#ifdef CONFIG_XENO_OPT_REGISTRY
	/* <!> Since xnregister_enter() may reschedule, only register
	   complete objects, so that the registry cannot return handles to
	   half-baked objects... */

	if (name) {
		xnpnode_t *pnode = &__event_pnode;

		if (!*name) {
			/* Since this is an anonymous object (empty name on entry)
			   from user-space, it gets registered under an unique
			   internal name but is not exported through /proc. */
			xnobject_create_name(event->name, sizeof(event->name),
					     (void *)event);
			pnode = NULL;
		}

		err =
		    xnregistry_enter(event->name, event, &event->handle, pnode);

		if (err)
			rt_event_delete(event);
	}
#endif /* CONFIG_XENO_OPT_REGISTRY */

	return err;
}

/**
 * @fn int rt_event_delete(RT_EVENT *event)
 * @brief Delete an event group.
 *
 * Destroy an event group and release all the tasks currently pending
 * on it.  An event group exists in the system since rt_event_create()
 * has been called to create it, so this service must be called in
 * order to destroy it afterwards.
 *
 * @param event The descriptor address of the affected event group.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if @a event is not a event group descriptor.
 *
 * - -EIDRM is returned if @a event is a deleted event group descriptor.
 *
 * - -EPERM is returned if this service was called from an
 * asynchronous context.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: possible.
 */

int rt_event_delete(RT_EVENT *event)
{
	int err = 0, rc;
	spl_t s;

	if (xnpod_asynch_p())
		return -EPERM;

	xnlock_get_irqsave(&nklock, s);

	event = xeno_h2obj_validate(event, XENO_EVENT_MAGIC, RT_EVENT);

	if (!event) {
		err = xeno_handle_error(event, XENO_EVENT_MAGIC, RT_EVENT);
		goto unlock_and_exit;
	}

	removeq(event->rqueue, &event->rlink);

	rc = xnsynch_destroy(&event->synch_base);

#ifdef CONFIG_XENO_OPT_REGISTRY
	if (event->handle)
		xnregistry_remove(event->handle);
#endif /* CONFIG_XENO_OPT_REGISTRY */

	xeno_mark_deleted(event);

	if (rc == XNSYNCH_RESCHED)
		/* Some task has been woken up as a result of the deletion:
		   reschedule now. */
		xnpod_schedule();

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int rt_event_signal(RT_EVENT *event,unsigned long mask)
 * @brief Post an event group.
 *
 * Post a set of bits to the event mask. All tasks having their wait
 * request fulfilled by the posted events are resumed.
 *
 * @param event The descriptor address of the affected event.
 *
 * @param mask The set of events to be posted.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if @a event is not an event group descriptor.
 *
 * - -EIDRM is returned if @a event is a deleted event group descriptor.
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
 * Rescheduling: possible.
 */

int rt_event_signal(RT_EVENT *event, unsigned long mask)
{
	xnpholder_t *holder, *nholder;
	int err = 0, resched = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	event = xeno_h2obj_validate(event, XENO_EVENT_MAGIC, RT_EVENT);

	if (!event) {
		err = xeno_handle_error(event, XENO_EVENT_MAGIC, RT_EVENT);
		goto unlock_and_exit;
	}

	/* Post the flags. */

	event->value |= mask;

	/* And wakeup any sleeper having its request fulfilled. */

	nholder = getheadpq(xnsynch_wait_queue(&event->synch_base));

	while ((holder = nholder) != NULL) {
		RT_TASK *sleeper = thread2rtask(link2thread(holder, plink));
		int mode = sleeper->wait_args.event.mode;
		unsigned long bits = sleeper->wait_args.event.mask;

		if (((mode & EV_ANY) && (bits & event->value) != 0) ||
		    (!(mode & EV_ANY) && ((bits & event->value) == bits))) {
			sleeper->wait_args.event.mask = (bits & event->value);
			nholder =
			    xnsynch_wakeup_this_sleeper(&event->synch_base,
							holder);
			resched = 1;
		} else
			nholder =
			    nextpq(xnsynch_wait_queue(&event->synch_base),
				   holder);
	}

	if (resched)
		xnpod_schedule();

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int rt_event_wait(RT_EVENT *event,unsigned long mask,unsigned long *mask_r,int mode,RTIME timeout)
 * @brief Pend on an event group.
 *
 * Waits for one or more events on the specified event group, either
 * in conjunctive or disjunctive mode.

 * If the specified set of bits is not set, the calling task is
 * blocked. The task is not resumed until the request is fulfilled.
 * The event bits are NOT cleared from the event group when a request
 * is satisfied; rt_event_wait() will return immediately with success
 * for the same event mask until rt_event_clear() is called to clear
 * those bits.
 *
 * @param event The descriptor address of the affected event group.
 *
 * @param mask The set of bits to wait for. Passing zero causes this
 * service to return immediately with a success value; the current
 * value of the event mask is also copied to @a mask_r.
 *
 * @param mask_r The value of the event mask at the time the task was
 * readied.
 *
 * @param mode The pend mode. The following flags can be OR'ed into
 * this bitmask, each of them affecting the operation:
 *
 * - EV_ANY makes the task pend in disjunctive mode (i.e. OR); this
 * means that the request is fulfilled when at least one bit set into
 * @a mask is set in the current event mask.
 *
 * - EV_ALL makes the task pend in conjunctive mode (i.e. AND); this
 * means that the request is fulfilled when at all bits set into @a
 * mask are set in the current event mask.
 *
 * @param timeout The number of clock ticks to wait for fulfilling the
 * request (see note). Passing TM_INFINITE causes the caller to block
 * indefinitely until the request is fulfilled. Passing TM_NONBLOCK
 * causes the service to return immediately without waiting if the
 * request cannot be satisfied immediately.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if @a event is not a event group descriptor.
 *
 * - -EIDRM is returned if @a event is a deleted event group
 * descriptor, including if the deletion occurred while the caller was
 * sleeping on it before the request has been satisfied.
 *
 * - -EWOULDBLOCK is returned if @a timeout is equal to TM_NONBLOCK
 * and the current event mask value does not satisfy the request.
 *
 * - -EINTR is returned if rt_task_unblock() has been called for the
 * waiting task before the request has been satisfied.
 *
 * - -ETIMEDOUT is returned if the request has not been satisfied
 * within the specified amount of time.
 *
 * - -EPERM is returned if this service should block, but was called
 * from a context which cannot sleep (e.g. interrupt, non-realtime or
 * scheduler locked).
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code or Interrupt service
 * routine only if @a timeout is equal to TM_NONBLOCK.
 * - Kernel-based task
 * - User-space task (switches to primary mode)
 *
 * Rescheduling: always unless the request is immediately satisfied or
 * @a timeout specifies a non-blocking operation.
 *
 * @note The @a timeout value will be interpreted as jiffies if the
 * native skin is bound to a periodic time base (see
 * CONFIG_XENO_OPT_NATIVE_PERIOD), or nanoseconds otherwise.
 */

int rt_event_wait(RT_EVENT *event,
		  unsigned long mask,
		  unsigned long *mask_r, int mode, RTIME timeout)
{
	RT_TASK *task;
	int err = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	event = xeno_h2obj_validate(event, XENO_EVENT_MAGIC, RT_EVENT);

	if (!event) {
		err = xeno_handle_error(event, XENO_EVENT_MAGIC, RT_EVENT);
		goto unlock_and_exit;
	}

	if (!mask) {
		*mask_r = event->value;
		goto unlock_and_exit;
	}

	if (timeout == TM_NONBLOCK) {
		unsigned long bits = (event->value & mask);
		*mask_r = bits;

		if (mode & EV_ANY) {
			if (!bits)
				err = -EWOULDBLOCK;
		} else if (bits != mask)
			err = -EWOULDBLOCK;

		goto unlock_and_exit;
	}

	if (((mode & EV_ANY) && (mask & event->value) != 0) ||
	    (!(mode & EV_ANY) && ((mask & event->value) == mask))) {
		*mask_r = (event->value & mask);
		goto unlock_and_exit;
	}

	if (xnpod_unblockable_p()) {
		err = -EPERM;
		goto unlock_and_exit;
	}

	task = xeno_current_task();
	task->wait_args.event.mode = mode;
	task->wait_args.event.mask = mask;
	xnsynch_sleep_on(&event->synch_base, timeout, XN_RELATIVE);
	/* The returned mask is only significant if the operation has
	   succeeded, but do always write it back anyway. */
	*mask_r = task->wait_args.event.mask;

	if (xnthread_test_info(&task->thread_base, XNRMID))
		err = -EIDRM;	/* Event group deleted while pending. */
	else if (xnthread_test_info(&task->thread_base, XNTIMEO))
		err = -ETIMEDOUT;	/* Timeout. */
	else if (xnthread_test_info(&task->thread_base, XNBREAK))
		err = -EINTR;	/* Unblocked. */

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int rt_event_clear(RT_EVENT *event,unsigned long mask,unsigned long *mask_r)
 * @brief Clear an event group.
 *
 * Clears a set of flags from an event mask.
 *
 * @param event The descriptor address of the affected event.
 *
 * @param mask The set of events to be cleared.
 *
 * @param mask_r If non-NULL, @a mask_r is the address of a memory
 * location which will be written upon success with the previous value
 * of the event group before the flags are cleared.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if @a event is not an event group descriptor.
 *
 * - -EIDRM is returned if @a event is a deleted event group descriptor.
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

int rt_event_clear(RT_EVENT *event, unsigned long mask, unsigned long *mask_r)
{
	int err = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	event = xeno_h2obj_validate(event, XENO_EVENT_MAGIC, RT_EVENT);

	if (!event) {
		err = xeno_handle_error(event, XENO_EVENT_MAGIC, RT_EVENT);
		goto unlock_and_exit;
	}

	if (mask_r)
		*mask_r = event->value;

	/* Clear the flags. */

	event->value &= ~mask;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int rt_event_inquire(RT_EVENT *event, RT_EVENT_INFO *info)
 * @brief Inquire about an event group.
 *
 * Return various information about the status of a specified
 * event group.
 *
 * @param event The descriptor address of the inquired event group.
 *
 * @param info The address of a structure the event group information
 * will be written to.

 * @return 0 is returned and status information is written to the
 * structure pointed at by @a info upon success. Otherwise:
 *
 * - -EINVAL is returned if @a event is not a event group descriptor.
 *
 * - -EIDRM is returned if @a event is a deleted event group
 * descriptor.
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

int rt_event_inquire(RT_EVENT *event, RT_EVENT_INFO *info)
{
	int err = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	event = xeno_h2obj_validate(event, XENO_EVENT_MAGIC, RT_EVENT);

	if (!event) {
		err = xeno_handle_error(event, XENO_EVENT_MAGIC, RT_EVENT);
		goto unlock_and_exit;
	}

	strcpy(info->name, event->name);
	info->value = event->value;
	info->nwaiters = xnsynch_nsleepers(&event->synch_base);

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int rt_event_bind(RT_EVENT *event,const char *name,RTIME timeout)
 * @brief Bind to an event flag group.
 *
 * This user-space only service retrieves the uniform descriptor of a
 * given Xenomai event flag group identified by its symbolic name. If the
 * event flag group does not exist on entry, this service blocks the
 * caller until a event flag group of the given name is created.
 *
 * @param name A valid NULL-terminated name which identifies the
 * event flag group to bind to.
 *
 * @param event The address of an event flag group descriptor
 * retrieved by the operation. Contents of this memory is undefined
 * upon failure.
 *
 * @param timeout The number of clock ticks to wait for the
 * registration to occur (see note). Passing TM_INFINITE causes the
 * caller to block indefinitely until the object is
 * registered. Passing TM_NONBLOCK causes the service to return
 * immediately without waiting if the object is not registered on
 * entry.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EFAULT is returned if @a event or @a name is referencing invalid
 * memory.
 *
 * - -EINTR is returned if rt_task_unblock() has been called for the
 * waiting task before the retrieval has completed.
 *
 * - -EWOULDBLOCK is returned if @a timeout is equal to TM_NONBLOCK
 * and the searched object is not registered on entry.
 *
 * - -ETIMEDOUT is returned if the object cannot be retrieved within
 * the specified amount of time.
 *
 * - -EPERM is returned if this service should block, but was called
 * from a context which cannot sleep (e.g. interrupt, non-realtime or
 * scheduler locked).
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - User-space task (switches to primary mode)
 *
 * Rescheduling: always unless the request is immediately satisfied or
 * @a timeout specifies a non-blocking operation.
 *
 * @note The @a timeout value will be interpreted as jiffies if the
 * native skin is bound to a periodic time base (see
 * CONFIG_XENO_OPT_NATIVE_PERIOD), or nanoseconds otherwise.
 */

/**
 * @fn int rt_event_unbind(RT_EVENT *event)
 *
 * @brief Unbind from an event flag group.
 *
 * This user-space only service unbinds the calling task from the
 * event flag group object previously retrieved by a call to
 * rt_event_bind().
 *
 * @param event The address of an event flag group descriptor to
 * unbind from.
 *
 * @return 0 is always returned.
 *
 * This service can be called from:
 *
 * - User-space task.
 *
 * Rescheduling: never.
 */

int __native_event_pkg_init(void)
{
	return 0;
}

void __native_event_pkg_cleanup(void)
{
	__native_event_flush_rq(&__native_global_rholder.eventq);
}

/*@}*/

EXPORT_SYMBOL(rt_event_create);
EXPORT_SYMBOL(rt_event_delete);
EXPORT_SYMBOL(rt_event_signal);
EXPORT_SYMBOL(rt_event_wait);
EXPORT_SYMBOL(rt_event_clear);
EXPORT_SYMBOL(rt_event_inquire);
