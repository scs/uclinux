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
 * \ingroup cond
 */

/*!
 * \ingroup native
 * \defgroup cond Condition variable services.
 *
 * Condition variable services.
 *
 * A condition variable is a synchronization object which allows tasks
 * to suspend execution until some predicate on shared data is
 * satisfied. The basic operations on conditions are: signal the
 * condition (when the predicate becomes true), and wait for the
 * condition, blocking the task execution until another task signals
 * the condition.  A condition variable must always be associated with
 * a mutex, to avoid a well-known race condition where a task prepares
 * to wait on a condition variable and another task signals the
 * condition just before the first task actually waits on it.
 *
 *@{*/

/** @example cond_var.c */

#include <nucleus/pod.h>
#include <nucleus/registry.h>
#include <nucleus/heap.h>
#include <native/task.h>
#include <native/mutex.h>
#include <native/cond.h>

#ifdef CONFIG_XENO_EXPORT_REGISTRY

static int __cond_read_proc(char *page,
			    char **start,
			    off_t off, int count, int *eof, void *data)
{
	RT_COND *cond = (RT_COND *)data;
	char *p = page;
	int len;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (xnsynch_nsleepers(&cond->synch_base) > 0) {
		xnpholder_t *holder;

		/* Pended condvar -- dump waiters. */

		holder = getheadpq(xnsynch_wait_queue(&cond->synch_base));

		while (holder) {
			xnthread_t *sleeper = link2thread(holder, plink);
			p += sprintf(p, "+%s\n", xnthread_name(sleeper));
			holder =
			    nextpq(xnsynch_wait_queue(&cond->synch_base),
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

static xnpnode_t __cond_pnode = {

	.dir = NULL,
	.type = "condvars",
	.entries = 0,
	.read_proc = &__cond_read_proc,
	.write_proc = NULL,
	.root = &__native_ptree,
};

#elif defined(CONFIG_XENO_OPT_REGISTRY)

static xnpnode_t __cond_pnode = {

	.type = "condvars"
};

#endif /* CONFIG_XENO_EXPORT_REGISTRY */

/**
 * @fn int rt_cond_create(RT_COND *cond, const char *name)
 * @brief Create a condition variable.
 *
 * Create a synchronization object that allows tasks to suspend
 * execution until some predicate on shared data is satisfied.
 *
 * @param cond The address of a condition variable descriptor Xenomai
 * will use to store the variable-related data.  This descriptor must
 * always be valid while the variable is active therefore it must be
 * allocated in permanent memory.
 *
 * @param name An ASCII string standing for the symbolic name of the
 * condition variable. When non-NULL and non-empty, this string is
 * copied to a safe place into the descriptor, and passed to the
 * registry package if enabled for indexing the created variable.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -ENOMEM is returned if the system fails to get enough dynamic
 * memory from the global real-time heap in order to register the
 * condition variable.
 *
 * - -EEXIST is returned if the @a name is already in use by some
 * registered object.
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

int rt_cond_create(RT_COND *cond, const char *name)
{
	int err = 0;
	spl_t s;

	if (xnpod_asynch_p())
		return -EPERM;

	xnsynch_init(&cond->synch_base, XNSYNCH_PRIO);
	cond->handle = 0;	/* i.e. (still) unregistered cond. */
	cond->magic = XENO_COND_MAGIC;
	xnobject_copy_name(cond->name, name);
	inith(&cond->rlink);
	cond->rqueue = &xeno_get_rholder()->condq;
	xnlock_get_irqsave(&nklock, s);
	appendq(cond->rqueue, &cond->rlink);
	xnlock_put_irqrestore(&nklock, s);

#ifdef CONFIG_XENO_OPT_PERVASIVE
	cond->cpid = 0;
#endif /* CONFIG_XENO_OPT_PERVASIVE */

#ifdef CONFIG_XENO_OPT_REGISTRY
	/* <!> Since xnregister_enter() may reschedule, only register
	   complete objects, so that the registry cannot return handles to
	   half-baked objects... */

	if (name) {
		xnpnode_t *pnode = &__cond_pnode;

		if (!*name) {
			/* Since this is an anonymous object (empty name on entry)
			   from user-space, it gets registered under an unique
			   internal name but is not exported through /proc. */
			xnobject_create_name(cond->name, sizeof(cond->name),
					     (void *)cond);
			pnode = NULL;
		}

		err = xnregistry_enter(cond->name, cond, &cond->handle, pnode);

		if (err)
			rt_cond_delete(cond);
	}
#endif /* CONFIG_XENO_OPT_REGISTRY */

	return err;
}

/**
 * @fn int rt_cond_delete(RT_COND *cond)
 * @brief Delete a condition variable.
 *
 * Destroy a condition variable and release all the tasks currently
 * pending on it.  A condition variable exists in the system since
 * rt_cond_create() has been called to create it, so this service must
 * be called in order to destroy it afterwards.
 *
 * @param cond The descriptor address of the affected condition
 * variable.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if @a cond is not a condition variable
 * descriptor.
 *
 * - -EIDRM is returned if @a cond is a deleted condition variable
 * descriptor.
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

int rt_cond_delete(RT_COND *cond)
{
	int err = 0, rc;
	spl_t s;

	if (xnpod_asynch_p())
		return -EPERM;

	xnlock_get_irqsave(&nklock, s);

	cond = xeno_h2obj_validate(cond, XENO_COND_MAGIC, RT_COND);

	if (!cond) {
		err = xeno_handle_error(cond, XENO_COND_MAGIC, RT_COND);
		goto unlock_and_exit;
	}

	removeq(cond->rqueue, &cond->rlink);

	rc = xnsynch_destroy(&cond->synch_base);

#ifdef CONFIG_XENO_OPT_REGISTRY
	if (cond->handle)
		xnregistry_remove(cond->handle);
#endif /* CONFIG_XENO_OPT_REGISTRY */

	xeno_mark_deleted(cond);

	if (rc == XNSYNCH_RESCHED)
		/* Some task has been woken up as a result of the deletion:
		   reschedule now. */
		xnpod_schedule();

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int rt_cond_signal(RT_COND *cond)
 * @brief Signal a condition variable.
 *
 * If the condition variable is pended, the first waiting task (by
 * queuing priority order) is immediately unblocked.
 *
 * @param cond The descriptor address of the affected condition
 * variable.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if @a cond is not a condition variable
 * descriptor.
 *
 * - -EIDRM is returned if @a cond is a deleted condition variable
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
 * Rescheduling: possible.
 */

int rt_cond_signal(RT_COND *cond)
{
	int err = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	cond = xeno_h2obj_validate(cond, XENO_COND_MAGIC, RT_COND);

	if (!cond) {
		err = xeno_handle_error(cond, XENO_COND_MAGIC, RT_COND);
		goto unlock_and_exit;
	}

	if (thread2rtask(xnsynch_wakeup_one_sleeper(&cond->synch_base)) != NULL) {
		xnsynch_set_owner(&cond->synch_base, NULL);	/* No ownership to track. */
		xnpod_schedule();
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int rt_cond_broadcast(RT_COND *cond)
 * @brief Broadcast a condition variable.
 *
 * If the condition variable is pended, all tasks currently waiting on
 * it are immediately unblocked.
 *
 * @param cond The descriptor address of the affected condition
 * variable.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if @a cond is not a condition variable
 * descriptor.
 *
 * - -EIDRM is returned if @a cond is a deleted condition variable
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
 * Rescheduling: possible.
 */

int rt_cond_broadcast(RT_COND *cond)
{
	int err = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	cond = xeno_h2obj_validate(cond, XENO_COND_MAGIC, RT_COND);

	if (!cond) {
		err = xeno_handle_error(cond, XENO_COND_MAGIC, RT_COND);
		goto unlock_and_exit;
	}

	if (xnsynch_flush(&cond->synch_base, 0) == XNSYNCH_RESCHED)
		xnpod_schedule();

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int rt_cond_wait(RT_COND *cond, RT_MUTEX *mutex, RTIME timeout)
 * @brief Wait on a condition.
 *
 * This service atomically release the mutex and causes the calling
 * task to block on the specified condition variable. The caller will
 * be unblocked when the variable is signaled, and the mutex
 * re-acquired before returning from this service.

 * Tasks pend on condition variables by priority order.
 *
 * @param cond The descriptor address of the affected condition
 * variable.
 *
 * @param mutex The descriptor address of the mutex protecting the
 * condition variable.
 *
 * @param timeout The number of clock ticks to wait for the condition
 * variable to be signaled (see note). Passing TM_INFINITE causes the
 * caller to block indefinitely until the condition variable is
 * signaled.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if @a mutex is not a mutex descriptor, or @a
 * cond is not a condition variable descriptor.
 *
 * - -EIDRM is returned if @a mutex or @a cond is a deleted object
 * descriptor, including if the deletion occurred while the caller was
 * sleeping on the variable.
 *
 * - -ETIMEDOUT is returned if @a timeout expired before the condition
 * variable has been signaled.
 *
 * - -EINTR is returned if rt_task_unblock() has been called for the
 * waiting task before the condition variable has been signaled.
 *
 * - -EWOULDBLOCK is returned if @a timeout equals TM_NONBLOCK.
 *
 * Environments:
 *
 * This service can be called from:
 *
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

int rt_cond_wait(RT_COND *cond, RT_MUTEX *mutex, RTIME timeout)
{
	int err = 0, kicked = 0;
	xnthread_t *thread;
	int lockcnt;
	spl_t s;

	if (timeout == TM_NONBLOCK)
		return -EWOULDBLOCK;

	if (xnpod_unblockable_p())
		return -EPERM;

	xnlock_get_irqsave(&nklock, s);

	cond = xeno_h2obj_validate(cond, XENO_COND_MAGIC, RT_COND);

	if (!cond) {
		err = xeno_handle_error(cond, XENO_COND_MAGIC, RT_COND);
		goto unlock_and_exit;
	}

	mutex = xeno_h2obj_validate(mutex, XENO_MUTEX_MAGIC, RT_MUTEX);

	if (!mutex) {
		err = xeno_handle_error(mutex, XENO_MUTEX_MAGIC, RT_MUTEX);
		goto unlock_and_exit;
	}

	thread = xnpod_current_thread();

	if (thread != xnsynch_owner(&mutex->synch_base)) {
		err = -EPERM;
		goto unlock_and_exit;
	}

	/*
	 * We can't use rt_mutex_release since that might reschedule
	 * before enter xnsynch_sleep_on, hence most of the code is
	 * duplicated here.
	 */
	lockcnt = mutex->lockcnt; /* Leave even if mutex is nested */

	mutex->lockcnt = 0;

	if (xnsynch_wakeup_one_sleeper(&mutex->synch_base)) {
		mutex->lockcnt = 1;
		/* Scheduling deferred */
	}

	xnsynch_sleep_on(&cond->synch_base, timeout, XN_RELATIVE);

	if (xnthread_test_info(thread, XNRMID))
		err = -EIDRM;	/* Condvar deleted while pending. */
	else if (xnthread_test_info(thread, XNTIMEO))
		err = -ETIMEDOUT;	/* Timeout. */
	else if (xnthread_test_info(thread, XNBREAK)) {
		err = -EINTR;	/* Unblocked. */
		kicked = xnthread_test_info(thread, XNKICKED);
	}

	rt_mutex_acquire(mutex, TM_INFINITE);

	mutex->lockcnt = lockcnt; /* Adjust lockcnt */

	if (kicked)
		xnthread_set_info(thread, XNKICKED);

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int rt_cond_inquire(RT_COND *cond, RT_COND_INFO *info)
 * @brief Inquire about a condition variable.
 *
 * Return various information about the status of a given condition
 * variable.
 *
 * @param cond The descriptor address of the inquired condition
 * variable.
 *
 * @param info The address of a structure the condition variable
 * information will be written to.

 * @return 0 is returned and status information is written to the
 * structure pointed at by @a info upon success. Otherwise:
 *
 * - -EINVAL is returned if @a cond is not a condition variable
 * descriptor.
 *
 * - -EIDRM is returned if @a cond is a deleted condition variable
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

int rt_cond_inquire(RT_COND *cond, RT_COND_INFO *info)
{
	int err = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	cond = xeno_h2obj_validate(cond, XENO_COND_MAGIC, RT_COND);

	if (!cond) {
		err = xeno_handle_error(cond, XENO_COND_MAGIC, RT_COND);
		goto unlock_and_exit;
	}

	strcpy(info->name, cond->name);
	info->nwaiters = xnsynch_nsleepers(&cond->synch_base);

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int rt_cond_bind(RT_COND *cond, const char *name, RTIME timeout)
 * @brief Bind to a condition variable.
 *
 * This user-space only service retrieves the uniform descriptor of a
 * given Xenomai condition variable identified by its symbolic name. If
 * the condition variable does not exist on entry, this service blocks
 * the caller until a condition variable of the given name is created.
 *
 * @param name A valid NULL-terminated name which identifies the
 * condition variable to bind to.
 *
 * @param cond The address of a condition variable descriptor
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
 * - -EFAULT is returned if @a cond or @a name is referencing invalid
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
 * @fn int rt_cond_unbind(RT_COND *cond)
 *
 * @brief Unbind from a condition variable.
 *
 * This user-space only service unbinds the calling task from the
 * condition variable object previously retrieved by a call to
 * rt_cond_bind().
 *
 * @param cond The address of a condition variable descriptor to
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

int __native_cond_pkg_init(void)
{
	return 0;
}

void __native_cond_pkg_cleanup(void)
{
	__native_cond_flush_rq(&__native_global_rholder.condq);
}

/*@}*/

EXPORT_SYMBOL(rt_cond_create);
EXPORT_SYMBOL(rt_cond_delete);
EXPORT_SYMBOL(rt_cond_signal);
EXPORT_SYMBOL(rt_cond_broadcast);
EXPORT_SYMBOL(rt_cond_wait);
EXPORT_SYMBOL(rt_cond_inquire);
