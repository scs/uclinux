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
 * \ingroup mutex
 */

/*!
 * \ingroup native
 * \defgroup mutex Mutex services.
 *
 * Mutex services.
 *
 * A mutex is a MUTual EXclusion object, and is useful for protecting
 * shared data structures from concurrent modifications, and
 * implementing critical sections and monitors.
 *
 * A mutex has two possible states: unlocked (not owned by any task),
 * and locked (owned by one task). A mutex can never be owned by two
 * different tasks simultaneously. A task attempting to lock a mutex
 * that is already locked by another task is blocked until the latter
 * unlocks the mutex first.
 *
 * Xenomai mutex services enforce a priority inheritance protocol in
 * order to solve priority inversions.
 *
 *@{*/

/** @example mutex.c */

#include <nucleus/pod.h>
#include <nucleus/registry.h>
#include <nucleus/heap.h>
#include <native/task.h>
#include <native/mutex.h>

#ifdef CONFIG_XENO_EXPORT_REGISTRY

static int __mutex_read_proc(char *page,
			     char **start,
			     off_t off, int count, int *eof, void *data)
{
	RT_MUTEX *mutex = (RT_MUTEX *)data;
	char *p = page;
	int len;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (xnsynch_owner(&mutex->synch_base) != NULL) {
		xnpholder_t *holder;

		/* Locked mutex -- dump owner and waiters, if any. */

		p += sprintf(p, "=locked by %s depth=%d\n",
			     xnthread_name(xnsynch_owner(&mutex->synch_base)),
			     mutex->lockcnt);

		holder = getheadpq(xnsynch_wait_queue(&mutex->synch_base));

		while (holder) {
			xnthread_t *sleeper = link2thread(holder, plink);
			p += sprintf(p, "+%s\n", xnthread_name(sleeper));
			holder =
			    nextpq(xnsynch_wait_queue(&mutex->synch_base),
				   holder);
		}
	} else
		/* Mutex unlocked. */
		p += sprintf(p, "=unlocked\n");

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

static xnpnode_t __mutex_pnode = {

	.dir = NULL,
	.type = "mutexes",
	.entries = 0,
	.read_proc = &__mutex_read_proc,
	.write_proc = NULL,
	.root = &__native_ptree,
};

#elif defined(CONFIG_XENO_OPT_REGISTRY)

static xnpnode_t __mutex_pnode = {

	.type = "mutexes"
};

#endif /* CONFIG_XENO_EXPORT_REGISTRY */

/**
 * @fn int rt_mutex_create(RT_MUTEX *mutex,const char *name)
 *
 * @brief Create a mutex.
 *
 * Create a mutual exclusion object that allows multiple tasks to
 * synchronize access to a shared resource. A mutex is left in an
 * unlocked state after creation.
 *
 * @param mutex The address of a mutex descriptor Xenomai will use to
 * store the mutex-related data.  This descriptor must always be valid
 * while the mutex is active therefore it must be allocated in
 * permanent memory.
 *
 * @param name An ASCII string standing for the symbolic name of the
 * mutex. When non-NULL and non-empty, this string is copied to a safe
 * place into the descriptor, and passed to the registry package if
 * enabled for indexing the created mutex.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -ENOMEM is returned if the system fails to get enough dynamic
 * memory from the global real-time heap in order to register the
 * mutex.
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

int rt_mutex_create(RT_MUTEX *mutex, const char *name)
{
	int err = 0;
	spl_t s;

	if (xnpod_asynch_p())
		return -EPERM;

	xnsynch_init(&mutex->synch_base, XNSYNCH_PRIO | XNSYNCH_PIP);
	mutex->handle = 0;	/* i.e. (still) unregistered mutex. */
	mutex->magic = XENO_MUTEX_MAGIC;
	mutex->lockcnt = 0;
	xnobject_copy_name(mutex->name, name);
	inith(&mutex->rlink);
	mutex->rqueue = &xeno_get_rholder()->mutexq;
	xnlock_get_irqsave(&nklock, s);
	appendq(mutex->rqueue, &mutex->rlink);
	xnlock_put_irqrestore(&nklock, s);

#ifdef CONFIG_XENO_OPT_PERVASIVE
	mutex->cpid = 0;
#endif /* CONFIG_XENO_OPT_PERVASIVE */

#ifdef CONFIG_XENO_OPT_REGISTRY
	/* <!> Since xnregister_enter() may reschedule, only register
	   complete objects, so that the registry cannot return handles to
	   half-baked objects... */

	if (name) {
		xnpnode_t *pnode = &__mutex_pnode;

		if (!*name) {
			/* Since this is an anonymous object (empty name on entry)
			   from user-space, it gets registered under an unique
			   internal name but is not exported through /proc. */
			xnobject_create_name(mutex->name, sizeof(mutex->name),
					     (void *)mutex);
			pnode = NULL;
		}

		err =
		    xnregistry_enter(mutex->name, mutex, &mutex->handle, pnode);

		if (err)
			rt_mutex_delete(mutex);
	}
#endif /* CONFIG_XENO_OPT_REGISTRY */

	return err;
}

/**
 * @fn int rt_mutex_delete(RT_MUTEX *mutex)
 *
 * @brief Delete a mutex.
 *
 * Destroy a mutex and release all the tasks currently pending on it.
 * A mutex exists in the system since rt_mutex_create() has been
 * called to create it, so this service must be called in order to
 * destroy it afterwards.
 *
 * @param mutex The descriptor address of the affected mutex.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if @a mutex is not a mutex descriptor.
 *
 * - -EIDRM is returned if @a mutex is a deleted mutex descriptor.
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

int rt_mutex_delete(RT_MUTEX *mutex)
{
	int err = 0, rc;
	spl_t s;

	if (xnpod_asynch_p())
		return -EPERM;

	xnlock_get_irqsave(&nklock, s);

	mutex = xeno_h2obj_validate(mutex, XENO_MUTEX_MAGIC, RT_MUTEX);

	if (!mutex) {
		err = xeno_handle_error(mutex, XENO_MUTEX_MAGIC, RT_MUTEX);
		goto unlock_and_exit;
	}

	removeq(mutex->rqueue, &mutex->rlink);

	rc = xnsynch_destroy(&mutex->synch_base);

#ifdef CONFIG_XENO_OPT_REGISTRY
	if (mutex->handle)
		xnregistry_remove(mutex->handle);
#endif /* CONFIG_XENO_OPT_REGISTRY */

	xeno_mark_deleted(mutex);

	if (rc == XNSYNCH_RESCHED)
		/* Some task has been woken up as a result of the deletion:
		   reschedule now. */
		xnpod_schedule();

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int rt_mutex_acquire(RT_MUTEX *mutex, RTIME timeout)
 *
 * @brief Acquire a mutex.
 *
 * Attempt to lock a mutex. The calling task is blocked until the
 * mutex is available, in which case it is locked again before this
 * service returns. Mutexes have an ownership property, which means
 * that their current owner is tracked. Xenomai mutexes are implicitely
 * recursive and implement the priority inheritance protocol.
 *
 * Since a nested locking count is maintained for the current owner,
 * rt_mutex_acquire() and rt_mutex_release() must be used in pairs.
 *
 * Tasks pend on mutexes by priority order.
 *
 * @param mutex The descriptor address of the mutex to acquire.
 *
 * @param timeout The number of clock ticks to wait for the mutex to
 * be available to the calling task (see note). Passing TM_INFINITE
 * causes the caller to block indefinitely until the mutex is
 * available. Passing TM_NONBLOCK causes the service to return
 * immediately without waiting if the mutex is still locked by another
 * task.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if @a mutex is not a mutex descriptor.
 *
 * - -EIDRM is returned if @a mutex is a deleted mutex descriptor,
 * including if the deletion occurred while the caller was sleeping on
 * it.
 *
 * - -EWOULDBLOCK is returned if @a timeout is equal to TM_NONBLOCK
 * and the mutex is not immediately available.
 *
 * - -EINTR is returned if rt_task_unblock() has been called for the
 * waiting task before the mutex has become available.
 *
 * - -ETIMEDOUT is returned if the mutex cannot be made available to
 * the calling task within the specified amount of time.
 *
 * - -EPERM is returned if this service was called from a context
 * which cannot be given the ownership of the mutex (e.g. interrupt,
 * non-realtime or scheduler locked).
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel-based task
 * - User-space task (switches to primary mode)
 *
 * Rescheduling: always unless the request is immediately satisfied or
 * @a timeout specifies a non-blocking operation.  If the caller is
 * blocked, the current owner's priority might be temporarily raised
 * as a consequence of the priority inheritance protocol.
 *
 * @note The @a timeout value will be interpreted as jiffies if the
 * native skin is bound to a periodic time base (see
 * CONFIG_XENO_OPT_NATIVE_PERIOD), or nanoseconds otherwise.
 */

int rt_mutex_acquire(RT_MUTEX *mutex, RTIME timeout)
{
	xnthread_t *thread;
	int err = 0;
	spl_t s;

	if (xnpod_unblockable_p())
		return -EPERM;

	xnlock_get_irqsave(&nklock, s);

	mutex = xeno_h2obj_validate(mutex, XENO_MUTEX_MAGIC, RT_MUTEX);

	if (!mutex) {
		err = xeno_handle_error(mutex, XENO_MUTEX_MAGIC, RT_MUTEX);
		goto unlock_and_exit;
	}

	thread = xnpod_current_thread();

	if (xnsynch_owner(&mutex->synch_base) == NULL) {
		xnsynch_set_owner(&mutex->synch_base, thread);
		goto grab_mutex;
	}

	if (xnsynch_owner(&mutex->synch_base) == thread) {
		mutex->lockcnt++;
		goto unlock_and_exit;
	}

	if (timeout == TM_NONBLOCK) {
		err = -EWOULDBLOCK;
		goto unlock_and_exit;
	}

	xnsynch_sleep_on(&mutex->synch_base, timeout, XN_RELATIVE);

	if (xnthread_test_info(thread, XNRMID))
		err = -EIDRM;	/* Mutex deleted while pending. */
	else if (xnthread_test_info(thread, XNTIMEO))
		err = -ETIMEDOUT;	/* Timeout. */
	else if (xnthread_test_info(thread, XNBREAK))
		err = -EINTR;	/* Unblocked. */
	else {
	      grab_mutex:
		/* xnsynch_sleep_on() might have stolen the resource,
		   so we need to put our internal data in sync. */
		mutex->lockcnt = 1;
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int rt_mutex_release(RT_MUTEX *mutex)
 *
 * @brief Unlock mutex.
 *
 * Release a mutex. If the mutex is pended, the first waiting task (by
 * priority order) is immediately unblocked and transfered the
 * ownership of the mutex; otherwise, the mutex is left in an unlocked
 * state.
 *
 * @param mutex The descriptor address of the released mutex.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if @a mutex is not a mutex descriptor.
 *
 * - -EIDRM is returned if @a mutex is a deleted mutex descriptor.
 *
 * - -EPERM is returned if @a mutex is not owned by the current task,
 * or more generally if this service was called from a context which
 * cannot own any mutex (e.g. interrupt, or non-realtime context).
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel-based task
 * - User-space task (switches to primary mode)
 *
 * Rescheduling: possible.
 */

int rt_mutex_release(RT_MUTEX *mutex)
{
	int err = 0;
	spl_t s;

	if (xnpod_unblockable_p())
		return -EPERM;

	xnlock_get_irqsave(&nklock, s);

	mutex = xeno_h2obj_validate(mutex, XENO_MUTEX_MAGIC, RT_MUTEX);

	if (!mutex) {
		err = xeno_handle_error(mutex, XENO_MUTEX_MAGIC, RT_MUTEX);
		goto unlock_and_exit;
	}

	if (xnpod_current_thread() != xnsynch_owner(&mutex->synch_base)) {
		err = -EPERM;
		goto unlock_and_exit;
	}

	if (--mutex->lockcnt > 0)
		goto unlock_and_exit;

	if (xnsynch_wakeup_one_sleeper(&mutex->synch_base)) {
		mutex->lockcnt = 1;
		xnpod_schedule();
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int rt_mutex_inquire(RT_MUTEX *mutex, RT_MUTEX_INFO *info)
 *
 * @brief Inquire about a mutex.
 *
 * Return various information about the status of a given mutex.
 *
 * @param mutex The descriptor address of the inquired mutex.
 *
 * @param info The address of a structure the mutex information will
 * be written to.

 * @return 0 is returned and status information is written to the
 * structure pointed at by @a info upon success. Otherwise:
 *
 * - -EINVAL is returned if @a mutex is not a mutex descriptor.
 *
 * - -EIDRM is returned if @a mutex is a deleted mutex descriptor.
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

int rt_mutex_inquire(RT_MUTEX *mutex, RT_MUTEX_INFO *info)
{
	int err = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	mutex = xeno_h2obj_validate(mutex, XENO_MUTEX_MAGIC, RT_MUTEX);

	if (!mutex) {
		err = xeno_handle_error(mutex, XENO_MUTEX_MAGIC, RT_MUTEX);
		goto unlock_and_exit;
	}

	strcpy(info->name, mutex->name);
	info->lockcnt = mutex->lockcnt;
	info->nwaiters = xnsynch_nsleepers(&mutex->synch_base);

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int rt_mutex_bind(RT_MUTEX *mutex,const char *name,RTIME timeout)
 *
 * @brief Bind to a mutex.
 *
 * This user-space only service retrieves the uniform descriptor of a
 * given Xenomai mutex identified by its symbolic name. If the mutex does
 * not exist on entry, this service blocks the caller until a mutex of
 * the given name is created.
 *
 * @param name A valid NULL-terminated name which identifies the
 * mutex to bind to.
 *
 * @param mutex The address of a mutex descriptor retrieved by the
 * operation. Contents of this memory is undefined upon failure.
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
 * - -EFAULT is returned if @a mutex or @a name is referencing invalid
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
 * @fn int rt_mutex_unbind(RT_MUTEX *mutex)
 *
 * @brief Unbind from a mutex.
 *
 * This user-space only service unbinds the calling task from the
 * mutex object previously retrieved by a call to rt_mutex_bind().
 *
 * @param mutex The address of a mutex descriptor to unbind from.
 *
 * @return 0 is always returned.
 *
 * This service can be called from:
 *
 * - User-space task.
 *
 * Rescheduling: never.
 */

int __native_mutex_pkg_init(void)
{
	return 0;
}

void __native_mutex_pkg_cleanup(void)
{
	__native_mutex_flush_rq(&__native_global_rholder.mutexq);
}

/*@}*/

EXPORT_SYMBOL(rt_mutex_create);
EXPORT_SYMBOL(rt_mutex_delete);
EXPORT_SYMBOL(rt_mutex_acquire);
EXPORT_SYMBOL(rt_mutex_release);
EXPORT_SYMBOL(rt_mutex_inquire);
