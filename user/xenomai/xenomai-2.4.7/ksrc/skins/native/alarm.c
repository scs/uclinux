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
 * \ingroup alarm
 */

/*!
 * \ingroup native
 * \defgroup alarm Alarm services.
 *
 * Alarms are general watchdog timers. Any Xenomai task may create any
 * number of alarms and use them to run a user-defined handler, after
 * a specified initial delay has elapsed. Alarms can be either one
 * shot or periodic; in the latter case, the real-time kernel
 * automatically reprograms the alarm for the next shot according to a
 * user-defined interval value.
 *
 *@{*/

/** @example user_alarm.c */

#include <nucleus/pod.h>
#include <nucleus/registry.h>
#include <nucleus/heap.h>
#include <native/task.h>
#include <native/alarm.h>
#include <native/timer.h>

#ifdef CONFIG_XENO_EXPORT_REGISTRY

static int __alarm_read_proc(char *page,
			     char **start,
			     off_t off, int count, int *eof, void *data)
{
	RT_ALARM *alarm = (RT_ALARM *)data;
	char *p = page;
	int len;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	p += sprintf(p, "interval=%Lu:expiries=%lu\n",
		     rt_timer_tsc2ns(xntimer_interval(&alarm->timer_base)),
		     alarm->expiries);

#ifdef CONFIG_XENO_OPT_PERVASIVE
	{
		xnpholder_t *holder =
		    getheadpq(xnsynch_wait_queue(&alarm->synch_base));

		while (holder) {
			xnthread_t *sleeper = link2thread(holder, plink);
			p += sprintf(p, "+%s\n", xnthread_name(sleeper));
			holder =
			    nextpq(xnsynch_wait_queue(&alarm->synch_base),
				   holder);
		}
	}
#endif /* CONFIG_XENO_OPT_PERVASIVE */

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

static xnpnode_t __alarm_pnode = {

	.dir = NULL,
	.type = "alarms",
	.entries = 0,
	.read_proc = &__alarm_read_proc,
	.write_proc = NULL,
	.root = &__native_ptree,
};

#elif defined(CONFIG_XENO_OPT_REGISTRY)

static xnpnode_t __alarm_pnode = {

	.type = "alarms"
};

#endif /* CONFIG_XENO_EXPORT_REGISTRY */

int __native_alarm_pkg_init(void)
{
	return 0;
}

void __native_alarm_pkg_cleanup(void)
{
	__native_alarm_flush_rq(&__native_global_rholder.alarmq);
}

static void __alarm_trampoline(xntimer_t *timer)
{
	RT_ALARM *alarm = container_of(timer, RT_ALARM, timer_base);
	++alarm->expiries;
	alarm->handler(alarm, alarm->cookie);
}

/**
 * @fn int rt_alarm_create(RT_ALARM *alarm,const char *name,rt_alarm_t handler,void *cookie)
 * @brief Create an alarm object from kernel space.
 *
 * Create an object triggering an alarm routine at a specified time in
 * the future. Alarms can be made periodic or oneshot, depending on
 * the reload interval value passed to rt_alarm_start() for them. In
 * kernel space, alarms are immediately notified on behalf of the
 * timer interrupt to a user-defined handler.
 *
 * @param alarm The address of an alarm descriptor Xenomai will use to
 * store the alarm-related data.  This descriptor must always be valid
 * while the alarm is active therefore it must be allocated in
 * permanent memory.
 *
 * @param name An ASCII string standing for the symbolic name of the
 * alarm. When non-NULL and non-empty, this string is copied to a safe
 * place into the descriptor, and passed to the registry package if
 * enabled for indexing the created alarm.
 *
 * @param handler The address of the routine to call when the alarm
 * expires. This routine will be passed the address of the current
 * alarm descriptor, and the opaque @a cookie.
 *
 * @param cookie A user-defined opaque cookie the real-time kernel
 * will pass to the alarm handler as its second argument.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -ENOMEM is returned if the system fails to get enough dynamic
 * memory from the global real-time heap in order to register the
 * alarm.
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
 *
 * Rescheduling: possible.
 *
 * @note It is possible to combine kernel-based alarm handling with
 * waiter threads pending on the same alarm object from user-space
 * through the rt_alarm_wait() service. For this purpose, the
 * rt_alarm_handler() routine which is internally invoked to wake up
 * alarm servers in user-space is accessible to user-provided alarm
 * handlers in kernel space, and should be called from there in order
 * to unblock any thread sleeping on the rt_alarm_wait() service.
 */

int rt_alarm_create(RT_ALARM *alarm,
		    const char *name, rt_alarm_t handler, void *cookie)
{
	int err = 0;
	spl_t s;

	if (xnpod_asynch_p())
		return -EPERM;

	xntimer_init(&alarm->timer_base, __native_tbase, __alarm_trampoline);
	alarm->handle = 0;	/* i.e. (still) unregistered alarm. */
	alarm->magic = XENO_ALARM_MAGIC;
	alarm->expiries = 0;
	alarm->handler = handler;
	alarm->cookie = cookie;
	xnobject_copy_name(alarm->name, name);
	inith(&alarm->rlink);
	alarm->rqueue = &xeno_get_rholder()->alarmq;
	xnlock_get_irqsave(&nklock, s);
	appendq(alarm->rqueue, &alarm->rlink);
	xnlock_put_irqrestore(&nklock, s);

#ifdef CONFIG_XENO_OPT_PERVASIVE
	xnsynch_init(&alarm->synch_base, XNSYNCH_PRIO);
	alarm->cpid = 0;
#endif /* CONFIG_XENO_OPT_PERVASIVE */

	if (name) {
#ifdef CONFIG_XENO_OPT_REGISTRY
		/* <!> Since xnregister_enter() may reschedule, only register
		   complete objects, so that the registry cannot return
		   handles to half-baked objects... */

		xnpnode_t *pnode = &__alarm_pnode;

		if (!*name) {
			/* Since this is an anonymous object (empty name on entry)
			   from user-space, it gets registered under an unique
			   internal name but is not exported through /proc. */
			xnobject_create_name(alarm->name, sizeof(alarm->name),
					     (void *)alarm);
			pnode = NULL;
		}

		err =
		    xnregistry_enter(alarm->name, alarm, &alarm->handle, pnode);

		if (err)
			rt_alarm_delete(alarm);
#endif /* CONFIG_XENO_OPT_REGISTRY */

		xntimer_set_name(&alarm->timer_base, alarm->name);
	}

	return err;
}

/**
 * @fn int rt_alarm_delete(RT_ALARM *alarm)
 * @brief Delete an alarm.
 *
 * Destroy an alarm. An alarm exists in the system since
 * rt_alarm_create() has been called to create it, so this service
 * must be called in order to destroy it afterwards.
 *
 * @param alarm The descriptor address of the affected alarm.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if @a alarm is not a alarm descriptor.
 *
 * - -EIDRM is returned if @a alarm is a deleted alarm descriptor.
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
 * Rescheduling: never.
 */

int rt_alarm_delete(RT_ALARM *alarm)
{
	int err = 0, rc = 0;
	spl_t s;

	if (xnpod_asynch_p())
		return -EPERM;

	xnlock_get_irqsave(&nklock, s);

	alarm = xeno_h2obj_validate(alarm, XENO_ALARM_MAGIC, RT_ALARM);

	if (!alarm) {
		err = xeno_handle_error(alarm, XENO_ALARM_MAGIC, RT_ALARM);
		goto unlock_and_exit;
	}

	removeq(alarm->rqueue, &alarm->rlink);

	xntimer_destroy(&alarm->timer_base);

#ifdef CONFIG_XENO_OPT_PERVASIVE
	rc = xnsynch_destroy(&alarm->synch_base);
#endif /* CONFIG_XENO_OPT_PERVASIVE */

#ifdef CONFIG_XENO_OPT_REGISTRY
	if (alarm->handle)
		xnregistry_remove(alarm->handle);
#endif /* CONFIG_XENO_OPT_REGISTRY */

	xeno_mark_deleted(alarm);

	if (rc == XNSYNCH_RESCHED)
		/* Some task has been woken up as a result of the deletion:
		   reschedule now. */
		xnpod_schedule();

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int rt_alarm_start(RT_ALARM *alarm,RTIME value,RTIME interval)
 * @brief Start an alarm.
 *
 * Program the trigger date of an alarm object. An alarm can be either
 * periodic or oneshot, depending on the reload value passed to this
 * routine. The given alarm must have been previously created by a
 * call to rt_alarm_create().
 *
 * Alarm handlers are always called on behalf of Xenomai's internal timer
 * tick handler, so the Xenomai services which can be called from such
 * handlers are restricted to the set of services available on behalf
 * of any ISR.
 *
 * This service overrides any previous setup of the expiry date and
 * reload interval for the given alarm.
 *
 * @param alarm The descriptor address of the affected alarm.
 *
 * @param value The relative date of the initial alarm shot, expressed
 * in clock ticks (see note).
 *
 * @param interval The reload value of the alarm. It is a periodic
 * interval value to be used for reprogramming the next alarm shot,
 * expressed in clock ticks (see note). If @a interval is equal to
 * TM_INFINITE, the alarm will not be reloaded after it has expired.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if @a alarm is not a alarm descriptor.
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
 * @note The initial @a value and @a interval will be interpreted as
 * jiffies if the native skin is bound to a periodic time base (see
 * CONFIG_XENO_OPT_NATIVE_PERIOD), or nanoseconds otherwise.
 */

int rt_alarm_start(RT_ALARM *alarm, RTIME value, RTIME interval)
{
	int err = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	alarm = xeno_h2obj_validate(alarm, XENO_ALARM_MAGIC, RT_ALARM);

	if (!alarm) {
		err = xeno_handle_error(alarm, XENO_ALARM_MAGIC, RT_ALARM);
		goto unlock_and_exit;
	}

	xntimer_start(&alarm->timer_base, value, interval, XN_RELATIVE);

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int rt_alarm_stop(RT_ALARM *alarm)
 * @brief Stop an alarm.
 *
 * Disarm an alarm object previously armed using rt_alarm_start() so
 * that it will not trigger until is is re-armed.
 *
 * @param alarm The descriptor address of the released alarm.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if @a alarm is not a alarm descriptor.
 *
 * - -EIDRM is returned if @a alarm is a deleted alarm descriptor.
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

int rt_alarm_stop(RT_ALARM *alarm)
{
	int err = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	alarm = xeno_h2obj_validate(alarm, XENO_ALARM_MAGIC, RT_ALARM);

	if (!alarm) {
		err = xeno_handle_error(alarm, XENO_ALARM_MAGIC, RT_ALARM);
		goto unlock_and_exit;
	}

	xntimer_stop(&alarm->timer_base);

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int rt_alarm_inquire(RT_ALARM *alarm, RT_ALARM_INFO *info)
 * @brief Inquire about an alarm.
 *
 * Return various information about the status of a given alarm.
 *
 * @param alarm The descriptor address of the inquired alarm.
 *
 * @param info The address of a structure the alarm information will
 * be written to.
 *
 * The expiration date returned in the information block is converted
 * to the current time unit. The special value TM_INFINITE is returned
 * if @a alarm is currently inactive/stopped. In single-shot mode, it
 * might happen that the alarm has already expired when this service
 * is run (even if the associated handler has not been fired yet); in
 * such a case, 1 is returned.
 *
 * @return 0 is returned and status information is written to the
 * structure pointed at by @a info upon success. Otherwise:
 *
 * - -EINVAL is returned if @a alarm is not a alarm descriptor.
 *
 * - -EIDRM is returned if @a alarm is a deleted alarm descriptor.
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

int rt_alarm_inquire(RT_ALARM *alarm, RT_ALARM_INFO *info)
{
	int err = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	alarm = xeno_h2obj_validate(alarm, XENO_ALARM_MAGIC, RT_ALARM);

	if (!alarm) {
		err = xeno_handle_error(alarm, XENO_ALARM_MAGIC, RT_ALARM);
		goto unlock_and_exit;
	}

	strcpy(info->name, alarm->name);
	info->expiration = xntimer_get_timeout(&alarm->timer_base);
	info->expiries = alarm->expiries;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int rt_alarm_create(RT_ALARM *alarm,const char *name)
 * @brief Create an alarm object from user-space.
 *
 * Initializes an alarm object from a user-space application.  Alarms
 * can be made periodic or oneshot, depending on the reload interval
 * value passed to rt_alarm_start() for them. In this mode, the basic
 * principle is to define some alarm server task which routinely waits
 * for the next incoming alarm event through the rt_alarm_wait()
 * syscall.
 *
 * @param alarm The address of an alarm descriptor Xenomai will use to
 * store the alarm-related data.  This descriptor must always be valid
 * while the alarm is active therefore it must be allocated in
 * permanent memory.
 *
 * @param name An ASCII string standing for the symbolic name of the
 * alarm. When non-NULL and non-empty, this string is copied to a safe
 * place into the descriptor, and passed to the registry package if
 * enabled for indexing the created alarm.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -ENOMEM is returned if the system fails to get enough dynamic
 * memory from the global real-time heap in order to register the
 * alarm.
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
 * - User-space task
 *
 * Rescheduling: possible.
 *
 * @note It is possible to combine kernel-based alarm handling with
 * waiter threads pending on the same alarm object from user-space
 * through the rt_alarm_wait() service. For this purpose, the
 * rt_alarm_handler() routine which is internally invoked to wake up
 * alarm servers in user-space is accessible to user-provided alarm
 * handlers in kernel space, and should be called from there in order
 * to unblock any thread sleeping on the rt_alarm_wait() service.
 */

/**
 * @fn int rt_alarm_wait(RT_ALARM *alarm)
 * @brief Wait for the next alarm shot.
 *
 * This user-space only call allows the current task to suspend
 * execution until the specified alarm triggers. The priority of the
 * current task is raised above all other Xenomai tasks - except those
 * also undergoing an alarm or interrupt wait (see rt_intr_wait()) -
 * so that it would preempt any of them under normal circumstances
 * (i.e. no scheduler lock).
 *
 * @param alarm The descriptor address of the awaited alarm.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if @a alarm is not an alarm descriptor.
 *
 * - -EPERM is returned if this service was called from a context
 * which cannot sleep (e.g. interrupt, non-realtime or scheduler
 * locked).
 *
 * - -EIDRM is returned if @a alarm is a deleted alarm descriptor,
 * including if the deletion occurred while the caller was waiting for
 * its next shot.
 *
 * - -EINTR is returned if rt_task_unblock() has been called for the
 * current task before the next alarm shot.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - User-space task
 *
 * Rescheduling: always.
 */

/*@}*/

EXPORT_SYMBOL(rt_alarm_create);
EXPORT_SYMBOL(rt_alarm_delete);
EXPORT_SYMBOL(rt_alarm_start);
EXPORT_SYMBOL(rt_alarm_stop);
EXPORT_SYMBOL(rt_alarm_inquire);
