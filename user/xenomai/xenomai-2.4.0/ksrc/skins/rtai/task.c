/**
 *
 * @note Copyright (C) 2004 Philippe Gerum <rpm@xenomai.org> 
 * @note Copyright (C) 2005 Nextream France S.A.
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

#include <nucleus/pod.h>
#include <nucleus/heap.h>
#include <rtai/task.h>

static DEFINE_XNQUEUE(__rtai_task_q);

static int __rtai_task_sig;

static int __task_get_denormalized_prio(xnthread_t *thread)
{
	return XNCORE_HIGH_PRIO - xnthread_current_priority(thread) + 1;
}

static unsigned __task_get_magic(void)
{
	return RTAI_SKIN_MAGIC;
}

static xnthrops_t __rtai_task_ops = {
	.get_denormalized_prio = &__task_get_denormalized_prio,
	.get_magic = &__task_get_magic,
};

static void __task_delete_hook(xnthread_t *thread)
{
	RT_TASK *task;

	if (xnthread_get_magic(thread) != RTAI_SKIN_MAGIC)
		return;

	task = thread2rtask(thread);

	removeq(&__rtai_task_q, &task->link);

	rtai_mark_deleted(task);

	if (xnthread_test_state(&task->thread_base, XNSHADOW))
		xnheap_schedule_free(&kheap, task, &task->link);
}

static void __task_switch_hook(xnthread_t *thread)
{
	if (xnthread_get_magic(thread) == RTAI_SKIN_MAGIC) {
		RT_TASK *task = thread2rtask(thread);

		if (task->sigfn)
			task->sigfn();
	}
}

int __rtai_task_pkg_init(void)
{
	xnpod_add_hook(XNHOOK_THREAD_DELETE, &__task_delete_hook);

	return 0;
}

void __rtai_task_pkg_cleanup(void)
{
	xnholder_t *holder;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	while ((holder = getheadq(&__rtai_task_q)) != NULL) {
		RT_TASK *task = link2rtask(holder);
		xnpod_abort_thread(&task->thread_base);
		xnlock_sync_irq(&nklock, s);
	}

	xnlock_put_irqrestore(&nklock, s);

	xnpod_remove_hook(XNHOOK_THREAD_DELETE, &__task_delete_hook);

	if (__rtai_task_sig)
		xnpod_remove_hook(XNHOOK_THREAD_SWITCH, &__task_switch_hook);
}

static void rt_task_trampoline(void *cookie)
{
	RT_TASK *task = (RT_TASK *)cookie;
	task->body(task->cookie);
	rt_task_delete(task);
}

int rt_task_init(RT_TASK *task,
		 void (*body) (int),
		 int cookie,
		 int stack_size,
		 int priority, int uses_fpu, void (*sigfn) (void))
{
	xnflags_t bflags = 0;
	int err;
	spl_t s;

	if (priority < XNCORE_LOW_PRIO ||
	    priority > XNCORE_HIGH_PRIO || task->magic == RTAI_TASK_MAGIC)
		return -EINVAL;

	priority = XNCORE_HIGH_PRIO - priority + 1;	/* Normalize. */

	if (uses_fpu)
#ifdef CONFIG_XENO_HW_FPU
		bflags |= XNFPU;
#else /* !CONFIG_XENO_HW_FPU */
		return -EINVAL;
#endif /* CONFIG_XENO_HW_FPU */

	if (xnpod_init_thread(&task->thread_base, rtai_tbase,
			      NULL, priority, bflags, stack_size,
			      &__rtai_task_ops) != 0)
		/* Assume this is the only possible failure. */
		return -ENOMEM;

	xnarch_cpus_clear(task->affinity);
	inith(&task->link);
	task->suspend_depth = 1;
	task->cookie = cookie;
	task->body = body;
	task->sigfn = sigfn;

	if (xnarch_cpus_empty(task->affinity))
		task->affinity = XNPOD_ALL_CPUS;
	
	xnlock_get_irqsave(&nklock, s);

	err = xnpod_start_thread(&task->thread_base, XNSUSP,	/* Suspend on startup. */
				 0, task->affinity, &rt_task_trampoline, task);
	if (err)
		goto unlock_and_exit;

	task->magic = RTAI_TASK_MAGIC;
	appendq(&__rtai_task_q, &task->link);

	/* Add a switch hook only if a signal function has been declared
	   at least once for some created task. */

	if (sigfn != NULL && __rtai_task_sig++ == 0)
		xnpod_add_hook(XNHOOK_THREAD_SWITCH, &__task_switch_hook);

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err ? -EINVAL : 0;
}

int __rtai_task_resume(RT_TASK *task)
{
	int err = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	task = rtai_h2obj_validate(task, RTAI_TASK_MAGIC, RT_TASK);

	if (!task) {
		err = -EINVAL;
		goto unlock_and_exit;
	}

	if (task->suspend_depth > 0 && --task->suspend_depth == 0) {
		xnpod_resume_thread(&task->thread_base, XNSUSP);
		xnpod_schedule();
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

int __rtai_task_suspend(RT_TASK *task)
{
	int err = 0;
	spl_t s;

	if (!task) {
		if (!xnpod_primary_p())
			return -EINVAL;

		task = rtai_current_task();
	}

	xnlock_get_irqsave(&nklock, s);

	task = rtai_h2obj_validate(task, RTAI_TASK_MAGIC, RT_TASK);

	if (!task) {
		err = -EINVAL;
		goto unlock_and_exit;
	}

	if (task->suspend_depth++ == 0) {
		xnpod_suspend_thread(&task->thread_base,
				     XNSUSP, XN_INFINITE, XN_RELATIVE, NULL);
		if (xnthread_test_info(&task->thread_base, XNBREAK))
			err = -EINTR;
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

int __rtai_task_delete(RT_TASK *task)
{
	int err = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	task = rtai_h2obj_validate(task, RTAI_TASK_MAGIC, RT_TASK);

	if (!task) {
		err = -EINVAL;
		goto unlock_and_exit;
	}

	if (task->sigfn != NULL && --__rtai_task_sig == 0)
		xnpod_remove_hook(XNHOOK_THREAD_SWITCH, &__task_switch_hook);

	/* Does not return if task is current. */
	xnpod_delete_thread(&task->thread_base);

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

int rt_task_make_periodic_relative_ns(RT_TASK *task,
				      RTIME start_delay, RTIME period)
{
	RTIME idate;
	int err;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	task = rtai_h2obj_validate(task, RTAI_TASK_MAGIC, RT_TASK);

	if (!task) {
		err = -EINVAL;
		goto unlock_and_exit;
	}

	idate =
	    start_delay ? xntbase_ticks2ns(rtai_tbase,
					   xntbase_get_time(rtai_tbase)) +
	    start_delay : XN_INFINITE;

	err = xnpod_set_thread_periodic(&task->thread_base, idate, period);

	if (task->suspend_depth > 0 && --task->suspend_depth == 0) {
		xnpod_resume_thread(&task->thread_base, XNSUSP);
		xnpod_schedule();
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

int rt_task_make_periodic(RT_TASK *task, RTIME start_time, RTIME period)
{
	int err;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	task = rtai_h2obj_validate(task, RTAI_TASK_MAGIC, RT_TASK);

	if (!task) {
		err = -EINVAL;
		goto unlock_and_exit;
	}

	if (start_time <= xntbase_get_time(rtai_tbase))
		start_time = XN_INFINITE;

	err = xnpod_set_thread_periodic(&task->thread_base, start_time, period);

	if (task->suspend_depth > 0 && --task->suspend_depth == 0) {
		xnpod_resume_thread(&task->thread_base, XNSUSP);
		xnpod_schedule();
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

void __rtai_task_wait_period(void)
{
	xnpod_wait_thread_period(NULL);
}

EXPORT_SYMBOL(rt_task_init);
EXPORT_SYMBOL(__rtai_task_resume);
EXPORT_SYMBOL(__rtai_task_suspend);
EXPORT_SYMBOL(__rtai_task_delete);
EXPORT_SYMBOL(rt_task_make_periodic_relative_ns);
EXPORT_SYMBOL(rt_task_make_periodic);
EXPORT_SYMBOL(__rtai_task_wait_period);
