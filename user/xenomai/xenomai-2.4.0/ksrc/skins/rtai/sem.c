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
#include <nucleus/synch.h>
#include <rtai/sem.h>
#include <rtai/task.h>

void rt_typed_sem_init(SEM * sem, int value, int type)
{
	int mode = XNSYNCH_PRIO;

	if ((type & RES_SEM) == RES_SEM) {
		mode |= XNSYNCH_PIP;
		value = 0;	/* We will use this as a lock count. */
	} else {
		if ((type & BIN_SEM) && value > 1)
			value = 1;

		if ((type & FIFO_Q) != 0)
			mode = XNSYNCH_FIFO;
	}

	xnsynch_init(&sem->synch_base, mode);
	sem->count = value;
	sem->type = type & 0x3;
	sem->owner = NULL;
	sem->magic = RTAI_SEM_MAGIC;
}

int __rtai_sem_delete(SEM * sem)
{
	int err = 0, rc;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	sem = rtai_h2obj_validate(sem, RTAI_SEM_MAGIC, SEM);

	if (!sem) {
		err = SEM_ERR;
		goto unlock_and_exit;
	}

	rc = xnsynch_destroy(&sem->synch_base);

	rtai_mark_deleted(sem);

	if (rc == XNSYNCH_RESCHED)
		xnpod_schedule();

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

int rt_sem_signal(SEM * sem)
{
	int err = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	sem = rtai_h2obj_validate(sem, RTAI_SEM_MAGIC, SEM);

	if (!sem) {
		err = SEM_ERR;
		goto unlock_and_exit;
	}

	if (sem->type == RES_SEM) {
		if (rtai_current_task() != sem->owner) {
			/* <!> This is stricter than the original implementation. */
			err = SEM_ERR;
			goto unlock_and_exit;
		}

		if (--sem->count > 0)	/* Recursion counter. */
			goto unlock_and_exit;

		sem->owner =
		    thread2rtask(xnsynch_wakeup_one_sleeper(&sem->synch_base));

		if (sem->owner != NULL)
			xnpod_schedule();
	} else if (xnsynch_wakeup_one_sleeper(&sem->synch_base) != NULL)
		xnpod_schedule();
	else if (sem->type == CNT_SEM)
		sem->count++;
	else
		sem->count = 1;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

int rt_sem_wait(SEM * sem)
{
	RT_TASK *task;
	int err = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	sem = rtai_h2obj_validate(sem, RTAI_SEM_MAGIC, SEM);

	if (!sem) {
		err = SEM_ERR;
		goto unlock_and_exit;
	}

	task = rtai_current_task();

	if (sem->type == RES_SEM) {
		if (sem->owner == NULL) {
			xnsynch_set_owner(&sem->synch_base, &task->thread_base);
			goto grab_resource;
		} else if (sem->owner == task) {	/* Recursive lock. */
			err = ++sem->count;
			goto unlock_and_exit;
		}
	} else if (sem->count > 0) {
		err = sem->count--;
		goto unlock_and_exit;
	}

	xnsynch_sleep_on(&sem->synch_base, XN_INFINITE, XN_RELATIVE);

	if (xnthread_test_info(&task->thread_base, XNRMID))
		err = SEM_ERR;	/* Semaphore deleted while pending. */
	else if (xnthread_test_info(&task->thread_base, XNBREAK))
		err = -EINTR;	/* Unblocked. */
	else if (sem->type == RES_SEM) {
	      grab_resource:
		sem->owner = task;
		err = sem->count = 1;	/* Initial lock. */
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

int rt_sem_wait_if(SEM * sem)
{
	RT_TASK *task;
	int err = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	sem = rtai_h2obj_validate(sem, RTAI_SEM_MAGIC, SEM);

	if (!sem) {
		err = SEM_ERR;
		goto unlock_and_exit;
	}

	task = rtai_current_task();

	if (sem->type == RES_SEM) {
		if (sem->owner == NULL) {
			xnsynch_set_owner(&sem->synch_base, &task->thread_base);
			sem->owner = task;
			err = sem->count = 1;	/* Initial lock. */
		} else if (sem->owner == task)	/* Recursive lock. */
			err = ++sem->count;
	} else if (sem->count > 0)
		err = sem->count--;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

int __rtai_sem_pkg_init(void)
{
	return 0;
}

void __rtai_sem_pkg_cleanup(void)
{
}

EXPORT_SYMBOL(rt_typed_sem_init);
EXPORT_SYMBOL(__rtai_sem_delete);
EXPORT_SYMBOL(rt_sem_signal);
EXPORT_SYMBOL(rt_sem_wait);
EXPORT_SYMBOL(rt_sem_wait_if);
