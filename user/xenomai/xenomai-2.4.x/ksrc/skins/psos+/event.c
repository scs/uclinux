/*
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
 */

#include "psos+/task.h"

void taskev_init(psosevent_t *evgroup)
{
	xnsynch_init(&evgroup->synchbase, XNSYNCH_FIFO);
	evgroup->events = 0;
}

void taskev_destroy(psosevent_t *evgroup)
{
	if (xnsynch_destroy(&evgroup->synchbase) == XNSYNCH_RESCHED)
		xnpod_schedule();
}

u_long ev_receive(u_long events, u_long flags, u_long timeout, u_long *events_r)
{
	u_long err = SUCCESS;
	psosevent_t *evgroup;
	psostask_t *task;
	spl_t s;

	if (xnpod_unblockable_p())
		return -EPERM;

	xnlock_get_irqsave(&nklock, s);

	task = psos_current_task();

	evgroup = &task->evgroup;

	if (!events) {
		*events_r = evgroup->events;
		goto unlock_and_exit;
	}

	if (flags & EV_NOWAIT) {
		u_long bits = (evgroup->events & events);
		evgroup->events &= ~events;
		*events_r = bits;

		if (flags & EV_ANY) {
			if (!bits)
				err = ERR_NOEVS;
		} else if (bits != events)
			err = ERR_NOEVS;

		goto unlock_and_exit;
	}

	if (((flags & EV_ANY) && (events & evgroup->events) != 0) ||
	    (!(flags & EV_ANY) && ((events & evgroup->events) == events))) {
		*events_r = (evgroup->events & events);
		evgroup->events &= ~events;
		goto unlock_and_exit;
	}

	task->waitargs.evgroup.flags = flags;
	task->waitargs.evgroup.events = events;
	xnsynch_sleep_on(&evgroup->synchbase, timeout, XN_RELATIVE);

	if (xnthread_test_info(&task->threadbase, XNBREAK))
		err = -EINTR;
	else if (xnthread_test_info(&task->threadbase, XNTIMEO)) {
		err = ERR_TIMEOUT;
		*events_r = evgroup->events;
	} else
		*events_r = task->waitargs.evgroup.events;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

u_long ev_send(u_long tid, u_long events)
{
	u_long err = SUCCESS;
	psosevent_t *evgroup;
	psostask_t *task;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	task = psos_h2obj_active(tid, PSOS_TASK_MAGIC, psostask_t);

	if (!task) {
		err = psos_handle_error(tid, PSOS_TASK_MAGIC, psostask_t);
		goto unlock_and_exit;
	}

	evgroup = &task->evgroup;
	evgroup->events |= events;

	/* Only the task to which the event group pertains can
	   pend on it. */

	if (!emptypq_p(xnsynch_wait_queue(&evgroup->synchbase))) {
		u_long flags = task->waitargs.evgroup.flags;
		u_long bits = task->waitargs.evgroup.events;

		if (((flags & EV_ANY) && (bits & evgroup->events) != 0) ||
		    (!(flags & EV_ANY) && ((bits & evgroup->events) == bits))) {
			xnsynch_wakeup_one_sleeper(&evgroup->synchbase);
			task->waitargs.evgroup.events =
			    (bits & evgroup->events);
			evgroup->events &= ~bits;
			xnpod_schedule();
		}
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}
