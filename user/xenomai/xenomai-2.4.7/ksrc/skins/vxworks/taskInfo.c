/*
 * Copyright (C) 2001,2002 IDEALX (http://www.idealx.com/).
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>.
 * Copyright (C) 2003 Philippe Gerum <rpm@xenomai.org>.
 *
 * Xenomai is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <vxworks/defs.h>

const char *taskName(TASK_ID task_id)
{
	wind_task_t *task;

	if (task_id == 0)
		task_id = taskIdSelf();

	task = wind_h2obj_active(task_id, WIND_TASK_MAGIC, wind_task_t);

	/* It is useless to lock the access to task here, because if the task
	   is deleted, the returned pointer will be invalid anyway. */

	if (!task)
		return NULL;

	return task->name;
}

TASK_ID taskIdDefault(TASK_ID task_id)
{
	static TASK_ID value = 0;

	if (task_id)
		value = task_id;

	return value;
}

BOOL taskIsReady(TASK_ID task_id)
{
	wind_task_t *task;

	check_OBJ_ID_ERROR(task_id, wind_task_t, task, WIND_TASK_MAGIC,
			   return 0);

	if (&task->threadbase == xnpod_current_thread())
		return 1;

	return testbits(xnthread_state_flags(&task->threadbase), XNREADY);
}

BOOL taskIsSuspended(TASK_ID task_id)
{
	wind_task_t *task;

	check_OBJ_ID_ERROR(task_id, wind_task_t, task, WIND_TASK_MAGIC,
			   return 0);

	return testbits(xnthread_state_flags(&task->threadbase), XNSUSP);
}

STATUS taskInfoGet(TASK_ID task_id, TASK_DESC *desc)
{
	wind_task_t *task;
	xnflags_t status;
	spl_t s;

	memset(desc, 0, sizeof(*desc));

	xnlock_get_irqsave(&nklock, s);

	check_OBJ_ID_ERROR(task_id, wind_task_t, task, WIND_TASK_MAGIC,
			   goto error);

	desc->td_tid = task_id;
	xnobject_copy_name(desc->td_name, task->name);
	desc->td_priority = wind_denormalized_prio(xnthread_current_priority
						(&task->threadbase));

	status = xnthread_state_flags(&task->threadbase);

	if (xnpod_current_thread() == &task->threadbase || (status & XNREADY))
		desc->td_status |= WIND_READY;
	else if (status & XNDORMANT)
		desc->td_status |= WIND_DEAD;
	else {
		if (status & XNSUSP)
			desc->td_status |= WIND_SUSPEND;
		if (status & XNPEND)
			desc->td_status |= WIND_PEND;
		if (status & XNDELAY)
			desc->td_status |= WIND_DELAY;
	}

	desc->td_flags = task->flags;
	desc->td_entry = task->entry;
	desc->td_errorStatus = errnoOfTaskGet(task_id);

#ifdef CONFIG_XENO_OPT_PERVASIVE
	if (status & XNSHADOW)
		desc->td_opaque = task->ptid;
		/* Userland should fill in the stack information. */
	else
#endif
	{
		desc->td_stacksize = xnthread_stack_size(&task->threadbase);
		desc->td_pStackBase = (char *)xnthread_stack_base(&task->threadbase);
		desc->td_pStackEnd = (char *)xnthread_stack_end(&task->threadbase);
		desc->td_pExcStackBase = desc->td_pStackBase;
		desc->td_pExcStackEnd = desc->td_pStackEnd;
	}

	xnlock_put_irqrestore(&nklock, s);

	return OK;

      error:
	xnlock_put_irqrestore(&nklock, s);
	return ERROR;
}
