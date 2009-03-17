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

int *wind_current_context_errno(void)
{
	return xnthread_get_errno_location(xnpod_current_thread());
}

void printErrno(int status)
{
	const char *msg;

	switch (status) {
	case S_objLib_OBJ_ID_ERROR:
		msg = "S_objLib_OBJ_ID_ERROR";
		break;
	case S_objLib_OBJ_UNAVAILABLE:
		msg = "S_objLib_OBJ_UNAVAILABLE";
		break;
	case S_objLib_OBJ_DELETED:
		msg = "S_objLib_OBJ_DELETED";
		break;
	case S_objLib_OBJ_TIMEOUT:
		msg = "S_objLib_OBJ_TIMEOUT";
		break;
	case S_taskLib_NAME_NOT_FOUND:
		msg = "S_taskLib_NAME_NOT_FOUND";
		break;
	case S_taskLib_TASK_HOOK_NOT_FOUND:
		msg = "S_taskLib_TASK_HOOK_NOT_FOUND";
		break;
	case S_taskLib_ILLEGAL_PRIORITY:
		msg = "S_taskLib_ILLEGAL_PRIORITY";
		break;
	case S_taskLib_TASK_HOOK_TABLE_FULL:
		msg = "S_taskLib_TASK_HOOK_TABLE_FULL";
		break;
	case S_semLib_INVALID_STATE:
		msg = "S_semLib_INVALID_STATE";
		break;
	case S_semLib_INVALID_OPTION:
		msg = "S_semLib_INVALID_OPTION";
		break;
	case S_semLib_INVALID_QUEUE_TYPE:
		msg = "S_semLib_INVALID_QUEUE_TYPE";
		break;
	case S_semLib_INVALID_OPERATION:
		msg = "S_semLib_INVALID_OPERATION";
		break;
	case S_msgQLib_INVALID_MSG_LENGTH:
		msg = "S_msgQLib_INVALID_MSG_LENGTH";
		break;
	case S_msgQLib_NON_ZERO_TIMEOUT_AT_INT_LEVEL:
		msg = "S_msgQLib_NON_ZERO_TIMEOUT_AT_INT_LEVEL";
		break;
	case S_msgQLib_INVALID_QUEUE_TYPE:
		msg = "S_msgQLib_INVALID_QUEUE_TYPE";
		break;
	case S_intLib_NOT_ISR_CALLABLE:
		msg = "S_intLib_NOT_ISR_CALLABLE";
		break;
	case S_memLib_NOT_ENOUGH_MEMORY:
		msg = "S_memLib_NOT_ENOUGH_MEMORY";
		break;
	default:
		msg = "Unknown error";
	}

	xnarch_printf("Error code %d: %s\n", status, msg);
}

STATUS errnoSet(int status)
{
	wind_errnoset(status);
	return OK;
}

int errnoGet(void)
{
	return wind_errnoget();
}

int errnoOfTaskGet(TASK_ID task_id)
{
	wind_task_t *task;
	int result;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	check_OBJ_ID_ERROR(task_id, wind_task_t, task, WIND_TASK_MAGIC,
			   goto error);

	result = *xnthread_get_errno_location(&task->threadbase);

	xnlock_put_irqrestore(&nklock, s);
	return result;

      error:
	xnlock_put_irqrestore(&nklock, s);
	return ERROR;
}

STATUS errnoOfTaskSet(TASK_ID task_id, int status)
{
	wind_task_t *task;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	check_OBJ_ID_ERROR(task_id, wind_task_t, task, WIND_TASK_MAGIC,
			   goto error);

	*xnthread_get_errno_location(&task->threadbase) = status;

	xnlock_put_irqrestore(&nklock, s);
	return OK;

      error:
	xnlock_put_irqrestore(&nklock, s);
	return ERROR;
}
