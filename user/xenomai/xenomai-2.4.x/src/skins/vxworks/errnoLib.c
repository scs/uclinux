/*
 * Copyright (C) 2006 Philippe Gerum <rpm@xenomai.org>.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <vxworks/vxworks.h>

extern int __vxworks_muxid;

void printErrno(int status)
{
	const char *msg;
	char buf[64];

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
		if (strerror_r(status, buf, sizeof(buf)))
			msg = "Unknown error";
		else
			msg = buf;
	}

	fprintf(stderr, "Error code %d: %s\n", status, msg);
}

STATUS errnoOfTaskSet(TASK_ID task_id, int errcode)
{
	int err;

	err = XENOMAI_SKINCALL2(__vxworks_muxid,
				__vxworks_errno_taskset, task_id, errcode);
	if (err) {
		errno = abs(err);
		return ERROR;
	}

	return OK;
}

int errnoOfTaskGet(TASK_ID task_id)
{
	int err, errcode;

	err = XENOMAI_SKINCALL2(__vxworks_muxid,
				__vxworks_errno_taskget, task_id, &errcode);
	if (err) {
		errno = abs(err);
		return ERROR;
	}

	return errcode;
}

STATUS errnoSet(int status)
{
	return errnoOfTaskSet(0, status);
}

int errnoGet(void)
{
	return errnoOfTaskGet(0);
}
