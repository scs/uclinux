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

#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <nucleus/thread.h>	/* For status bits. */
#include <vxworks/vxworks.h>

extern int __vxworks_muxid;

const char *taskName(TASK_ID task_id)
{
	static char namebuf[XNOBJECT_NAME_LEN];
	int err;

	err = XENOMAI_SKINCALL2(__vxworks_muxid,
				__vxworks_taskinfo_name, task_id, namebuf);
	if (err) {
		errno = abs(err);
		return NULL;
	}

	return namebuf;
}

TASK_ID taskIdDefault(TASK_ID task_id)
{
	TASK_ID ret_id;

	XENOMAI_SKINCALL2(__vxworks_muxid,
			  __vxworks_taskinfo_iddfl, task_id, &ret_id);
	return ret_id;
}

BOOL taskIsReady(TASK_ID task_id)
{
	unsigned long status;
	int err;

	err = XENOMAI_SKINCALL2(__vxworks_muxid,
				__vxworks_taskinfo_status, task_id, &status);
	if (err)
		return 0;

	return !!(status & XNREADY);
}

BOOL taskIsSuspended(TASK_ID task_id)
{
	unsigned long status;
	int err;

	err = XENOMAI_SKINCALL2(__vxworks_muxid,
				__vxworks_taskinfo_status, task_id, &status);
	if (err)
		return 0;

	return !!(status & XNSUSP);
}

STATUS taskInfoGet(TASK_ID task_id, TASK_DESC *desc)
{
	int probe1, probe2;
	size_t stacksize;
	void *stackbase;
	int err;

	err = XENOMAI_SKINCALL2(__vxworks_muxid,
				__vxworks_taskinfo_get, task_id, desc);
	if (err) {
		errno = abs(err);
		return ERROR;
	}

#ifdef __UCLIBC__
	/*
	 * pthread_getattr_np() is not currently available with
	 * uClibc, so we can't easily determine the stack
	 * configuration.
	 */
	stackbase = NULL;
	stacksize = 0;
#else
	{
		pthread_attr_t attr;

		if (pthread_getattr_np((pthread_t)desc->td_opaque, &attr)) {
			errno = S_objLib_OBJ_ID_ERROR;
			return ERROR;
		}
		pthread_attr_getstack(&attr, &stackbase, &stacksize);
	}
#endif

	desc->td_stacksize = stacksize;
	desc->td_pStackBase = stackbase;

	if (&probe1 < &probe2)
		/* Stack grows upward. */
		desc->td_pStackEnd = (caddr_t)stackbase + stacksize;
	else
		/* Stack grows downward. */
		desc->td_pStackEnd = (caddr_t)stackbase - stacksize;

	desc->td_pExcStackBase = desc->td_pStackBase;
	desc->td_pExcStackEnd = desc->td_pStackEnd;

	return OK;
}
