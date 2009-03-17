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

#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include <vxworks/vxworks.h>

extern int __vxworks_muxid;

SEM_ID semBCreate(int flags, SEM_B_STATE state)
{
	SEM_ID sem_id;
	int err;

	err = XENOMAI_SKINCALL3(__vxworks_muxid,
				__vxworks_sem_bcreate, flags, state, &sem_id);
	if (err) {
		errno = abs(err);
		return 0;
	}

	return sem_id;
}

SEM_ID semCCreate(int flags, int count)
{
	SEM_ID sem_id;
	int err;

	err = XENOMAI_SKINCALL3(__vxworks_muxid,
				__vxworks_sem_ccreate, flags, count, &sem_id);
	if (err) {
		errno = abs(err);
		return 0;
	}

	return sem_id;
}

SEM_ID semMCreate(int flags)
{
	SEM_ID sem_id;
	int err;

	err = XENOMAI_SKINCALL2(__vxworks_muxid,
				__vxworks_sem_mcreate, flags, &sem_id);
	if (err) {
		errno = abs(err);
		return 0;
	}

	return sem_id;
}

STATUS semDelete(SEM_ID sem_id)
{
	int err;

	err = XENOMAI_SKINCALL1(__vxworks_muxid, __vxworks_sem_delete, sem_id);
	if (err) {
		errno = abs(err);
		return ERROR;
	}

	return OK;
}

STATUS semTake(SEM_ID sem_id, int timeout)
{
	int err;

	err = XENOMAI_SKINCALL2(__vxworks_muxid,
				__vxworks_sem_take, sem_id, timeout);
	if (err) {
		errno = abs(err);
		return ERROR;
	}

	return OK;
}

STATUS semGive(SEM_ID sem_id)
{
	int err;

	err = XENOMAI_SKINCALL1(__vxworks_muxid, __vxworks_sem_give, sem_id);
	if (err) {
		errno = abs(err);
		return ERROR;
	}

	return OK;
}

STATUS semFlush(SEM_ID sem_id)
{
	int err;

	err = XENOMAI_SKINCALL1(__vxworks_muxid, __vxworks_sem_flush, sem_id);
	if (err) {
		errno = abs(err);
		return ERROR;
	}

	return OK;
}
