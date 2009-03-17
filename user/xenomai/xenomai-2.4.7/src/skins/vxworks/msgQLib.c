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
#include <vxworks/vxworks.h>

extern int __vxworks_muxid;

MSG_Q_ID msgQCreate(int nb_msgs, int length, int flags)
{
	MSG_Q_ID qid;
	int err;

	err = XENOMAI_SKINCALL4(__vxworks_muxid,
				__vxworks_msgq_create,
				nb_msgs, length, flags, &qid);
	if (err) {
		errno = abs(err);
		return 0;
	}

	return qid;
}

STATUS msgQDelete(MSG_Q_ID qid)
{
	int err;

	err = XENOMAI_SKINCALL1(__vxworks_muxid, __vxworks_msgq_delete, qid);
	if (err) {
		errno = abs(err);
		return ERROR;
	}

	return OK;
}

int msgQNumMsgs(MSG_Q_ID qid)
{
	int err, nummsgs;

	err = XENOMAI_SKINCALL2(__vxworks_muxid,
				__vxworks_msgq_nummsgs, qid, &nummsgs);
	if (err) {
		errno = abs(err);
		return ERROR;
	}

	return nummsgs;
}

int msgQReceive(MSG_Q_ID qid, char *buf, UINT nbytes, int timeout)
{
	int err, rbytes;

	err = XENOMAI_SKINCALL5(__vxworks_muxid,
				__vxworks_msgq_receive,
				qid, buf, nbytes, timeout, &rbytes);
	if (err) {
		errno = abs(err);
		return ERROR;
	}

	return rbytes;
}

STATUS msgQSend(MSG_Q_ID qid, const char *buf, UINT nbytes, int timeout,
		int prio)
{
	int err;

	err = XENOMAI_SKINCALL5(__vxworks_muxid,
				__vxworks_msgq_send,
				qid, buf, nbytes, timeout, prio);
	if (err) {
		errno = abs(err);
		return ERROR;
	}

	return OK;
}
