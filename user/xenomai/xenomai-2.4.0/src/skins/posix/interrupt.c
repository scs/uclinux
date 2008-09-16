/*
 * Copyright (C) 2005 Philippe Gerum <rpm@xenomai.org>.
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

#include <errno.h>
#include <posix/syscall.h>
#include <pthread.h>

extern int __pse51_muxid;

int pthread_intr_attach_np(pthread_intr_t * intr, unsigned irq, int mode)
{
	int err;

	err = -XENOMAI_SKINCALL3(__pse51_muxid,
				 __pse51_intr_attach, intr, irq, mode);
	if (!err)
		return 0;

	errno = err;

	return -1;
}

int pthread_intr_detach_np(pthread_intr_t intr)
{
	int err;

	err = -XENOMAI_SKINCALL1(__pse51_muxid, __pse51_intr_detach, intr);
	if (!err)
		return 0;

	errno = err;

	return -1;
}

int pthread_intr_wait_np(pthread_intr_t intr, const struct timespec *to)
{
	int err, oldtype;

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

	err = XENOMAI_SKINCALL2(__pse51_muxid, __pse51_intr_wait, intr, to);

	pthread_setcanceltype(oldtype, NULL);

	if (err > 0)
		return err;

	errno = -err;

	return -1;
}

int pthread_intr_control_np(pthread_intr_t intr, int cmd)
{
	int err;

	err = -XENOMAI_SKINCALL2(__pse51_muxid,
				 __pse51_intr_control, intr, cmd);
	if (!err)
		return 0;

	errno = err;

	return -1;
}
