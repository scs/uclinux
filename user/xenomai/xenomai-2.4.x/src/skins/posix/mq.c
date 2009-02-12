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
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <posix/syscall.h>
#include <pthread.h>
#include <mqueue.h>

extern int __pse51_muxid;

mqd_t __wrap_mq_open(const char *name, int oflags, ...)
{
	struct mq_attr *attr = NULL;
	mode_t mode = 0;
	va_list ap;
	int q, err;

	if ((oflags & O_CREAT) != 0) {
		va_start(ap, oflags);
		mode = va_arg(ap, int);	/* unused */
		attr = va_arg(ap, struct mq_attr *);
		va_end(ap);
	}

	q = __real_open("/dev/null", O_RDWR, 0);

	if (q == -1)
		return (mqd_t) - 1;

	err = -XENOMAI_SKINCALL5(__pse51_muxid,
				 __pse51_mq_open, name, oflags, mode, attr, q);

	if (!err)
		return (mqd_t) q;

	errno = err;
	return (mqd_t) - 1;
}

int __wrap_mq_close(mqd_t q)
{
	int err;

	err = XENOMAI_SKINCALL1(__pse51_muxid, __pse51_mq_close, q);
	if (!err)
		return __real_close(q);

	errno = -err;
	return -1;
}

int __wrap_mq_unlink(const char *name)
{
	int err;

	err = XENOMAI_SKINCALL1(__pse51_muxid, __pse51_mq_unlink, name);
	if (!err)
		return 0;

	errno = -err;
	return -1;
}

int __wrap_mq_getattr(mqd_t q, struct mq_attr *attr)
{
	int err;

	err = XENOMAI_SKINCALL2(__pse51_muxid, __pse51_mq_getattr, q, attr);
	if (!err)
		return 0;

	errno = -err;
	return -1;
}

int __wrap_mq_setattr(mqd_t q,
		      const struct mq_attr *__restrict__ attr,
		      struct mq_attr *__restrict__ oattr)
{
	int err;

	err = XENOMAI_SKINCALL3(__pse51_muxid,
				__pse51_mq_setattr, q, attr, oattr);
	if (!err)
		return 0;

	errno = -err;
	return -1;
}

int __wrap_mq_send(mqd_t q, const char *buffer, size_t len, unsigned prio)
{
	int err, oldtype;

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

	err = XENOMAI_SKINCALL4(__pse51_muxid,
				__pse51_mq_send, q, buffer, len, prio);

	pthread_setcanceltype(oldtype, NULL);

	if (!err)
		return 0;

	errno = -err;
	return -1;
}

int __wrap_mq_timedsend(mqd_t q,
			const char *buffer,
			size_t len,
			unsigned prio, const struct timespec *timeout)
{
	int err, oldtype;

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

	err = XENOMAI_SKINCALL5(__pse51_muxid,
				__pse51_mq_timedsend,
				q, buffer, len, prio, timeout);

	pthread_setcanceltype(oldtype, NULL);

	if (!err)
		return 0;

	errno = -err;
	return -1;
}

ssize_t __wrap_mq_receive(mqd_t q, char *buffer, size_t len, unsigned *prio)
{
	ssize_t rlen = (ssize_t) len;
	int err, oldtype;

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

	err = XENOMAI_SKINCALL4(__pse51_muxid,
				__pse51_mq_receive, q, buffer, &rlen, prio);

	pthread_setcanceltype(oldtype, NULL);

	if (!err)
		return rlen;

	errno = -err;
	return -1;
}

ssize_t __wrap_mq_timedreceive(mqd_t q,
			       char *__restrict__ buffer,
			       size_t len,
			       unsigned *__restrict__ prio,
			       const struct timespec * __restrict__ timeout)
{
	ssize_t rlen = (ssize_t) len;
	int err, oldtype;

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

	err = XENOMAI_SKINCALL5(__pse51_muxid,
				__pse51_mq_timedreceive,
				q, buffer, &rlen, prio, timeout);

	pthread_setcanceltype(oldtype, NULL);

	if (!err)
		return rlen;

	errno = -err;
	return -1;
}

int __wrap_mq_notify(mqd_t mqdes, const struct sigevent *notification)
{
	int err;

	err = XENOMAI_SKINCALL2(__pse51_muxid,
				__pse51_mq_notify, mqdes, notification);
	if (err) {
		errno = -err;
		return -1;
	}

	return 0;
}
