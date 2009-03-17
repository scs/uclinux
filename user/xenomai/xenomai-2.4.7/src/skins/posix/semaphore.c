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

#include <stdlib.h>		/* For malloc & free. */
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>		/* For O_CREAT. */
#include <pthread.h>		/* For pthread_setcanceltype. */
#include <posix/syscall.h>
#include <semaphore.h>

extern int __pse51_muxid;

int __wrap_sem_init(sem_t * sem, int pshared, unsigned value)
{
	union __xeno_sem *_sem = (union __xeno_sem *)sem;
	int err;

	err = -XENOMAI_SKINCALL3(__pse51_muxid,
				 __pse51_sem_init,
				 &_sem->shadow_sem, pshared, value);
	if (!err)
		return 0;

	errno = err;

	return -1;
}

int __wrap_sem_destroy(sem_t * sem)
{
	union __xeno_sem *_sem = (union __xeno_sem *)sem;
	int err;

	err = -XENOMAI_SKINCALL1(__pse51_muxid,
				 __pse51_sem_destroy, &_sem->shadow_sem);
	if (!err)
		return 0;

	errno = err;

	return -1;
}

int __wrap_sem_post(sem_t * sem)
{
	union __xeno_sem *_sem = (union __xeno_sem *)sem;
	int err;

	err = -XENOMAI_SKINCALL1(__pse51_muxid,
				 __pse51_sem_post, &_sem->shadow_sem);
	if (!err)
		return 0;

	errno = err;

	return -1;
}

int __wrap_sem_wait(sem_t * sem)
{
	union __xeno_sem *_sem = (union __xeno_sem *)sem;
	int err, oldtype;

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

	err = -XENOMAI_SKINCALL1(__pse51_muxid,
				 __pse51_sem_wait, &_sem->shadow_sem);

	pthread_setcanceltype(oldtype, NULL);

	if (!err)
		return 0;

	errno = err;

	return -1;
}

int __wrap_sem_timedwait(sem_t * sem, const struct timespec *ts)
{
	union __xeno_sem *_sem = (union __xeno_sem *)sem;
	int err, oldtype;

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

	err = -XENOMAI_SKINCALL2(__pse51_muxid,
				 __pse51_sem_timedwait, &_sem->shadow_sem, ts);

	pthread_setcanceltype(oldtype, NULL);

	if (!err)
		return 0;

	errno = err;

	return -1;
}

int __wrap_sem_trywait(sem_t * sem)
{
	union __xeno_sem *_sem = (union __xeno_sem *)sem;
	int err;

	err = -XENOMAI_SKINCALL1(__pse51_muxid,
				 __pse51_sem_trywait, &_sem->shadow_sem);
	if (!err)
		return 0;

	errno = err;

	return -1;
}

int __wrap_sem_getvalue(sem_t * sem, int *sval)
{
	union __xeno_sem *_sem = (union __xeno_sem *)sem;
	int err;

	err = -XENOMAI_SKINCALL2(__pse51_muxid,
				 __pse51_sem_getvalue, &_sem->shadow_sem, sval);
	if (!err)
		return 0;

	errno = err;

	return -1;
}

sem_t *__wrap_sem_open(const char *name, int oflags, ...)
{
	union __xeno_sem *sem, *rsem;
	unsigned value = 0;
	mode_t mode = 0;
	va_list ap;
	int err;

	if ((oflags & O_CREAT)) {
		va_start(ap, oflags);
		mode = va_arg(ap, int);
		value = va_arg(ap, unsigned);
		va_end(ap);
	}

	rsem = sem = (union __xeno_sem *)malloc(sizeof(*sem));

	if (!rsem) {
		err = ENOSPC;
		goto error;
	}

	err = -XENOMAI_SKINCALL5(__pse51_muxid,
				 __pse51_sem_open,
				 &rsem, name, oflags, mode, value);

	if (!err) {
		if (rsem != sem)
			free(sem);
		return &rsem->native_sem;
	}

	free(sem);
      error:
	errno = err;
	return SEM_FAILED;
}

int __wrap_sem_close(sem_t * sem)
{
	union __xeno_sem *_sem = (union __xeno_sem *)sem;
	int err, closed;

	err = -XENOMAI_SKINCALL2(__pse51_muxid,
				 __pse51_sem_close, &_sem->shadow_sem, &closed);

	if (!err) {
		if (closed)
			free(sem);
		return 0;
	}

	errno = err;
	return -1;
}

int __wrap_sem_unlink(const char *name)
{
	int err;

	err = -XENOMAI_SKINCALL1(__pse51_muxid, __pse51_sem_unlink, name);

	if (!err)
		return 0;

	errno = err;
	return -1;
}
