/*
 * Copyright (C) 2005 Heikki Lindholm <holindho@cs.helsinki.fi>.
 * Copyright (C) 2008 Philippe Gerum <rpm@xenomai.org>.
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
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>

/*
 * This file maintains a list of placeholders for routines that we do
 * NOT want to be wrapped to their Xenomai POSIX API counterparts when
 * used internally by the VxWorks interface.
 */

__attribute__ ((weak))
int __real_pthread_setschedparam(pthread_t thread,
				 int policy, const struct sched_param *param)
{
	return pthread_setschedparam(thread, policy, param);
}

__attribute__ ((weak))
int __real_pthread_create(pthread_t *tid,
			  const pthread_attr_t * attr,
			  void *(*start) (void *), void *arg)
{
	return pthread_create(tid, attr, start, arg);
}

__attribute__ ((weak))
int __real_pthread_kill(pthread_t tid, int sig)
{
	return pthread_kill(tid, sig);
}

__attribute__ ((weak))
int __real_open(const char *path, int oflag, ...)
{
	va_list ap;
	mode_t mode;

	if (oflag & O_CREAT) {
		va_start(ap, oflag);
		mode = va_arg(ap, mode_t);
		va_end(ap);
		return open(path, oflag, mode);
	} else
		return open(path, oflag);
}

__attribute__ ((weak))
int __real_close(int fd)
{
	return close(fd);
}

__attribute__ ((weak))
int __real_ioctl(int fd, int request, ...)
{
	va_list ap;
	void *arg;

	va_start(ap, request);
	arg = va_arg(ap, void *);
	va_end(ap);

	return ioctl(fd, request, arg);
}

__attribute__ ((weak))
void *__real_mmap(void *addr,
		  size_t len, int prot, int flags, int fd, off_t off)
{
	return mmap(addr, len, prot, flags, fd, off);
}

__attribute__ ((weak))
int __real_munmap(void *addr, size_t len)
{
	return munmap(addr, len);
}
