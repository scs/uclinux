/*
 * Copyright (C) 2005 Heikki Lindholm <holindho@cs.helsinki.fi>.
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

/* NOTE: functions in dynamically linked libraries aren't wrapped. These
 * are fallback functions for __real* functions used by the library itself
 */

#include <stdarg.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

/* sched */
int __real_pthread_setschedparam(pthread_t thread,
				 int policy, const struct sched_param *param)
{
	return pthread_setschedparam(thread, policy, param);
}

int __real_pthread_getschedparam(pthread_t thread,
				 int *policy, struct sched_param *param)
{
	return pthread_getschedparam(thread, policy, param);
}

int __real_sched_yield(void)
{
	return sched_yield();
}

/* pthread */
int __real_pthread_create(pthread_t *tid,
			  const pthread_attr_t * attr,
			  void *(*start) (void *), void *arg)
{
	return pthread_create(tid, attr, start, arg);
}

/* semaphores */
int __real_sem_init(sem_t * sem, int pshared, unsigned value)
{
	return sem_init(sem, pshared, value);
}

int __real_sem_destroy(sem_t * sem)
{
	return sem_destroy(sem);
}

int __real_sem_post(sem_t * sem)
{
	return sem_post(sem);
}

int __real_sem_wait(sem_t * sem)
{
	return sem_wait(sem);
}

/* rtdm */
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

int __real_socket(int protocol_family, int socket_type, int protocol)
{
	return socket(protocol_family, socket_type, protocol);
}

int __real_close(int fd)
{
	return close(fd);
}

int __real_ioctl(int fd, int request, ...)
{
	va_list ap;
	void *arg;

	va_start(ap, request);
	arg = va_arg(ap, void *);
	va_end(ap);

	return ioctl(fd, request, arg);
}

ssize_t __real_read(int fd, void *buf, size_t nbyte)
{
	return read(fd, buf, nbyte);
}

ssize_t __real_write(int fd, const void *buf, size_t nbyte)
{
	return write(fd, buf, nbyte);
}

ssize_t __real_recvmsg(int fd, struct msghdr * msg, int flags)
{
	return recvmsg(fd, msg, flags);
}

ssize_t __real_sendmsg(int fd, const struct msghdr * msg, int flags)
{
	return sendmsg(fd, msg, flags);
}

ssize_t __real_recvfrom(int fd, void *buf, size_t len, int flags,
			struct sockaddr * from, socklen_t * fromlen)
{
	return recvfrom(fd, buf, len, flags, from, fromlen);
}

ssize_t __real_sendto(int fd, const void *buf, size_t len, int flags,
		      const struct sockaddr * to, socklen_t tolen)
{
	return sendto(fd, buf, len, flags, to, tolen);
}

ssize_t __real_recv(int fd, void *buf, size_t len, int flags)
{
	return recv(fd, buf, len, flags);
}

ssize_t __real_send(int fd, const void *buf, size_t len, int flags)
{
	return send(fd, buf, len, flags);
}

int __real_getsockopt(int fd, int level, int optname, void *optval,
		      socklen_t * optlen)
{
	return getsockopt(fd, level, optname, optval, optlen);
}

int __real_setsockopt(int fd, int level, int optname, const void *optval,
		      socklen_t optlen)
{
	return setsockopt(fd, level, optname, optval, optlen);
}

int __real_bind(int fd, const struct sockaddr *my_addr, socklen_t addrlen)
{
	return bind(fd, my_addr, addrlen);
}

int __real_connect(int fd, const struct sockaddr *serv_addr, socklen_t addrlen)
{
	return connect(fd, serv_addr, addrlen);
}

int __real_listen(int fd, int backlog)
{
	return listen(fd, backlog);
}

int __real_accept(int fd, struct sockaddr *addr, socklen_t * addrlen)
{
	return accept(fd, addr, addrlen);
}

int __real_getsockname(int fd, struct sockaddr *name, socklen_t * namelen)
{
	return getsockname(fd, name, namelen);
}

int __real_getpeername(int fd, struct sockaddr *name, socklen_t * namelen)
{
	return getpeername(fd, name, namelen);
}

int __real_shutdown(int fd, int how)
{
	return shutdown(fd, how);
}

/* shm */
int __real_shm_open(const char *name, int oflag, mode_t mode)
{
	return shm_open(name, oflag, mode);
}

int __real_shm_unlink(const char *name)
{
	return shm_unlink(name);
}

int __real_ftruncate(int fildes, off_t length)
{
	return ftruncate(fildes, length);
}

void *__real_mmap(void *addr,
		  size_t len, int prot, int flags, int fd, off_t off)
{
	return mmap(addr, len, prot, flags, fd, off);
}

int __real_munmap(void *addr, size_t len)
{
	return munmap(addr, len);
}
