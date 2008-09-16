/*
 * Copyright (C) 2005 Jan Kiszka <jan.kiszka@web.de>.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 
  USA.
 */

#include <errno.h>
#include <stdarg.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <rtdm/rtdm.h>
#include <rtdm/syscall.h>

extern int __rtdm_muxid;
extern int __rtdm_fd_start;

static inline int set_errno(int ret)
{
	if (ret >= 0)
		return ret;

	errno = -ret;
	return -1;
}

int __wrap_open(const char *path, int oflag, ...)
{
	int ret, oldtype;
	const char *rtdm_path = path;

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

	/* skip path prefix for RTDM invocation */
	if (strncmp(path, "/dev/", 5) == 0)
		rtdm_path += 5;

	ret = XENOMAI_SKINCALL2(__rtdm_muxid, __rtdm_open, rtdm_path, oflag);

	pthread_setcanceltype(oldtype, NULL);

	if (ret >= 0)
		ret += __rtdm_fd_start;
	else if (ret == -ENODEV || ret == -ENOSYS) {
		va_list ap;

		va_start(ap, oflag);

		ret = __real_open(path, oflag, va_arg(ap, mode_t));

		va_end(ap);

		if (ret >= __rtdm_fd_start) {
			__real_close(ret);
			errno = EMFILE;
			ret = -1;
		}
	} else {
		errno = -ret;
		ret = -1;
	}

	return ret;
}

int __wrap_socket(int protocol_family, int socket_type, int protocol)
{
	int ret;

	ret = XENOMAI_SKINCALL3(__rtdm_muxid,
				__rtdm_socket,
				protocol_family, socket_type, protocol);
	if (ret >= 0)
		ret += __rtdm_fd_start;
	else if (ret == -EAFNOSUPPORT || ret == -ENOSYS) {
		ret = __real_socket(protocol_family, socket_type, protocol);

		if (ret >= __rtdm_fd_start) {
			__real_close(ret);
			errno = -EMFILE;
			ret = -1;
		}
	} else {
		errno = -ret;
		ret = -1;
	}

	return ret;
}

int __wrap_close(int fd)
{
	extern int __shm_close(int fd);
	int ret;

	if (fd >= __rtdm_fd_start) {
		int oldtype;

		pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

		ret = set_errno(XENOMAI_SKINCALL1(__rtdm_muxid,
						  __rtdm_close,
						  fd - __rtdm_fd_start));

		pthread_setcanceltype(oldtype, NULL);

		return ret;
	} else
		ret = __shm_close(fd);

	if (ret == -1 && (errno == EBADF || errno == ENOSYS))
		return __real_close(fd);

	return ret;
}

int __wrap_ioctl(int fd, unsigned long int request, ...)
{
	va_list ap;
	void *arg;

	va_start(ap, request);
	arg = va_arg(ap, void *);
	va_end(ap);

	if (fd >= __rtdm_fd_start)
		return set_errno(XENOMAI_SKINCALL3(__rtdm_muxid,
						   __rtdm_ioctl,
						   fd - __rtdm_fd_start,
						   request, arg));
	else
		return __real_ioctl(fd, request, arg);
}

ssize_t __wrap_read(int fd, void *buf, size_t nbyte)
{
	if (fd >= __rtdm_fd_start) {
		int ret, oldtype;

		pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

		ret = set_errno(XENOMAI_SKINCALL3(__rtdm_muxid,
						  __rtdm_read,
						  fd - __rtdm_fd_start,
						  buf, nbyte));

		pthread_setcanceltype(oldtype, NULL);

		return ret;
	} else
		return __real_read(fd, buf, nbyte);
}

ssize_t __wrap_write(int fd, const void *buf, size_t nbyte)
{
	if (fd >= __rtdm_fd_start) {
		int ret, oldtype;

		pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

		ret = set_errno(XENOMAI_SKINCALL3(__rtdm_muxid,
						  __rtdm_write,
						  fd - __rtdm_fd_start,
						  buf, nbyte));

		pthread_setcanceltype(oldtype, NULL);

		return ret;
	} else
		return __real_write(fd, buf, nbyte);
}

ssize_t __wrap_recvmsg(int fd, struct msghdr * msg, int flags)
{
	if (fd >= __rtdm_fd_start) {
		int ret, oldtype;

		pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

		ret = set_errno(XENOMAI_SKINCALL3(__rtdm_muxid,
						  __rtdm_recvmsg,
						  fd - __rtdm_fd_start,
						  msg, flags));

		pthread_setcanceltype(oldtype, NULL);

		return ret;
	} else
		return __real_recvmsg(fd, msg, flags);
}

ssize_t __wrap_sendmsg(int fd, const struct msghdr * msg, int flags)
{
	if (fd >= __rtdm_fd_start) {
		int ret, oldtype;

		pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

		ret = set_errno(XENOMAI_SKINCALL3(__rtdm_muxid,
						  __rtdm_sendmsg,
						  fd - __rtdm_fd_start,
						  msg, flags));

		pthread_setcanceltype(oldtype, NULL);

		return ret;
	} else
		return __real_sendmsg(fd, msg, flags);
}

ssize_t __wrap_recvfrom(int fd, void *buf, size_t len, int flags,
			struct sockaddr * from, socklen_t * fromlen)
{
	if (fd >= __rtdm_fd_start) {
		struct iovec iov = { buf, len };
		struct msghdr msg =
		    { from, (from != NULL) ? *fromlen : 0, &iov, 1, NULL, 0 };
		int ret, oldtype;

		pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

		ret = XENOMAI_SKINCALL3(__rtdm_muxid,
					__rtdm_recvmsg,
					fd - __rtdm_fd_start, &msg, flags);

		pthread_setcanceltype(oldtype, NULL);

		if (ret < 0) {
			errno = -ret;
			ret = -1;
		} else if (from != NULL)
			*fromlen = msg.msg_namelen;
		return ret;
	} else
		return __real_recvfrom(fd, buf, len, flags, from, fromlen);
}

ssize_t __wrap_sendto(int fd, const void *buf, size_t len, int flags,
		      const struct sockaddr * to, socklen_t tolen)
{
	if (fd >= __rtdm_fd_start) {
		struct iovec iov = { (void *)buf, len };
		struct msghdr msg =
		    { (struct sockaddr *)to, tolen, &iov, 1, NULL, 0 };
		int ret, oldtype;

		pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

		ret = set_errno(XENOMAI_SKINCALL3(__rtdm_muxid,
						  __rtdm_sendmsg,
						  fd - __rtdm_fd_start,
						  &msg, flags));

		pthread_setcanceltype(oldtype, NULL);

		return ret;
	} else
		return __real_sendto(fd, buf, len, flags, to, tolen);
}

ssize_t __wrap_recv(int fd, void *buf, size_t len, int flags)
{
	if (fd >= __rtdm_fd_start) {
		struct iovec iov = { buf, len };
		struct msghdr msg = { NULL, 0, &iov, 1, NULL, 0 };
		int ret, oldtype;

		pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

		ret = set_errno(XENOMAI_SKINCALL3(__rtdm_muxid,
						  __rtdm_recvmsg,
						  fd - __rtdm_fd_start,
						  &msg, flags));

		pthread_setcanceltype(oldtype, NULL);

		return ret;
	} else
		return __real_recv(fd, buf, len, flags);
}

ssize_t __wrap_send(int fd, const void *buf, size_t len, int flags)
{
	if (fd >= __rtdm_fd_start) {
		struct iovec iov = { (void *)buf, len };
		struct msghdr msg = { NULL, 0, &iov, 1, NULL, 0 };
		int ret, oldtype;

		pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

		ret = set_errno(XENOMAI_SKINCALL3(__rtdm_muxid,
						  __rtdm_sendmsg,
						  fd - __rtdm_fd_start,
						  &msg, flags));

		pthread_setcanceltype(oldtype, NULL);

		return ret;
	} else
		return __real_send(fd, buf, len, flags);
}

int __wrap_getsockopt(int fd, int level, int optname, void *optval,
		      socklen_t * optlen)
{
	if (fd >= __rtdm_fd_start) {
		struct _rtdm_getsockopt_args args =
		    { level, optname, optval, optlen };

		return set_errno(XENOMAI_SKINCALL3(__rtdm_muxid,
						   __rtdm_ioctl,
						   fd - __rtdm_fd_start,
						   _RTIOC_GETSOCKOPT, &args));
	} else
		return __real_getsockopt(fd, level, optname, optval, optlen);
}

int __wrap_setsockopt(int fd, int level, int optname, const void *optval,
		      socklen_t optlen)
{
	if (fd >= __rtdm_fd_start) {
		struct _rtdm_setsockopt_args args =
		    { level, optname, (void *)optval, optlen };

		return set_errno(XENOMAI_SKINCALL3(__rtdm_muxid,
						   __rtdm_ioctl,
						   fd - __rtdm_fd_start,
						   _RTIOC_SETSOCKOPT, &args));
	} else
		return __real_setsockopt(fd, level, optname, optval, optlen);
}

int __wrap_bind(int fd, const struct sockaddr *my_addr, socklen_t addrlen)
{
	if (fd >= __rtdm_fd_start) {
		struct _rtdm_setsockaddr_args args = { my_addr, addrlen };

		return set_errno(XENOMAI_SKINCALL3(__rtdm_muxid,
						   __rtdm_ioctl,
						   fd - __rtdm_fd_start,
						   _RTIOC_BIND, &args));
	} else
		return __real_bind(fd, my_addr, addrlen);
}

int __wrap_connect(int fd, const struct sockaddr *serv_addr, socklen_t addrlen)
{
	if (fd >= __rtdm_fd_start) {
		struct _rtdm_setsockaddr_args args = { serv_addr, addrlen };
		int ret, oldtype;

		pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

		ret = set_errno(XENOMAI_SKINCALL3(__rtdm_muxid,
						  __rtdm_ioctl,
						  fd - __rtdm_fd_start,
						  _RTIOC_CONNECT, &args));

		pthread_setcanceltype(oldtype, NULL);

		return ret;
	} else
		return __real_connect(fd, serv_addr, addrlen);
}

int __wrap_listen(int fd, int backlog)
{
	if (fd >= __rtdm_fd_start) {
		return set_errno(XENOMAI_SKINCALL3(__rtdm_muxid,
						   __rtdm_ioctl,
						   fd - __rtdm_fd_start,
						   _RTIOC_LISTEN, backlog));
	} else
		return __real_listen(fd, backlog);
}

int __wrap_accept(int fd, struct sockaddr *addr, socklen_t * addrlen)
{
	if (fd >= __rtdm_fd_start) {
		struct _rtdm_getsockaddr_args args = { addr, addrlen };
		int oldtype;

		pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

		fd = XENOMAI_SKINCALL3(__rtdm_muxid,
				       __rtdm_ioctl,
				       fd - __rtdm_fd_start,
				       _RTIOC_ACCEPT, &args);

		pthread_setcanceltype(oldtype, NULL);

		if (fd >= 0)
			fd += __rtdm_fd_start;
	} else {
		fd = __real_accept(fd, addr, addrlen);

		if (fd >= __rtdm_fd_start) {
			__real_close(fd);
			fd = -EMFILE;
		}
	}

	return set_errno(fd);
}

int __wrap_getsockname(int fd, struct sockaddr *name, socklen_t * namelen)
{
	if (fd >= __rtdm_fd_start) {
		struct _rtdm_getsockaddr_args args = { name, namelen };

		return set_errno(XENOMAI_SKINCALL3(__rtdm_muxid,
						   __rtdm_ioctl,
						   fd - __rtdm_fd_start,
						   _RTIOC_GETSOCKNAME, &args));
	} else
		return __real_getsockname(fd, name, namelen);
}

int __wrap_getpeername(int fd, struct sockaddr *name, socklen_t * namelen)
{
	if (fd >= __rtdm_fd_start) {
		struct _rtdm_getsockaddr_args args = { name, namelen };

		return set_errno(XENOMAI_SKINCALL3(__rtdm_muxid,
						   __rtdm_ioctl,
						   fd - __rtdm_fd_start,
						   _RTIOC_GETPEERNAME, &args));
	} else
		return __real_getpeername(fd, name, namelen);
}

int __wrap_shutdown(int fd, int how)
{
	if (fd >= __rtdm_fd_start) {
		return set_errno(XENOMAI_SKINCALL3(__rtdm_muxid,
						   __rtdm_ioctl,
						   fd - __rtdm_fd_start,
						   _RTIOC_SHUTDOWN, how));
	} else
		return __real_shutdown(fd, how);
}
