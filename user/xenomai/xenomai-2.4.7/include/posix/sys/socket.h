/*
 * Copyright (C) 2005 Philippe Gerum <rpm@xenomai.org>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef _XENO_POSIX_SOCKET_H
#define _XENO_POSIX_SOCKET_H

#if !(defined(__KERNEL__) || defined(__XENO_SIM__))

#include_next <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

int __real_socket(int protocol_family, int socket_type, int protocol);

ssize_t __real_recvmsg(int fd, struct msghdr *msg, int flags);

ssize_t __real_sendmsg(int fd, const struct msghdr *msg, int flags);

ssize_t __real_recvfrom(int fd, void *buf, size_t len, int flags,
                        struct sockaddr *from, socklen_t *fromlen);

ssize_t __real_sendto(int fd, const void *buf, size_t len, int flags,
                      const struct sockaddr *to, socklen_t tolen);

ssize_t __real_recv(int fd, void *buf, size_t len, int flags);

ssize_t __real_send(int fd, const void *buf, size_t len, int flags);

int __real_getsockopt(int fd, int level, int optname, void *optval,
                      socklen_t *optlen);

int __real_setsockopt(int fd, int level, int optname, const void *optval,
                      socklen_t optlen);

int __real_bind(int fd, const struct sockaddr *my_addr, socklen_t addrlen);

int __real_connect(int fd, const struct sockaddr *serv_addr,
                   socklen_t addrlen);

int __real_listen(int fd, int backlog);

int __real_accept(int fd, struct sockaddr *addr, socklen_t *addrlen);

int __real_getsockname(int fd, struct sockaddr *name, socklen_t *namelen);

int __real_getpeername(int fd, struct sockaddr *name, socklen_t *namelen);

int __real_shutdown(int fd, int how);

#ifdef __cplusplus
}
#endif

#endif /* !(__KERNEL__ || __XENO_SIM__) */

#endif /* _XENO_POSIX_SOCKET_H */
