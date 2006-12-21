/* vi: set sw=4 ts=4: */
/*
 * select() for uClibc
 *
 * Copyright (C) 2000-2004 by Erik Andersen <andersen@codepoet.org>
 *
 * GNU Library General Public License (LGPL) version 2 or later.
 */

#include "syscalls.h"
#include <unistd.h>

#ifdef __NR_pselect6

# define __NR___libc_pselect6 __NR_pselect6
_syscall6(int, __libc_pselect6, int, n, fd_set *, readfds, fd_set *, writefds,
		fd_set *, exceptfds, const struct timespec *, timeout, 
		const sigset_t *, sigmask);

inline int __libc_select (int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, 
		struct timeval *timeout)
{
	int result;
	struct timespec ts;

	if(timeout) {
		ts.tv_sec = timeout->tv_sec;
		ts.tv_nsec = timeout->tv_usec*1000;
		result = __libc_pselect6(n, readfds, writefds, exceptfds, &ts, 0);
	}
	else {
		result = __libc_pselect6(n, readfds, writefds, exceptfds, 0, 0);
	}
	

	return result;
}

#else

# ifdef __NR__newselect
#  undef __NR_select
#  define __NR_select __NR__newselect
# endif

# define __NR___libc_select __NR_select
_syscall5(int, __libc_select, int, n, fd_set *, readfds, fd_set *, writefds,
		  fd_set *, exceptfds, struct timeval *, timeout);

#endif

weak_alias(__libc_select, select);
