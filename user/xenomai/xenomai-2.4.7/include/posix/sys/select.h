#ifndef _XENO_POSIX_SELECT_H
#define _XENO_POSIX_SELECT_H

#if !(defined(__KERNEL__) || defined(__XENO_SIM__))

#include_next <sys/select.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int __real_select (int __nfds, fd_set *__restrict __readfds,
			  fd_set *__restrict __writefds,
			  fd_set *__restrict __exceptfds,
			  struct timeval *__restrict __timeout);

#ifdef __cplusplus
}
#endif

#endif /* !(__KERNEL__ || __XENO_SIM__) */

#endif /* _XENO_POSIX_SELECT_H */
