/* vi: set sw=4 ts=4: */
/*
 * getgroups() for uClibc
 *
 * Copyright (C) 2000-2004 by Erik Andersen <andersen@codepoet.org>
 *
 * GNU Library General Public License (LGPL) version 2 or later.
 */

#include "syscalls.h"
#include <unistd.h>

#define MIN(a,b) (((a)<(b))?(a):(b))

#define __NR___syscall_getgroups __NR_getgroups
static inline _syscall2(int, __syscall_getgroups,
		int, size, __kernel_gid_t *, list);

int getgroups(int n, gid_t * groups)
{
	if (unlikely(n < 0)) {
		__set_errno(EINVAL);
		return -1;
	} else {
		int i, ngids;
		__kernel_gid_t *kernel_groups;

		n = MIN(n, sysconf(_SC_NGROUPS_MAX));
		if(kernel_groups=(__kernel_gid_t *)malloc(sizeof(__kernel_gid_t)*n) == NULL){
			__set_errno(EINVAL);
			return -1;
		}
			
		ngids = __syscall_getgroups(n, kernel_groups);
		if (n != 0 && ngids > 0) {
			for (i = 0; i < ngids; i++) {
				groups[i] = kernel_groups[i];
			}
		}
		free(kernel_groups);
		return ngids;
	}
}
