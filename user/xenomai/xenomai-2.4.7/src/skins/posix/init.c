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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <posix/posix.h>
#include <posix/syscall.h>
#include <rtdm/syscall.h>
#include <asm-generic/bits/bind.h>
#include <asm-generic/bits/mlock_alert.h>

int __pse51_muxid = -1;
int __rtdm_muxid = -1;
int __rtdm_fd_start = INT_MAX;
static int fork_handler_registered;

int __wrap_pthread_setschedparam(pthread_t, int, const struct sched_param *);
void pse51_clock_init(int);

static __attribute__ ((constructor))
void __init_posix_interface(void)
{
	struct sched_param parm;
	int muxid, err;

	muxid =
	    xeno_bind_skin(PSE51_SKIN_MAGIC, "POSIX", "xeno_posix");

#ifdef CONFIG_XENO_HW_DIRECT_TSC
	pse51_clock_init(muxid);
#endif /* CONFIG_XENO_HW_DIRECT_TSC */
	
	__pse51_muxid = __xn_mux_shifted_id(muxid);

	muxid = XENOMAI_SYSBIND(RTDM_SKIN_MAGIC,
				XENOMAI_FEAT_DEP, XENOMAI_ABI_REV, NULL);
	if (muxid > 0) {
		__rtdm_muxid = __xn_mux_shifted_id(muxid);
		__rtdm_fd_start = FD_SETSIZE - XENOMAI_SKINCALL0(__rtdm_muxid,
								 __rtdm_fdcount);
	}

	/* Shadow the main thread. mlock the whole memory for the time of the
	   syscall, in order to avoid the SIGXCPU signal. */
	if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
		perror("Xenomai Posix skin init: mlockall");
		exit(EXIT_FAILURE);
	}

	parm.sched_priority = 0;
	err = __wrap_pthread_setschedparam(pthread_self(), SCHED_OTHER,
					   &parm);
	if (err) {
		fprintf(stderr, "Xenomai Posix skin init: "
			"pthread_setschedparam: %s\n", strerror(err));
		exit(EXIT_FAILURE);
	}

#ifndef CONFIG_XENO_POSIX_AUTO_MLOCKALL
	if (munlockall()) {
		perror("Xenomai Posix skin init: munlockall");
		exit(EXIT_FAILURE);
	}
#endif /* !CONFIG_XENO_POSIX_AUTO_MLOCKALL */

	if (!fork_handler_registered) {
		err = pthread_atfork(NULL, NULL, &__init_posix_interface);
		if (err) {
			fprintf(stderr, "Xenomai Posix skin init: "
				"pthread_atfork: %s\n", strerror(err));
			exit(EXIT_FAILURE);
		}
		fork_handler_registered = 1;
	}
}
