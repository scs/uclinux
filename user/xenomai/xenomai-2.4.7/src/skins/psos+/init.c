/*
 * Copyright (C) 2006 Philippe Gerum <rpm@xenomai.org>.
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
#include <errno.h>
#include <sys/mman.h>
#include <psos+/psos.h>
#include <asm-generic/bits/bind.h>
#include <asm-generic/bits/mlock_alert.h>

int __psos_muxid = -1;

xnsysinfo_t __psos_sysinfo;

static __attribute__ ((constructor))
void __init_xeno_interface(void)
{
	u_long err, tid;

	__psos_muxid = xeno_bind_skin(PSOS_SKIN_MAGIC, "psos", "xeno_psos");

	err = XENOMAI_SYSCALL2(__xn_sys_info, __psos_muxid, &__psos_sysinfo);

	if (err) {
		fprintf(stderr, "Xenomai pSOS skin init: cannot retrieve sysinfo, status %ld", err);
		exit(EXIT_FAILURE);
	}

	__psos_muxid = __xn_mux_shifted_id(__psos_muxid);

	/* Shadow the main thread. mlock the whole memory for the time
	   of the syscall, in order to avoid the SIGXCPU signal. */
	if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
		perror("Xenomai pSOS skin init: mlockall() failed");
		exit(EXIT_FAILURE);
	}

	err = t_shadow("MAIN", 0, 0, &tid);

	if (err) {
		fprintf(stderr, "Xenomai pSOS skin init: t_shadow() failed, status %ld", err);
		exit(EXIT_FAILURE);
	}

#ifndef CONFIG_XENO_PSOS_AUTO_MLOCKALL
	if (munlockall()) {
		perror("Xenomai pSOS skin init: munlockall");
		exit(EXIT_FAILURE);
	}
#endif /* !CONFIG_XENO_PSOS_AUTO_MLOCKALL */
}

void k_fatal(u_long err_code, u_long flags)
{
	exit(1);
}
