/*
 * hw_livedrive.c - lirc routines for a Creative Labs LiveDrive.
 *
 *     Copyright (C) 2003 Stephen Beahm <stephenbeahm@adelphia.net>
 *
 *     This program is free software; you can redistribute it and/or 
 *     modify it under the terms of the GNU General Public License as 
 *     published by the Free Software Foundation; either version 2 of 
 *     the License, or (at your option) any later version. 
 * 
 *     This program is distributed in the hope that it will be useful, 
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of 
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
 *     GNU General Public License for more details. 
 * 
 *     You should have received a copy of the GNU General Public 
 *     License along with this program; if not, write to the Free 
 *     Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, 
 *     USA. 
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include "hardware.h"
#include "ir_remote.h"
#include "lircd.h"
#include "hw_livedrive_common.h"

struct timeval start, end, last;
ir_code pre, code;

int livedrive_init(void)
{
	if ((hw.fd = open(hw.device, O_RDONLY, 0)) < 0) {
		logprintf(LOG_ERR, "could not open %s", hw.device);
		return (0);
	}

	return (1);
}

int livedrive_deinit(void)
{
	close(hw.fd);
	return (1);
}

int
livedrive_decode(struct ir_remote *remote,
		 ir_code * prep, ir_code * codep, ir_code * postp,
		 int *repeat_flagp, lirc_t * remaining_gapp)
{
	lirc_t gap;
	
	if (!map_code(remote, prep, codep, postp, 16, pre, 16, code, 0, 0))
		return (0);

	gap = 0;
	if (start.tv_sec - last.tv_sec >= 2)
		*repeat_flagp = 0;
	else {
		gap = time_elapsed(&last, &start);

		if (gap < 300000)
			*repeat_flagp = 1;
		else
			*repeat_flagp = 0;
	}

	LOGPRINTF(1, "pre: %llx", (unsigned long long) *prep);
	LOGPRINTF(1, "code: %llx", (unsigned long long) *codep);
	LOGPRINTF(1, "repeat_flag: %d", *repeat_flagp);
	LOGPRINTF(1, "gap: %lu", (unsigned long) gap);
	LOGPRINTF(1, "rem: %lu", (unsigned long) remote->remaining_gap);

	return (1);
}
