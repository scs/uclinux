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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <vxworks/vxworks.h>

extern int __vxworks_muxid;

static inline int __wdWait(wind_wd_utarget_t *wdt)
{
	return XENOMAI_SKINCALL1(__vxworks_muxid, __vxworks_wd_wait, wdt);
}

static void wdServer(void)
{
	wind_wd_utarget_t wdt;

	for (;;) {
		switch (__wdWait(&wdt)) {
		case 0:
			wdt.handler(wdt.arg);
		case -EINTR:
			break;
		default:	/* includes -EIDRM */
			taskDeleteForce(0);
		}
	}
}

WDOG_ID wdCreate(void)
{
	WDOG_ID wdog_id;
	int err;

	err = XENOMAI_SKINCALL1(__vxworks_muxid, __vxworks_wd_create, &wdog_id);
	if (err) {
		errno = abs(err);
		return 0;
	}

	return wdog_id;
}

STATUS wdDelete(WDOG_ID wdog_id)
{
	int err;

	err = XENOMAI_SKINCALL1(__vxworks_muxid, __vxworks_wd_delete, wdog_id);
	if (err) {
		errno = abs(err);
		return ERROR;
	}

	return OK;
}

STATUS wdStart(WDOG_ID wdog_id, int timeout, wind_timer_t handler, long arg)
{
	long start_server;
	int err;

	err = XENOMAI_SKINCALL5(__vxworks_muxid,
				__vxworks_wd_start, wdog_id, timeout, handler,
				arg, &start_server);
	if (err) {
		errno = abs(err);
		return ERROR;
	}

	/* Upon creation of the first watchdog, start a server task
	   which will fire the watchdog handlers as needed. */

	if (start_server) {
		char name[XNOBJECT_NAME_LEN];
		snprintf(name, XNOBJECT_NAME_LEN - 1, "wdserver-%d", getpid());
		if (taskSpawn(name, 0, 0, 0, (FUNCPTR) & wdServer,
			      0, 0, 0, 0, 0, 0, 0, 0, 0, 0) == ERROR) {
			fprintf(stderr, "VxWorks: failed to start the watchdog server (err %d)\n", errno);
			return ERROR;
		}
	}

	return OK;
}

STATUS wdCancel(WDOG_ID wdog_id)
{
	int err;

	err = XENOMAI_SKINCALL1(__vxworks_muxid, __vxworks_wd_cancel, wdog_id);
	if (err) {
		errno = abs(err);
		return ERROR;
	}

	return OK;
}
