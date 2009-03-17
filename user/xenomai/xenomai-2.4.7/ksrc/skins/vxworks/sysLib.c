/*
 * Copyright (C) 2001,2002 IDEALX (http://www.idealx.com/).
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>.
 * Copyright (C) 2003 Philippe Gerum <rpm@xenomai.org>.
 *
 * Xenomai is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <vxworks/defs.h>

#define ONE_BILLION 1000000000

static wind_tick_handler_t tick_handler;
static long tick_handler_arg;

void tickAnnounce(void)
{
	/* Announce a tick to the time base. */
	xntbase_tick(wind_tbase);
}

void wind_sysclk_hook(void)
{
	tick_handler(tick_handler_arg);
}

int wind_sysclk_init(u_long period)
{
	extern u_long sync_time;
	u_long init_rate;
	int err;

	init_rate = period ? ONE_BILLION / period : 0;

	err = xntbase_alloc("vxworks", period, sync_time ? 0 : XNTBISO,
			    &wind_tbase);
	if (err || period == 0)
		return err;

	err = sysClkRateSet(init_rate);
	if (err)
		xntbase_free(wind_tbase);
	else
		xntbase_start(wind_tbase);

	return err;
}

void wind_sysclk_cleanup(void)
{
	xntbase_free(wind_tbase);
}

STATUS sysClkConnect(wind_tick_handler_t func, long arg)
{
	if (func == NULL)
		return ERROR;

	tick_handler_arg = arg;
	tick_handler = func;
	xntbase_set_hook(wind_tbase, &wind_sysclk_hook);

	return OK;
}

void sysClkDisable(void)
{
	xntbase_stop(wind_tbase);
}

void sysClkEnable(void)
{
	xntbase_start(wind_tbase);
}

int sysClkRateGet(void)
{
	return xntbase_get_ticks2sec(wind_tbase);
}

STATUS sysClkRateSet(int new_rate)
{
	int err;

	error_check(!xnpod_secondary_p(), -EPERM, return ERROR);

	if (new_rate <= 0) {
		return ERROR;
	}

	err = xntbase_update(wind_tbase, ONE_BILLION / new_rate);

	return err == 0 ? OK : ERROR;
}
