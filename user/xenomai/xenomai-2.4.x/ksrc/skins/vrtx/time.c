/*
 * Copyright (C) 2001,2002 IDEALX (http://www.idealx.com/).
 * Written by Julien Pinon <jpinon@idealx.com>.
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

#include <vrtx/task.h>

#define TEN_POW_9 1000000000ULL

void ui_timer(void)
{
	xntbase_tick(vrtx_tbase);
}

void sc_gclock(struct timespec *timep, unsigned long *nsp, int *errp)
{
	unsigned long remain;
	xnticks_t now;

	*nsp = xntbase_get_tickval(vrtx_tbase);
	now = xntbase_get_time(vrtx_tbase);
	timep->seconds = xnarch_uldivrem(now, 1000000000, &remain);
	timep->nanoseconds = remain;
	*errp = RET_OK;
}

void sc_sclock(struct timespec time, unsigned long ns, int *errp)
{
 	spl_t s;
 
	if (ns > 1000000000 ||
	    time.nanoseconds < 0 || time.nanoseconds > 999999999) {
		*errp = ER_IIP;
		return;
	}

	if (ns != xntbase_get_tickval(vrtx_tbase)) {
		xntbase_switch("vrtx", ns, &vrtx_tbase);

		if (ns != 0)
			xntbase_start(vrtx_tbase);
	}

	xnlock_get_irqsave(&nklock, s);
	xntbase_adjust_time(&nktbase,
			    time.seconds * TEN_POW_9 + time.nanoseconds -
			    xntbase_get_time(&nktbase));
	xnlock_put_irqrestore(&nklock, s);

	*errp = RET_OK;
}

unsigned long sc_gtime(void)
{
	return (unsigned long)xntbase_get_time(vrtx_tbase);
}

void sc_stime(unsigned long time)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	xntbase_adjust_time(vrtx_tbase, time - sc_gtime());
	xnlock_put_irqrestore(&nklock, s);
}

void sc_delay(long ticks)
{
	if (ticks > 0) {
		vrtxtask_t *task = vrtx_current_task();
		task->vrtxtcb.TCBSTAT = TBSDELAY;
		xnpod_delay(ticks);
		/* XNBREAK can only be checked in syscall.c due to
		 * call protoype. */
	} else
		xnpod_yield();	/* Perform manual round-robin */
}

void sc_adelay(struct timespec time, int *errp)
{
	xnticks_t now, etime;

	if ((time.nanoseconds < 0) || (time.nanoseconds > 999999999)) {
		*errp = ER_IIP;
		return;
	}

	etime = time.seconds * TEN_POW_9 + time.nanoseconds;
	now = xntbase_get_time(vrtx_tbase);
	*errp = RET_OK;

	if (etime > now) {
		vrtxtask_t *task = vrtx_current_task();
		task->vrtxtcb.TCBSTAT = TBSADELAY;
		xnpod_delay(etime - now);
		if (xnthread_test_info(&task->threadbase, XNBREAK))
		    *errp = -EINTR;
	} else
		xnpod_yield();	/* Perform manual round-robin */
}
