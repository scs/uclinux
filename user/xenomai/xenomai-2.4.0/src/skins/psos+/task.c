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

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>
#include <psos+/psos.h>

extern int __psos_muxid;

struct psos_task_iargs {

	const char *name;
	u_long prio;
	u_long flags;
	u_long *tid_r;
	xncompletion_t *completionp;
};

static void (*old_sigharden_handler)(int sig);

static void psos_task_sigharden(int sig)
{
	if (old_sigharden_handler &&
	    old_sigharden_handler != &psos_task_sigharden)
		old_sigharden_handler(sig);

	XENOMAI_SYSCALL1(__xn_sys_migrate, XENOMAI_XENO_DOMAIN);
}

static void *psos_task_trampoline(void *cookie)
{
	struct psos_task_iargs *iargs = (struct psos_task_iargs *)cookie;
	void (*entry)(u_long, u_long, u_long, u_long);
	u_long dummy_args[4] = { 0, 0, 0, 0 }, *targs;
	struct sched_param param;
	long err;

	if (iargs->prio > 0) {
		/* Apply sched params here as some libpthread implementions
		   fail doing this via pthread_create. */
		param.sched_priority = sched_get_priority_max(SCHED_FIFO);
		pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
	}

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	old_sigharden_handler = signal(SIGHARDEN, &psos_task_sigharden);

	err = XENOMAI_SKINCALL5(__psos_muxid,
				__psos_t_create,
				iargs->name, iargs->prio, iargs->flags,
				iargs->tid_r, iargs->completionp);
	if (err)
		goto fail;

	/* Wait on the barrier for the task to be started. The barrier
	   could be released in order to process Linux signals while the
	   Xenomai shadow is still dormant; in such a case, resume wait. */

	do
		err = XENOMAI_SYSCALL2(__xn_sys_barrier, &entry, &targs);
	while (err == -EINTR);

	if (!err) {
		if (targs == NULL)
			targs = dummy_args;
		entry(targs[0], targs[1], targs[2], targs[3]);
	}

      fail:

	pthread_exit((void *)err);
}

u_long t_create(const char *name,
		u_long prio,
		u_long sstack,	/* Ignored. */
		u_long ustack,
		u_long flags,
		u_long *tid_r)
{
	struct psos_task_iargs iargs;
	xncompletion_t completion;
	pthread_attr_t thattr;
	pthread_t thid;
	long err;

	/* Migrate this thread to the Linux domain since we are about
	   to issue a series of regular kernel syscalls in order to
	   create the new Linux thread, which in turn will be mapped
	   to a pSOS shadow. */

	XENOMAI_SYSCALL1(__xn_sys_migrate, XENOMAI_LINUX_DOMAIN);

	completion.syncflag = 0;
	completion.pid = -1;

	iargs.name = name;
	iargs.prio = prio;
	iargs.flags = flags;
	iargs.tid_r = tid_r;
	iargs.completionp = &completion;

	pthread_attr_init(&thattr);

	ustack += sstack;

	if (ustack == 0)
		ustack = PTHREAD_STACK_MIN * 4;
	else if (ustack < PTHREAD_STACK_MIN)
		ustack = PTHREAD_STACK_MIN;

	pthread_attr_setstacksize(&thattr, ustack);
	pthread_attr_setdetachstate(&thattr, PTHREAD_CREATE_DETACHED);

	err = pthread_create(&thid, &thattr, &psos_task_trampoline, &iargs);

	/* Pass back POSIX codes returned by internal calls as
	   negative values to distinguish them from pSOS ones. */

	if (err)
		return -err;

	/* Sync with psos_task_trampoline() then return.*/

	return XENOMAI_SYSCALL1(__xn_sys_completion, &completion);
}

u_long t_shadow(const char *name, /* Xenomai extension. */
		u_long prio,
		u_long flags,
		u_long *tid_r)
{
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	old_sigharden_handler = signal(SIGHARDEN, &psos_task_sigharden);

	return XENOMAI_SKINCALL5(__psos_muxid,
				 __psos_t_create,
				 name, prio, flags,
				 tid_r, NULL);
}

u_long t_start(u_long tid,
	       u_long mode,
	       void (*startaddr)(u_long a0,
				 u_long a1,
				 u_long a2,
				 u_long a3),
	       u_long targs[])
{
	return XENOMAI_SKINCALL4(__psos_muxid, __psos_t_start,
				 tid, mode, startaddr, targs);
}

u_long t_delete(u_long tid)
{
	return XENOMAI_SKINCALL1(__psos_muxid, __psos_t_delete, tid);
}

u_long t_suspend(u_long tid)
{
	return XENOMAI_SKINCALL1(__psos_muxid, __psos_t_suspend, tid);
}

u_long t_resume(u_long tid)
{
	return XENOMAI_SKINCALL1(__psos_muxid, __psos_t_resume, tid);
}

u_long t_ident(const char *name, u_long nodeno, u_long *tid_r)
{
	return XENOMAI_SKINCALL2(__psos_muxid, __psos_t_ident, name, tid_r);
}

u_long t_mode(u_long clrmask, u_long setmask, u_long *oldmode_r)
{
	return XENOMAI_SKINCALL3(__psos_muxid, __psos_t_mode,
				 clrmask, setmask, oldmode_r);
}

u_long t_setpri(u_long tid, u_long newprio, u_long *oldprio_r)
{
	return XENOMAI_SKINCALL3(__psos_muxid, __psos_t_setpri,
				 tid, newprio, oldprio_r);
}

u_long ev_send(u_long tid, u_long events)
{
	return XENOMAI_SKINCALL2(__psos_muxid, __psos_ev_send, tid, events);
}

u_long ev_receive(u_long events, u_long flags, u_long timeout, u_long *events_r)
{
	return XENOMAI_SKINCALL4(__psos_muxid, __psos_ev_receive,
				 events, flags, timeout, events_r);
}
