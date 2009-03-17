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
#include <stdio.h>
#include <memory.h>
#include <malloc.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>
#include <vrtx/vrtx.h>

extern pthread_key_t __vrtx_tskey;

extern int __vrtx_muxid;

/* Public Xenomai interface. */

struct vrtx_task_iargs {
	int tid;
	int *tid_r;
	int prio;
	int mode;
	void (*entry) (void *);
	void *param;
	xncompletion_t *completionp;
};

static void (*old_sigharden_handler)(int sig);

static void vrtx_task_sigharden(int sig)
{
	if (old_sigharden_handler &&
	    old_sigharden_handler != &vrtx_task_sigharden)
		old_sigharden_handler(sig);

	XENOMAI_SYSCALL1(__xn_sys_migrate, XENOMAI_XENO_DOMAIN);
}

static int vrtx_task_set_posix_priority(int prio, struct sched_param *param)
{
	int maxpprio, pprio;

	maxpprio = sched_get_priority_max(SCHED_FIFO);

	/* We need to normalize this value first. */
	pprio = vrtx_normalized_prio(prio);
	if (pprio > maxpprio)
		pprio = maxpprio;

	memset(param, 0, sizeof(*param));
	param->sched_priority = pprio;

	return pprio ? SCHED_FIFO : SCHED_OTHER;
}

static void *vrtx_task_trampoline(void *cookie)
{
	struct vrtx_task_iargs *iargs =
	    (struct vrtx_task_iargs *)cookie, _iargs;
	struct vrtx_arg_bulk bulk;
	struct sched_param param;
	int policy;
	long err;
	TCB *tcb;

	/* Backup the arg struct, it might vanish after completion. */
	memcpy(&_iargs, iargs, sizeof(_iargs));

	/*
	 * Apply sched params here as some libpthread implementations
	 * fail doing this properly via pthread_create.
	 */
	policy = vrtx_task_set_posix_priority(iargs->prio, &param);
	pthread_setschedparam(pthread_self(), policy, &param);

	/* vrtx_task_delete requires asynchronous cancellation */
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	tcb = (TCB *) malloc(sizeof(*tcb));
	if (tcb == NULL) {
		fprintf(stderr, "Xenomai: failed to allocate local TCB?!\n");
		err = -ENOMEM;
		goto fail;
	}

	pthread_setspecific(__vrtx_tskey, tcb);

	old_sigharden_handler = signal(SIGHARDEN, &vrtx_task_sigharden);

	bulk.a1 = (u_long)iargs->tid;
	bulk.a2 = (u_long)iargs->prio;
	bulk.a3 = (u_long)iargs->mode;

	err = XENOMAI_SKINCALL3(__vrtx_muxid,
				__vrtx_tecreate,
				&bulk, iargs->tid_r, iargs->completionp);
	if (err)
		goto fail;

	/* Wait on the barrier for the task to be started. The barrier
	   could be released in order to process Linux signals while the
	   Xenomai shadow is still dormant; in such a case, resume wait. */

	do
		err = XENOMAI_SYSCALL2(__xn_sys_barrier, NULL, NULL);
	while (err == -EINTR);

	if (!err)
		_iargs.entry(_iargs.param);
fail:
	pthread_exit((void *)err);
}

int sc_tecreate(void (*entry) (void *),
		int tid,
		int prio,
		int mode,
		u_long ustacksz,
		u_long sstacksz __attribute__ ((unused)),
		char *paddr, u_long psize, int *errp)
{
	struct vrtx_task_iargs iargs;
	xncompletion_t completion;
	struct sched_param param;
	int err, tid_r, policy;
	pthread_attr_t thattr;
	pthread_t thid;

	/* Migrate this thread to the Linux domain since we are about to
	   issue a series of regular kernel syscalls in order to create
	   the new Linux thread, which in turn will be mapped to a VRTX
	   shadow. */

	XENOMAI_SYSCALL1(__xn_sys_migrate, XENOMAI_LINUX_DOMAIN);

	completion.syncflag = 0;
	completion.pid = -1;

	iargs.tid = tid;
	iargs.tid_r = &tid_r;
	iargs.prio = prio;
	iargs.mode = mode;
	iargs.entry = entry;
	iargs.param = paddr;
	iargs.completionp = &completion;

	pthread_attr_init(&thattr);

	if (ustacksz == 0)
		ustacksz = PTHREAD_STACK_MIN * 4;
	else if (ustacksz < PTHREAD_STACK_MIN * 2)
		ustacksz = PTHREAD_STACK_MIN * 2;

	pthread_attr_setinheritsched(&thattr, PTHREAD_EXPLICIT_SCHED);
	policy = vrtx_task_set_posix_priority(prio, &param);
	pthread_attr_setschedparam(&thattr, &param);
	pthread_attr_setschedpolicy(&thattr, policy);
	pthread_attr_setstacksize(&thattr, ustacksz);
	pthread_attr_setdetachstate(&thattr, PTHREAD_CREATE_DETACHED);

	err = pthread_create(&thid, &thattr, &vrtx_task_trampoline, &iargs);
	if (!err)
		/* Wait for sync with vrtx_task_trampoline() */
		err = XENOMAI_SYSCALL1(__xn_sys_completion, &completion);

	/* POSIX codes returned by internal calls do not conflict with
	   VRTX ones, so both can be returned through the error
	   pointer. */

	*errp = err;

	return tid_r;
}

int sc_tcreate(void (*entry) (void *), int tid, int prio, int *errp)
{
	return sc_tecreate(entry, tid, prio, 0, 0, 0, NULL, 0, errp);
	/* Eh, this one was easy. */
}

void sc_tdelete(int tid, int opt, int *errp)
{
	*errp = XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_tdelete, tid, opt);
}

void sc_tpriority(int tid, int prio, int *errp)
{
	*errp = XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_tpriority, tid, prio);
}

void sc_tresume(int tid, int opt, int *errp)
{
	*errp = XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_tresume, tid, opt);
}

void sc_tsuspend(int tid, int opt, int *errp)
{
	*errp = XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_tsuspend, tid, opt);
}

TCB *sc_tinquiry(int pinfo[], int tid, int *errp)
{
	TCB *tcb;

	tcb = (TCB *) pthread_getspecific(__vrtx_tskey);	/* Cannot fail. */

	*errp = XENOMAI_SKINCALL3(__vrtx_muxid,
				  __vrtx_tinquiry, pinfo, tcb, tid);
	if (*errp)
		return NULL;

	return tcb;
}

void sc_tslice(unsigned short ticks)
{
	XENOMAI_SKINCALL1(__vrtx_muxid, __vrtx_tslice, ticks);
}

void sc_lock(void)
{
	XENOMAI_SKINCALL0(__vrtx_muxid, __vrtx_lock);
}

void sc_unlock(void)
{
	XENOMAI_SKINCALL0(__vrtx_muxid, __vrtx_unlock);
}
