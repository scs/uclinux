/*
 * Copyright (C) 2007 Philippe Gerum <rpm@xenomai.org>.
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
#include <asm/xenomai/system.h>
#include <uitron/uitron.h>

extern int __uitron_muxid;

struct uitron_task_iargs {

	ID tskid;
	T_CTSK *pk_ctsk;
	xncompletion_t *completionp;
};

static void (*old_sigharden_handler)(int sig);

static void uitron_task_sigharden(int sig)
{
	if (old_sigharden_handler &&
	    old_sigharden_handler != &uitron_task_sigharden)
		old_sigharden_handler(sig);

	XENOMAI_SYSCALL1(__xn_sys_migrate, XENOMAI_XENO_DOMAIN);
}

static void *uitron_task_trampoline(void *cookie)
{
	struct uitron_task_iargs *iargs = (struct uitron_task_iargs *)cookie;
	void (*entry)(INT);
	long err;
	INT arg;

	/* Apply sched params here as some libpthread implementions fail
	   doing this via pthread_create. */
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	old_sigharden_handler = signal(SIGHARDEN, &uitron_task_sigharden);

	err = XENOMAI_SKINCALL3(__uitron_muxid,
				__uitron_cre_tsk,
				iargs->tskid, iargs->pk_ctsk,
				iargs->completionp);
	if (err)
		goto fail;

	/* iargs->pk_ctsk might not be valid anymore, after our parent
	   was released from the completion sync, so do not
	   dereference this pointer. */

	do
		err = XENOMAI_SYSCALL2(__xn_sys_barrier, &entry, &arg);
	while (err == -EINTR);

	if (!err)
		entry(arg);

      fail:

	pthread_exit((void *)err);
}

ER cre_tsk(ID tskid, T_CTSK *pk_ctsk)
{
	struct uitron_task_iargs iargs;
	xncompletion_t completion;
	pthread_attr_t thattr;
	pthread_t thid;
	long err;

	XENOMAI_SYSCALL1(__xn_sys_migrate, XENOMAI_LINUX_DOMAIN);

	completion.syncflag = 0;
	completion.pid = -1;

	iargs.tskid = tskid;
	iargs.pk_ctsk = pk_ctsk;
	iargs.completionp = &completion;

	pthread_attr_init(&thattr);

	if (pk_ctsk->stksz == 0)
		pk_ctsk->stksz = PTHREAD_STACK_MIN * 4;
	else if (pk_ctsk->stksz < PTHREAD_STACK_MIN)
		pk_ctsk->stksz = PTHREAD_STACK_MIN;

	pthread_attr_setstacksize(&thattr, pk_ctsk->stksz);
	pthread_attr_setdetachstate(&thattr, PTHREAD_CREATE_DETACHED);
	err = pthread_create(&thid, &thattr, &uitron_task_trampoline, &iargs);

	if (err)
		return -err;

	/* Sync with uitron_task_trampoline() then return.*/

	return XENOMAI_SYSCALL1(__xn_sys_completion, &completion);
}

ER shd_tsk(ID tskid, T_CTSK *pk_ctsk) /* Xenomai extension. */
{
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	old_sigharden_handler = signal(SIGHARDEN, &uitron_task_sigharden);

	return XENOMAI_SKINCALL3(__uitron_muxid,
				 __uitron_cre_tsk,
				 tskid, pk_ctsk,
				 NULL);
}

ER del_tsk(ID tskid)
{
	return XENOMAI_SKINCALL1(__uitron_muxid, __uitron_del_tsk, tskid);
}

ER sta_tsk(ID tskid, INT stacd)
{
	return XENOMAI_SKINCALL2(__uitron_muxid, __uitron_sta_tsk,
				 tskid, stacd);
}

void ext_tsk(void)
{
	XENOMAI_SKINCALL0(__uitron_muxid, __uitron_ext_tsk);
}

void exd_tsk(void)
{
	XENOMAI_SKINCALL0(__uitron_muxid, __uitron_exd_tsk);
}

ER ter_tsk(ID tskid)
{
	return XENOMAI_SKINCALL1(__uitron_muxid, __uitron_ter_tsk, tskid);
}

ER dis_dsp(void)
{
	return XENOMAI_SKINCALL0(__uitron_muxid, __uitron_dis_dsp);
}

ER ena_dsp(void)
{
	return XENOMAI_SKINCALL0(__uitron_muxid, __uitron_ena_dsp);
}

ER chg_pri(ID tskid, PRI tskpri)
{
	return XENOMAI_SKINCALL2(__uitron_muxid, __uitron_chg_pri,
				 tskid, tskpri);
}

ER rot_rdq(PRI tskpri)
{
	return XENOMAI_SKINCALL1(__uitron_muxid, __uitron_rot_rdq, tskpri);
}

ER rel_wai(ID tskid)
{
	return XENOMAI_SKINCALL1(__uitron_muxid, __uitron_rel_wai, tskid);
}

ER get_tid(ID *p_tskid)
{
	return XENOMAI_SKINCALL1(__uitron_muxid, __uitron_get_tid, p_tskid);
}

ER ref_tsk(T_RTSK *pk_rtsk, ID tskid)
{
	return XENOMAI_SKINCALL2(__uitron_muxid, __uitron_ref_tsk,
				 pk_rtsk, tskid);
}

ER sus_tsk(ID tskid)
{
	return XENOMAI_SKINCALL1(__uitron_muxid, __uitron_sus_tsk, tskid);
}

ER rsm_tsk(ID tskid)
{
	return XENOMAI_SKINCALL1(__uitron_muxid, __uitron_rsm_tsk, tskid);
}

ER frsm_tsk(ID tskid)
{
	return XENOMAI_SKINCALL1(__uitron_muxid, __uitron_frsm_tsk, tskid);
}

ER slp_tsk(void)
{
	return XENOMAI_SKINCALL0(__uitron_muxid, __uitron_slp_tsk);
}

ER tslp_tsk(TMO tmout)
{
	return XENOMAI_SKINCALL1(__uitron_muxid, __uitron_tslp_tsk, tmout);
}

ER wup_tsk(ID tskid)
{
	return XENOMAI_SKINCALL1(__uitron_muxid, __uitron_wup_tsk, tskid);
}

ER can_wup(INT *p_wupcnt, ID tskid)
{
	return XENOMAI_SKINCALL2(__uitron_muxid, __uitron_can_wup,
				 p_wupcnt, tskid);
}
