/*
 * Copyright (C) 2001,2002 IDEALX (http://www.idealx.com/).
 * Written by Julien Pinon <jpinon@idealx.com>.
 * Copyright (C) 2003,2006 Philippe Gerum <rpm@xenomai.org>.
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

static xnmap_t *vrtx_task_idmap;

static xnqueue_t vrtx_task_q;

static u_long vrtx_default_stacksz;

static TCB vrtx_idle_tcb;

static int vrtx_get_denormalized_prio(xnthread_t *thread, int coreprio)
{
	return vrtx_denormalized_prio(coreprio);
}

static unsigned vrtx_get_magic(void)
{
	return VRTX_SKIN_MAGIC;
}

static xnthrops_t vrtxtask_ops = {
	.get_denormalized_prio = &vrtx_get_denormalized_prio,
	.get_magic = &vrtx_get_magic,
};

static void vrtxtask_delete_hook(xnthread_t *thread)
{
	vrtxtask_t *task;

	if (xnthread_get_magic(thread) != VRTX_SKIN_MAGIC)
		return;

	task = thread2vrtxtask(thread);
	removeq(&vrtx_task_q, &task->link);

	if (task->param != NULL && task->paramsz > 0)
		xnfree(task->param);

	if (task->tid)
		xnmap_remove(vrtx_task_idmap, task->tid);

	vrtx_mark_deleted(task);

	xnheap_schedule_free(&kheap, task, &task->link);
}

int vrtxtask_init(u_long stacksize)
{
	initq(&vrtx_task_q);
	vrtx_default_stacksz = stacksize;
	vrtx_task_idmap = xnmap_create(VRTX_MAX_NTASKS, VRTX_MAX_NTASKS / 2, 1);

	if (!vrtx_task_idmap)
		return -ENOMEM;

	xnpod_add_hook(XNHOOK_THREAD_DELETE, vrtxtask_delete_hook);

	return 0;
}

void vrtxtask_cleanup(void)
{
	xnholder_t *holder;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	while ((holder = getheadq(&vrtx_task_q)) != NULL) {
		xnpod_abort_thread(&link2vrtxtask(holder)->threadbase);
		xnlock_sync_irq(&nklock, s);
	}

	xnlock_put_irqrestore(&nklock, s);

	xnpod_remove_hook(XNHOOK_THREAD_DELETE, vrtxtask_delete_hook);
	xnmap_delete(vrtx_task_idmap);
}

static void vrtxtask_trampoline(void *cookie)
{
	vrtxtask_t *task = (vrtxtask_t *)cookie;
	int err;

	task->entry(task->param);
	sc_tdelete(0, 0, &err);
}

int sc_tecreate_inner(vrtxtask_t *task,
		      void (*entry) (void *),
		      int tid,
		      int prio,
		      int mode,
		      u_long user,
		      u_long sys, char *paddr, u_long psize, int *errp)
{
	xnflags_t bmode = 0, bflags = 0;
	char *_paddr = NULL;
	char name[16];
	spl_t s;

	if (user == 0)
		user = vrtx_default_stacksz;

	if (prio < 0 || prio > 255 || tid < -1 || tid > 255 ||
	    (!(mode & 0x100) && user + sys < 1024)) {	/* Tiny kernel stack */
		*errp = ER_IIP;
		return -1;
	}

	if (tid != 0)
		tid = xnmap_enter(vrtx_task_idmap, tid, task);

	if (tid < 0) {
		*errp = ER_TID;
		return -1;
	}

	if (paddr != NULL && psize > 0) {
		_paddr = xnmalloc(psize);

		if (!_paddr) {
			xnmap_remove(vrtx_task_idmap, tid);
			*errp = ER_MEM;
			return -1;
		}

		memcpy(_paddr, paddr, psize);
		paddr = _paddr;
	}

	sprintf(name, "t%.3d", tid);

#ifdef CONFIG_XENO_OPT_PERVASIVE
	if (mode & 0x100)
		bflags |= XNSHADOW;
#endif /* CONFIG_XENO_OPT_PERVASIVE */

	if (!(mode & 0x8))
		bflags |= XNFPU;

	if (xnpod_init_thread(&task->threadbase,
			      vrtx_tbase,
			      name,
			      vrtx_normalized_prio(prio),
			      bflags, user + sys, &vrtxtask_ops) != 0) {
		if (_paddr)
			xnfree(_paddr);

		xnmap_remove(vrtx_task_idmap, tid);
		*errp = ER_MEM;
		return -1;
	}

	inith(&task->link);
	task->tid = tid;
	task->entry = entry;
	task->param = paddr;
	task->paramsz = psize;
	task->magic = VRTX_TASK_MAGIC;
	task->vrtxtcb.TCBSTAT = 0;

	if (mode & 0x2)
		bmode |= XNSUSP;

	if (mode & 0x4)
		bmode |= XNLOCK;

	if (mode & 0x10)
		bmode |= XNRRB;

	*errp = RET_OK;

	xnlock_get_irqsave(&nklock, s);
	appendq(&vrtx_task_q, &task->link);
	xnlock_put_irqrestore(&nklock, s);

	xnpod_start_thread(&task->threadbase,
			   bmode, 0, XNPOD_ALL_CPUS, &vrtxtask_trampoline,
			   task);
	return tid;
}

int sc_tecreate(void (*entry) (void *),
		int tid,
		int prio,
		int mode,
		u_long user, u_long sys, char *paddr, u_long psize, int *errp)
{
	vrtxtask_t *task;

	task = xnmalloc(sizeof(*task));

	if (!task) {
		*errp = ER_TCB;
		return -1;
	}

	tid =
	    sc_tecreate_inner(task, entry, tid, prio, mode, user, sys, paddr,
			      psize, errp);

	if (tid < 0)
		xnfree(task);

	return tid;
}

int sc_tcreate(void (*entry) (void *), int tid, int prio, int *errp)
{
	return sc_tecreate(entry,
			   tid, prio, 0x0, vrtx_default_stacksz, 0, NULL, 0,
			   errp);
}

/*
 * sc_tdelete() -- Delete a task or a group of tasks.  CAVEAT: If the
 * caller belongs to the priority group of the deleted tasks (opt ==
 * 'A'), the operation may be suspended somewhere in the middle of the
 * deletion loop and never resume.
 */

void sc_tdelete(int tid, int opt, int *errp)
{
	vrtxtask_t *task;
	spl_t s;

	if (opt == 'A') {	/* Delete by priority (depleted form) */
		xnholder_t *holder, *nextholder;

		xnlock_get_irqsave(&nklock, s);

		nextholder = getheadq(&vrtx_task_q);

		*errp = RET_OK;

		while ((holder = nextholder) != NULL) {
			nextholder = nextq(&vrtx_task_q, holder);
			task = link2vrtxtask(holder);

			/* The task base priority is tested here, this excludes
			   temporarily raised priorities due to a PIP boost. */

			if (vrtx_denormalized_prio
			    (xnthread_base_priority(&task->threadbase)) == tid)
				xnpod_delete_thread(&task->threadbase);
		}

		xnlock_put_irqrestore(&nklock, s);

		return;
	}

	if (opt != 0) {
		*errp = ER_IIP;
		return;
	}

	xnlock_get_irqsave(&nklock, s);

	if (tid == 0)
		task = vrtx_current_task();
	else {
		task = xnmap_fetch(vrtx_task_idmap, tid);

		if (!task) {
			*errp = ER_TID;
			goto unlock_and_exit;
		}
	}

	*errp = RET_OK;

	xnpod_delete_thread(&task->threadbase);

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);
}

void sc_tpriority(int tid, int prio, int *errp)
{
	vrtxtask_t *task;
	spl_t s;

	if (prio < 0 || prio > 255) {
		*errp = ER_IIP;
		return;
	}

	xnlock_get_irqsave(&nklock, s);

	if (tid == 0)
		task = vrtx_current_task();
	else {
		task = xnmap_fetch(vrtx_task_idmap, tid);

		if (!task) {
			*errp = ER_TID;
			goto unlock_and_exit;
		}
	}

	if (prio ==
	    vrtx_denormalized_prio(xnthread_base_priority(&task->threadbase))) {
		/* Allow a round-robin effect if newprio == oldprio... */
		if (!xnthread_test_state(&task->threadbase, XNBOOST))
			/* ...unless the thread is PIP-boosted. */
			xnpod_resume_thread(&task->threadbase, 0);
	} else
		xnpod_renice_thread(&task->threadbase,
				    vrtx_normalized_prio(prio));

	*errp = RET_OK;

	xnpod_schedule();

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);
}

/*
 * sc_tresume() -- Resume a task or a group of tasks.
 * CAVEAT: If the calling task is targeted as a result of this
 * call, it is not clear whether the operation should lead to an
 * implicit round-robin effect or not. It currently does.
 */

void sc_tresume(int tid, int opt, int *errp)
{
	vrtxtask_t *task;
	spl_t s;

	if (opt == 'A') {	/* Resume by priority (depleted form) */
		xnholder_t *holder, *nextholder;

		xnlock_get_irqsave(&nklock, s);

		nextholder = getheadq(&vrtx_task_q);

		while ((holder = nextholder) != NULL) {
			nextholder = nextq(&vrtx_task_q, holder);
			task = link2vrtxtask(holder);

			/* The task base priority is tested here, this excludes
			   temporarily raised priorities due to a PIP boost. */

			if (vrtx_denormalized_prio
			    (xnthread_base_priority(&task->threadbase)) == tid)
				xnpod_resume_thread(&task->threadbase, XNSUSP);
		}

		*errp = RET_OK;

		xnpod_schedule();

		xnlock_put_irqrestore(&nklock, s);

		return;
	}

	if (opt != 0) {
		*errp = ER_IIP;
		return;
	}

	xnlock_get_irqsave(&nklock, s);

	if (tid == 0)
		task = vrtx_current_task();
	else {
		task = xnmap_fetch(vrtx_task_idmap, tid);

		if (!task) {
			*errp = ER_TID;
			goto unlock_and_exit;
		}
	}

	xnpod_resume_thread(&task->threadbase, XNSUSP);

	*errp = RET_OK;

	xnpod_schedule();

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);
}

/*
 * sc_tsuspend() -- Suspend a task or a group of tasks.
 * CAVEAT: If the caller belongs to the priority group of the deleted
 * tasks (opt == 'A'), the operation may be suspended somewhere in the
 * middle of the suspension loop and resumed later when the caller is
 * unblocked.
 */

void sc_tsuspend(int tid, int opt, int *errp)
{
	vrtxtask_t *task;
	spl_t s;

	if (opt == 'A') {	/* Resume by priority (depleted form) */
		xnholder_t *holder, *nextholder;

		xnlock_get_irqsave(&nklock, s);

		nextholder = getheadq(&vrtx_task_q);

		*errp = RET_OK;

		while ((holder = nextholder) != NULL) {
			nextholder = nextq(&vrtx_task_q, holder);
			task = link2vrtxtask(holder);

			/* The task base priority is tested here, this excludes
			   temporarily raised priorities due to a PIP boost. */

			if (vrtx_denormalized_prio
			    (xnthread_base_priority(&task->threadbase)) ==
			    tid) {
				task->vrtxtcb.TCBSTAT = TBSSUSP;

				xnpod_suspend_thread(&task->threadbase,
						     XNSUSP, XN_INFINITE, XN_RELATIVE, NULL);

				if (xnthread_test_info(&task->threadbase, XNBREAK))
					*errp = -EINTR;
			}
		}

		xnlock_put_irqrestore(&nklock, s);

		return;
	}

	if (opt != 0) {
		*errp = ER_IIP;
		return;
	}

	xnlock_get_irqsave(&nklock, s);

	if (tid == 0)
		task = vrtx_current_task();
	else {
		task = xnmap_fetch(vrtx_task_idmap, tid);

		if (!task) {
			*errp = ER_TID;
			goto unlock_and_exit;
		}
	}

	task->vrtxtcb.TCBSTAT = TBSSUSP;

	*errp = RET_OK;

	xnpod_suspend_thread(&task->threadbase, XNSUSP, XN_INFINITE, XN_RELATIVE, NULL);

	if (xnthread_test_info(&task->threadbase, XNBREAK))
		*errp = -EINTR;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);
}

void sc_tslice(u_short ticks)
{
	if (ticks == 0)
		xnpod_deactivate_rr();
	else
		xnpod_activate_rr(ticks);
}

void sc_lock(void)
{
	xnpod_lock_sched();
}

void sc_unlock(void)
{
	xnpod_unlock_sched();
}

TCB *sc_tinquiry(int pinfo[], int tid, int *errp)
{
	vrtxtask_t *task;
	TCB *tcb;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (tid == 0) {
		if (xnpod_interrupt_p()) {	/* Called on behalf of an ISR */
			pinfo[0] = 0;
			pinfo[1] = 256;
			pinfo[2] = xnpod_idle_p()? TBSIDLE : 0;
			tcb = &vrtx_idle_tcb;
			tcb->TCBSTAT = pinfo[2];
			goto done;
		}

		task = vrtx_current_task();
	} else {
		task = xnmap_fetch(vrtx_task_idmap, tid);

		if (!task) {
			tcb = NULL;
			*errp = ER_TID;
			goto unlock_and_exit;
		}
	}

	tcb = &task->vrtxtcb;

	/* the VRTX specs says that TCB is only valid in a call to
	 * sc_tinquiry.  we can set TCBSTAT only before each suspending
	 * call and correct it here if the task has been resumed  */

	if (!(testbits(task->threadbase.state, XNTHREAD_BLOCK_BITS)))
		tcb->TCBSTAT = 0;

	pinfo[0] = task->tid;
	pinfo[1] =
	    vrtx_denormalized_prio(xnthread_base_priority(&task->threadbase));
	pinfo[2] = tcb->TCBSTAT;

      done:

	*errp = RET_OK;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return tcb;
}
