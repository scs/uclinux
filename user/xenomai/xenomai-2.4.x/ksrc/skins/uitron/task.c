/*
 * Copyright (C) 2001-2007 Philippe Gerum <rpm@xenomai.org>.
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

#include <nucleus/registry.h>
#include <nucleus/pod.h>
#include <nucleus/heap.h>
#include <uitron/task.h>

xnmap_t *ui_task_idmap;

static xnqueue_t uitaskq;

static int uitask_get_denormalized_prio(xnthread_t *thread, int coreprio)
{
	return ui_denormalized_prio(coreprio);
}

static unsigned uitask_get_magic(void)
{
	return uITRON_SKIN_MAGIC;
}

static xnthrops_t uitask_ops = {
	.get_denormalized_prio = &uitask_get_denormalized_prio,
	.get_magic = &uitask_get_magic,
};

static void uitask_delete_hook(xnthread_t *thread)
{
	uitask_t *task;

	if (xnthread_get_magic(thread) != uITRON_SKIN_MAGIC)
		return;

	task = thread2uitask(thread);
	removeq(&uitaskq, &task->link);
	ui_mark_deleted(task);
	xnfree(task);
}

int uitask_init(void)
{
	initq(&uitaskq);
	ui_task_idmap = xnmap_create(uITRON_MAX_TASKID, uITRON_MAX_TASKID, 1);
	if (!ui_task_idmap)
		return -ENOMEM;
	xnpod_add_hook(XNHOOK_THREAD_DELETE, uitask_delete_hook);
	return 0;
}

void uitask_cleanup(void)
{
	xnholder_t *holder;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	while ((holder = getheadq(&uitaskq)) != NULL) {
		uitask_t *task = link2uitask(holder);
		xnpod_abort_thread(&task->threadbase);
		xnlock_sync_irq(&nklock, s);
	}

	xnlock_put_irqrestore(&nklock, s);

	xnpod_remove_hook(XNHOOK_THREAD_DELETE, uitask_delete_hook);
	xnmap_delete(ui_task_idmap);
}

ER cre_tsk(ID tskid, T_CTSK *pk_ctsk)
{
	int bflags = XNFPU;
	uitask_t *task;
	char aname[32];
	spl_t s;

	if (xnpod_asynch_p())
		return EN_CTXID;

	/* uITRON uses a reverse priority scheme: the lower the value,
	   the higher the priority. Level 0 is kept for creating non
	   real-time shadows. */

	if (pk_ctsk->itskpri < 0 ||
	    pk_ctsk->itskpri > 8)
		return E_PAR;

	if (pk_ctsk->stksz < 1024)
		return E_PAR;

#ifdef CONFIG_XENO_OPT_PERVASIVE
	if (pk_ctsk->tskatr & TA_SHADOW)
		bflags |= XNSHADOW;
	else if (pk_ctsk->itskpri == 0)
		/* Only shadows may have a non-RT priority. */
		return E_PAR;
#endif /* CONFIG_XENO_OPT_PERVASIVE */

	if (tskid <= 0 || tskid > uITRON_MAX_TASKID)
		return E_ID;

	task = xnmalloc(sizeof(*task));

	if (!task)
		return E_NOMEM;

	tskid = xnmap_enter(ui_task_idmap, tskid, task);

	if (tskid <= 0) {
		xnfree(task);
		return E_OBJ;
	}

	sprintf(aname, "tsk%d", tskid);

	if (xnpod_init_thread(&task->threadbase,
			      ui_tbase,
			      aname,
			      ui_normalized_prio(pk_ctsk->itskpri), bflags,
			      pk_ctsk->stksz, &uitask_ops) != 0) {
		xnmap_remove(ui_task_idmap, tskid);
		xnfree(task);
		return E_NOMEM;
	}

	inith(&task->link);
	task->id = tskid;
	task->entry = pk_ctsk->task;
	task->exinf = pk_ctsk->exinf;
	task->tskatr = pk_ctsk->tskatr;
	task->suspcnt = 0;
	task->wkupcnt = 0;
	task->waitinfo = 0;
	xnlock_get_irqsave(&nklock, s);
	appendq(&uitaskq, &task->link);
	xnlock_put_irqrestore(&nklock, s);
	task->magic = uITRON_TASK_MAGIC;

	return E_OK;
}

ER del_tsk(ID tskid)
{
	uitask_t *task;
	ER err = E_OK;
	spl_t s;

	if (xnpod_asynch_p())
		return EN_CTXID;

	if (tskid <= 0 || tskid > uITRON_MAX_TASKID)
		return E_ID;

	xnlock_get_irqsave(&nklock, s);

	task = xnmap_fetch(ui_task_idmap, tskid);

	if (!task) {
		err = E_NOEXS;
		goto unlock_and_exit;
	}

	if (!xnthread_test_state(&task->threadbase, XNDORMANT)) {
		err = E_OBJ;
		goto unlock_and_exit;
	}

	xnmap_remove(ui_task_idmap, task->id);
	xnpod_delete_thread(&task->threadbase);

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return E_OK;
}

static void uitask_trampoline(void *cookie)
{
	uitask_t *task = (uitask_t *) cookie;
	void (*entry) (INT) = (void (*)(INT))task->entry;
	entry(task->stacd);
	ext_tsk();
}

ER sta_tsk(ID tskid, INT stacd)
{
	uitask_t *task;
	ER err = E_OK;
	spl_t s;

	if (xnpod_asynch_p())
		return EN_CTXID;

	if (tskid <= 0 || tskid > uITRON_MAX_TASKID)
		return E_ID;

	xnlock_get_irqsave(&nklock, s);

	task = xnmap_fetch(ui_task_idmap, tskid);

	if (!task) {
		err = E_NOEXS;
		goto unlock_and_exit;
	}

	if (!xnthread_test_state(&task->threadbase, XNDORMANT)) {
		err = E_OBJ;
		goto unlock_and_exit;
	}

	task->suspcnt = 0;
	task->wkupcnt = 0;
	task->waitinfo = 0;
	task->stacd = stacd;

#ifdef CONFIG_XENO_OPT_PERVASIVE
	if (xnthread_test_state(&task->threadbase, XNSHADOW))
		xnpod_start_thread(&task->threadbase,
				   0, 0, XNPOD_ALL_CPUS,
				   (void(*)(void *))task->entry, (void *)(long)stacd);
	else
#endif /* CONFIG_XENO_OPT_PERVASIVE */
		xnpod_start_thread(&task->threadbase,
				   0, 0, XNPOD_ALL_CPUS, uitask_trampoline, task);

	xnpod_resume_thread(&task->threadbase, XNDORMANT);

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

void ext_tsk(void)
{
	if (xnpod_unblockable_p()) {
		xnlogwarn("ext_tsk() not called on behalf of a uITRON task");
		return;
	}

	if (xnpod_locked_p()) {
		xnlogwarn("ext_tsk() called while in dispatch-disabled state");
		return;
	}

	xnpod_suspend_thread(&ui_current_task()->threadbase,
			     XNDORMANT, XN_INFINITE, XN_RELATIVE, NULL);
}

void exd_tsk(void)
{
	uitask_t *task;
	spl_t s;

	if (xnpod_unblockable_p()) {
		xnlogwarn("exd_tsk() not called on behalf of a uITRON task");
		return;
	}

	if (xnpod_locked_p()) {
		xnlogwarn("exd_tsk() called while in dispatch-disabled state");
		return;
	}

	task = ui_current_task();
	xnlock_get_irqsave(&nklock, s);
	xnmap_remove(ui_task_idmap, task->id);
	xnpod_delete_thread(&task->threadbase);
	xnlock_put_irqrestore(&nklock, s);
}

/* Helper routine for the task termination -- must be called
   on behalf a safe context since it does not enforce any
   critical section. */

static void ter_tsk_helper(uitask_t * task)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	xnthread_clear_info(&task->threadbase, uITRON_TASK_HOLD);

	if (xnthread_test_state(&task->threadbase, XNSUSP))
		xnpod_resume_thread(&task->threadbase, XNSUSP);

	xnpod_unblock_thread(&task->threadbase);

	xnpod_suspend_thread(&task->threadbase, XNDORMANT, XN_INFINITE, XN_RELATIVE, NULL);

	xnlock_put_irqrestore(&nklock, s);
}

ER ter_tsk(ID tskid)
{
	uitask_t *task;
	ER err = E_OK;
	spl_t s;

	if (xnpod_unblockable_p())
		return EN_CTXID;

	if (tskid <= 0 || tskid > uITRON_MAX_TASKID)
		return E_ID;

	if (tskid == ui_current_task()->id)
		return E_OBJ;

	xnlock_get_irqsave(&nklock, s);

	task = xnmap_fetch(ui_task_idmap, tskid);

	if (!task) {
		err = E_NOEXS;
		goto unlock_and_exit;
	}

	if (xnthread_test_state(&task->threadbase, XNDORMANT)) {
		err = E_OBJ;
		goto unlock_and_exit;
	}

	if (xnthread_test_state(&task->threadbase, XNLOCK)) {
		/* We must be running on behalf of an IST here, so we
		   only mark the target task as held for
		   termination. The actual termination code will be
		   applied by the task itself when it re-enables
		   dispatching. */
		xnthread_set_info(&task->threadbase, uITRON_TASK_HOLD);
		goto unlock_and_exit;

	}

	ter_tsk_helper(task);

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

ER dis_dsp(void)
{
	if (xnpod_asynch_p())
		return E_CTX;

	if (!xnpod_locked_p())
		xnpod_lock_sched();

	return E_OK;
}

ER ena_dsp(void)
{
	if (xnpod_asynch_p())
		return E_CTX;

	if (xnpod_locked_p()) {
		xnpod_unlock_sched();

		if (xnthread_test_info(&ui_current_task()->threadbase,
				       uITRON_TASK_HOLD))
			ter_tsk_helper(ui_current_task());
	}

	return E_OK;
}

ER chg_pri(ID tskid, PRI tskpri)
{
	uitask_t *task;
	spl_t s;

	if (tskpri != TPRI_INI) {
		if (tskpri < 1 || tskpri > 8)
			return E_PAR;
	}

	if (tskid == TSK_SELF) {
		if (!xnpod_primary_p())
			return E_ID;

		task = ui_current_task();
		xnlock_get_irqsave(&nklock, s);
	} else {
		if (tskid <= 0 || tskid > uITRON_MAX_TASKID)
			return E_ID;

		xnlock_get_irqsave(&nklock, s);

		task = xnmap_fetch(ui_task_idmap, tskid);

		if (!task) {
			xnlock_put_irqrestore(&nklock, s);
			return E_NOEXS;
		}

		if (xnthread_test_state(&task->threadbase, XNDORMANT)) {
			xnlock_put_irqrestore(&nklock, s);
			return E_OBJ;
		}
	}

	if (tskpri == TPRI_INI)
		tskpri = ui_denormalized_prio(xnthread_initial_priority(&task->threadbase));

	/* uITRON specs explicitly states: "If the priority specified
	   is the same as the current priority, the task will still be
	   moved behind other tasks of the same priority", so this
	   allows for manual round-robin. */
	xnpod_renice_thread(&task->threadbase, ui_normalized_prio(tskpri));
	xnpod_schedule();
	xnlock_put_irqrestore(&nklock, s);

	return E_OK;
}

ER rot_rdq(PRI tskpri)
{
	if (tskpri != TPRI_RUN) {
		if (tskpri < 1 || tskpri > 8)
			return E_PAR;
		xnpod_rotate_readyq(ui_normalized_prio(tskpri));
	} else
		xnpod_rotate_readyq(XNPOD_RUNPRIO);

	xnpod_schedule();

	return E_OK;
}

ER rel_wai(ID tskid)
{
	uitask_t *task;
	ER err = E_OK;
	spl_t s;

	if (xnpod_asynch_p())
		return EN_CTXID;

	if (tskid <= 0 || tskid > uITRON_MAX_TASKID)
		return E_ID;

	if (xnpod_primary_p() && tskid == ui_current_task()->id)
		return E_OBJ;

	xnlock_get_irqsave(&nklock, s);

	task = xnmap_fetch(ui_task_idmap, tskid);

	if (!task) {
		err = E_NOEXS;
		goto unlock_and_exit;
	}

	if (xnthread_test_state(&task->threadbase, XNDORMANT)) {
		err = E_OBJ;
		goto unlock_and_exit;
	}

	xnthread_set_info(&task->threadbase, uITRON_TASK_RLWAIT);
	xnpod_unblock_thread(&task->threadbase);
	xnpod_schedule();

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

ER get_tid(ID *p_tskid)
{
	if (!xnpod_primary_p())
		*p_tskid = FALSE;
	else
		*p_tskid = ui_current_task()->id;

	return E_OK;
}

ER ref_tsk(T_RTSK *pk_rtsk, ID tskid)
{
	UINT tskstat = 0;
	uitask_t *task;
	spl_t s;

	if (tskid == TSK_SELF) {
		if (!xnpod_primary_p())
			return E_ID;

		task = ui_current_task();
		xnlock_get_irqsave(&nklock, s);
	} else {
		if (tskid <= 0 || tskid > uITRON_MAX_TASKID)
			return E_ID;

		xnlock_get_irqsave(&nklock, s);

		task = xnmap_fetch(ui_task_idmap, tskid);

		if (!task) {
			xnlock_put_irqrestore(&nklock, s);
			return E_NOEXS;
		}
	}

	if (task == ui_current_task())
		tskstat |= TTS_RUN;
	else if (xnthread_test_state(&task->threadbase, XNDORMANT))
		tskstat |= TTS_DMT;
	else if (xnthread_test_state(&task->threadbase, XNREADY))
		tskstat |= TTS_RDY;
	else {
		if (xnthread_test_state(&task->threadbase, XNPEND))
			tskstat |= TTS_WAI;
		if (xnthread_test_state(&task->threadbase, XNSUSP))
			tskstat |= TTS_SUS;
	}

	pk_rtsk->exinf = task->exinf;
	pk_rtsk->tskpri = ui_denormalized_prio(xnthread_current_priority(&task->threadbase));
	pk_rtsk->tskstat = tskstat;
	pk_rtsk->suscnt = task->suspcnt;
	pk_rtsk->wupcnt = task->wkupcnt;
	pk_rtsk->tskwait = testbits(tskstat, TTS_WAI) ? task->waitinfo : 0;
	pk_rtsk->wid = 0;	/* FIXME */
	pk_rtsk->tskatr = task->tskatr;
	pk_rtsk->task = task->entry;
	pk_rtsk->itskpri = ui_denormalized_prio(xnthread_initial_priority(&task->threadbase));
	pk_rtsk->stksz = (INT)xnthread_stack_size(&task->threadbase);

	xnlock_put_irqrestore(&nklock, s);

	return E_OK;
}

ER sus_tsk(ID tskid)
{
	uitask_t *task;
	ER err = E_OK;
	spl_t s;

	if (xnpod_unblockable_p())
		return EN_CTXID;

	if (tskid <= 0 || tskid > uITRON_MAX_TASKID)
		return E_ID;

	if (tskid == ui_current_task()->id)
		return E_OBJ;

	xnlock_get_irqsave(&nklock, s);

	task = xnmap_fetch(ui_task_idmap, tskid);

	if (!task) {
		err = E_NOEXS;
		goto unlock_and_exit;
	}

	if (xnthread_test_state(&task->threadbase, XNDORMANT)) {
		err = E_OBJ;
		goto unlock_and_exit;
	}

	if (task->suspcnt >= 0x7fffffff) {
		err = E_QOVR;
		goto unlock_and_exit;
	}

	if (task->suspcnt++ == 0)
		xnpod_suspend_thread(&task->threadbase,
				     XNSUSP, XN_INFINITE, XN_RELATIVE, NULL);

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

static ER rsm_tsk_helper(ID tskid, int force)
{
	uitask_t *task;
	ER err = E_OK;
	spl_t s;

	if (xnpod_asynch_p())
		return EN_CTXID;

	if (tskid <= 0 || tskid > uITRON_MAX_TASKID)
		return E_ID;

	if (xnpod_primary_p() && tskid == ui_current_task()->id)
		return E_OBJ;

	xnlock_get_irqsave(&nklock, s);

	task = xnmap_fetch(ui_task_idmap, tskid);

	if (!task) {
		err = E_NOEXS;
		goto unlock_and_exit;
	}

	if (task->suspcnt == 0 ||
	    xnthread_test_state(&task->threadbase, XNDORMANT)) {
		err = E_OBJ;
		goto unlock_and_exit;
	}

	if (force || --task->suspcnt == 0) {
		task->suspcnt = 0;
		xnpod_resume_thread(&task->threadbase, XNSUSP);
		xnpod_schedule();
	}

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

ER rsm_tsk(ID tskid)
{
	return rsm_tsk_helper(tskid, 0);
}

ER frsm_tsk(ID tskid)
{
	return rsm_tsk_helper(tskid, 1);
}

ER slp_tsk(void)
{
	uitask_t *task;
	ER err = E_OK;
	spl_t s;

	if (xnpod_unblockable_p())
		return E_CTX;

	task = ui_current_task();

	xnlock_get_irqsave(&nklock, s);

	if (task->wkupcnt > 0) {
		task->wkupcnt--;
		goto unlock_and_exit;
	}

	xnthread_set_info(&task->threadbase, uITRON_TASK_SLEEP);

	xnthread_clear_info(&task->threadbase, uITRON_TASK_RLWAIT);

	xnpod_suspend_thread(&task->threadbase, XNDELAY, XN_INFINITE, XN_RELATIVE, NULL);

	xnthread_clear_info(&task->threadbase, uITRON_TASK_SLEEP);

	if (xnthread_test_info(&task->threadbase, XNBREAK))
		err = E_RLWAI;

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

ER tslp_tsk(TMO tmout)
{
	uitask_t *task;
	ER err = E_OK;
	spl_t s;

	if (xnpod_unblockable_p())
		return E_CTX;

	if (tmout == 0)
		return E_TMOUT;

	if (tmout < TMO_FEVR)
		return E_PAR;

	task = ui_current_task();

	xnlock_get_irqsave(&nklock, s);

	if (task->wkupcnt > 0) {
		task->wkupcnt--;
		goto unlock_and_exit;
	}

	if (tmout == TMO_FEVR)
		tmout = XN_INFINITE;

	xnthread_set_info(&task->threadbase, uITRON_TASK_SLEEP);

	xnthread_clear_info(&task->threadbase, uITRON_TASK_RLWAIT);

	xnpod_suspend_thread(&task->threadbase, XNDELAY, tmout, XN_RELATIVE, NULL);

	xnthread_clear_info(&task->threadbase, uITRON_TASK_SLEEP);

	if (xnthread_test_info(&task->threadbase, XNBREAK))
		err = E_RLWAI;
	else if (xnthread_test_info(&task->threadbase, XNTIMEO))
		err = E_TMOUT;

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

ER wup_tsk(ID tskid)
{
	uitask_t *task;
	ER err = E_OK;
	spl_t s;

	if (xnpod_asynch_p())
		return EN_CTXID;

	if (tskid <= 0 || tskid > uITRON_MAX_TASKID)
		return E_ID;

	if (xnpod_primary_p() && tskid == ui_current_task()->id)
		return E_OBJ;

	xnlock_get_irqsave(&nklock, s);

	task = xnmap_fetch(ui_task_idmap, tskid);

	if (!task) {
		err = E_NOEXS;
		goto unlock_and_exit;
	}

	if (xnthread_test_state(&task->threadbase, XNDORMANT)) {
		err = E_OBJ;
		goto unlock_and_exit;
	}

	if (!xnthread_test_info(&task->threadbase, uITRON_TASK_SLEEP)) {
		if (task->wkupcnt >= 0x7fffffff) {
			err = E_QOVR;
			goto unlock_and_exit;
		}
		task->wkupcnt++;
	} else {
		xnpod_resume_thread(&task->threadbase, XNDELAY);
		xnpod_schedule();
	}

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

ER can_wup(INT *p_wupcnt, ID tskid)
{
	uitask_t *task;
	ER err = E_OK;
	spl_t s;

	if (tskid == TSK_SELF) {
		if (!xnpod_primary_p())
			return E_ID;

		task = ui_current_task();
		xnlock_get_irqsave(&nklock, s);
	} else {
		if (tskid <= 0 || tskid > uITRON_MAX_TASKID)
			return E_ID;

		xnlock_get_irqsave(&nklock, s);

		task = xnmap_fetch(ui_task_idmap, tskid);

		if (!task) {
			err = E_NOEXS;
			goto unlock_and_exit;
		}

		if (xnthread_test_state(&task->threadbase, XNDORMANT)) {
			err = E_OBJ;
			goto unlock_and_exit;
		}
	}

	*p_wupcnt = task->wkupcnt;
	task->wkupcnt = 0;

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

EXPORT_SYMBOL(cre_tsk);
EXPORT_SYMBOL(del_tsk);
EXPORT_SYMBOL(sta_tsk);
EXPORT_SYMBOL(ext_tsk);
EXPORT_SYMBOL(exd_tsk);
EXPORT_SYMBOL(ter_tsk);
EXPORT_SYMBOL(dis_dsp);
EXPORT_SYMBOL(ena_dsp);
EXPORT_SYMBOL(chg_pri);
EXPORT_SYMBOL(rot_rdq);
EXPORT_SYMBOL(rel_wai);
EXPORT_SYMBOL(get_tid);
EXPORT_SYMBOL(ref_tsk);
EXPORT_SYMBOL(sus_tsk);
EXPORT_SYMBOL(rsm_tsk);
EXPORT_SYMBOL(frsm_tsk);
EXPORT_SYMBOL(slp_tsk);
EXPORT_SYMBOL(tslp_tsk);
EXPORT_SYMBOL(wup_tsk);
EXPORT_SYMBOL(can_wup);
