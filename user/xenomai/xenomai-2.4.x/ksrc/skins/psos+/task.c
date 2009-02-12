/*
 * Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
 *
 * Xenomai is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <nucleus/registry.h>
#include <psos+/task.h>
#include <psos+/tm.h>

static xnqueue_t psostaskq;

static u_long psos_time_slice;

static u_long psos_task_ids;

static unsigned psos_get_magic(void)
{
	return PSOS_SKIN_MAGIC;
}

static xnthrops_t psos_task_ops = {
	.get_magic = &psos_get_magic,
};

static void psostask_delete_hook(xnthread_t *thread)
{
	/* The scheduler is locked while hooks are running */
	psostask_t *task;
	psostm_t *tm;

	if (xnthread_get_magic(thread) != PSOS_SKIN_MAGIC)
		return;

#ifdef CONFIG_XENO_OPT_REGISTRY
	if (xnthread_handle(thread) != XN_NO_HANDLE)
		xnregistry_remove(xnthread_handle(thread));
#endif /* CONFIG_XENO_OPT_REGISTRY */

	task = thread2psostask(thread);

	removeq(&psostaskq, &task->link);

	while ((tm = (psostm_t *)getgq(&task->alarmq)) != NULL)
		tm_destroy_internal(tm);

	taskev_destroy(&task->evgroup);
	xnarch_delete_display(&task->threadbase);
	psos_mark_deleted(task);

	xnheap_schedule_free(&kheap, task, &task->link);
}

void psostask_init(u_long rrperiod)
{
	initq(&psostaskq);
	psos_time_slice = rrperiod;
	xnpod_add_hook(XNHOOK_THREAD_DELETE, psostask_delete_hook);
}

void psostask_cleanup(void)
{
	xnholder_t *holder;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	while ((holder = getheadq(&psostaskq)) != NULL) {
		psostask_t *task = link2psostask(holder);
		xnpod_abort_thread(&task->threadbase);
		xnlock_sync_irq(&nklock, s);
	}

	xnlock_put_irqrestore(&nklock, s);

	xnpod_remove_hook(XNHOOK_THREAD_DELETE, psostask_delete_hook);
}

u_long t_create(const char *name,
		u_long prio,
		u_long sstack, u_long ustack, u_long flags, u_long *tid_r)
{
	xnflags_t bflags = 0;
	psostask_t *task;
	spl_t s;
	int n;

	/* Xenomai extension: we accept priority level #0 for creating
	   non-RT tasks (i.e. underlaid by SCHED_NORMAL pthreads),
	   which are allowed to call into the pSOS emulator, usually
	   for synchronization services. */

	if (prio > 255)
		return ERR_PRIOR;

	task = (psostask_t *)xnmalloc(sizeof(*task));

	if (!task)
		return ERR_NOTCB;

	if (flags & T_FPU)
		bflags |= XNFPU;

#ifdef CONFIG_XENO_OPT_PERVASIVE
	if (flags & T_SHADOW)
		bflags |= XNSHADOW;
#endif /* CONFIG_XENO_OPT_PERVASIVE */

	ustack += sstack;

	if (!(flags & T_SHADOW) && ustack < 1024) {
		xnfree(task);
		return ERR_TINYSTK;
	}

	if (name && *name)
		xnobject_copy_name(task->name, name);
	else
		/* i.e. Anonymous object which must be accessible from
		   user-space. */
		sprintf(task->name, "anon_task%lu", psos_task_ids++);

	if (xnpod_init_thread(&task->threadbase, psos_tbase,
			      task->name, prio, bflags, ustack, &psos_task_ops) != 0) {
		xnfree(task);
		return ERR_NOSTK;	/* Assume this is the only possible failure */
	}

	xnthread_time_slice(&task->threadbase) = psos_time_slice;

	taskev_init(&task->evgroup);
	inith(&task->link);

	for (n = 0; n < PSOSTASK_NOTEPAD_REGS; n++)
		task->notepad[n] = 0;

	initgq(&task->alarmq,
	       &xnmod_glink_queue,
	       xnmod_alloc_glinks,
	       XNMOD_GHOLDER_THRESHOLD);

	task->magic = PSOS_TASK_MAGIC;

	xnlock_get_irqsave(&nklock, s);
	appendq(&psostaskq, &task->link);
	*tid_r = (u_long)task;
	xnlock_put_irqrestore(&nklock, s);

#ifdef CONFIG_XENO_OPT_REGISTRY
	{
		u_long err = xnregistry_enter(task->name,
					      task, &xnthread_handle(&task->threadbase), NULL);
		if (err) {
			t_delete((u_long)task);
			return err;
		}
	}
#endif /* CONFIG_XENO_OPT_REGISTRY */

	xnarch_create_display(&task->threadbase, task->name, psostask);

	return SUCCESS;
}

static void psostask_trampoline(void *cookie)
{

	psostask_t *task = (psostask_t *)cookie;
	task->entry(task->args[0], task->args[1], task->args[2], task->args[3]);
	t_delete(0);
}

u_long t_start(u_long tid,
	       u_long mode,
	       void (*startaddr) (u_long, u_long, u_long, u_long),
	       u_long targs[])
{
	u_long err = SUCCESS;
	xnflags_t xnmode;
	psostask_t *task;
	spl_t s;
	int n;

	/* We have no error case here: just clear out any unwanted bit. */
	mode &= ~T_START_MASK;

	xnlock_get_irqsave(&nklock, s);

	task = psos_h2obj_active(tid, PSOS_TASK_MAGIC, psostask_t);

	if (!task) {
		err = psos_handle_error(tid, PSOS_TASK_MAGIC, psostask_t);
		goto unlock_and_exit;
	}

	if (!xnthread_test_state(&task->threadbase, XNDORMANT)) {
		err = ERR_ACTIVE;	/* Task already started */
		goto unlock_and_exit;
	}

	xnmode = psos_mode_to_xeno(mode);

	task->entry = startaddr;

#ifdef CONFIG_XENO_OPT_PERVASIVE
	if (xnthread_test_state(&task->threadbase, XNSHADOW)) {
		memset(task->args, 0, sizeof(task->args));
		/* The shadow will be returned the exact values passed
		 * to t_start(), since the trampoline is performed at
		 * user-space level. We just relay the information
		 * from t_create() to t_start() here.*/
		xnpod_start_thread(&task->threadbase,
				   xnmode,
				   (int)((mode >> 8) & 0x7),
				   XNPOD_ALL_CPUS, (void (*)(void *))startaddr, targs);
	}
	else
#endif /* CONFIG_XENO_OPT_PERVASIVE */
	{
		for (n = 0; n < 4; n++)
			task->args[n] = targs ? targs[n] : 0;

		xnpod_start_thread(&task->threadbase,
				   xnmode,
				   (int)((mode >> 8) & 0x7),
				   XNPOD_ALL_CPUS, &psostask_trampoline, task);
	}

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

u_long t_restart(u_long tid, u_long targs[])
{
	u_long err = SUCCESS;
	psostask_t *task;
	spl_t s;
	int n;

	if (xnpod_unblockable_p())
		return -EPERM;

	xnlock_get_irqsave(&nklock, s);

	if (tid == 0)
		task = psos_current_task();
	else {
		task = psos_h2obj_active(tid, PSOS_TASK_MAGIC, psostask_t);

		if (!task) {
			err = psos_handle_error(tid, PSOS_TASK_MAGIC, psostask_t);
			goto unlock_and_exit;
		}

		if (xnthread_test_state(&task->threadbase, XNDORMANT)) {
			err = ERR_NACTIVE;
			goto unlock_and_exit;
		}
	}

	for (n = 0; n < 4; n++)
		task->args[n] = targs ? targs[n] : 0;

	xnpod_restart_thread(&task->threadbase);

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

u_long t_delete(u_long tid)
{
	u_long err = SUCCESS;
	psostask_t *task;
	spl_t s;

	if (tid == 0)
		xnpod_delete_self();	/* Never returns */

	xnlock_get_irqsave(&nklock, s);

	task = psos_h2obj_active(tid, PSOS_TASK_MAGIC, psostask_t);

	if (!task) {
		err = psos_handle_error(tid, PSOS_TASK_MAGIC, psostask_t);
		goto unlock_and_exit;
	}

	xnpod_delete_thread(&task->threadbase);

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

u_long t_ident(const char *name, u_long node, u_long *tid_r)
{
	u_long err = SUCCESS;
	xnholder_t *holder;
	psostask_t *task;
	spl_t s;

	if (node > 1)
		return ERR_NODENO;

	if (!name) {
		if (xnpod_unblockable_p())
			return ERR_OBJID;
		*tid_r = (u_long)psos_current_task();
		return SUCCESS;
	}

	xnlock_get_irqsave(&nklock, s);

	for (holder = getheadq(&psostaskq);
	     holder; holder = nextq(&psostaskq, holder)) {
		task = link2psostask(holder);

		if (!strcmp(task->name, name)) {
			*tid_r = (u_long)task;
			goto unlock_and_exit;
		}
	}

	err = ERR_OBJNF;

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

u_long t_mode(u_long mask, u_long newmask, u_long *oldmode)
{
	psostask_t *task;

	if (!xnpod_primary_p())
		return -EPERM;

	task = psos_current_task();

	/* We have no error case here: just clear out any unwanted bit. */
	mask &= T_MODE_MASK;
	newmask &= T_MODE_MASK;
	if (mask == 0) {
		*oldmode = xeno_mode_to_psos(xnthread_state_flags(&task->threadbase) & XNTHREAD_MODE_BITS);
		*oldmode |= ((task->threadbase.imask & 0x7) << 8);
		return SUCCESS;
	}

	*oldmode =
		xeno_mode_to_psos(xnpod_set_thread_mode
				  (&task->threadbase,
				   psos_mode_to_xeno(mask),
				   psos_mode_to_xeno(newmask)));
	*oldmode |= ((task->threadbase.imask & 0x7) << 8);

	/* Reschedule in case the scheduler has been unlocked. */
	xnpod_schedule();

	return SUCCESS;
}

u_long t_getreg(u_long tid, u_long regnum, u_long *regvalue)
{
	u_long err = SUCCESS;
	psostask_t *task;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (tid == 0)
		task = psos_current_task();
	else {
		task = psos_h2obj_active(tid, PSOS_TASK_MAGIC, psostask_t);

		if (!task) {
			err = psos_handle_error(tid, PSOS_TASK_MAGIC, psostask_t);
			goto unlock_and_exit;
		}
	}

	if (regnum >= PSOSTASK_NOTEPAD_REGS) {
		err = ERR_REGNUM;
		goto unlock_and_exit;
	}

	*regvalue = task->notepad[regnum];

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

u_long t_resume(u_long tid)
{
	u_long err = SUCCESS;
	psostask_t *task;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (tid == 0) {
		if (xnpod_unblockable_p()) {
			err = -EPERM;
			goto unlock_and_exit;
		}

		/* Would be admittedly silly, but silly code does
		 * exist, and it's a matter of returning ERR_NOTSUSP
		 * instead of ERR_OBJID. */
		task = psos_current_task();
	}
	else {
		task = psos_h2obj_active(tid, PSOS_TASK_MAGIC, psostask_t);

		if (!task) {
			err = psos_handle_error(tid, PSOS_TASK_MAGIC, psostask_t);
			goto unlock_and_exit;
		}
	}

	if (!xnthread_test_state(&task->threadbase, XNSUSP)) {
		err = ERR_NOTSUSP;	/* Task not suspended. */
		goto unlock_and_exit;
	}

	xnpod_resume_thread(&task->threadbase, XNSUSP);
	xnpod_schedule();

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

u_long t_suspend(u_long tid)
{
	u_long err = SUCCESS;
	psostask_t *task;
	spl_t s;

	if (tid == 0) {
		if (xnpod_unblockable_p())
			return -EPERM;

		xnpod_suspend_self();

		if (xnthread_test_info(&psos_current_task()->threadbase, XNBREAK))
			return -EINTR;

		return SUCCESS;
	}

	xnlock_get_irqsave(&nklock, s);

	task = psos_h2obj_active(tid, PSOS_TASK_MAGIC, psostask_t);

	if (!task) {
		err = psos_handle_error(tid, PSOS_TASK_MAGIC, psostask_t);
		goto unlock_and_exit;
	}

	if (xnthread_test_state(&task->threadbase, XNSUSP)) {
		err = ERR_SUSP;	/* Task already suspended. */
		goto unlock_and_exit;
	}

	xnpod_suspend_thread(&task->threadbase, XNSUSP, XN_INFINITE, XN_RELATIVE, NULL);

	if (xnthread_test_info(&task->threadbase, XNBREAK))
		err = -EINTR;

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

u_long t_setpri(u_long tid, u_long newprio, u_long *oldprio)
{
	u_long err = SUCCESS;
	psostask_t *task;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (tid == 0) {
		if (xnpod_unblockable_p())
			return -EPERM;
		task = psos_current_task();
	}
	else {
		task = psos_h2obj_active(tid, PSOS_TASK_MAGIC, psostask_t);

		if (!task) {
			err =
				psos_handle_error(tid, PSOS_TASK_MAGIC, psostask_t);
			goto unlock_and_exit;
		}
	}

	*oldprio = xnthread_current_priority(&task->threadbase);

	if (newprio != 0) {
		if (newprio < 1 || newprio > 255) {
			err = ERR_SETPRI;
			goto unlock_and_exit;
		}

		if (newprio != *oldprio) {
			xnpod_renice_thread(&task->threadbase, newprio);
			xnpod_schedule();
		}
	}

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

u_long t_setreg(u_long tid, u_long regnum, u_long regvalue)
{
	u_long err = SUCCESS;
	psostask_t *task;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (tid == 0) {
		if (!xnpod_primary_p())
			return -EPERM;

		task = psos_current_task();
	}
	else {
		task = psos_h2obj_active(tid, PSOS_TASK_MAGIC, psostask_t);

		if (!task) {
			err = psos_handle_error(tid, PSOS_TASK_MAGIC, psostask_t);
			goto unlock_and_exit;
		}
	}

	if (regnum >= PSOSTASK_NOTEPAD_REGS) {
		err = ERR_REGNUM;
		goto unlock_and_exit;
	}

	task->notepad[regnum] = regvalue;

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/*
 * IMPLEMENTATION NOTES:
 *
 * - Code executing on behalf of interrupt context is currently not
 * allowed to scan/alter the global psos task queue (psostaskq).
 */
