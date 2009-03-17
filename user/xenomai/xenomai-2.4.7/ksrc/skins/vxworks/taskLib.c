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

#define WIND_MAX_PRIORITIES 255

static xnqueue_t wind_tasks_q;
static unsigned long task_ids;
static xnticks_t rrperiod;

static int testSafe(wind_task_t *task);
static void wind_task_delete_hook(xnthread_t *xnthread);
static void wind_task_trampoline(void *cookie);

static int wind_task_get_denormalized_prio(xnthread_t *thread, int coreprio)
{
	return wind_denormalized_prio(coreprio);
}

static unsigned wind_task_get_magic(void)
{
	return VXWORKS_SKIN_MAGIC;
}

static xnthrops_t windtask_ops = {
	.get_denormalized_prio = &wind_task_get_denormalized_prio,
	.get_magic = &wind_task_get_magic,
};

void wind_task_init(void)
{
	initq(&wind_tasks_q);
	xnpod_add_hook(XNHOOK_THREAD_DELETE, wind_task_delete_hook);
}

void wind_task_cleanup(void)
{
	xnholder_t *holder;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	while ((holder = getheadq(&wind_tasks_q)) != NULL) {
		WIND_TCB *pTcb = link2wind_task(holder);
		xnpod_abort_thread(&pTcb->threadbase);
		xnlock_sync_irq(&nklock, s);
	}

	xnlock_put_irqrestore(&nklock, s);

	xnpod_remove_hook(XNHOOK_THREAD_DELETE, wind_task_delete_hook);
}

void wind_set_rrperiod(xnticks_t ticks)
{
	rrperiod = ticks;
}

STATUS taskInit(WIND_TCB *pTcb,
		const char *name,
		int prio,
		int flags,
		char *stack __attribute__ ((unused)),
		int stacksize,
		FUNCPTR entry,
		long arg0, long arg1, long arg2, long arg3, long arg4,
		long arg5, long arg6, long arg7, long arg8, long arg9)
{
	xnflags_t bflags = 0;
	spl_t s;

	check_NOT_ISR_CALLABLE(return ERROR);

	if (prio < 0 || prio > WIND_MAX_PRIORITIES) {
		wind_errnoset(S_taskLib_ILLEGAL_PRIORITY);
		return ERROR;
	}

	/* We forbid to use twice the same tcb */
	if (!pTcb || pTcb->magic == WIND_TASK_MAGIC) {
		wind_errnoset(S_objLib_OBJ_ID_ERROR);
		return ERROR;
	}

	/* VxWorks does not check for invalid option flags, so we
	   neither. */

#ifdef CONFIG_XENO_OPT_PERVASIVE
 	/* Caller should fill in this field whenever applicable. */
 	pTcb->ptid = 0;
	if (flags & VX_SHADOW)
		bflags |= XNSHADOW;
#else /* !CONFIG_XENO_OPT_PERVASIVE */
	if (stacksize < 1024)
		return ERROR;
#endif /* CONFIG_XENO_OPT_PERVASIVE */

	if (flags & VX_FP_TASK)
		bflags |= XNFPU;

	/*  not implemented: VX_PRIVATE_ENV, VX_NO_STACK_FILL, VX_UNBREAKABLE */

	pTcb->flow_id = task_ids++;

	if (name && *name)
		xnobject_copy_name(pTcb->name, name);
	else
		/* i.e. Anonymous object which must be accessible from
		   user-space. */
		sprintf(pTcb->name, "t%lu", pTcb->flow_id);

	if (xnpod_init_thread(&pTcb->threadbase,
			      wind_tbase,
			      pTcb->name,
			      wind_normalized_prio(prio), bflags,
			      stacksize, &windtask_ops) != 0) {
		/* Assume this is the only possible failure. */
		wind_errnoset(S_memLib_NOT_ENOUGH_MEMORY);
		return ERROR;
	}

	/* finally set the Tcb after error conditions checking */
	pTcb->magic = WIND_TASK_MAGIC;
	pTcb->flags = flags & ~VX_SHADOW;
	pTcb->prio = prio;
	pTcb->entry = entry;

	xnthread_time_slice(&pTcb->threadbase) = rrperiod;

	pTcb->safecnt = 0;
	xnsynch_init(&pTcb->safesync, 0);

	/* TODO: fill in attributes of wind_task_t:
	   pTcb->status
	 */

	pTcb->auto_delete = 0;
	inith(&pTcb->link);

	pTcb->arg0 = arg0;
	pTcb->arg1 = arg1;
	pTcb->arg2 = arg2;
	pTcb->arg3 = arg3;
	pTcb->arg4 = arg4;
	pTcb->arg5 = arg5;
	pTcb->arg6 = arg6;
	pTcb->arg7 = arg7;
	pTcb->arg8 = arg8;
	pTcb->arg9 = arg9;

	xnlock_get_irqsave(&nklock, s);
	appendq(&wind_tasks_q, &pTcb->link);
	xnlock_put_irqrestore(&nklock, s);

#ifdef CONFIG_XENO_OPT_REGISTRY
	if (xnregistry_enter(pTcb->name,
			     pTcb, &xnthread_handle(&pTcb->threadbase), NULL)) {
		wind_errnoset(S_objLib_OBJ_ID_ERROR);
		taskDeleteForce((TASK_ID) pTcb);
		return ERROR;
	}
#endif /* CONFIG_XENO_OPT_REGISTRY */

	return OK;
}

STATUS taskActivate(TASK_ID task_id)
{
	wind_task_t *task;
	spl_t s;

	if (task_id == 0)
		return ERROR;

	xnlock_get_irqsave(&nklock, s);

	check_OBJ_ID_ERROR(task_id, wind_task_t, task, WIND_TASK_MAGIC,
			   goto error);

	if (!xnthread_test_state(&(task->threadbase), XNDORMANT))
		goto error;

	xnpod_start_thread(&task->threadbase, XNRRB, 0,
			   XNPOD_ALL_CPUS, wind_task_trampoline, task);

	xnlock_put_irqrestore(&nklock, s);

	return OK;

      error:
	xnlock_put_irqrestore(&nklock, s);
	return ERROR;

}

TASK_ID taskSpawn(const char *name,
		  int prio,
		  int flags,
		  int stacksize,
		  FUNCPTR entry,
		  long arg0, long arg1, long arg2, long arg3, long arg4,
		  long arg5, long arg6, long arg7, long arg8, long arg9)
{
	wind_task_t *task;
	TASK_ID task_id;
	STATUS status;

	check_NOT_ISR_CALLABLE(return ERROR);

	check_alloc(wind_task_t, task, return ERROR);
	task_id = (TASK_ID) task;

	status = taskInit(task,
			  name,
			  prio,
			  flags,
			  NULL,
			  stacksize,
			  entry,
			  arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
			  arg9);

	if (status == ERROR)
		return ERROR;

	task->auto_delete = 1;
	status = taskActivate(task_id);

	if (status == ERROR) {
		taskDeleteForce(task_id);
		return ERROR;
	}

	return task_id;
}

STATUS taskDeleteForce(TASK_ID task_id)
{
	wind_task_t *task;
	spl_t s;

	check_NOT_ISR_CALLABLE(return ERROR);

	if (task_id == 0)
		xnpod_delete_self();	/* Never returns */

	xnlock_get_irqsave(&nklock, s);
	check_OBJ_ID_ERROR(task_id, wind_task_t, task, WIND_TASK_MAGIC,
			   goto error);
	xnpod_delete_thread(&task->threadbase);
	xnlock_put_irqrestore(&nklock, s);

	return OK;

      error:
	xnlock_put_irqrestore(&nklock, s);
	return ERROR;
}

STATUS taskDelete(TASK_ID task_id)
{
	wind_task_t *task;
	unsigned long int flow_id;
	spl_t s;

	check_NOT_ISR_CALLABLE(return ERROR);

	if (task_id == 0)
		xnpod_delete_self();

	xnlock_get_irqsave(&nklock, s);

	check_OBJ_ID_ERROR(task_id, wind_task_t, task, WIND_TASK_MAGIC,
			   goto error);
	flow_id = task->flow_id;

	if (testSafe(task) == ERROR)
		goto error;

	/* we use flow_id here just in case task was destroyed and the block
	   reused for another task by the allocator */
	if (!wind_h2obj_active(task, WIND_TASK_MAGIC, wind_task_t)
	    || task->flow_id != flow_id) {
		wind_errnoset(S_objLib_OBJ_DELETED);
		goto error;
	}

	xnpod_delete_thread(&task->threadbase);
	xnlock_put_irqrestore(&nklock, s);

	return OK;

      error:
	xnlock_put_irqrestore(&nklock, s);
	return ERROR;
}

void taskExit(int code)
{
	if (xnpod_interrupt_p())
		return;

	wind_errnoset(code);
	xnpod_delete_self();
}

STATUS taskSuspend(TASK_ID task_id)
{
	wind_task_t *task;
	spl_t s;

	if (task_id == 0) {
		xnpod_suspend_self();
		error_check(xnthread_test_info
			    (&wind_current_task()->threadbase, XNBREAK), -EINTR,
			    return ERROR);
		return OK;
	}

	xnlock_get_irqsave(&nklock, s);

	check_OBJ_ID_ERROR(task_id, wind_task_t, task, WIND_TASK_MAGIC,
			   goto error);

	xnpod_suspend_thread(&task->threadbase, XNSUSP, XN_INFINITE, XN_RELATIVE, NULL);

	error_check(xnthread_test_info(&task->threadbase, XNBREAK), -EINTR,
		    goto error);

	xnlock_put_irqrestore(&nklock, s);

	return OK;

      error:
	xnlock_put_irqrestore(&nklock, s);
	return ERROR;
}

STATUS taskResume(TASK_ID task_id)
{
	wind_task_t *task;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	check_OBJ_ID_ERROR(task_id, wind_task_t, task, WIND_TASK_MAGIC,
			   goto error);

	xnpod_resume_thread(&task->threadbase, XNSUSP);

	xnpod_schedule();

	xnlock_put_irqrestore(&nklock, s);
	return OK;

      error:
	xnlock_put_irqrestore(&nklock, s);
	return ERROR;
}

STATUS taskRestart(TASK_ID task_id)
{
	wind_task_t *task;
	spl_t s;

	check_NOT_ISR_CALLABLE(return ERROR);

	xnlock_get_irqsave(&nklock, s);

	if (task_id == 0)
		task = wind_current_task();
	else
		check_OBJ_ID_ERROR(task_id, wind_task_t, task, WIND_TASK_MAGIC,
				   goto error);

	xnpod_restart_thread(&task->threadbase);

	xnlock_put_irqrestore(&nklock, s);
	return OK;

      error:
	xnlock_put_irqrestore(&nklock, s);
	return ERROR;
}

STATUS taskPrioritySet(TASK_ID task_id, int prio)
{
	wind_task_t *task;
	spl_t s;

	if (prio < 0 || prio > WIND_MAX_PRIORITIES) {
		wind_errnoset(S_taskLib_ILLEGAL_PRIORITY);
		return ERROR;
	}

	xnlock_get_irqsave(&nklock, s);

	if (task_id == 0)
		task = wind_current_task();
	else
		check_OBJ_ID_ERROR(task_id, wind_task_t, task, WIND_TASK_MAGIC,
				   goto error);

	xnpod_renice_thread(&task->threadbase, wind_normalized_prio(prio));
	task->prio = prio;

	xnpod_schedule();

	xnlock_put_irqrestore(&nklock, s);
	return OK;

      error:
	xnlock_put_irqrestore(&nklock, s);
	return ERROR;
}

STATUS taskPriorityGet(TASK_ID task_id, int *pprio)
{
	wind_task_t *task;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (task_id == 0)
		task = wind_current_task();
	else
		check_OBJ_ID_ERROR(task_id, wind_task_t, task, WIND_TASK_MAGIC,
				   goto error);

	*pprio =
	    wind_denormalized_prio(xnthread_current_priority
				   (&task->threadbase));

	xnlock_put_irqrestore(&nklock, s);
	return OK;

      error:
	xnlock_put_irqrestore(&nklock, s);
	return ERROR;
}

STATUS taskLock(void)
{
	check_NOT_ISR_CALLABLE(return ERROR);

	xnpod_lock_sched();

	return OK;
}

STATUS taskUnlock(void)
{
	check_NOT_ISR_CALLABLE(return ERROR);

	xnpod_unlock_sched();

	return OK;
}

TASK_ID taskIdSelf(void)
{
	check_NOT_ISR_CALLABLE(return ERROR);

	return (TASK_ID) wind_current_task();
}

STATUS taskSafe(void)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	taskSafeInner(xnpod_current_thread());
	xnlock_put_irqrestore(&nklock, s);

	return OK;
}

STATUS taskUnsafe(void)
{
	spl_t s;

	if (!xnpod_primary_p()) {
		wind_errnoset(-EPERM);
		return ERROR;
	}

	xnlock_get_irqsave(&nklock, s);

	if (taskUnsafeInner(xnpod_current_thread()))
		xnpod_schedule();

	xnlock_put_irqrestore(&nklock, s);

	return OK;
}

STATUS taskDelay(int ticks)
{
	check_NOT_ISR_CALLABLE(return ERROR);

	if (ticks > 0) {
		xnpod_delay(ticks);
		error_check(xnthread_test_info
			    (&wind_current_task()->threadbase, XNBREAK), -EINTR,
			    return ERROR);
	} else
		xnpod_yield();

	return OK;
}

STATUS taskIdVerify(TASK_ID task_id)
{
	wind_task_t *task;

	check_OBJ_ID_ERROR(task_id, wind_task_t, task, WIND_TASK_MAGIC,
			   return ERROR);

	return OK;
}

wind_task_t *taskTcb(TASK_ID task_id)
{
	wind_task_t *task;

	check_OBJ_ID_ERROR(task_id, wind_task_t, task, WIND_TASK_MAGIC,
			   return NULL);

	return task;
}

/* We put this function here and not in taskInfo.c because it needs access to
   wind_tasks_q */
TASK_ID taskNameToId(const char *name)
{
	TASK_ID result = (TASK_ID)ERROR;
	xnholder_t *holder;
	wind_task_t *task;
	spl_t s;

	if (!name)
		return ERROR;

	xnlock_get_irqsave(&nklock, s);

	for (holder = getheadq(&wind_tasks_q);
	     holder; holder = nextq(&wind_tasks_q, holder)) {
		task = link2wind_task(holder);
		if (!strcmp(name, task->name)) {
			result = (TASK_ID) task;
			break;
		}
	}

	if (result == ERROR)
		wind_errnoset(S_taskLib_NAME_NOT_FOUND);

	xnlock_put_irqrestore(&nklock, s);

	return result;
}

xnhandle_t taskNameToHandle(const char *name)
{
	xnhandle_t handle;
	wind_task_t *task;
	TASK_ID task_id;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	task_id = taskNameToId(name);
	if (task_id == ERROR) {
		handle = XN_NO_HANDLE;
		goto out;
	}
	task = (wind_task_t *)task_id;
	handle = xnthread_handle(&task->threadbase);
out:
	xnlock_put_irqrestore(&nklock, s);

	return handle;
}

/* nklock must be locked on entry, interrupts off */
static int testSafe(wind_task_t *task)
{
	while (task->safecnt > 0) {
		xnsynch_sleep_on(&task->safesync, XN_INFINITE, XN_RELATIVE);
		error_check(xnthread_test_info(&task->threadbase, XNBREAK),
			    -EINTR, return ERROR);
	}
	return OK;
}

static void wind_task_delete_hook(xnthread_t *thread)
{
	wind_task_t *task;

	if (xnthread_get_magic(thread) != VXWORKS_SKIN_MAGIC)
		return;

#ifdef CONFIG_XENO_OPT_REGISTRY
	if (xnthread_handle(thread) != XN_NO_HANDLE)
	    xnregistry_remove(xnthread_handle(thread));
#endif /* CONFIG_XENO_OPT_REGISTRY */

	task = thread2wind_task(thread);

	xnsynch_destroy(&task->safesync);

	removeq(&wind_tasks_q, &task->link);

	wind_mark_deleted(task);

	if (task->auto_delete)
		xnheap_schedule_free(&kheap, task, &task->link);
}

static void wind_task_trampoline(void *cookie)
{
	wind_task_t *task = (wind_task_t *)cookie;

	task->entry(task->arg0, task->arg1, task->arg2, task->arg3, task->arg4,
		    task->arg5, task->arg6, task->arg7, task->arg8, task->arg9);

	taskDeleteForce((TASK_ID) task);
}
