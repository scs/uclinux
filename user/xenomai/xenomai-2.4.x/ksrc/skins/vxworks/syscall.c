/**
 * @file
 * This file is part of the Xenomai project.
 *
 * @note Copyright (C) 2006,2007 Philippe Gerum <rpm@xenomai.org> 
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <nucleus/shadow.h>
#include <vxworks/defs.h>
#include <vxworks/syscall.h>

/*
 * By convention, error codes are passed back through the syscall
 * return value:
 * - negative codes stand for internal (i.e. nucleus) errors;
 * - strictly positive values stand for genuine VxWorks errors.
 * - zero means success.
 *
 * Object identifiers shared between kernel and user-space are always
 * registry handles, instead of direct memory addresses, for obvious
 * safety reasons.  Therefore, when resolving any VxWorks object
 * address passed by a user-space application to a skin service, we go
 * through the registry first, so that we are guaranteed to get back a
 * pointer to a known real-time object, at least. The skin routine
 * will eventually check for the magic number to make sure that we are
 * actually targeting a proper VxWorks object.
 */

int __wind_muxid;

static WIND_TCB *__wind_task_current(struct task_struct *curr)
{
	xnthread_t *thread = xnshadow_thread(curr);

	if (!thread || xnthread_get_magic(thread) != VXWORKS_SKIN_MAGIC)
		return NULL;

	return thread2wind_task(thread);	/* Convert TCB pointers. */
}

/*
 * int __wind_task_init(struct wind_arg_bulk *bulk,
 *                      WIND_TCB_PLACEHOLDER *ph,
 *                      xncompletion_t *completion)
 * bulk = {
 * a1: const char *name;
 * a2: int prio;
 * a3: int flags;
 * a4: pthread_self();
 * }
 */

static int __wind_task_init(struct task_struct *curr, struct pt_regs *regs)
{
	xncompletion_t __user *u_completion;
	char name[XNOBJECT_NAME_LEN];
	struct wind_arg_bulk bulk;
	int err = 0, prio, flags;
	WIND_TCB_PLACEHOLDER ph;
	WIND_TCB *task;

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg1(regs), sizeof(bulk)))
		return -EFAULT;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(ph)))
		return -EFAULT;

	__xn_copy_from_user(curr, &bulk, (void __user *)__xn_reg_arg1(regs),
			    sizeof(bulk));

	if (bulk.a1) {
		if (!__xn_access_ok(curr, VERIFY_READ, bulk.a1, sizeof(name)))
			return -EFAULT;

		__xn_strncpy_from_user(curr, name, (const char __user *)bulk.a1,
				       sizeof(name) - 1);
		name[sizeof(name) - 1] = '\0';
		strncpy(curr->comm, name, sizeof(curr->comm));
		curr->comm[sizeof(curr->comm) - 1] = '\0';
	} else
		*name = '\0';

	/* Task priority. */
	prio = bulk.a2;
	/* Task flags. */
	flags = bulk.a3 | VX_SHADOW;
	/* Completion descriptor our parent thread is pending on. */
	u_completion = (xncompletion_t __user *)__xn_reg_arg3(regs);

	task = (WIND_TCB *)xnmalloc(sizeof(*task));

	if (!task) {
		if (u_completion)
			xnshadow_signal_completion(u_completion, -ENOMEM);

		return -ENOMEM;
	}

	xnthread_clear_state(&task->threadbase, XNZOMBIE);

	/* Force FPU support in user-space. This will lead to a no-op if
	   the platform does not support it. */

	if (taskInit(task, name, prio, flags, NULL, 0, NULL,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0) == OK) {
		/* Let the skin discard the TCB memory upon exit. */
		task->auto_delete = 1;
		task->ptid = bulk.a4;
		/* Copy back the registry handle to the ph struct. */
		ph.handle = xnthread_handle(&task->threadbase);
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs), &ph,
				  sizeof(ph));
		err = xnshadow_map(&task->threadbase, u_completion);
	} else {
		/* Unblock and pass back error code. */

		err = wind_errnoget();

		if (u_completion)
			xnshadow_signal_completion(u_completion, err);
	}

	if (err && !xnthread_test_state(&task->threadbase, XNZOMBIE))
		xnfree(task);

	return err;
}

/*
 * int __wind_task_activate(TASK_ID task_id)
 */

static int __wind_task_activate(struct task_struct *curr, struct pt_regs *regs)
{
	WIND_TCB *pTcb = (WIND_TCB *)xnregistry_fetch(__xn_reg_arg1(regs));

	if (!pTcb)
		return S_objLib_OBJ_ID_ERROR;

	if (taskActivate((TASK_ID) pTcb) == ERROR)
		return wind_errnoget();

	return 0;
}

/*
 * int __wind_task_deleteforce(TASK_ID task_id)
 */

static int __wind_task_deleteforce(struct task_struct *curr,
				   struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	WIND_TCB *pTcb;

	if (handle)
		pTcb = (WIND_TCB *)xnregistry_fetch(handle);
	else
		pTcb = __wind_task_current(curr);

	if (!pTcb)
		return S_objLib_OBJ_ID_ERROR;

	if (taskDeleteForce((TASK_ID) pTcb) == ERROR)
		return wind_errnoget();

	return 0;
}

/*
 * int __wind_task_delete(TASK_ID task_id)
 */

static int __wind_task_delete(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	WIND_TCB *pTcb;

	if (handle)
		pTcb = (WIND_TCB *)xnregistry_fetch(handle);
	else
		pTcb = __wind_task_current(curr);

	if (!pTcb)
		return S_objLib_OBJ_ID_ERROR;

	if (taskDelete((TASK_ID) pTcb) == ERROR)
		return wind_errnoget();

	return 0;
}

/*
 * int __wind_task_suspend(TASK_ID task_id)
 */

static int __wind_task_suspend(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	WIND_TCB *pTcb;

	if (handle)
		pTcb = (WIND_TCB *)xnregistry_fetch(handle);
	else
		pTcb = __wind_task_current(curr);

	if (!pTcb)
		return S_objLib_OBJ_ID_ERROR;

	if (taskSuspend((TASK_ID) pTcb) == ERROR)
		return wind_errnoget();

	return 0;
}

/*
 * int __wind_task_resume(TASK_ID task_id)
 */

static int __wind_task_resume(struct task_struct *curr, struct pt_regs *regs)
{
	WIND_TCB *pTcb = (WIND_TCB *)xnregistry_fetch(__xn_reg_arg1(regs));

	if (!pTcb)
		return S_objLib_OBJ_ID_ERROR;

	if (taskResume((TASK_ID) pTcb) == ERROR)
		return wind_errnoget();

	return 0;
}

/*
 * int __wind_task_self(WIND_TCB *pTcb)
 */

static int __wind_task_self(struct task_struct *curr, struct pt_regs *regs)
{
	WIND_TCB_PLACEHOLDER ph;
	WIND_TCB *pTcb;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(ph)))
		return -EFAULT;

	pTcb = __wind_task_current(curr);

	if (!pTcb)
		/* Calls on behalf of a non-task context beget an error for
		   the user-space interface. */
		return S_objLib_OBJ_ID_ERROR;

	ph.handle = xnthread_handle(&pTcb->threadbase);	/* Copy back the task handle. */

	__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs), &ph,
			  sizeof(ph));

	return 0;
}

/*
 * int __wind_task_priorityset(TASK_ID task_id, int prio)
 */

static int __wind_task_priorityset(struct task_struct *curr,
				   struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	int prio = __xn_reg_arg2(regs);
	WIND_TCB *pTcb;

	if (handle)
		pTcb = (WIND_TCB *)xnregistry_fetch(handle);
	else
		pTcb = __wind_task_current(curr);

	if (!pTcb)
		return S_objLib_OBJ_ID_ERROR;

	if (taskPrioritySet((TASK_ID) pTcb, prio) == ERROR)
		return wind_errnoget();

	return 0;
}

/*
 * int __wind_task_priorityget(TASK_ID task_id, int *pprio)
 */

static int __wind_task_priorityget(struct task_struct *curr,
				   struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	WIND_TCB *pTcb;
	int prio;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(prio)))
		return -EFAULT;

	if (handle)
		pTcb = (WIND_TCB *)xnregistry_fetch(handle);
	else
		pTcb = __wind_task_current(curr);

	if (!pTcb)
		return S_objLib_OBJ_ID_ERROR;

	if (taskPriorityGet((TASK_ID) pTcb, &prio) == ERROR)
		return wind_errnoget();

	__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs), &prio,
			  sizeof(prio));

	return 0;
}

/*
 * int __wind_task_lock(void)
 */

static int __wind_task_lock(struct task_struct *curr, struct pt_regs *regs)
{
	taskLock();
	return 0;
}

/*
 * int __wind_task_unlock(void)
 */

static int __wind_task_unlock(struct task_struct *curr, struct pt_regs *regs)
{
	taskUnlock();
	return 0;
}

/*
 * int __wind_task_safe(void)
 */

static int __wind_task_safe(struct task_struct *curr, struct pt_regs *regs)
{
	taskSafe();
	return 0;
}

static int __wind_task_unsafe(struct task_struct *curr, struct pt_regs *regs)
{
	if (taskUnsafe() == ERROR)
		return wind_errnoget();

	return 0;
}

/*
 * int __wind_task_delay(int ticks)
 */

static int __wind_task_delay(struct task_struct *curr, struct pt_regs *regs)
{
	int ticks = __xn_reg_arg1(regs);

	if (taskDelay(ticks) == ERROR)
		return wind_errnoget();

	return 0;
}

/*
 * int __wind_task_verifyid(TASK_ID task_id)
 */

static int __wind_task_verifyid(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	WIND_TCB *pTcb;

	pTcb = (WIND_TCB *)xnregistry_fetch(handle);

	if (!pTcb)
		return S_objLib_OBJ_ID_ERROR;

	if (taskIdVerify((TASK_ID) pTcb) == ERROR)
		return wind_errnoget();

	return 0;
}

/*
 * int __wind_task_nametoid(const char *name, WIND_TCB *pTcb)
 */

static int __wind_task_nametoid(struct task_struct *curr, struct pt_regs *regs)
{
	char name[XNOBJECT_NAME_LEN];
	WIND_TCB_PLACEHOLDER ph;
	xnhandle_t handle;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(ph)))
		return -EFAULT;

	if (!__xn_reg_arg1(regs))
		return S_taskLib_NAME_NOT_FOUND;

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg1(regs), sizeof(name)))
		return -EFAULT;

	__xn_strncpy_from_user(curr, name,
			       (const char __user *)__xn_reg_arg1(regs),
			       sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';

	handle = taskNameToHandle(name);
	if (handle == XN_NO_HANDLE)
		return wind_errnoget();

	ph.handle = handle; /* Copy back the task handle. */

	__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs), &ph,
			  sizeof(ph));

	return 0;
}

/*
 * int __wind_task_setmode(int clrmask, int setmask, int *mode_r)
 */

static int __wind_task_setmode(struct task_struct *curr, struct pt_regs *regs)
{
	int setmask, clrmask, mode_r;

	clrmask = __xn_reg_arg1(regs);
	setmask = __xn_reg_arg2(regs);

	/* Primary required: current thread must be valid. */
	mode_r = xnpod_set_thread_mode(xnpod_current_thread(),
				       clrmask, setmask);
	if (__xn_reg_arg3(regs))
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg3(regs),
				  &mode_r, sizeof(mode_r));
	return 0;
}

/*
 * int __wind_sem_bcreate(int flags, SEM_B_STATE state, SEM_ID *psem_id)
 */

static int __wind_sem_bcreate(struct task_struct *curr, struct pt_regs *regs)
{
	SEM_B_STATE state;
	wind_sem_t *sem;
	SEM_ID sem_id;
	int flags;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg3(regs), sizeof(sem_id)))
		return -EFAULT;

	flags = __xn_reg_arg1(regs);
	state = __xn_reg_arg2(regs);
	sem = (wind_sem_t *)semBCreate(flags, state);

	if (!sem)
		return wind_errnoget();

	sem_id = sem->handle;
	__xn_copy_to_user(curr, (void __user *)__xn_reg_arg3(regs), &sem_id,
			  sizeof(sem_id));

	return 0;
}

/*
 * int __wind_sem_ccreate(int flags, int count, SEM_ID *psem_id)
 */

static int __wind_sem_ccreate(struct task_struct *curr, struct pt_regs *regs)
{
	int flags, count;
	wind_sem_t *sem;
	SEM_ID sem_id;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg3(regs), sizeof(sem_id)))
		return -EFAULT;

	flags = __xn_reg_arg1(regs);
	count = __xn_reg_arg2(regs);
	sem = (wind_sem_t *)semCCreate(flags, count);

	if (!sem)
		return wind_errnoget();

	sem_id = sem->handle;
	__xn_copy_to_user(curr, (void __user *)__xn_reg_arg3(regs), &sem_id,
			  sizeof(sem_id));

	return 0;
}

/*
 * int __wind_sem_mcreate(int flags, SEM_ID *psem_id)
 */

static int __wind_sem_mcreate(struct task_struct *curr, struct pt_regs *regs)
{
	wind_sem_t *sem;
	SEM_ID sem_id;
	int flags;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(sem_id)))
		return -EFAULT;

	flags = __xn_reg_arg1(regs);
	sem = (wind_sem_t *)semMCreate(flags);

	if (!sem)
		return wind_errnoget();

	sem_id = sem->handle;
	__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs), &sem_id,
			  sizeof(sem_id));

	return 0;
}

/*
 * int __wind_sem_delete(SEM_ID sem_id)
 */

static int __wind_sem_delete(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	wind_sem_t *sem;

	sem = (wind_sem_t *)xnregistry_fetch(handle);

	if (!sem)
		return S_objLib_OBJ_ID_ERROR;

	if (semDelete((SEM_ID)sem) == ERROR)
		return wind_errnoget();

	return 0;
}

/*
 * int __wind_sem_take(SEM_ID sem_id, int timeout)
 */

static int __wind_sem_take(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	int timeout = __xn_reg_arg2(regs);
	wind_sem_t *sem;

	sem = (wind_sem_t *)xnregistry_fetch(handle);

	if (!sem)
		return S_objLib_OBJ_ID_ERROR;

	if (semTake((SEM_ID)sem, timeout) == ERROR)
		return wind_errnoget();

	return 0;
}

/*
 * int __wind_sem_give(SEM_ID sem_id)
 */

static int __wind_sem_give(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	wind_sem_t *sem;

	sem = (wind_sem_t *)xnregistry_fetch(handle);

	if (!sem)
		return S_objLib_OBJ_ID_ERROR;

	if (semGive((SEM_ID)sem) == ERROR)
		return wind_errnoget();

	return 0;
}

/*
 * int __wind_sem_flush(SEM_ID sem_id)
 */

static int __wind_sem_flush(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	wind_sem_t *sem;

	sem = (wind_sem_t *)xnregistry_fetch(handle);

	if (!sem)
		return S_objLib_OBJ_ID_ERROR;

	if (semFlush((SEM_ID)sem) == ERROR)
		return wind_errnoget();

	return 0;
}

/*
 * int __wind_taskinfo_name(TASK_ID task_id, char *namebuf)
 */

static int __wind_taskinfo_name(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	const char *name;
	WIND_TCB *pTcb;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), XNOBJECT_NAME_LEN))
		return -EFAULT;

	pTcb = (WIND_TCB *)xnregistry_fetch(handle);

	if (!pTcb)
		return S_objLib_OBJ_ID_ERROR;

	name = taskName((TASK_ID) pTcb);

	if (!name)
		return S_objLib_OBJ_ID_ERROR;

	/* We assume that a VxWorks task name fits in XNOBJECT_NAME_LEN
	   bytes, including the trailing \0. */
	__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs), name,
			  strlen(name) + 1);

	return 0;
}

/*
 * int __wind_taskinfo_iddfl(TASK_ID task_id, TASK_ID *pret_id)
 */

static int __wind_taskinfo_iddfl(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	TASK_ID ret_id;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(ret_id)))
		return -EFAULT;

	ret_id = taskIdDefault(handle);
	__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs), &ret_id,
			  sizeof(ret_id));

	return 0;
}

/*
 * int __wind_taskinfo_status(TASK_ID task_id, unsigned long *pstatus)
 */

static int __wind_taskinfo_status(struct task_struct *curr,
				  struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	unsigned long status;
	WIND_TCB *pTcb;
	spl_t s;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(status)))
		return -EFAULT;

	xnlock_get_irqsave(&nklock, s);

	pTcb = (WIND_TCB *)xnregistry_fetch(handle);

	if (!pTcb || pTcb->magic != WIND_TASK_MAGIC) {
		xnlock_put_irqrestore(&nklock, s);
		return S_objLib_OBJ_ID_ERROR;
	}

	status = xnthread_state_flags(&pTcb->threadbase);

	xnlock_put_irqrestore(&nklock, s);

	__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs), &status,
			  sizeof(status));

	return 0;
}

/*
 * int __wind_taskinfo_get(TASK_ID task_id, TASK_DESC *desc)
 */
static int __wind_taskinfo_get(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	TASK_DESC desc;
	WIND_TCB *pTcb;
	int err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(desc)))
		return -EFAULT;

	pTcb = (WIND_TCB *)xnregistry_fetch(handle);
	if (!pTcb)
		return S_objLib_OBJ_ID_ERROR;

	err = taskInfoGet((TASK_ID)pTcb, &desc);
	if (!err) {
		/* Replace the kernel-based pointer by the userland handle. */
		desc.td_tid = handle;
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs), &desc,
				  sizeof(desc));
	}

	return err;
}

/*
 * int __wind_errno_taskset(TASK_ID task_id, int errcode)
 */

static int __wind_errno_taskset(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	int errcode = __xn_reg_arg2(regs);
	WIND_TCB *pTcb;

	if (!handle) {
		wind_errnoset(errcode);
		return 0;
	}

	pTcb = (WIND_TCB *)xnregistry_fetch(handle);
	if (!pTcb)
		return S_objLib_OBJ_ID_ERROR;

	if (errnoOfTaskSet((TASK_ID) pTcb, errcode) == ERROR)
		return wind_errnoget();

	return 0;
}

/*
 * int __wind_errno_taskget(TASK_ID task_id, int *perrcode)
 */

static int __wind_errno_taskget(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	WIND_TCB *pTcb;
	int errcode;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(errcode)))
		return -EFAULT;

	if (!handle)
		errcode = wind_errnoget();
	else {
		pTcb = (WIND_TCB *)xnregistry_fetch(handle);
		if (!pTcb)
			return S_objLib_OBJ_ID_ERROR;

		errcode = errnoOfTaskGet((TASK_ID) pTcb);
		if (errcode == ERROR)
			return wind_errnoget();
	}

	__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs), &errcode,
			  sizeof(errcode));

	return 0;
}

/*
 * int __wind_kernel_timeslice(int ticks)
 */

static int __wind_kernel_timeslice(struct task_struct *curr,
				   struct pt_regs *regs)
{
	int ticks = __xn_reg_arg1(regs);

	kernelTimeSlice(ticks);	/* Always ok. */

	return 0;
}

/*
 * int __wind_msgq_create(int nb_msgs, int length, int flags, MSG_Q_ID *pqid)
 */

static int __wind_msgq_create(struct task_struct *curr, struct pt_regs *regs)
{
	int nb_msgs, length, flags;
	wind_msgq_t *msgq;
	MSG_Q_ID qid;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg4(regs), sizeof(qid)))
		return -EFAULT;

	nb_msgs = __xn_reg_arg1(regs);
	length = __xn_reg_arg2(regs);
	flags = __xn_reg_arg3(regs);
	msgq = (wind_msgq_t *)msgQCreate(nb_msgs, length, flags);

	if (!msgq)
		return wind_errnoget();

	qid = msgq->handle;
	__xn_copy_to_user(curr, (void __user *)__xn_reg_arg4(regs), &qid,
			  sizeof(qid));

	return 0;
}

/*
 * int __wind_msgq_delete()
 */

static int __wind_msgq_delete(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	wind_msgq_t *msgq;

	msgq = (wind_msgq_t *)xnregistry_fetch(handle);

	if (!msgq)
		return S_objLib_OBJ_ID_ERROR;

	if (msgQDelete((MSG_Q_ID)msgq) == ERROR)
		return wind_errnoget();

	return 0;
}

/*
 * int __wind_msgq_nummsgs(MSG_Q_ID qid, int *pnummsgs)
 */

static int __wind_msgq_nummsgs(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	wind_msgq_t *msgq;
	int nummsgs;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(nummsgs)))
		return -EFAULT;

	msgq = (wind_msgq_t *)xnregistry_fetch(handle);

	if (!msgq)
		return S_objLib_OBJ_ID_ERROR;

	nummsgs = msgQNumMsgs((MSG_Q_ID)msgq);

	if (nummsgs == ERROR)
		return wind_errnoget();

	__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs), &nummsgs,
			  sizeof(nummsgs));

	return 0;
}

/*
 * int __wind_msgq_receive(MSG_Q_ID qid, char *buf, unsigned nbytes, int timeout, unsigned *rbytes)
 */

static int __wind_msgq_receive(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	char tmp_buf[128], *msgbuf;
	wind_msgq_t *msgq;
	int timeout, err;
	unsigned nbytes;

	nbytes = __xn_reg_arg3(regs);
	timeout = __xn_reg_arg4(regs);

	if (!__xn_access_ok(curr, VERIFY_WRITE, __xn_reg_arg2(regs), nbytes))
		return -EFAULT;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg5(regs), sizeof(nbytes)))
		return -EFAULT;

	msgq = (wind_msgq_t *)xnregistry_fetch(handle);

	if (!msgq)
		return S_objLib_OBJ_ID_ERROR;

	if (nbytes <= sizeof(tmp_buf))
		msgbuf = tmp_buf;
	else {
		msgbuf = (char *)xnmalloc(nbytes);

		if (!msgbuf)
			return S_memLib_NOT_ENOUGH_MEMORY;
	}

	/* This is sub-optimal since we end up copying the data twice. */

	err = msgQReceive((MSG_Q_ID)msgq, msgbuf, nbytes, timeout);

	if (err != ERROR) {
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs),
				  msgbuf, err);
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg5(regs),
				  &err, sizeof(err));
		err = 0;
	} else
		err = wind_errnoget();

	if (msgbuf != tmp_buf)
		xnfree(msgbuf);

	return err;
}

/*
 * int __wind_msgq_send(MSG_Q_ID qid ,const char *buf, unsigned nbytes, int timeout, int prio)
 */

static int __wind_msgq_send(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	char tmp_buf[128], *msgbuf;
	wind_msgq_t *msgq;
	int timeout, prio;
	unsigned nbytes;
	STATUS err;

	nbytes = __xn_reg_arg3(regs);
	timeout = __xn_reg_arg4(regs);
	prio = __xn_reg_arg5(regs);

	if (timeout != NO_WAIT && !xnpod_primary_p())
		return -EPERM;

	msgq = (wind_msgq_t *)xnregistry_fetch(handle);

	if (!msgq)
		return S_objLib_OBJ_ID_ERROR;

	if (nbytes > msgq->msg_length)
		return S_msgQLib_INVALID_MSG_LENGTH;

	if (!__xn_access_ok(curr, VERIFY_READ, __xn_reg_arg2(regs), nbytes))
		return -EFAULT;

	if (nbytes <= sizeof(tmp_buf))
		msgbuf = tmp_buf;
	else {
		msgbuf = (char *)xnmalloc(nbytes);

		if (!msgbuf)
			return S_memLib_NOT_ENOUGH_MEMORY;
	}

	/* This is sub-optimal since we end up copying the data twice. */

	__xn_copy_from_user(curr, msgbuf, (void __user *)__xn_reg_arg2(regs),
			    nbytes);

	err = msgQSend((MSG_Q_ID)msgq, msgbuf, nbytes, timeout, prio);

	if (msgbuf != tmp_buf)
		xnfree(msgbuf);

	return err == ERROR ? wind_errnoget() : 0;
}

/*
 * int __wind_tick_get(ULONG *ticks)
 */

static int __wind_tick_get(struct task_struct *curr, struct pt_regs *regs)
{
	ULONG ticks;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(ticks)))
		return -EFAULT;

	ticks = tickGet();
	__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs), &ticks,
			  sizeof(ticks));

	return 0;
}

/*
 * int __wind_tick_set(ULONG ticks)
 */

static int __wind_tick_set(struct task_struct *curr, struct pt_regs *regs)
{
	tickSet(__xn_reg_arg1(regs));
	return 0;
}

/*
 * int __wind_sys_clkdisable(void)
 */

static int __wind_sys_clkdisable(struct task_struct *curr, struct pt_regs *regs)
{
	sysClkDisable();
	return 0;
}

/*
 * int __wind_sys_clkenable(void)
 */

static int __wind_sys_clkenable(struct task_struct *curr, struct pt_regs *regs)
{
	sysClkEnable();
	return 0;
}

/*
 * int __wind_sys_clkrateget(int *hz)
 */

static int __wind_sys_clkrateget(struct task_struct *curr, struct pt_regs *regs)
{
	int hz;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(hz)))
		return -EFAULT;

	hz = sysClkRateGet();
	__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs), &hz,
			  sizeof(hz));

	return 0;
}

/*
 * int __wind_sys_clkrateset(int hz)
 */

static int __wind_sys_clkrateset(struct task_struct *curr, struct pt_regs *regs)
{
	return sysClkRateSet(__xn_reg_arg1(regs)) == ERROR;
}

/*
 * int __wind_wd_create(WDOG_ID *pwdog_id)
 */

static int __wind_wd_create(struct task_struct *curr, struct pt_regs *regs)
{
	WDOG_ID wdog_id;
	wind_wd_t *wd;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(wdog_id)))
		return -EFAULT;

	wd = (wind_wd_t *)wdCreate();

	if (!wd)
		return wind_errnoget();

	wd->rh = wind_get_rholder();
	wdog_id = wd->handle;
	__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs), &wdog_id,
			  sizeof(wdog_id));

	return 0;
}

/*
 * int __wind_wd_delete(WDOG_ID wdog_id)
 */

static int __wind_wd_delete(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	wind_wd_t *wd;

	wd = (wind_wd_t *)xnregistry_fetch(handle);

	if (!wd)
		return S_objLib_OBJ_ID_ERROR;

	if (wdDelete((WDOG_ID)wd) == ERROR)
		return wind_errnoget();

	return 0;
}

/*
 * int __wind_wd_start(WDOG_ID wdog_id,
 *		       int timeout,
 *                     wind_timer_t timer,
 *                     long arg,
 *                     *long start_serverp)
 */

void __wind_wd_handler(void *cookie)
{
	wind_wd_t *wd = (wind_wd_t *)cookie;

	if (wd->plink.last == wd->plink.next) {	/* Not linked? */
		appendq(&wd->rh->wdpending, &wd->plink);
		if (countq(&wd->rh->wdpending) == 1)
			xnsynch_flush(&wd->rh->wdsynch, 0);
	}
}

static int __wind_wd_start(struct task_struct *curr, struct pt_regs *regs)
{
	wind_rholder_t *rh;
	long start_server;
	xnhandle_t handle;
	wind_wd_t *wd;
	int timeout;
	spl_t s;

	if (!__xn_access_ok(curr, VERIFY_WRITE, __xn_reg_arg5(regs), sizeof(start_server)))
		return -EFAULT;

	handle = __xn_reg_arg1(regs);

	wd = (wind_wd_t *)xnregistry_fetch(handle);

	if (!wd)
		return S_objLib_OBJ_ID_ERROR;

	rh = wind_get_rholder();

	if (wd->rh != rh)
		/*
		 * User may not fiddle with watchdogs created from
		 * other processes.
		 */
		return S_objLib_OBJ_UNAVAILABLE;

	timeout = __xn_reg_arg2(regs);

	xnlock_get_irqsave(&nklock, s);

	if (wdStart
	    ((WDOG_ID)wd, timeout, (wind_timer_t) & __wind_wd_handler,
	     (long)wd) == ERROR) {
		xnlock_put_irqrestore(&nklock, s);
		return wind_errnoget();
	}

	wd->wdt.handler = (wind_timer_t) __xn_reg_arg3(regs);
	wd->wdt.arg = (long)__xn_reg_arg4(regs);
	start_server = rh->wdcount++ == 0;

	xnlock_put_irqrestore(&nklock, s);

	__xn_copy_to_user(curr, (void __user *)__xn_reg_arg5(regs), &start_server,
			  sizeof(start_server));

	return 0;
}

/*
 * int __wind_wd_cancel(WDOG_ID wdog_id)
 */

static int __wind_wd_cancel(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	wind_wd_t *wd;

	wd = (wind_wd_t *)xnregistry_fetch(handle);

	if (!wd)
		return S_objLib_OBJ_ID_ERROR;

	if (wdCancel((WDOG_ID)wd) == ERROR)
		return wind_errnoget();

	return 0;
}

/*
 * int __wind_wd_wait(wind_wd_utarget_t *pwdt)
 */

static int __wind_wd_wait(struct task_struct *curr, struct pt_regs *regs)
{
	xnholder_t *holder;
	wind_rholder_t *rh;
	WIND_TCB *pTcb;
	wind_wd_t *wd;
	int err = 0;
	spl_t s;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(wd->wdt)))
		return -EFAULT;

	rh = wind_get_rholder();

	xnlock_get_irqsave(&nklock, s);

	pTcb = __wind_task_current(curr);

	if (xnthread_base_priority(&pTcb->threadbase) != XNCORE_IRQ_PRIO)
		/* Renice the waiter above all regular tasks if needed. */
		xnpod_renice_thread(&pTcb->threadbase, XNCORE_IRQ_PRIO);

	if (!emptyq_p(&rh->wdpending))
		goto pull_event;

	xnsynch_sleep_on(&rh->wdsynch, XN_INFINITE, XN_RELATIVE);

	if (xnthread_test_info(&pTcb->threadbase, XNBREAK)) {
		err = -EINTR;	/* Unblocked. */
		goto unlock_and_exit;
	}
	
	if (xnthread_test_info(&pTcb->threadbase, XNRMID)) {
		err = -EIDRM;	/* Watchdog deleted while pending. */
		goto unlock_and_exit;
	}

 pull_event:

	holder = getq(&rh->wdpending);

	if (holder) {
		wd = link2wind_wd(holder);
		/* We need the following to mark the watchdog as unqueued. */
		inith(holder);
		xnlock_put_irqrestore(&nklock, s);
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs),
				  &wd->wdt, sizeof(wd->wdt));
		return 0;
	}

 unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/*
 * int __wind_int_context(void)
 */

static int __wind_int_context(struct task_struct *curr, struct pt_regs *regs)
{
	WIND_TCB *pTcb = __wind_task_current(curr);
	return pTcb
	    && xnthread_base_priority(&pTcb->threadbase) == XNCORE_IRQ_PRIO;
}

static void *__wind_shadow_eventcb(int event, void *data)
{
	struct wind_resource_holder *rh;
	switch(event) {

	case XNSHADOW_CLIENT_ATTACH:

		rh = (struct wind_resource_holder *) xnarch_alloc_host_mem(sizeof(*rh));
		if (!rh)
			return ERR_PTR(-ENOMEM);

		initq(&rh->wdq);
		/* A single server thread pends on this. */
		xnsynch_init(&rh->wdsynch, XNSYNCH_FIFO);
		initq(&rh->wdpending);
		rh->wdcount = 0;
		initq(&rh->msgQq);
		initq(&rh->semq);

		return &rh->ppd;

	case XNSHADOW_CLIENT_DETACH:

		rh = ppd2rholder((xnshadow_ppd_t *) data);
		wind_wd_flush_rq(&rh->wdq);
		xnsynch_destroy(&rh->wdsynch);
		/* No need to reschedule: all our threads have been zapped. */
		wind_msgq_flush_rq(&rh->msgQq);
		wind_sem_flush_rq(&rh->semq);

		xnarch_free_host_mem(rh, sizeof(*rh));

		return NULL;
	}

	return ERR_PTR(-EINVAL);
}

static xnsysent_t __systab[] = {
	[__vxworks_task_init] = {&__wind_task_init, __xn_exec_init},
	[__vxworks_task_activate] = {&__wind_task_activate, __xn_exec_any},
	[__vxworks_task_deleteforce] =
	    {&__wind_task_deleteforce, __xn_exec_conforming},
	[__vxworks_task_delete] = {&__wind_task_delete, __xn_exec_conforming},
	[__vxworks_task_suspend] = {&__wind_task_suspend, __xn_exec_conforming},
	[__vxworks_task_resume] = {&__wind_task_resume, __xn_exec_any},
	[__vxworks_task_self] = {&__wind_task_self, __xn_exec_primary},
	[__vxworks_task_priorityset] =
	    {&__wind_task_priorityset, __xn_exec_any},
	[__vxworks_task_priorityget] =
	    {&__wind_task_priorityget, __xn_exec_any},
	[__vxworks_task_lock] = {&__wind_task_lock, __xn_exec_primary},
	[__vxworks_task_unlock] = {&__wind_task_unlock, __xn_exec_conforming},
	[__vxworks_task_safe] = {&__wind_task_safe, __xn_exec_primary},
	[__vxworks_task_unsafe] = {&__wind_task_unsafe, __xn_exec_primary},
	[__vxworks_task_delay] = {&__wind_task_delay, __xn_exec_primary},
	[__vxworks_task_verifyid] = {&__wind_task_verifyid, __xn_exec_any},
	[__vxworks_task_nametoid] = {&__wind_task_nametoid, __xn_exec_any},
	[__vxworks_task_setmode] = {&__wind_task_setmode, __xn_exec_primary},
	[__vxworks_sem_bcreate] = {&__wind_sem_bcreate, __xn_exec_any},
	[__vxworks_sem_ccreate] = {&__wind_sem_ccreate, __xn_exec_any},
	[__vxworks_sem_mcreate] = {&__wind_sem_mcreate, __xn_exec_any},
	[__vxworks_sem_delete] = {&__wind_sem_delete, __xn_exec_any},
	[__vxworks_sem_take] = {&__wind_sem_take, __xn_exec_primary},
	[__vxworks_sem_give] = {&__wind_sem_give, __xn_exec_conforming},
	[__vxworks_sem_flush] = {&__wind_sem_flush, __xn_exec_any},
	[__vxworks_taskinfo_name] = {&__wind_taskinfo_name, __xn_exec_any},
	[__vxworks_taskinfo_iddfl] = {&__wind_taskinfo_iddfl, __xn_exec_any},
	[__vxworks_taskinfo_status] = {&__wind_taskinfo_status, __xn_exec_any},
	[__vxworks_taskinfo_get] = {&__wind_taskinfo_get, __xn_exec_any},
	[__vxworks_errno_taskset] = {&__wind_errno_taskset, __xn_exec_primary},
	[__vxworks_errno_taskget] = {&__wind_errno_taskget, __xn_exec_primary},
	[__vxworks_kernel_timeslice] =
	    {&__wind_kernel_timeslice, __xn_exec_any},
	[__vxworks_msgq_create] = {&__wind_msgq_create, __xn_exec_any},
	[__vxworks_msgq_delete] = {&__wind_msgq_delete, __xn_exec_any},
	[__vxworks_msgq_nummsgs] = {&__wind_msgq_nummsgs, __xn_exec_any},
	[__vxworks_msgq_receive] = {&__wind_msgq_receive, __xn_exec_conforming},
	[__vxworks_msgq_send] = {&__wind_msgq_send, __xn_exec_conforming},
	[__vxworks_tick_get] = {&__wind_tick_get, __xn_exec_any},
	[__vxworks_tick_set] = {&__wind_tick_set, __xn_exec_any},
	[__vxworks_sys_clkdisable] = {&__wind_sys_clkdisable, __xn_exec_any},
	[__vxworks_sys_clkenable] = {&__wind_sys_clkenable, __xn_exec_any},
	[__vxworks_sys_clkrateget] = {&__wind_sys_clkrateget, __xn_exec_any},
	[__vxworks_sys_clkrateset] = {&__wind_sys_clkrateset, __xn_exec_any},
	[__vxworks_wd_create] = {&__wind_wd_create, __xn_exec_any},
	[__vxworks_wd_delete] = {&__wind_wd_delete, __xn_exec_any},
	[__vxworks_wd_start] = {&__wind_wd_start, __xn_exec_any},
	[__vxworks_wd_cancel] = {&__wind_wd_cancel, __xn_exec_any},
	[__vxworks_wd_wait] = {&__wind_wd_wait, __xn_exec_primary},
	[__vxworks_int_context] = {&__wind_int_context, __xn_exec_any},
};

extern xntbase_t *wind_tbase;

static struct xnskin_props __props = {
	.name = "vxworks",
	.magic = VXWORKS_SKIN_MAGIC,
	.nrcalls = sizeof(__systab) / sizeof(__systab[0]),
	.systab = __systab,
	.eventcb = __wind_shadow_eventcb,
	.timebasep = &wind_tbase,
	.module = THIS_MODULE
};

static void __shadow_delete_hook(xnthread_t *thread)
{
	if (xnthread_get_magic(thread) == VXWORKS_SKIN_MAGIC &&
	    xnthread_test_state(thread, XNMAPPED))
		xnshadow_unmap(thread);
}

int wind_syscall_init(void)
{
	__wind_muxid = xnshadow_register_interface(&__props);

	if (__wind_muxid < 0)
		return -ENOSYS;

	xnpod_add_hook(XNHOOK_THREAD_DELETE, &__shadow_delete_hook);

	return 0;
}

void wind_syscall_cleanup(void)
{
	xnpod_remove_hook(XNHOOK_THREAD_DELETE, &__shadow_delete_hook);
	xnshadow_unregister_interface(__wind_muxid);
}
