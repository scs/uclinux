/**
 * @file
 * This file is part of the Xenomai project.
 *
 * @note Copyright (C) 2006 Philippe Gerum <rpm@xenomai.org> 
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
#include <nucleus/registry.h>
#include <psos+/defs.h>
#include <psos+/task.h>
#include <psos+/syscall.h>
#include <psos+/queue.h>
#include <psos+/sem.h>
#include <psos+/tm.h>
#include <psos+/rn.h>
#include <psos+/pt.h>

/*
 * By convention, error codes are passed back through the syscall
 * return value:
 * - negative codes stand for internal (i.e. nucleus) errors;
 * - strictly positive values stand for genuine pSOS errors.
 * - zero means success.
 *
 * NOTE: the pSOS skin normally returns object memory addresses as
 * identifiers to kernel-space users. For user-space callers, we go
 * though the registry for obtaining safe identifiers.
 */

int __psos_muxid;

static psostask_t *__psos_task_current(struct task_struct *curr)
{
	xnthread_t *thread = xnshadow_thread(curr);

	if (!thread || xnthread_get_magic(thread) != PSOS_SKIN_MAGIC)
		return NULL;

	return thread2psostask(thread);	/* Convert TCB pointers. */
}

/*
 * int __t_create(const char *name,
 *                u_long prio,
 *                u_long flags,
 *                u_long *tid_r,
 *                xncompletion_t *completion)
 */

static int __t_create(struct task_struct *curr, struct pt_regs *regs)
{
	xncompletion_t __user *u_completion;
	u_long prio, flags, tid, err;
	char name[XNOBJECT_NAME_LEN];
	psostask_t *task;

	if (!__xn_access_ok(curr, VERIFY_READ, __xn_reg_arg1(regs), 4))
		return -EFAULT;

	/* Get task name. */
	__xn_strncpy_from_user(curr, name, (const char __user *)__xn_reg_arg1(regs),
			       sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';
	strncpy(curr->comm, name, sizeof(curr->comm));
	curr->comm[sizeof(curr->comm) - 1] = '\0';

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg4(regs), sizeof(tid)))
		return -EFAULT;

	/* Task priority. */
	prio = __xn_reg_arg2(regs);
	/* Task flags. Force FPU support in user-space. This will lead
	   to a no-op if the platform does not support it. */
	flags = __xn_reg_arg3(regs) | T_SHADOW | T_FPU;
	/* Completion descriptor our parent thread is pending on. */
	u_completion = (xncompletion_t __user *)__xn_reg_arg5(regs);

	err = t_create(name, prio, 0, 0, flags, &tid);

	if (err == SUCCESS) {
		task = (psostask_t *)tid;
		/* Copy back the registry handle. So far, nobody knows
		 * about the new thread id, so we can manipulate its
		 * TCB pointer freely. */
		tid = xnthread_handle(&task->threadbase);
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg4(regs), &tid,
				  sizeof(tid));
		err = xnshadow_map(&task->threadbase, u_completion); /* May be NULL */
	} else {
		/* Unblock and pass back error code. */

		if (u_completion)
			xnshadow_signal_completion(u_completion, err);
	}

	return err;
}

/*
 * int __t_start(u_long tid,
 *	         u_long mode,
 *	         void (*startaddr) (u_long, u_long, u_long, u_long),
 *  	         u_long targs[])
 */

static int __t_start(struct task_struct *curr, struct pt_regs *regs)
{
	void (*startaddr)(u_long, u_long, u_long, u_long);
	u_long mode, *argp;
	xnhandle_t handle;
	psostask_t *task;

	handle = __xn_reg_arg1(regs);
	task = (psostask_t *)xnregistry_fetch(handle);

	if (!task)
		return ERR_OBJID;

	/* We should now have a valid tid to pass to t_start(), but
	 * the corresponding task may vanish while we are preparing
	 * this call. Therefore, we _never_ dereference the task
	 * pointer, but only pass it to the real service, which will
	 * revalidate the handle again before processing. A better
	 * approach would be to use the registry for drawing pSOS
	 * handles both from kernel and user-space based domains. */

	mode = __xn_reg_arg2(regs);
	startaddr = (typeof(startaddr))__xn_reg_arg3(regs);
	argp = (u_long *)__xn_reg_arg4(regs); /* May be NULL. */

	return t_start((u_long)task, mode, startaddr, argp);
}

/*
 * int __t_delete(u_long tid)
 */
static int __t_delete(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle;
	psostask_t *task;

	handle = __xn_reg_arg1(regs);

	if (handle)
		task = (psostask_t *)xnregistry_fetch(handle);
	else
		task = __psos_task_current(curr);

	if (!task)
		return ERR_OBJID;

	return t_delete((u_long)task);
}

/*
 * int __t_suspend(u_long tid)
 */

static int __t_suspend(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	psostask_t *task;

	if (handle)
		task = (psostask_t *)xnregistry_fetch(handle);
	else
		task = __psos_task_current(curr);

	if (!task)
		return ERR_OBJID;

	return t_suspend((u_long)task);
}

/*
 * int __t_resume(u_long tid)
 */

static int __t_resume(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	psostask_t *task;

	if (handle)
		task = (psostask_t *)xnregistry_fetch(handle);
	else
		task = __psos_task_current(curr);

	if (!task)
		return ERR_OBJID;

	return t_resume((u_long)task);
}

/*
 * int __t_ident(const char *name, u_long *tid_r)
 */

static int __t_ident(struct task_struct *curr, struct pt_regs *regs)
{
	char name[XNOBJECT_NAME_LEN], *namep;
	u_long err, tid;
	spl_t s;

	if (__xn_reg_arg1(regs)) {
		if (!__xn_access_ok(curr, VERIFY_READ, __xn_reg_arg1(regs), 4))
			return -EFAULT;

		/* Get task name. */
		__xn_strncpy_from_user(curr, name, (const char __user *)__xn_reg_arg1(regs),
				       sizeof(name));
		namep = name;
	} else
		namep = NULL;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(tid)))
		return -EFAULT;

	xnlock_get_irqsave(&nklock, s);

	err = t_ident(namep, 0, &tid);

	if (err == SUCCESS) {
		psostask_t *task = (psostask_t *)tid;
		tid = xnthread_handle(&task->threadbase);
	}

	xnlock_put_irqrestore(&nklock, s);

	if (err == SUCCESS)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs), &tid,
				  sizeof(tid));

	return err;
}

/*
 * int __t_mode(u_long clrmask, u_long setmask, u_long *oldmode_r)
 */

static int __t_mode(struct task_struct *curr, struct pt_regs *regs)
{
	u_long clrmask, setmask, oldmode, err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg3(regs), sizeof(oldmode)))
		return -EFAULT;

	clrmask = __xn_reg_arg1(regs);
	setmask = __xn_reg_arg2(regs);

	err = t_mode(clrmask, setmask, &oldmode);

	if (err == SUCCESS)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg3(regs), &oldmode,
				  sizeof(oldmode));

	return err;
}

/*
 * int __t_setpri(u_long tid, u_long newprio, u_long *oldprio_r)
 */

static int __t_setpri(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	u_long err, newprio, oldprio;
	psostask_t *task;

	if (handle)
		task = (psostask_t *)xnregistry_fetch(handle);
	else
		task = __psos_task_current(curr);

	if (!task)
		return ERR_OBJID;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg3(regs), sizeof(oldprio)))
		return -EFAULT;

	newprio = __xn_reg_arg2(regs);

	err = t_setpri((u_long)task, newprio, &oldprio);

	if (err == SUCCESS)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg3(regs), &oldprio,
				  sizeof(oldprio));

	return err;
}

/*
 * int __ev_send(u_long tid, u_long events)
 */

static int __ev_send(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	psostask_t *task;
	u_long events;

	if (handle)
		task = (psostask_t *)xnregistry_fetch(handle);
	else
		task = __psos_task_current(curr);

	if (!task)
		return ERR_OBJID;

	events = __xn_reg_arg2(regs);

	return ev_send((u_long)task, events);
}

/*
 * int __ev_receive(u_long events, u_long flags, u_long timeout, u_long *events_r)
 */

static int __ev_receive(struct task_struct *curr, struct pt_regs *regs)
{
	u_long err, flags, timeout, events, events_r;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg4(regs), sizeof(events_r)))
		return -EFAULT;

	events = __xn_reg_arg1(regs);
	flags = __xn_reg_arg2(regs);
	timeout = __xn_reg_arg3(regs);

	err = ev_receive(events, flags, timeout, &events_r);

	if (err == SUCCESS)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg4(regs), &events_r,
				  sizeof(events_r));

	return err;
}

/*
 * int __q_create(const char *name, u_long maxnum, u_long flags, u_long *qid_r)
 */

static int __q_create(struct task_struct *curr, struct pt_regs *regs)
{
	u_long maxnum, flags, qid, err;
	char name[XNOBJECT_NAME_LEN];
	psosqueue_t *queue;

	if (!__xn_access_ok(curr, VERIFY_READ, __xn_reg_arg1(regs), 4))
		return -EFAULT;

	/* Get queue name. */
	__xn_strncpy_from_user(curr, name, (const char __user *)__xn_reg_arg1(regs),
			       sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg4(regs), sizeof(qid)))
		return -EFAULT;

	/* Max message number. */
	maxnum = __xn_reg_arg2(regs);
	/* Queue flags. */
	flags = __xn_reg_arg3(regs);

	err = q_create(name, maxnum, flags, &qid);

	if (err == SUCCESS) {
		queue = (psosqueue_t *)qid;
		/* Copy back the registry handle. */
		qid = queue->handle;
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg4(regs), &qid,
				  sizeof(qid));
	}

	return err;
}

/*
 * int __q_delete(u_long qid)
 */

static int __q_delete(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	psosqueue_t *queue;

	queue = (psosqueue_t *)xnregistry_fetch(handle);

	if (!queue)
		return ERR_OBJID;

	return q_delete((u_long)queue);
}

/*
 * int __q_ident(const char *name, u_long *qid_r)
 */

static int __q_ident(struct task_struct *curr, struct pt_regs *regs)
{
	char name[XNOBJECT_NAME_LEN];
	u_long err, qid;
	spl_t s;

	if (!__xn_access_ok(curr, VERIFY_READ, __xn_reg_arg1(regs), 4))
		return -EFAULT;

	/* Get queue name. */
	__xn_strncpy_from_user(curr, name, (const char __user *)__xn_reg_arg1(regs),
			       sizeof(name));

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(qid)))
		return -EFAULT;

	xnlock_get_irqsave(&nklock, s);

	err = q_ident(name, 0, &qid);

	if (err == SUCCESS) {
		psosqueue_t *queue = (psosqueue_t *)qid;
		qid = queue->handle;
	}

	xnlock_put_irqrestore(&nklock, s);

	if (err == SUCCESS)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs), &qid,
				  sizeof(qid));

	return err;
}

/*
 * int __q_receive(u_long qid, u_long flags, u_long timeout, u_long msgbuf[4])
 */

static int __q_receive(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	u_long flags, timeout, msgbuf[4], err;
	psosqueue_t *queue;

	queue = (psosqueue_t *)xnregistry_fetch(handle);

	if (!queue)
		return ERR_OBJID;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg4(regs), sizeof(u_long[4])))
		return -EFAULT;

	flags = __xn_reg_arg2(regs);
	timeout = __xn_reg_arg3(regs);

	err = q_receive((u_long)queue, flags, timeout, msgbuf);

	if (err == SUCCESS)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg4(regs), msgbuf,
				  sizeof(u_long[4]));

	return err;
}

/*
 * int __q_send(u_long qid, u_long msgbuf[4])
 */

static int __q_send(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	psosqueue_t *queue;
	u_long msgbuf[4];

	queue = (psosqueue_t *)xnregistry_fetch(handle);

	if (!queue)
		return ERR_OBJID;

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg2(regs), sizeof(u_long[4])))
		return -EFAULT;

	__xn_copy_from_user(curr, msgbuf, (void __user *)__xn_reg_arg2(regs),
			       sizeof(u_long[4]));

	return q_send((u_long)queue, msgbuf);
}

/*
 * int __q_urgent(u_long qid, u_long msgbuf[4])
 */

static int __q_urgent(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	psosqueue_t *queue;
	u_long msgbuf[4];

	queue = (psosqueue_t *)xnregistry_fetch(handle);

	if (!queue)
		return ERR_OBJID;

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg2(regs), sizeof(u_long[4])))
		return -EFAULT;

	__xn_copy_from_user(curr, msgbuf, (void __user *)__xn_reg_arg2(regs),
			       sizeof(u_long[4]));

	return q_urgent((u_long)queue, msgbuf);
}

/*
 * int __q_broadcast(u_long qid, u_long msgbuf[4], u_long *count_r)
 */

static int __q_broadcast(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	u_long msgbuf[4], count, err;
	psosqueue_t *queue;

	queue = (psosqueue_t *)xnregistry_fetch(handle);

	if (!queue)
		return ERR_OBJID;

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg2(regs), sizeof(u_long[4])))
		return -EFAULT;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg3(regs), sizeof(count)))
		return -EFAULT;

	__xn_copy_from_user(curr, msgbuf, (void __user *)__xn_reg_arg2(regs),
			       sizeof(u_long[4]));

	err = q_broadcast((u_long)queue, msgbuf, &count);

	if (err == SUCCESS)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg3(regs), &count,
				  sizeof(count));

	return err;
}

/*
 * int __q_vcreate(const char *name, u_long maxnum, u_long maxlen, u_long flags, u_long *qid_r)
 */

static int __q_vcreate(struct task_struct *curr, struct pt_regs *regs)
{
	u_long maxnum, maxlen, flags, qid, err;
	char name[XNOBJECT_NAME_LEN];
	psosqueue_t *queue;

	if (!__xn_access_ok(curr, VERIFY_READ, __xn_reg_arg1(regs), 4))
		return -EFAULT;

	/* Get queue name. */
	__xn_strncpy_from_user(curr, name, (const char __user *)__xn_reg_arg1(regs),
			       sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg5(regs), sizeof(qid)))
		return -EFAULT;

	/* Max message number. */
	maxnum = __xn_reg_arg2(regs);
	/* Max message length. */
	maxlen = __xn_reg_arg3(regs);
	/* Queue flags. */
	flags = __xn_reg_arg4(regs);

	err = q_vcreate(name, flags, maxnum, maxlen, &qid);

	if (err == SUCCESS) {
		queue = (psosqueue_t *)qid;
		/* Copy back the registry handle. */
		qid = queue->handle;
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg5(regs), &qid,
				  sizeof(qid));
	}

	return err;
}

/*
 * int __q_vdelete(u_long qid)
 */

static int __q_vdelete(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	psosqueue_t *queue;

	queue = (psosqueue_t *)xnregistry_fetch(handle);

	if (!queue)
		return ERR_OBJID;

	return q_vdelete((u_long)queue);
}

/*
 * int __q_vident(const char *name, u_long *qid_r)
 */

static int __q_vident(struct task_struct *curr, struct pt_regs *regs)
{
	char name[XNOBJECT_NAME_LEN];
	u_long err, qid;
	spl_t s;

	if (!__xn_access_ok(curr, VERIFY_READ, __xn_reg_arg1(regs), 4))
		return -EFAULT;

	/* Get queue name. */
	__xn_strncpy_from_user(curr, name, (const char __user *)__xn_reg_arg1(regs),
			       sizeof(name));

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(qid)))
		return -EFAULT;

	xnlock_get_irqsave(&nklock, s);

	err = q_vident(name, 0, &qid);

	if (err == SUCCESS) {
		psosqueue_t *queue = (psosqueue_t *)qid;
		qid = queue->handle;
	}

	xnlock_put_irqrestore(&nklock, s);

	if (err == SUCCESS)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs), &qid,
				  sizeof(qid));

	return err;
}

/*
 * int __q_vreceive(u_long qid, struct modifiers *mod, void *msgbuf_r, u_long buflen, u_long *msglen_r)
 */

static int __q_vreceive(struct task_struct *curr, struct pt_regs *regs)
{
	u_long flags, timeout, msglen, buflen, err;
	xnhandle_t handle = __xn_reg_arg1(regs);
	psosqueue_t *queue;
	char tmp_buf[64];
	void *msgbuf;
	struct {
		u_long flags;
		u_long timeout;
	} modifiers;

	queue = (psosqueue_t *)xnregistry_fetch(handle);

	if (!queue)
		return ERR_OBJID;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg5(regs), sizeof(u_long)))
		return -EFAULT;

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg2(regs), sizeof(modifiers)))
		return -EFAULT;

	__xn_copy_from_user(curr, &modifiers, (void __user *)__xn_reg_arg2(regs),
			       sizeof(modifiers));

	buflen = __xn_reg_arg4(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg3(regs), buflen))
		return -EFAULT;

	flags = modifiers.flags;
	timeout = modifiers.timeout;

	if (buflen > sizeof(tmp_buf)) {
		msgbuf = xnmalloc(buflen);
		if (msgbuf == NULL)
			return -ENOMEM;
	} else
		/* Optimize a bit: if the message can fit in a small
		 * temp buffer in stack space, use the latter. */
		msgbuf = tmp_buf;
	
	err = q_vreceive((u_long)queue, flags, timeout, msgbuf, buflen, &msglen);

	if (err == SUCCESS) {
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg3(regs), msgbuf,
				  msglen);
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg5(regs), &msglen,
				  sizeof(msglen));
	}

	if (msgbuf != tmp_buf)
		xnfree(msgbuf);

	return err;
}

/*
 * int __q_vsend(u_long qid, void *msgbuf, u_long msglen)
 */

static int __q_vsend(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	u_long msglen, err;
	psosqueue_t *queue;
	char tmp_buf[64];
	void *msgbuf;

	queue = (psosqueue_t *)xnregistry_fetch(handle);

	if (!queue)
		return ERR_OBJID;

	msglen = __xn_reg_arg3(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg2(regs), msglen))
		return -EFAULT;

	if (msglen > sizeof(tmp_buf)) {
		msgbuf = xnmalloc(msglen);
		if (msgbuf == NULL)
			return -ENOMEM;
	} else
		/* Optimize a bit: if the message can fit in a small
		 * temp buffer in stack space, use the latter. */
		msgbuf = tmp_buf;
	
	__xn_copy_from_user(curr, msgbuf, (void __user *)__xn_reg_arg2(regs),
			    msglen);

	err = q_vsend((u_long)queue, msgbuf, msglen);

	if (msgbuf != tmp_buf)
		xnfree(msgbuf);

	return err;
}

/*
 * int __q_vurgent(u_long qid, void *msgbuf, u_long msglen)
 */

static int __q_vurgent(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	u_long msglen, err;
	psosqueue_t *queue;
	char tmp_buf[64];
	void *msgbuf;

	queue = (psosqueue_t *)xnregistry_fetch(handle);

	if (!queue)
		return ERR_OBJID;

	msglen = __xn_reg_arg3(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg2(regs), msglen))
		return -EFAULT;

	if (msglen > sizeof(tmp_buf)) {
		msgbuf = xnmalloc(msglen);
		if (msgbuf == NULL)
			return -ENOMEM;
	} else
		/* Optimize a bit: if the message can fit in a small
		 * temp buffer in stack space, use the latter. */
		msgbuf = tmp_buf;
	
	__xn_copy_from_user(curr, msgbuf, (void __user *)__xn_reg_arg2(regs),
			    msglen);

	err = q_vurgent((u_long)queue, msgbuf, msglen);

	if (msgbuf != tmp_buf)
		xnfree(msgbuf);

	return err;
}

/*
 * int __q_vbroadcast(u_long qid, void *msgbuf, u_long msglen, u_long *count_r)
 */

static int __q_vbroadcast(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	u_long msglen, count, err;
	psosqueue_t *queue;
	char tmp_buf[64];
	void *msgbuf;

	queue = (psosqueue_t *)xnregistry_fetch(handle);

	if (!queue)
		return ERR_OBJID;

	msglen = __xn_reg_arg3(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg2(regs), msglen))
		return -EFAULT;

	if (msglen > sizeof(tmp_buf)) {
		msgbuf = xnmalloc(msglen);
		if (msgbuf == NULL)
			return -ENOMEM;
	} else
		/* Optimize a bit: if the message can fit in a small
		 * temp buffer in stack space, use the latter. */
		msgbuf = tmp_buf;
	
	__xn_copy_from_user(curr, msgbuf, (void __user *)__xn_reg_arg2(regs),
			    msglen);

	err = q_vbroadcast((u_long)queue, msgbuf, msglen, &count);

	if (msgbuf != tmp_buf)
		xnfree(msgbuf);

	if (err == SUCCESS)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg4(regs), &count,
				  sizeof(count));

	return err;
}

/*
 * int __sm_create(const char *name, u_long icount, u_long flags, u_long *smid_r)
 */

static int __sm_create(struct task_struct *curr, struct pt_regs *regs)
{
	u_long icount, flags, smid, err;
	char name[XNOBJECT_NAME_LEN];
	psossem_t *sem;

	if (!__xn_access_ok(curr, VERIFY_READ, __xn_reg_arg1(regs), 4))
		return -EFAULT;

	/* Get queue name. */
	__xn_strncpy_from_user(curr, name, (const char __user *)__xn_reg_arg1(regs),
			       sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg4(regs), sizeof(smid)))
		return -EFAULT;

	/* Initial value. */
	icount = __xn_reg_arg2(regs);
	/* Creation flags. */
	flags = __xn_reg_arg3(regs);

	err = sm_create(name, icount, flags, &smid);

	if (err == SUCCESS) {
		sem = (psossem_t *)smid;
		/* Copy back the registry handle. */
		smid = sem->handle;
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg4(regs), &smid,
				  sizeof(smid));
	}

	return err;
}

/*
 * int __sm_delete(u_long smid)
 */

static int __sm_delete(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	psossem_t *sem;

	sem = (psossem_t *)xnregistry_fetch(handle);

	if (!sem)
		return ERR_OBJID;

	return sm_delete((u_long)sem);
}

 /*
  * int __sm_p(u_long smid, u_long flags, u_long timeout)
  */

static int __sm_p(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	psossem_t *sem;
	u_long  flags, timeout;

	sem = (psossem_t *)xnregistry_fetch(handle);

	if (!sem)
		return ERR_OBJID;

	flags   = __xn_reg_arg2(regs);
	timeout = __xn_reg_arg3(regs);

	return sm_p((u_long)sem, (u_long)flags, (u_long)timeout);
}

/*
 * int __sm_v(u_long smid)
 */

static int __sm_v(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	psossem_t *sem;

	sem = (psossem_t *)xnregistry_fetch(handle);

	if (!sem)
		return ERR_OBJID;

	return sm_v((u_long)sem);
}

/*
 * u_long tm_wkafter(u_long ticks)
 */

static int __tm_wkafter(struct task_struct *curr, struct pt_regs *regs)
{
	u_long	ticks = __xn_reg_arg1(regs);

	return tm_wkafter(ticks);
}

/*
 * u_long tm_cancel(u_long tmid)
 */

static int __tm_cancel(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	psostm_t *tm;

	tm = (psostm_t *)xnregistry_fetch(handle);

	if (!tm)
		return ERR_OBJID;

	return tm_cancel((u_long)tm);
}

/*
 * u_long tm_evafter(u_long ticks, u_long events, u_long *tmid_r)
 */

static int __tm_evafter(struct task_struct *curr, struct pt_regs *regs)
{
	u_long ticks, events, tmid, err;
	psostm_t *tm;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg3(regs), sizeof(tmid)))
		return -EFAULT;

	ticks = __xn_reg_arg1(regs);
	events = __xn_reg_arg2(regs);

	err = tm_evafter(ticks, events, &tmid);

	if (err == SUCCESS) {
		tm = (psostm_t *)tmid;
		/* Copy back the registry handle. */
		tmid = tm->handle;
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg3(regs), &tmid,
				  sizeof(tmid));
	}

	return err;
}

/*
 * u_long tm_get(u_long *date_r, u_long *time_r, u_long *ticks_r)
 */

static int __tm_get(struct task_struct *curr, struct pt_regs *regs)
{
	u_long date, time, ticks, err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(date)))
		return -EFAULT;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(time)))
		return -EFAULT;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg3(regs), sizeof(ticks)))
		return -EFAULT;

	err = tm_get(&date, &time, &ticks);

	if (err == SUCCESS) {
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs), &date,
				  sizeof(date));
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs), &time,
				  sizeof(time));
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg3(regs), &ticks,
				  sizeof(ticks));
	}

	return err;
}

/*
 * u_long tm_getm(u_long_long *ns_r)
 */

static int __tm_getm(struct task_struct *curr, struct pt_regs *regs)
{
	xnticks_t ns;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(ns)))
		return -EFAULT;

	ns = xntbase_get_jiffies(&nktbase); /* TSC converted to nanoseconds */

	__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs), &ns,
			  sizeof(ns));

	return 0;
}

/*
 * u_long tm_getc(u_long_long *ticks_r)
 */

static int __tm_getc(struct task_struct *curr, struct pt_regs *regs)
{
	xnticks_t ticks;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(ticks)))
		return -EFAULT;

	ticks = xntbase_get_jiffies(psos_tbase);

	__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs), &ticks,
			  sizeof(ticks));

	return 0;
}

/*
 * u_long tm_signal(u_long value, u_long interval, int signo, u_long *tmid_r)
 */

static int __tm_signal(struct task_struct *curr, struct pt_regs *regs)
{
	u_long value = __xn_reg_arg1(regs);
	u_long interval = __xn_reg_arg2(regs);
	int signo = __xn_reg_arg3(regs);
	u_long err, tmid;
	psostm_t *tm;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg4(regs), sizeof(tmid)))
		return -EFAULT;

	if (value == 0)
		return 0;

	err = tm_start_signal_timer(value, interval, signo, &tmid);

	if (err == SUCCESS) {
		tm = (psostm_t *)tmid;
		/* Copy back the registry handle. */
		tmid = tm->handle;
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg4(regs), &tmid,
				  sizeof(tmid));
	}

	return err;
}

/*
 * u_long tm_set(u_long date, u_long time, u_long ticks)
 */

static int __tm_set(struct task_struct *curr, struct pt_regs *regs)
{
	u_long date, time, ticks;

	date = __xn_reg_arg1(regs);
	time = __xn_reg_arg2(regs);
	ticks = __xn_reg_arg3(regs);

	return tm_set(date, time, ticks);
}

/*
 * u_long tm_evwhen(u_long date, u_long time, u_long ticks, u_long events, u_long *tmid_r)
 */
static int __tm_evwhen(struct task_struct *curr, struct pt_regs *regs)
{
	u_long date, time, ticks, events, tmid, err;
	psostm_t *tm;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg5(regs), sizeof(tmid)))
		return -EFAULT;

	date = __xn_reg_arg1(regs);
	time = __xn_reg_arg2(regs);
	ticks = __xn_reg_arg3(regs);
	events = __xn_reg_arg4(regs);

	err = tm_evwhen(date, time, ticks, events, &tmid);

	if (err == SUCCESS) {
		tm = (psostm_t *)tmid;
		/* Copy back the registry handle. */
		tmid = tm->handle;
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg5(regs), &tmid,
				  sizeof(tmid));
	}

	return err;
}

/*
 * u_long tm_wkwhen(u_long date, u_long time, u_long ticks)
 */
static int __tm_wkwhen(struct task_struct *curr, struct pt_regs *regs)
{
	u_long date, time, ticks;

	date = __xn_reg_arg1(regs);
	time = __xn_reg_arg2(regs);
	ticks = __xn_reg_arg3(regs);

	return tm_wkwhen(date, time, ticks);
}

/*
 * u_long tm_evevery(u_long ticks, u_long events, u_long *tmid_r)
 */

static int __tm_evevery(struct task_struct *curr, struct pt_regs *regs)
{
	u_long ticks, events, tmid, err;
	psostm_t *tm;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg3(regs), sizeof(tmid)))
		return -EFAULT;

	ticks = __xn_reg_arg1(regs);
	events = __xn_reg_arg2(regs);

	err = tm_evevery(ticks, events, &tmid);

	if (err == SUCCESS) {
		tm = (psostm_t *)tmid;
		/* Copy back the registry handle. */
		tmid = tm->handle;
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg3(regs), &tmid,
				  sizeof(tmid));
	}

	return err;
}

/*
 * u_long rn_create(const char *name, struct sizeopt *szp, struct rninfo *rnip)
 */

static int __rn_create(struct task_struct *curr, struct pt_regs *regs)
{
	char name[XNOBJECT_NAME_LEN];
	struct {
		u_long rnsize;
		u_long usize;
		u_long flags;
	} sizeopt;
	struct {
		u_long rnid;
		u_long allocsz;
		void *rncb;
		u_long mapsize;
	} rninfo;
	psosrn_t *rn;
	u_long err;

	if (!__xn_access_ok(curr, VERIFY_READ, __xn_reg_arg1(regs), 4))
		return -EFAULT;

	/* Get region name. */
	__xn_strncpy_from_user(curr, name, (const char __user *)__xn_reg_arg1(regs),
			       sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg2(regs), sizeof(sizeopt)))
		return -EFAULT;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg3(regs), sizeof(rninfo)))
		return -EFAULT;

	__xn_copy_from_user(curr, &sizeopt, (void __user *)__xn_reg_arg2(regs),
			       sizeof(sizeopt));

	err = rn_create(name, NULL,
			sizeopt.rnsize,
			sizeopt.usize, sizeopt.flags,
			&rninfo.rnid, &rninfo.allocsz);

	if (err == SUCCESS) {
		rn = (psosrn_t *)rninfo.rnid;
		rn->mm = curr->mm;
		rninfo.rnid = rn->handle;
		rninfo.rncb = &rn->heapbase;
		rninfo.mapsize = xnheap_extentsize(&rn->heapbase);
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg3(regs), &rninfo,
				  sizeof(rninfo));
	}

	return err;
}

/*
 * u_long rn_delete(u_long rnid)
 */

static int __rn_delete(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	psosrn_t *rn;

	rn = (psosrn_t *)xnregistry_fetch(handle);

	if (!rn)
		return ERR_OBJID;

	return rn_delete((u_long)rn);
}

/*
 * int __rn_ident(const char *name, u_long *rnid_r)
 */

static int __rn_ident(struct task_struct *curr, struct pt_regs *regs)
{
	char name[XNOBJECT_NAME_LEN];
	u_long err, rnid;
	spl_t s;

	if (!__xn_access_ok(curr, VERIFY_READ, __xn_reg_arg1(regs), 4))
		return -EFAULT;

	/* Get region name. */
	__xn_strncpy_from_user(curr, name, (const char __user *)__xn_reg_arg1(regs),
			       sizeof(name));

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(rnid)))
		return -EFAULT;

	xnlock_get_irqsave(&nklock, s);

	err = rn_ident(name, &rnid);

	if (err == SUCCESS) {
		psosrn_t *rn = (psosrn_t *)rnid;
		rnid = rn->handle;
	}

	xnlock_put_irqrestore(&nklock, s);

	if (err == SUCCESS)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs), &rnid,
				  sizeof(rnid));
	return err;
}

/*
 * u_long rn_getseg(u_long rnid, u_long size, u_long flags,
 *                  u_long timeout, void **segaddr)
 */

static int __rn_getseg(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	u_long size, flags, timeout, err;
	void *segaddr;
	psosrn_t *rn;
	spl_t s;

	rn = (psosrn_t *)xnregistry_fetch(handle);

	if (!rn)
		return ERR_OBJID;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg5(regs), sizeof(segaddr)))
		return -EFAULT;

	size = __xn_reg_arg2(regs);
	flags = __xn_reg_arg3(regs);
	timeout = __xn_reg_arg4(regs);

	xnlock_get_irqsave(&nklock, s);

	err = rn_getseg((u_long)rn, size, flags, timeout, &segaddr);

	if (err == SUCCESS) {
		/* Convert pointer to user-space mapping. */
		segaddr = rn->mapbase + xnheap_mapped_offset(&rn->heapbase, segaddr);
		xnlock_put_irqrestore(&nklock, s);
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg5(regs), &segaddr,
				  sizeof(segaddr));
	} else
		xnlock_put_irqrestore(&nklock, s);

	return err;
}

/*
 * u_long rn_retseg(u_long rnid, void *segaddr)
 */

static int __rn_retseg(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	void *segaddr;
	psosrn_t *rn;
	spl_t s;

	segaddr = (void *)__xn_reg_arg2(regs);

	if (!segaddr)
		return ERR_SEGADDR;

	xnlock_get_irqsave(&nklock, s);

	rn = (psosrn_t *)xnregistry_fetch(handle);

	if (!rn) {
		xnlock_put_irqrestore(&nklock, s);
		return ERR_OBJID;
	}

	segaddr = xnheap_mapped_address(&rn->heapbase,
					(caddr_t) segaddr - rn->mapbase);
	xnlock_put_irqrestore(&nklock, s);

	return rn_retseg((u_long)rn, segaddr);
}

/*
 * u_long __rn_bind(u_long rnid, caddr_t mapbase)
 */

static int __rn_bind(struct task_struct *curr, struct pt_regs *regs)
{
	caddr_t mapbase = (caddr_t) __xn_reg_arg2(regs);
	u_long handle = __xn_reg_arg1(regs), err = 0;
	psosrn_t *rn;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	rn = (psosrn_t *)xnregistry_fetch(handle);

	if (rn && rn->mm == curr->mm)
		rn->mapbase = mapbase;
	else
		err = ERR_OBJID;

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/*
 * u_long __as_send(u_long tid, u_long signals)
 */

static int __as_send(struct task_struct *curr, struct pt_regs *regs)
{
	xnhandle_t handle = __xn_reg_arg1(regs);
	u_long signals = __xn_reg_arg2(regs);
	psostask_t *task;

	if (handle)
		task = (psostask_t *)xnregistry_fetch(handle);
	else
		task = __psos_task_current(curr);

	if (!task)
		return ERR_OBJID;

	return as_send((u_long)task, signals);
}

static void *psos_shadow_eventcb(int event, void *data)
{
	struct psos_resource_holder *rh;
	switch(event) {

	case XNSHADOW_CLIENT_ATTACH:

		rh = (struct psos_resource_holder *) xnarch_alloc_host_mem(sizeof(*rh));
		if (!rh)
			return ERR_PTR(-ENOMEM);

		initq(&rh->smq);
		initq(&rh->qq);
		initq(&rh->ptq);
		initq(&rh->rnq);

		return &rh->ppd;

	case XNSHADOW_CLIENT_DETACH:

		rh = ppd2rholder((xnshadow_ppd_t *) data);
		psos_sem_flush_rq(&rh->smq);
		psos_queue_flush_rq(&rh->qq);
		psos_pt_flush_rq(&rh->ptq);
		psos_rn_flush_rq(&rh->rnq);

		xnarch_free_host_mem(rh, sizeof(*rh));

		return NULL;
	}

	return ERR_PTR(-EINVAL);
}

static xnsysent_t __systab[] = {
	[__psos_t_create] = {&__t_create, __xn_exec_init},
	[__psos_t_start] = {&__t_start, __xn_exec_any},
	[__psos_t_delete] = {&__t_delete, __xn_exec_conforming},
	[__psos_t_suspend] = {&__t_suspend, __xn_exec_conforming},
	[__psos_t_resume] = {&__t_resume, __xn_exec_any},
	[__psos_t_ident] = {&__t_ident, __xn_exec_primary},
	[__psos_t_mode] = {&__t_mode, __xn_exec_primary},
	[__psos_t_setpri] = {&__t_setpri, __xn_exec_conforming},
	[__psos_ev_send] = {&__ev_send, __xn_exec_any},
	[__psos_ev_receive] = {&__ev_receive, __xn_exec_primary},
	[__psos_q_create] = {&__q_create, __xn_exec_any},
	[__psos_q_delete] = {&__q_delete, __xn_exec_any},
	[__psos_q_ident] = {&__q_ident, __xn_exec_any},
	[__psos_q_receive] = {&__q_receive, __xn_exec_primary},
	[__psos_q_send] = {&__q_send, __xn_exec_any},
	[__psos_q_urgent] = {&__q_urgent, __xn_exec_any},
	[__psos_q_broadcast] = {&__q_broadcast, __xn_exec_any},
	[__psos_q_vcreate] = {&__q_vcreate, __xn_exec_any},
	[__psos_q_vdelete] = {&__q_vdelete, __xn_exec_any},
	[__psos_q_vident] = {&__q_vident, __xn_exec_any},
	[__psos_q_vreceive] = {&__q_vreceive, __xn_exec_primary},
	[__psos_q_vsend] = {&__q_vsend, __xn_exec_any},
	[__psos_q_vurgent] = {&__q_vurgent, __xn_exec_any},
	[__psos_q_vbroadcast] = {&__q_vbroadcast, __xn_exec_any},
	[__psos_sm_create] = {&__sm_create, __xn_exec_any},
	[__psos_sm_delete] = {&__sm_delete, __xn_exec_any},
	[__psos_sm_p] = {&__sm_p, __xn_exec_primary},
	[__psos_sm_v] = {&__sm_v, __xn_exec_any},
	[__psos_rn_create] = {&__rn_create, __xn_exec_lostage},
	[__psos_rn_delete] = {&__rn_delete, __xn_exec_lostage},
	[__psos_rn_ident] = {&__rn_ident, __xn_exec_any},
	[__psos_rn_getseg] = {&__rn_getseg, __xn_exec_any},
	[__psos_rn_retseg] = {&__rn_retseg, __xn_exec_any},
	[__psos_rn_bind] = {&__rn_bind, __xn_exec_any},
	[__psos_tm_wkafter] = {&__tm_wkafter, __xn_exec_primary},
	[__psos_tm_cancel] = {&__tm_cancel, __xn_exec_any},
	[__psos_tm_evafter] = {&__tm_evafter, __xn_exec_primary},
	[__psos_tm_get] = {&__tm_get, __xn_exec_any},
	[__psos_tm_set] = {&__tm_set, __xn_exec_any},
	[__psos_tm_evwhen] = {&__tm_evwhen, __xn_exec_primary},
	[__psos_tm_wkwhen] = {&__tm_wkwhen, __xn_exec_primary},
	[__psos_tm_evevery] = {&__tm_evevery, __xn_exec_primary},
	[__psos_tm_getm] = {&__tm_getm, __xn_exec_any},
	[__psos_tm_signal] = {&__tm_signal, __xn_exec_primary},
	[__psos_as_send] = {&__as_send, __xn_exec_conforming},
	[__psos_tm_getc] = {&__tm_getc, __xn_exec_any},
};

extern xntbase_t *psos_tbase;

static struct xnskin_props __props = {
	.name = "psos",
	.magic = PSOS_SKIN_MAGIC,
	.nrcalls = sizeof(__systab) / sizeof(__systab[0]),
	.systab = __systab,
	.eventcb = &psos_shadow_eventcb,
	.timebasep = &psos_tbase,
	.module = THIS_MODULE
};

static void __shadow_delete_hook(xnthread_t *thread)
{
	if (xnthread_get_magic(thread) == PSOS_SKIN_MAGIC &&
	    xnthread_test_state(thread, XNMAPPED))
		xnshadow_unmap(thread);
}

int psos_syscall_init(void)
{
	__psos_muxid = xnshadow_register_interface(&__props);

	if (__psos_muxid < 0)
		return -ENOSYS;

	xnpod_add_hook(XNHOOK_THREAD_DELETE, &__shadow_delete_hook);

	return 0;
}

void psos_syscall_cleanup(void)
{
	xnpod_remove_hook(XNHOOK_THREAD_DELETE, &__shadow_delete_hook);
	xnshadow_unregister_interface(__psos_muxid);
}
