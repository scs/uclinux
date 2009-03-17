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
#include <vrtx/defs.h>
#include <vrtx/task.h>
#include <vrtx/heap.h>
#include <vrtx/pt.h>
#include <vrtx/syscall.h>

extern xnmap_t *vrtx_heap_idmap;

extern xnmap_t *vrtx_pt_idmap;

/*
 * By convention, error codes are passed back through the syscall
 * return value:
 * - negative codes stand for internal (i.e. nucleus) errors;
 * - strictly positive values stand for genuine VRTX errors.
 * - zero means success.
 */

static int __muxid;

/*
 * int __sc_tecreate(struct vrtx_arg_bulk *bulk,
 *                   int *ptid,
 *                   xncompletion_t *completion)
 * bulk = {
 * a1: int tid;
 * a2: int prio;
 * a3: int mode;
 * }
 */

static int __sc_tecreate(struct task_struct *curr, struct pt_regs *regs)
{
	xncompletion_t __user *u_completion;
	struct vrtx_arg_bulk bulk;
	int prio, mode, tid, err;
	vrtxtask_t *task;

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg1(regs), sizeof(bulk)))
		return -EFAULT;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(tid)))
		return -EFAULT;

	__xn_copy_from_user(curr, &bulk, (void __user *)__xn_reg_arg1(regs),
			    sizeof(bulk));

	/* Suggested task id. */
	tid = bulk.a1;
	/* Task priority. */
	prio = bulk.a2;
	/* Task mode. */
	mode = bulk.a3 | 0x100;

	/* Completion descriptor our parent thread is pending on. */
	u_completion = (xncompletion_t __user *)__xn_reg_arg3(regs);

	task = xnmalloc(sizeof(*task));

	if (!task) {
		err = ER_TCB;
		goto done;
	}

	xnthread_clear_state(&task->threadbase, XNZOMBIE);

	tid =
	    sc_tecreate_inner(task, NULL, tid, prio, mode, 0, 0, NULL, 0, &err);

	if (tid < 0) {
		if (u_completion)
			xnshadow_signal_completion(u_completion, err);
	} else {
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs),
				  &tid, sizeof(tid));
		err = xnshadow_map(&task->threadbase, u_completion);
	}

	if (err && !xnthread_test_state(&task->threadbase, XNZOMBIE))
		xnfree(task);

      done:

	return err;
}

/*
 * int __sc_tdelete(int tid, int opt)
 */

static int __sc_tdelete(struct task_struct *curr, struct pt_regs *regs)
{
	int err, tid, opt;

	tid = __xn_reg_arg1(regs);
	opt = __xn_reg_arg2(regs);
	sc_tdelete(tid, opt, &err);

	return err;
}

/*
 * int __sc_tpriority(int tid, int prio)
 */

static int __sc_tpriority(struct task_struct *curr, struct pt_regs *regs)
{
	int err, tid, prio;

	tid = __xn_reg_arg1(regs);
	prio = __xn_reg_arg2(regs);
	sc_tpriority(tid, prio, &err);

	return err;
}

/*
 * int __sc_tresume(int tid, int opt)
 */

static int __sc_tresume(struct task_struct *curr, struct pt_regs *regs)
{
	int err, tid, opt;

	tid = __xn_reg_arg1(regs);
	opt = __xn_reg_arg2(regs);
	sc_tpriority(tid, opt, &err);

	return err;
}

/*
 * int __sc_tsuspend(int tid, int opt)
 */

static int __sc_tsuspend(struct task_struct *curr, struct pt_regs *regs)
{
	int err, tid, opt;

	tid = __xn_reg_arg1(regs);
	opt = __xn_reg_arg2(regs);
	sc_tsuspend(tid, opt, &err);

	return err;
}

/*
 * int __sc_tslice(unsigned short ticks)
 */

static int __sc_tslice(struct task_struct *curr, struct pt_regs *regs)
{
	unsigned short ticks;

	ticks = (unsigned short)__xn_reg_arg1(regs);
	sc_tslice(ticks);

	return 0;
}

/*
 * int __sc_tinquiry(int pinfo[], TCB *tcb, int tid)
 */

static int __sc_tinquiry(struct task_struct *curr, struct pt_regs *regs)
{
	int err, tid, pinfo[3];
	TCB *tcb;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(pinfo)))
		return -EFAULT;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(*tcb)))
		return -EFAULT;

	tid = __xn_reg_arg3(regs);
	tcb = sc_tinquiry(pinfo, tid, &err);

	if (!err) {
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs),
				  pinfo, sizeof(pinfo));
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs), tcb,
				  sizeof(*tcb));
	}

	return err;
}

/*
 * int __sc_lock(void)
 */

static int __sc_lock(struct task_struct *curr, struct pt_regs *regs)
{
	sc_lock();
	return 0;
}

/*
 * int __sc_unlock(void)
 */

static int __sc_unlock(struct task_struct *curr, struct pt_regs *regs)
{
	sc_unlock();
	return 0;
}

/*
 * int __sc_delay(long timeout)
 */

static int __sc_delay(struct task_struct *curr, struct pt_regs *regs)
{
	vrtxtask_t *task = vrtx_current_task();
	sc_delay(__xn_reg_arg1(regs));
	if (xnthread_test_info(&task->threadbase, XNBREAK))
		return -EINTR;
	return 0;
}

/*
 * int __sc_adelay(struct timespec *time)
 */

static int __sc_adelay(struct task_struct *curr, struct pt_regs *regs)
{
	struct timespec time;
	int err;

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg1(regs), sizeof(time)))
		return -EFAULT;

	__xn_copy_from_user(curr, &time, (void __user *)__xn_reg_arg1(regs),
			    sizeof(time));

	sc_adelay(time, &err);

	return err;
}

/*
 * int __sc_stime(unsigned long ticks)
 */

static int __sc_stime(struct task_struct *curr, struct pt_regs *regs)
{
	sc_stime(__xn_reg_arg1(regs));
	return 0;
}

/*
 * int __sc_gtime(unsigned long *ticks_p)
 */

static int __sc_gtime(struct task_struct *curr, struct pt_regs *regs)
{
	unsigned long ticks;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(ticks)))
		return -EFAULT;

	ticks = sc_gtime();

	__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs), &ticks,
			  sizeof(ticks));
	return 0;
}

/*
 * int __sc_sclock(struct timespec *time, unsigned long ns)
 */

static int __sc_sclock(struct task_struct *curr, struct pt_regs *regs)
{
	struct timespec time;
	unsigned long ns;
	int err;

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg1(regs), sizeof(time)))
		return -EFAULT;

	__xn_copy_from_user(curr, &time, (void __user *)__xn_reg_arg1(regs),
			    sizeof(time));

	ns = __xn_reg_arg1(regs);

	sc_sclock(time, ns, &err);

	return err;
}

/*
 * int __sc_gclock(struct timespec *time, unsigned long ns)
 */

static int __sc_gclock(struct task_struct *curr, struct pt_regs *regs)
{
	struct timespec time;
	unsigned long ns;
	int err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(time)))
		return -EFAULT;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(ns)))
		return -EFAULT;

	sc_gclock(&time, &ns, &err);

	if (!err) {
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs),
				  &time, sizeof(time));
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs), &ns,
				  sizeof(ns));
	}

	return err;
}

/*
 * int __sc_mcreate(int opt, int *mid)
 */

static int __sc_mcreate(struct task_struct *curr, struct pt_regs *regs)
{
	int opt = __xn_reg_arg1(regs), mid, err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(mid)))
		return -EFAULT;

	mid = sc_mcreate(opt, &err);

	if (!err)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs),
				  &mid, sizeof(mid));
	return err;
}

/*
 * int __sc_mdelete(int mid, int opt)
 */

static int __sc_mdelete(struct task_struct *curr, struct pt_regs *regs)
{
	int opt, mid, err;

	mid = __xn_reg_arg1(regs);
	opt = __xn_reg_arg2(regs);
	sc_mdelete(mid, opt, &err);

	return err;
}

/*
 * int __sc_mpost(int mid)
 */

static int __sc_mpost(struct task_struct *curr, struct pt_regs *regs)
{
	int mid, err;

	mid = __xn_reg_arg1(regs);
	sc_mpost(mid, &err);

	return err;
}

/*
 * int __sc_maccept(int mid)
 */

static int __sc_maccept(struct task_struct *curr, struct pt_regs *regs)
{
	int mid, err;

	mid = __xn_reg_arg1(regs);
	sc_maccept(mid, &err);

	return err;
}

/*
 * int __sc_mpend(int mid, unsigned long timeout)
 */

static int __sc_mpend(struct task_struct *curr, struct pt_regs *regs)
{
	unsigned long timeout;
	int mid, err;

	mid = __xn_reg_arg1(regs);
	timeout = __xn_reg_arg2(regs);
	sc_mpend(mid, timeout, &err);

	return err;
}

/*
 * int __sc_minquiry(int mid, int *statusp)
 */

static int __sc_minquiry(struct task_struct *curr, struct pt_regs *regs)
{
	int mid, status, err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(status)))
		return -EFAULT;

	mid = __xn_reg_arg1(regs);
	status = sc_minquiry(mid, &err);

	if (!err)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs),
				  &status, sizeof(status));
	return err;
}

/*
 * int __sc_qecreate(int qid, int qsize, int opt, int *qidp)
 */

static int __sc_qecreate(struct task_struct *curr, struct pt_regs *regs)
{
	int qid, qsize, opt, err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg4(regs), sizeof(qid)))
		return -EFAULT;

	qid = __xn_reg_arg1(regs);
	qsize = __xn_reg_arg2(regs);
	opt = __xn_reg_arg3(regs);
	qid = sc_qecreate(qid, qsize, opt, &err);

	if (!err)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg4(regs),
				  &qid, sizeof(qid));
	return err;
}

/*
 * int __sc_qdelete(int qid, int opt)
 */

static int __sc_qdelete(struct task_struct *curr, struct pt_regs *regs)
{
	int qid, opt, err;

	qid = __xn_reg_arg1(regs);
	opt = __xn_reg_arg2(regs);
	sc_qdelete(qid, opt, &err);

	return err;
}

/*
 * int __sc_qpost(int qid, char *msg)
 */

static int __sc_qpost(struct task_struct *curr, struct pt_regs *regs)
{
	int qid, err;
	char *msg;

	qid = __xn_reg_arg1(regs);
	msg = (char *)__xn_reg_arg2(regs);
	sc_qpost(qid, msg, &err);

	return err;
}

/*
 * int __sc_qbrdcst(int qid, char *msg)
 */

static int __sc_qbrdcst(struct task_struct *curr, struct pt_regs *regs)
{
	int qid, err;
	char *msg;

	qid = __xn_reg_arg1(regs);
	msg = (char *)__xn_reg_arg2(regs);
	sc_qbrdcst(qid, msg, &err);

	return err;
}

/*
 * int __sc_qjam(int qid, char *msg)
 */

static int __sc_qjam(struct task_struct *curr, struct pt_regs *regs)
{
	int qid, err;
	char *msg;

	qid = __xn_reg_arg1(regs);
	msg = (char *)__xn_reg_arg2(regs);
	sc_qjam(qid, msg, &err);

	return err;
}

/*
 * int __sc_qpend(int qid, unsigned long timeout, char **msgp)
 */

static int __sc_qpend(struct task_struct *curr, struct pt_regs *regs)
{
	long timeout;
	int qid, err;
	char *msg;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg3(regs), sizeof(msg)))
		return -EFAULT;

	qid = __xn_reg_arg1(regs);
	timeout = __xn_reg_arg2(regs);
	msg = sc_qpend(qid, timeout, &err);

	if (!err)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg3(regs),
				  &msg, sizeof(msg));
	return err;
}

/*
 * int __sc_qaccept(int qid, char **msgp)
 */

static int __sc_qaccept(struct task_struct *curr, struct pt_regs *regs)
{
	int qid, err;
	char *msg;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(msg)))
		return -EFAULT;

	qid = __xn_reg_arg1(regs);
	msg = sc_qaccept(qid, &err);

	if (!err)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs),
				  &msg, sizeof(msg));
	return err;
}

/*
 * int __sc_qinquiry(int qid, int *countp, char **msgp)
 */

static int __sc_qinquiry(struct task_struct *curr, struct pt_regs *regs)
{
	int qid, count, err;
	char *msg;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(count)))
		return -EFAULT;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg3(regs), sizeof(msg)))
		return -EFAULT;

	qid = __xn_reg_arg1(regs);
	msg = sc_qinquiry(qid, &count, &err);

	if (!err) {
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs),
				  &count, sizeof(count));
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg3(regs),
				  &msg, sizeof(msg));
	}

	return err;
}

/*
 * int __sc_post(char **mboxp, char *msg)
 */

static int __sc_post(struct task_struct *curr, struct pt_regs *regs)
{
	char **mboxp, *msg;
	int err;

	/* We should be able to write to a mailbox storage, even if we
	 * actually don't. */
	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(msg)))
		return -EFAULT;

	mboxp = (char **)__xn_reg_arg1(regs);
	msg = (char *)__xn_reg_arg2(regs);
	sc_post(mboxp, msg, &err);

	return err;
}

/*
 * int __sc_accept(char **mboxp, char **msgp)
 */

static int __sc_accept(struct task_struct *curr, struct pt_regs *regs)
{
	char **mboxp, *msg;
	int err;

	/* We should be able to write to a mailbox storage, even if we
	 * actually don't. */
	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(msg)))
		return -EFAULT;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(msg)))
		return -EFAULT;

	mboxp = (char **)__xn_reg_arg1(regs);
	msg = sc_accept(mboxp, &err);

	if (!err)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs),
				  &msg, sizeof(msg));
	return err;
}

/*
 * int __sc_pend(char **mboxp, long timeout, char **msgp)
 */

static int __sc_pend(struct task_struct *curr, struct pt_regs *regs)
{
	char **mboxp, *msg;
	long timeout;
	int err;

	/* We should be able to write to a mailbox storage, even if we
	 * actually don't. */
	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(msg)))
		return -EFAULT;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg3(regs), sizeof(msg)))
		return -EFAULT;

	mboxp = (char **)__xn_reg_arg1(regs);
	timeout = __xn_reg_arg2(regs);
	msg = sc_pend(mboxp, timeout, &err);

	if (!err)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg3(regs),
				  &msg, sizeof(msg));
	return err;
}

/*
 * int __sc_fcreate(int *fidp)
 */

static int __sc_fcreate(struct task_struct *curr, struct pt_regs *regs)
{
	int fid, err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(fid)))
		return -EFAULT;

	fid = sc_fcreate(&err);

	if (!err)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs),
				  &fid, sizeof(fid));
	return err;
}

/*
 * int __sc_fdelete(int fid, int opt)
 */

static int __sc_fdelete(struct task_struct *curr, struct pt_regs *regs)
{
	int fid, opt, err;

	fid = __xn_reg_arg1(regs);
	opt = __xn_reg_arg2(regs);
	sc_fdelete(fid, opt, &err);

	return err;
}

/*
 * int __sc_fpost(int fid, int mask)
 */

static int __sc_fpost(struct task_struct *curr, struct pt_regs *regs)
{
	int fid, mask, err;

	fid = __xn_reg_arg1(regs);
	mask = __xn_reg_arg2(regs);
	sc_fpost(fid, mask, &err);

	return err;
}

/*
 * int __sc_fpend(int fid, long timeout, int mask, int opt, int *mask_r)
 */

static int __sc_fpend(struct task_struct *curr, struct pt_regs *regs)
{
	int fid, mask, mask_r, opt, err;
	long timeout;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg5(regs), sizeof(mask_r)))
		return -EFAULT;

	fid = __xn_reg_arg1(regs);
	timeout = __xn_reg_arg2(regs);
	mask = __xn_reg_arg3(regs);
	opt = __xn_reg_arg4(regs);
	mask_r = sc_fpend(fid, timeout, mask, opt, &err);

	if (!err)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg5(regs),
				  &mask_r, sizeof(mask_r));
	return err;
}

/*
 * int __sc_fclear(int fid, int mask, int *mask_r)
 */

static int __sc_fclear(struct task_struct *curr, struct pt_regs *regs)
{
	int fid, mask, mask_r, err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg3(regs), sizeof(mask_r)))
		return -EFAULT;

	fid = __xn_reg_arg1(regs);
	mask = __xn_reg_arg2(regs);
	mask_r = sc_fclear(fid, mask, &err);

	if (!err)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg3(regs),
				  &mask_r, sizeof(mask_r));
	return err;
}

/*
 * int __sc_finquiry(int fid, int *mask_r)
 */

static int __sc_finquiry(struct task_struct *curr, struct pt_regs *regs)
{
	int fid, mask_r, err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(mask_r)))
		return -EFAULT;

	fid = __xn_reg_arg1(regs);
	mask_r = sc_finquiry(fid, &err);

	if (!err)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs),
				  &mask_r, sizeof(mask_r));
	return err;
}

/*
 * int __sc_screate(unsigned initval, int opt, int *semidp)
 */

static int __sc_screate(struct task_struct *curr, struct pt_regs *regs)
{
	int semid, opt, err;
	unsigned initval;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg3(regs), sizeof(semid)))
		return -EFAULT;

	initval = __xn_reg_arg1(regs);
	opt = __xn_reg_arg2(regs);
	semid = sc_screate(initval, opt, &err);

	if (!err)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg3(regs),
				  &semid, sizeof(semid));
	return err;
}

/*
 * int __sc_sdelete(int semid, int opt)
 */

static int __sc_sdelete(struct task_struct *curr, struct pt_regs *regs)
{
	int semid, opt, err;

	semid = __xn_reg_arg1(regs);
	opt = __xn_reg_arg2(regs);
	sc_sdelete(semid, opt, &err);

	return err;
}

/*
 * int __sc_spost(int semid)
 */

static int __sc_spost(struct task_struct *curr, struct pt_regs *regs)
{
	int semid, err;

	semid = __xn_reg_arg1(regs);
	sc_spost(semid, &err);

	return err;
}

/*
 * int __sc_spend(int semid, long timeout)
 */

static int __sc_spend(struct task_struct *curr, struct pt_regs *regs)
{
	int semid, err;
	long timeout;

	semid = __xn_reg_arg1(regs);
	timeout = __xn_reg_arg2(regs);
	sc_spend(semid, timeout, &err);

	return err;
}

/*
 * int __sc_saccept(int semid)
 */

static int __sc_saccept(struct task_struct *curr, struct pt_regs *regs)
{
	int semid, err;

	semid = __xn_reg_arg1(regs);
	sc_saccept(semid, &err);

	return err;
}

/*
 * int __sc_sinquiry(int semid, int *count_r)
 */

static int __sc_sinquiry(struct task_struct *curr, struct pt_regs *regs)
{
	int semid, count_r, err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(count_r)))
		return -EFAULT;

	semid = __xn_reg_arg1(regs);
	count_r = sc_sinquiry(semid, &err);

	if (!err)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs),
				  &count_r, sizeof(count_r));
	return err;
}

/*
 * int __sc_hcreate(u_long heapsize, unsigned log2psize, vrtx_hdesc_t *hdesc)
 */

static int __sc_hcreate(struct task_struct *curr, struct pt_regs *regs)
{
	unsigned log2psize;
	vrtx_hdesc_t hdesc;
	vrtxheap_t *heap;
	u_long heapsize;
	int err, hid;
	spl_t s;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg3(regs), sizeof(hdesc)))
		return -EFAULT;

	/* Size of heap space. */
	heapsize = __xn_reg_arg1(regs);
	/* Page size. */
	log2psize = (int)__xn_reg_arg2(regs);

	hid = sc_hcreate(NULL, heapsize, log2psize, &err);

	if (err)
		return err;

	xnlock_get_irqsave(&nklock, s);

	heap = xnmap_fetch(vrtx_heap_idmap, hid);

	if (heap) {		/* Paranoid. */
		heap->mm = curr->mm;
		hdesc.hid = hid;
		hdesc.hcb = &heap->sysheap;
		hdesc.hsize = xnheap_extentsize(&heap->sysheap);

		xnlock_put_irqrestore(&nklock, s);

		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg3(regs),
				  &hdesc, sizeof(hdesc));
	} else {
		xnlock_put_irqrestore(&nklock, s);
		err = ER_ID;
	}

	return err;
}

/*
 * int __sc_hbind(int hid, caddr_t mapbase)
 */

static int __sc_hbind(struct task_struct *curr, struct pt_regs *regs)
{
	caddr_t mapbase = (caddr_t) __xn_reg_arg2(regs);
	int hid = __xn_reg_arg1(regs), err = 0;
	vrtxheap_t *heap;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	heap = xnmap_fetch(vrtx_heap_idmap, hid);

	if (heap && heap->mm == curr->mm)
		heap->mapbase = mapbase;
	else
		err = ER_ID;

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/*
 * int __sc_hdelete(int hid, int opt)
 */

static int __sc_hdelete(struct task_struct *curr, struct pt_regs *regs)
{
	int err, hid, opt;

	hid = __xn_reg_arg1(regs);
	opt = __xn_reg_arg2(regs);
	sc_hdelete(hid, opt, &err);

	return err;
}

/*
 * int __sc_halloc(int hid, unsigned long bsize, char **bufp)
 */

static int __sc_halloc(struct task_struct *curr, struct pt_regs *regs)
{
	vrtxheap_t *heap;
	char *buf = NULL;
	u_long bsize;
	int err, hid;
	spl_t s;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg3(regs), sizeof(buf)))
		return -EFAULT;

	hid = __xn_reg_arg1(regs);
	bsize = (u_long)__xn_reg_arg2(regs);

	xnlock_get_irqsave(&nklock, s);

	heap = xnmap_fetch(vrtx_heap_idmap, hid);

	if (!heap || heap->mm != curr->mm) {
		/* Allocation requests must be issued from the same
		 * process which created the heap. */
		err = ER_ID;
		goto unlock_and_exit;
	}

	buf = sc_halloc(hid, bsize, &err);

	/* Convert the allocated buffer kernel-based address to the
	   equivalent area into the caller's address space. */

	if (!err)
		buf = heap->mapbase + xnheap_mapped_offset(&heap->sysheap, buf);

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	__xn_copy_to_user(curr, (void __user *)__xn_reg_arg3(regs), &buf,
			  sizeof(buf));

	return err;
}

/*
 * int __sc_hfree(int hid, char *buf)
 */

static int __sc_hfree(struct task_struct *curr, struct pt_regs *regs)
{
	char __user *buf;
	vrtxheap_t *heap;
	int hid, err;
	spl_t s;

	hid = __xn_reg_arg1(regs);
	buf = (char __user *)__xn_reg_arg2(regs);

	xnlock_get_irqsave(&nklock, s);

	heap = xnmap_fetch(vrtx_heap_idmap, hid);

	if (!heap || heap->mm != curr->mm) {
		/* Deallocation requests must be issued from the same
		 * process which created the heap. */
		err = ER_ID;
		goto unlock_and_exit;
	}

	/* Convert the caller-based address of buf to the equivalent area
	   into the kernel address space. */

	if (buf) {
		buf =
		    xnheap_mapped_address(&heap->sysheap,
					  (caddr_t) buf - heap->mapbase);
		sc_hfree(hid, buf, &err);
	} else
		err = ER_NMB;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/*
 * int __sc_hinquiry(int info[3], int hid)
 */

static int __sc_hinquiry(struct task_struct *curr, struct pt_regs *regs)
{
	int err, hid, pinfo[3];

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(pinfo)))
		return -EFAULT;

	hid = __xn_reg_arg2(regs);
	sc_tinquiry(pinfo, hid, &err);

	if (!err)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs),
				  pinfo, sizeof(pinfo));

	return err;
}

/*
 * int __sc_pcreate(int pid, long ptsize, long bsize, vrtx_pdesc_t *pdesc)
 */

static int __sc_pcreate(struct task_struct *curr, struct pt_regs *regs)
{
	u_long ptsize, bsize;
	vrtx_pdesc_t pdesc;
	xnheap_t *ptheap;
	vrtxpt_t *pt;
	int err, pid;
	char *ptaddr;
	spl_t s;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg4(regs), sizeof(pdesc)))
		return -EFAULT;

	ptheap = (xnheap_t *)xnmalloc(sizeof(*ptheap));

	if (!ptheap)
		return ER_MEM;

	/* Suggested partition ID. */
	pid = __xn_reg_arg1(regs);
	/* Size of partition space -- account for the heap mgmt overhead. */
	ptsize = __xn_reg_arg2(regs);
	/* Shared heaps use the natural page size (PAGE_SIZE) */
	ptsize = xnheap_rounded_size(ptsize, PAGE_SIZE);
	/* Block size. */
	bsize = __xn_reg_arg3(regs);

	err = xnheap_init_mapped(ptheap, ptsize, 0);

	if (err)
		goto free_heap;

	/* Allocate the partition space as a single shared heap block. */
	ptaddr = xnheap_alloc(ptheap, ptsize);
	pid = sc_pcreate(pid, ptaddr, ptsize, bsize, &err);

	if (err)
		goto unmap_pt;

	xnlock_get_irqsave(&nklock, s);

	pt = xnmap_fetch(vrtx_pt_idmap, pid);

	if (pt) {		/* Paranoid. */
		pt->mm = curr->mm;
		pt->sysheap = ptheap;
		pdesc.pid = pid;
		pdesc.ptcb = ptheap;
		pdesc.ptsize = xnheap_extentsize(ptheap);

		xnlock_put_irqrestore(&nklock, s);

		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg4(regs),
				  &pdesc, sizeof(pdesc));
		return 0;
	}

	xnlock_put_irqrestore(&nklock, s);

	err = ER_PID;

unmap_pt:

	xnheap_destroy_mapped(ptheap, NULL, NULL);

free_heap:

	xnfree(ptheap);

	return err;
}

/*
 * int __sc_pbind(int pid, caddr_t mapbase)
 */

static int __sc_pbind(struct task_struct *curr, struct pt_regs *regs)
{
	caddr_t mapbase = (caddr_t) __xn_reg_arg2(regs);
	int pid = __xn_reg_arg1(regs), err = 0;
	vrtxpt_t *pt;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	pt = xnmap_fetch(vrtx_pt_idmap, pid);

	if (pt && pt->mm == curr->mm)
		pt->mapbase = mapbase;
	else
		err = ER_PID;

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/*
 * int __sc_pdelete(int pid, int opt)
 */

static int __sc_pdelete(struct task_struct *curr, struct pt_regs *regs)
{
	int err, pid, opt;

	pid = __xn_reg_arg1(regs);
	opt = __xn_reg_arg2(regs);
	sc_pdelete(pid, opt, &err);

	return err;
}

/*
 * int __sc_gblock(int pid, char **bufp)
 */

static int __sc_gblock(struct task_struct *curr, struct pt_regs *regs)
{
	char *buf = NULL;
	vrtxpt_t *pt;
	int err, pid;
	spl_t s;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(buf)))
		return -EFAULT;

	pid = __xn_reg_arg1(regs);

	xnlock_get_irqsave(&nklock, s);

	pt = xnmap_fetch(vrtx_pt_idmap, pid);

	if (!pt || pt->mm != curr->mm) {
		/* Allocation requests must be issued from the same
		 * process which created the partition. */
		err = ER_PID;
		goto unlock_and_exit;
	}

	buf = sc_gblock(pid, &err);

	/* Convert the allocated buffer kernel-based address to the
	   equivalent area into the caller's address space. */

	if (!err)
		buf = pt->mapbase + xnheap_mapped_offset(pt->sysheap, buf);

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs), &buf,
			  sizeof(buf));

	return err;
}

/*
 * int __sc_rblock(int pid, char *buf)
 */

static int __sc_rblock(struct task_struct *curr, struct pt_regs *regs)
{
	char __user *buf;
	vrtxpt_t *pt;
	int pid, err;
	spl_t s;

	pid = __xn_reg_arg1(regs);
	buf = (char __user *)__xn_reg_arg2(regs);

	xnlock_get_irqsave(&nklock, s);

	pt = xnmap_fetch(vrtx_pt_idmap, pid);

	if (!pt || pt->mm != curr->mm) {
		/* Deallocation requests must be issued from the same
		 * process which created the partition. */
		err = ER_ID;
		goto unlock_and_exit;
	}

	/* Convert the caller-based address of buf to the equivalent area
	   into the kernel address space. */

	if (buf) {
		buf =
		    xnheap_mapped_address(pt->sysheap,
					  (caddr_t) buf - pt->mapbase);
		sc_rblock(pid, buf, &err);
	} else
		err = ER_NMB;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/*
 * int __sc_pinquiry(u_long info[3], int pid)
 */

static int __sc_pinquiry(struct task_struct *curr, struct pt_regs *regs)
{
	u_long pinfo[3];
	int err, pid;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(pinfo)))
		return -EFAULT;

	pid = __xn_reg_arg2(regs);
	sc_pinquiry(pinfo, pid, &err);

	if (!err)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs),
				  pinfo, sizeof(pinfo));

	return err;
}

static xnsysent_t __systab[] = {
	[__vrtx_tecreate] = {&__sc_tecreate, __xn_exec_init},
	[__vrtx_tdelete] = {&__sc_tdelete, __xn_exec_conforming},
	[__vrtx_tpriority] = {&__sc_tpriority, __xn_exec_primary},
	[__vrtx_tresume] = {&__sc_tresume, __xn_exec_any},
	[__vrtx_tsuspend] = {&__sc_tsuspend, __xn_exec_conforming},
	[__vrtx_tslice] = {&__sc_tslice, __xn_exec_any},
	[__vrtx_tinquiry] = {&__sc_tinquiry, __xn_exec_primary},
	[__vrtx_lock] = {&__sc_lock, __xn_exec_primary},
	[__vrtx_unlock] = {&__sc_unlock, __xn_exec_primary},
	[__vrtx_delay] = {&__sc_delay, __xn_exec_primary},
	[__vrtx_adelay] = {&__sc_adelay, __xn_exec_primary},
	[__vrtx_stime] = {&__sc_stime, __xn_exec_any},
	[__vrtx_gtime] = {&__sc_gtime, __xn_exec_any},
	[__vrtx_sclock] = {&__sc_sclock, __xn_exec_any},
	[__vrtx_gclock] = {&__sc_gclock, __xn_exec_any},
	[__vrtx_mcreate] = {&__sc_mcreate, __xn_exec_any},
	[__vrtx_mdelete] = {&__sc_mdelete, __xn_exec_any},
	[__vrtx_mpost] = {&__sc_mpost, __xn_exec_primary},
	[__vrtx_maccept] = {&__sc_maccept, __xn_exec_primary},
	[__vrtx_mpend] = {&__sc_mpend, __xn_exec_primary},
	[__vrtx_minquiry] = {&__sc_minquiry, __xn_exec_any},
	[__vrtx_qecreate] = {&__sc_qecreate, __xn_exec_any},
	[__vrtx_qdelete] = {&__sc_qdelete, __xn_exec_any},
	[__vrtx_qpost] = {&__sc_qpost, __xn_exec_any},
	[__vrtx_qbrdcst] = {&__sc_qbrdcst, __xn_exec_any},
	[__vrtx_qjam] = {&__sc_qjam, __xn_exec_any},
	[__vrtx_qpend] = {&__sc_qpend, __xn_exec_primary},
	[__vrtx_qaccept] = {&__sc_qaccept, __xn_exec_any},
	[__vrtx_qinquiry] = {&__sc_qinquiry, __xn_exec_any},
	[__vrtx_post] = {&__sc_post, __xn_exec_any},
	[__vrtx_accept] = {&__sc_accept, __xn_exec_any},
	[__vrtx_pend] = {&__sc_pend, __xn_exec_primary},
	[__vrtx_fcreate] = {&__sc_fcreate, __xn_exec_any},
	[__vrtx_fdelete] = {&__sc_fdelete, __xn_exec_any},
	[__vrtx_fpost] = {&__sc_fpost, __xn_exec_any},
	[__vrtx_fpend] = {&__sc_fpend, __xn_exec_primary},
	[__vrtx_fclear] = {&__sc_fclear, __xn_exec_any},
	[__vrtx_finquiry] = {&__sc_finquiry, __xn_exec_any},
	[__vrtx_screate] = {&__sc_screate, __xn_exec_any},
	[__vrtx_sdelete] = {&__sc_sdelete, __xn_exec_any},
	[__vrtx_spost] = {&__sc_spost, __xn_exec_any},
	[__vrtx_spend] = {&__sc_spend, __xn_exec_primary},
	[__vrtx_saccept] = {&__sc_saccept, __xn_exec_any},
	[__vrtx_sinquiry] = {&__sc_sinquiry, __xn_exec_any},
	[__vrtx_hcreate] = {&__sc_hcreate, __xn_exec_lostage},
	[__vrtx_hbind] = {&__sc_hbind, __xn_exec_any},
	[__vrtx_hdelete] = {&__sc_hdelete, __xn_exec_lostage},
	[__vrtx_halloc] = {&__sc_halloc, __xn_exec_conforming},
	[__vrtx_hfree] = {&__sc_hfree, __xn_exec_any},
	[__vrtx_hinquiry] = {&__sc_hinquiry, __xn_exec_any},
	[__vrtx_pcreate] = {&__sc_pcreate, __xn_exec_lostage},
	[__vrtx_pbind] = {&__sc_pbind, __xn_exec_any},
	[__vrtx_pdelete] = {&__sc_pdelete, __xn_exec_lostage},
	[__vrtx_gblock] = {&__sc_gblock, __xn_exec_conforming},
	[__vrtx_rblock] = {&__sc_rblock, __xn_exec_any},
	[__vrtx_pinquiry] = {&__sc_pinquiry, __xn_exec_any},
};

extern xntbase_t *vrtx_tbase;

static struct xnskin_props __props = {
	.name = "vrtx",
	.magic = VRTX_SKIN_MAGIC,
	.nrcalls = sizeof(__systab) / sizeof(__systab[0]),
	.systab = __systab,
	.eventcb = NULL,
	.timebasep = &vrtx_tbase,
	.module = THIS_MODULE
};

static void __shadow_delete_hook(xnthread_t *thread)
{
	if (xnthread_get_magic(thread) == VRTX_SKIN_MAGIC &&
	    xnthread_test_state(thread, XNMAPPED))
		xnshadow_unmap(thread);
}

int vrtxsys_init(void)
{
	__muxid = xnshadow_register_interface(&__props);

	if (__muxid < 0)
		return -ENOSYS;

	xnpod_add_hook(XNHOOK_THREAD_DELETE, &__shadow_delete_hook);

	return 0;
}

void vrtxsys_cleanup(void)
{
	xnpod_remove_hook(XNHOOK_THREAD_DELETE, &__shadow_delete_hook);
	xnshadow_unregister_interface(__muxid);
}
