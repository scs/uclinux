/**
 * @file
 * This file is part of the Xenomai project.
 *
 * @note Copyright (C) 2007 Philippe Gerum <rpm@xenomai.org> 
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
#include <uitron/syscall.h>
#include <uitron/task.h>
#include <uitron/sem.h>
#include <uitron/mbx.h>
#include <uitron/flag.h>
#include <uitron/ppd.h>

int __ui_muxid;

/*
 * int __uitron_cre_tsk(ID tskid, T_CTSK *pk_ctsk, xncompletion_t *completion)
 */

static int __ui_cre_tsk(struct task_struct *curr, struct pt_regs *regs)
{
	xncompletion_t __user *u_completion;
	uitask_t *task;
	T_CTSK pk_ctsk;
	ID tskid;
	spl_t s;
	ER err;

	if (!__xn_access_ok(curr, VERIFY_READ, __xn_reg_arg2(regs), sizeof(pk_ctsk)))
		return -EFAULT;

	tskid = __xn_reg_arg1(regs);
	__xn_copy_from_user(curr, &pk_ctsk, (void __user *)__xn_reg_arg2(regs),
			    sizeof(pk_ctsk));
	pk_ctsk.tskatr |= TA_SHADOW;
	/* Completion descriptor our parent thread is pending on. */
	u_completion = (xncompletion_t __user *)__xn_reg_arg3(regs);

	err = cre_tsk(tskid, &pk_ctsk);

	if (likely(err == E_OK)) {
		xnlock_get_irqsave(&nklock, s);
		task = xnmap_fetch(ui_task_idmap, tskid);
		if (!task) {
			xnlock_put_irqrestore(&nklock, s);
			err = E_OBJ;
			goto fail;
		}
		strncpy(curr->comm, xnthread_name(&task->threadbase), sizeof(curr->comm));
		curr->comm[sizeof(curr->comm) - 1] = '\0';
		xnlock_put_irqrestore(&nklock, s);
		/* Since we may not hold the superlock across a call
		 * to xnshadow_map(), we do have a small race window
		 * here, if the created task is killed then its TCB
		 * recycled before we could map it; however, the risk
		 * is mitigated by consistency checks performed in
		 * xnshadow_map(). */
		return xnshadow_map(&task->threadbase, u_completion); /* May be NULL */
	}

fail:
	/* Unblock and pass back the error code. */

	if (u_completion)
		xnshadow_signal_completion(u_completion, err);

	return err;
}

/*
 * int __ui_del_tsk(ID tskid)
 */

static int __ui_del_tsk(struct task_struct *curr, struct pt_regs *regs)
{
	ID tskid = __xn_reg_arg1(regs);

	return del_tsk(tskid);
}

/*
 * int __ui_sta_tsk(ID tskid, INT stacd)
 */

static int __ui_sta_tsk(struct task_struct *curr, struct pt_regs *regs)
{
	ID tskid = __xn_reg_arg1(regs);
	INT stacd = __xn_reg_arg2(regs);

	return sta_tsk(tskid, stacd);
}

/*
 * int __ui_ext_tsk(void)
 */

static int __ui_ext_tsk(struct task_struct *curr, struct pt_regs *regs)
{
	ext_tsk();
	return 0;
}

/*
 * int __ui_exd_tsk(void)
 */

static int __ui_exd_tsk(struct task_struct *curr, struct pt_regs *regs)
{
	exd_tsk();
	return 0;
}

/*
 * int __ui_ter_tsk(ID tskid)
 */

static int __ui_ter_tsk(struct task_struct *curr, struct pt_regs *regs)
{
	ID tskid = __xn_reg_arg1(regs);

	return ter_tsk(tskid);
}

/*
 * int __ui_dis_dsp(void)
 */

static int __ui_dis_dsp(struct task_struct *curr, struct pt_regs *regs)
{
	return dis_dsp();
}

/*
 * int __ui_ena_dsp(void)
 */

static int __ui_ena_dsp(struct task_struct *curr, struct pt_regs *regs)
{
	return ena_dsp();
}

/*
 * int __ui_chg_pri(ID tskid, PRI tskpri)
 */

static int __ui_chg_pri(struct task_struct *curr, struct pt_regs *regs)
{
	ID tskid = __xn_reg_arg1(regs);
	PRI tskpri = __xn_reg_arg2(regs);

	return chg_pri(tskid, tskpri);
}

/*
 * int __ui_rot_rdq(PRI tskpri)
 */

static int __ui_rot_rdq(struct task_struct *curr, struct pt_regs *regs)
{
	PRI tskpri = __xn_reg_arg1(regs);

	return rot_rdq(tskpri);
}

/*
 * int __ui_rel_wai(ID tskid)
 */

static int __ui_rel_wai(struct task_struct *curr, struct pt_regs *regs)
{
	ID tskid = __xn_reg_arg1(regs);

	return rel_wai(tskid);
}

/*
 * int __ui_get_tid(ID *p_tskid)
 */

static int __ui_get_tid(struct task_struct *curr, struct pt_regs *regs)
{
	ID tskid;
	ER err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(tskid)))
		return -EFAULT;

	err = get_tid(&tskid);

	if (err == E_OK)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs), &tskid,
				  sizeof(tskid));
	return err;
}

/*
 * int __ui_ref_tsk(T_RTSK *pk_rtsk, ID tskid)
 */

static int __ui_ref_tsk(struct task_struct *curr, struct pt_regs *regs)
{
	ID tskid = __xn_reg_arg2(regs);
	T_RTSK pk_rtsk;
	ER err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(pk_rtsk)))
		return -EFAULT;

	err = ref_tsk(&pk_rtsk, tskid);

	if (err == E_OK)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs), &pk_rtsk,
				  sizeof(pk_rtsk));
	return err;
}

/*
 * int __ui_sus_tsk(ID tskid)
 */

static int __ui_sus_tsk(struct task_struct *curr, struct pt_regs *regs)
{
	ID tskid = __xn_reg_arg1(regs);

	return sus_tsk(tskid);
}

/*
 * int __ui_rsm_tsk(ID tskid)
 */

static int __ui_rsm_tsk(struct task_struct *curr, struct pt_regs *regs)
{
	ID tskid = __xn_reg_arg1(regs);

	return rsm_tsk(tskid);
}

/*
 * int __ui_frsm_tsk(ID tskid)
 */

static int __ui_frsm_tsk(struct task_struct *curr, struct pt_regs *regs)
{
	ID tskid = __xn_reg_arg1(regs);

	return frsm_tsk(tskid);
}

/*
 * int __ui_slp_tsk(void)
 */

static int __ui_slp_tsk(struct task_struct *curr, struct pt_regs *regs)
{
	ER err = slp_tsk();

	if (err == E_RLWAI) {
		uitask_t *task = ui_current_task();
		if (!xnthread_test_info(&task->threadbase, uITRON_TASK_RLWAIT))
			err = -EINTR;
	}

	return err;
}

/*
 * int __ui_tslp_tsk(TMO tmout)
 */

static int __ui_tslp_tsk(struct task_struct *curr, struct pt_regs *regs)
{
	TMO tmout = __xn_reg_arg1(regs);
	ER err;

	err = tslp_tsk(tmout);

	if (err == E_RLWAI) {
		uitask_t *task = ui_current_task();
		if (!xnthread_test_info(&task->threadbase, uITRON_TASK_RLWAIT))
			err = -EINTR;
	}

	return err;
}

/*
 * int __ui_wup_tsk(ID tskid)
 */

static int __ui_wup_tsk(struct task_struct *curr, struct pt_regs *regs)
{
	ID tskid = __xn_reg_arg1(regs);

	return wup_tsk(tskid);
}

/*
 * int __ui_can_wup(INT *p_wupcnt, ID tskid)
 */

static int __ui_can_wup(struct task_struct *curr, struct pt_regs *regs)
{
	ID tskid = __xn_reg_arg2(regs);
	INT wupcnt;
	ER err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(wupcnt)))
		return -EFAULT;

	err = can_wup(&wupcnt, tskid);

	if (err == E_OK)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs), &wupcnt,
				  sizeof(wupcnt));
	return err;
}

/*
 * int __ui_cre_sem(ID semid, T_CSEM *pk_csem)
 */

static int __ui_cre_sem(struct task_struct *curr, struct pt_regs *regs)
{
	ID semid = __xn_reg_arg1(regs);
	T_CSEM pk_csem;

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg2(regs), sizeof(pk_csem)))
		return -EFAULT;

	__xn_copy_from_user(curr, &pk_csem, (void __user *)__xn_reg_arg2(regs),
			    sizeof(pk_csem));

	return cre_sem(semid, &pk_csem);
}

/*
 * int __ui_del_sem(ID semid)
 */

static int __ui_del_sem(struct task_struct *curr, struct pt_regs *regs)
{
	ID semid = __xn_reg_arg1(regs);

	return del_sem(semid);
}

/*
 * int __ui_sig_sem(ID semid)
 */

static int __ui_sig_sem(struct task_struct *curr, struct pt_regs *regs)
{
	ID semid = __xn_reg_arg1(regs);

	return sig_sem(semid);
}

/*
 * int __ui_wai_sem(ID semid)
 */

static int __ui_wai_sem(struct task_struct *curr, struct pt_regs *regs)
{
	ID semid = __xn_reg_arg1(regs);
	ER err;

	err = wai_sem(semid);

	if (err == E_RLWAI) {
		uitask_t *task = ui_current_task();
		if (!xnthread_test_info(&task->threadbase, uITRON_TASK_RLWAIT))
			err = -EINTR;
	}

	return err;
}

/*
 * int __ui_preq_sem(ID semid)
 */

static int __ui_preq_sem(struct task_struct *curr, struct pt_regs *regs)
{
	ID semid = __xn_reg_arg1(regs);

	return preq_sem(semid);
}

/*
 * int __ui_twai_sem(ID semid, TMO tmout)
 */

static int __ui_twai_sem(struct task_struct *curr, struct pt_regs *regs)
{
	ID semid = __xn_reg_arg1(regs);
	TMO tmout = __xn_reg_arg2(regs);
	ER err;

	err = twai_sem(semid, tmout);

	if (err == E_RLWAI) {
		uitask_t *task = ui_current_task();
		if (!xnthread_test_info(&task->threadbase, uITRON_TASK_RLWAIT))
			err = -EINTR;
	}

	return err;
}

/*
 * int __ui_ref_sem(T_RSEM *pk_rsem, ID semid)
 */

static int __ui_ref_sem(struct task_struct *curr, struct pt_regs *regs)
{
	ID semid = __xn_reg_arg2(regs);
	T_RSEM pk_rsem;
	ER err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(pk_rsem)))
		return -EFAULT;

	err = ref_sem(&pk_rsem, semid);

	if (err == E_OK)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs), &pk_rsem,
				  sizeof(pk_rsem));
	return err;
}

/*
 * int __ui_cre_flg(ID semid, T_CFLG *pk_cflg)
 */

static int __ui_cre_flg(struct task_struct *curr, struct pt_regs *regs)
{
	ID flgid = __xn_reg_arg1(regs);
	T_CFLG pk_cflg;

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg2(regs), sizeof(pk_cflg)))
		return -EFAULT;

	__xn_copy_from_user(curr, &pk_cflg, (void __user *)__xn_reg_arg2(regs),
			    sizeof(pk_cflg));

	return cre_flg(flgid, &pk_cflg);
}

/*
 * int __ui_del_flg(ID flgid)
 */

static int __ui_del_flg(struct task_struct *curr, struct pt_regs *regs)
{
	ID flgid = __xn_reg_arg1(regs);

	return del_flg(flgid);
}

/*
 * int __ui_set_flg(ID flgid, UINT setptn)
 */

static int __ui_set_flg(struct task_struct *curr, struct pt_regs *regs)
{
	ID flgid = __xn_reg_arg1(regs);
	UINT setptn = __xn_reg_arg2(regs);

	return set_flg(flgid, setptn);
}

/*
 * int __ui_clr_flg(ID flgid, UINT clrptn)
 */

static int __ui_clr_flg(struct task_struct *curr, struct pt_regs *regs)
{
	ID flgid = __xn_reg_arg1(regs);
	UINT clrptn = __xn_reg_arg2(regs);

	return clr_flg(flgid, clrptn);
}

/*
 * int __ui_wai_flg(UINT *p_flgptn, ID flgid, UINT waiptn, UINT wfmode)
 */

static int __ui_wai_flg(struct task_struct *curr, struct pt_regs *regs)
{
	UINT flgptn, waiptn, wfmode;
	ID flgid;
	ER err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(flgptn)))
		return -EFAULT;

	flgid = __xn_reg_arg2(regs);
	waiptn = __xn_reg_arg3(regs);
	wfmode = __xn_reg_arg4(regs);

	err = wai_flg(&flgptn, flgid, waiptn, wfmode);

	if (err == E_OK)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs), &flgptn,
				  sizeof(flgptn));
	else if (err == E_RLWAI) {
		uitask_t *task = ui_current_task();
		if (!xnthread_test_info(&task->threadbase, uITRON_TASK_RLWAIT))
			err = -EINTR;
	}

	return err;
}

/*
 * int __ui_twai_flg(UINT *p_flgptn, ID flgid, UINT waiptn, UINT wfmode, TMO tmout)
 */

static int __ui_twai_flg(struct task_struct *curr, struct pt_regs *regs)
{
	UINT flgptn, waiptn, wfmode;
	TMO tmout;
	ID flgid;
	ER err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(flgptn)))
		return -EFAULT;

	flgid = __xn_reg_arg2(regs);
	waiptn = __xn_reg_arg3(regs);
	wfmode = __xn_reg_arg4(regs);
	tmout = __xn_reg_arg5(regs);

	err = twai_flg(&flgptn, flgid, waiptn, wfmode, tmout);

	if (err == E_OK)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs), &flgptn,
				  sizeof(flgptn));
	else if (err == E_RLWAI) {
		uitask_t *task = ui_current_task();
		if (!xnthread_test_info(&task->threadbase, uITRON_TASK_RLWAIT))
			err = -EINTR;
	}

	return err;
}

/*
 * int __ui_pol_flg(UINT *p_flgptn, ID flgid, UINT waiptn, UINT wfmode)
 */

static int __ui_pol_flg(struct task_struct *curr, struct pt_regs *regs)
{
	UINT flgptn, waiptn, wfmode;
	ID flgid;
	ER err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(flgptn)))
		return -EFAULT;

	flgid = __xn_reg_arg2(regs);
	waiptn = __xn_reg_arg3(regs);
	wfmode = __xn_reg_arg4(regs);

	err = pol_flg(&flgptn, flgid, waiptn, wfmode);

	if (err == E_OK)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs), &flgptn,
				  sizeof(flgptn));
	return err;
}

/*
 * int __ui_ref_flg(T_RFLG *pk_rflg, ID flgid)
 */

static int __ui_ref_flg(struct task_struct *curr, struct pt_regs *regs)
{
	ID flgid = __xn_reg_arg2(regs);
	T_RFLG pk_rflg;
	ER err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(pk_rflg)))
		return -EFAULT;

	err = ref_flg(&pk_rflg, flgid);

	if (err == E_OK)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs), &pk_rflg,
				  sizeof(pk_rflg));
	return err;
}

/*
 * int __ui_cre_mbx(ID mbxid, T_CMBX *pk_cmbx)
 */

static int __ui_cre_mbx(struct task_struct *curr, struct pt_regs *regs)
{
	ID mbxid = __xn_reg_arg1(regs);
	T_CMBX pk_cmbx;

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg2(regs), sizeof(pk_cmbx)))
		return -EFAULT;

	__xn_copy_from_user(curr, &pk_cmbx, (void __user *)__xn_reg_arg2(regs),
			    sizeof(pk_cmbx));

	return cre_mbx(mbxid, &pk_cmbx);
}

/*
 * int __ui_del_mbx(ID mbxid)
 */

static int __ui_del_mbx(struct task_struct *curr, struct pt_regs *regs)
{
	ID mbxid = __xn_reg_arg1(regs);

	return del_mbx(mbxid);
}

/*
 * int __ui_snd_msg(ID mbxid, T_MSG *pk_msg)
 */

static int __ui_snd_msg(struct task_struct *curr, struct pt_regs *regs)
{
	ID mbxid = __xn_reg_arg1(regs);
	T_MSG __user *pk_msg = (T_MSG __user *)__xn_reg_arg2(regs);

	return snd_msg(mbxid, pk_msg);
}

/*
 * int __ui_rcv_msg(T_MSG **ppk_msg, ID mbxid)
 */

static int __ui_rcv_msg(struct task_struct *curr, struct pt_regs *regs)
{
	ID mbxid = __xn_reg_arg2(regs);
	T_MSG *pk_msg;
	ER err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(pk_msg)))
		return -EFAULT;

	err = rcv_msg(&pk_msg, mbxid);

	if (err == E_OK)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs), &pk_msg,
				  sizeof(pk_msg));
	else if (err == E_RLWAI) {
		uitask_t *task = ui_current_task();
		if (!xnthread_test_info(&task->threadbase, uITRON_TASK_RLWAIT))
			err = -EINTR;
	}

	return err;
}

/*
 * int __ui_prcv_msg(T_MSG **ppk_msg, ID mbxid)
 */

static int __ui_prcv_msg(struct task_struct *curr, struct pt_regs *regs)
{
	ID mbxid = __xn_reg_arg2(regs);
	T_MSG *pk_msg;
	ER err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(pk_msg)))
		return -EFAULT;

	err = prcv_msg(&pk_msg, mbxid);

	if (err == E_OK)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs), &pk_msg,
				  sizeof(pk_msg));
	return err;
}

/*
 * int __ui_trcv_msg(T_MSG **ppk_msg, ID mbxid, TMO tmout)
 */

static int __ui_trcv_msg(struct task_struct *curr, struct pt_regs *regs)
{
	ID mbxid = __xn_reg_arg2(regs);
	TMO tmout = __xn_reg_arg3(regs);
	T_MSG *pk_msg;
	ER err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(pk_msg)))
		return -EFAULT;

	err = trcv_msg(&pk_msg, mbxid, tmout);

	if (err == E_OK)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs), &pk_msg,
				  sizeof(pk_msg));
	else if (err == E_RLWAI) {
		uitask_t *task = ui_current_task();
		if (!xnthread_test_info(&task->threadbase, uITRON_TASK_RLWAIT))
			err = -EINTR;
	}

	return err;
}

/*
 * int __ui_ref_mbx(T_RMBX *pk_rmbx, ID mbxid)
 */

static int __ui_ref_mbx(struct task_struct *curr, struct pt_regs *regs)
{
	ID mbxid = __xn_reg_arg2(regs);
	T_RMBX pk_rmbx;
	ER err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(pk_rmbx)))
		return -EFAULT;

	err = ref_mbx(&pk_rmbx, mbxid);

	if (err == E_OK)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs), &pk_rmbx,
				  sizeof(pk_rmbx));
	return err;
}

static void *ui_shadow_eventcb(int event, void *data)
{
	struct ui_resource_holder *rh;

	switch(event) {

	case XNSHADOW_CLIENT_ATTACH:

		rh = xnarch_alloc_host_mem(sizeof(*rh));
		if (!rh)
			return ERR_PTR(-ENOMEM);

		initq(&rh->semq);
		initq(&rh->flgq);
		initq(&rh->mbxq);

		return &rh->ppd;

	case XNSHADOW_CLIENT_DETACH:

		rh = ppd2rholder((xnshadow_ppd_t *) data);
		ui_sem_flush_rq(&rh->semq);
		ui_flag_flush_rq(&rh->flgq);
		ui_mbx_flush_rq(&rh->mbxq);

		xnarch_free_host_mem(rh, sizeof(*rh));

		return NULL;
	}

	return ERR_PTR(-EINVAL);
}

static xnsysent_t __systab[] = {
	[__uitron_cre_tsk] = {&__ui_cre_tsk, __xn_exec_init},
	[__uitron_del_tsk] = {&__ui_del_tsk, __xn_exec_conforming},
	[__uitron_sta_tsk] = {&__ui_sta_tsk, __xn_exec_any},
	[__uitron_ext_tsk] = {&__ui_ext_tsk, __xn_exec_primary},
	[__uitron_exd_tsk] = {&__ui_exd_tsk, __xn_exec_primary},
	[__uitron_ter_tsk] = {&__ui_ter_tsk, __xn_exec_any},
	[__uitron_dis_dsp] = {&__ui_dis_dsp, __xn_exec_any},
	[__uitron_ena_dsp] = {&__ui_ena_dsp, __xn_exec_conforming},
	[__uitron_chg_pri] = {&__ui_chg_pri, __xn_exec_conforming},
	[__uitron_rot_rdq] = {&__ui_rot_rdq, __xn_exec_primary},
	[__uitron_rel_wai] = {&__ui_rel_wai, __xn_exec_any},
	[__uitron_get_tid] = {&__ui_get_tid, __xn_exec_any},
	[__uitron_ref_tsk] = {&__ui_ref_tsk, __xn_exec_conforming},
	[__uitron_sus_tsk] = {&__ui_sus_tsk, __xn_exec_conforming},
	[__uitron_rsm_tsk] = {&__ui_rsm_tsk, __xn_exec_any},
	[__uitron_frsm_tsk] = {&__ui_frsm_tsk, __xn_exec_any},
	[__uitron_slp_tsk] = {&__ui_slp_tsk, __xn_exec_primary},
	[__uitron_tslp_tsk] = {&__ui_tslp_tsk, __xn_exec_primary},
	[__uitron_wup_tsk] = {&__ui_wup_tsk, __xn_exec_any},
	[__uitron_can_wup] = {&__ui_can_wup, __xn_exec_conforming},
	[__uitron_cre_sem] = {&__ui_cre_sem, __xn_exec_any},
	[__uitron_del_sem] = {&__ui_del_sem, __xn_exec_any},
	[__uitron_sig_sem] = {&__ui_sig_sem, __xn_exec_any},
	[__uitron_wai_sem] = {&__ui_wai_sem, __xn_exec_primary},
	[__uitron_preq_sem] = {&__ui_preq_sem, __xn_exec_any},
	[__uitron_twai_sem] = {&__ui_twai_sem, __xn_exec_primary},
	[__uitron_ref_sem] = {&__ui_ref_sem, __xn_exec_any},
	[__uitron_cre_flg] = {&__ui_cre_flg, __xn_exec_any},
	[__uitron_del_flg] = {&__ui_del_flg, __xn_exec_any},
	[__uitron_set_flg] = {&__ui_set_flg, __xn_exec_any},
	[__uitron_clr_flg] = {&__ui_clr_flg, __xn_exec_any},
	[__uitron_wai_flg] = {&__ui_wai_flg, __xn_exec_primary},
	[__uitron_pol_flg] = {&__ui_pol_flg, __xn_exec_any},
	[__uitron_twai_flg] = {&__ui_twai_flg, __xn_exec_primary},
	[__uitron_ref_flg] = {&__ui_ref_flg, __xn_exec_any},
	[__uitron_cre_mbx] = {&__ui_cre_mbx, __xn_exec_any},
	[__uitron_del_mbx] = {&__ui_del_mbx, __xn_exec_any},
	[__uitron_snd_msg] = {&__ui_snd_msg, __xn_exec_any},
	[__uitron_rcv_msg] = {&__ui_rcv_msg, __xn_exec_primary},
	[__uitron_prcv_msg] = {&__ui_prcv_msg, __xn_exec_any},
	[__uitron_trcv_msg] = {&__ui_trcv_msg, __xn_exec_primary},
	[__uitron_ref_mbx] = {&__ui_ref_mbx, __xn_exec_any},
};

static struct xnskin_props __props = {
	.name = "uitron",
	.magic = uITRON_SKIN_MAGIC,
	.nrcalls = sizeof(__systab) / sizeof(__systab[0]),
	.systab = __systab,
	.eventcb = &ui_shadow_eventcb,
	.timebasep = &ui_tbase,
	.module = THIS_MODULE
};

static void __shadow_delete_hook(xnthread_t *thread)
{
	if (xnthread_get_magic(thread) == uITRON_SKIN_MAGIC &&
	    xnthread_test_state(thread, XNMAPPED))
		xnshadow_unmap(thread);
}

int ui_syscall_init(void)
{
	__ui_muxid = xnshadow_register_interface(&__props);

	if (__ui_muxid < 0)
		return -ENOSYS;

	xnpod_add_hook(XNHOOK_THREAD_DELETE, &__shadow_delete_hook);

	return 0;
}

void ui_syscall_cleanup(void)
{
	xnpod_remove_hook(XNHOOK_THREAD_DELETE, &__shadow_delete_hook);
	xnshadow_unregister_interface(__ui_muxid);
}
