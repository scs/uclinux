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
#include <nucleus/heap.h>
#include <uitron/task.h>
#include <uitron/mbx.h>

static xnmap_t *ui_mbx_idmap;

#ifdef CONFIG_XENO_EXPORT_REGISTRY

static int __mbx_read_proc(char *page,
			    char **start,
			    off_t off, int count, int *eof, void *data)
{
	uimbx_t *mbx = (uimbx_t *)data;
	char *p = page;
	int len;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	p += sprintf(p, "%d/%d message(s), attr=%s\n",
		     mbx->mcount, mbx->bufcnt,
		     mbx->mbxatr & TA_TPRI ? "TA_TPRI" : "TA_TFIFO");

	if (xnsynch_pended_p(&mbx->synchbase)) {
		xnpholder_t *holder;

		/* Pended mbx -- dump waiters. */

		holder = getheadpq(xnsynch_wait_queue(&mbx->synchbase));

		while (holder) {
			xnthread_t *sleeper = link2thread(holder, plink);
			p += sprintf(p, "+%s\n", xnthread_name(sleeper));
			holder = nextpq(xnsynch_wait_queue(&mbx->synchbase), holder);
		}
	}

	xnlock_put_irqrestore(&nklock, s);

	len = (p - page) - off;
	if (len <= off + count)
		*eof = 1;
	*start = page + off;
	if (len > count)
		len = count;
	if (len < 0)
		len = 0;

	return len;
}

extern xnptree_t __uitron_ptree;

static xnpnode_t __mbx_pnode = {

	.dir = NULL,
	.type = "mailboxes",
	.entries = 0,
	.read_proc = &__mbx_read_proc,
	.write_proc = NULL,
	.root = &__uitron_ptree,
};

#elif defined(CONFIG_XENO_OPT_REGISTRY)

static xnpnode_t __mbx_pnode = {

	.type = "mailboxes"
};

#endif /* CONFIG_XENO_EXPORT_REGISTRY */

int uimbx_init(void)
{
	ui_mbx_idmap = xnmap_create(uITRON_MAX_MBXID, uITRON_MAX_MBXID, 1);
	return ui_mbx_idmap ? 0 : -ENOMEM;
}

void uimbx_cleanup(void)
{
	ui_mbx_flush_rq(&__ui_global_rholder.mbxq);
	xnmap_delete(ui_mbx_idmap);
}

ER cre_mbx(ID mbxid, T_CMBX *pk_cmbx)
{
	uimbx_t *mbx;
	T_MSG **ring;

	if (xnpod_asynch_p())
		return EN_CTXID;

	if (mbxid <= 0 || mbxid > uITRON_MAX_MBXID)
		return E_ID;

	if (pk_cmbx->bufcnt <= 0)
		return E_PAR;

	if (pk_cmbx->mbxatr & TA_MPRI)
		return E_RSATR;

	mbx = xnmalloc(sizeof(*mbx));

	if (!mbx)
		return E_NOMEM;

	ring = xnmalloc(sizeof(T_MSG *) * pk_cmbx->bufcnt);

	if (!ring) {
		xnfree(mbx);
		return E_NOMEM;
	}

	mbxid = xnmap_enter(ui_mbx_idmap, mbxid, mbx);

	if (mbxid <= 0) {
		xnfree(mbx);
		return E_OBJ;
	}

	xnsynch_init(&mbx->synchbase,
		     (pk_cmbx->mbxatr & TA_TPRI) ? XNSYNCH_PRIO : XNSYNCH_FIFO);

	mbx->id = mbxid;
	mbx->exinf = pk_cmbx->exinf;
	mbx->mbxatr = pk_cmbx->mbxatr;
	mbx->bufcnt = pk_cmbx->bufcnt;
	mbx->rdptr = 0;
	mbx->wrptr = 0;
	mbx->mcount = 0;
	mbx->ring = ring;
#ifdef CONFIG_XENO_OPT_REGISTRY
	sprintf(mbx->name, "mbx%d", mbxid);
	xnregistry_enter(mbx->name, mbx, &mbx->handle, &__mbx_pnode);
#endif /* CONFIG_XENO_OPT_REGISTRY */
	xnarch_memory_barrier();
	mbx->magic = uITRON_MBX_MAGIC;

	return E_OK;
}

ER del_mbx(ID mbxid)
{
	uimbx_t *mbx;
	spl_t s;

	if (xnpod_asynch_p())
		return EN_CTXID;

	if (mbxid <= 0 || mbxid > uITRON_MAX_MBXID)
		return E_ID;

	xnlock_get_irqsave(&nklock, s);

	mbx = xnmap_fetch(ui_mbx_idmap, mbxid);

	if (!mbx) {
		xnlock_put_irqrestore(&nklock, s);
		return E_NOEXS;
	}

	xnmap_remove(ui_mbx_idmap, mbx->id);
	ui_mark_deleted(mbx);
#ifdef CONFIG_XENO_OPT_REGISTRY
	xnregistry_remove(mbx->handle);
#endif /* CONFIG_XENO_OPT_REGISTRY */
	xnfree(mbx->ring);
	xnfree(mbx);

	if (xnsynch_destroy(&mbx->synchbase) == XNSYNCH_RESCHED)
		xnpod_schedule();

	xnlock_put_irqrestore(&nklock, s);

	return E_OK;
}

ER snd_msg(ID mbxid, T_MSG *pk_msg)
{
	uitask_t *sleeper;
	ER err = E_OK;
	uimbx_t *mbx;
	int wrptr;
	spl_t s;

	if (mbxid <= 0 || mbxid > uITRON_MAX_MBXID)
		return E_ID;

	xnlock_get_irqsave(&nklock, s);

	mbx = xnmap_fetch(ui_mbx_idmap, mbxid);

	if (!mbx) {
		err = E_NOEXS;
		goto unlock_and_exit;
	}

	sleeper = thread2uitask(xnsynch_wakeup_one_sleeper(&mbx->synchbase));

	if (sleeper) {
		sleeper->wargs.msg = pk_msg;
		xnpod_schedule();
		goto unlock_and_exit;
	}

	wrptr = mbx->wrptr;

	if (mbx->mcount > 0 && wrptr == mbx->rdptr)
		err = E_QOVR;
	else {
		mbx->ring[wrptr] = pk_msg;
		mbx->wrptr = (wrptr + 1) % mbx->bufcnt;
		mbx->mcount++;
	}

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

static ER rcv_msg_helper(T_MSG ** ppk_msg, ID mbxid, TMO tmout)
{
	xnticks_t timeout;
	uitask_t *task;
	ER err = E_OK;
	uimbx_t *mbx;
	spl_t s;

	if (xnpod_unblockable_p())
		return E_CTX;

	if (tmout == TMO_FEVR)
		timeout = XN_INFINITE;
	else if (tmout == 0)
		timeout = XN_NONBLOCK;
	else if (tmout < TMO_FEVR)
		return E_PAR;
	else
		timeout = (xnticks_t)tmout;

	if (mbxid <= 0 || mbxid > uITRON_MAX_MBXID)
		return E_ID;

	xnlock_get_irqsave(&nklock, s);

	mbx = xnmap_fetch(ui_mbx_idmap, mbxid);

	if (!mbx) {
		err = E_NOEXS;
		goto unlock_and_exit;
	}

	if (mbx->mcount > 0) {
		*ppk_msg = mbx->ring[mbx->rdptr];
		mbx->rdptr = (mbx->rdptr + 1) % mbx->bufcnt;
		mbx->mcount--;
		goto unlock_and_exit;
	}

	if (timeout == XN_NONBLOCK) {
		err = E_TMOUT;
		goto unlock_and_exit;
	}

	task = ui_current_task();

	xnthread_clear_info(&task->threadbase, uITRON_TASK_RLWAIT);

	xnsynch_sleep_on(&mbx->synchbase, timeout, XN_RELATIVE);

	if (xnthread_test_info(&task->threadbase, XNRMID))
		err = E_DLT;	/* Flag deleted while pending. */
	else if (xnthread_test_info(&task->threadbase, XNTIMEO))
		err = E_TMOUT;	/* Timeout. */
	else if (xnthread_test_info(&task->threadbase, XNBREAK))
		err = E_RLWAI;	/* rel_wai() or signal received while waiting. */
	else
		*ppk_msg = task->wargs.msg;

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

ER rcv_msg(T_MSG **ppk_msg, ID mbxid)
{
	return rcv_msg_helper(ppk_msg, mbxid, TMO_FEVR);
}

ER prcv_msg(T_MSG **ppk_msg, ID mbxid)
{
	return rcv_msg_helper(ppk_msg, mbxid, 0);
}

ER trcv_msg(T_MSG **ppk_msg, ID mbxid, TMO tmout)
{
	return rcv_msg_helper(ppk_msg, mbxid, tmout);
}

ER ref_mbx(T_RMBX *pk_rmbx, ID mbxid)
{
	uitask_t *sleeper;
	ER err = E_OK;
	uimbx_t *mbx;
	spl_t s;

	if (xnpod_asynch_p())
		return EN_CTXID;

	if (mbxid <= 0 || mbxid > uITRON_MAX_FLAGID)
		return E_ID;

	xnlock_get_irqsave(&nklock, s);

	mbx = xnmap_fetch(ui_mbx_idmap, mbxid);

	if (!mbx) {
		err = E_NOEXS;
		goto unlock_and_exit;
	}

	if (xnsynch_pended_p(&mbx->synchbase)) {
		sleeper =
			thread2uitask(link2thread
				      (getheadpq(xnsynch_wait_queue(&mbx->synchbase)),
				       plink));
		pk_rmbx->wtsk = sleeper->id;
	} else
		pk_rmbx->wtsk = FALSE;

	pk_rmbx->exinf = mbx->exinf;
	pk_rmbx->pk_msg =
	    mbx->mcount > 0 ? mbx->ring[mbx->rdptr] : (T_MSG *) NADR;

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

EXPORT_SYMBOL(cre_mbx);
EXPORT_SYMBOL(del_mbx);
EXPORT_SYMBOL(snd_msg);
EXPORT_SYMBOL(rcv_msg);
EXPORT_SYMBOL(prcv_msg);
EXPORT_SYMBOL(trcv_msg);
EXPORT_SYMBOL(ref_mbx);
