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
#include <uitron/sem.h>

static xnmap_t *ui_sem_idmap;

#ifdef CONFIG_XENO_EXPORT_REGISTRY

static int __sem_read_proc(char *page,
			   char **start,
			   off_t off, int count, int *eof, void *data)
{
	uisem_t *sem = (uisem_t *)data;
	char *p = page;
	int len;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	p += sprintf(p, "=%d, attr=%s\n", sem->semcnt,
		     sem->sematr & TA_TPRI ? "TA_TPRI" : "TA_TFIFO");

	if (xnsynch_pended_p(&sem->synchbase)) {
		xnpholder_t *holder;

		/* Pended semaphore -- dump waiters. */

		holder = getheadpq(xnsynch_wait_queue(&sem->synchbase));

		while (holder) {
			xnthread_t *sleeper = link2thread(holder, plink);
			p += sprintf(p, "+%s\n", xnthread_name(sleeper));
			holder = nextpq(xnsynch_wait_queue(&sem->synchbase), holder);
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

static xnpnode_t __sem_pnode = {

	.dir = NULL,
	.type = "semaphores",
	.entries = 0,
	.read_proc = &__sem_read_proc,
	.write_proc = NULL,
	.root = &__uitron_ptree,
};

#elif defined(CONFIG_XENO_OPT_REGISTRY)

static xnpnode_t __sem_pnode = {

	.type = "semaphores"
};

#endif /* CONFIG_XENO_EXPORT_REGISTRY */

int uisem_init(void)
{
	ui_sem_idmap = xnmap_create(uITRON_MAX_SEMID, uITRON_MAX_SEMID, 1);
	return ui_sem_idmap ? 0 : -ENOMEM;
}

void uisem_cleanup(void)
{
	ui_sem_flush_rq(&__ui_global_rholder.semq);
	xnmap_delete(ui_sem_idmap);
}

ER cre_sem(ID semid, T_CSEM *pk_csem)
{
	uisem_t *sem;

	if (xnpod_asynch_p())
		return EN_CTXID;

	if (pk_csem->isemcnt < 0 ||
	    pk_csem->maxsem < 0 || pk_csem->isemcnt > pk_csem->maxsem)
		return E_PAR;

	if (semid <= 0 || semid > uITRON_MAX_SEMID)
		return E_ID;

	sem = xnmalloc(sizeof(*sem));

	if (!sem)
		return E_NOMEM;

	semid = xnmap_enter(ui_sem_idmap, semid, sem);

	if (semid <= 0) {
		xnfree(sem);
		return E_OBJ;
	}

	xnsynch_init(&sem->synchbase,
		     (pk_csem->sematr & TA_TPRI) ? XNSYNCH_PRIO : XNSYNCH_FIFO);

	sem->id = semid;
	sem->exinf = pk_csem->exinf;
	sem->sematr = pk_csem->sematr;
	sem->semcnt = pk_csem->isemcnt;
	sem->maxsem = pk_csem->maxsem;
#ifdef CONFIG_XENO_OPT_REGISTRY
	sprintf(sem->name, "sem%d", semid);
	xnregistry_enter(sem->name, sem, &sem->handle, &__sem_pnode);
#endif /* CONFIG_XENO_OPT_REGISTRY */
	xnarch_memory_barrier();
	sem->magic = uITRON_SEM_MAGIC;

	return E_OK;
}

ER del_sem(ID semid)
{
	uisem_t *sem;
	spl_t s;

	if (xnpod_asynch_p())
		return EN_CTXID;

	if (semid <= 0 || semid > uITRON_MAX_SEMID)
		return E_ID;

	xnlock_get_irqsave(&nklock, s);

	sem = xnmap_fetch(ui_sem_idmap, semid);

	if (!sem) {
		xnlock_put_irqrestore(&nklock, s);
		return E_NOEXS;
	}

	xnmap_remove(ui_sem_idmap, sem->id);
	ui_mark_deleted(sem);

#ifdef CONFIG_XENO_OPT_REGISTRY
	xnregistry_remove(sem->handle);
#endif /* CONFIG_XENO_OPT_REGISTRY */
	xnfree(sem);

	if (xnsynch_destroy(&sem->synchbase) == XNSYNCH_RESCHED)
		xnpod_schedule();

	xnlock_put_irqrestore(&nklock, s);

	return E_OK;
}

ER sig_sem(ID semid)
{
	uitask_t *sleeper;
	ER err = E_OK;
	uisem_t *sem;
	spl_t s;

	if (xnpod_asynch_p())
		return EN_CTXID;

	if (semid <= 0 || semid > uITRON_MAX_SEMID)
		return E_ID;

	xnlock_get_irqsave(&nklock, s);

	sem = xnmap_fetch(ui_sem_idmap, semid);

	if (!sem) {
		err = E_NOEXS;
		goto unlock_and_exit;
	}

	if (xnsynch_pended_p(&sem->synchbase)) {
		sleeper = thread2uitask(xnsynch_wakeup_one_sleeper(&sem->synchbase));
		xnpod_schedule();
		goto unlock_and_exit;
	}

	if (++sem->semcnt > sem->maxsem || sem->semcnt < 0) {
		sem->semcnt--;
		err = E_QOVR;
	}

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

static ER wai_sem_helper(ID semid, TMO tmout)
{
	xnticks_t timeout;
	uitask_t *task;
	ER err = E_OK;
	uisem_t *sem;
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

	if (semid <= 0 || semid > uITRON_MAX_SEMID)
		return E_ID;

	xnlock_get_irqsave(&nklock, s);

	sem = xnmap_fetch(ui_sem_idmap, semid);

	if (!sem) {
		err = E_NOEXS;
		goto unlock_and_exit;
	}

	if (sem->semcnt > 0) {
		sem->semcnt--;
		goto unlock_and_exit;
	}

	else if (timeout == XN_NONBLOCK) {
		err = E_TMOUT;
		goto unlock_and_exit;
	}

	task = ui_current_task();

	xnthread_clear_info(&task->threadbase, uITRON_TASK_RLWAIT);

	xnsynch_sleep_on(&sem->synchbase, timeout, XN_RELATIVE);

	if (xnthread_test_info(&task->threadbase, XNRMID))
		err = E_DLT;	/* Semaphore deleted while pending. */
	else if (xnthread_test_info(&task->threadbase, XNTIMEO))
		err = E_TMOUT;	/* Timeout. */
	else if (xnthread_test_info(&task->threadbase, XNBREAK))
		err = E_RLWAI;	/* rel_wai() or signal received while waiting. */

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

ER wai_sem(ID semid)
{
	return wai_sem_helper(semid, TMO_FEVR);
}

ER preq_sem(ID semid)
{
	return wai_sem_helper(semid, 0);
}

ER twai_sem(ID semid, TMO tmout)
{
	return wai_sem_helper(semid, tmout);
}

ER ref_sem(T_RSEM *pk_rsem, ID semid)
{
	uitask_t *sleeper;
	uisem_t *sem;
	spl_t s;

	if (semid <= 0 || semid > uITRON_MAX_SEMID)
		return E_ID;

	xnlock_get_irqsave(&nklock, s);

	sem = xnmap_fetch(ui_sem_idmap, semid);

	if (!sem) {
		xnlock_put_irqrestore(&nklock, s);
		return E_NOEXS;
	}

	if (xnsynch_pended_p(&sem->synchbase)) {
		sleeper =
			thread2uitask(link2thread
				      (getheadpq(xnsynch_wait_queue(&sem->synchbase)),
				       plink));
		pk_rsem->wtsk = sleeper->id;
	} else
		pk_rsem->wtsk = FALSE;

	pk_rsem->exinf = sem->exinf;
	pk_rsem->semcnt = sem->semcnt;

	xnlock_put_irqrestore(&nklock, s);

	return E_OK;
}

EXPORT_SYMBOL(cre_sem);
EXPORT_SYMBOL(del_sem);
EXPORT_SYMBOL(sig_sem);
EXPORT_SYMBOL(wai_sem);
EXPORT_SYMBOL(preq_sem);
EXPORT_SYMBOL(twai_sem);
EXPORT_SYMBOL(ref_sem);
