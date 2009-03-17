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
#include <psos+/sem.h>

static xnqueue_t psossemq;

static int sm_destroy_internal(psossem_t *sem);

#ifdef CONFIG_XENO_EXPORT_REGISTRY

static int sem_read_proc(char *page,
			 char **start,
			 off_t off, int count, int *eof, void *data)
{
	psossem_t *sem = (psossem_t *)data;
	char *p = page;
	int len;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	p += sprintf(p, "value=%u\n", sem->count);

	if (xnsynch_nsleepers(&sem->synchbase) == 0) {
		xnpholder_t *holder;

		/* Pended semaphore -- dump waiters. */

		holder = getheadpq(xnsynch_wait_queue(&sem->synchbase));

		while (holder) {
			xnthread_t *sleeper = link2thread(holder, plink);
			p += sprintf(p, "+%s\n", xnthread_name(sleeper));
			holder =
			    nextpq(xnsynch_wait_queue(&sem->synchbase), holder);
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

extern xnptree_t __psos_ptree;

static xnpnode_t sem_pnode = {

	.dir = NULL,
	.type = "semaphores",
	.entries = 0,
	.read_proc = &sem_read_proc,
	.write_proc = NULL,
	.root = &__psos_ptree,
};

#elif defined(CONFIG_XENO_OPT_REGISTRY)

static xnpnode_t sem_pnode = {

	.type = "semaphores"
};

#endif /* CONFIG_XENO_EXPORT_REGISTRY */

void psossem_init(void)
{
	initq(&psossemq);
}

void psossem_cleanup(void)
{
	psos_sem_flush_rq(&__psos_global_rholder.smq);
}

u_long sm_create(const char *name, u_long icount, u_long flags, u_long *smid)
{
	psossem_t *sem;
	int bflags = 0;
	spl_t s;

	sem = (psossem_t *)xnmalloc(sizeof(*sem));

	if (!sem)
		return ERR_NOSCB;

	if (flags & SM_PRIOR)
		bflags |= XNSYNCH_PRIO;

	xnsynch_init(&sem->synchbase, bflags);

	inith(&sem->link);
	sem->count = icount;
	sem->magic = PSOS_SEM_MAGIC;
	xnobject_copy_name(sem->name, name);

	inith(&sem->rlink);
	sem->rqueue = &psos_get_rholder()->smq;
	xnlock_get_irqsave(&nklock, s);
	appendq(sem->rqueue, &sem->rlink);
	appendq(&psossemq, &sem->link);
	xnlock_put_irqrestore(&nklock, s);
#ifdef CONFIG_XENO_OPT_REGISTRY
	{
		static unsigned long sem_ids;
		u_long err;

		if (!*name)
			sprintf(sem->name, "anon_sem%lu", sem_ids++);

		err = xnregistry_enter(sem->name, sem, &sem->handle, &sem_pnode);

		if (err) {
			sem->handle = XN_NO_HANDLE;
			sm_delete((u_long)sem);
			return err;
		}
	}
#endif /* CONFIG_XENO_OPT_REGISTRY */

	*smid = (u_long)sem;

	return SUCCESS;
}

static int sm_destroy_internal(psossem_t *sem)
{
	int rc;

	removeq(sem->rqueue, &sem->rlink);
	removeq(&psossemq, &sem->link);
	rc = xnsynch_destroy(&sem->synchbase);
#ifdef CONFIG_XENO_OPT_REGISTRY
	if (sem->handle)
		xnregistry_remove(sem->handle);
#endif /* CONFIG_XENO_OPT_REGISTRY */
	psos_mark_deleted(sem);

	xnfree(sem);

	return rc;
}

u_long sm_delete(u_long smid)
{
	u_long err = SUCCESS;
	psossem_t *sem;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	sem = psos_h2obj_active(smid, PSOS_SEM_MAGIC, psossem_t);

	if (!sem) {
		err = psos_handle_error(smid, PSOS_SEM_MAGIC, psossem_t);
		goto unlock_and_exit;
	}

	if (sm_destroy_internal(sem) == XNSYNCH_RESCHED) {
		err = ERR_TATSDEL;
		xnpod_schedule();
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

u_long sm_ident(const char *name, u_long node, u_long *smid)
{
	u_long err = SUCCESS;
	xnholder_t *holder;
	psossem_t *sem;
	spl_t s;

	if (node > 1)
		return ERR_NODENO;

	xnlock_get_irqsave(&nklock, s);

	for (holder = getheadq(&psossemq);
	     holder; holder = nextq(&psossemq, holder)) {
		sem = link2psossem(holder);

		if (!strcmp(sem->name, name)) {
			*smid = (u_long)sem;
			goto unlock_and_exit;
		}
	}

	err = ERR_OBJNF;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

u_long sm_p(u_long smid, u_long flags, u_long timeout)
{
	u_long err = SUCCESS;
	psostask_t *task;
	psossem_t *sem;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	sem = psos_h2obj_active(smid, PSOS_SEM_MAGIC, psossem_t);

	if (!sem) {
		err = psos_handle_error(smid, PSOS_SEM_MAGIC, psossem_t);
		goto unlock_and_exit;
	}

	if (flags & SM_NOWAIT) {
		if (sem->count > 0)
			sem->count--;
		else
			err = ERR_NOSEM;
	} else {
		if (xnpod_unblockable_p()) {
			err = -EPERM;
			goto unlock_and_exit;
		}

		if (sem->count > 0)
			sem->count--;
		else {
			xnsynch_sleep_on(&sem->synchbase, timeout, XN_RELATIVE);

			task = psos_current_task();

			if (xnthread_test_info(&task->threadbase, XNBREAK))
				err = -EINTR;
			else if (xnthread_test_info(&task->threadbase, XNRMID))
				err = ERR_SKILLD;	/* Semaphore deleted while pending. */
			else if (xnthread_test_info(&task->threadbase, XNTIMEO))
				err = ERR_TIMEOUT;	/* Timeout. */
		}
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

u_long sm_v(u_long smid)
{
	u_long err = SUCCESS;
	psossem_t *sem;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	sem = psos_h2obj_active(smid, PSOS_SEM_MAGIC, psossem_t);

	if (!sem) {
		err = psos_handle_error(smid, PSOS_SEM_MAGIC, psossem_t);
		goto unlock_and_exit;
	}

	if (xnsynch_wakeup_one_sleeper(&sem->synchbase) != NULL)
		xnpod_schedule();
	else
		sem->count++;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/*
 * IMPLEMENTATION NOTES:
 *
 * - Code executing on behalf of interrupt context is currently not
 * allowed to scan/alter the global sema4 queue (psossemq).
 */
