/*
 * Copyright (C) 2001,2002 IDEALX (http://www.idealx.com/).
 * Written by Julien Pinon <jpinon@idealx.com>.
 * Copyright (C) 2003,2006 Philippe Gerum <rpm@xenomai.org>.
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

#include <vrtx/task.h>
#include <vrtx/sem.h>

static xnmap_t *vrtx_sem_idmap;

static xnqueue_t vrtx_sem_q;

#ifdef CONFIG_XENO_EXPORT_REGISTRY

static int sem_read_proc(char *page,
			 char **start,
			 off_t off, int count, int *eof, void *data)
{
	vrtxsem_t *sem = (vrtxsem_t *)data;
	char *p = page;
	int len;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	p += sprintf(p, "value=%lu\n", sem->count);

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

extern xnptree_t __vrtx_ptree;

static xnpnode_t __sem_pnode = {

	.dir = NULL,
	.type = "semaphores",
	.entries = 0,
	.read_proc = &sem_read_proc,
	.write_proc = NULL,
	.root = &__vrtx_ptree,
};

#elif defined(CONFIG_XENO_OPT_REGISTRY)

static xnpnode_t __sem_pnode = {

	.type = "semaphores"
};

#endif /* CONFIG_XENO_EXPORT_REGISTRY */

static int sem_destroy_internal(vrtxsem_t *sem)
{
	int s;

	removeq(&vrtx_sem_q, &sem->link);
	xnmap_remove(vrtx_sem_idmap, sem->semid);
	s = xnsynch_destroy(&sem->synchbase);
#ifdef CONFIG_XENO_OPT_REGISTRY
	xnregistry_remove(sem->handle);
#endif /* CONFIG_XENO_OPT_REGISTRY */
	vrtx_mark_deleted(sem);
	xnfree(sem);

	return s;
}

int vrtxsem_init(void)
{
	initq(&vrtx_sem_q);
	vrtx_sem_idmap = xnmap_create(VRTX_MAX_SEMS, 0, 0);
	return vrtx_sem_idmap ? 0 : -ENOMEM;
}

void vrtxsem_cleanup(void)
{

	xnholder_t *holder;

	while ((holder = getheadq(&vrtx_sem_q)) != NULL)
		sem_destroy_internal(link2vrtxsem(holder));

	xnmap_delete(vrtx_sem_idmap);
}

int sc_screate(unsigned initval, int opt, int *errp)
{
	int bflags = 0, semid;
	vrtxsem_t *sem;
	spl_t s;

	if (opt & ~1) {
		*errp = ER_IIP;
		return -1;
	}

	sem = (vrtxsem_t *)xnmalloc(sizeof(*sem));

	if (!sem) {
		*errp = ER_NOCB;
		return -1;
	}

	semid = xnmap_enter(vrtx_sem_idmap, -1, sem);

	if (semid < 0) {
		*errp = ER_NOCB;
		xnfree(sem);
		return -1;
	}

	if (opt == 0)
		bflags = XNSYNCH_PRIO;
	else
		bflags = XNSYNCH_FIFO;

	xnsynch_init(&sem->synchbase, bflags | XNSYNCH_DREORD);
	inith(&sem->link);
	sem->semid = semid;
	sem->magic = VRTX_SEM_MAGIC;
	sem->count = initval;

	xnlock_get_irqsave(&nklock, s);
	appendq(&vrtx_sem_q, &sem->link);
	xnlock_put_irqrestore(&nklock, s);

#ifdef CONFIG_XENO_OPT_REGISTRY
	sprintf(sem->name, "sem%d", semid);
	xnregistry_enter(sem->name, sem, &sem->handle, &__sem_pnode);
#endif /* CONFIG_XENO_OPT_REGISTRY */

	*errp = RET_OK;

	return semid;
}

void sc_sdelete(int semid, int opt, int *errp)
{
	vrtxsem_t *sem;
	spl_t s;

	if (opt & ~1) {
		*errp = ER_IIP;
		return;
	}

	xnlock_get_irqsave(&nklock, s);

	sem = xnmap_fetch(vrtx_sem_idmap, semid);

	if (sem == NULL) {
		*errp = ER_ID;
		goto unlock_and_exit;
	}

	if (opt == 0 && xnsynch_nsleepers(&sem->synchbase) > 0) {
		*errp = ER_PND;
		goto unlock_and_exit;
	}

	/* forcing delete or no task pending */
	if (sem_destroy_internal(sem) == XNSYNCH_RESCHED)
		xnpod_schedule();

	*errp = RET_OK;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);
}

void sc_spend(int semid, long timeout, int *errp)
{
	vrtxtask_t *task;
	vrtxsem_t *sem;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	sem = xnmap_fetch(vrtx_sem_idmap, semid);

	if (sem == NULL) {
		*errp = ER_ID;
		goto unlock_and_exit;
	}

	*errp = RET_OK;

	if (sem->count > 0)
		sem->count--;
	else {
		if (xnpod_unblockable_p()) {
			*errp = -EPERM;
			goto unlock_and_exit;
		}

		task = vrtx_current_task();

		task->vrtxtcb.TCBSTAT = TBSSEMA;

		if (timeout)
			task->vrtxtcb.TCBSTAT |= TBSDELAY;

		xnsynch_sleep_on(&sem->synchbase, timeout, XN_RELATIVE);

		if (xnthread_test_info(&task->threadbase, XNBREAK))
			*errp = -EINTR;
		else if (xnthread_test_info(&task->threadbase, XNRMID))
			*errp = ER_DEL;	/* Semaphore deleted while pending. */
		else if (xnthread_test_info(&task->threadbase, XNTIMEO))
			*errp = ER_TMO;	/* Timeout. */
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);
}

void sc_saccept(int semid, int *errp)
{
	vrtxsem_t *sem;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	sem = xnmap_fetch(vrtx_sem_idmap, semid);

	if (sem == NULL) {
		*errp = ER_ID;
		goto unlock_and_exit;
	}

	if (sem->count > 0) {
		sem->count--;
		*errp = RET_OK;
	} else
		*errp = ER_NMP;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);
}

void sc_spost(int semid, int *errp)
{
	vrtxsem_t *sem;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	sem = xnmap_fetch(vrtx_sem_idmap, semid);

	if (sem == NULL) {
		*errp = ER_ID;
		goto unlock_and_exit;
	}

	*errp = RET_OK;

	if (xnsynch_wakeup_one_sleeper(&sem->synchbase))
		xnpod_schedule();
	else if (sem->count == MAX_SEM_VALUE)
		*errp = ER_OVF;
	else
		sem->count++;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);
}

int sc_sinquiry(int semid, int *errp)
{
	vrtxsem_t *sem;
	int count;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	sem = xnmap_fetch(vrtx_sem_idmap, semid);

	if (sem == NULL) {
		*errp = ER_ID;
		count = 0;
	} else {
		*errp = RET_OK;
		count = sem->count;
	}

	xnlock_put_irqrestore(&nklock, s);

	return count;
}
