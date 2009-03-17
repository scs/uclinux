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

#define WIND_SEMB_OPTION_MASK (SEM_Q_FIFO|SEM_Q_PRIORITY)
#define WIND_SEMC_OPTION_MASK (SEM_Q_FIFO|SEM_Q_PRIORITY)
#define WIND_SEMM_OPTION_MASK SEM_OPTION_MASK

#define WIND_SEM_DEL_SAFE XNSYNCH_SPARE0

static const sem_vtbl_t semb_vtbl;
static const sem_vtbl_t semc_vtbl;
static const sem_vtbl_t semm_vtbl;

static void sem_destroy_internal(wind_sem_t *sem);
static SEM_ID sem_create_internal(int flags, const sem_vtbl_t *vtbl, int count);

#ifdef CONFIG_XENO_EXPORT_REGISTRY

static int sem_read_proc(char *page,
			 char **start,
			 off_t off, int count, int *eof, void *data)
{
	wind_sem_t *sem = (wind_sem_t *)data;
	char *p = page;
	int len;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	p += sprintf(p, "type=%s:value=%u\n", sem->vtbl->type, sem->count);

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

extern xnptree_t __vxworks_ptree;

static xnpnode_t sem_pnode = {

	.dir = NULL,
	.type = "semaphores",
	.entries = 0,
	.read_proc = &sem_read_proc,
	.write_proc = NULL,
	.root = &__vxworks_ptree,
};

#elif defined(CONFIG_XENO_OPT_REGISTRY)

static xnpnode_t sem_pnode = {

	.type = "semaphores"
};

#endif /* CONFIG_XENO_EXPORT_REGISTRY */

void wind_sem_init(void)
{
}

void wind_sem_cleanup(void)
{
	wind_sem_flush_rq(&__wind_global_rholder.semq);
}

SEM_ID semBCreate(int flags, SEM_B_STATE state)
{
	int bflags = 0;

	error_check(flags & ~WIND_SEMB_OPTION_MASK, S_semLib_INVALID_QUEUE_TYPE,
		    return 0);

	error_check(state != SEM_EMPTY
		    && state != SEM_FULL, S_semLib_INVALID_STATE, return 0);

	if (flags & SEM_Q_PRIORITY)
		bflags |= XNSYNCH_PRIO;

	return sem_create_internal(bflags, &semb_vtbl, (int)state);
}

SEM_ID semCCreate(int flags, int count)
{
	int bflags = 0;

	error_check(flags & ~WIND_SEMC_OPTION_MASK, S_semLib_INVALID_QUEUE_TYPE,
		    return 0);

	if (flags & SEM_Q_PRIORITY)
		bflags |= XNSYNCH_PRIO;

	return sem_create_internal(bflags, &semc_vtbl, count);
}

SEM_ID semMCreate(int flags)
{
	int bflags = 0;

	error_check(flags & ~WIND_SEMM_OPTION_MASK, S_semLib_INVALID_QUEUE_TYPE,
		    return 0);

	if (flags & SEM_Q_PRIORITY)
		bflags |= XNSYNCH_PRIO;

	if (flags & SEM_INVERSION_SAFE) {
		if (!(flags & SEM_Q_PRIORITY)) {
			wind_errnoset(S_semLib_INVALID_OPTION);
			return 0;
		}

		bflags |= XNSYNCH_PIP;
	}

	if (flags & SEM_DELETE_SAFE)
		bflags |= WIND_SEM_DEL_SAFE;

	return sem_create_internal(bflags, &semm_vtbl, 0);
}

STATUS semDelete(SEM_ID sem_id)
{
	wind_sem_t *sem;
	spl_t s;

	check_NOT_ISR_CALLABLE(return ERROR);

	xnlock_get_irqsave(&nklock, s);
	check_OBJ_ID_ERROR(sem_id, wind_sem_t, sem, WIND_SEM_MAGIC, goto error);
	sem_destroy_internal(sem);
	xnlock_put_irqrestore(&nklock, s);

	return OK;

      error:
	xnlock_put_irqrestore(&nklock, s);
	return ERROR;
}

STATUS semTake(SEM_ID sem_id, int timeout)
{
	xnticks_t xntimeout;
	wind_sem_t *sem;
	spl_t s;

	check_NOT_ISR_CALLABLE(return ERROR);

	switch (timeout) {
	case WAIT_FOREVER:
		xntimeout = XN_INFINITE;
		break;
	case NO_WAIT:
		xntimeout = XN_NONBLOCK;
		break;
	default:
		xntimeout = timeout;
	}

	xnlock_get_irqsave(&nklock, s);
	check_OBJ_ID_ERROR(sem_id, wind_sem_t, sem, WIND_SEM_MAGIC, goto error);

	if (sem->vtbl->take(sem, xntimeout) == ERROR)
		goto error;

	xnlock_put_irqrestore(&nklock, s);
	return OK;

      error:
	xnlock_put_irqrestore(&nklock, s);
	return ERROR;

}

STATUS semGive(SEM_ID sem_id)
{
	wind_sem_t *sem;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	check_OBJ_ID_ERROR(sem_id, wind_sem_t, sem, WIND_SEM_MAGIC, goto error);

	if (sem->vtbl->give(sem) == ERROR)
		goto error;

	xnlock_put_irqrestore(&nklock, s);
	return OK;

      error:
	xnlock_put_irqrestore(&nklock, s);
	return ERROR;
}

STATUS semFlush(SEM_ID sem_id)
{
	wind_sem_t *sem;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	check_OBJ_ID_ERROR(sem_id, wind_sem_t, sem, WIND_SEM_MAGIC, goto error);

	if (sem->vtbl->flush(sem) == ERROR)
		goto error;

	xnlock_put_irqrestore(&nklock, s);
	return OK;

      error:
	xnlock_put_irqrestore(&nklock, s);
	return ERROR;
}

/* Must be called with nklock locked, interrupts off. */
static STATUS semb_take(wind_sem_t *sem, xnticks_t to)
{
	xnthread_t *thread = xnpod_current_thread();

	if (sem->count > 0)
		--sem->count;
	else {
		error_check(to == XN_NONBLOCK, S_objLib_OBJ_UNAVAILABLE,
			    return ERROR);

		xnsynch_sleep_on(&sem->synchbase, to, XN_RELATIVE);

		error_check(xnthread_test_info(thread, XNBREAK), -EINTR,
			    return ERROR);

		error_check(xnthread_test_info(thread, XNRMID),
			    S_objLib_OBJ_DELETED, return ERROR);

		error_check(xnthread_test_info(thread, XNTIMEO),
			    S_objLib_OBJ_TIMEOUT, return ERROR);
	}

	return OK;
}

/* Must be called with nklock locked, interrupts off. */
static STATUS semb_give(wind_sem_t *sem)
{
	if (xnsynch_wakeup_one_sleeper(&sem->synchbase) != NULL)
		xnpod_schedule();
	else {
		if (sem->count != 0) {
			wind_errnoset(S_semLib_INVALID_OPERATION);
			return ERROR;
		}
		sem->count = 1;
	}

	return OK;
}

/* Must be called with nklock locked, interrupts off. */
static STATUS semb_flush(wind_sem_t *sem)
{
	if (xnsynch_flush(&sem->synchbase, 0) == XNSYNCH_RESCHED)
		xnpod_schedule();

	return OK;
}

static const sem_vtbl_t semb_vtbl = {
      take:&semb_take,
      give:&semb_give,
      flush:&semb_flush,
      type:"binary"
};

/* Must be called with nklock locked, interrupts off. */
static STATUS semc_give(wind_sem_t *sem)
{
	if (xnsynch_wakeup_one_sleeper(&sem->synchbase) != NULL)
		xnpod_schedule();
	else
		++sem->count;

	return OK;
}

static const sem_vtbl_t semc_vtbl = {
      take:&semb_take,
      give:&semc_give,
      flush:&semb_flush,
      type:"counting"
};

/* Must be called with nklock locked, interrupts off. */
static STATUS semm_take(wind_sem_t *sem, xnticks_t to)
{
	xnthread_t *cur = xnpod_current_thread();

	if (xnsynch_owner(&sem->synchbase) == NULL) {
		xnsynch_set_owner(&sem->synchbase, cur);
		goto grab_sem;
	}

	if (xnsynch_owner(&sem->synchbase) == cur) {
		sem->count++;
		return OK;
	}

	error_check(to == XN_NONBLOCK, S_objLib_OBJ_UNAVAILABLE,
		    return ERROR);

	xnsynch_sleep_on(&sem->synchbase, to, XN_RELATIVE);

	error_check(xnthread_test_info(cur, XNBREAK),
		    -EINTR, return ERROR);

	error_check(xnthread_test_info(cur, XNRMID),
		    S_objLib_OBJ_DELETED, return ERROR);

	error_check(xnthread_test_info(cur, XNTIMEO),
		    S_objLib_OBJ_TIMEOUT, return ERROR);
 grab_sem:
	/*
	 * xnsynch_sleep_on() might have stolen the resource, so we
	 * need to put our internal data in sync.
	 */
	sem->count = 1;

	if (xnsynch_test_flags(&sem->synchbase, WIND_SEM_DEL_SAFE))
		taskSafeInner(cur);

	return OK;
}

/* Must be called with nklock locked, interrupts off. */
static STATUS semm_give(wind_sem_t *sem)
{
	xnthread_t *cur = xnpod_current_thread();
	int resched = 0;

	check_NOT_ISR_CALLABLE(return ERROR);

	if (cur != xnsynch_owner(&sem->synchbase)) {
		wind_errnoset(S_semLib_INVALID_OPERATION);
		return ERROR;
	}

	if (--sem->count > 0)
		return OK;

	if (xnsynch_wakeup_one_sleeper(&sem->synchbase)) {
		sem->count = 1;
		resched = 1;
	}

	if (xnsynch_test_flags(&sem->synchbase, WIND_SEM_DEL_SAFE))
		if (taskUnsafeInner(cur))
			resched = 1;

	if (resched)
		xnpod_schedule();

	return OK;
}

static STATUS semm_flush(wind_sem_t *sem __attribute__ ((unused)))
{
	wind_errnoset(S_semLib_INVALID_OPERATION);

	return ERROR;
}

static const sem_vtbl_t semm_vtbl = {
      take:&semm_take,
      give:&semm_give,
      flush:&semm_flush,
      type:"mutex"
};

static SEM_ID sem_create_internal(int flags, const sem_vtbl_t *vtbl, int count)
{
	wind_sem_t *sem;
	spl_t s;

	error_check(xnpod_asynch_p(), -EPERM, return 0);

	check_alloc(wind_sem_t, sem, return 0);

	xnsynch_init(&sem->synchbase, (xnflags_t)flags);
	sem->magic = WIND_SEM_MAGIC;
	sem->count = count;
	sem->vtbl = vtbl;
	inith(&sem->rlink);
	sem->rqueue = &wind_get_rholder()->semq;

	xnlock_get_irqsave(&nklock, s);
	appendq(sem->rqueue, &sem->rlink);
	xnlock_put_irqrestore(&nklock, s);
#ifdef CONFIG_XENO_OPT_REGISTRY
	{
		static unsigned long sem_ids;

		sprintf(sem->name, "sem%lu", sem_ids++);

		if (xnregistry_enter(sem->name, sem, &sem->handle, &sem_pnode)) {
			wind_errnoset(S_objLib_OBJ_ID_ERROR);
			semDelete((SEM_ID)sem);
			return 0;
		}
	}
#endif /* CONFIG_XENO_OPT_REGISTRY */

	return (SEM_ID)sem;
}

static void sem_destroy_internal(wind_sem_t *sem)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	xnsynch_destroy(&sem->synchbase);
#ifdef CONFIG_XENO_OPT_REGISTRY
	xnregistry_remove(sem->handle);
#endif /* CONFIG_XENO_OPT_REGISTRY */
	wind_mark_deleted(sem);
	removeq(sem->rqueue, &sem->rlink);
	xnlock_put_irqrestore(&nklock, s);

	xnfree(sem);
}
