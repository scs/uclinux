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
#include <psos+/rn.h>

static xnqueue_t psosrnq;

static psosrn_t *psosrn0;

static void *rn0addr;

static int rn_destroy_internal(psosrn_t *rn);

#ifdef CONFIG_XENO_EXPORT_REGISTRY

static int rn_read_proc(char *page,
			char **start,
			off_t off, int count, int *eof, void *data)
{
	psosrn_t *rn = (psosrn_t *)data;
	char *p = page;
	int len;
	spl_t s;

	p += sprintf(p, "size=%lu:used=%lu\n",
		     (u_long)rn->rnsize, xnheap_used_mem(&rn->heapbase));

	xnlock_get_irqsave(&nklock, s);

	if (xnsynch_nsleepers(&rn->synchbase) == 0) {
		xnpholder_t *holder;

		/* Pended region -- dump waiters. */

		holder = getheadpq(xnsynch_wait_queue(&rn->synchbase));

		while (holder) {
			xnthread_t *sleeper = link2thread(holder, plink);
			p += sprintf(p, "+%s\n", xnthread_name(sleeper));
			holder =
			    nextpq(xnsynch_wait_queue(&rn->synchbase), holder);
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

static xnpnode_t rn_pnode = {

	.dir = NULL,
	.type = "regions",
	.entries = 0,
	.read_proc = &rn_read_proc,
	.write_proc = NULL,
	.root = &__psos_ptree,
};

#elif defined(CONFIG_XENO_OPT_REGISTRY)

static xnpnode_t rn_pnode = {

	.type = "regions"
};

#endif /* CONFIG_XENO_EXPORT_REGISTRY */

int psosrn_init(u_long rn0size)
{
	u_long allocsize, rn0id;

	initq(&psosrnq);

	if (rn0size < 2048)
		rn0size = 2048;

#ifdef CONFIG_XENO_OPT_PERVASIVE
	rn0addr = NULL;	/* rn_create() will allocate a shared region. */
#else /* !CONFIG_XENO_OPT_PERVASIVE */
	rn0addr = xnmalloc(rn0size);

	if (!rn0addr)
		return -ENOMEM;
#endif /* !CONFIG_XENO_OPT_PERVASIVE */

	rn_create("RN#0", rn0addr, rn0size, 128, RN_FORCEDEL, &rn0id,
		  &allocsize);

	psosrn0 = (psosrn_t *)rn0id;	/* Eeek... */

	return 0;
}

void psosrn_cleanup(void)
{
	psos_rn_flush_rq(&__psos_global_rholder.rnq);

	if (rn0addr)
		xnfree(rn0addr);
}

static int rn_destroy_internal(psosrn_t *rn)
{
	int rc;

	removeq(rn->rqueue, &rn->rlink);
	removeq(&psosrnq, &rn->link);
	rc = xnsynch_destroy(&rn->synchbase);
	psos_mark_deleted(rn);
#ifdef CONFIG_XENO_OPT_REGISTRY
	if (rn->handle)
		xnregistry_remove(rn->handle);
#endif /* CONFIG_XENO_OPT_REGISTRY */
#ifdef CONFIG_XENO_OPT_PERVASIVE
	if (xnheap_mapped_p(&rn->heapbase))
		xnheap_destroy_mapped(&rn->heapbase, NULL, NULL);
	else
#endif /* CONFIG_XENO_OPT_PERVASIVE */
		xnheap_destroy(&rn->heapbase, NULL, NULL);

	xnfree(rn);

	return rc;
}

u_long rn_create(const char *name,
		 void *rnaddr,
		 u_long rnsize,
		 u_long usize, u_long flags, u_long *rnid, u_long *allocsize)
{
	int bflags = 0;
	psosrn_t *rn;
	spl_t s;

	if ((u_long)rnaddr & (sizeof(u_long) - 1))
		return ERR_RNADDR;

	if (usize < 16)
		return ERR_TINYUNIT;

	if ((usize & (usize - 1)) != 0)
		return ERR_UNITSIZE;	/* Not a power of two. */

	if (rnsize <= sizeof(psosrn_t))
		return ERR_TINYRN;

	if (flags & RN_PRIOR)
		bflags |= XNSYNCH_PRIO;

	if (flags & RN_DEL)
		bflags |= RN_FORCEDEL;

	rn = (psosrn_t *)xnmalloc(sizeof(*rn));

	if (rn == NULL)
		return -ENOMEM;

#ifdef __KERNEL__
	if (rnaddr == NULL) {
#ifdef CONFIG_XENO_OPT_PERVASIVE
		u_long err;

		rnsize = xnheap_rounded_size(rnsize, PAGE_SIZE),
		err = xnheap_init_mapped(&rn->heapbase, rnsize, 0);

		if (err)
			return err;

		rn->mm = NULL;
#else /* !CONFIG_XENO_OPT_PERVASIVE */
		return ERR_RNADDR;
#endif /* CONFIG_XENO_OPT_PERVASIVE */
	} else
#endif /* __KERNEL__ */
		/*
		 * Caller must have accounted for overhead and
		 * alignment since it supplies the memory space.
		 */
		if (xnheap_init(&rn->heapbase, rnaddr, rnsize, XNCORE_PAGE_SIZE) != 0)
			return ERR_TINYRN;

	inith(&rn->link);
	rn->rnsize = rnsize;
	rn->usize = usize;
	xnobject_copy_name(rn->name, name);

	xnsynch_init(&rn->synchbase, bflags);
	rn->magic = PSOS_RN_MAGIC;

	inith(&rn->rlink);
	rn->rqueue = &psos_get_rholder()->rnq;
	xnlock_get_irqsave(&nklock, s);
	appendq(rn->rqueue, &rn->rlink);
	appendq(&psosrnq, &rn->link);
	xnlock_put_irqrestore(&nklock, s);
#ifdef CONFIG_XENO_OPT_REGISTRY
	{
		static unsigned long rn_ids;
		u_long err;

		if (!*name)
			sprintf(rn->name, "anon_rn%lu", rn_ids++);

		err = xnregistry_enter(rn->name, rn, &rn->handle, &rn_pnode);

		if (err) {
			rn->handle = XN_NO_HANDLE;
			rn_delete((u_long)rn);
			return err;
		}
	}
#endif /* CONFIG_XENO_OPT_REGISTRY */

	*rnid = (u_long)rn;
	*allocsize = rn->rnsize;

	return SUCCESS;
}

u_long rn_delete(u_long rnid)
{
	u_long err = SUCCESS;
	psosrn_t *rn;
	spl_t s;

	if (rnid == 0)		/* May not delete region #0 */
		return ERR_OBJID;

	xnlock_get_irqsave(&nklock, s);

	rn = psos_h2obj_active(rnid, PSOS_RN_MAGIC, psosrn_t);

	if (!rn) {
		err = psos_handle_error(rnid, PSOS_RN_MAGIC, psosrn_t);
		goto unlock_and_exit;
	}

	if (rn_destroy_internal(rn) == XNSYNCH_RESCHED) {
		err = ERR_TATRNDEL;
		xnpod_schedule();
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

u_long rn_getseg(u_long rnid,
		 u_long size, u_long flags, u_long timeout, void **segaddr)
{
	u_long err = SUCCESS;
	psostask_t *task;
	psosrn_t *rn;
	void *chunk;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (rnid == 0)
		rn = psosrn0;
	else {
		rn = psos_h2obj_active(rnid, PSOS_RN_MAGIC, psosrn_t);

		if (!rn) {
			err = psos_handle_error(rnid, PSOS_RN_MAGIC, psosrn_t);
			goto unlock_and_exit;
		}
	}

	if (size > rn->rnsize) {
		err = ERR_TOOBIG;
		goto unlock_and_exit;
	}

	chunk = xnheap_alloc(&rn->heapbase, size);

	if (chunk == NULL) {
		if (flags & RN_NOWAIT) {
			/* Be gracious to those who are lazy with respect to
			   return code checking -- set the pointer to NULL :o> */
			*segaddr = NULL;
			err = ERR_NOSEG;
			goto unlock_and_exit;
		}

		if (xnpod_unblockable_p()) {
		    err = -EPERM;
		    goto unlock_and_exit;
		}

		task = psos_current_task();
		task->waitargs.region.size = size;
		task->waitargs.region.chunk = NULL;
		xnsynch_sleep_on(&rn->synchbase, timeout, XN_RELATIVE);

		if (xnthread_test_info(&task->threadbase, XNBREAK))
			err = -EINTR;	/* Unblocked. */
		else if (xnthread_test_info(&task->threadbase, XNRMID))
			err = ERR_RNKILLD;	/* Region deleted while pending. */
		else if (xnthread_test_info(&task->threadbase, XNTIMEO))
			err = ERR_TIMEOUT;	/* Timeout. */

		chunk = task->waitargs.region.chunk;
	}

	*segaddr = chunk;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

u_long rn_ident(const char *name, u_long *rnid)
{
	u_long err = SUCCESS;
	xnholder_t *holder;
	psosrn_t *rn;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	for (holder = getheadq(&psosrnq); holder;
	     holder = nextq(&psosrnq, holder)) {
		rn = link2psosrn(holder);

		if (!strcmp(rn->name, name)) {
			*rnid = (u_long)rn;
			goto unlock_and_exit;
		}
	}

	err = ERR_OBJNF;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

u_long rn_retseg(u_long rnid, void *chunk)
{
	u_long err = SUCCESS;
	xnsynch_t *synch;
	psosrn_t *rn;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (rnid == 0)
		rn = psosrn0;
	else {
		rn = psos_h2obj_active(rnid, PSOS_RN_MAGIC, psosrn_t);

		if (!rn) {
			err = psos_handle_error(rnid, PSOS_RN_MAGIC, psosrn_t);
			goto unlock_and_exit;
		}
	}

	switch (xnheap_free(&rn->heapbase, chunk)) {
	case -EINVAL:
		err = ERR_SEGADDR;
		goto unlock_and_exit;
	case -EFAULT:
		err = ERR_NOTINRN;
		goto unlock_and_exit;
	}

	/* Attempt to wake up one or more threads pending on a memory
	   request since some memory has just been released. */

	synch = &rn->synchbase;

	if (xnsynch_nsleepers(synch) > 0) {
		xnpholder_t *holder, *nholder;

		nholder = getheadpq(xnsynch_wait_queue(synch));

		while ((holder = nholder) != NULL) {
			psostask_t *sleeper =
			    thread2psostask(link2thread(holder, plink));

			chunk =
			    xnheap_alloc(&rn->heapbase,
					 sleeper->waitargs.region.size);
			if (chunk) {
				nholder =
				    xnsynch_wakeup_this_sleeper(synch, holder);
				sleeper->waitargs.region.chunk = chunk;
			} else
				nholder =
				    nextpq(xnsynch_wait_queue(synch), holder);
		}

		xnpod_schedule();
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}
