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

#include <nucleus/jhash.h>
#include <vrtx/task.h>
#include <vrtx/mb.h>

static xnqueue_t vrtx_mbox_q;

/* Note: In the current implementation, mailbox addresses passed to
 * the VRTX services are never dereferenced, but only used as hash
 * keys. */

#ifdef CONFIG_XENO_EXPORT_REGISTRY

static int __mb_read_proc(char *page,
			  char **start,
			  off_t off, int count, int *eof, void *data)
{
	vrtxmb_t *mb = (vrtxmb_t *)data;
	char *p = page;
	int len;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (xnsynch_nsleepers(&mb->synchbase) > 0) {
		xnpholder_t *holder;

		holder = getheadpq(xnsynch_wait_queue(&mb->synchbase));

		while (holder) {
			xnthread_t *sleeper = link2thread(holder, plink);
			p += sprintf(p, "+%s\n", xnthread_name(sleeper));
			holder =
			    nextpq(xnsynch_wait_queue(&mb->synchbase),
				   holder);
		}
	} else
		/* Mailbox not pended. */
		p += sprintf(p, "=%p\n", mb->msg);

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

static xnpnode_t __mb_pnode = {

	.dir = NULL,
	.type = "mailboxes",
	.entries = 0,
	.read_proc = &__mb_read_proc,
	.write_proc = NULL,
	.root = &__vrtx_ptree,
};

#elif defined(CONFIG_XENO_OPT_REGISTRY)

static xnpnode_t __mb_pnode = {

	.type = "mailboxes"
};

#endif /* CONFIG_XENO_EXPORT_REGISTRY */

#define MB_HASHBITS 8

static vrtxmb_t *jhash_buckets[1 << MB_HASHBITS];	/* Guaranteed zero */

union jhash_union {

	char **key;
	uint32_t val;
};

static void mb_hash(char **pkey, vrtxmb_t * mb)
{
	union jhash_union hkey = {.key = pkey };
	vrtxmb_t **bucketp;
	uint32_t hash;
	spl_t s;

	hash = jhash2(&hkey.val, sizeof(pkey) / sizeof(uint32_t), 0);
	bucketp = &jhash_buckets[hash & ((1 << MB_HASHBITS) - 1)];

	xnlock_get_irqsave(&nklock, s);
	mb->hnext = *bucketp;
	*bucketp = mb;
	xnlock_put_irqrestore(&nklock, s);
}

static void mb_unhash(char **pkey)
{
	union jhash_union hkey = {.key = pkey };
	vrtxmb_t **tail, *mb;
	uint32_t hash;
	spl_t s;

	hash = jhash2(&hkey.val, sizeof(pkey) / sizeof(uint32_t), 0);
	tail = &jhash_buckets[hash & ((1 << MB_HASHBITS) - 1)];

	xnlock_get_irqsave(&nklock, s);

	mb = *tail;

	while (mb != NULL && mb->mboxp != pkey) {
		tail = &mb->hnext;
		mb = *tail;
	}

	if (mb)
		*tail = mb->hnext;

	xnlock_put_irqrestore(&nklock, s);
}

static vrtxmb_t *mb_find(char **pkey)
{
	union jhash_union hkey = {.key = pkey };
	uint32_t hash;
	vrtxmb_t *mb;
	spl_t s;

	hash = jhash2(&hkey.val, sizeof(pkey) / sizeof(uint32_t), 0);

	xnlock_get_irqsave(&nklock, s);

	mb = jhash_buckets[hash & ((1 << MB_HASHBITS) - 1)];

	while (mb != NULL && mb->mboxp != pkey)
		mb = mb->hnext;

	xnlock_put_irqrestore(&nklock, s);

	return mb;
}

void vrtxmb_init(void)
{
	initq(&vrtx_mbox_q);
}

void vrtxmb_cleanup(void)
{
	xnholder_t *holder;
	vrtxmb_t *mb;

	while ((holder = getq(&vrtx_mbox_q)) != NULL) {
		mb = link2vrtxmb(holder);
		xnsynch_destroy(&mb->synchbase);
#ifdef CONFIG_XENO_OPT_REGISTRY
		xnregistry_remove(mb->handle);
#endif /* CONFIG_XENO_OPT_REGISTRY */
		mb_unhash(mb->mboxp);
		xnfree(mb);
	}
}

/*
 * Manages a hash of xnsynch_t objects, indexed by mailboxes
 * addresses.  Given a mailbox, returns its descriptor address.  If
 * the mailbox is not found, creates a descriptor for it. Must be
 * called interrupts off, nklock locked.
 */

vrtxmb_t *mb_map(char **mboxp)
{
	vrtxmb_t *mb = mb_find(mboxp);

	if (mb)
		return mb;

	/* New mailbox, create a new slot for it. */

	mb = (vrtxmb_t *) xnmalloc(sizeof(*mb));

	if (!mb)
		return NULL;

	inith(&mb->link);
	mb->mboxp = mboxp;
	mb->msg = NULL;
	mb->hnext = NULL;
	xnsynch_init(&mb->synchbase, XNSYNCH_PRIO | XNSYNCH_DREORD);
	appendq(&vrtx_mbox_q, &mb->link);
	mb_hash(mboxp, mb);

#ifdef CONFIG_XENO_OPT_REGISTRY
	sprintf(mb->name, "mb@%p", mboxp);
	xnregistry_enter(mb->name, mb, &mb->handle, &__mb_pnode);
#endif /* CONFIG_XENO_OPT_REGISTRY */

	return mb;
}

char *sc_accept(char **mboxp, int *errp)
{
	char *msg = NULL;
	vrtxmb_t *mb;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	mb = mb_map(mboxp);

	if (!mb) {
		*errp = ER_NOCB;
		goto unlock_and_exit;
	}

	msg = mb->msg;

	if (msg == NULL)
		*errp = ER_NMP;
	else {
		mb->msg = NULL;
		*errp = RET_OK;
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return msg;
}

char *sc_pend(char **mboxp, long timeout, int *errp)
{
	char *msg = NULL;
	vrtxtask_t *task;
	vrtxmb_t *mb;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	mb = mb_map(mboxp);

	if (!mb) {
		*errp = ER_NOCB;
		goto unlock_and_exit;
	}

	if (mb->msg != NULL)
		goto done;

	if (xnpod_unblockable_p()) {
		*errp = -EPERM;
		goto unlock_and_exit;
	}

	task = vrtx_current_task();
	task->vrtxtcb.TCBSTAT = TBSMBOX;

	if (timeout)
		task->vrtxtcb.TCBSTAT |= TBSDELAY;

	xnsynch_sleep_on(&mb->synchbase, timeout, XN_RELATIVE);

	if (xnthread_test_info(&task->threadbase, XNBREAK)) {
		*errp = -EINTR;
		goto unlock_and_exit;
	}

	if (xnthread_test_info(&task->threadbase, XNTIMEO)) {
		*errp = ER_TMO;
		goto unlock_and_exit;
	}

      done:

	msg = mb->msg;
	mb->msg = NULL;
	*errp = RET_OK;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return msg;
}

void sc_post(char **mboxp, char *msg, int *errp)
{
	vrtxmb_t *mb;
	spl_t s;

	if (msg == NULL) {
		*errp = ER_ZMW;
		return;
	}

	xnlock_get_irqsave(&nklock, s);

	mb = mb_map(mboxp);

	if (!mb) {
		*errp = ER_NOCB;
		goto unlock_and_exit;
	}

	if (mb->msg != NULL) {
		*errp = ER_MIU;
		goto unlock_and_exit;
	}

	mb->msg = msg;
	*errp = RET_OK;

	/* xnsynch_wakeup_one_sleeper() readies the front thread */
	if (xnsynch_wakeup_one_sleeper(&mb->synchbase))
		xnpod_schedule();

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);
}
