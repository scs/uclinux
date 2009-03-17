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

#include "psos+/pt.h"

static xnqueue_t psosptq;

void psospt_init(void)
{
	initq(&psosptq);
}

void psospt_cleanup(void)
{
	psos_pt_flush_rq(&__psos_global_rholder.ptq);
}

static inline size_t pt_overhead(size_t psize, size_t bsize)
{
	size_t m = (bsize * 8);
	size_t q = (size_t)xnarch_llimd(psize - sizeof(psospt_t), m, m + 1);
	return (psize - q + pt_align_mask) & ~pt_align_mask;
}

u_long pt_create(const char *name, void *paddr, void *laddr,	/* unused */
		 u_long psize,
		 u_long bsize, u_long flags, u_long *ptid, u_long *nbuf)
{
	u_long overhead;
	psospt_t *pt;
	char *mp;
	u_long n;
	spl_t s;

	if ((u_long)paddr & (sizeof(u_long) - 1))
		return ERR_PTADDR;

	if (bsize <= pt_align_mask)
		return ERR_BUFSIZE;

	if (bsize & (bsize - 1))
		return ERR_BUFSIZE;	/* Not a power of two. */

	if (psize < sizeof(psospt_t))
		return ERR_TINYPT;

	pt = (psospt_t *)paddr;
	inith(&pt->link);

	xnobject_copy_name(pt->name, name);
	pt->flags = flags;
	pt->bsize = (bsize + pt_align_mask) & ~pt_align_mask;
	overhead = pt_overhead(psize, pt->bsize);

	pt->nblks = (psize - overhead) / pt->bsize;
	if (pt->nblks == 0)
		return ERR_TINYPT;

	pt->psize = pt->nblks * pt->bsize;
	pt->data = (caddr_t)pt + overhead;
	pt->freelist = mp = pt->data;
	pt->ublks = 0;

	for (n = pt->nblks; n > 1; n--) {
		char *nmp = mp + pt->bsize;
		*((void **)mp) = nmp;
		mp = nmp;
	}

	*((void **)mp) = NULL;

	memset(pt->bitmap, 0, overhead - sizeof(*pt) + sizeof(pt->bitmap));
	pt->magic = PSOS_PT_MAGIC;

	inith(&pt->rlink);
	pt->rqueue = &psos_get_rholder()->ptq;
	xnlock_get_irqsave(&nklock, s);
	appendq(pt->rqueue, &pt->rlink);
	appendq(&psosptq, &pt->link);
	xnlock_put_irqrestore(&nklock, s);

	*nbuf = pt->nblks;
	*ptid = (u_long)pt;

	return SUCCESS;
}

u_long pt_delete(u_long ptid)
{
	u_long err = SUCCESS;
	psospt_t *pt;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	pt = psos_h2obj_active(ptid, PSOS_PT_MAGIC, psospt_t);

	if (!pt) {
		err = psos_handle_error(ptid, PSOS_PT_MAGIC, psospt_t);
		goto unlock_and_exit;
	}

	if (!(pt->flags & PT_DEL) && pt->ublks > 0) {
		err = ERR_BUFINUSE;
		goto unlock_and_exit;
	}

	removeq(pt->rqueue, &pt->rlink);
	psos_mark_deleted(pt);
	removeq(&psosptq, &pt->link);

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

u_long pt_getbuf(u_long ptid, void **bufaddr)
{
	u_long numblk, err = SUCCESS;
	psospt_t *pt;
	void *buf;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	pt = psos_h2obj_active(ptid, PSOS_PT_MAGIC, psospt_t);

	if (!pt) {
		err = psos_handle_error(ptid, PSOS_PT_MAGIC, psospt_t);
		goto unlock_and_exit;
	}

	if ((buf = pt->freelist) != NULL) {
		pt->freelist = *((void **)buf);
		pt->ublks++;
		numblk = ((char *)buf - pt->data) / pt->bsize;
		pt_bitmap_setbit(pt, numblk);
	} else
		err = ERR_NOBUF;

	*bufaddr = buf;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

u_long pt_retbuf(u_long ptid, void *buf)
{
	u_long numblk, err = SUCCESS;
	psospt_t *pt;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	pt = psos_h2obj_active(ptid, PSOS_PT_MAGIC, psospt_t);

	if (!pt) {
		err = psos_handle_error(ptid, PSOS_PT_MAGIC, psospt_t);
		goto unlock_and_exit;
	}

	if ((char *)buf < pt->data ||
	    (char *)buf >= pt->data + pt->psize ||
	    (((char *)buf - pt->data) % pt->bsize) != 0) {
		err = ERR_BUFADDR;
		goto unlock_and_exit;
	}

	numblk = ((char *)buf - pt->data) / pt->bsize;

	if (!pt_bitmap_tstbit(pt, numblk)) {
		err = ERR_BUFFREE;
		goto unlock_and_exit;
	}

	pt_bitmap_clrbit(pt, numblk);
	*((void **)buf) = pt->freelist;
	pt->freelist = buf;
	pt->ublks--;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

u_long pt_ident(const char *name, u_long node, u_long *ptid)
{
	u_long err = SUCCESS;
	xnholder_t *holder;
	psospt_t *pt;
	spl_t s;

	if (node > 1)
		return ERR_NODENO;

	xnlock_get_irqsave(&nklock, s);

	for (holder = getheadq(&psosptq); holder;
	     holder = nextq(&psosptq, holder)) {
		pt = link2psospt(holder);

		if (!strcmp(pt->name, name)) {
			*ptid = (u_long)pt;
			goto unlock_and_exit;
		}
	}

	err = ERR_OBJNF;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/*
 * IMPLEMENTATION NOTES:
 *
 * - A partition memory layout is as follows:
 *
 *   struct psospt {
 *      Partition's superblock
 *      (char *data => pointer to the user data area)
 *      (u_long bitmap[1] => first word of bitmap)
 *   }
 *   [...block status bitmap (busy/free)...]
 *   [...user data area...]
 *
 * - Each free block starts with a link to the next free block
 * in the partition's free list. A NULL link ends this list.
 */
