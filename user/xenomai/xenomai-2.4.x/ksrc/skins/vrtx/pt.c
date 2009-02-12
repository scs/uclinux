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

#include <vrtx/pt.h>

xnmap_t *vrtx_pt_idmap;

static xnqueue_t vrtx_pt_q;

#ifdef CONFIG_XENO_EXPORT_REGISTRY

static int __pt_read_proc(char *page,
			  char **start,
			  off_t off, int count, int *eof, void *data)
{
	vrtxpt_t *pt = (vrtxpt_t *)data;
	char *p = page;
	int len;

	p += sprintf(p, "bsize=%lu:f_blocks=%lu:u_blocks=%lu\n",
		     pt->bsize, pt->fblks, pt->ublks);

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

static xnpnode_t __pt_pnode = {

	.dir = NULL,
	.type = "partitions",
	.entries = 0,
	.read_proc = &__pt_read_proc,
	.write_proc = NULL,
	.root = &__vrtx_ptree,
};

#elif defined(CONFIG_XENO_OPT_REGISTRY)

static xnpnode_t __pt_pnode = {

	.type = "partitions"
};

#endif /* CONFIG_XENO_EXPORT_REGISTRY */

static void vrtxpt_delete_internal(vrtxpt_t *pt)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	removeq(&vrtx_pt_q, &pt->link);
	xnmap_remove(vrtx_pt_idmap, pt->pid);
#ifdef CONFIG_XENO_OPT_REGISTRY
	xnregistry_remove(pt->handle);
#endif /* CONFIG_XENO_OPT_REGISTRY */
	vrtx_mark_deleted(pt);
	xnlock_clear_irqon(&nklock);

#ifdef CONFIG_XENO_OPT_PERVASIVE
	if (pt->sysheap) {
		xnheap_destroy_mapped(pt->sysheap, NULL, NULL);
		xnfree(pt->sysheap);
	}
#endif /* CONFIG_XENO_OPT_PERVASIVE */

	xnlock_put_irqrestore(&nklock, s);
}

int vrtxpt_init(void)
{
	initq(&vrtx_pt_q);
	vrtx_pt_idmap = xnmap_create(VRTX_MAX_PTS, VRTX_MAX_PTS / 2, 0);
	return vrtx_pt_idmap ? 0 : -ENOMEM;
}

void vrtxpt_cleanup(void)
{

	xnholder_t *holder;

	while ((holder = getheadq(&vrtx_pt_q)) != NULL) {
		vrtxpt_t *pt = link2vrtxpt(holder);
		vrtxpt_delete_internal(pt);
	}

	xnmap_delete(vrtx_pt_idmap);
}

static int vrtxpt_add_extent(vrtxpt_t *pt, char *extaddr, long extsize)
{
	u_long bitmapsize;
	vrtxptext_t *ptext;
	char *mp;
	spl_t s;
	long n;

	if (extsize <= pt->bsize + sizeof(vrtxptext_t))
		return ER_IIP;

	extsize -= sizeof(vrtxptext_t);
	ptext = (vrtxptext_t *) extaddr;
	inith(&ptext->link);

	bitmapsize = (extsize * 8) / (pt->bsize + 8);
	bitmapsize = (bitmapsize + ptext_align_mask) & ~ptext_align_mask;

	if (bitmapsize <= ptext_align_mask)
		return ER_IIP;

	ptext->nblks = (extsize - bitmapsize) / pt->bsize;

	if (ptext->nblks > 65534)
		return ER_IIP;

	ptext->extsize = ptext->nblks * pt->bsize;
	ptext->data = (char *)ptext->bitmap + bitmapsize;
	ptext->freelist = mp = ptext->data;

	pt->fblks += ptext->nblks;

	for (n = ptext->nblks; n > 1; n--) {
		char *nmp = mp + pt->bsize;
		*((void **)mp) = nmp;
		mp = nmp;
	}

	*((void **)mp) = NULL;

	for (n = bitmapsize / sizeof(u_long) - 1; n >= 0; n--)
		ptext->bitmap[n] = 0;

	xnlock_get_irqsave(&nklock, s);
	appendq(&pt->extq, &ptext->link);
	xnlock_put_irqrestore(&nklock, s);

	return RET_OK;
}

int sc_pcreate(int pid, char *paddr, long psize, long bsize, int *errp)
{
	vrtxpt_t *pt;
	spl_t s;

	if (pid < -1 ||
	    bsize <= ptext_align_mask ||
	    psize < bsize + sizeof(vrtxpt_t) + sizeof(vrtxptext_t)) {
		*errp = ER_IIP;
		return -1;
	}

	pt = (vrtxpt_t *)paddr;
	inith(&pt->link);
	initq(&pt->extq);
	pt->bsize = (bsize + ptext_align_mask) & ~ptext_align_mask;
	pt->ublks = 0;
	pt->pid = pid;
#ifdef CONFIG_XENO_OPT_PERVASIVE
	pt->sysheap = NULL;
#endif /* CONFIG_XENO_OPT_PERVASIVE */

	*errp =
	    vrtxpt_add_extent(pt, (char *)pt + sizeof(*pt),
			      psize - sizeof(*pt));

	if (*errp != RET_OK)
		return -1;

	pid = xnmap_enter(vrtx_pt_idmap, pid, pt);

	if (pid < 0) {
		*errp = ER_PID;
		return -1;
	}

	pt->pid = pid;
	pt->magic = VRTX_PT_MAGIC;

	xnlock_get_irqsave(&nklock, s);
	appendq(&vrtx_pt_q, &pt->link);
	xnlock_put_irqrestore(&nklock, s);
#ifdef CONFIG_XENO_OPT_REGISTRY
	sprintf(pt->name, "pt%d", pid);
	xnregistry_enter(pt->name, pt, &pt->handle, &__pt_pnode);
#endif /* CONFIG_XENO_OPT_REGISTRY */

	return pid;
}

void sc_pdelete(int pid, int opt, int *errp)
{
	vrtxpt_t *pt;
	spl_t s;

	if (opt & ~1) {
		*errp = ER_IIP;
		return;
	}

	xnlock_get_irqsave(&nklock, s);

	pt = xnmap_fetch(vrtx_pt_idmap, pid);

	if (pt == NULL) {
		*errp = ER_PID;
		goto unlock_and_exit;
	}

	vrtxpt_delete_internal(pt);

	*errp = RET_OK;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);
}

char *sc_gblock(int pid, int *errp)
{
	vrtxptext_t *ptext;
	xnholder_t *holder;
	void *buf = NULL;
	u_long numblk;
	vrtxpt_t *pt;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	pt = xnmap_fetch(vrtx_pt_idmap, pid);

	if (pt == NULL) {
		*errp = ER_PID;
		goto unlock_and_exit;
	}

	for (holder = getheadq(&pt->extq);
	     holder; holder = nextq(&pt->extq, holder)) {
		ptext = link2vrtxptext(holder);

		if ((buf = ptext->freelist) != NULL) {
			ptext->freelist = *((void **)buf);
			pt->ublks++;
			pt->fblks--;
			numblk = ((char *)buf - ptext->data) / pt->bsize;
			ptext_bitmap_setbit(ptext, numblk);
			break;
		}
	}

	xnlock_put_irqrestore(&nklock, s);

	*errp = (buf == NULL ? ER_MEM : RET_OK);

      unlock_and_exit:

	return (char *)buf;
}

void sc_rblock(int pid, char *buf, int *errp)
{
	vrtxptext_t *ptext;
	xnholder_t *holder;
	u_long numblk;
	vrtxpt_t *pt;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	pt = xnmap_fetch(vrtx_pt_idmap, pid);

	if (pt == NULL) {
		*errp = ER_PID;
		goto unlock_and_exit;
	}

	/* For each extent linked to the partition's queue */

	for (holder = getheadq(&pt->extq);
	     holder; holder = nextq(&pt->extq, holder)) {
		ptext = link2vrtxptext(holder);

		/* Check if the released buffer address lays into the
		   currently scanned extent. */

		if (buf >= ptext->data && buf < ptext->data + ptext->extsize) {
			if (((buf - ptext->data) % pt->bsize) != 0)
				goto nmb;

			numblk = (buf - ptext->data) / pt->bsize;

			/* Check using the bitmap if the block was previously
			   allocated. Remember that gblock()/rblock() ops are
			   valid on behalf of ISRs, so we need to protect
			   ourselves using a hard critical section. */

			if (ptext_bitmap_tstbit(ptext, numblk)) {
				/* Ok, all is fine: release and exit */
				ptext_bitmap_clrbit(ptext, numblk);
				*((void **)buf) = ptext->freelist;
				ptext->freelist = buf;
				pt->ublks--;
				pt->fblks++;
				*errp = RET_OK;
				goto unlock_and_exit;
			}
		}
	}

      nmb:
	*errp = ER_NMB;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);
}

void sc_pextend(int pid, char *extaddr, long extsize, int *errp)
{
	vrtxpt_t *pt;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	pt = xnmap_fetch(vrtx_pt_idmap, pid);

	if (pt == NULL) {
		*errp = ER_PID;
		goto unlock_and_exit;
	}

	*errp = vrtxpt_add_extent(pt, extaddr, extsize);

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);
}

void sc_pinquiry(unsigned long info[3], int pid, int *errp)
{
	vrtxpt_t *pt;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	pt = xnmap_fetch(vrtx_pt_idmap, pid);

	if (pt == NULL) {
		*errp = ER_PID;
		goto unlock_and_exit;
	}

	info[0] = pt->ublks;
	info[1] = pt->fblks;
	info[2] = pt->bsize;

	*errp = RET_OK;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);
}

/*
 * IMPLEMENTATION NOTES:
 *
 * - A partition memory layout is as follows:
 *
 *   struct vrtxpt {
 *      Partition's superblock
 *      Extent queue (vrtxptext) -----+
 *   }                                |
 *                                    |
 *                                    |
 *                                    |
 *   struct vrtxext { <---------------+ x N
 *
 *      (char *data => pointer to the user data area)
 *      (u_long bitmap[1] => first word of bitmap)
 *
 *   }
 *   [...block status bitmap (busy/free)...]
 *   [...user data area...]
 *
 * - Each free block starts with a link to the next free block
 * in the partition's free list. A NULL link ends this list.
 */
