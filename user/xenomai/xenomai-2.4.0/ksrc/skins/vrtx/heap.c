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

#include "vrtx/task.h"
#include "vrtx/heap.h"

xnmap_t *vrtx_heap_idmap;

static xnqueue_t vrtx_heap_q;

#ifdef CONFIG_XENO_EXPORT_REGISTRY

static int __heap_read_proc(char *page,
			    char **start,
			    off_t off, int count, int *eof, void *data)
{
	vrtxheap_t *heap = (vrtxheap_t *)data;
	char *p = page;
	int len;

	p += sprintf(p, "size=%lu:used=%lu\n",
		     xnheap_usable_mem(&heap->sysheap), xnheap_used_mem(&heap->sysheap));

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

static xnpnode_t __heap_pnode = {

	.dir = NULL,
	.type = "heaps",
	.entries = 0,
	.read_proc = &__heap_read_proc,
	.write_proc = NULL,
	.root = &__vrtx_ptree,
};

#elif defined(CONFIG_XENO_OPT_REGISTRY)

static xnpnode_t __heap_pnode = {

	.type = "heaps"
};

#endif /* CONFIG_XENO_EXPORT_REGISTRY */

static void heap_destroy_internal(vrtxheap_t *heap)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	removeq(&vrtx_heap_q, &heap->link);
	xnmap_remove(vrtx_heap_idmap, heap->hid);
	vrtx_mark_deleted(heap);
#ifdef CONFIG_XENO_OPT_REGISTRY
	xnregistry_remove(heap->handle);
#endif /* CONFIG_XENO_OPT_REGISTRY */
	xnlock_clear_irqon(&nklock);

#ifdef CONFIG_XENO_OPT_PERVASIVE
	if (xnheap_mapped_p(&heap->sysheap))
		xnheap_destroy_mapped(&heap->sysheap);
	else
#endif /* CONFIG_XENO_OPT_PERVASIVE */
		xnheap_destroy(&heap->sysheap, NULL, NULL);
	xnfree(heap);

	xnlock_put_irqrestore(&nklock, s);
}

int vrtxheap_init(u_long heap0size)
{
	char *heap0addr;
	int err, hid;

	initq(&vrtx_heap_q);

	if (heap0size < 2048)
		heap0size = 2048;

	vrtx_heap_idmap = xnmap_create(VRTX_MAX_HEAPS, 0, 0);

	if (!vrtx_heap_idmap)
		return -ENOMEM;

	heap0addr = (char *)xnmalloc(heap0size);

	if (!heap0addr) {
		xnmap_delete(vrtx_heap_idmap);
		return -ENOMEM;
	}

	hid = sc_hcreate(heap0addr, heap0size, 7, &err); /* Must be #0 */

	if (err) {
		xnmap_delete(vrtx_heap_idmap);

		if (err == ER_IIP)
			return -EINVAL;
		else
			return -ENOMEM;
	}

	return 0;
}

void vrtxheap_cleanup(void)
{
	xnholder_t *holder;

	while ((holder = getheadq(&vrtx_heap_q)) != NULL)
		heap_destroy_internal(link2vrtxheap(holder));

	xnmap_delete(vrtx_heap_idmap);
}

int sc_hcreate(char *heapaddr, u_long heapsize, unsigned log2psize, int *errp)
{
	vrtxheap_t *heap;
	u_long pagesize;
	int err, hid;
	spl_t s;

	/* checks will be done in xnheap_init */

	if (log2psize == 0)
		pagesize = 512;	/* VRTXsa system call reference */
	else
		pagesize = 1 << log2psize;

	heap = (vrtxheap_t *)xnmalloc(sizeof(*heap));

	if (!heap) {
		*errp = ER_NOCB;
		return 0;
	}

#ifdef __KERNEL__
	if (heapaddr == NULL) {
#ifdef CONFIG_XENO_OPT_PERVASIVE
		heapsize = xnheap_rounded_size(heapsize, PAGE_SIZE);
		err = xnheap_init_mapped(&heap->sysheap, heapsize, 0);

		if (err) {
			*errp = ER_MEM;
			return 0;
		}

		heap->mm = NULL;
#else /* !CONFIG_XENO_OPT_PERVASIVE */
		*errp = ER_IIP;
		return 0;
#endif /* CONFIG_XENO_OPT_PERVASIVE */
	} else
#endif /* __KERNEL__ */
	{
		/*
		 * Caller must have accounted for overhead and
		 * alignment since it supplies the memory space.
		 */
		err = xnheap_init(&heap->sysheap, heapaddr, heapsize, pagesize);

		if (err) {
			if (err == -EINVAL)
				*errp = ER_IIP;
			else
				*errp = ER_NOCB;

			xnfree(heap);

			return 0;
		}
	}

	heap->magic = VRTX_HEAP_MAGIC;
	inith(&heap->link);
	heap->log2psize = log2psize;
	heap->allocated = 0;
	heap->released = 0;

	hid = xnmap_enter(vrtx_heap_idmap, -1, heap);

	if (hid < 0) {
		xnheap_destroy(&heap->sysheap, NULL, NULL);
		xnfree(heap);
		*errp = ER_NOCB;
		return 0;
	}

	heap->hid = hid;

	xnlock_get_irqsave(&nklock, s);
	appendq(&vrtx_heap_q, &heap->link);
	xnlock_put_irqrestore(&nklock, s);

#ifdef CONFIG_XENO_OPT_REGISTRY
	sprintf(heap->name, "heap%d", hid);
	xnregistry_enter(heap->name, heap, &heap->handle, &__heap_pnode);
#endif /* CONFIG_XENO_OPT_REGISTRY */

	*errp = RET_OK;

	return hid;
}

void sc_hdelete(int hid, int opt, int *errp)
{
	vrtxheap_t *heap;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	heap = xnmap_fetch(vrtx_heap_idmap, hid);

	if (opt == 0) {		/* Delete heap only if no blocks are allocated */
		if (heap->sysheap.ubytes > 0) {
			*errp = ER_PND;
			goto unlock_and_exit;
		}
	} else if (opt != 1) {
		*errp = ER_IIP;
		goto unlock_and_exit;
	}

	*errp = RET_OK;

	heap_destroy_internal(heap);

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);
}

char *sc_halloc(int hid, unsigned long bsize, int *errp)
{
	vrtxheap_t *heap;
	char *blockp;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	heap = xnmap_fetch(vrtx_heap_idmap, hid);

	if (heap == NULL) {
		blockp = NULL;
		*errp = ER_ID;
		goto unlock_and_exit;
	}

	blockp = xnheap_alloc(&heap->sysheap, bsize);

	if (blockp == NULL)
		*errp = ER_MEM;
	else {
		*errp = RET_OK;
		heap->allocated++;
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return blockp;
}

void sc_hfree(int hid, char *blockp, int *errp)
{
	vrtxheap_t *heap;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	heap = xnmap_fetch(vrtx_heap_idmap, hid);

	if (heap == NULL) {
		*errp = ER_ID;
		goto unlock_and_exit;
	}

	if (xnheap_free(&heap->sysheap, blockp) != 0) {
		*errp = ER_NMB;
		goto unlock_and_exit;
	}

	*errp = RET_OK;
	heap->allocated--;
	heap->released++;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);
}

void sc_hinquiry(int info[3], int hid, int *errp)
{
	vrtxheap_t *heap;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	heap = xnmap_fetch(vrtx_heap_idmap, hid);

	if (heap == NULL) {
		*errp = ER_ID;
		goto unlock_and_exit;
	}

	*errp = RET_OK;

	info[0] = heap->allocated;
	info[1] = heap->released;
	info[2] = heap->log2psize;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);
}
