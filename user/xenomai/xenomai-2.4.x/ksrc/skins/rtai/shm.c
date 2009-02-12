/**
 *
 * @note Copyright (C) 2004 Philippe Gerum <rpm@xenomai.org> 
 * @note Copyright (C) 2005 Nextream France S.A.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <nucleus/pod.h>
#include <nucleus/registry.h>
#include <nucleus/heap.h>
#include <nucleus/queue.h>
#include <rtai/shm.h>

/*
 * Implemented:
 *   - rt_kmalloc()/rt_kfree(): kernel and user, but bug in user
 *   - rt_heap_open()/rt_heap_close(): kernel and user
 *
 * rt_heal_alloc* should be straightforward after rewrite of ioctl 
 * to xenomai.
 */

typedef struct xnshm_a {

	xnholder_t link;
	unsigned ref;
	xnheap_t *heap;
	void *chunk;
	unsigned long name;
	int size;
#ifdef CONFIG_XENO_OPT_REGISTRY
	char szName[6];
	xnhandle_t handle;
#endif /* CONFIG_XENO_OPT_REGISTRY */

} xnshm_a_t;

static inline xnshm_a_t *link2shma(xnholder_t *ln)
{
	return ln ? container_of(ln, xnshm_a_t, link) : NULL;
}

xnqueue_t xnshm_allocq;

#ifdef CONFIG_XENO_EXPORT_REGISTRY

extern xnptree_t __rtai_ptree;

static int __shm_read_proc(char *page,
			   char **start,
			   off_t off, int count, int *eof, void *data)
{
	xnshm_a_t *p = data;
	char *ptrW = page;
	int len;

	ptrW += sprintf(ptrW, "Name   - Ptr      - Size     - Ref\n");
	ptrW +=	sprintf(ptrW, "%s - %08lX - %08X - %i\n",
			p->szName, p->name, p->size, p->ref);

	len = ptrW - page - off;
	if (len <= off + count)
		*eof = 1;
	*start = page + off;
	if (len > count)
		len = count;
	if (len < 0)
		len = 0;

	return len;
}

static xnpnode_t __shm_pnode = {

	.dir = NULL,
	.type = "shm",
	.entries = 0,
	.read_proc = &__shm_read_proc,
	.write_proc = NULL,
	.root = &__rtai_ptree,
};

#elif defined(CONFIG_XENO_OPT_REGISTRY)

static xnpnode_t __fifo_pnode = {

	.type = "fifo"
};

#endif /* CONFIG_XENO_EXPORT_REGISTRY */

static xnshm_a_t *kalloc_new_shm(unsigned long name, int size)
{
	xnshm_a_t *p;

	p = xnheap_alloc(&kheap, sizeof(xnshm_a_t));
	if (!p)
		return NULL;

	p->chunk = xnheap_alloc(&kheap, size);
	if (!p->chunk) {
		xnheap_free(&kheap, p);
		return NULL;
	}
	memset(p->chunk, 0, size);

	inith(&p->link);
	p->ref = 1;
	p->name = name;
	p->size = size;
	p->heap = &kheap;

	return p;
}

static xnshm_a_t *create_new_heap(unsigned long name, int heapsize, int suprt)
{
	xnshm_a_t *p;
	int err;

	p = xnheap_alloc(&kheap, sizeof(xnshm_a_t));
	if (!p)
		return NULL;

	p->heap = xnheap_alloc(&kheap, sizeof(xnheap_t));
	if (!p->heap) {
		xnheap_free(&kheap, p);
		return NULL;
	}

	/*
	 * Account for the minimum heap size and overhead so that the
	 * actual free space is large enough to match the requested
	 * size.
	 */

#ifdef CONFIG_XENO_OPT_PERVASIVE
	heapsize = xnheap_rounded_size(heapsize, PAGE_SIZE);

	err = xnheap_init_mapped(p->heap,
				 heapsize,
				 suprt == USE_GFP_KERNEL ? GFP_KERNEL : 0);
#else /* !CONFIG_XENO_OPT_PERVASIVE */
	{
		void *heapmem;

		heapsize = xnheap_rounded_size(heapsize, XNCORE_PAGE_SIZE);

		heapmem = xnarch_alloc_host_mem(heapsize);

		if (!heapmem) {
			err = -ENOMEM;
		} else {

			err = xnheap_init(p->heap, heapmem, heapsize, XNCORE_PAGE_SIZE);
			if (err) {
				xnarch_free_host_mem(heapmem, heapsize);
			}
		}
	}
#endif /* !CONFIG_XENO_OPT_PERVASIVE */
	if (err) {
		xnheap_free(&kheap, p->heap);
		xnheap_free(&kheap, p);
		return NULL;
	}

	p->chunk = xnheap_mapped_address(p->heap, 0);

	memset(p->chunk, 0, heapsize);

	inith(&p->link);
	p->ref = 1;
	p->name = name;
	p->size = heapsize;

	return p;
}

/*
 * _shm_alloc allocs chunk from Fusion kheap or alloc a new heap
 */
void *_shm_alloc(unsigned long name, int size, int suprt, int in_kheap,
		 unsigned long *opaque)
{
	void *ret = NULL;
	xnholder_t *holder;
	xnshm_a_t *p;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	holder = getheadq(&xnshm_allocq);

	while (holder != NULL) {
		p = link2shma(holder);

		if (p->name == name) {
			/* assert(size==p->size); */

			p->ref++;
			ret = p->chunk;
			*opaque = (unsigned long)p->heap;
			goto unlock_and_exit;
		}

		holder = nextq(&xnshm_allocq, holder);
	}

	if (in_kheap) {
		p = kalloc_new_shm(name, size);
	} else {
		/* create new heap can suspend */
		xnlock_put_irqrestore(&nklock, s);
		p = create_new_heap(name, size, suprt);
		xnlock_get_irqsave(&nklock, s);
	}
	if (!p)
		goto unlock_and_exit;

	*opaque = (unsigned long)p->heap;
	appendq(&xnshm_allocq, &p->link);

#ifdef CONFIG_XENO_OPT_REGISTRY
	{
		p->handle = 0;
		num2nam(p->name, p->szName);
		xnregistry_enter(p->szName, p, &p->handle, &__shm_pnode);
	}
#endif /* CONFIG_XENO_OPT_REGISTRY */

	ret = p->chunk;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return ret;
}

void *rt_shm_alloc(unsigned long name, int size, int suprt)
{
	unsigned long opaque;

	return _shm_alloc(name, size, suprt, 1, &opaque);
}

void *rt_heap_open(unsigned long name, int size, int suprt)
{
	unsigned long opaque;

	return _shm_alloc(name, size, suprt, 0, &opaque);
}

#ifndef CONFIG_XENO_OPT_PERVASIVE
static void __heap_flush_private(xnheap_t *heap,
				 void *heapmem, u_long heapsize, void *cookie)
{
	xnarch_free_host_mem(heapmem, heapsize);
}
#endif /* CONFIG_XENO_OPT_PERVASIVE */

static int _shm_free(unsigned long name)
{
	int ret = 0;
	xnholder_t *holder;
	xnshm_a_t *p;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	holder = getheadq(&xnshm_allocq);

	while (holder != NULL) {
		p = link2shma(holder);

		if (p->name == name && --p->ref == 0) {
#ifdef CONFIG_XENO_OPT_REGISTRY
			if (p->handle)
				xnregistry_remove(p->handle);
#endif /* CONFIG_XENO_OPT_REGISTRY */
			if (p->heap == &kheap)
				xnheap_free(&kheap, p->chunk);
			else {
				/* Should release lock here? 
				 * Can destroy_mapped suspend ?
				 * [YES!]
				 */
#ifdef CONFIG_XENO_OPT_PERVASIVE
				ret = xnheap_destroy_mapped(p->heap, NULL, NULL);
#else /* !CONFIG_XENO_OPT_PERVASIVE */
				ret =
				    xnheap_destroy(p->heap,
						   &__heap_flush_private, NULL);
#endif /* !CONFIG_XENO_OPT_PERVASIVE */
				if (ret)
					goto unlock_and_exit;
				xnheap_free(&kheap, p->heap);
			}
			removeq(&xnshm_allocq, &p->link);
			ret = p->size;
			xnheap_free(&kheap, p);
			break;
		}

		holder = nextq(&xnshm_allocq, holder);
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return ret;
}

int rt_shm_free(unsigned long name)
{
	return _shm_free(name);
}

int __rtai_shm_pkg_init(void)
{
	initq(&xnshm_allocq);
	return 0;
}

void __rtai_shm_pkg_cleanup(void)
{
#if 0
	xnholder_t *holder;
	xnshm_a_t *p;
	char szName[6];

	// Garbage collector : to be added : lock problem 
	holder = getheadq(&xnshm_allocq);

	while (holder != NULL) {
		p = link2shma(holder);

		if (p) {
			num2nam(p->name, szName);
			printk
			    ("[RTAI -SHM] Cleanup of unfreed memory %s( %d ref.)\n",
			     szName, p->ref);
			if (p->heap == &kheap)
				xnheap_free(&kheap, p->chunk);
			else {
				/* FIXME: MUST release lock here.
				 */
#ifdef CONFIG_XENO_OPT_PERVASIVE
				xnheap_destroy_mapped(p->heap, NULL, NULL);
#else /* !CONFIG_XENO_OPT_PERVASIVE */
				xnheap_destroy(p->heap, &__heap_flush_private,
					       NULL);
#endif /* !CONFIG_XENO_OPT_PERVASIVE */
				xnheap_free(&kheap, p->heap);
			}
			removeq(&xnshm_allocq, &p->link);
			xnheap_free(&kheap, p);
		}

		holder = nextq(&xnshm_allocq, holder);
	}
#endif
}

EXPORT_SYMBOL(rt_shm_alloc);
EXPORT_SYMBOL(rt_shm_free);
EXPORT_SYMBOL(rt_heap_open);
