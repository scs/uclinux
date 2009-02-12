/*
 * @note Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
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
 *
 * \ingroup heap
 */

#ifndef _XENO_NUCLEUS_HEAP_H
#define _XENO_NUCLEUS_HEAP_H

#include <nucleus/queue.h>

/*
 * CONSTRAINTS:
 *
 * Minimum page size is 2 ** XNHEAP_MINLOG2 (must be large enough to
 * hold a pointer).
 *
 * Maximum page size is 2 ** XNHEAP_MAXLOG2.
 *
 * Minimum block size equals the minimum page size.
 *
 * Requested block size smaller than the minimum block size is
 * rounded to the minimum block size.
 *
 * Requested block size larger than 2 times the page size is rounded
 * to the next page boundary and obtained from the free page
 * list. So we need a bucket for each power of two between
 * XNHEAP_MINLOG2 and XNHEAP_MAXLOG2 inclusive, plus one to honor
 * requests ranging from the maximum page size to twice this size.
 */

#if defined(__KERNEL__) || defined(__XENO_SIM__)

#define XNHEAP_MINLOG2    3
#define XNHEAP_MAXLOG2    22	/* Must hold pagemap::bcount objects */
#define XNHEAP_MINALLOCSZ (1 << XNHEAP_MINLOG2)
#define XNHEAP_MINALIGNSZ (1 << 4) /* i.e. 16 bytes */
#define XNHEAP_NBUCKETS   (XNHEAP_MAXLOG2 - XNHEAP_MINLOG2 + 2)
#define XNHEAP_MAXEXTSZ   (1 << 31) /* i.e. 2Gb */

#define XNHEAP_PFREE   0
#define XNHEAP_PCONT   1
#define XNHEAP_PLIST   2

#define XNHEAP_GFP_NONCACHED (1 << __GFP_BITS_SHIFT)

typedef struct xnextent {

	xnholder_t link;

#define link2extent(ln)	container_of(ln, xnextent_t, link)

	caddr_t membase,	/* Base address of the page array */
		memlim,		/* Memory limit of page array */
		freelist;	/* Head of the free page list */

	struct xnpagemap {	/* Beginning of page map */
		unsigned int type : 8;	  /* PFREE, PCONT, PLIST or log2 */
		unsigned int bcount : 24; /* Number of active blocks. */
	} pagemap[1];

} xnextent_t;

typedef struct xnheap {

	xnholder_t link;

#define link2heap(ln)		container_of(ln, xnheap_t, link)

	u_long extentsize,
		pagesize,
		pageshift,
		hdrsize,
		npages,		/* Number of pages per extent */
		ubytes,
		maxcont;

	xnqueue_t extents;

        DECLARE_XNLOCK(lock);

	struct xnbucket {
		caddr_t freelist;
		int fcount;
	} buckets[XNHEAP_NBUCKETS];

	xnholder_t *idleq;

	xnarch_heapcb_t archdep;

	XNARCH_DECL_DISPLAY_CONTEXT();

} xnheap_t;

extern xnheap_t kheap;

#if CONFIG_XENO_OPT_SYS_STACKPOOLSZ > 0
extern xnheap_t kstacks;
#endif

#define xnheap_extentsize(heap)		((heap)->extentsize)
#define xnheap_page_size(heap)		((heap)->pagesize)
#define xnheap_page_count(heap)		((heap)->npages)
#define xnheap_usable_mem(heap)		((heap)->maxcont * countq(&(heap)->extents))
#define xnheap_used_mem(heap)		((heap)->ubytes)
#define xnheap_max_contiguous(heap)	((heap)->maxcont)

static inline size_t xnheap_align(size_t size, size_t al)
{
	/* The alignment value must be a power of 2 */
	return ((size+al-1)&(~(al-1)));
}

static inline size_t xnheap_overhead(size_t hsize, size_t psize)
{
	size_t m = psize / sizeof(struct xnpagemap);
	size_t q = (size_t)xnarch_llimd(hsize - sizeof(xnextent_t), m, m + 1);
	return xnheap_align(hsize - q, XNHEAP_MINALIGNSZ);
}

#define xnmalloc(size)     xnheap_alloc(&kheap,size)
#define xnfree(ptr)        xnheap_free(&kheap,ptr)
#define xnfreesync()       xnheap_finalize_free(&kheap)
#define xnfreesafe(thread,ptr,ln)		\
    do {					\
    if (xnpod_current_p(thread))		\
	xnheap_schedule_free(&kheap,ptr,ln);	\
    else					\
	xnheap_free(&kheap,ptr);		\
} while(0)

static inline size_t xnheap_rounded_size(size_t hsize, size_t psize)
{
	/*
	 * Account for the minimum heap size (i.e. 2 * page size) plus
	 * overhead so that the actual heap space is large enough to
	 * match the requested size. Using a small page size for large
	 * single-block heaps might reserve a lot of useless page map
	 * memory, but this should never get pathological anyway,
	 * since we only consume 4 bytes per page.
	 */
	if (hsize < 2 * psize)
		hsize = 2 * psize;
	hsize += xnheap_overhead(hsize, psize);
	return xnheap_align(hsize, psize);
}

#ifdef __cplusplus
extern "C" {
#endif

/* Private interface. */

#ifdef __KERNEL__

#define XNHEAP_DEV_MINOR 254

int xnheap_mount(void);

void xnheap_umount(void);

int xnheap_init_mapped(xnheap_t *heap,
		       u_long heapsize,
		       int memflags);

int xnheap_destroy_mapped(xnheap_t *heap,
			  void (*release)(struct xnheap *heap),
			  void __user *mapaddr);

#define xnheap_mapped_offset(heap,ptr) \
(((caddr_t)(ptr)) - ((caddr_t)(heap)->archdep.heapbase))

#define xnheap_mapped_address(heap,off) \
(((caddr_t)(heap)->archdep.heapbase) + (off))

#define xnheap_mapped_p(heap) \
((heap)->archdep.heapbase != NULL)

#endif /* __KERNEL__ */

/* Public interface. */

int xnheap_init(xnheap_t *heap,
		void *heapaddr,
		u_long heapsize,
		u_long pagesize);

int xnheap_destroy(xnheap_t *heap,
		   void (*flushfn)(xnheap_t *heap,
				   void *extaddr,
				   u_long extsize,
				   void *cookie),
		   void *cookie);

int xnheap_extend(xnheap_t *heap,
		  void *extaddr,
		  u_long extsize);

void *xnheap_alloc(xnheap_t *heap,
		   u_long size);

int xnheap_test_and_free(xnheap_t *heap,
			 void *block,
			 int (*ckfn)(void *block));

int xnheap_free(xnheap_t *heap,
		void *block);

void xnheap_schedule_free(xnheap_t *heap,
			  void *block,
			  xnholder_t *link);

void xnheap_finalize_free_inner(xnheap_t *heap);

static inline void xnheap_finalize_free(xnheap_t *heap)
{
    if (heap->idleq)
	xnheap_finalize_free_inner(heap);
}

int xnheap_check_block(xnheap_t *heap,
		       void *block);

#ifdef __cplusplus
}
#endif

#endif /* __KERNEL__ || __XENO_SIM__ */

#define XNHEAP_DEV_NAME  "/dev/rtheap"

#endif /* !_XENO_NUCLEUS_HEAP_H */
