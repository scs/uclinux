/*!\file
 * \brief Dynamic memory allocation services.
 * \author Philippe Gerum
 *
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
 *
 * \ingroup heap
 */

/*!
 * \ingroup nucleus
 * \defgroup heap Dynamic memory allocation services.
 *
 * Dynamic memory allocation services.
 *
 * The implementation of the memory allocator follows the algorithm
 * described in a USENIX 1988 paper called "Design of a General
 * Purpose Memory Allocator for the 4.3BSD Unix Kernel" by Marshall
 * K. McKusick and Michael J. Karels. You can find it at various
 * locations on the net, including
 * http://docs.FreeBSD.org/44doc/papers/kernmalloc.pdf.  A minor
 * variation allows this implementation to have 'extendable' heaps
 * when needed, with multiple memory extents providing autonomous page
 * address spaces.
 *
 * The data structures hierarchy is as follows:
 *
 * <tt> @verbatim
HEAP {
     block_buckets[]
     extent_queue -------+
}                        |
                         V
                      EXTENT #1 {
                             {static header}
                             page_map[npages]
                             page_array[npages][pagesize]
                      } -+
                         |
                         |
                         V
                      EXTENT #n {
                             {static header}
                             page_map[npages]
                             page_array[npages][pagesize]
                      }
@endverbatim </tt>
 *
 *@{*/

#include <nucleus/pod.h>
#include <nucleus/thread.h>
#include <nucleus/heap.h>
#include <nucleus/assert.h>
#include <asm/xenomai/bits/heap.h>

#ifndef CONFIG_XENO_OPT_DEBUG_NUCLEUS
#define CONFIG_XENO_OPT_DEBUG_NUCLEUS 0
#endif

xnheap_t kheap;			/* System heap */

#if CONFIG_XENO_OPT_SYS_STACKPOOLSZ > 0
xnheap_t kstacks;		/* Private stack pool */
#endif

static void init_extent(xnheap_t *heap, xnextent_t *extent)
{
	caddr_t freepage;
	int n, lastpgnum;

	inith(&extent->link);

	/* The page area starts right after the (aligned) header. */
	extent->membase = (caddr_t) extent + heap->hdrsize;
	lastpgnum = heap->npages - 1;

	/* Mark each page as free in the page map. */
	for (n = 0, freepage = extent->membase;
	     n < lastpgnum; n++, freepage += heap->pagesize) {
		*((caddr_t *) freepage) = freepage + heap->pagesize;
		extent->pagemap[n].type = XNHEAP_PFREE;
		extent->pagemap[n].bcount = 0;
	}

	*((caddr_t *) freepage) = NULL;
	extent->pagemap[lastpgnum].type = XNHEAP_PFREE;
	extent->pagemap[lastpgnum].bcount = 0;
	extent->memlim = freepage + heap->pagesize;

	/* The first page starts the free list of a new extent. */
	extent->freelist = extent->membase;
}

/*
 */

/*!
 * \fn xnheap_init(xnheap_t *heap,void *heapaddr,u_long heapsize,u_long pagesize)
 * \brief Initialize a memory heap.
 *
 * Initializes a memory heap suitable for time-bounded allocation
 * requests of dynamic memory.
 *
 * @param heap The address of a heap descriptor which will be used to
 * store the allocation data.  This descriptor must always be valid
 * while the heap is active therefore it must be allocated in
 * permanent memory.
 *
 * @param heapaddr The address of the heap storage area. All
 * allocations will be made from the given area in time-bounded
 * mode. Since additional extents can be added to a heap, this
 * parameter is also known as the "initial extent".
 *
 * @param heapsize The size in bytes of the initial extent pointed at
 * by @a heapaddr. @a heapsize must be a multiple of pagesize and
 * lower than 16 Mbytes. @a heapsize must be large enough to contain a
 * dynamically-sized internal header. The following formula gives the
 * size of this header:\n
 *
 * H = heapsize, P=pagesize, M=sizeof(struct pagemap), E=sizeof(xnextent_t)\n
 * hdrsize = ((H - E) * M) / (M + 1)\n
 *
 * This value is then aligned on the next 16-byte boundary. The
 * routine xnheap_overhead() computes the corrected heap size
 * according to the previous formula.
 *
 * @param pagesize The size in bytes of the fundamental memory page
 * which will be used to subdivide the heap internally. Choosing the
 * right page size is important regarding performance and memory
 * fragmentation issues, so it might be a good idea to take a look at
 * http://docs.FreeBSD.org/44doc/papers/kernmalloc.pdf to pick the
 * best one for your needs. In the current implementation, pagesize
 * must be a power of two in the range [ 8 .. 32768 ] inclusive.
 *
 * @return 0 is returned upon success, or one of the following error
 * codes:
 *
 * - -EINVAL is returned whenever a parameter is invalid.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 */

int xnheap_init(xnheap_t *heap,
		void *heapaddr, u_long heapsize, u_long pagesize)
{
	u_long hdrsize, shiftsize, pageshift;
	xnextent_t *extent;

	/*
	 * Perform some parametrical checks first.
	 * Constraints are:
	 * PAGESIZE must be >= 2 ** MINLOG2.
	 * PAGESIZE must be <= 2 ** MAXLOG2.
	 * PAGESIZE must be a power of 2.
	 * HEAPSIZE must be large enough to contain the static part of an
	 * extent header.
	 * HEAPSIZE must be a multiple of PAGESIZE.
	 * HEAPSIZE must be lower than XNHEAP_MAXEXTSZ.
	 */

	if ((pagesize < (1 << XNHEAP_MINLOG2)) ||
	    (pagesize > (1 << XNHEAP_MAXLOG2)) ||
	    (pagesize & (pagesize - 1)) != 0 ||
	    heapsize <= sizeof(xnextent_t) ||
	    heapsize > XNHEAP_MAXEXTSZ || (heapsize & (pagesize - 1)) != 0)
		return -EINVAL;

	/*
	 * Determine the page map overhead inside the given extent
	 * size. We need to reserve 4 bytes in a page map for each
	 * page which is addressable into this extent. The page map is
	 * itself stored in the extent space, right after the static
	 * part of its header, and before the first allocatable page.
	 * pmapsize = (heapsize - sizeof(xnextent_t)) / pagesize *
	 * sizeof(struct xnpagemap). The overall header size is:
	 * static_part + pmapsize rounded to the minimum alignment
	 * size.
	*/
	hdrsize = xnheap_overhead(heapsize, pagesize);

	/* Compute the page shiftmask from the page size (i.e. log2 value). */
	for (pageshift = 0, shiftsize = pagesize;
	     shiftsize > 1; shiftsize >>= 1, pageshift++)
		;	/* Loop */

	heap->pagesize = pagesize;
	heap->pageshift = pageshift;
	heap->extentsize = heapsize;
	heap->hdrsize = hdrsize;
	heap->npages = (heapsize - hdrsize) >> pageshift;

	/*
	 * An extent must contain at least two addressable pages to cope
	 * with allocation sizes between pagesize and 2 * pagesize.
	 */
	if (heap->npages < 2)
		return -EINVAL;

	heap->ubytes = 0;
	heap->maxcont = heap->npages * pagesize;
	heap->idleq = NULL;
	inith(&heap->link);
	initq(&heap->extents);
	xnlock_init(&heap->lock);
	xnarch_init_heapcb(&heap->archdep);
	memset(heap->buckets, 0, sizeof(heap->buckets));
	extent = (xnextent_t *)heapaddr;
	init_extent(heap, extent);

	appendq(&heap->extents, &extent->link);

	xnarch_init_display_context(heap);

	return 0;
}

/*! 
 * \fn void xnheap_destroy(xnheap_t *heap, void (*flushfn)(xnheap_t *heap, void *extaddr, u_long extsize, void *cookie), void *cookie)
 * \brief Destroys a memory heap.
 *
 * Destroys a memory heap.
 *
 * @param heap The descriptor address of the destroyed heap.
 *
 * @param flushfn If non-NULL, the address of a flush routine which
 * will be called for each extent attached to the heap. This routine
 * can be used by the calling code to further release the heap memory.
 *
 * @param cookie If @a flushfn is non-NULL, @a cookie is an opaque
 * pointer which will be passed unmodified to @a flushfn.
 *
 * @return 0 is returned on success, or -EBUSY if external mappings
 * are still pending on the heap memory.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 */

int xnheap_destroy(xnheap_t *heap,
		   void (*flushfn) (xnheap_t *heap,
				    void *extaddr,
				    u_long extsize, void *cookie), void *cookie)
{
	xnholder_t *holder;
	spl_t s;

	if (!flushfn)
		return 0;

	xnlock_get_irqsave(&heap->lock, s);

	while ((holder = getq(&heap->extents)) != NULL) {
		xnlock_put_irqrestore(&heap->lock, s);
		flushfn(heap, link2extent(holder), heap->extentsize, cookie);
		xnlock_get_irqsave(&heap->lock, s);
	}

	xnlock_put_irqrestore(&heap->lock, s);

	return 0;
}

/*
 * get_free_range() -- Obtain a range of contiguous free pages to
 * fulfill an allocation of 2 ** log2size.  The caller must have
 * acquired the heap lock.
 */

static caddr_t get_free_range(xnheap_t *heap, u_long bsize, int log2size)
{
	caddr_t block, eblock, freepage, lastpage, headpage, freehead = NULL;
	u_long pagenum, pagecont, freecont;
	xnholder_t *holder;
	xnextent_t *extent;

	holder = getheadq(&heap->extents);

	while (holder != NULL) {
		extent = link2extent(holder);
		freepage = extent->freelist;

		while (freepage != NULL) {
			headpage = freepage;
			freecont = 0;

			/*
			 * Search for a range of contiguous pages in
			 * the free page list of the current
			 * extent. The range must be 'bsize' long.
			 */
			do {
				lastpage = freepage;
				freepage = *((caddr_t *) freepage);
				freecont += heap->pagesize;
			}
			while (freepage == lastpage + heap->pagesize
			       && freecont < bsize);

			if (freecont >= bsize) {
				/*
				 * Ok, got it. Just update the free
				 * page list, then proceed to the next
				 * step.
				 */
				if (headpage == extent->freelist)
					extent->freelist =
					    *((caddr_t *) lastpage);
				else
					*((caddr_t *) freehead) =
					    *((caddr_t *) lastpage);

				goto splitpage;
			}

			freehead = lastpage;
		}
		holder = nextq(&heap->extents, holder);
	}

	return NULL;

      splitpage:

	/* At this point, headpage is valid and points to the first page
	   of a range of contiguous free pages larger or equal than
	   'bsize'. */

	if (bsize < heap->pagesize) {
		/* If the allocation size is smaller than the standard page
		   size, split the page in smaller blocks of this size,
		   building a free list of free blocks. */

		for (block = headpage, eblock =
		     headpage + heap->pagesize - bsize; block < eblock;
		     block += bsize)
			*((caddr_t *) block) = block + bsize;

		*((caddr_t *) eblock) = NULL;
	} else
		*((caddr_t *) headpage) = NULL;

	pagenum = (headpage - extent->membase) >> heap->pageshift;

	/*
	 * Update the page map.  If log2size is non-zero (i.e. bsize
	 * <= 2 * pagesize), store it in the first page's slot to
	 * record the exact block size (which is a power of
	 * two). Otherwise, store the special marker XNHEAP_PLIST,
	 * indicating the start of a block whose size is a multiple of
	 * the standard page size, but not necessarily a power of two.
	 * In any case, the following pages slots are marked as
	 * 'continued' (PCONT).
	 */

	extent->pagemap[pagenum].type = log2size ? : XNHEAP_PLIST;
	extent->pagemap[pagenum].bcount = 1;

	for (pagecont = bsize >> heap->pageshift; pagecont > 1; pagecont--) {
		extent->pagemap[pagenum + pagecont - 1].type = XNHEAP_PCONT;
		extent->pagemap[pagenum + pagecont - 1].bcount = 0;
	}

	return headpage;
}

/*! 
 * \fn void *xnheap_alloc(xnheap_t *heap, u_long size)
 * \brief Allocate a memory block from a memory heap.
 *
 * Allocates a contiguous region of memory from an active memory heap.
 * Such allocation is guaranteed to be time-bounded.
 *
 * @param heap The descriptor address of the heap to get memory from.
 *
 * @param size The size in bytes of the requested block. Sizes lower
 * or equal to the page size are rounded either to the minimum
 * allocation size if lower than this value, or to the minimum
 * alignment size if greater or equal to this value. In the current
 * implementation, with MINALLOC = 8 and MINALIGN = 16, a 7 bytes
 * request will be rounded to 8 bytes, and a 17 bytes request will be
 * rounded to 32.
 *
 * @return The address of the allocated region upon success, or NULL
 * if no memory is available from the specified heap.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 */

void *xnheap_alloc(xnheap_t *heap, u_long size)
{
	xnholder_t *holder;
	xnextent_t *extent;
	int log2size, ilog;
	u_long pagenum;
	caddr_t block;
	u_long bsize;
	spl_t s;

	if (size == 0)
		return NULL;

	if (size <= heap->pagesize)
		/* Sizes lower or equal to the page size are rounded either to
		   the minimum allocation size if lower than this value, or to
		   the minimum alignment size if greater or equal to this
		   value. In other words, with MINALLOC = 8 and MINALIGN = 16,
		   a 7 bytes request will be rounded to 8 bytes, and a 17
		   bytes request will be rounded to 32. */
	{
		if (size <= XNHEAP_MINALIGNSZ)
			size =
			    (size + XNHEAP_MINALLOCSZ -
			     1) & ~(XNHEAP_MINALLOCSZ - 1);
		else
			size =
			    (size + XNHEAP_MINALIGNSZ -
			     1) & ~(XNHEAP_MINALIGNSZ - 1);
	} else
		/* Sizes greater than the page size are rounded to a multiple
		   of the page size. */
		size = (size + heap->pagesize - 1) & ~(heap->pagesize - 1);

	/* It becomes more space efficient to directly allocate pages from
	   the free page list whenever the requested size is greater than
	   2 times the page size. Otherwise, use the bucketed memory
	   blocks. */

	if (likely(size <= heap->pagesize * 2)) {
		/* Find the first power of two greater or equal to the rounded
		   size. The log2 value of this size is also computed. */

		for (bsize = (1 << XNHEAP_MINLOG2), log2size = XNHEAP_MINLOG2;
		     bsize < size; bsize <<= 1, log2size++)
			;	/* Loop */

		ilog = log2size - XNHEAP_MINLOG2;

		xnlock_get_irqsave(&heap->lock, s);

		block = heap->buckets[ilog].freelist;

		if (block == NULL) {
			block = get_free_range(heap, bsize, log2size);
			if (block == NULL)
				goto release_and_exit;
			if (bsize <= heap->pagesize)
				heap->buckets[ilog].fcount += (heap->pagesize >> log2size) - 1;
		} else {
			if (bsize <= heap->pagesize)
				--heap->buckets[ilog].fcount;

			for (holder = getheadq(&heap->extents), extent = NULL;
			     holder != NULL; holder = nextq(&heap->extents, holder)) {
				extent = link2extent(holder);
				if ((caddr_t) block >= extent->membase &&
				    (caddr_t) block < extent->memlim)
					break;
			}
			XENO_ASSERT(NUCLEUS, extent != NULL,
				    xnpod_fatal("Cannot determine source extent for block %p (heap %p)?!",
						block, heap);
				);
			pagenum = ((caddr_t) block - extent->membase) >> heap->pageshift;
			++extent->pagemap[pagenum].bcount;
		}

		heap->buckets[ilog].freelist = *((caddr_t *) block);
		heap->ubytes += bsize;
	} else {
		if (size > heap->maxcont)
			return NULL;

		xnlock_get_irqsave(&heap->lock, s);

		/* Directly request a free page range. */
		block = get_free_range(heap, size, 0);

		if (block)
			heap->ubytes += size;
	}

      release_and_exit:

	xnlock_put_irqrestore(&heap->lock, s);

	return block;
}

/*! 
 * \fn int xnheap_test_and_free(xnheap_t *heap,void *block,int (*ckfn)(void *block))
 * \brief Test and release a memory block to a memory heap.
 *
 * Releases a memory region to the memory heap it was previously
 * allocated from. Before the actual release is performed, an optional
 * user-defined can be invoked to check for additional criteria with
 * respect to the request consistency.
 *
 * @param heap The descriptor address of the heap to release memory
 * to.
 *
 * @param block The address of the region to be returned to the heap.
 *
 * @param ckfn The address of a user-supplied verification routine
 * which is to be called after the memory address specified by @a
 * block has been checked for validity. The routine is expected to
 * proceed to further consistency checks, and either return zero upon
 * success, or non-zero upon error. In the latter case, the release
 * process is aborted, and @a ckfn's return value is passed back to
 * the caller of this service as its error return code. @a ckfn must
 * not trigger the rescheduling procedure either directly or
 * indirectly.
 *
 * @return 0 is returned upon success, or -EINVAL is returned whenever
 * the block is not a valid region of the specified heap. Additional
 * return codes can also be defined locally by the @a ckfn routine.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 */

int xnheap_test_and_free(xnheap_t *heap, void *block, int (*ckfn) (void *block))
{
	caddr_t freepage, lastpage, nextpage, tailpage, freeptr, *tailptr;
	int log2size, npages, err, nblocks, xpage, ilog;
	u_long pagenum, pagecont, boffset, bsize;
	xnextent_t *extent = NULL;
	xnholder_t *holder;
	spl_t s;

	xnlock_get_irqsave(&heap->lock, s);

	/* Find the extent from which the returned block is
	   originating. */

	for (holder = getheadq(&heap->extents);
	     holder != NULL; holder = nextq(&heap->extents, holder)) {
		extent = link2extent(holder);
		if ((caddr_t) block >= extent->membase &&
		    (caddr_t) block < extent->memlim)
			break;
	}

	if (!holder) {
		err = -EFAULT;
		goto unlock_and_fail;
	}

	/* Compute the heading page number in the page map. */
	pagenum = ((caddr_t) block - extent->membase) >> heap->pageshift;
	boffset =
	    ((caddr_t) block -
	     (extent->membase + (pagenum << heap->pageshift)));

	switch (extent->pagemap[pagenum].type) {
	case XNHEAP_PFREE:	/* Unallocated page? */
	case XNHEAP_PCONT:	/* Not a range heading page? */

	      bad_block:
		err = -EINVAL;

	      unlock_and_fail:

		xnlock_put_irqrestore(&heap->lock, s);
		return err;

	case XNHEAP_PLIST:

		if (ckfn && (err = ckfn(block)) != 0)
			goto unlock_and_fail;

		npages = 1;

		while (npages < heap->npages &&
		       extent->pagemap[pagenum + npages].type == XNHEAP_PCONT)
			npages++;

		bsize = npages * heap->pagesize;

	free_page_list:

		/* Link all freed pages in a single sub-list. */

		for (freepage = (caddr_t) block,
		     tailpage = (caddr_t) block + bsize - heap->pagesize;
		     freepage < tailpage; freepage += heap->pagesize)
			*((caddr_t *) freepage) = freepage + heap->pagesize;

	free_pages:

		/* Mark the released pages as free in the extent's page map. */

		for (pagecont = 0; pagecont < npages; pagecont++)
			extent->pagemap[pagenum + pagecont].type = XNHEAP_PFREE;

		/* Return the sub-list to the free page list, keeping
		   an increasing address order to favor coalescence. */

		for (nextpage = extent->freelist, lastpage = NULL;
		     nextpage != NULL && nextpage < (caddr_t) block;
		     lastpage = nextpage, nextpage = *((caddr_t *) nextpage))
		  ;	/* Loop */

		*((caddr_t *) tailpage) = nextpage;

		if (lastpage)
			*((caddr_t *) lastpage) = (caddr_t) block;
		else
			extent->freelist = (caddr_t) block;
		break;

	default:

		log2size = extent->pagemap[pagenum].type;
		bsize = (1 << log2size);

		if ((boffset & (bsize - 1)) != 0)	/* Not a block start? */
			goto bad_block;

		if (ckfn && (err = ckfn(block)) != 0)
			goto unlock_and_fail;

		/*
		 * Return the page to the free list if we've just
		 * freed its last busy block. Pages from multi-page
		 * blocks are always pushed to the free list (bcount
		 * value for the heading page is always 1).
		 */

		ilog = log2size - XNHEAP_MINLOG2;

		if (likely(--extent->pagemap[pagenum].bcount > 0)) {
			/* Return the block to the bucketed memory space. */
			*((caddr_t *) block) = heap->buckets[ilog].freelist;
			heap->buckets[ilog].freelist = block;
			++heap->buckets[ilog].fcount;
			break;
		}

		npages = bsize >> heap->pageshift;

		if (unlikely(npages > 1))
			/*
			 * The simplest case: we only have a single
			 * block to deal with, which spans multiple
			 * pages. We just need to release it as a list
			 * of pages, without caring about the
			 * consistency of the bucket.
			 */
			goto free_page_list;

		freepage = extent->membase + (pagenum << heap->pageshift);
		block = freepage;
		tailpage = freepage;
		nextpage = freepage + heap->pagesize;
		nblocks = heap->pagesize >> log2size;
		heap->buckets[ilog].fcount -= (nblocks - 1);

		XENO_ASSERT(NUCLEUS, heap->buckets[ilog].fcount >= 0,
			    xnpod_fatal("free block count became negative (heap %p, log2=%d, fcount=%d)?!",
					heap, log2size, heap->buckets[ilog].fcount);
			);
		/*
		 * Easy case: all free blocks are laid on a single
		 * page we are now releasing. Just clear the bucket
		 * and bail out.
		 */

		if (likely(heap->buckets[ilog].fcount == 0)) {
			heap->buckets[ilog].freelist = NULL;
			goto free_pages;
		}

		/*
		 * Worst case: multiple pages are traversed by the
		 * bucket list. Scan the list to remove all blocks
		 * belonging to the freed page. We are done whenever
		 * all possible blocks from the freed page have been
		 * traversed, or we hit the end of list, whichever
		 * comes first.
		 */

		for (tailptr = &heap->buckets[ilog].freelist, freeptr = *tailptr, xpage = 1;
		     freeptr != NULL && nblocks > 0; freeptr = *((caddr_t *) freeptr)) {
			if (unlikely(freeptr < freepage || freeptr >= nextpage)) {
				if (unlikely(xpage)) { /* Limit random writes */
					*tailptr = freeptr;
					xpage = 0;
				}
				tailptr = (caddr_t *)freeptr;
			} else {
				--nblocks;
				xpage = 1;
			}
		}

		*tailptr = freeptr;
		goto free_pages;
	}

	heap->ubytes -= bsize;

	xnlock_put_irqrestore(&heap->lock, s);

	return 0;
}

/*! 
 * \fn int xnheap_free(xnheap_t *heap, void *block)
 * \brief Release a memory block to a memory heap.
 *
 * Releases a memory region to the memory heap it was previously
 * allocated from.
 *
 * @param heap The descriptor address of the heap to release memory
 * to.
 *
 * @param block The address of the region to be returned to the heap.
 *
 * @return 0 is returned upon success, or one of the following error
 * codes:
 *
 * - -EFAULT is returned whenever the memory address is outside the
 * heap address space.
 *
 * - -EINVAL is returned whenever the memory address does not
 * represent a valid block.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 */

int xnheap_free(xnheap_t *heap, void *block)
{
	return xnheap_test_and_free(heap, block, NULL);
}

/*! 
 * \fn int xnheap_extend(xnheap_t *heap, void *extaddr, u_long extsize)
 * \brief Extend a memory heap.
 *
 * Add a new extent to an existing memory heap.
 *
 * @param heap The descriptor address of the heap to add an extent to.
 *
 * @param extaddr The address of the extent memory.
 *
 * @param extsize The size of the extent memory (in bytes). In the
 * current implementation, this size must match the one of the initial
 * extent passed to xnheap_init().
 *
 * @return 0 is returned upon success, or -EINVAL is returned if
 * @a extsize differs from the initial extent's size.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 */

int xnheap_extend(xnheap_t *heap, void *extaddr, u_long extsize)
{
	xnextent_t *extent = (xnextent_t *)extaddr;
	spl_t s;

	if (extsize != heap->extentsize)
		return -EINVAL;

	init_extent(heap, extent);
	xnlock_get_irqsave(&heap->lock, s);
	appendq(&heap->extents, &extent->link);
	xnlock_put_irqrestore(&heap->lock, s);

	return 0;
}

/*! 
 * \fn int xnheap_schedule_free(xnheap_t *heap, void *block, xnholder_t *link)
 * \brief Schedule a memory block for release.
 *
 * This routine records a block for later release by
 * xnheap_finalize_free(). This service is useful to lazily free
 * blocks of heap memory when immediate release is not an option,
 * e.g. when active references are still pending on the object for a
 * short time after the call. xnheap_finalize_free() is expected to be
 * eventually called by the client code at some point in the future
 * when actually freeing the idle objects is deemed safe.
 *
 * @param heap The descriptor address of the heap to release memory
 * to.
 *
 * @param block The address of the region to be returned to the heap.
 *
 * @param link The address of a link member, likely but not
 * necessarily within the released object, which will be used by the
 * heap manager to hold the block in the queue of idle objects.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 */

void xnheap_schedule_free(xnheap_t *heap, void *block, xnholder_t *link)
{
	spl_t s;

	xnlock_get_irqsave(&heap->lock, s);
	/* Hack: we only need a one-way linked list for remembering the
	   idle objects through the 'next' field, so the 'last' field of
	   the link is used to point at the beginning of the freed
	   memory. */
	link->last = (xnholder_t *)block;
	link->next = heap->idleq;
	heap->idleq = link;
	xnlock_put_irqrestore(&heap->lock, s);
}

void xnheap_finalize_free_inner(xnheap_t *heap)
{
	xnholder_t *holder;
	spl_t s;

	xnlock_get_irqsave(&heap->lock, s);

	while ((holder = heap->idleq) != NULL) {
		heap->idleq = holder->next;
		xnheap_free(heap, holder->last);
	}

	xnlock_put_irqrestore(&heap->lock, s);
}

int xnheap_check_block(xnheap_t *heap, void *block)
{
	xnextent_t *extent = NULL;
	u_long pagenum, boffset;
	xnholder_t *holder;
	int ptype, err = 0;
	spl_t s;

	xnlock_get_irqsave(&heap->lock, s);

	/* Find the extent from which the checked block is
	   originating. */

	for (holder = getheadq(&heap->extents);
	     holder != NULL; holder = nextq(&heap->extents, holder)) {
		extent = link2extent(holder);
		if ((caddr_t) block >= extent->membase &&
		    (caddr_t) block < extent->memlim)
			break;
	}

	if (!holder)
		goto bad_block;

	/* Compute the heading page number in the page map. */
	pagenum = ((caddr_t) block - extent->membase) >> heap->pageshift;
	boffset =
	    ((caddr_t) block -
	     (extent->membase + (pagenum << heap->pageshift)));
	ptype = extent->pagemap[pagenum].type;

	if (ptype == XNHEAP_PFREE ||	/* Unallocated page? */
	    ptype == XNHEAP_PCONT)	/* Not a range heading page? */
  bad_block: 
		err = -EINVAL;

	xnlock_put_irqrestore(&heap->lock, s);

	return err;
}

#ifdef CONFIG_XENO_OPT_PERVASIVE

#include <asm/io.h>
#include <linux/miscdevice.h>
#include <linux/device.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>

static DEFINE_XNQUEUE(kheapq);	/* Shared heap queue. */

static inline void *__alloc_and_reserve_heap(size_t size, int kmflags)
{
	unsigned long vaddr, vabase;
	void *ptr;

	/* Size must be page-aligned. */

	if ((kmflags & ~XNHEAP_GFP_NONCACHED) == 0) {
		if (kmflags == 0)
			ptr = vmalloc(size);
		else
			ptr = __vmalloc(size,
					GFP_KERNEL | __GFP_HIGHMEM,
					pgprot_noncached(PAGE_KERNEL));
		if (ptr == NULL)
			return NULL;

		vabase = (unsigned long)ptr;
		for (vaddr = vabase; vaddr < vabase + size; vaddr += PAGE_SIZE)
			SetPageReserved(vmalloc_to_page((void *)vaddr));
	} else {
		/*
		 * Otherwise, we have been asked for some kmalloc()
		 * space. Assume that we can wait to get the required memory.
		 */
		if (size <= KMALLOC_MAX_SIZE)
			ptr = kmalloc(size, kmflags | GFP_KERNEL);
		else
			ptr = (void *)__get_free_pages(kmflags | GFP_KERNEL,
						       get_order(size));
		if (ptr == NULL)
			return NULL;

		vabase = (unsigned long)ptr;
		for (vaddr = vabase; vaddr < vabase + size; vaddr += PAGE_SIZE)
			SetPageReserved(virt_to_page(vaddr));
	}

	return ptr;
}

static void __unreserve_and_free_heap(void *ptr, size_t size, int kmflags)
{
	unsigned long vaddr, vabase;

	/* Size must be page-aligned. */

	vabase = (unsigned long)ptr;

	if ((kmflags & ~XNHEAP_GFP_NONCACHED) == 0) {
		for (vaddr = vabase; vaddr < vabase + size; vaddr += PAGE_SIZE)
			ClearPageReserved(vmalloc_to_page((void *)vaddr));

		vfree(ptr);
	} else {
		for (vaddr = vabase; vaddr < vabase + size; vaddr += PAGE_SIZE)
			ClearPageReserved(virt_to_page(vaddr));

		if (size <= KMALLOC_MAX_SIZE)
			kfree(ptr);
		else
			free_pages((unsigned long)ptr, get_order(size));
	}
}

static void xnheap_vmclose(struct vm_area_struct *vma)
{
	xnheap_t *heap = vma->vm_private_data;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (atomic_dec_and_test(&heap->archdep.numaps)) {
		if (heap->archdep.release) {
			removeq(&kheapq, &heap->link);
			xnlock_put_irqrestore(&nklock, s);
			__unreserve_and_free_heap(heap->archdep.heapbase,
						  xnheap_extentsize(heap),
						  heap->archdep.kmflags);
			xnlock_get_irqsave(&nklock, s);
			heap->archdep.release(heap);
		}
	}

	xnlock_put_irqrestore(&nklock, s);
}

static struct vm_operations_struct xnheap_vmops = {
      .close = &xnheap_vmclose
};

static int xnheap_open(struct inode *inode, struct file *file)
{
	file->private_data = NULL;
	return 0;
}

static inline xnheap_t *__validate_heap_addr(void *addr)
{
	xnholder_t *holder;

	for (holder = getheadq(&kheapq); holder;
	     holder = nextq(&kheapq, holder))
		if (link2heap(holder) == addr)
			return addr;

	return NULL;
}

static int xnheap_ioctl(struct inode *inode,
			struct file *file, unsigned int cmd, unsigned long arg)
{
	xnheap_t *heap;
	int err = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	heap = __validate_heap_addr((void *)arg);

	if (!heap) {
		err = -EINVAL;
		goto unlock_and_exit;
	}

	file->private_data = heap;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

static int xnheap_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned long offset, size, vaddr;
	xnheap_t *heap;

	if (vma->vm_ops != NULL || file->private_data == NULL)
		/* Caller should mmap() once for a given file instance, after
		   the ioctl() binding has been issued. */
		return -ENXIO;

	if ((vma->vm_flags & VM_WRITE) && !(vma->vm_flags & VM_SHARED))
		return -EINVAL;	/* COW unsupported. */

	offset = vma->vm_pgoff << PAGE_SHIFT;
	size = vma->vm_end - vma->vm_start;
	heap = (xnheap_t *)file->private_data;

	if (offset + size > xnheap_extentsize(heap))
		return -ENXIO;

	if (countq(&heap->extents) > 1)
		/* Cannot map multi-extent heaps, we need the memory
		   area we map from to be contiguous. */
		return -ENXIO;

	vma->vm_ops = &xnheap_vmops;
	vma->vm_private_data = file->private_data;

	vaddr = (unsigned long)heap->archdep.heapbase + offset;

	if ((heap->archdep.kmflags & ~XNHEAP_GFP_NONCACHED) == 0) {
		unsigned long maddr = vma->vm_start;

		if (heap->archdep.kmflags == XNHEAP_GFP_NONCACHED)
			vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

		while (size > 0) {
			if (xnarch_remap_vm_page(vma, maddr, vaddr))
				return -EAGAIN;

			maddr += PAGE_SIZE;
			vaddr += PAGE_SIZE;
			size -= PAGE_SIZE;
		}
	} else if (xnarch_remap_io_page_range(file,vma,
					      vma->vm_start,
					      virt_to_phys((void *)vaddr),
					      size, vma->vm_page_prot))
		return -EAGAIN;

	xnarch_fault_range(vma);

	atomic_inc(&heap->archdep.numaps);

	return 0;
}

int xnheap_init_mapped(xnheap_t *heap, u_long heapsize, int memflags)
{
	void *heapbase;
	spl_t s;
	int err;

	/* Caller must have accounted for internal overhead. */
	heapsize = xnheap_align(heapsize, PAGE_SIZE);

	if ((memflags & XNHEAP_GFP_NONCACHED)
	    && memflags != XNHEAP_GFP_NONCACHED)
		return -EINVAL;

	heapbase = __alloc_and_reserve_heap(heapsize, memflags);
	if (!heapbase)
		return -ENOMEM;

	err = xnheap_init(heap, heapbase, heapsize, PAGE_SIZE);
	if (err) {
		__unreserve_and_free_heap(heapbase, heapsize, memflags);
		return err;
	}

	heap->archdep.kmflags = memflags;
	heap->archdep.heapbase = heapbase;
	heap->archdep.release = NULL;

	xnlock_get_irqsave(&nklock, s);
	appendq(&kheapq, &heap->link);
	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

int xnheap_destroy_mapped(xnheap_t *heap, void (*release)(struct xnheap *heap),
			  void __user *mapaddr)
{
	int ret = 0, ccheck;
	unsigned long len;
	spl_t s;

	ccheck = mapaddr ? 1 : 0;

	xnlock_get_irqsave(&nklock, s);

	if (atomic_read(&heap->archdep.numaps) > ccheck) {
		heap->archdep.release = release;
		xnlock_put_irqrestore(&nklock, s);
		return -EBUSY;
	}

	removeq(&kheapq, &heap->link); /* Prevent further mapping. */
	xnlock_put_irqrestore(&nklock, s);

	len = xnheap_extentsize(heap);

	if (mapaddr) {
		down_write(&current->mm->mmap_sem);
		heap->archdep.release = NULL;
		ret = do_munmap(current->mm, (unsigned long)mapaddr, len);
		up_write(&current->mm->mmap_sem);
	}

	if (ret == 0) {
		__unreserve_and_free_heap(heap->archdep.heapbase, len,
					  heap->archdep.kmflags);
		if (release) {
			xnlock_get_irqsave(&nklock, s);
			release(heap);
			xnlock_put_irqrestore(&nklock, s);
		}
	}

	return ret;
}

static struct file_operations xnheap_fops = {
	.owner = THIS_MODULE,
	.open = &xnheap_open,
	.ioctl = &xnheap_ioctl,
	.mmap = &xnheap_mmap
};

static struct miscdevice xnheap_dev = {
	XNHEAP_DEV_MINOR, "rtheap", &xnheap_fops
};

int xnheap_mount(void)
{
	return misc_register(&xnheap_dev);
}

void xnheap_umount(void)
{
	misc_deregister(&xnheap_dev);
}

EXPORT_SYMBOL(xnheap_init_mapped);
EXPORT_SYMBOL(xnheap_destroy_mapped);

#endif /* CONFIG_XENO_OPT_PERVASIVE */

/*@}*/

EXPORT_SYMBOL(xnheap_alloc);
EXPORT_SYMBOL(xnheap_destroy);
EXPORT_SYMBOL(xnheap_extend);
EXPORT_SYMBOL(xnheap_test_and_free);
EXPORT_SYMBOL(xnheap_free);
EXPORT_SYMBOL(xnheap_init);
EXPORT_SYMBOL(xnheap_schedule_free);
EXPORT_SYMBOL(xnheap_finalize_free_inner);
EXPORT_SYMBOL(xnheap_check_block);

EXPORT_SYMBOL(kheap);
