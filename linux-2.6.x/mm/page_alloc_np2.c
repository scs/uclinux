/*
 *  linux/mm/page_alloc_np2.c
 *
 *  Manages the free list, the system allocates free pages here.
 *  Note that kmalloc() lives in slab.c
 *
 *  See Documentation/nommu-np2.txt for more info.
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 *  Reshaped it to be a zoned allocator, Ingo Molnar, Red Hat, 1999
 *  Discontiguous memory support, Kanoj Sarcar, SGI, Nov 1999
 *  Zone balancing, Kanoj Sarcar, SGI, Jan 2000
 *  Per cpu hot/cold page lists, bulk allocation, Martin J. Bligh, Sept 2002
 *          (lots of bits borrowed from Ingo Molnar & Andrew Morton)
 *  Added non power of 2 logic 04/02/2006 Phil Wilshire 
 */

#include <linux/stddef.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/interrupt.h>
#include <linux/pagemap.h>
#include <linux/bootmem.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/suspend.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/notifier.h>
#include <linux/topology.h>
#include <linux/sysctl.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/memory_hotplug.h>
#include <linux/nodemask.h>
#include <linux/vmalloc.h>
#include <linux/mempolicy.h>
#include <linux/stop_machine.h>

#include <linux/proc_fs.h>

#include <asm/tlbflush.h>
#include <asm/div64.h>
#include "internal.h"

#undef NP2_DEBUG

#ifdef NP2_DEBUG
# define PRINTK(fmt, args...) printk(KERN_DEBUG "NP2:%s:%i: " fmt, __FUNCTION__, __LINE__, ## args)
#else
# define PRINTK(fmt, args...)
#endif

/*
 * MCD - HACK: Find somewhere to initialize this EARLY, or make this
 * initializer cleaner
 */
nodemask_t node_online_map __read_mostly = { { [0] = 1UL } };
EXPORT_SYMBOL(node_online_map);
nodemask_t node_possible_map __read_mostly = NODE_MASK_ALL;
EXPORT_SYMBOL(node_possible_map);
unsigned long totalram_pages __read_mostly;
unsigned long totalhigh_pages __read_mostly;
unsigned long totalreserve_pages __read_mostly;
long nr_swap_pages;
int percpu_pagelist_fraction;

static int np2_pagevec;
static int np2_hot_pages;
static int np2_cold_pages;
static int np2_unalloc;
static int np2_msize;

static int np2_num_allocs;
static int np2_num_frees;
static char np2_pbuff[8096];
static int use_np2 = 1;

static void np2_set_page_size(struct page *page, int size);
static void np2_clear_page_size(struct page *page, int size, int order);
static int np2_merge_pages(void);
static void np2_show_pages(int spaces, int holes, int check);
static void np2_show_list(void);

static void __free_pages_ok(struct page *page, unsigned int order);

/*
 * results with 256, 32 in the lowmem_reserve sysctl:
 *	1G machine -> (16M dma, 800M-16M normal, 1G-800M high)
 *	1G machine -> (16M dma, 784M normal, 224M high)
 *	NORMAL allocation will leave 784M/256 of ram reserved in the ZONE_DMA
 *	HIGHMEM allocation will leave 224M/32 of ram reserved in ZONE_NORMAL
 *	HIGHMEM allocation will (224M+784M)/256 of ram reserved in ZONE_DMA
 *
 * TBD: should special case ZONE_DMA32 machines here - in those we normally
 * don't need any ZONE_NORMAL reservation
 */
int sysctl_lowmem_reserve_ratio[MAX_NR_ZONES-1] = { 256, 256, 32 };

EXPORT_SYMBOL(totalram_pages);

/*
 * Used by page_zone() to look up the address of the struct zone whose
 * id is encoded in the upper bits of page->flags
 */
struct zone *zone_table[1 << ZONETABLE_SHIFT] __read_mostly;
EXPORT_SYMBOL(zone_table);

static char *zone_names[MAX_NR_ZONES] = { "DMA", "DMA32", "Normal", "HighMem" };
int min_free_kbytes = 1024;

unsigned long __meminitdata nr_kernel_pages;
unsigned long __meminitdata nr_all_pages;

static int np2_get_size(int order)
{
	int size;
	if (order > 32) {
		size = order - 32;
	} else {
		size = (1 << order);
	}
	return size;
}

/* TODO: add this to bootmem.c */
/* initial set up */
void np2_setup(pg_data_t * pgdat)
{
	struct page *page;
	unsigned int i, idx;
	bootmem_data_t *bdata = pgdat->bdata;

	page = virt_to_page(phys_to_virt(bdata->node_boot_start));
	idx = bdata->node_low_pfn - (bdata->node_boot_start >> PAGE_SHIFT);

	PRINTK("page %08x idx %d page[idx] %08x \n",
	       (unsigned int)page, idx, (unsigned int)&page[idx]);

	/* set them all to 0 */
	for (i = 0; i < idx; i++) {
		page->np2_size = 0;
		page++;
	}
	return;
}

/* A lot of the proc interfaces simply use printk to display data */
static int
np2_list_proc(char *buf, char **start, off_t off,
	      int count, int *eof, void *data)
{
	char *p = buf;
	if (off == 0) {
		p += sprintf(p, "Free memory list \n");
		np2_show_list();
		printk(" list %s \n", np2_pbuff);
		p += sprintf(p, "pagevec %d \n", np2_pagevec);
		p += sprintf(p, "hot pages %d \n", np2_hot_pages);
		p += sprintf(p, "cold pages %d \n", np2_cold_pages);
		p += sprintf(p, "unalloc pages %d \n", np2_unalloc);
	}

	return p - buf;
}

static int
np2_merge_proc(char *buf, char **start, off_t off,
	       int count, int *eof, void *data)
{
	char *p = buf;

	if (off == 0) {
		np2_msize = np2_merge_pages();
		p += sprintf(p, "Looking for free memory \n");
		p += sprintf(p, "Max Space  = 0x%X\n", np2_msize);
		p += sprintf(p, "Num Allocs  = 0x%d\n", np2_num_allocs);
		p += sprintf(p, "Num Frees  = 0x%d\n", np2_num_frees);
		p += sprintf(p, "Num Unalloc  = 0x%d\n", np2_unalloc);

		//np2_show_pages(1,0,0); num_un
	}

	return p - buf;
}

static int
np2_space_proc(char *buf, char **start, off_t off,
	       int count, int *eof, void *data)
{
	char *p = buf;
	if (off == 0) {
		p += sprintf(p, "Looking for free memory \n");
		p += sprintf(p, "Num Allocs  = 0x%d\n", np2_num_allocs);
		p += sprintf(p, "Num Frees  = 0x%d\n", np2_num_frees);
		p += sprintf(p, "Num Unalloc  = 0x%d\n", np2_unalloc);
		np2_show_pages(1, 0, 0);
	}

	return p - buf;
}

static int
np2_holes_proc(char *buf, char **start, off_t off,
	       int count, int *eof, void *data)
{
	char *p = buf;
	if (off == 0) {
		p += sprintf(p, "Looking for allocated memory \n");
		p += sprintf(p, "Num Allocs  = 0x%d\n", np2_num_allocs);
		p += sprintf(p, "Num Frees  = 0x%d\n", np2_num_frees);
		np2_show_pages(0, 1, 0);
	}

	return p - buf;
}
static int
np2_all_proc(char *buf, char **start, off_t off,
	     int count, int *eof, void *data)
{
	char *p = buf;
	if (off == 0) {
		p += sprintf(p, "Looking for allocated memory \n");
		p += sprintf(p, "Num Allocs  = 0x%d\n", np2_num_allocs);
		p += sprintf(p, "Num Frees  = 0x%d\n", np2_num_frees);
		np2_show_pages(1, 1, 1);
	}

	return p - buf;
}

static int
np2_help_proc(char *buf, char **start, off_t off,
	      int count, int *eof, void *data)
{
	char *p = buf;
	if (off == 0) {
		p += sprintf(p, "* np2 proc interface\n"
			     "* ==================\n"
			     "* /proc/np2/holes  - show allocated groups\n"
			     "* /proc/np2/space  - show free groups\n"
			     "* /proc/np2/all    - show free and alloc groups\n"
			     "* /proc/np2/list   - show the free list\n"
			     "* /proc/np2/merge  - merge adjacent free groups\n");
	}

	return p - buf;
}

static int
__init np2_setup3(void)
{
	struct proc_dir_entry *pdir;

	PRINTK("proc setup\n");

	pdir = create_proc_entry("np2", S_IFDIR, NULL);
	pdir = create_proc_read_entry("np2/space", 0, 0, np2_space_proc, NULL);
	pdir = create_proc_read_entry("np2/holes", 0, 0, np2_holes_proc, NULL);
	pdir = create_proc_read_entry("np2/all", 0, 0, np2_all_proc, NULL);
	pdir = create_proc_read_entry("np2/help", 0, 0, np2_help_proc, NULL);
	pdir = create_proc_read_entry("np2/merge", 0, 0, np2_merge_proc, NULL);
	pdir = create_proc_read_entry("np2/list", 0, 0, np2_list_proc, NULL);
	return 0;
}

module_init(np2_setup3);

/* do this on the first alloc request */
static void np2_setup2(void)
{

	np2_msize = np2_merge_pages();
	PRINTK("np2_setup2 max size avail = %x (%d) pages \n",
	       np2_msize, np2_msize);
	//np2_show_pages(1,1,0);
}

/* do this when allocating memory */
static void np2_set_page_size(struct page *page, int size)
{
	if (size > 0)
		size = -size;
	page->np2_size = size;
}

static void np2_clear_page_size(struct page *page, int size, int order)
{
	if (page->np2_size < 0) {
		page->np2_size = -page->np2_size;
	} else {
		if (np2_unalloc < 100)
			PRINTK("unalloc page freed !!"
			       " %p size %d order %d current %s\n",
			       page_address(page),
			       (int)page->np2_size, order, current->comm);
		//if (page->np2_size == 0 ) page->np2_size = size;
		np2_unalloc++;

	}
}

/* This uses the page->size component to detect and merge pages */
static int np2_merge_pages(void)
{
	struct zone *zone;
	struct page *page;
	unsigned long pfn;
	int rsize = 0;
	int nsize;
	int ignore = 0;
	unsigned long flags;

	for_each_zone(zone) {
		spin_lock_irqsave(&zone->lock, flags);
		/* clean up the list, we'll build a new one */
		INIT_LIST_HEAD(&zone->np2_list);

		/* Will not work well for holes at the moment */
		for (pfn = 0; pfn < zone->spanned_pages; pfn++) {
			page = pfn_to_page(pfn + zone->zone_start_pfn);

			if (ignore > 0) {
				if (pfn >= zone->np2_minpfn) {
					if (page->np2_size != 0) {
						PRINTK("inval page in ignore area pfn %d size %d\n",
						       (int)pfn, (int)page->np2_size);
					}
				}
				ignore--;
				continue;
			}
			if (page->np2_size < 0) {
				ignore = -page->np2_size;
				ignore--;
			}

			if (page->np2_size > 0) {

#if 0
				/* look for a missing page */
				if (page[page->np2_size].np2_size == 0 ) {
					/* rescan this page */
					page->np2_size++;
					pfn--;
					continue;
				}
#endif

				/* look for a merge */
				if (page[page->np2_size].np2_size > 0) {
					/* rescan this page */
					nsize =
					    page->np2_size +
					    page[page->np2_size].np2_size;
					page[page->np2_size].np2_size = 0;
					set_page_count(&page[page->np2_size], 1);
					page->np2_size = nsize;
					ignore = 0;
					pfn--;	
					continue;
				} else {
					if (page->np2_size > 0)
						list_add(&page->np2_list,
							 &zone->np2_list);
					ignore = page->np2_size;
					ignore--;
					if (page->np2_size > rsize) {
						/* capture largest block */
						rsize = page->np2_size;
						/* set the zone's lowest page */
						zone->np2_minpfn = pfn;
						PRINTK("Merge Set minpfn %d\n", pfn);
					}
				}
			}
		}
		spin_unlock_irqrestore(&zone->lock, flags);
	}
	return rsize;
}

static void np2_show_list(void)
{
	struct zone *zone;
	struct page *page;
	struct list_head *curr;
	/* create a copy of the list for display */
	char *p;
	p = np2_pbuff;
	for_each_zone(zone) {
		list_for_each(curr, &zone->np2_list) {
			page = list_entry(curr, struct page, np2_list);
			p += sprintf(p,
				     " list at pfn %d addr %p size %08x\n",
				     (int)page_to_pfn(page), page_address(page),
				     (int)page->np2_size);
			if ((p - np2_pbuff) > 8000) {
				p += sprintf(p, " list out of space....\n");
				return;
			}
		}
	}
}

/* This uses the page->size component to detect and merge pages
 * debug  = show the memory layout
 * spaces = show spaces ( free memory )
 * holes  = show holes ( used memory )
 * check  = make sure that each page is in a hole or a space
 */
static void np2_show_pages(int spaces, int holes, int check)
{
	struct zone *zone;
	struct page *page;
	unsigned long pfn;
	int inspace = 0;
	int inhole = 0;

	for_each_zone(zone) {
		/* Will not work well for holes at the moment */
		for (pfn = 0; pfn < zone->spanned_pages; pfn++) {
			page = pfn_to_page(pfn + zone->zone_start_pfn);
			if (check) {
				if (((inhole > 0) || (inspace > 0))
				    && (page->np2_size != 0)) {
					PRINTK("error pfn %5d "
					       "addr %p size %8x ih %d is %d\n",
					       (int)pfn, page_address(page),
					       (int)page->np2_size, inhole,
					       inspace);
				}

				if (((inhole == 0) && (inspace == 0))
				    && (page->np2_size == 0)) {
					PRINTK
					    ("orphan pfn %3d addr %p count %d\n",
					     (int)pfn, page_address(page),
					     page_count(page));
				}
				if ((page->np2_size > 0) && (inhole > 0)) {
					PRINTK("space in hole "
					       "pfn %5d addr %p psp %d inhole %d "
					       "count %d\n",
					       (int)pfn, page_address(page),
					       page->np2_size,
					       inhole, page_count(page));
				}
				if ((page->np2_size < 0) && (inspace > 0)) {
					PRINTK("hole in space "
					       "pfn %5d addr %p phole %d inspace %d "
					       "count %d\n",
					       (int)pfn, page_address(page),
					       -page->np2_size,
					       inspace, page_count(page));
				}

			}
			if (spaces) {
				if (page->np2_size > 0) {
					PRINTK
					    ("space at pfn %5d addr %p size %8x count %d\n",
					     (int)pfn, page_address(page),
					     (int)page->np2_size,
					     page_count(page));
					inspace = page->np2_size;
				}
			}
			if (holes) {
				if (page->np2_size < 0) {
					PRINTK
					    ("hole at pfn %5d addr %p size %8x count %d\n",
					     (int)pfn, page_address(page),
					     ~page->np2_size + 1,
					     page_count(page));
					inhole = -page->np2_size;
				}

			}
			if (inhole)
				inhole--;
			if (inspace)
				inspace--;
		}
	}
	return;
}

/* the basic np2 allocator 
 * gets small pages ( < 2 ) from start big pages from end
 */
static struct page *np2_get_pages(int size)
{
	struct zone *zone;
	struct page *page;
	struct page *fpage;
	unsigned long pfn;
	int fromend = 0;
	int pg_found = 0;
	int ssize;		/* used to round up allocations */
	int osize;
	int fsize;
	unsigned long flags = 0;
	struct list_head *curr;

	int uselists = 1;
	int usespin1 = 1;
	int splitsingle = 1;

	zone = NULL;		/* happy compiler */

	/* only split by even number of  pages or more */
	ssize = size;
	if (size & 1)
		ssize = size + 1;
	fromend = 1;		/* get from end of block */

	if (uselists) {
		for_each_zone(zone) {
			if (usespin1)
				spin_lock_irqsave(&zone->lock, flags);
			fsize = 0;
			fpage = NULL;

			if (size == 1) {
				/* first scan for single pages */
				list_for_each(curr, &zone->np2_list) {
					page =
					    list_entry(curr, struct page,
						       np2_list);
					if (page->np2_size == size) {
						pg_found = 1;
						goto np2_spage;
					}
				}
			}
			/* first scan the lists */
			list_for_each(curr, &zone->np2_list) {
				page = list_entry(curr, struct page, np2_list);
				if (ssize >= 0) {
					if (page->np2_size == ssize) {
						PRINTK("list match at ssize %d page %p (%d) pfn %d\n",
							     (int)ssize,
							     page_address(page),
							     page->np2_size,
							     (int)
							     page_to_pfn(page));
						pg_found = 1;
						goto np2_page;
					}
				}
				/* also find smallest larger page group */
				if (page->np2_size > ssize) {
					if (fsize == 0) {
						fsize = page->np2_size;
						fpage = page;
					} else {
						if (page->np2_size < fsize) {
							fsize = page->np2_size;
							fpage = page;
						}
					}
				}

			}
			/* See if we found a smaller page.
			 * Its a shame that we cannot reuse the 2 page allocs yet.
			 */
			if (fpage) {
				page = fpage;
				pg_found = 1;
				PRINTK("list match at ssize %d page %p (%d) pfn %d\n",
					       (int)ssize,
					       page_address(page),
					       page->np2_size,
					       (int)page_to_pfn(page));
				goto np2_page;
			}
			if (usespin1)
				spin_unlock_irqrestore(&zone->lock, flags);
		}		/* end for each zone */
	}			/* end uselists */

	/* not using lists, use super slob instead ... first scan for an exact match */

	for_each_zone(zone) {
		if (usespin1)
			spin_lock_irqsave(&zone->lock, flags);

		for (pfn = zone->np2_minpfn; pfn < zone->spanned_pages; pfn++) {
			page = pfn_to_page(pfn + zone->zone_start_pfn);

			if (page->np2_size == ssize) {
				pg_found = 1;
				goto np2_page;
			}
		}
		if (usespin1)
			spin_unlock_irqrestore(&zone->lock, flags);

	}
	/* now get what you can */
	for_each_zone(zone) {
		if (usespin1)
			spin_lock_irqsave(&zone->lock, flags);
		for (pfn = zone->np2_minpfn; pfn < zone->spanned_pages; pfn++) {
			page = pfn_to_page(pfn + zone->zone_start_pfn);

			if (0 && (page->np2_size & 1)) {	/* 2 page allocs on even boundary */
				if (size == 2) {	/* no this did not fix it */
					ssize = 3;	/* problems in softirq.c */
				}
			}
			if (page->np2_size >= ssize) {
				pg_found = 1;
				goto np2_page;
			}
		}
		if (usespin1)
			spin_unlock_irqrestore(&zone->lock, flags);

	}
	page = NULL;

      np2_page:

	/* larger or equal page group found split it up if needed */
	if (page) {
		if (page->np2_size > ssize) {	/* was size ??? */
			if (fromend) {	/* take from the end of the block */
				osize = page->np2_size;
				page->np2_size = osize - ssize;
				page = &page[osize - ssize];
			} else {	/* take from start of block */
				osize = page->np2_size;
				page[ssize].np2_size = osize - ssize;
			}
			page->np2_size = ssize;
			__free_pages(page, 0);
		}
		list_del(&page->np2_list);
		page->np2_size = -ssize;
		if (splitsingle) {
			if ((size == 1) && (ssize == 2)) {
				struct page *spage;
				page->np2_size = -1;
				spage = page + 1;
				spage->np2_size = 1;
				__free_pages(spage, 0);
			}
		}
		/* adjust count ... remember this is negative */
		zone->free_pages += page->np2_size;

		if (usespin1)
			spin_unlock_irqrestore(&zone->lock, flags);
	}			/* end page */

	return page;

      np2_spage:		/* single page allocation */
	page->np2_size = -1;
	list_del(&page->np2_list);
	zone->free_pages += page->np2_size;
	if (usespin1)
		spin_unlock_irqrestore(&zone->lock, flags);
	return page;

}

#ifdef CONFIG_DEBUG_VM
static int page_outside_zone_boundaries(struct zone *zone, struct page *page)
{
	int ret = 0;
	unsigned seq;
	unsigned long pfn = page_to_pfn(page);

	do {
		seq = zone_span_seqbegin(zone);
		if (pfn >= zone->zone_start_pfn + zone->spanned_pages)
			ret = 1;
		else if (pfn < zone->zone_start_pfn)
			ret = 1;
	} while (zone_span_seqretry(zone, seq));

	return ret;
}

static int page_is_consistent(struct zone *zone, struct page *page)
{
#ifdef CONFIG_HOLES_IN_ZONE
	if (!pfn_valid(page_to_pfn(page)))
		return 0;
#endif
	if (zone != page_zone(page))
		return 0;

	return 1;
}
/*
 * Temporary debugging check for pages not lying within a given zone.
 */
static int bad_range(struct zone *zone, struct page *page)
{
	if (page_outside_zone_boundaries(zone, page))
		return 1;
	if (!page_is_consistent(zone, page))
		return 1;

	return 0;
}

#else
static inline int bad_range(struct zone *zone, struct page *page)
{
	return 0;
}
#endif

static void bad_page(struct page *page)
{
	printk(KERN_EMERG "Bad page state in process '%s'\n"
		KERN_EMERG "page:%p flags:0x%0*lx mapping:%p mapcount:%d count:%d\n"
		KERN_EMERG "Trying to fix it up, but a reboot is needed\n"
		KERN_EMERG "Backtrace:\n",
		current->comm, page, (int)(2*sizeof(unsigned long)),
		(unsigned long)page->flags, page->mapping,
		page_mapcount(page), page_count(page));
	dump_stack();
	page->flags &= ~(1 << PG_lru	|
			1 << PG_private |
			1 << PG_locked	|
			1 << PG_active	|
			1 << PG_dirty	|
			1 << PG_reclaim |
			1 << PG_slab    |
			1 << PG_swapcache |
			1 << PG_writeback);
	set_page_count(page, 0);
	reset_page_mapcount(page);
	page->mapping = NULL;
	add_taint(TAINT_BAD_PAGE);
}

/*
 * Higher-order pages are called "compound pages".  They are structured thusly:
 *
 * The first PAGE_SIZE page is called the "head page".
 *
 * The remaining PAGE_SIZE pages are called "tail pages".
 *
 * All pages have PG_compound set.  All pages have their ->private pointing at
 * the head page (even the head page has this).
 *
 * The first tail page's ->lru.next holds the address of the compound page's
 * put_page() function.  Its ->lru.prev holds the order of allocation.
 * This usage means that zero-order pages may not be compound.
 */

static void free_compound_page(struct page *page)
{
	__free_pages_ok(page, (unsigned long)page[1].lru.prev);
}

static void prep_compound_page(struct page *page, unsigned long order)
{
	int i;
	int nr_pages = 1 << order;

	page[1].lru.next = (void *)free_compound_page;	/* set dtor */
	page[1].lru.prev = (void *)order;
	for (i = 0; i < nr_pages; i++) {
		struct page *p = page + i;

		__SetPageCompound(p);
		set_page_private(p, (unsigned long)page);
	}
}

static void destroy_compound_page(struct page *page, unsigned long order)
{
	int i;
	int nr_pages = 1 << order;

	if (unlikely((unsigned long)page[1].lru.prev != order))
		bad_page(page);

	for (i = 0; i < nr_pages; i++) {
		struct page *p = page + i;

		if (unlikely(!PageCompound(p) |
				(page_private(p) != (unsigned long)page)))
			bad_page(page);
		__ClearPageCompound(p);
	}
}

static inline void prep_zero_page(struct page *page, int order, gfp_t gfp_flags)
{
	int i;

	BUG_ON((gfp_flags & (__GFP_WAIT | __GFP_HIGHMEM)) == __GFP_HIGHMEM);
	/*
	 * clear_highpage() will use KM_USER0, so it's a bug to use __GFP_ZERO
	 * and __GFP_HIGHMEM from hard or soft interrupt context.
	 */
	BUG_ON((gfp_flags & __GFP_HIGHMEM) && in_interrupt());
	for (i = 0; i < np2_get_size(order); i++)
		clear_highpage(page + i);
}

/*
 * function for dealing with page's order in buddy system.
 * zone->lock is already acquired when we use these.
 * So, we don't need atomic page->flags operations here.
 */
static inline unsigned long page_order(struct page *page)
{
	return page_private(page);
}

static inline void set_page_order(struct page *page, int order)
{
	set_page_private(page, order);
	__SetPagePrivate(page);
}

static inline void rmv_page_order(struct page *page)
{
	__ClearPagePrivate(page);
	set_page_private(page, 0);
}

/*
 * Locate the struct page for both the matching buddy in our
 * pair (buddy1) and the combined O(n+1) page they form (page).
 *
 * 1) Any buddy B1 will have an order O twin B2 which satisfies
 * the following equation:
 *     B2 = B1 ^ (1 << O)
 * For example, if the starting buddy (buddy2) is #8 its order
 * 1 buddy is #10:
 *     B2 = 8 ^ (1 << 1) = 8 ^ 2 = 10
 *
 * 2) Any buddy B will have an order O+1 parent P which
 * satisfies the following equation:
 *     P = B & ~(1 << O)
 *
 * Assumption: *_mem_map is contiguous at least up to MAX_ORDER
 */
static inline struct page *
__page_find_buddy(struct page *page, unsigned long page_idx, unsigned int order)
{
	unsigned long buddy_idx = page_idx ^ (1 << order);

	return page + (buddy_idx - page_idx);
}

static inline unsigned long
__find_combined_index(unsigned long page_idx, unsigned int order)
{
	return (page_idx & ~(1 << order));
}

/*
 * This function checks whether a page is free && is the buddy
 * we can do coalesce a page and its buddy if
 * (a) the buddy is not in a hole &&
 * (b) the buddy is free &&
 * (c) the buddy is on the buddy system &&
 * (d) a page and its buddy have the same order.
 * for recording page's order, we use page_private(page) and PG_private.
 *
 */
static inline int page_is_buddy(struct page *page, struct page *buddy,
								int order)
{
#ifdef CONFIG_HOLES_IN_ZONE
	if (!pfn_valid(page_to_pfn(buddy)))
		return 0;
#endif

	if (PagePrivate(page) &&
	    (page_order(page) == order) && page_count(page) == 0)
		return 1;
	return 0;
}

/*
 * Freeing function for a buddy system allocator.
 *
 * The concept of a buddy system is to maintain direct-mapped table
 * (containing bit values) for memory blocks of various "orders".
 * The bottom level table contains the map for the smallest allocatable
 * units of memory (here, pages), and each level above it describes
 * pairs of units from the levels below, hence, "buddies".
 * At a high level, all that happens here is marking the table entry
 * at the bottom level available, and propagating the changes upward
 * as necessary, plus some accounting needed to play nicely with other
 * parts of the VM system.
 * At each level, we keep a list of pages, which are heads of continuous
 * free pages of length of (1 << order) and marked with PG_Private.Page's
 * order is recorded in page_private(page) field.
 * So when we are allocating or freeing one, we can derive the state of the
 * other.  That is, if we allocate a small block, and both were   
 * free, the remainder of the region must be split into blocks.   
 * If a block is freed, and its buddy is also free, then this
 * triggers coalescing into a block of larger size.            
 *
 * -- wli
 */

static inline void __free_one_page(struct page *page,
		struct zone *zone, unsigned int order)
{
	unsigned long page_idx;
	int order_size = 1 << order;

	if (unlikely(PageCompound(page)))
		destroy_compound_page(page, order);

	page_idx = page_to_pfn(page) & ((1 << MAX_ORDER) - 1);

	BUG_ON(page_idx & (order_size - 1));
	BUG_ON(bad_range(zone, page));

	zone->free_pages += order_size;
	while (order < MAX_ORDER-1) {
		unsigned long combined_idx;
		struct free_area *area;
		struct page *buddy;

		buddy = __page_find_buddy(page, page_idx, order);
		if (!page_is_buddy(page, buddy, order))
			break;		/* Move the buddy up one level. */

		list_del(&buddy->lru);
		area = zone->free_area + order;
		area->nr_free--;
		rmv_page_order(buddy);
		combined_idx = __find_combined_index(page_idx, order);
		page = page + (combined_idx - page_idx);
		page_idx = combined_idx;
		order++;
	}
	set_page_order(page, order);
	list_add(&page->lru, &zone->free_area[order].free_list);
	zone->free_area[order].nr_free++;
}

static inline int free_pages_check(struct page *page)
{
	if (unlikely(page_mapcount(page) |
		(page->mapping != NULL)  |
		(page_count(page) != 0)  |
		(page->flags & (
			1 << PG_lru	|
			1 << PG_private |
			1 << PG_locked	|
			1 << PG_active	|
			1 << PG_reclaim	|
			1 << PG_slab	|
			1 << PG_swapcache |
			1 << PG_writeback |
			1 << PG_reserved))))
		bad_page(page);
	if (PageDirty(page))
		__ClearPageDirty(page);
	/*
	 * For now, we report if PG_reserved was found set, but do not
	 * clear it, and do not free the page.  But we shall soon need
	 * to do more, for when the ZERO_PAGE count wraps negative.
	 */
	return PageReserved(page);
}

/*
 * Frees a list of pages. 
 * Assumes all pages on list are in same zone, and of same order.
 * count is the number of pages to free.
 *
 * If the zone was previously in an "all pages pinned" state then look to
 * see if this freeing clears that state.
 *
 * And clear the zone's pages_scanned counter, to hold off the "all pages are
 * pinned" detection logic.
 */
static void free_pages_bulk(struct zone *zone, int count,
					struct list_head *list, int order)
{
	spin_lock(&zone->lock);
	zone->all_unreclaimable = 0;
	zone->pages_scanned = 0;
	while (count--) {
		struct page *page;

		BUG_ON(list_empty(list));
		page = list_entry(list->prev, struct page, lru);
		/* have to delete it as __free_one_page list manipulates */
		list_del(&page->lru);
		__free_one_page(page, zone, order);
	}
	spin_unlock(&zone->lock);
}

static void free_one_page(struct zone *zone, struct page *page, int order)
{
	LIST_HEAD(list);
	list_add(&page->lru, &list);
	free_pages_bulk(zone, 1, &list, order);
}

static void __free_pages_ok(struct page *page, unsigned int order)
{
	unsigned long flags;
	int i;
	int reserved = 0;

	arch_free_page(page, order);
	if (!PageHighMem(page))
		debug_check_no_locks_freed(page_address(page),
					   PAGE_SIZE<<order);

	for (i = 0 ; i < (1 << order) ; ++i)
		reserved += free_pages_check(page + i);
	if (reserved)
		return;

	kernel_map_pages(page, 1 << order, 0);
	local_irq_save(flags);
	__count_vm_events(PGFREE, 1 << order);
	free_one_page(page_zone(page), page, order);
	local_irq_restore(flags);
}

/*
 * permit the bootmem allocator to evade page validation on high-order frees
 */
void fastcall __init __free_pages_bootmem(struct page *page, unsigned int order)
{
	if (order == 0) {
		__ClearPageReserved(page);
		if (use_np2) {
			page->np2_size = -1;
			__free_pages(page, 0);
		} else {
			set_page_refcounted(page);
			__free_page(page);
		}
	} else {
		int loop;

		prefetchw(page);
		for (loop = 0; loop < BITS_PER_LONG; loop++) {
			struct page *p = &page[loop];

			if (loop + 1 < BITS_PER_LONG)
				prefetchw(p + 1);
			__ClearPageReserved(p);
		}

		if (use_np2) {
			page->np2_size = -np2_get_size(order);
		} else {
			set_page_refcounted(page);
		}
		__free_pages(page, order);
	}
}


/*
 * The order of subdivision here is critical for the IO subsystem.
 * Please do not alter this order without good reasons and regression
 * testing. Specifically, as large blocks of memory are subdivided,
 * the order in which smaller blocks are delivered depends on the order
 * they're subdivided in this function. This is the primary factor
 * influencing the order in which pages are delivered to the IO
 * subsystem according to empirical testing, and this is also justified
 * by considering the behavior of a buddy system containing a single
 * large block of memory acted on by a series of small allocations.
 * This behavior is a critical factor in sglist merging's success.
 *
 * -- wli
 */
static inline void expand(struct zone *zone, struct page *page,
 	int low, int high, struct free_area *area)
{
	unsigned long size = 1 << high;

	while (high > low) {
		area--;
		high--;
		size >>= 1;
		BUG_ON(bad_range(zone, &page[size]));
		list_add(&page[size].lru, &area->free_list);
		area->nr_free++;
		set_page_order(&page[size], high);
	}
}

/*
 * This page is about to be returned from the page allocator
 */
static int prep_new_page(struct page *page, int order, gfp_t gfp_flags)
{
	if (unlikely(page_mapcount(page) |
		(page->mapping != NULL)  |
		(page_count(page) != 0)  |
		(page->flags & (
			1 << PG_lru	|
			1 << PG_private	|
			1 << PG_locked	|
			1 << PG_active	|
			1 << PG_dirty	|
			1 << PG_reclaim	|
			1 << PG_slab    |
			1 << PG_swapcache |
			1 << PG_writeback |
			1 << PG_reserved))))
		bad_page(page);

	/*
	 * For now, we report if PG_reserved was found set, but do not
	 * clear it, and do not allocate the page: as a safety net.
	 */
	if (PageReserved(page))
		return 1;

	page->flags &= ~(1 << PG_uptodate | 1 << PG_error |
			1 << PG_referenced | 1 << PG_arch_1 |
			1 << PG_checked | 1 << PG_mappedtodisk);
	set_page_private(page, 0);
	set_page_refcounted(page);
	kernel_map_pages(page, 1 << order, 1);

	if (gfp_flags & __GFP_ZERO)
		prep_zero_page(page, order, gfp_flags);

	if (order && (gfp_flags & __GFP_COMP))
		prep_compound_page(page, order);

	return 0;
}

/* 
 * Do the hard work of removing an element from the buddy allocator.
 * Call me with the zone->lock already held.
 */
static struct page *__rmqueue(struct zone *zone, unsigned int order)
{
	struct free_area * area;
	unsigned int current_order;
	struct page *page;

	for (current_order = order; current_order < MAX_ORDER; ++current_order) {
		area = zone->free_area + current_order;
		if (list_empty(&area->free_list))
			continue;

		page = list_entry(area->free_list.next, struct page, lru);
		list_del(&page->lru);
		rmv_page_order(page);
		area->nr_free--;
		zone->free_pages -= 1UL << order;
		expand(zone, page, order, current_order, area);
		return page;
	}

	return NULL;
}

/* 
 * Obtain a specified number of elements from the buddy allocator, all under
 * a single hold of the lock, for efficiency.  Add them to the supplied list.
 * Returns the number of new pages which were placed at *list.
 */
static int rmqueue_bulk(struct zone *zone, unsigned int order, 
			unsigned long count, struct list_head *list)
{
	int i;
	
	spin_lock(&zone->lock);
	for (i = 0; i < count; ++i) {
		struct page *page = __rmqueue(zone, order);
		if (unlikely(page == NULL))
			break;
		list_add_tail(&page->lru, list);
	}
	spin_unlock(&zone->lock);
	return i;
}

#ifdef CONFIG_NUMA
/*
 * Called from the slab reaper to drain pagesets on a particular node that
 * belong to the currently executing processor.
 * Note that this function must be called with the thread pinned to
 * a single processor.
 */
void drain_node_pages(int nodeid)
{
	int i, z;
	unsigned long flags;

	for (z = 0; z < MAX_NR_ZONES; z++) {
		struct zone *zone = NODE_DATA(nodeid)->node_zones + z;
		struct per_cpu_pageset *pset;

		pset = zone_pcp(zone, smp_processor_id());
		for (i = 0; i < ARRAY_SIZE(pset->pcp); i++) {
			struct per_cpu_pages *pcp;

			pcp = &pset->pcp[i];
			if (pcp->count) {
				local_irq_save(flags);
				free_pages_bulk(zone, pcp->count, &pcp->list, 0);
				pcp->count = 0;
				local_irq_restore(flags);
			}
		}
	}
}
#endif

#if defined(CONFIG_PM) || defined(CONFIG_HOTPLUG_CPU)
static void __drain_pages(unsigned int cpu)
{
	unsigned long flags;
	struct zone *zone;
	int i;

	for_each_zone(zone) {
		struct per_cpu_pageset *pset;

		pset = zone_pcp(zone, cpu);
		for (i = 0; i < ARRAY_SIZE(pset->pcp); i++) {
			struct per_cpu_pages *pcp;

			pcp = &pset->pcp[i];
			local_irq_save(flags);
			free_pages_bulk(zone, pcp->count, &pcp->list, 0);
			pcp->count = 0;
			local_irq_restore(flags);
		}
	}
}
#endif /* CONFIG_PM || CONFIG_HOTPLUG_CPU */

#ifdef CONFIG_PM

void mark_free_pages(struct zone *zone)
{
	unsigned long zone_pfn, flags;
	int order;
	struct list_head *curr;

	if (!zone->spanned_pages)
		return;

	spin_lock_irqsave(&zone->lock, flags);
	for (zone_pfn = 0; zone_pfn < zone->spanned_pages; ++zone_pfn)
		ClearPageNosaveFree(pfn_to_page(zone_pfn + zone->zone_start_pfn));

	for (order = MAX_ORDER - 1; order >= 0; --order)
		list_for_each(curr, &zone->free_area[order].free_list) {
			unsigned long start_pfn, i;

			start_pfn = page_to_pfn(list_entry(curr, struct page, lru));

			for (i=0; i < (1<<order); i++)
				SetPageNosaveFree(pfn_to_page(start_pfn+i));
	}
	spin_unlock_irqrestore(&zone->lock, flags);
}

/*
 * Spill all of this CPU's per-cpu pages back into the buddy allocator.
 */
void drain_local_pages(void)
{
	unsigned long flags;

	local_irq_save(flags);	
	__drain_pages(smp_processor_id());
	local_irq_restore(flags);	
}
#endif /* CONFIG_PM */

/*
 * Free a 0-order page
 */
static void fastcall free_hot_cold_page(struct page *page, int cold)
{
	struct zone *zone = page_zone(page);
	struct per_cpu_pages *pcp;
	unsigned long flags;

	arch_free_page(page, 0);

	if (PageAnon(page))
		page->mapping = NULL;
	if (free_pages_check(page))
		return;

	kernel_map_pages(page, 1, 0);

	pcp = &zone_pcp(zone, get_cpu())->pcp[cold];
	local_irq_save(flags);
	__count_vm_event(PGFREE);
	list_add(&page->lru, &pcp->list);
	pcp->count++;
	if (pcp->count >= pcp->high) {
		free_pages_bulk(zone, pcp->batch, &pcp->list, 0);
		pcp->count -= pcp->batch;
	}
	local_irq_restore(flags);
	put_cpu();
}

void fastcall free_hot_page(struct page *page)
{
	if (use_np2) {
		np2_hot_pages++;
		if (np2_hot_pages < 256) {
			PRINTK("free hotpage pfn %5d "
			       "addr %p size %8x count %d \n",
			       (int)page_to_pfn(page),
			       page_address(page),
			       (int)page->np2_size, page_count(page)
			    );
		}
		//__free_pages(page,0);
	} else {
		free_hot_cold_page(page, 0);
	}
}

void fastcall free_cold_page(struct page *page)
{
	if (use_np2) {
		np2_cold_pages++;
		if (0 && (np2_cold_pages < 256)) {
			PRINTK("free coldpage pfn %5d "
			       "addr %p size %8x count %d \n",
			       (int)page_to_pfn(page),
			       page_address(page),
			       (int)page->np2_size, page_count(page)
			    );
		}
		//__free_pages(page,0);
	} else {
		free_hot_cold_page(page, 1);
	}
}

/*
 * split_page takes a non-compound higher-order page, and splits it into
 * n (1<<order) sub-pages: page[0..n]
 * Each sub-page must be freed individually.
 *
 * Note: this is probably too low level an operation for use in drivers.
 * Please consult with lkml before using this in your driver.
 */
void split_page(struct page *page, unsigned int order)
{
	int i;

	BUG_ON(PageCompound(page));
	BUG_ON(!page_count(page));
	for (i = 1; i < (1 << order); i++)
		set_page_refcounted(page + i);
}

/*
 * Really, prep_compound_page() should be called from __rmqueue_bulk().  But
 * we cheat by calling it from here, in the order > 0 path.  Saves a branch
 * or two.
 */
static struct page *buffered_rmqueue(struct zonelist *zonelist,
			struct zone *zone, int order, gfp_t gfp_flags)
{
	unsigned long flags;
	struct page *page;
	int cold = !!(gfp_flags & __GFP_COLD);
	int cpu;
	int size = np2_get_size(order);

again:
	cpu  = get_cpu();
	if (likely(order == 0)) {
		struct per_cpu_pages *pcp;

		pcp = &zone_pcp(zone, cpu)->pcp[cold];
		local_irq_save(flags);
		if (!pcp->count) {
			pcp->count += rmqueue_bulk(zone, 0,
						pcp->batch, &pcp->list);
			if (unlikely(!pcp->count))
				goto failed;
		}
		page = list_entry(pcp->list.next, struct page, lru);
		list_del(&page->lru);
		pcp->count--;
	} else {
		spin_lock_irqsave(&zone->lock, flags);
		page = __rmqueue(zone, order);
		spin_unlock(&zone->lock);
		if (!page)
			goto failed;
	}

	__count_zone_vm_events(PGALLOC, zone, np2_get_size(order));
	zone_statistics(zonelist, zone);
	local_irq_restore(flags);
	put_cpu();

	BUG_ON(bad_range(zone, page));
	if (prep_new_page(page, order, gfp_flags))
		goto again;

	if (use_np2)
		printk(KERN_EMERG "NP2: should not get here!!!\n");
	if (page)
		page->np2_size = -size;

	return page;

failed:
	local_irq_restore(flags);
	put_cpu();
	return NULL;
}

#define ALLOC_NO_WATERMARKS	0x01 /* don't check watermarks at all */
#define ALLOC_WMARK_MIN		0x02 /* use pages_min watermark */
#define ALLOC_WMARK_LOW		0x04 /* use pages_low watermark */
#define ALLOC_WMARK_HIGH	0x08 /* use pages_high watermark */
#define ALLOC_HARDER		0x10 /* try to alloc harder */
#define ALLOC_HIGH		0x20 /* __GFP_HIGH set */
#define ALLOC_CPUSET		0x40 /* check for correct cpuset */

/*
 * Return 1 if free pages are above 'mark'. This takes into account the order
 * of the allocation.
 */
int zone_watermark_ok(struct zone *z, int order, unsigned long mark,
		      int classzone_idx, int alloc_flags)
{
	/* free_pages my go negative - that's OK */
	long min = mark, free_pages = z->free_pages - (1 << order) + 1;
	int o;

	if (alloc_flags & ALLOC_HIGH)
		min -= min / 2;
	if (alloc_flags & ALLOC_HARDER)
		min -= min / 4;

	if (free_pages <= min + z->lowmem_reserve[classzone_idx])
		return 0;
	for (o = 0; o < order; o++) {
		/* At the next order, this order's pages become unavailable */
		free_pages -= z->free_area[o].nr_free << o;

		/* Require fewer higher order pages to be free */
		min >>= 1;

		if (free_pages <= min)
			return 0;
	}
	return 1;
}

/*
 * get_page_from_freeliest goes through the zonelist trying to allocate
 * a page.
 */
static struct page *
get_page_from_freelist(gfp_t gfp_mask, unsigned int order,
		struct zonelist *zonelist, int alloc_flags)
{
	struct zone **z = zonelist->zones;
	struct page *page = NULL;
	int classzone_idx = zone_idx(*z);

	/*
	 * Go through the zonelist once, looking for a zone with enough free.
	 * See also cpuset_zone_allowed() comment in kernel/cpuset.c.
	 */
	do {
		if ((alloc_flags & ALLOC_CPUSET) &&
				!cpuset_zone_allowed(*z, gfp_mask))
			continue;

		if (!(alloc_flags & ALLOC_NO_WATERMARKS)) {
			unsigned long mark;
			if (alloc_flags & ALLOC_WMARK_MIN)
				mark = (*z)->pages_min;
			else if (alloc_flags & ALLOC_WMARK_LOW)
				mark = (*z)->pages_low;
			else
				mark = (*z)->pages_high;
			if (!zone_watermark_ok(*z, order, mark,
				    classzone_idx, alloc_flags))
				if (!zone_reclaim_mode ||
				    !zone_reclaim(*z, gfp_mask, order))
					continue;
		}

		page = buffered_rmqueue(zonelist, *z, order, gfp_mask);
		if (page) {
			break;
		}
	} while (*(++z) != NULL);
	return page;
}

/*
 * This is the 'heart' of the zoned buddy allocator.
 */
struct page * fastcall
__alloc_pages(gfp_t gfp_mask, unsigned int order,
		struct zonelist *zonelist)
{
	const gfp_t wait = gfp_mask & __GFP_WAIT;
	struct zone **z;
	struct page *page;
	struct reclaim_state reclaim_state;
	struct task_struct *p = current;
	int do_retry;
	int alloc_flags;
	int did_some_progress;
	int size = np2_get_size(order);

	might_sleep_if(wait);

	if (np2_num_allocs == 0) {
		np2_setup2();
	}
	np2_num_allocs++;
	if (use_np2) {
		page = np2_get_pages(size);
		if (!page) {
			PRINTK("NP2 unable to alloc size %d\n", size);
			np2_show_pages(1, 0, 0);
		} else {
			// PSW added these
			prep_new_page(page, order, gfp_mask);
			if (0 && (np2_num_allocs > 0) && (np2_num_allocs < 250)) {
				PRINTK("(%3d) pfn %5d "
				       "addr %p size %8x order %d count %d <%s>\n",
				       np2_num_allocs,
				       (int)page_to_pfn(page),
				       page_address(page),
				       -(int)page->np2_size,
				       order, page_count(page), current->comm);
			}
			if (0 && strcmp(current->comm, "swapper") == 0) {
				PRINTK("swapper pfn %5d "
				       "addr %p size %8x order %d count %d \n",
				       (int)page_to_pfn(page),
				       page_address(page),
				       -(int)page->np2_size,
				       order, page_count(page)
				    );
			}
		}
		return page;	/* np2 return */
	}

      restart:
	z = zonelist->zones;	/* the list of zones suitable for gfp_mask */

	if (unlikely(*z == NULL)) {
		/* Should this ever happen?? */
		return NULL;
	}

	page = get_page_from_freelist(gfp_mask|__GFP_HARDWALL, order,
				zonelist, ALLOC_WMARK_LOW|ALLOC_CPUSET);
	if (page)
		goto got_pg;

	do {
		wakeup_kswapd(*z, order);
	} while (*(++z));

	/*
	 * OK, we're below the kswapd watermark and have kicked background
	 * reclaim. Now things get more complex, so set up alloc_flags according
	 * to how we want to proceed.
	 *
	 * The caller may dip into page reserves a bit more if the caller
	 * cannot run direct reclaim, or if the caller has realtime scheduling
	 * policy or is asking for __GFP_HIGH memory.  GFP_ATOMIC requests will
	 * set both ALLOC_HARDER (!wait) and ALLOC_HIGH (__GFP_HIGH).
	 */
	alloc_flags = ALLOC_WMARK_MIN;
	if ((unlikely(rt_task(p)) && !in_interrupt()) || !wait)
		alloc_flags |= ALLOC_HARDER;
	if (gfp_mask & __GFP_HIGH)
		alloc_flags |= ALLOC_HIGH;
	alloc_flags |= ALLOC_CPUSET;

	/*
	 * Go through the zonelist again. Let __GFP_HIGH and allocations
	 * coming from realtime tasks go deeper into reserves.
	 *
	 * This is the last chance, in general, before the goto nopage.
	 * Ignore cpuset if GFP_ATOMIC (!wait) rather than fail alloc.
	 * See also cpuset_zone_allowed() comment in kernel/cpuset.c.
	 */
	page = get_page_from_freelist(gfp_mask, order, zonelist, alloc_flags);
	if (page)
		goto got_pg;

	/* This allocation should allow future memory freeing. */

	if (((p->flags & PF_MEMALLOC) || unlikely(test_thread_flag(TIF_MEMDIE)))
			&& !in_interrupt()) {
		if (!(gfp_mask & __GFP_NOMEMALLOC)) {
nofail_alloc:
			/* go through the zonelist yet again, ignoring mins */
			page = get_page_from_freelist(gfp_mask, order,
				zonelist, ALLOC_NO_WATERMARKS);
			if (page)
				goto got_pg;
			if (gfp_mask & __GFP_NOFAIL) {
				blk_congestion_wait(WRITE, HZ/50);
				goto nofail_alloc;
			}
		}
		goto nopage;
	}

	/* Atomic allocations - we can't balance anything */
	if (!wait)
		goto nopage;

rebalance:
	cond_resched();

	/* We now go into synchronous reclaim */
	cpuset_memory_pressure_bump();
	p->flags |= PF_MEMALLOC;
	reclaim_state.reclaimed_slab = 0;
	p->reclaim_state = &reclaim_state;

	did_some_progress = try_to_free_pages(zonelist->zones, gfp_mask);

	p->reclaim_state = NULL;
	p->flags &= ~PF_MEMALLOC;

	cond_resched();

	if (likely(did_some_progress)) {
		page = get_page_from_freelist(gfp_mask, order,
						zonelist, alloc_flags);
		if (page)
			goto got_pg;
	} else if ((gfp_mask & __GFP_FS) && !(gfp_mask & __GFP_NORETRY)) {
		/*
		 * Go through the zonelist yet one more time, keep
		 * very high watermark here, this is only to catch
		 * a parallel oom killing, we must fail if we're still
		 * under heavy pressure.
		 */
		page = get_page_from_freelist(gfp_mask|__GFP_HARDWALL, order,
				zonelist, ALLOC_WMARK_HIGH|ALLOC_CPUSET);
		if (page)
			goto got_pg;

		out_of_memory(zonelist, gfp_mask, order);
		goto restart;
	}

	/*
	 * Don't let big-order allocations loop unless the caller explicitly
	 * requests that.  Wait for some write requests to complete then retry.
	 *
	 * In this implementation, __GFP_REPEAT means __GFP_NOFAIL for order
	 * <= 3, but that may not be true in other implementations.
	 */
	do_retry = 0;
	if (!(gfp_mask & __GFP_NORETRY)) {
		if ((order <= 3) || (gfp_mask & __GFP_REPEAT))
			do_retry = 1;
		if (gfp_mask & __GFP_NOFAIL)
			do_retry = 1;
	}
	if (do_retry) {
		blk_congestion_wait(WRITE, HZ/50);
		goto rebalance;
	}

nopage:
	if (!(gfp_mask & __GFP_NOWARN) && printk_ratelimit()) {
		printk(KERN_WARNING "%s: page allocation failure."
			" order:%d, mode:0x%x\n",
			p->comm, order, gfp_mask);
		dump_stack();
		show_mem();
	}
got_pg:
	return page;
}

EXPORT_SYMBOL(__alloc_pages);

/*
 * Common helper functions.
 */
fastcall unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order)
{
	struct page * page;
	page = alloc_pages(gfp_mask, order);
	if (!page)
		return 0;
	return (unsigned long) page_address(page);
}

EXPORT_SYMBOL(__get_free_pages);

fastcall unsigned long get_zeroed_page(gfp_t gfp_mask)
{
	struct page * page;

	/*
	 * get_zeroed_page() returns a 32-bit address, which cannot represent
	 * a highmem page
	 */
	BUG_ON((gfp_mask & __GFP_HIGHMEM) != 0);

	page = alloc_pages(gfp_mask | __GFP_ZERO, 0);
	if (page)
		return (unsigned long) page_address(page);
	return 0;
}

EXPORT_SYMBOL(get_zeroed_page);

void __pagevec_free(struct pagevec *pvec)
{
	int i = pagevec_count(pvec);

	PRINTK("pagevec page_count %d page %p count %d\n",
	       page_count(pvec->pages[i - 1]),
	       page_address(pvec->pages[i - 1]), i);
	if (use_np2) {
		np2_pagevec++;
		return;
	}

	while (--i >= 0)
		free_hot_cold_page(pvec->pages[i], pvec->cold);
}

fastcall void __free_pages(struct page *page, unsigned int order)
{
	struct zone *zone;
	unsigned long flags;
	int size = np2_get_size(order);

	if (use_np2) {
		put_page_testzero(page);
		/* manage np2 size */
		np2_clear_page_size(page, size, order);
		np2_num_frees++;
		if (use_np2) {
			zone = page_zone(page);
			spin_lock_irqsave(&zone->lock, flags);
			zone->free_pages += page->np2_size;
			if (page->np2_size > 0 /* 2 */ ) {
				list_add(&page->np2_list, &zone->np2_list);
			}
			if (PageCompound(page))
				destroy_compound_page(page, order);
			spin_unlock_irqrestore(&zone->lock, flags);
			return;
		}

		if (order == 0)
			free_hot_page(page);
		else
			__free_pages_ok(page, order);
	}
}

EXPORT_SYMBOL(__free_pages);

fastcall void free_pages(unsigned long addr, unsigned int order)
{
	if (addr != 0) {
		BUG_ON(!virt_addr_valid((void *)addr));
		__free_pages(virt_to_page((void *)addr), order);
	}
}

EXPORT_SYMBOL(free_pages);

/*
 * Total amount of free (allocatable) RAM:
 */
unsigned int nr_free_pages(void)
{
	unsigned int sum = 0;
	struct zone *zone;

	for_each_zone(zone)
		sum += zone->free_pages;

	return sum;
}

EXPORT_SYMBOL(nr_free_pages);

#ifdef CONFIG_NUMA
unsigned int nr_free_pages_pgdat(pg_data_t *pgdat)
{
	unsigned int i, sum = 0;

	for (i = 0; i < MAX_NR_ZONES; i++)
		sum += pgdat->node_zones[i].free_pages;

	return sum;
}
#endif

static unsigned int nr_free_zone_pages(int offset)
{
	/* Just pick one node, since fallback list is circular */
	pg_data_t *pgdat = NODE_DATA(numa_node_id());
	unsigned int sum = 0;

	struct zonelist *zonelist = pgdat->node_zonelists + offset;
	struct zone **zonep = zonelist->zones;
	struct zone *zone;

	for (zone = *zonep++; zone; zone = *zonep++) {
		unsigned long size = zone->present_pages;
		unsigned long high = zone->pages_high;
		if (size > high)
			sum += size - high;
	}

	return sum;
}

/*
 * Amount of free RAM allocatable within ZONE_DMA and ZONE_NORMAL
 */
unsigned int nr_free_buffer_pages(void)
{
	return nr_free_zone_pages(gfp_zone(GFP_USER));
}

/*
 * Amount of free RAM allocatable within all zones
 */
unsigned int nr_free_pagecache_pages(void)
{
	return nr_free_zone_pages(gfp_zone(GFP_HIGHUSER));
}

#ifdef CONFIG_HIGHMEM
unsigned int nr_free_highpages (void)
{
	pg_data_t *pgdat;
	unsigned int pages = 0;

	for_each_online_pgdat(pgdat)
		pages += pgdat->node_zones[ZONE_HIGHMEM].free_pages;

	return pages;
}
#endif

#ifdef CONFIG_NUMA
static void show_node(struct zone *zone)
{
	printk("Node %d ", zone->zone_pgdat->node_id);
}
#else
#define show_node(zone)	do { } while (0)
#endif

void si_meminfo(struct sysinfo *val)
{
	val->totalram = totalram_pages;
	val->sharedram = 0;
	val->freeram = nr_free_pages();
	val->bufferram = nr_blockdev_pages();
#ifdef CONFIG_HIGHMEM
	val->totalhigh = totalhigh_pages;
	val->freehigh = nr_free_highpages();
#else
	val->totalhigh = 0;
	val->freehigh = 0;
#endif
	val->mem_unit = PAGE_SIZE;
}

EXPORT_SYMBOL(si_meminfo);

#ifdef CONFIG_NUMA
void si_meminfo_node(struct sysinfo *val, int nid)
{
	pg_data_t *pgdat = NODE_DATA(nid);

	val->totalram = pgdat->node_present_pages;
	val->freeram = nr_free_pages_pgdat(pgdat);
	val->totalhigh = pgdat->node_zones[ZONE_HIGHMEM].present_pages;
	val->freehigh = pgdat->node_zones[ZONE_HIGHMEM].free_pages;
	val->mem_unit = PAGE_SIZE;
}
#endif

#define K(x) ((x) << (PAGE_SHIFT-10))

/*
 * Show free area list (used inside shift_scroll-lock stuff)
 * We also calculate the percentage fragmentation. We do this by counting the
 * memory on each free list with the exception of the first item on the list.
 */
void show_free_areas(void)
{
	int cpu, temperature;
	unsigned long active;
	unsigned long inactive;
	unsigned long free;
	struct zone *zone;

	for_each_zone(zone) {
		show_node(zone);
		printk("%s per-cpu:", zone->name);

		if (!populated_zone(zone)) {
			printk(" empty\n");
			continue;
		} else
			printk("\n");

		for_each_online_cpu(cpu) {
			struct per_cpu_pageset *pageset;

			pageset = zone_pcp(zone, cpu);

			for (temperature = 0; temperature < 2; temperature++)
				printk("cpu %d %s: high %d, batch %d used:%d\n",
					cpu,
					temperature ? "cold" : "hot",
					pageset->pcp[temperature].high,
					pageset->pcp[temperature].batch,
					pageset->pcp[temperature].count);
		}
	}

	get_zone_counts(&active, &inactive, &free);

	printk("Free pages: %11ukB (%ukB HighMem)\n",
		K(nr_free_pages()),
		K(nr_free_highpages()));

	printk("Active:%lu inactive:%lu dirty:%lu writeback:%lu "
		"unstable:%lu free:%u slab:%lu mapped:%lu pagetables:%lu\n",
		active,
		inactive,
		global_page_state(NR_FILE_DIRTY),
		global_page_state(NR_WRITEBACK),
		global_page_state(NR_UNSTABLE_NFS),
		nr_free_pages(),
		global_page_state(NR_SLAB),
		global_page_state(NR_FILE_MAPPED),
		global_page_state(NR_PAGETABLE));

	for_each_zone(zone) {
		int i;

		show_node(zone);
		printk("%s"
			" free:%lukB"
			" min:%lukB"
			" low:%lukB"
			" high:%lukB"
			" active:%lukB"
			" inactive:%lukB"
			" present:%lukB"
			" pages_scanned:%lu"
			" all_unreclaimable? %s"
			"\n",
			zone->name,
			K(zone->free_pages),
			K(zone->pages_min),
			K(zone->pages_low),
			K(zone->pages_high),
			K(zone->nr_active),
			K(zone->nr_inactive),
			K(zone->present_pages),
			zone->pages_scanned,
			(zone->all_unreclaimable ? "yes" : "no")
			);
		printk("lowmem_reserve[]:");
		for (i = 0; i < MAX_NR_ZONES; i++)
			printk(" %lu", zone->lowmem_reserve[i]);
		printk("\n");
	}

	for_each_zone(zone) {
 		unsigned long nr[MAX_ORDER], flags, order, total = 0;

		show_node(zone);
		printk("%s: ", zone->name);
		if (!populated_zone(zone)) {
			printk("empty\n");
			continue;
		}

		spin_lock_irqsave(&zone->lock, flags);
		for (order = 0; order < MAX_ORDER; order++) {
			nr[order] = zone->free_area[order].nr_free;
			total += nr[order] << order;
		}
		spin_unlock_irqrestore(&zone->lock, flags);
		for (order = 0; order < MAX_ORDER; order++)
			printk("%lu*%lukB ", nr[order], K(1UL) << order);
		printk("= %lukB\n", K(total));
	}

	show_swap_cache_info();
}

/*
 * Builds allocation fallback zone lists.
 *
 * Add all populated zones of a node to the zonelist.
 */
static int __meminit build_zonelists_node(pg_data_t *pgdat,
			struct zonelist *zonelist, int nr_zones, int zone_type)
{
	struct zone *zone;

	BUG_ON(zone_type > ZONE_HIGHMEM);

	do {
		zone = pgdat->node_zones + zone_type;
		if (populated_zone(zone)) {
#ifndef CONFIG_HIGHMEM
			BUG_ON(zone_type > ZONE_NORMAL);
#endif
			zonelist->zones[nr_zones++] = zone;
			check_highest_zone(zone_type);
		}
		zone_type--;

	} while (zone_type >= 0);
	return nr_zones;
}

static inline int highest_zone(int zone_bits)
{
	int res = ZONE_NORMAL;
	if (zone_bits & (__force int)__GFP_HIGHMEM)
		res = ZONE_HIGHMEM;
	if (zone_bits & (__force int)__GFP_DMA32)
		res = ZONE_DMA32;
	if (zone_bits & (__force int)__GFP_DMA)
		res = ZONE_DMA;
	return res;
}

#ifdef CONFIG_NUMA
#define MAX_NODE_LOAD (num_online_nodes())
static int __meminitdata node_load[MAX_NUMNODES];
/**
 * find_next_best_node - find the next node that should appear in a given node's fallback list
 * @node: node whose fallback list we're appending
 * @used_node_mask: nodemask_t of already used nodes
 *
 * We use a number of factors to determine which is the next node that should
 * appear on a given node's fallback list.  The node should not have appeared
 * already in @node's fallback list, and it should be the next closest node
 * according to the distance array (which contains arbitrary distance values
 * from each node to each node in the system), and should also prefer nodes
 * with no CPUs, since presumably they'll have very little allocation pressure
 * on them otherwise.
 * It returns -1 if no node is found.
 */
static int __meminit find_next_best_node(int node, nodemask_t *used_node_mask)
{
	int n, val;
	int min_val = INT_MAX;
	int best_node = -1;

	/* Use the local node if we haven't already */
	if (!node_isset(node, *used_node_mask)) {
		node_set(node, *used_node_mask);
		return node;
	}

	for_each_online_node(n) {
		cpumask_t tmp;

		/* Don't want a node to appear more than once */
		if (node_isset(n, *used_node_mask))
			continue;

		/* Use the distance array to find the distance */
		val = node_distance(node, n);

		/* Penalize nodes under us ("prefer the next node") */
		val += (n < node);

		/* Give preference to headless and unused nodes */
		tmp = node_to_cpumask(n);
		if (!cpus_empty(tmp))
			val += PENALTY_FOR_NODE_WITH_CPUS;

		/* Slight preference for less loaded node */
		val *= (MAX_NODE_LOAD*MAX_NUMNODES);
		val += node_load[n];

		if (val < min_val) {
			min_val = val;
			best_node = n;
		}
	}

	if (best_node >= 0)
		node_set(best_node, *used_node_mask);

	return best_node;
}

static void __meminit build_zonelists(pg_data_t *pgdat)
{
	int i, j, k, node, local_node;
	int prev_node, load;
	struct zonelist *zonelist;
	nodemask_t used_mask;

	/* initialize zonelists */
	for (i = 0; i < GFP_ZONETYPES; i++) {
		zonelist = pgdat->node_zonelists + i;
		zonelist->zones[0] = NULL;
	}

	/* NUMA-aware ordering of nodes */
	local_node = pgdat->node_id;
	load = num_online_nodes();
	prev_node = local_node;
	nodes_clear(used_mask);
	while ((node = find_next_best_node(local_node, &used_mask)) >= 0) {
		int distance = node_distance(local_node, node);

		/*
		 * If another node is sufficiently far away then it is better
		 * to reclaim pages in a zone before going off node.
		 */
		if (distance > RECLAIM_DISTANCE)
			zone_reclaim_mode = 1;

		/*
		 * We don't want to pressure a particular node.
		 * So adding penalty to the first node in same
		 * distance group to make it round-robin.
		 */

		if (distance != node_distance(local_node, prev_node))
			node_load[node] += load;
		prev_node = node;
		load--;
		for (i = 0; i < GFP_ZONETYPES; i++) {
			zonelist = pgdat->node_zonelists + i;
			for (j = 0; zonelist->zones[j] != NULL; j++);

			k = highest_zone(i);

	 		j = build_zonelists_node(NODE_DATA(node), zonelist, j, k);
			zonelist->zones[j] = NULL;
		}
	}
}

#else	/* CONFIG_NUMA */

static void __meminit build_zonelists(pg_data_t *pgdat)
{
	int i, j, k, node, local_node;

	local_node = pgdat->node_id;
	for (i = 0; i < GFP_ZONETYPES; i++) {
		struct zonelist *zonelist;

		zonelist = pgdat->node_zonelists + i;

		j = 0;
		k = highest_zone(i);
 		j = build_zonelists_node(pgdat, zonelist, j, k);
 		/*
 		 * Now we build the zonelist so that it contains the zones
 		 * of all the other nodes.
 		 * We don't want to pressure a particular node, so when
 		 * building the zones for node N, we make sure that the
 		 * zones coming right after the local ones are those from
 		 * node N+1 (modulo N)
 		 */
		for (node = local_node + 1; node < MAX_NUMNODES; node++) {
			if (!node_online(node))
				continue;
			j = build_zonelists_node(NODE_DATA(node), zonelist, j, k);
		}
		for (node = 0; node < local_node; node++) {
			if (!node_online(node))
				continue;
			j = build_zonelists_node(NODE_DATA(node), zonelist, j, k);
		}

		zonelist->zones[j] = NULL;
	}
}

#endif	/* CONFIG_NUMA */

/* return values int ....just for stop_machine_run() */
static int __meminit __build_all_zonelists(void *dummy)
{
	int nid;
	for_each_online_node(nid)
		build_zonelists(NODE_DATA(nid));
	return 0;
}

void __meminit build_all_zonelists(void)
{
	if (system_state == SYSTEM_BOOTING) {
		__build_all_zonelists(0);
		cpuset_init_current_mems_allowed();
	} else {
		/* we have to stop all cpus to guaranntee there is no user
		   of zonelist */
		stop_machine_run(__build_all_zonelists, NULL, NR_CPUS);
		/* cpuset refresh routine should be here */
	}
	vm_total_pages = nr_free_pagecache_pages();
	printk("Built %i zonelists.  Total pages: %ld\n",
			num_online_nodes(), vm_total_pages);
}

/*
 * Helper functions to size the waitqueue hash table.
 * Essentially these want to choose hash table sizes sufficiently
 * large so that collisions trying to wait on pages are rare.
 * But in fact, the number of active page waitqueues on typical
 * systems is ridiculously low, less than 200. So this is even
 * conservative, even though it seems large.
 *
 * The constant PAGES_PER_WAITQUEUE specifies the ratio of pages to
 * waitqueues, i.e. the size of the waitq table given the number of pages.
 */
#define PAGES_PER_WAITQUEUE	256

#ifndef CONFIG_MEMORY_HOTPLUG
static inline unsigned long wait_table_hash_nr_entries(unsigned long pages)
{
	unsigned long size = 1;

	pages /= PAGES_PER_WAITQUEUE;

	while (size < pages)
		size <<= 1;

	/*
	 * Once we have dozens or even hundreds of threads sleeping
	 * on IO we've got bigger problems than wait queue collision.
	 * Limit the size of the wait table to a reasonable size.
	 */
	size = min(size, 4096UL);

	return max(size, 4UL);
}
#else
/*
 * A zone's size might be changed by hot-add, so it is not possible to determine
 * a suitable size for its wait_table.  So we use the maximum size now.
 *
 * The max wait table size = 4096 x sizeof(wait_queue_head_t).   ie:
 *
 *    i386 (preemption config)    : 4096 x 16 = 64Kbyte.
 *    ia64, x86-64 (no preemption): 4096 x 20 = 80Kbyte.
 *    ia64, x86-64 (preemption)   : 4096 x 24 = 96Kbyte.
 *
 * The maximum entries are prepared when a zone's memory is (512K + 256) pages
 * or more by the traditional way. (See above).  It equals:
 *
 *    i386, x86-64, powerpc(4K page size) : =  ( 2G + 1M)byte.
 *    ia64(16K page size)                 : =  ( 8G + 4M)byte.
 *    powerpc (64K page size)             : =  (32G +16M)byte.
 */
static inline unsigned long wait_table_hash_nr_entries(unsigned long pages)
{
	return 4096UL;
}
#endif

/*
 * This is an integer logarithm so that shifts can be used later
 * to extract the more random high bits from the multiplicative
 * hash function before the remainder is taken.
 */
static inline unsigned long wait_table_bits(unsigned long size)
{
	return ffz(~size);
}

#define LONG_ALIGN(x) (((x)+(sizeof(long))-1)&~((sizeof(long))-1))

static void __init calculate_zone_totalpages(struct pglist_data *pgdat,
		unsigned long *zones_size, unsigned long *zholes_size)
{
	unsigned long realtotalpages, totalpages = 0;
	int i;

	for (i = 0; i < MAX_NR_ZONES; i++)
		totalpages += zones_size[i];
	pgdat->node_spanned_pages = totalpages;

	realtotalpages = totalpages;
	if (zholes_size)
		for (i = 0; i < MAX_NR_ZONES; i++)
			realtotalpages -= zholes_size[i];
	pgdat->node_present_pages = realtotalpages;
	printk(KERN_DEBUG "On node %d totalpages: %lu\n", pgdat->node_id, realtotalpages);
}


/*
 * Initially all pages are reserved - free ones are freed
 * up by free_all_bootmem() once the early boot process is
 * done. Non-atomic initialization, single-pass.
 */
void __meminit memmap_init_zone(unsigned long size, int nid, unsigned long zone,
		unsigned long start_pfn)
{
	struct page *page;
	unsigned long end_pfn = start_pfn + size;
	unsigned long pfn;

	for (pfn = start_pfn; pfn < end_pfn; pfn++) {
		if (!early_pfn_valid(pfn))
			continue;
		page = pfn_to_page(pfn);
		set_page_links(page, zone, nid, pfn);
		init_page_count(page);
		reset_page_mapcount(page);
		SetPageReserved(page);
		INIT_LIST_HEAD(&page->lru);
#ifdef WANT_PAGE_VIRTUAL
		/* The shift won't overflow because ZONE_NORMAL is below 4G. */
		if (!is_highmem_idx(zone))
			set_page_address(page, __va(pfn << PAGE_SHIFT));
#endif
	}
}

void zone_init_free_lists(struct pglist_data *pgdat, struct zone *zone,
				unsigned long size)
{
	int order;
	for (order = 0; order < MAX_ORDER ; order++) {
		INIT_LIST_HEAD(&zone->free_area[order].free_list);
		zone->free_area[order].nr_free = 0;
	}
	zone->np2_minpfn = 0;
}

#define ZONETABLE_INDEX(x, zone_nr)	((x << ZONES_SHIFT) | zone_nr)
void zonetable_add(struct zone *zone, int nid, int zid, unsigned long pfn,
		unsigned long size)
{
	unsigned long snum = pfn_to_section_nr(pfn);
	unsigned long end = pfn_to_section_nr(pfn + size);

	if (FLAGS_HAS_NODE)
		zone_table[ZONETABLE_INDEX(nid, zid)] = zone;
	else
		for (; snum <= end; snum++)
			zone_table[ZONETABLE_INDEX(snum, zid)] = zone;
}

#ifndef __HAVE_ARCH_MEMMAP_INIT
#define memmap_init(size, nid, zone, start_pfn) \
	memmap_init_zone((size), (nid), (zone), (start_pfn))
#endif

static int __cpuinit zone_batchsize(struct zone *zone)
{
	int batch;

	/*
	 * The per-cpu-pages pools are set to around 1000th of the
	 * size of the zone.  But no more than 1/2 of a meg.
	 *
	 * OK, so we don't know how big the cache is.  So guess.
	 */
	batch = zone->present_pages / 1024;
	if (batch * PAGE_SIZE > 512 * 1024)
		batch = (512 * 1024) / PAGE_SIZE;
	batch /= 4;		/* We effectively *= 4 below */
	if (batch < 1)
		batch = 1;

	/*
	 * Clamp the batch to a 2^n - 1 value. Having a power
	 * of 2 value was found to be more likely to have
	 * suboptimal cache aliasing properties in some cases.
	 *
	 * For example if 2 tasks are alternately allocating
	 * batches of pages, one task can end up with a lot
	 * of pages of one half of the possible page colors
	 * and the other with pages of the other colors.
	 */
	batch = (1 << (fls(batch + batch/2)-1)) - 1;

	return batch;
}

inline void setup_pageset(struct per_cpu_pageset *p, unsigned long batch)
{
	struct per_cpu_pages *pcp;

	memset(p, 0, sizeof(*p));

	pcp = &p->pcp[0];		/* hot */
	pcp->count = 0;
	pcp->high = 6 * batch;
	pcp->batch = max(1UL, 1 * batch);
	INIT_LIST_HEAD(&pcp->list);

	pcp = &p->pcp[1];		/* cold*/
	pcp->count = 0;
	pcp->high = 2 * batch;
	pcp->batch = max(1UL, batch/2);
	INIT_LIST_HEAD(&pcp->list);
}

/*
 * setup_pagelist_highmark() sets the high water mark for hot per_cpu_pagelist
 * to the value high for the pageset p.
 */

static void setup_pagelist_highmark(struct per_cpu_pageset *p,
				unsigned long high)
{
	struct per_cpu_pages *pcp;

	pcp = &p->pcp[0]; /* hot list */
	pcp->high = high;
	pcp->batch = max(1UL, high/4);
	if ((high/4) > (PAGE_SHIFT * 8))
		pcp->batch = PAGE_SHIFT * 8;
}


#ifdef CONFIG_NUMA
/*
 * Boot pageset table. One per cpu which is going to be used for all
 * zones and all nodes. The parameters will be set in such a way
 * that an item put on a list will immediately be handed over to
 * the buddy list. This is safe since pageset manipulation is done
 * with interrupts disabled.
 *
 * Some NUMA counter updates may also be caught by the boot pagesets.
 *
 * The boot_pagesets must be kept even after bootup is complete for
 * unused processors and/or zones. They do play a role for bootstrapping
 * hotplugged processors.
 *
 * zoneinfo_show() and maybe other functions do
 * not check if the processor is online before following the pageset pointer.
 * Other parts of the kernel may not check if the zone is available.
 */
static struct per_cpu_pageset boot_pageset[NR_CPUS];

/*
 * Dynamically allocate memory for the
 * per cpu pageset array in struct zone.
 */
static int __cpuinit process_zones(int cpu)
{
	struct zone *zone, *dzone;

	for_each_zone(zone) {

		zone_pcp(zone, cpu) = kmalloc_node(sizeof(struct per_cpu_pageset),
					 GFP_KERNEL, cpu_to_node(cpu));
		if (!zone_pcp(zone, cpu))
			goto bad;

		setup_pageset(zone_pcp(zone, cpu), zone_batchsize(zone));

		if (percpu_pagelist_fraction)
			setup_pagelist_highmark(zone_pcp(zone, cpu),
			 	(zone->present_pages / percpu_pagelist_fraction));
	}

	return 0;
bad:
	for_each_zone(dzone) {
		if (dzone == zone)
			break;
		kfree(zone_pcp(dzone, cpu));
		zone_pcp(dzone, cpu) = NULL;
	}
	return -ENOMEM;
}

static inline void free_zone_pagesets(int cpu)
{
	struct zone *zone;

	for_each_zone(zone) {
		struct per_cpu_pageset *pset = zone_pcp(zone, cpu);

		zone_pcp(zone, cpu) = NULL;
		kfree(pset);
	}
}

static int __cpuinit pageset_cpuup_callback(struct notifier_block *nfb,
		unsigned long action,
		void *hcpu)
{
	int cpu = (long)hcpu;
	int ret = NOTIFY_OK;

	switch (action) {
		case CPU_UP_PREPARE:
			if (process_zones(cpu))
				ret = NOTIFY_BAD;
			break;
		case CPU_UP_CANCELED:
		case CPU_DEAD:
			free_zone_pagesets(cpu);
			break;
		default:
			break;
	}
	return ret;
}

static struct notifier_block __cpuinitdata pageset_notifier =
	{ &pageset_cpuup_callback, NULL, 0 };

void __init setup_per_cpu_pageset(void)
{
	int err;

	/* Initialize per_cpu_pageset for cpu 0.
	 * A cpuup callback will do this for every cpu
	 * as it comes online
	 */
	err = process_zones(smp_processor_id());
	BUG_ON(err);
	register_cpu_notifier(&pageset_notifier);
}

#endif

static __meminit
int zone_wait_table_init(struct zone *zone, unsigned long zone_size_pages)
{
	int i;
	struct pglist_data *pgdat = zone->zone_pgdat;
	size_t alloc_size;

	/*
	 * The per-page waitqueue mechanism uses hashed waitqueues
	 * per zone.
	 */
	zone->wait_table_hash_nr_entries =
		 wait_table_hash_nr_entries(zone_size_pages);
	zone->wait_table_bits =
		wait_table_bits(zone->wait_table_hash_nr_entries);
	alloc_size = zone->wait_table_hash_nr_entries
					* sizeof(wait_queue_head_t);

 	if (system_state == SYSTEM_BOOTING) {
		zone->wait_table = (wait_queue_head_t *)
			alloc_bootmem_node(pgdat, alloc_size);
	} else {
		/*
		 * This case means that a zone whose size was 0 gets new memory
		 * via memory hot-add.
		 * But it may be the case that a new node was hot-added.  In
		 * this case vmalloc() will not be able to use this new node's
		 * memory - this wait_table must be initialized to use this new
		 * node itself as well.
		 * To use this new node's memory, further consideration will be
		 * necessary.
		 */
		zone->wait_table = (wait_queue_head_t *)vmalloc(alloc_size);
	}
	if (!zone->wait_table)
		return -ENOMEM;

	for(i = 0; i < zone->wait_table_hash_nr_entries; ++i)
		init_waitqueue_head(zone->wait_table + i);

	return 0;
}

static __meminit void zone_pcp_init(struct zone *zone)
{
	int cpu;
	unsigned long batch = zone_batchsize(zone);

	for (cpu = 0; cpu < NR_CPUS; cpu++) {
#ifdef CONFIG_NUMA
		/* Early boot. Slab allocator not functional yet */
		zone_pcp(zone, cpu) = &boot_pageset[cpu];
		setup_pageset(&boot_pageset[cpu],0);
#else
		setup_pageset(zone_pcp(zone,cpu), batch);
#endif
	}
	if (zone->present_pages)
		printk(KERN_DEBUG "  %s zone: %lu pages, LIFO batch:%lu\n",
			zone->name, zone->present_pages, batch);
}

__meminit int init_currently_empty_zone(struct zone *zone,
					unsigned long zone_start_pfn,
					unsigned long size)
{
	struct pglist_data *pgdat = zone->zone_pgdat;
	int ret;
	ret = zone_wait_table_init(zone, size);
	if (ret)
		return ret;
	pgdat->nr_zones = zone_idx(zone) + 1;

	zone->zone_start_pfn = zone_start_pfn;

	memmap_init(size, pgdat->node_id, zone_idx(zone), zone_start_pfn);

	zone_init_free_lists(pgdat, zone, zone->spanned_pages);

	return 0;
}

/*
 * Set up the zone data structures:
 *   - mark all pages reserved
 *   - mark all memory queues empty
 *   - clear the memory bitmaps
 */
static void __meminit free_area_init_core(struct pglist_data *pgdat,
		unsigned long *zones_size, unsigned long *zholes_size)
{
	unsigned long j;
	int nid = pgdat->node_id;
	unsigned long zone_start_pfn = pgdat->node_start_pfn;
	int ret;

	pgdat_resize_init(pgdat);
	pgdat->nr_zones = 0;
	init_waitqueue_head(&pgdat->kswapd_wait);
	pgdat->kswapd_max_order = 0;

	for (j = 0; j < MAX_NR_ZONES; j++) {
		struct zone *zone = pgdat->node_zones + j;
		unsigned long size, realsize;

		realsize = size = zones_size[j];
		if (zholes_size)
			realsize -= zholes_size[j];

		if (j < ZONE_HIGHMEM)
			nr_kernel_pages += realsize;
		nr_all_pages += realsize;

		zone->spanned_pages = size;
		zone->present_pages = realsize;
#ifdef CONFIG_NUMA
		zone->min_unmapped_ratio = (realsize*sysctl_min_unmapped_ratio)
						/ 100;
#endif
		zone->name = zone_names[j];
		spin_lock_init(&zone->lock);
		spin_lock_init(&zone->lru_lock);
		zone_seqlock_init(zone);
		zone->zone_pgdat = pgdat;
		zone->free_pages = 0;

		zone->temp_priority = zone->prev_priority = DEF_PRIORITY;

		zone_pcp_init(zone);
		INIT_LIST_HEAD(&zone->active_list);
		INIT_LIST_HEAD(&zone->inactive_list);
		INIT_LIST_HEAD(&zone->np2_list);
		zone->nr_scan_active = 0;
		zone->nr_scan_inactive = 0;
		zone->nr_active = 0;
		zone->nr_inactive = 0;
		zap_zone_vm_stats(zone);
		atomic_set(&zone->reclaim_in_progress, 0);
		if (!size)
			continue;

		zonetable_add(zone, nid, j, zone_start_pfn, size);
		ret = init_currently_empty_zone(zone, zone_start_pfn, size);
		BUG_ON(ret);
		zone_start_pfn += size;
	}
}

static void __init alloc_node_mem_map(struct pglist_data *pgdat)
{
	/* Skip empty nodes */
	if (!pgdat->node_spanned_pages)
		return;

#ifdef CONFIG_FLAT_NODE_MEM_MAP
	/* ia64 gets its own node_mem_map, before this, without bootmem */
	if (!pgdat->node_mem_map) {
		unsigned long size, start, end;
		struct page *map;

		/*
		 * The zone's endpoints aren't required to be MAX_ORDER
		 * aligned but the node_mem_map endpoints must be in order
		 * for the buddy allocator to function correctly.
		 */
		start = pgdat->node_start_pfn & ~(MAX_ORDER_NR_PAGES - 1);
		end = pgdat->node_start_pfn + pgdat->node_spanned_pages;
		end = ALIGN(end, MAX_ORDER_NR_PAGES);
		size =  (end - start) * sizeof(struct page);
		map = alloc_remap(pgdat->node_id, size);
		if (!map)
			map = alloc_bootmem_node(pgdat, size);
		pgdat->node_mem_map = map + (pgdat->node_start_pfn - start);
	}
#ifdef CONFIG_FLATMEM
	/*
	 * With no DISCONTIG, the global mem_map is just set as node 0's
	 */
	if (pgdat == NODE_DATA(0))
		mem_map = NODE_DATA(0)->node_mem_map;
#endif
#endif /* CONFIG_FLAT_NODE_MEM_MAP */
}

void __meminit free_area_init_node(int nid, struct pglist_data *pgdat,
		unsigned long *zones_size, unsigned long node_start_pfn,
		unsigned long *zholes_size)
{
	pgdat->node_id = nid;
	pgdat->node_start_pfn = node_start_pfn;
	calculate_zone_totalpages(pgdat, zones_size, zholes_size);

	alloc_node_mem_map(pgdat);

	free_area_init_core(pgdat, zones_size, zholes_size);
}

#ifndef CONFIG_NEED_MULTIPLE_NODES
static bootmem_data_t contig_bootmem_data;
struct pglist_data contig_page_data = { .bdata = &contig_bootmem_data };

EXPORT_SYMBOL(contig_page_data);
#endif

void __init free_area_init(unsigned long *zones_size)
{
	free_area_init_node(0, NODE_DATA(0), zones_size,
			__pa(PAGE_OFFSET) >> PAGE_SHIFT, NULL);
}

#ifdef CONFIG_HOTPLUG_CPU
static int page_alloc_cpu_notify(struct notifier_block *self,
				 unsigned long action, void *hcpu)
{
	int cpu = (unsigned long)hcpu;

	if (action == CPU_DEAD) {
		local_irq_disable();
		__drain_pages(cpu);
		vm_events_fold_cpu(cpu);
		local_irq_enable();
		refresh_cpu_vm_stats(cpu);
	}
	return NOTIFY_OK;
}
#endif /* CONFIG_HOTPLUG_CPU */

void __init page_alloc_init(void)
{
	hotcpu_notifier(page_alloc_cpu_notify, 0);
}

/*
 * calculate_totalreserve_pages - called when sysctl_lower_zone_reserve_ratio
 *	or min_free_kbytes changes.
 */
static void calculate_totalreserve_pages(void)
{
	struct pglist_data *pgdat;
	unsigned long reserve_pages = 0;
	int i, j;

	for_each_online_pgdat(pgdat) {
		for (i = 0; i < MAX_NR_ZONES; i++) {
			struct zone *zone = pgdat->node_zones + i;
			unsigned long max = 0;

			/* Find valid and maximum lowmem_reserve in the zone */
			for (j = i; j < MAX_NR_ZONES; j++) {
				if (zone->lowmem_reserve[j] > max)
					max = zone->lowmem_reserve[j];
			}

			/* we treat pages_high as reserved pages. */
			max += zone->pages_high;

			if (max > zone->present_pages)
				max = zone->present_pages;
			reserve_pages += max;
		}
	}
	totalreserve_pages = reserve_pages;
}

/*
 * setup_per_zone_lowmem_reserve - called whenever
 *	sysctl_lower_zone_reserve_ratio changes.  Ensures that each zone
 *	has a correct pages reserved value, so an adequate number of
 *	pages are left in the zone after a successful __alloc_pages().
 */
static void setup_per_zone_lowmem_reserve(void)
{
	struct pglist_data *pgdat;
	int j, idx;

	for_each_online_pgdat(pgdat) {
		for (j = 0; j < MAX_NR_ZONES; j++) {
			struct zone *zone = pgdat->node_zones + j;
			unsigned long present_pages = zone->present_pages;

			zone->lowmem_reserve[j] = 0;

			for (idx = j-1; idx >= 0; idx--) {
				struct zone *lower_zone;

				if (sysctl_lowmem_reserve_ratio[idx] < 1)
					sysctl_lowmem_reserve_ratio[idx] = 1;

				lower_zone = pgdat->node_zones + idx;
				lower_zone->lowmem_reserve[j] = present_pages /
					sysctl_lowmem_reserve_ratio[idx];
				present_pages += lower_zone->present_pages;
			}
		}
	}

	/* update totalreserve_pages */
	calculate_totalreserve_pages();
}

/*
 * setup_per_zone_pages_min - called when min_free_kbytes changes.  Ensures 
 *	that the pages_{min,low,high} values for each zone are set correctly 
 *	with respect to min_free_kbytes.
 */
void setup_per_zone_pages_min(void)
{
	unsigned long pages_min = min_free_kbytes >> (PAGE_SHIFT - 10);
	unsigned long lowmem_pages = 0;
	struct zone *zone;
	unsigned long flags;

	/* Calculate total number of !ZONE_HIGHMEM pages */
	for_each_zone(zone) {
		if (!is_highmem(zone))
			lowmem_pages += zone->present_pages;
	}

	for_each_zone(zone) {
		u64 tmp;

		spin_lock_irqsave(&zone->lru_lock, flags);
		tmp = (u64)pages_min * zone->present_pages;
		do_div(tmp, lowmem_pages);
		if (is_highmem(zone)) {
			/*
			 * __GFP_HIGH and PF_MEMALLOC allocations usually don't
			 * need highmem pages, so cap pages_min to a small
			 * value here.
			 *
			 * The (pages_high-pages_low) and (pages_low-pages_min)
			 * deltas controls asynch page reclaim, and so should
			 * not be capped for highmem.
			 */
			int min_pages;

			min_pages = zone->present_pages / 1024;
			if (min_pages < SWAP_CLUSTER_MAX)
				min_pages = SWAP_CLUSTER_MAX;
			if (min_pages > 128)
				min_pages = 128;
			zone->pages_min = min_pages;
		} else {
			/*
			 * If it's a lowmem zone, reserve a number of pages
			 * proportionate to the zone's size.
			 */
			zone->pages_min = tmp;
		}

		zone->pages_low   = zone->pages_min + (tmp >> 2);
		zone->pages_high  = zone->pages_min + (tmp >> 1);
		spin_unlock_irqrestore(&zone->lru_lock, flags);
	}

	/* update totalreserve_pages */
	calculate_totalreserve_pages();
}

/*
 * Initialise min_free_kbytes.
 *
 * For small machines we want it small (128k min).  For large machines
 * we want it large (64MB max).  But it is not linear, because network
 * bandwidth does not increase linearly with machine size.  We use
 *
 * 	min_free_kbytes = 4 * sqrt(lowmem_kbytes), for better accuracy:
 *	min_free_kbytes = sqrt(lowmem_kbytes * 16)
 *
 * which yields
 *
 * 16MB:	512k
 * 32MB:	724k
 * 64MB:	1024k
 * 128MB:	1448k
 * 256MB:	2048k
 * 512MB:	2896k
 * 1024MB:	4096k
 * 2048MB:	5792k
 * 4096MB:	8192k
 * 8192MB:	11584k
 * 16384MB:	16384k
 */
static int __init init_per_zone_pages_min(void)
{
	unsigned long lowmem_kbytes;

	lowmem_kbytes = nr_free_buffer_pages() * (PAGE_SIZE >> 10);

	min_free_kbytes = int_sqrt(lowmem_kbytes * 16);
	if (min_free_kbytes < 128)
		min_free_kbytes = 128;
	if (min_free_kbytes > 65536)
		min_free_kbytes = 65536;
	setup_per_zone_pages_min();
	setup_per_zone_lowmem_reserve();
	return 0;
}
module_init(init_per_zone_pages_min)

/*
 * min_free_kbytes_sysctl_handler - just a wrapper around proc_dointvec() so 
 *	that we can call two helper functions whenever min_free_kbytes
 *	changes.
 */
int min_free_kbytes_sysctl_handler(ctl_table *table, int write, 
	struct file *file, void __user *buffer, size_t *length, loff_t *ppos)
{
	proc_dointvec(table, write, file, buffer, length, ppos);
	setup_per_zone_pages_min();
	return 0;
}

#ifdef CONFIG_NUMA
int sysctl_min_unmapped_ratio_sysctl_handler(ctl_table *table, int write,
	struct file *file, void __user *buffer, size_t *length, loff_t *ppos)
{
	struct zone *zone;
	int rc;

	rc = proc_dointvec_minmax(table, write, file, buffer, length, ppos);
	if (rc)
		return rc;

	for_each_zone(zone)
		zone->min_unmapped_ratio = (zone->present_pages *
				sysctl_min_unmapped_ratio) / 100;
	return 0;
}
#endif

/*
 * lowmem_reserve_ratio_sysctl_handler - just a wrapper around
 *	proc_dointvec() so that we can call setup_per_zone_lowmem_reserve()
 *	whenever sysctl_lowmem_reserve_ratio changes.
 *
 * The reserve ratio obviously has absolutely no relation with the
 * pages_min watermarks. The lowmem reserve ratio can only make sense
 * if in function of the boot time zone sizes.
 */
int lowmem_reserve_ratio_sysctl_handler(ctl_table *table, int write,
	struct file *file, void __user *buffer, size_t *length, loff_t *ppos)
{
	proc_dointvec_minmax(table, write, file, buffer, length, ppos);
	setup_per_zone_lowmem_reserve();
	return 0;
}

/*
 * percpu_pagelist_fraction - changes the pcp->high for each zone on each
 * cpu.  It is the fraction of total pages in each zone that a hot per cpu pagelist
 * can have before it gets flushed back to buddy allocator.
 */

int percpu_pagelist_fraction_sysctl_handler(ctl_table *table, int write,
	struct file *file, void __user *buffer, size_t *length, loff_t *ppos)
{
	struct zone *zone;
	unsigned int cpu;
	int ret;

	ret = proc_dointvec_minmax(table, write, file, buffer, length, ppos);
	if (!write || (ret == -EINVAL))
		return ret;
	for_each_zone(zone) {
		for_each_online_cpu(cpu) {
			unsigned long  high;
			high = zone->present_pages / percpu_pagelist_fraction;
			setup_pagelist_highmark(zone_pcp(zone, cpu), high);
		}
	}
	return 0;
}

__initdata int hashdist = HASHDIST_DEFAULT;

#ifdef CONFIG_NUMA
static int __init set_hashdist(char *str)
{
	if (!str)
		return 0;
	hashdist = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("hashdist=", set_hashdist);
#endif

/*
 * allocate a large system hash table from bootmem
 * - it is assumed that the hash table must contain an exact power-of-2
 *   quantity of entries
 * - limit is the number of hash buckets, not the total allocation size
 */
void *__init alloc_large_system_hash(const char *tablename,
				     unsigned long bucketsize,
				     unsigned long numentries,
				     int scale,
				     int flags,
				     unsigned int *_hash_shift,
				     unsigned int *_hash_mask,
				     unsigned long limit)
{
	unsigned long long max = limit;
	unsigned long log2qty, size;
	void *table = NULL;

	/* allow the kernel cmdline to have a say */
	if (!numentries) {
		/* round applicable memory size up to nearest megabyte */
		numentries = (flags & HASH_HIGHMEM) ? nr_all_pages : nr_kernel_pages;
		numentries += (1UL << (20 - PAGE_SHIFT)) - 1;
		numentries >>= 20 - PAGE_SHIFT;
		numentries <<= 20 - PAGE_SHIFT;

		/* limit to 1 bucket per 2^scale bytes of low memory */
		if (scale > PAGE_SHIFT)
			numentries >>= (scale - PAGE_SHIFT);
		else
			numentries <<= (PAGE_SHIFT - scale);
	}
	numentries = roundup_pow_of_two(numentries);

	/* limit allocation size to 1/16 total memory by default */
	if (max == 0) {
		max = ((unsigned long long)nr_all_pages << PAGE_SHIFT) >> 4;
		do_div(max, bucketsize);
	}

	if (numentries > max)
		numentries = max;

	log2qty = long_log2(numentries);

	do {
		size = bucketsize << log2qty;
		if (flags & HASH_EARLY)
			table = alloc_bootmem(size);
		else if (hashdist)
			table = __vmalloc(size, GFP_ATOMIC, PAGE_KERNEL);
		else {
			unsigned long order;
			for (order = 0; ((1UL << order) << PAGE_SHIFT) < size; order++)
				;
			table = (void*) __get_free_pages(GFP_ATOMIC, order);
		}
	} while (!table && size > PAGE_SIZE && --log2qty);

	if (!table)
		panic("Failed to allocate %s hash table\n", tablename);

	printk("%s hash table entries: %d (order: %d, %lu bytes)\n",
	       tablename,
	       (1U << log2qty),
	       long_log2(size) - PAGE_SHIFT,
	       size);

	if (_hash_shift)
		*_hash_shift = log2qty;
	if (_hash_mask)
		*_hash_mask = (1 << log2qty) - 1;

	return table;
}

#ifdef CONFIG_OUT_OF_LINE_PFN_TO_PAGE
struct page *pfn_to_page(unsigned long pfn)
{
	return __pfn_to_page(pfn);
}
unsigned long page_to_pfn(struct page *page)
{
	return __page_to_pfn(page);
}
EXPORT_SYMBOL(pfn_to_page);
EXPORT_SYMBOL(page_to_pfn);
#endif /* CONFIG_OUT_OF_LINE_PFN_TO_PAGE */
