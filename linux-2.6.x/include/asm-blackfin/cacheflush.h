/* cacheflush.h: blackfin low-level cache routines
 * adapted from the i386 and PPC versions by Greg Ungerer (gerg@snapgear.com)
 *
 * Copyright (C) 2002  David Howells (dhowells@redhat.com)
 * Copyright (C) 2004  LG Soft India
 * - Incorporating the cache flush routines. 
 */

#ifndef _BFINNOMMU_CACHEFLUSH_H
#define _BFINNOMMU_CACHEFLUSH_H

#include <linux/mm.h>
#include <asm/cplb.h>

extern void blackfin_icache_flush_range(unsigned int start, unsigned int end);
extern void blackfin_dcache_flush_range(unsigned int start, unsigned int end);
extern void blackfin_dcache_invalidate_range(unsigned int start, unsigned int end);

#define flush_cache_all()			__flush_cache_all()

#define flush_cache_mm(mm)			\
	do {					\
						\
		if((mm) == current->active_mm)	\
			flush_cache_all();	\
	} while (0)			

/* This is applicable for VM system */
#define flush_cache_range(vma, start, end)	\
	do { 					\
		if((vma) == current->mm)	\
			flush_cache_all();	\
	} while (0)

#define flush_cache_page(vma, vmaddr)		\
	do { 					\
		if (vma->vm_mm == current->mm)	\
			flush_cache_all();	\
	} while (0)

static inline void flush_icache_range(unsigned start, unsigned end)
{
#if defined( CONFIG_BLKFIN_DCACHE ) && defined( CONFIG_BLKFIN_WB )
blackfin_dcache_flush_range((start), (end));
#endif
#if defined( CONFIG_BLKFIN_CACHE )
blackfin_icache_flush_range((start), (end));
#endif
}
#define flush_icache_page(vma,pg)		do { } while (0)
#define flush_icache_user_range(vma,pg,adr,len)	do { } while (0)
#define flush_cache_vmap(start, end)		flush_cache_all()
#define flush_cache_vunmap(start, end)		flush_cache_all()

#define copy_to_user_page(vma, page, vaddr, dst, src, len) \
	memcpy(dst, src, len)
#define copy_from_user_page(vma, page, vaddr, dst, src, len) \
	memcpy(dst, src, len)

extern void blackfin_dflush_page(void *addr);

#define invalidate_dcache_range(start,end)\
blackfin_dcache_invalidate_range((start), (end))
#define flush_dcache_range(start,end)\
blackfin_dcache_flush_range((start), (end))

#define flush_dcache_page(page) blackfin_dflush_page(page_address(page))

extern void  flush_instruction_cache(void);
extern void  flush_data_cache(void);

extern inline void __flush_cache_all(void)
{
	/* Flush all the pending writes in the data 
	 * cache associated with a particular DCPLB, Working !! 
  	 */
#ifdef CONFIG_BLKFIN_CACHE 
	/*
	flush_instruction_cache();
	*/
#endif
	/* Flush all the pending writes in the instruction
	 * cache associated with a particular ICPLB, Working !! 
  	 */
#ifdef CONFIG_BLKFIN_DCACHE 
	/*FIXME
	flush_data_cache();
	*/
#endif
}

#endif /* _BFINNOMMU_CACHEFLUSH_H */
