/* cacheflush.h: blackfin low-level cache routines
 * adapted from the i386 and PPC versions by Greg Ungerer (gerg@snapgear.com)
 *
 * Copyright (C) 2002  David Howells (dhowells@redhat.com)
 * Copyright (C) 2004  LG Soft India
 * - Incorporating the cache flush routines.
 */

#ifndef _BFINNOMMU_CACHEFLUSH_H
#define _BFINNOMMU_CACHEFLUSH_H

#include <asm/cplb.h>

extern void flush_instruction_cache(void);
extern void blackfin_icache_flush_range(unsigned int, unsigned int);
extern void blackfin_dcache_flush_range(unsigned int, unsigned int);
extern void blackfin_dcache_invalidate_range(unsigned int, unsigned int);
extern void blackfin_dflush_page(void *);
extern void flush_data_cache(void);

#define flush_cache_mm(mm)			do { } while (0)
#define flush_cache_range(vma, start, end)	do { } while (0)
#define flush_cache_page(vma, vmaddr)		do { } while (0)
#define flush_cache_vmap(start, end)		do { } while (0)
#define flush_cache_vunmap(start, end)		do { } while (0)

static inline void flush_icache_range(unsigned start, unsigned end)
{
#if defined( CONFIG_BLKFIN_DCACHE ) && defined( CONFIG_BLKFIN_WB )
	blackfin_dcache_flush_range((start), (end));
#endif
#if defined( CONFIG_BLKFIN_CACHE )
	blackfin_icache_flush_range((start), (end));
#endif
}

#define copy_to_user_page(vma, page, vaddr, dst, src, len)	memcpy(dst, src, len)
#define copy_from_user_page(vma, page, vaddr, dst, src, len)	memcpy(dst, src, len)

#if defined( CONFIG_BLKFIN_DCACHE )
	#define invalidate_dcache_range(start,end)	blackfin_dcache_invalidate_range((start), (end))
#else
	#define invalidate_dcache_range(start,end)	do { } while (0)
#endif
#if defined( CONFIG_BLKFIN_DCACHE ) && defined( CONFIG_BLKFIN_WB )
#	define flush_dcache_range(start,end)		blackfin_dcache_flush_range((start), (end))
#	define flush_dcache_page(page)			blackfin_dflush_page(page_address(page))
#else
#	define flush_dcache_range(start,end)		do { } while (0)
#	define flush_dcache_page(page)			do { } while (0)
#endif

static inline void flush_cache_all(void)
{
#ifdef CONFIG_BLKFIN_CACHE
	flush_instruction_cache();
#endif
#ifdef CONFIG_BLKFIN_DCACHE
	flush_data_cache();
#endif
}

#endif /* _BFINNOMMU_CACHEFLUSH_H */
