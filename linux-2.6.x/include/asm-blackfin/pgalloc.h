#ifndef _BFINNOMMU_PGALLOC_H
#define _BFINNOMMU_PGALLOC_H

/*
 * Copyright (C) 2000 Lineo, David McCullough <davidm@lineo.com>
 */

#include <asm/setup.h>
#include <asm/io.h> 


#define check_pgt_cache()	do { } while (0)


/*
 * Cache handling functions
 */

#if DAVIDM
/*
 * invalidate the cache for the specified memory range.
 * It starts at the physical address specified for
 * the given number of bytes.
 */
extern void cache_clear(unsigned long paddr, int len);

/*
 * push any dirty cache in the specified memory range.
 * It starts at the physical address specified for
 * the given number of bytes.
 */
extern void cache_push(unsigned long paddr, int len);

/*
 * push and invalidate pages in the specified user virtual
 * memory range.
 */
extern void cache_push_v(unsigned long vaddr, int len);

/* cache code */
#define FLUSH_I_AND_D	(0x00000808)
#define FLUSH_I 	(0x00000008)

/* This is needed whenever the virtual mapping of the current
   process changes.  */
#endif

#endif /* _BFINNOMMU_PGALLOC_H */
