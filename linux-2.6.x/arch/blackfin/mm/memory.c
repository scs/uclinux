/*
 *  linux/arch/bfinnommu/mm/memory.c
 *
 *  Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>,
 *
 *  MAR/1999 -- hacked for the ColdFire (gerg@lineo.com)
 *
 *  Based on:
 *
 *  linux/arch/m68k/mm/memory.c
 *  linux/arch/m68knommu/mm/memory.c
 *
 *  Copyright (C) 1995  Hamish Macdonald
 */

#include <linux/config.h>
#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/slab.h>

#include <asm/setup.h>
#include <asm/segment.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/system.h>
#include <asm/traps.h>
#include <asm/io.h>	


/*
 * 040: Hit every page containing an address in the range paddr..paddr+len-1.
 * (Low order bits of the ea of a CINVP/CPUSHP are "don't care"s).
 * Hit every page until there is a page or less to go. Hit the next page,
 * and the one after that if the range hits it.
 */
/* ++roman: A little bit more care is required here: The CINVP instruction
 * invalidates cache entries WITHOUT WRITING DIRTY DATA BACK! So the beginning
 * and the end of the region must be treated differently if they are not
 * exactly at the beginning or end of a page boundary. Else, maybe too much
 * data becomes invalidated and thus lost forever. CPUSHP does what we need:
 * it invalidates the page after pushing dirty data to memory. (Thanks to Jes
 * for discovering the problem!)
 */
/* ... but on the '060, CPUSH doesn't invalidate (for us, since we have set
 * the DPI bit in the CACR; would it cause problems with temporarily changing
 * this?). So we have to push first and then additionally to invalidate.
 */

/*
 * cache_clear() semantics: Clear any cache entries for the area in question,
 * without writing back dirty entries first. This is useful if the data will
 * be overwritten anyway, e.g. by DMA to memory. The range is defined by a
 * _physical_ address.
 */

void cache_clear (unsigned long paddr, int len)
{
}


/*
 *	Define cache invalidate functions. Anything
 *	that has separate data and instruction caches will be a problem.
 */
#define	cache_invalidate_lines(a,b)


/*
 * cache_push() semantics: Write back any dirty cache data in the given area,
 * and invalidate the range in the instruction cache. It needs not (but may)
 * invalidate those entries also in the data cache. The range is defined by a
 * _physical_ address.
 */

void cache_push (unsigned long paddr, int len)
{
	cache_invalidate_lines(paddr, len);
}


/*
 * cache_push_v() semantics: Write back any dirty cache data in the given
 * area, and invalidate those entries at least in the instruction cache. This
 * is intended to be used after data has been written that can be executed as
 * code later. The range is defined by a _user_mode_ _virtual_ address  (or,
 * more exactly, the space is defined by the %sfc/%dfc register.)
 */

void cache_push_v (unsigned long vaddr, int len)
{
	cache_invalidate_lines(vaddr, len);
}

unsigned long mm_phys_to_virt (unsigned long addr)
{
    return phys_to_virt (addr);
}

/* Map some physical address range into the kernel address space. The
 * code is copied and adapted from map_chunk().
 */

unsigned long kernel_map(unsigned long paddr, unsigned long size,
			 int nocacheflag, unsigned long *memavailp )
{
	return paddr;
}


#ifdef MAGIC_ROM_PTR
int is_in_rom(unsigned long addr) {
	extern unsigned long    _ramstart, _ramend;

	/* Anything not in operational RAM is returned as in rom! */
	if ((addr >= _ramstart) && (addr < _ramend))
		return(0);
	return(1);
}
#endif

