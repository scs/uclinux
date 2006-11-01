#ifndef _BLACKFIN_PGTABLE_H
#define _BLACKFIN_PGTABLE_H

#include <asm-generic/4level-fixup.h>

#include <asm/setup.h>

typedef pte_t *pte_addr_t;
/*
* Trivial page table functions.
*/
#define pgd_present(pgd)	(1)
#define pgd_none(pgd)		(0)
#define pgd_bad(pgd)		(0)
#define pgd_clear(pgdp)
#define kern_addr_valid(addr)	(1)
#define	pmd_offset(a, b)	((void *)0)

#define kern_addr_valid(addr) (1)

#define PAGE_NONE		__pgprot(0)	/* these mean nothing to NO_MM */
#define PAGE_SHARED		__pgprot(0)	/* these mean nothing to NO_MM */
#define PAGE_COPY		__pgprot(0)	/* these mean nothing to NO_MM */
#define PAGE_READONLY		__pgprot(0)	/* these mean nothing to NO_MM */
#define PAGE_KERNEL		__pgprot(0)	/* these mean nothing to NO_MM */

extern void paging_init(void);

#define __swp_type(x)		(0)
#define __swp_offset(x)		(0)
#define __swp_entry(typ,off)	((swp_entry_t) { ((typ) | ((off) << 7)) })
#define __pte_to_swp_entry(pte)	((swp_entry_t) { pte_val(pte) })
#define __swp_entry_to_pte(x)	((pte_t) { (x).val })

static inline int pte_file(pte_t pte)
{
	return 0;
}

/*
 * ZERO_PAGE is a global shared page that is always zero: used
 * for zero-mapped memory areas etc..
 */
#define ZERO_PAGE(vaddr)	(virt_to_page(0))

extern unsigned int kobjsize(const void *objp);

#define swapper_pg_dir ((pgd_t *) 0)
/*
 * No page table caches to initialise.
 */
#define pgtable_cache_init()	do { } while (0)
#define io_remap_pfn_range      remap_pfn_range

/*
 * All 32bit addresses are effectively valid for vmalloc...
 * Sort of meaningless for non-VM targets.
 */
#define	VMALLOC_START	0
#define	VMALLOC_END	0xffffffff

#endif				/* _BLACKFIN_PGTABLE_H */
