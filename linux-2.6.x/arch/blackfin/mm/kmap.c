/*
 *  linux/arch/bfinnommu/mm/kmap.c
 *
 *  Based: linux/arch/m68knommu/mm/kmap.c
 *
 *  Copyright (C) 2000 Lineo, <davidm@lineo.com>
 */

#undef DEBUG

/*
 * Map some physical address range into the kernel address space.
 */

void *__ioremap(unsigned long physaddr, unsigned long size, int cacheflag)
{
	return (void *)physaddr;
}

/*
 * Unmap a ioremap()ed region again
 */
void iounmap(void *addr)
{
}

/*
 * __iounmap unmaps nearly everything, so be careful
 * it doesn't free currently pointer/page tables anymore but it
 * wans't used anyway and might be added later.
 */
void __iounmap(void *addr, unsigned long size)
{
}

/*
 * Set new cache mode for some kernel address space.
 * The caller must push data for that range itself, if such data may already
 * be in the cache.
 */
void kernel_set_cachemode(void *addr, unsigned long size, int cmode)
{
}

int is_in_rom(unsigned long addr)
{
        extern unsigned long _ramstart, _ramend;
                                                                                
        /*
         *      What we are really trying to do is determine if addr is
         *      in an allocated kernel memory region. If not then assume
         *      we cannot free it or otherwise de-allocate it. Ideally
         *      we could restrict this to really being in a ROM or flash,
         *      but that would need to be done on a board by board basis,
         *      not globally.
         */
        if ((addr < _ramstart) || (addr >= _ramend))
                return(1);
                                                                                
        /* Default case, not in ROM */
        return(0);
}
