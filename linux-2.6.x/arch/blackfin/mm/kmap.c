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
