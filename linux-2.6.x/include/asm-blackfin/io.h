#ifndef _BFIN_IO_H
#define _BFIN_IO_H

#ifdef __KERNEL__

/*
 * These are for ISA/PCI shared memory _only_ and should never be used
 * on any other type of memory, including Zorro memory. They are meant to
 * access the bus in the bus byte order which is little-endian!.
 *
 * readX/writeX() are used to access memory mapped devices. On some
 * architectures the memory mapped IO stuff needs to be accessed
 * differently. On the bfin architecture, we just read/write the
 * memory location directly.
 */
#define readb(addr) ({ unsigned __v; asm volatile ("csync; %0 = b [%1] (z); " \
  : "=d"(__v): "a"(addr)); (unsigned char)__v; })
#define readw(addr) ({ unsigned __v; asm volatile ("csync; %0 = w [%1] (z); " \
  : "=d"(__v): "a"(addr)); (unsigned short)__v; })
#define readl(addr) ({ unsigned __v; asm volatile ("csync; %0 = [%1]; " \
  : "=d"(__v): "a"(addr)); __v; })

#define writeb(b,addr) (void)((*(volatile unsigned char *) (addr)) = (b))
#define writew(b,addr) (void)((*(volatile unsigned short *) (addr)) = (b))
#define writel(b,addr) (void)((*(volatile unsigned int *) (addr)) = (b))

#define __raw_readb readb
#define __raw_readw readw
#define __raw_readl readl
#define __raw_writeb writeb
#define __raw_writew writew
#define __raw_writel writel
#define memset_io(a,b,c)	memset((void *)(a),(b),(c))
#define memcpy_fromio(a,b,c)	memcpy((a),(void *)(b),(c))
#define memcpy_toio(a,b,c)	memcpy((void *)(a),(b),(c))

#define inb(addr)    readb(addr)
#define inw(addr)    readw(addr)
#define inl(addr)    readl(addr)
#define outb(x,addr) ((void) writeb(x,addr))
#define outw(x,addr) ((void) writew(x,addr))
#define outl(x,addr) ((void) writel(x,addr))

#define inb_p(addr)    inb(addr)
#define inw_p(addr)    inw(addr)
#define inl_p(addr)    inl(addr)
#define outb_p(x,addr) outb(x,addr)
#define outw_p(x,addr) outw(x,addr)
#define outl_p(x,addr) outl(x,addr)

#define insb(port, addr, count) memcpy((void*)addr, (void*)port, count)
#define insw(port, addr, count) memcpy((void*)addr, (void*)port, (2*count))
#define insl(port, addr, count) memcpy((void*)addr, (void*)port, (4*count))

#define outsb(port, addr, count) memcpy((void*)port, (void*)addr, count)
#define outsw(port, addr, count) memcpy((void*)port, (void*)addr, (2*count))
#define outsl(port, addr, count) memcpy((void*)port, (void*)addr, (4*count))
#define IO_SPACE_LIMIT 0xffffffff

/* Values for nocacheflag and cmode */
#define IOMAP_NOCACHE_SER		1

#ifndef __ASSEMBLY__	

extern void *__ioremap(unsigned long physaddr, unsigned long size, int cacheflag);
extern void iounmap(void *addr);

extern inline void *ioremap(unsigned long physaddr, unsigned long size)
{
	return __ioremap(physaddr, size, IOMAP_NOCACHE_SER);
}
extern inline void *ioremap_nocache(unsigned long physaddr, unsigned long size)
{
	return __ioremap(physaddr, size, IOMAP_NOCACHE_SER);
}

extern void blkfin_inv_cache_all(void);

#endif

#define dma_cache_inv(_start,_size) do { blkfin_inv_cache_all();} while (0)
#define dma_cache_wback(_start,_size) do { } while (0)
#define dma_cache_wback_inv(_start,_size) do { blkfin_inv_cache_all();} while (0)

/* Pages to physical address... */ 
#define page_to_phys(page)      ((page - mem_map) << PAGE_SHIFT)
#define page_to_bus(page)       ((page - mem_map) << PAGE_SHIFT)

#define mm_ptov(vaddr)		((void *) (vaddr))
#define mm_vtop(vaddr)		((unsigned long) (vaddr))
#define phys_to_virt(vaddr)	((void *) (vaddr))
#define virt_to_phys(vaddr)	((unsigned long) (vaddr))

#define virt_to_bus virt_to_phys
#define bus_to_virt phys_to_virt

#endif /* __KERNEL__ */

#endif /* _BFIN_IO_H */
