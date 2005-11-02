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
#define readb(addr) ({ unsigned __v; \
		       int _tmp; \
                       __builtin_bfin_csync(); \
		       __asm__ __volatile__ ("cli %1;\n\t"\
	         			 "NOP;NOP;NOP;\n\t"\
					     "%0 = b [%2] (z);\n\t"\
					     "sti %1;\n\t" \
  : "=d"(__v), "=d"(_tmp): "a"(addr)); (unsigned char)__v; })

#define readw(addr) ({ unsigned __v; \
					   int _tmp; \
                       __builtin_bfin_csync(); \
                       __asm__ __volatile__ ("cli %1;\n\t"\
	         			    				 "NOP;NOP;NOP;\n\t"\
	         			     				 "%0 = w [%2] (z);\n\t"\
                                             "sti %1;\n\t" \
  : "=d"(__v), "=d"(_tmp): "a"(addr)); (unsigned short)__v; })

#define readl(addr) ({ unsigned __v; \
					   int _tmp; \
                      __builtin_bfin_csync(); \
                      __asm__ __volatile__ ("cli %1;\n\t"\
	         			    				 "NOP;NOP;NOP;\n\t"\
                                            "%0 = [%2];\n\t"\
                                            "sti %1;\n\t" \
  : "=d"(__v), "=d"(_tmp): "a"(addr)); __v; })

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

#define IO_SPACE_LIMIT 0xffffffff

/* Values for nocacheflag and cmode */
#define IOMAP_NOCACHE_SER		1

#ifndef __ASSEMBLY__

extern void outsb(unsigned long port, const void *addr, unsigned long count);
extern void outsw(unsigned long port, const void *addr, unsigned long count);
extern void outsl(unsigned long port, const void *addr, unsigned long count);

extern void insb(unsigned long port, void *addr, unsigned long count);
extern void insw(unsigned long port, void *addr, unsigned long count);
extern void insl(unsigned long port, void *addr, unsigned long count);

extern void *__ioremap(unsigned long physaddr, unsigned long size,
		       int cacheflag);
extern void iounmap(void *addr);

static inline void *ioremap(unsigned long physaddr, unsigned long size)
{
	return __ioremap(physaddr, size, IOMAP_NOCACHE_SER);
}
static inline void *ioremap_nocache(unsigned long physaddr, unsigned long size)
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

/*
 * Convert a physical pointer to a virtual kernel pointer for /dev/mem
 * access
 */
#define xlate_dev_mem_ptr(p)	__va(p)

/*
 * Convert a virtual cached pointer to an uncached pointer
 */
#define xlate_dev_kmem_ptr(p)	p

#endif				/* __KERNEL__ */

#endif				/* _BFIN_IO_H */
