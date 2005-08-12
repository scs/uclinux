/*
 * Dynamic DMA mapping support.
 */

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/bootmem.h>
#include <linux/spinlock.h>
#include <linux/device.h>
#include <asm/io.h>

static spinlock_t dma_page_lock = SPIN_LOCK_UNLOCKED;
static unsigned int *dma_page;
static unsigned int dma_pages;
static unsigned long dma_base;
static unsigned long dma_size;
static unsigned int dma_initialized = 0;
extern unsigned long _ramend;
extern unsigned long memory_end;

void dma_alloc_init(unsigned long start, unsigned long end)
{
	dma_page = (unsigned int *)__get_free_page(GFP_KERNEL);
	memset(dma_page, 0, PAGE_SIZE);
	dma_base = PAGE_ALIGN(start);
	dma_size = PAGE_ALIGN(end) - PAGE_ALIGN(start);
	dma_pages = dma_size >> PAGE_SHIFT;
	memset((void*)dma_base, 0, 1024*1024);
	dma_initialized = 1;

	printk("%s: dma_page @ 0x%p - %d pages at 0x%08lx\n", __FUNCTION__, dma_page, dma_pages, dma_base);
}

static inline unsigned int get_pages(size_t size)
{
	return ((size - 1) >> PAGE_SHIFT) + 1;
}

static unsigned long __alloc_dma_pages(unsigned int pages)
{
	unsigned long ret = 0, flags;
	int i, count = 0;

	if (dma_initialized == 0)
		dma_alloc_init(memory_end, _ramend);

	spin_lock_irqsave(&dma_page_lock, flags);

	for (i = 0; i < dma_pages;)
	{
		if (dma_page[i++] == 0)
		{
			if (++count == pages)
			{
				while (count--)
					dma_page[--i] = 1;
				ret = dma_base + (i << PAGE_SHIFT);
				break;
			}
		} else 
			count = 0;
	}
	spin_unlock_irqrestore(&dma_page_lock, flags);
	return ret;
}

static void __free_dma_pages(unsigned long addr, unsigned int pages)
{
	unsigned long page = (addr - dma_base) >> PAGE_SHIFT;
	unsigned long flags;
	int i;

	if ((page + pages) > dma_pages)
	{
		printk(KERN_ERR "%s: freeing outside range.\n", __FUNCTION__);
		BUG();
	}

	spin_lock_irqsave(&dma_page_lock, flags);
	for (i = page; i < page + pages; i++)
	{
		dma_page[i] = 0;
	}
	spin_unlock_irqrestore(&dma_page_lock, flags);
}

void *dma_alloc_coherent(struct device *dev, size_t size, 
			dma_addr_t *dma_handle, int gfp)
{
	void* ret;

	ret = (void*)__alloc_dma_pages(get_pages(size));

	if (ret)
	{
		memset(ret, 0, size);
		dma_handle = (dma_addr_t*)virt_to_phys(ret);
		printk("%s: allocated %d bytes at 0x%08lx(0x%p)\n", __FUNCTION__, size, (unsigned long)ret, dma_handle);
	}

	return ret;
}

void dma_free_coherent(struct device *dev, size_t size, void *vaddr, 
			dma_addr_t dma_handle)
{
	__free_dma_pages((unsigned long)vaddr, get_pages(size));
}
