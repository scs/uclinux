/*
 * arch/arm/mach-ixp425/ixp425-pcibuf.c 
 *
 * IXP425 PCI bounce buffer routines.  The IXP425 only has a 64MB inbound
 * PCI window, but allows for up 256MB of SDRAM.  This means that if 
 * running with > 64MB of memory, we need to bounce buffers between the
 * safe and unsafe areas. An attempt was made to port the SA1111 bounce
 * routines to this platform but that does not work due to the fact that
 * EEPro100 (and probably others) PCI driver calls pci_map_single() while
 * handling interrupts to refill Rx buffers.  The sa1111 implementation
 * of bounce buffering uses pci_pools which call pci_alloc_consistent
 * which calls consistent_alloc which is not interrupt safe on 2.4.
 * We're basically doing the same, except that we are using our own
 * object cache instead of relying on the PCI layer to take care of
 * it for us.
 *
 * This file we be killed in 2.5 and replaced with the sa1111 style 
 * implementation.
 *
 * Maintainer: Deepak Saxena <dsaxena@mvista.com>
 *
 * Copyright (C) 2003 MontaVista Software, Inc.
 * Copyright (C) 2002 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>

#include <asm/hardware.h>
#include <asm/sizes.h>

// #define DEBUG
#ifdef DEBUG
#  define DBG(x...) printk(KERN_DEBUG __FILE__": "x)
#else
#  define DBG(x...)
#endif

/*
 * From SA1111 implementation
 */
struct safe_buffer {
	struct		list_head node;

	/* Original request */
	void		*ptr;
	size_t		size;

	/* Safe buffer information */
	void		*safe;
	dma_addr_t	safe_dma_addr;
};

LIST_HEAD(safe_buffers);

static spinlock_t pcibuf_lock = SPIN_LOCK_UNLOCKED;

static inline void *
alloc_safe_buffer(void *unsafe, int size, dma_addr_t *dma_addr)
{
	struct safe_buffer *safe_buf;
	unsigned long flags;

	DBG("alloc_safe_buffer(size=%d)\n", size);

	/*
	 * This should really be it's own object cache...
	 */
	safe_buf = kmalloc(sizeof(*safe_buf), GFP_ATOMIC);
	if(!safe_buf)
		return 0;

	safe_buf->safe = kmalloc(size, GFP_DMA | GFP_ATOMIC);

	if (!safe_buf->safe) {
		kfree(safe_buf);
		return 0;
	}

	safe_buf->ptr = unsafe;
	safe_buf->size = size;
	*dma_addr = safe_buf->safe_dma_addr = virt_to_bus(safe_buf->safe);

	spin_lock_irqsave(&pcibuf_lock, flags);
	list_add(&safe_buf->node, &safe_buffers);
	spin_unlock_irqrestore(&pcibuf_lock, flags);

	return safe_buf->safe;
}

static inline void 
free_safe_buffer(struct safe_buffer *safe_buf)
{
	unsigned long flags;

	spin_lock_irqsave(&pcibuf_lock, flags);
	list_del(&safe_buf->node);
	kfree(safe_buf->safe);
	kfree(safe_buf);
	spin_unlock_irqrestore(&pcibuf_lock, flags);
}

static inline void*
find_safe_buffer(dma_addr_t dma_addr, void **unsafe)
{
	struct list_head *entry;
	struct safe_buffer *safe_buf; 
	unsigned long flags;

	spin_lock_irqsave(&pcibuf_lock, flags);
	list_for_each(entry, &safe_buffers) {
		safe_buf = list_entry(entry, struct safe_buffer, node);
		
		if(safe_buf->safe_dma_addr == dma_addr) {
			*unsafe = safe_buf->ptr;
			spin_unlock_irqrestore(&pcibuf_lock, flags);
			return safe_buf;
		}
	}
	spin_unlock_irqrestore(&pcibuf_lock, flags);

	return 0;	    
}

dma_addr_t ixp425_map_single(void *virt, size_t size, int direction)
{
	dma_addr_t dma_addr;
	void *safe;

	DBG("ixp425_map_single(virt=%p,size=%d,dir=%x)\n", 
		virt, size, direction);

	/*
	 * FIX ME: We are assuming we are in host mode and therefore
	 * the inbound BAR is set to 0.  
	 *
	 * Need to check (dma_addr + size ) > (BAR0 + SZ_64M)
	 */
	dma_addr = virt_to_bus(virt);

	if((dma_addr+size) >= SZ_64M) {
		safe = alloc_safe_buffer(virt, size, &dma_addr);
		if (!safe) {
			printk(KERN_ERR "%s: Could not allocate safe buffer",
					__FILE__);
			return 0;
		}

		DBG("unsafe buffer %p (phy=%p) mapped to %p (phy=%p)\n", virt, 
			(void *)virt_to_phys(virt), safe, (void *)dma_addr);

		/*
		 * Only need to copy if DMAing to device
		 */
		if((direction == PCI_DMA_TODEVICE) || 
		   (direction == PCI_DMA_BIDIRECTIONAL)) {
			memcpy(safe, virt, size);
		}
		consistent_sync(safe, size, direction);
	}
	else
		consistent_sync(virt, size, direction);

	return dma_addr;
}

void ixp425_unmap_single(dma_addr_t dma_addr, size_t size, int direction)
{
	void *unsafe;
	struct safe_buffer *safe_buf;

	DBG("ixp425_unmap_single(ptr=%p, size=%d, dir=%x)\n",  
		(void *)dma_addr, size, direction);

	if ((safe_buf = find_safe_buffer(dma_addr, &unsafe))) {
		if((direction == PCI_DMA_FROMDEVICE) ||
		   (direction == PCI_DMA_BIDIRECTIONAL)) {
			DBG("copyback unsafe %p, safe %p, size %d\n", unsafe, safe_buf->safe, size);
			consistent_sync(safe_buf->safe, size, direction);
			memcpy(unsafe, safe_buf->safe, size);
		}
	
		free_safe_buffer(safe_buf);
	} else {
		/* 
		 * Assume this is normal memory.  We have a possible
		 * OOPs here if someone sends us a bad dma_addr_t.
		 */
		unsafe = bus_to_virt(dma_addr);
		consistent_sync(unsafe, size, direction);
	}
}

void ixp425_sync_single(dma_addr_t dma_addr, size_t size, int direction)
{
	void *unsafe;
	struct safe_buffer *safe_buf;

	DBG("ixp425_sync_single(dma_addr=%p, size=%d, dir=%x)\n", 
		(void *)dma_addr, size, direction);

	if((safe_buf = find_safe_buffer(dma_addr, &unsafe))) {
		DBG("copyback unsafe %p, safe %p, size %d\n", unsafe, safe_buf->safe, size);
		switch(direction) {
			case PCI_DMA_TODEVICE:
				memcpy(safe_buf->safe, unsafe, size);
				consistent_sync(safe_buf->safe, size, direction);
				break;
			case PCI_DMA_FROMDEVICE:
				consistent_sync(safe_buf->safe, size, direction);
				memcpy(unsafe, safe_buf->safe, size);
				break;
		}
	} else {
		/* assume this is normal memory */
		unsafe = bus_to_virt(dma_addr);
		consistent_sync(unsafe, size, direction);
	}
}


EXPORT_SYMBOL(ixp425_map_single);
EXPORT_SYMBOL(ixp425_unmap_single);
EXPORT_SYMBOL(ixp425_sync_single);


