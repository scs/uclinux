#ifndef _BFINNOMMU_DMA_MAPPING_H
#define _BFINNOMMU_DMA_MAPPING_H

#include <linux/config.h>

void dma_alloc_init(unsigned long start, unsigned long end);
void* dma_alloc_coherent(struct device* dev, size_t size, dma_addr_t *dma_handle, int gfp);
void  dma_free_coherent(struct device* dev, size_t size, void *vaddr, dma_addr_t dma_handle);

#endif /* _BFINNOMMU_DMA_MAPPING_H */
