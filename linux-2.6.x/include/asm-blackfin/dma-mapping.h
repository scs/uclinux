#ifndef _BFINNOMMU_DMA_MAPPING_H
#define _BFINNOMMU_DMA_MAPPING_H

#include <linux/config.h>

#ifdef CONFIG_PCI
#include <asm-generic/dma-mapping.h>
#else
#include <asm-generic/dma-mapping-broken.h>
#endif

#endif /* _BFINNOMMU_DMA_MAPPING_H */
