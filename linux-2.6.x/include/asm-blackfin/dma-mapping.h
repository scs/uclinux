#ifndef _ARMNOMMU_DMA_MAPPING_H
#define _ARMNOMMU_DMA_MAPPING_H

#include <linux/config.h>

#ifdef CONFIG_PCI
#include <asm-generic/dma-mapping.h>
#else
#include <asm-generic/dma-mapping-broken.h>
#endif

#endif /* _ARMNOMMU_DMA_MAPPING_H */
