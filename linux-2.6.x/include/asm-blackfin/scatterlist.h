#ifndef _BLACKFIN_SCATTERLIST_H
#define _BLACKFIN_SCATTERLIST_H

struct scatterlist {
	struct page *page;
	unsigned int offset;
	dma_addr_t dma_address;
	unsigned int length;
};

/*
 * These macros should be used after a pci_map_sg call has been done
 * to get bus addresses of each of the SG entries and their lengths.
 * You should only work with the number of sg entries pci_map_sg
 * returns, or alternatively stop on the first sg_dma_len(sg) which
 * is 0.
 */
#define sg_dma_address(sg)	((unsigned long) (page_to_phys((sg)->page) + (sg)->offset))
#define sg_dma_len(sg)		((sg)->length)

#define ISA_DMA_THRESHOLD	(0xffffffff)

#endif				/* !(_BLACKFIN_SCATTERLIST_H) */
