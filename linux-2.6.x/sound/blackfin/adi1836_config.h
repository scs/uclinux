/* $Id$ */

/* SPI and SPORT DMA and IRQ channels for adi1836 driver */


/*
 * peripheral DMA and IRQ assignments
 * see ADSP-BF533 page 4.30 - 4.32 for irq 
 * see ADSP-BF533 page 9.28 - 9.31 for dma 
 * see arch/bfinnommu/mach-bf533/ints-priority.c for 
 *     peripheral interrupt mapping mechanism
 */


#ifndef SND_CONFIG_BLACKFIN_PFBIT
#define SND_CONFIG_BLACKFIN_PFBIT 4    /* pf bit tied to ad1836 chip select */
#endif

#if 0 /* not used */
#ifndef CONFIG_SND_BLACKFIN_SPI_DMA
#define CONFIG_SND_BLACKFIN_SPI_DMA 5  /* bf53x default DMA channel for SPI */
#endif
#endif

#ifndef CONFIG_SND_BLACKFIN_SPI_IRQ_DATA 
#define CONFIG_SND_BLACKFIN_SPI_IRQ_DATA IRQ_SPI  /* periph irq 3 -> IVG 10 */
#endif

#ifndef CONFIG_SND_BLACKFIN_SPI_IRQ_ERR 
#define CONFIG_SND_BLACKFIN_SPI_IRQ_ERR IRQ_SPI_ERROR    /* periph irq 0 -> IVG 7 */
#endif

#ifndef CONFIG_SND_BLACKFIN_SPORT
#define CONFIG_SND_BLACKFIN_SPORT 0  /* bf53x default Sport channel for ad1836 */
#endif

#ifndef CONFIG_SND_BLACKFIN_SPORT_DMA_RX
#define CONFIG_SND_BLACKFIN_SPORT_DMA_RX 1   /* bf53x default DMA channel for Sport0 rx  */
#endif

#ifndef CONFIG_SND_BLACKFIN_SPORT_DMA_TX
#define CONFIG_SND_BLACKFIN_SPORT_DMA_TX 2   /* bf53x default DMA channel for Sport0 tx  */
#endif

#ifndef CONFIG_SND_BLACKFIN_SPORT_IRQ_ERR 
#define CONFIG_SND_BLACKFIN_SPORT_IRQ_ERR IRQ_SPORT0_ERROR   /* periph irq 0 -> IVG 7 */
#endif

#ifndef CONFIG_SND_BLACKFIN_SPORT_IRQ_RX 
#define CONFIG_SND_BLACKFIN_SPORT_IRQ_RX IRQ_SPORT0   /* periph irq 2 -> IVG 9 */
#endif

#ifndef CONFIG_SND_BLACKFIN_SPORT_IRQ_TX 
#define CONFIG_SND_BLACKFIN_SPORT_IRQ_TX IRQ_SPARE1  /* periph irq 2 -> IVG 9 */
#endif
