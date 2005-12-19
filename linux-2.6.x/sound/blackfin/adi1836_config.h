/* $Id$ */

/* SPI and SPORT DMA and IRQ channels for adi1836 driver */


/*
 * peripheral DMA and IRQ assignments
 * see ADSP-BF533 page 4.30 - 4.32 for irq 
 * see ADSP-BF533 page 9.28 - 9.31 for dma 
 * see arch/blackfin/mach-bf533/ints-priority.c for 
 *     peripheral interrupt mapping mechanism
 */


#ifndef CONFIG_SND_BLACKFIN_SPI_PFBIT
#define CONFIG_SND_BLACKFIN_SPI_PFBIT 4    /* pf bit tied to ad1836 chip select */
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

#if 0 == CONFIG_SND_BLACKFIN_SPORT
#define CONFIG_SND_BLACKFIN_SPORT_DMA_RX CH_SPORT0_RX
#else
#define CONFIG_SND_BLACKFIN_SPORT_DMA_RX CH_SPORT1_RX
#endif

#if 0 == CONFIG_SND_BLACKFIN_SPORT
#define CONFIG_SND_BLACKFIN_SPORT_DMA_TX CH_SPORT0_TX
#else
#define CONFIG_SND_BLACKFIN_SPORT_DMA_TX CH_SPORT1_TX
#endif

#if 0 == CONFIG_SND_BLACKFIN_SPORT
#define CONFIG_SND_BLACKFIN_SPORT_IRQ_ERR IRQ_SPORT0_ERROR   /* periph irq 0 -> IVG 7 */
#else
#define CONFIG_SND_BLACKFIN_SPORT_IRQ_ERR IRQ_SPORT1_ERROR
#endif

