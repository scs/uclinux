/*
 * Blackfin BF533/2.6 support : LG Soft India
 * Tab Size == 4 ....MaTed
 */

#ifndef __ADSPLPBLACKFIN__
#ifndef _BLKFin_H_
#define _BLKFin_H_


#include <linux/config.h>	


/*some misc defines*/

#define IMASK_IVG15		0x8000
#define IMASK_IVG14		0x4000
#define IMASK_IVG13		0x2000
#define IMASK_IVG12		0x1000

#define IMASK_IVG11		0x0800
#define IMASK_IVG10		0x0400
#define IMASK_IVG9		0x0200
#define IMASK_IVG8		0x0100

#define IMASK_IVG7		0x0080
#define IMASK_IVGTMR		0x0040
#define IMASK_IVGHW		0x0020

/***************************
 * Blackfin Cache setup
 */

#define BLKFIN_ICACHESIZE	(16*1024)
#define BLKFIN_DCACHESIZE	(32*1024)

#define BLKFIN_ISUBBANKS	4
#define BLKFIN_IWAYS		4
#define BLKFIN_ILINES		32

#define BLKFIN_DSUPBANKS	2
#define BLKFIN_DSUBBANKS	4
#define BLKFIN_DWAYS		2	
#define BLKFIN_DLINES		64	

#define WAY0_L			0x1
#define WAY1_L			0x2
#define WAY01_L			0x3
#define WAY2_L			0x4
#define WAY02_L			0x5
#define	WAY12_L			0x6
#define	WAY012_L		0x7

#define	WAY3_L			0x8
#define	WAY03_L			0x9
#define	WAY13_L			0xA
#define	WAY013_L		0xB
					
#define	WAY32_L			0xC
#define	WAY320_L		0xD
#define	WAY321_L		0xE
#define	WAYALL_L		0xF

#define DMC_ENABLE (2<<2)	/*yes, 2, not 1*/

/* IAR0 BIT FIELDS*/
#define RTC_ERROR_BIT			0x0FFFFFFF
#define UART_ERROR_BIT			0xF0FFFFFF
#define SPORT1_ERROR_BIT		0xFF0FFFFF
#define SPI_ERROR_BIT			0xFFF0FFFF
#define SPORT0_ERROR_BIT		0xFFFF0FFF
#define PPI_ERROR_BIT			0xFFFFF0FF
#define DMA_ERROR_BIT			0xFFFFFF0F
#define PLLWAKE_ERROR_BIT		0xFFFFFFFF

/* IAR1 BIT FIELDS*/
#define DMA7_UARTTX_BIT			0x0FFFFFFF
#define DMA6_UARTRX_BIT			0xF0FFFFFF
#define DMA5_SPI_BIT			0xFF0FFFFF
#define DMA4_SPORT1TX_BIT		0xFFF0FFFF
#define DMA3_SPORT1RX_BIT		0xFFFF0FFF
#define DMA2_SPORT0TX_BIT		0xFFFFF0FF
#define DMA1_SPORT0RX_BIT		0xFFFFFF0F
#define DMA0_PPI_BIT			0xFFFFFFFF

/* IAR2 BIT FIELDS*/
#define WDTIMER_BIT			0x0FFFFFFF
#define MEMDMA1_BIT			0xF0FFFFFF
#define MEMDMA0_BIT			0xFF0FFFFF
#define PFB_BIT				0xFFF0FFFF
#define PFA_BIT				0xFFFF0FFF
#define TIMER2_BIT			0xFFFFF0FF
#define TIMER1_BIT			0xFFFFFF0F
#define TIMER0_BIT		        0xFFFFFFFF

/*Miscellaneous Values*/
#define CCLK_550	0x6400	/* For STAMP board */
#define CCLK_594	0x2C00	/* For EZKIT board */

#define DELAY_STMP	0x80
#define DELAY_EZ	0x1000

#define ZERO		0x0

#ifdef CONFIG_EZKIT
#define AMBCTL0VAL	0x7BB07BB0
#define AMBCTL1VAL	0x22547BB0
#define AMGCTLVAL	0xFF
#define RAM_END		0x2000000
#endif

#ifdef CONFIG_BLKFIN_STAMP
#define AMBCTL0VAL	0xBBC3BBC3
#define AMBCTL1VAL	0x99B39983
#define AMGCTLVAL	0xFF
#define RAM_END		0x1000000	
#endif

#endif  /* _BLKFin_H_  */
#endif /* !defined __ADSPLPBLACKFIN__ */
