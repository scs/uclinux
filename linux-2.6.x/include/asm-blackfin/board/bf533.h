/*
 * Blackfin BF533/2.6 support : LG Soft India
 * Tab Size == 4 ....MaTed
 */

#ifndef __ADSPLPBLACKFIN__
#ifndef _BLKFin_H_
#define _BLKFin_H_

#include <linux/config.h>	

#define OFFSET_( x ) ((x) & 0x0000FFFF) /* define macro for offset */
#define L1_ISRAM         0xFFA00000
#define L1_ISRAM_END     0xFFA10000
#define DATA_BANKA_SRAM		0xFF800000

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
#define RAM_END		0x1FFEFF0
#endif

#ifdef CONFIG_BLKFIN_STAMP
#define AMBCTL0VAL	0xBBC3BBC3
#define AMBCTL1VAL	0x99B39983
#define AMGCTLVAL	0xFF
#define RAM_END		0x8000000
#endif

/********************************PLL Settings **************************************/

#if(CONFIG_CLKIN_HALF == 0)
	#define CONFIG_VCO_HZ	(CONFIG_CLKIN_HZ * CONFIG_VCO_MULT)
#else
	#define CONFIG_VCO_HZ	((CONFIG_CLKIN_HZ * CONFIG_VCO_MULT)/2)
#endif

#if(CONFIG_PLL_BYPASS == 0)
	#define CONFIG_CCLK_HZ	(CONFIG_VCO_HZ/CONFIG_CCLK_DIV)
	#define CONFIG_SCLK_HZ	(CONFIG_VCO_HZ/CONFIG_SCLK_DIV)
#else
	#define CONFIG_CCLK_HZ	CONFIG_CLKIN_HZ
	#define CONFIG_SCLK_HZ	CONFIG_CLKIN_HZ
#endif

#if (CONFIG_VCO_MULT < 0)
		#error "VCO Multiplier is either less than 0 or more than 63. Please select a different value"
#endif

#if(CONFIG_VCO_MULT > 63)
		#error "VCO Multiplier is either less than 0 or more than 63. Please select a different value"
#endif

#if (CONFIG_SCLK_DIV < 1)
		#error "SCLK DIV cannot be less than 1 or more than 15. Please select a proper value"
#endif

#if (CONFIG_SCLK_DIV > 15)
		#error "SCLK DIV cannot be less than 1 or more than 15. Please select a proper value"
#endif

#if (CONFIG_CCLK_DIV != 1)
	#if (CONFIG_CCLK_DIV != 2)
		#if (CONFIG_CCLK_DIV != 4) 
			#if (CONFIG_CCLK_DIV != 8)
				#error "CCLK DIV can be 1,2,4 or 8 only.Please select a proper value"
			#endif
		#endif
	#endif
#endif

#ifdef CONFIG_EZKIT
	#define MAX_VC	600000000
#elif defined CONFIG_BLKFIN_STAMP
	#define MAX_VC	650000000
#endif

#if (CONFIG_VCO_HZ < 55000000)
		#error "VCO selected is either less than minimum value of more than maximum value. Please change the VCO multipler"
#endif

#if(CONFIG_VCO_HZ > MAX_VC)
		#error "VCO selected is either less than minimum value of more than maximum value. Please change the VCO multipler"
#endif	

#if (CONFIG_SCLK_HZ > 132000000)
		#error "Sclk value selected is either less than minimum or more than maximum.Please select a proper value for SCLK multiplier"
#endif
	
#if (CONFIG_SCLK_HZ < 27000000)
		#error "Sclk value selected is either less than minimum or more than maximum.Please select a proper value for SCLK multiplier"
#endif

#if (CONFIG_SCLK_HZ >= CONFIG_CCLK_HZ)
	#if(CONFIG_SCLK_HZ != CONFIG_CLKIN_HZ)
		#if(CONFIG_CCLK_HZ != CONFIG_CLKIN_HZ)
			#error "Please select sclk less than cclk"
		#endif
	#endif
#endif

#if (CONFIG_CCLK_DIV == 1)
  #define CONFIG_CCLK_ACT_DIV   CCLK_DIV1
#endif
#if (CONFIG_CCLK_DIV == 2)
  #define CONFIG_CCLK_ACT_DIV   CCLK_DIV2
#endif
#if (CONFIG_CCLK_DIV == 4)
  #define CONFIG_CCLK_ACT_DIV   CCLK_DIV4
#endif
#if (CONFIG_CCLK_DIV == 8)
  #define CONFIG_CCLK_ACT_DIV   CCLK_DIV8
#endif
#ifndef CONFIG_CCLK_ACT_DIV
  #define CONFIG_CCLK_ACT_DIV   CONFIG_CCLK_DIV_not_defined_properly
#endif

#endif  /* _BLKFin_H_  */
#endif /* !defined __ADSPLPBLACKFIN__ */
