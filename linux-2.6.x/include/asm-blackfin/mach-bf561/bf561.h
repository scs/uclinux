/*
 * Blackfin BF561/2.6 support : HH Tech China
 */

#ifndef __ADSPLPBLACKFIN__
#ifndef _BLKFin_H_
#define _BLKFin_H_

#include <linux/config.h>	

#define OFFSET_( x ) ((x) & 0x0000FFFF) /* define macro for offset */
#define L1_ISRAM		0xFFA00000
#define L1_ISRAM_END		0xFFA04000
#define DATA_BANKA_SRAM		0xFF800000
#define DATA_BANKA_SRAM_END	0xFF804000
#define DATA_BANKB_SRAM		0xFF900000
#define DATA_BANKB_SRAM_END	0xFF904000
#define L1_DSRAMA		0xFF800000
#define L1_DSRAMA_END		0xFF804000
#define L1_DSRAMB		0xFF900000
#define L1_DSRAMB_END		0xFF904000
#define L2_SRAM			0xFEB00000
#define L2_SRAM_END		0xFEB20000
#define AMB_FLASH		0x20000000
#define AMB_FLASH_END		0x21000000
#define AMB_FLASH_LENGTH	0x01000000
#define L1_ISRAM_LENGTH		0x4000
#define L1_DSRAMA_LENGTH	0x4000
#define L1_DSRAMB_LENGTH	0x4000
#define L2_SRAM_LENGTH		0x20000

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

/* IAR0 BIT FIELDS */
#define	PLL_WAKEUP_BIT		0xFFFFFFFF
#define	DMA1_ERROR_BIT		0xFFFFFF0F
#define	DMA2_ERROR_BIT		0xFFFFF0FF
#define IMDMA_ERROR_BIT		0xFFFF0FFF
#define	PPI1_ERROR_BIT		0xFFF0FFFF
#define	PPI2_ERROR_BIT		0xFF0FFFFF
#define	SPORT0_ERROR_BIT	0xF0FFFFFF
#define	SPORT1_ERROR_BIT	0x0FFFFFFF
/* IAR1 BIT FIELDS */
#define	SPI_ERROR_BIT		0xFFFFFFFF
#define	UART_ERROR_BIT		0xFFFFFF0F
#define RESERVED_ERROR_BIT	0xFFFFF0FF
#define	DMA1_0_BIT		0xFFFF0FFF
#define	DMA1_1_BIT		0xFFF0FFFF
#define	DMA1_2_BIT		0xFF0FFFFF
#define	DMA1_3_BIT		0xF0FFFFFF
#define	DMA1_4_BIT		0x0FFFFFFF
/* IAR2 BIT FIELDS */
#define	DMA1_5_BIT		0xFFFFFFFF
#define	DMA1_6_BIT		0xFFFFFF0F
#define	DMA1_7_BIT		0xFFFFF0FF
#define	DMA1_8_BIT		0xFFFF0FFF
#define	DMA1_9_BIT		0xFFF0FFFF
#define	DMA1_10_BIT		0xFF0FFFFF
#define	DMA1_11_BIT		0xF0FFFFFF
#define	DMA2_0_BIT		0x0FFFFFFF
/* IAR3 BIT FIELDS */
#define	DMA2_1_BIT		0xFFFFFFFF
#define	DMA2_2_BIT		0xFFFFFF0F
#define	DMA2_3_BIT		0xFFFFF0FF
#define	DMA2_4_BIT		0xFFFF0FFF
#define	DMA2_5_BIT		0xFFF0FFFF
#define	DMA2_6_BIT		0xFF0FFFFF
#define	DMA2_7_BIT		0xF0FFFFFF
#define	DMA2_8_BIT		0x0FFFFFFF
/* IAR4 BIT FIELDS */
#define	DMA2_9_BIT		0xFFFFFFFF
#define	DMA2_10_BIT             0xFFFFFF0F
#define	DMA2_11_BIT             0xFFFFF0FF
#define TIMER0_BIT	        0xFFFF0FFF
#define TIMER1_BIT              0xFFF0FFFF
#define TIMER2_BIT              0xFF0FFFFF
#define TIMER3_BIT              0xF0FFFFFF
#define TIMER4_BIT              0x0FFFFFFF
/* IAR5 BIT FIELDS */
#define TIMER5_BIT		0xFFFFFFFF
#define TIMER6_BIT              0xFFFFFF0F
#define TIMER7_BIT              0xFFFFF0FF
#define TIMER8_BIT              0xFFFF0FFF
#define TIMER9_BIT              0xFFF0FFFF
#define TIMER10_BIT             0xFF0FFFFF
#define TIMER11_BIT             0xF0FFFFFF
#define	PROG0_INTA_BIT	        0x0FFFFFFF
/* IAR6 BIT FIELDS */
#define	PROG0_INTB_BIT		0xFFFFFFFF
#define	PROG1_INTA_BIT          0xFFFFFF0F
#define	PROG1_INTB_BIT          0xFFFFF0FF
#define	PROG2_INTA_BIT          0xFFFF0FFF
#define	PROG2_INTB_BIT          0xFFF0FFFF
#define DMA1_WRRD0_BIT          0xFF0FFFFF
#define DMA1_WRRD1_BIT          0xF0FFFFFF
#define DMA2_WRRD0_BIT          0x0FFFFFFF
/* IAR7 BIT FIELDS */
#define DMA2_WRRD1_BIT		0xFFFFFFFF
#define IMDMA_WRRD0_BIT         0xFFFFFF0F
#define IMDMA_WRRD1_BIT         0xFFFFF0FF
#define	WATCH_BIT	        0xFFFF0FFF
#define RESERVED_1_BIT	        0xFFF0FFFF
#define RESERVED_2_BIT	        0xFF0FFFFF
#define SUPPLE_0_BIT	        0xF0FFFFFF
#define SUPPLE_1_BIT	        0x0FFFFFFF

/* Miscellaneous Values */
#define ZERO			0x0

#ifdef	CONFIG_HHBF
#define RAM_LENGTH		(CONFIG_MEM_SIZE * 1024 * 1024)
#define RAM_END			0x02000000  /* 0x04000000 */
#endif	/* comment by mhfan */

/****************************** EBIU Settings ********************************/
#define AMBCTL0VAL	((CONFIG_BANK_1 << 16) | CONFIG_BANK_0)
#define AMBCTL1VAL	((CONFIG_BANK_3 << 16) | CONFIG_BANK_2)

#if (CONFIG_C_AMBEN_ALL)
#define V_AMBEN AMBEN_ALL
#endif
#if (CONFIG_C_AMBEN)
#define V_AMBEN 0x0
#endif
#if (CONFIG_C_AMBEN_B0)
#define V_AMBEN AMBEN_B0
#endif
#if (CONFIG_C_AMBEN_B0_B1)
#define V_AMBEN AMBEN_B0_B1
#endif
#if (CONFIG_C_AMBEN_B0_B1_B2)
#define V_AMBEN AMBEN_B0_B1_B2
#endif 
#if (CONFIG_C_AMCKEN)
#define V_AMCKEN AMCKEN 
#else    
#define V_AMCKEN 0x0
#endif
#if (CONFIG_C_CDPRIO)
#define V_CDPRIO 0x100
#else    
#define V_CDPRIO 0x0
#endif

#define AMGCTLVAL	(V_AMBEN | V_AMCKEN | V_CDPRIO | 0x00F2)

/******************************* PLL Settings ********************************/
#if (CONFIG_VCO_MULT < 0)
		#error "VCO Multiplier is less than 0. Please select a different value"
#endif

#if (CONFIG_VCO_MULT == 0)
		#error "VCO Multiplier should be greater than 0. Please select a different value"
#endif

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

#define MAX_VC	600000000

#if(CONFIG_VCO_HZ > MAX_VC)
		#error "VCO selected is more than maximum value. Please change the VCO multipler"
#endif	

#if (CONFIG_SCLK_HZ > 133000000)
		#error "Sclk value selected is more than maximum.Please select a proper value for SCLK multiplier"
#endif
	
#if (CONFIG_SCLK_HZ < 27000000)
		#error "Sclk value selected is less than minimum.Please select a proper value for SCLK multiplier"
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


#if 1 	/* comment by mhfan */
/* Event Vector Table Address */
#define EVT_EMULATION_ADDR      0xffe02000
#define EVT_RESET_ADDR          0xffe02004
#define EVT_NMI_ADDR            0xffe02008
#define EVT_EXCEPTION_ADDR      0xffe0200c
#define EVT_GLOBAL_INT_ENB_ADDR 0xffe02010
#define EVT_HARDWARE_ERROR_ADDR 0xffe02014
#define EVT_TIMER_ADDR          0xffe02018
#define EVT_IVG7_ADDR           0xffe0201c
#define EVT_IVG8_ADDR           0xffe02020
#define EVT_IVG9_ADDR           0xffe02024
#define EVT_IVG10_ADDR          0xffe02028
#define EVT_IVG11_ADDR          0xffe0202c
#define EVT_IVG12_ADDR          0xffe02030
#define EVT_IVG13_ADDR          0xffe02034
#define EVT_IVG14_ADDR          0xffe02038
#define EVT_IVG15_ADDR          0xffe0203c
#define EVT_OVERRIDE_ADDR       0xffe02100
#endif	/* comment by mhfan */

#endif  /* _BLKFin_H_  */
#endif	/* !defined __ADSPLPBLACKFIN__ */
