/*
 * $Id$
 *
 * arch/blackfin/mach-bf533/ints-priority.c
 *
 */

#include <linux/module.h>
#include <asm/blackfin.h>
#include <asm/irq.h>

void program_IAR(void);
/*Program the IAR registers*/

void program_IAR(void)
{
		/* Program the IAR0 Register with the configured priority */
	        *pSIC_IAR0 =  ((CONFIG_PLLWAKE_ERROR-7) << PLLWAKE_ERROR_POS) |
                ((CONFIG_DMA_ERROR   -7) <<    DMA_ERROR_POS) |
                ((CONFIG_PPI_ERROR   -7) <<    PPI_ERROR_POS) |
                ((CONFIG_SPORT0_ERROR-7) << SPORT0_ERROR_POS) |
                ((CONFIG_SPI_ERROR   -7) <<    SPI_ERROR_POS) |
                ((CONFIG_SPORT1_ERROR-7) << SPORT1_ERROR_POS) |
                ((CONFIG_UART_ERROR  -7) <<   UART_ERROR_POS) |
                ((CONFIG_RTC_ERROR   -7) <<    RTC_ERROR_POS);	

		*pSIC_IAR1 =	((CONFIG_DMA0_PPI-7)    << DMA0_PPI_POS) |
                ((CONFIG_DMA1_SPORT0RX-7) << DMA1_SPORT0RX_POS) |
                ((CONFIG_DMA2_SPORT0TX-7) << DMA2_SPORT0TX_POS) |
                ((CONFIG_DMA3_SPORT1RX-7) << DMA3_SPORT1RX_POS) |
                ((CONFIG_DMA4_SPORT1TX-7) << DMA4_SPORT1TX_POS) |
                ((CONFIG_DMA5_SPI-7)    << DMA5_SPI_POS)    |
                ((CONFIG_DMA6_UARTRX-7) << DMA6_UARTRX_POS) |
                ((CONFIG_DMA7_UARTTX-7) << DMA7_UARTTX_POS);
 
		*pSIC_IAR2 =	((CONFIG_TIMER0-7) << TIMER0_POS) |
		((CONFIG_TIMER1-7) << TIMER1_POS) |
		((CONFIG_TIMER2-7) << TIMER2_POS) |
		((CONFIG_PFA-7) << PFA_POS) |
		((CONFIG_PFB-7) << PFB_POS) |
		((CONFIG_MEMDMA0-7) << MEMDMA0_POS) |
		((CONFIG_MEMDMA1-7) << MEMDMA1_POS) |
		((CONFIG_WDTIMER-7) << WDTIMER_POS);
	        __builtin_bfin_ssync();
};	/*End of program_IAR*/
