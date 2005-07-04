/*****************************************************************************
* $Id$
*
*        BF-537/6/4 Specific Declarations
*
****************************************************************************/

#ifndef _MACH_DMA_H_
#define _MACH_DMA_H_


#define MAX_BLACKFIN_DMA_CHANNEL 16

#define CH_PPI 			    0
#define CH_EMAC_RX 		    1
#define CH_EMAC_TX 		    2
#define CH_SPORT0_RX 		3
#define CH_SPORT0_TX 		4
#define CH_SPORT1_RX 		5
#define CH_SPORT1_TX 		6
#define CH_SPI 			    7
#define CH_UART0_RX 		8
#define CH_UART0_TX 		9
#define CH_UART1_RX 		10
#define CH_UART1_TX 		11

#define CH_MEM_STREAM0_DEST	12	// TX
#define CH_MEM_STREAM0_SRC  13  // RX
#define CH_MEM_STREAM1_DEST	14	// TX
#define CH_MEM_STREAM1_SRC 	15 	// RX

#endif
