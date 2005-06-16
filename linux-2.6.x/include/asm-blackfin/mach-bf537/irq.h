/*
 * File: $Id$
 *
 *This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of this archive
 * for more details.
 *
 * Changed by HuTao Apr18, 2003
 *
 * Copyright was missing when I got the code so took from MIPS arch ...MaTed---
 * Copyright (C) 1994 by Waldorf GMBH, written by Ralf Baechle
 * Copyright (C) 1995, 96, 97, 98, 99, 2000, 2001 by Ralf Baechle
 *
 * Adapted for BlackFin (ADI) by Ted Ma <mated@sympatico.ca>
 * Copyright (c) 2002 Arcturus Networks Inc. (www.arcturusnetworks.com)
 * Copyright (c) 2002 Lineo, Inc. <mattw@lineo.com>
 *
 * Adapted for BlackFin BF533 by Bas Vermeulen <bas@buyways.nl>
 * Copyright (c) 2003 BuyWays B.V. (www.buyways.nl)
 * Copyright (c) 2004 LG Soft India.
 *
 * Adapted for BlackFin BF537 by Michael Hennerich <hennerich@blackfin.uclinux.org>
 * Copyright (c) 2005 Analog Devices Inc.
 *
 */

#ifndef _BF537_IRQ_H_
#define _BF537_IRQ_H_

/*
 * Interrupt source definitions
             Event Source    Core Event Name
Core        Emulation               **
 Events         (highest priority)  EMU         0
            Reset                   RST         1
            NMI                     NMI         2
            Exception               EVX         3
            Reserved                --          4
            Hardware Error          IVHW        5
            Core Timer              IVTMR       6 *

.....

            Software Interrupt 1    IVG14       31
            Software Interrupt 2    --
                 (lowest priority)  IVG15       32 *
 */


#define SYS_IRQS		41
#define NR_PERI_INTS    32

/* The ABSTRACT IRQ definitions */
/** the first seven of the following are fixed, the rest you change if you need to **/
#define	IRQ_EMU				0	/*Emulation*/
#define	IRQ_RST				1	/*reset*/
#define	IRQ_NMI				2	/*Non Maskable*/
#define	IRQ_EVX				3	/*Exception*/
#define	IRQ_UNUSED			4	/*- unused interrupt*/
#define	IRQ_HWERR			5	/*Hardware Error*/
#define	IRQ_CORETMR			6	/*Core timer*/

#define	IRQ_PLL_WAKEUP		7	/*PLL Wakeup Interrupt*/
#define	IRQ_DMA_ERROR		8	/*DMA Error (general)*/
#define	IRQ_PPI_ERROR		9	/*PPI Error Interrupt*/
#define	IRQ_CAN_ERROR		9	/*CAN Error Interrupt*/
#define	IRQ_MAC_ERROR		9	/*PPI Error Interrupt*/
#define	IRQ_SPORT0_ERROR	9 	/*SPORT0 Error Interrupt*/
#define	IRQ_SPORT1_ERROR	9	/*SPORT1 Error Interrupt*/
#define	IRQ_SPI_ERROR		9	/*SPI Error Interrupt*/
#define	IRQ_UART0_ERROR		9	/*UART Error Interrupt*/
#define	IRQ_UART1_ERROR		9	/*UART Error Interrupt*/
#define	IRQ_RTC				10	/*RTC Interrupt*/
#define	IRQ_PPI				11	/*DMA0 Interrupt (PPI)*/
#define	IRQ_SPORT0_RX		12	/*DMA3 Interrupt (SPORT0 RX)*/
#define	IRQ_SPORT0_TX		13	/*DMA4 Interrupt (SPORT0 TX)*/
#define	IRQ_SPORT1_RX		14	/*DMA5 Interrupt (SPORT1 RX)*/
#define	IRQ_SPORT1_TX		15	/*DMA6 Interrupt (SPORT1 TX)*/
#define IRQ_TWI				16	/*TWI Interrupt*/
#define IRQ_SPI				17	/*DMA7 Interrupt (SPI)*/
#define	IRQ_UART0_RX		18	/*DMA8 Interrupt (UART0 RX)*/
#define	IRQ_UART0_TX		19	/*DMA9 Interrupt (UART0 TX)*/
#define	IRQ_UART1_RX		20	/*DMA10 Interrupt (UART1 RX)*/
#define	IRQ_UART1_TX		21	/*DMA11 Interrupt (UART1 TX)*/
#define	IRQ_CAN_RX			22	/*CAN Receive Interrupt*/
#define	IRQ_CAN_TX			23	/*CAN Transmit Interrupt*/
#define	IRQ_MAC_RX			24  /*DMA1 (Ethernet RX) Interrupt*/
#define	IRQ_MAC_TX			25  /*DMA2 (Ethernet TX) Interrupt*/
#define	IRQ_TMR0			26	/*Timer 0*/
#define	IRQ_TMR1			27	/*Timer 1*/
#define	IRQ_TMR2			28	/*Timer 2*/
#define	IRQ_TMR3			29	/*Timer 3*/
#define	IRQ_TMR4			30	/*Timer 4*/
#define	IRQ_TMR5			31	/*Timer 5*/
#define	IRQ_TMR6			32	/*Timer 6*/
#define	IRQ_TMR7			33	/*Timer 7*/
#define	IRQ_PROG_INTA		34	/* PF Ports F&G (PF31:0) Interrupt A*/
#define	IRQ_PROG_INTB		35	/* PF Port F (PF15:0) Interrupt B*/
#define	IRQ_MEM_DMA0		36	/*(Memory DMA Stream 0)*/
#define	IRQ_MEM_DMA1		37	/*(Memory DMA Stream 1)*/
#define	IRQ_WATCH	   		38	/*Watch Dog Timer*/
#define IRQ_PFB_PORTG		39  /*PF Port G (PF31:16) Interrupt B 	*/

#define	IRQ_SW_INT1			40	/*Software Int 1*/
#define	IRQ_SW_INT2			41	/*Software Int 2 (reserved for SYSCALL)*/

#define IRQ_PF0			33
#define IRQ_PF1			34
#define IRQ_PF2			35
#define IRQ_PF3			36
#define IRQ_PF4			37
#define IRQ_PF5			38
#define IRQ_PF6			39
#define IRQ_PF7			40
#define IRQ_PF8			41
#define IRQ_PF9			42
#define IRQ_PF10		43
#define IRQ_PF11		44
#define IRQ_PF12		45
#define IRQ_PF13		46
#define IRQ_PF14		47
#define IRQ_PF15		48

#ifdef CONFIG_IRQCHIP_DEMUX_GPIO
#define	NR_IRQS		(IRQ_PF15+1)
#else
#define	NR_IRQS		SYS_IRQS
#endif


#define IVG7			7
#define IVG8			8
#define IVG9			9
#define IVG10			10
#define IVG11			11
#define IVG12			12
#define IVG13			13
#define IVG14			14
#define IVG15			15

/* IAR0 BIT FIELDS*/
#define	IRQ_PLL_WAKEUP_POS	0
#define	IRQ_DMA_ERROR_POS   4
#define	IRQ_ERROR_POS       8
#define	IRQ_RTC_POS         12
#define	IRQ_PPI_POS         16
#define	IRQ_SPORT0_RX_POS   20
#define	IRQ_SPORT0_TX_POS   24
#define	IRQ_SPORT1_RX_POS   28

/* IAR1 BIT FIELDS*/
#define	IRQ_SPORT1_TX_POS	0
#define IRQ_TWI_POS         4
#define IRQ_SPI_POS         8
#define	IRQ_UART0_RX_POS    12
#define	IRQ_UART0_TX_POS    16
#define	IRQ_UART1_RX_POS    20
#define	IRQ_UART1_TX_POS    24
#define	IRQ_CAN_RX_POS      28

/* IAR2 BIT FIELDS*/
#define	IRQ_CAN_TX_POS		0
#define	IRQ_MAC_RX_POS      4
#define	IRQ_MAC_TX_POS      8
#define	IRQ_TMR0_POS        12
#define	IRQ_TMR1_POS        16
#define	IRQ_TMR2_POS        20
#define	IRQ_TMR3_POS        24
#define	IRQ_TMR4_POS        28

/* IAR3 BIT FIELDS*/
#define	IRQ_TMR5_POS		0
#define	IRQ_TMR6_POS        4
#define	IRQ_TMR7_POS        8
#define	IRQ_PROG_INTA_POS   12
#define	IRQ_PROG_INTB_POS   16
#define	IRQ_MEM_DMA0_POS    20
#define	IRQ_MEM_DMA1_POS    24
#define	IRQ_WATCH_POS       28

#endif /* _BF537_IRQ_H_ */
