/*
 * Common header file for blackfin family of processors.
 *
 */

#ifndef _MACH_BLACKFIN_H_
#define _MACH_BLACKFIN_H_


#include "bf537.h"
#include "mem_map.h"
#include "defBF534.h"

#if CONFIG_BF537
#include "defBF537.h"
#endif



#if !(defined(__ASSEMBLY__) || defined(ASSEMBLY))
#include "cdefBF534.h"

/* UART 0*/
#define pUART_THR pUART0_THR
#define pUART_RBR pUART0_RBR
#define pUART_DLL pUART0_DLL
#define pUART_IER pUART0_IER
#define pUART_DLH pUART0_DLH
#define pUART_IIR pUART0_IIR
#define pUART_LCR pUART0_LCR
#define pUART_MCR pUART0_MCR
#define pUART_LSR pUART0_LSR
#define pUART_SCR  pUART0_SCR
#define pUART_GCTL pUART0_GCTL

#if CONFIG_BF537
#include "cdefBF537.h"
#endif
#endif

/* MAP used DEFINES from BF533 to BF537 - so we don't need to change them in the driver, kernel, etc. */

/* UART_IIR Register */
#define STATUS(x)	((x << 1) & 0x06)
#define STATUS_P1	0x02
#define STATUS_P0	0x01

/* UART 0*/

/* DMA Channnel */
#define CH_UART_RX CH_UART0_RX
#define CH_UART_TX CH_UART0_TX

/* System Interrupt Controller */
#define IRQ_UART_RX IRQ_UART0_RX
#define	IRQ_UART_TX IRQ_UART0_TX
#define	IRQ_UART_ERROR IRQ_UART0_ERROR

/* MMR Registers*/
#define UART_THR UART0_THR
#define UART_RBR UART0_RBR
#define UART_DLL UART0_DLL
#define UART_IER UART0_IER
#define UART_DLH UART0_DLH
#define UART_IIR UART0_IIR
#define UART_LCR UART0_LCR
#define UART_MCR UART0_MCR
#define UART_LSR UART0_LSR
#define UART_SCR  UART0_SCR
#define UART_GCTL UART0_GCTL


/* DPMC*/
#define STOPCK_OFF STOPCK

/* FIO USE PORT F*/
#if CONFIG_BF537_PORT_F
#define pFIO_FLAG_D		pPORTFIO
#define pFIO_FLAG_C		pPORTFIO_CLEAR
#define pFIO_FLAG_S		pPORTFIO_SET
#define pFIO_FLAG_T		pPORTFIO_TOGGLE
#define pFIO_MASKA_D	pPORTFIO_MASKA
#define pFIO_MASKA_C	pPORTFIO_MASKA_CLEAR
#define pFIO_MASKA_S	pPORTFIO_MASKA_SET
#define pFIO_MASKA_T	pPORTFIO_MASKA_TOGGLE
#define pFIO_MASKB_D	pPORTFIO_MASKB
#define pFIO_MASKB_C	pPORTFIO_MASKB_CLEAR
#define pFIO_MASKB_S	pPORTFIO_MASKB_SET
#define pFIO_MASKB_T	pPORTFIO_MASKB_TOGGLE
#define pFIO_DIR		pPORTFIO_DIR
#define pFIO_POLAR		pPORTFIO_POLAR
#define pFIO_EDGE		pPORTFIO_EDGE
#define pFIO_BOTH		pPORTFIO_BOTH
#define pFIO_INEN		pPORTFIO_INEN
#endif

/* FIO USE PORT G*/
#if CONFIG_BF537_PORT_G
#define pFIO_FLAG_D		pPORTGIO
#define pFIO_FLAG_C		pPORTGIO_CLEAR
#define pFIO_FLAG_S		pPORTGIO_SET
#define pFIO_FLAG_T		pPORTGIO_TOGGLE
#define pFIO_MASKA_D	pPORTGIO_MASKA
#define pFIO_MASKA_C	pPORTGIO_MASKA_CLEAR
#define pFIO_MASKA_S	pPORTGIO_MASKA_SET
#define pFIO_MASKA_T	pPORTGIO_MASKA_TOGGLE
#define pFIO_MASKB_D	pPORTGIO_MASKB
#define pFIO_MASKB_C	pPORTGIO_MASKB_CLEAR
#define pFIO_MASKB_S	pPORTGIO_MASKB_SET
#define pFIO_MASKB_T	pPORTGIO_MASKB_TOGGLE
#define pFIO_DIR		pPORTGIO_DIR
#define pFIO_POLAR		pPORTGIO_POLAR
#define pFIO_EDGE		pPORTGIO_EDGE
#define pFIO_BOTH		pPORTGIO_BOTH
#define pFIO_INEN		pPORTGIO_INEN
#endif


/* RTC_ICTL and RTC_ISTAT Masks															    */                                                      
#define	SWEF  STOPWATCH		  /* Stopwatch Interrupt Enable									*/      
#define	AEF	  ALARM			  /* Alarm Interrupt Enable										*/      
#define	SEF	  SECOND		  /* Seconds (1 Hz) Interrupt Enable							*/
#define	MEF	  MINUTE		  /* Minutes Interrupt Enable									*/
#define	HEF	  HOUR			  /* Hours Interrupt Enable										*/      
#define	DEF	  DAY			  /* 24 Hours (Days) Interrupt Enable							*/
#define	DAEF  DAY_ALARM		  /* Day Alarm (Day, Hour, Minute, Second) Interrupt Enable		*/      
#define	WPS	  WRITE_PENDING	  /* Write Pending Status										*/  
#define	WCOM  WRITE_COMPLETE  /* Write Complete Interrupt Enable							*/  


/* PLL_DIV Masks													*/
#define CCLK_DIV1 CSEL_DIV1 /* 		CCLK = VCO / 1					*/
#define CCLK_DIV2 CSEL_DIV2 /* 		CCLK = VCO / 2					*/
#define CCLK_DIV4 CSEL_DIV4 /* 		CCLK = VCO / 4					*/
#define CCLK_DIV8 CSEL_DIV8 /* 		CCLK = VCO / 8					*/

#endif
