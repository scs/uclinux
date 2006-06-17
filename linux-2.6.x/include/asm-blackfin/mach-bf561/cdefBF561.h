
/*  */
/*
 * File:         include/asm-blackfin/mach-bf561/cdefBF561.h
 * Based on:
 * Author:
 *
 * Created:
 * Description:
 * C POINTERS TO SYSTEM MMR REGISTER AND MEMORY MAP FOR ADSP-BF561
 * Rev:
 *
 * Modified:
 *
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.
 * If not, write to the Free Software Foundation,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef _CDEF_BF561_H
#define _CDEF_BF561_H

/*
#if !defined(__ADSPBF561__)
#warning cdefBF561.h should only be included for BF561 chip.
#endif
*/
/* include all Core registers and bit definitions */
#include "defBF561.h"

/*include core specific register pointer definitions*/
#include <asm/mach-common/cdef_LPBlackfin.h>

/*********************************************************************************** */
/* System MMR Register Map */
/*********************************************************************************** */

/* Clock and System Control (0xFFC00000 - 0xFFC000FF) */
#define pPLL_CTL (volatile unsigned short *)PLL_CTL
#define bfin_read_PLL_CTL()                  bfin_read16(PLL_CTL)
#define bfin_write_PLL_CTL(val)              bfin_write16(PLL_CTL,val)
#define pPLL_DIV (volatile unsigned short *)PLL_DIV
#define bfin_read_PLL_DIV()                  bfin_read16(PLL_DIV)
#define bfin_write_PLL_DIV(val)              bfin_write16(PLL_DIV,val)
#define pVR_CTL (volatile unsigned short *)VR_CTL
#define bfin_read_VR_CTL()                   bfin_read16(VR_CTL)
#define bfin_write_VR_CTL(val)               bfin_write16(VR_CTL,val)
#define pPLL_STAT (volatile unsigned short *)PLL_STAT
#define bfin_read_PLL_STAT()                 bfin_read16(PLL_STAT)
#define bfin_write_PLL_STAT(val)             bfin_write16(PLL_STAT,val)
#define pPLL_LOCKCNT (volatile unsigned short *)PLL_LOCKCNT
#define bfin_read_PLL_LOCKCNT()              bfin_read16(PLL_LOCKCNT)
#define bfin_write_PLL_LOCKCNT(val)          bfin_write16(PLL_LOCKCNT,val)

/* System Reset and Interrupt Controller registers for core A (0xFFC0 0100-0xFFC0 01FF) */
#define pSICA_SWRST (volatile unsigned short *)SICA_SWRST
#define bfin_read_SICA_SWRST()               bfin_read16(SICA_SWRST)
#define bfin_write_SICA_SWRST(val)           bfin_write16(SICA_SWRST,val)
#define pSICA_SYSCR (volatile unsigned short *)SICA_SYSCR
#define bfin_read_SICA_SYSCR()               bfin_read16(SICA_SYSCR)
#define bfin_write_SICA_SYSCR(val)           bfin_write16(SICA_SYSCR,val)
#define pSICA_RVECT (volatile unsigned short *)SICA_RVECT
#define bfin_read_SICA_RVECT()               bfin_read16(SICA_RVECT)
#define bfin_write_SICA_RVECT(val)           bfin_write16(SICA_RVECT,val)
#define pSICA_IMASK (volatile unsigned long *)SICA_IMASK
#define bfin_read_SICA_IMASK()               bfin_read32(SICA_IMASK)
#define bfin_write_SICA_IMASK(val)           bfin_write32(SICA_IMASK,val)
#define pSICA_IMASK0 (volatile unsigned long *)SICA_IMASK0
#define bfin_read_SICA_IMASK0()              bfin_read32(SICA_IMASK0)
#define bfin_write_SICA_IMASK0(val)          bfin_write32(SICA_IMASK0,val)
#define pSICA_IMASK1 (volatile unsigned long *)SICA_IMASK1
#define bfin_read_SICA_IMASK1()              bfin_read32(SICA_IMASK1)
#define bfin_write_SICA_IMASK1(val)          bfin_write32(SICA_IMASK1,val)
#define pSICA_IAR0 ((volatile unsigned long *)SICA_IAR0)
#define bfin_read_SICA_IAR0()                bfin_read32(SICA_IAR0)
#define bfin_write_SICA_IAR0(val)            bfin_write32(SICA_IAR0,val)
#define pSICA_IAR1 (volatile unsigned long *)SICA_IAR1
#define bfin_read_SICA_IAR1()                bfin_read32(SICA_IAR1)
#define bfin_write_SICA_IAR1(val)            bfin_write32(SICA_IAR1,val)
#define pSICA_IAR2 (volatile unsigned long *)SICA_IAR2
#define bfin_read_SICA_IAR2()                bfin_read32(SICA_IAR2)
#define bfin_write_SICA_IAR2(val)            bfin_write32(SICA_IAR2,val)
#define pSICA_IAR3 (volatile unsigned long *)SICA_IAR3
#define bfin_read_SICA_IAR3()                bfin_read32(SICA_IAR3)
#define bfin_write_SICA_IAR3(val)            bfin_write32(SICA_IAR3,val)
#define pSICA_IAR4 (volatile unsigned long *)SICA_IAR4
#define bfin_read_SICA_IAR4()                bfin_read32(SICA_IAR4)
#define bfin_write_SICA_IAR4(val)            bfin_write32(SICA_IAR4,val)
#define pSICA_IAR5 (volatile unsigned long *)SICA_IAR5
#define bfin_read_SICA_IAR5()                bfin_read32(SICA_IAR5)
#define bfin_write_SICA_IAR5(val)            bfin_write32(SICA_IAR5,val)
#define pSICA_IAR6 (volatile unsigned long *)SICA_IAR6
#define bfin_read_SICA_IAR6()                bfin_read32(SICA_IAR6)
#define bfin_write_SICA_IAR6(val)            bfin_write32(SICA_IAR6,val)
#define pSICA_IAR7 (volatile unsigned long *)SICA_IAR7
#define bfin_read_SICA_IAR7()                bfin_read32(SICA_IAR7)
#define bfin_write_SICA_IAR7(val)            bfin_write32(SICA_IAR7,val)
#define pSICA_ISR0 (volatile unsigned long *)SICA_ISR0
#define bfin_read_SICA_ISR0()                bfin_read32(SICA_ISR0)
#define bfin_write_SICA_ISR0(val)            bfin_write32(SICA_ISR0,val)
#define pSICA_ISR1 (volatile unsigned long *)SICA_ISR1
#define bfin_read_SICA_ISR1()                bfin_read32(SICA_ISR1)
#define bfin_write_SICA_ISR1(val)            bfin_write32(SICA_ISR1,val)
#define pSICA_IWR0 (volatile unsigned long *)SICA_IWR0
#define bfin_read_SICA_IWR0()                bfin_read32(SICA_IWR0)
#define bfin_write_SICA_IWR0(val)            bfin_write32(SICA_IWR0,val)
#define pSICA_IWR1 (volatile unsigned long *)SICA_IWR1
#define bfin_read_SICA_IWR1()                bfin_read32(SICA_IWR1)
#define bfin_write_SICA_IWR1(val)            bfin_write32(SICA_IWR1,val)

/* System Reset and Interrupt Controller registers for Core B (0xFFC0 1100-0xFFC0 11FF) */
#define pSICB_SWRST (volatile unsigned short *)SICB_SWRST
#define bfin_read_SICB_SWRST()               bfin_read16(SICB_SWRST)
#define bfin_write_SICB_SWRST(val)           bfin_write16(SICB_SWRST,val)
#define pSICB_SYSCR (volatile unsigned short *)SICB_SYSCR
#define bfin_read_SICB_SYSCR()               bfin_read16(SICB_SYSCR)
#define bfin_write_SICB_SYSCR(val)           bfin_write16(SICB_SYSCR,val)
#define pSICB_RVECT (volatile unsigned short *)SICB_RVECT
#define bfin_read_SICB_RVECT()               bfin_read16(SICB_RVECT)
#define bfin_write_SICB_RVECT(val)           bfin_write16(SICB_RVECT,val)
#define pSICB_IMASK0 (volatile unsigned long *)SICB_IMASK0
#define bfin_read_SICB_IMASK0()              bfin_read32(SICB_IMASK0)
#define bfin_write_SICB_IMASK0(val)          bfin_write32(SICB_IMASK0,val)
#define pSICB_IMASK1 (volatile unsigned long *)SICB_IMASK1
#define bfin_read_SICB_IMASK1()              bfin_read32(SICB_IMASK1)
#define bfin_write_SICB_IMASK1(val)          bfin_write32(SICB_IMASK1,val)
#define pSICB_IAR0 (volatile unsigned long *)SICB_IAR0
#define bfin_read_SICB_IAR0()                bfin_read32(SICB_IAR0)
#define bfin_write_SICB_IAR0(val)            bfin_write32(SICB_IAR0,val)
#define pSICB_IAR1 (volatile unsigned long *)SICB_IAR1
#define bfin_read_SICB_IAR1()                bfin_read32(SICB_IAR1)
#define bfin_write_SICB_IAR1(val)            bfin_write32(SICB_IAR1,val)
#define pSICB_IAR2 (volatile unsigned long *)SICB_IAR2
#define bfin_read_SICB_IAR2()                bfin_read32(SICB_IAR2)
#define bfin_write_SICB_IAR2(val)            bfin_write32(SICB_IAR2,val)
#define pSICB_IAR3 (volatile unsigned long *)SICB_IAR3
#define bfin_read_SICB_IAR3()                bfin_read32(SICB_IAR3)
#define bfin_write_SICB_IAR3(val)            bfin_write32(SICB_IAR3,val)
#define pSICB_IAR4 (volatile unsigned long *)SICB_IAR4
#define bfin_read_SICB_IAR4()                bfin_read32(SICB_IAR4)
#define bfin_write_SICB_IAR4(val)            bfin_write32(SICB_IAR4,val)
#define pSICB_IAR5 (volatile unsigned long *)SICB_IAR5
#define bfin_read_SICB_IAR5()                bfin_read32(SICB_IAR5)
#define bfin_write_SICB_IAR5(val)            bfin_write32(SICB_IAR5,val)
#define pSICB_IAR6 (volatile unsigned long *)SICB_IAR6
#define bfin_read_SICB_IAR6()                bfin_read32(SICB_IAR6)
#define bfin_write_SICB_IAR6(val)            bfin_write32(SICB_IAR6,val)
#define pSICB_IAR7 (volatile unsigned long *)SICB_IAR7
#define bfin_read_SICB_IAR7()                bfin_read32(SICB_IAR7)
#define bfin_write_SICB_IAR7(val)            bfin_write32(SICB_IAR7,val)
#define pSICB_ISR0 (volatile unsigned long *)SICB_ISR0
#define bfin_read_SICB_ISR0()                bfin_read32(SICB_ISR0)
#define bfin_write_SICB_ISR0(val)            bfin_write32(SICB_ISR0,val)
#define pSICB_ISR1 (volatile unsigned long *)SICB_ISR1
#define bfin_read_SICB_ISR1()                bfin_read32(SICB_ISR1)
#define bfin_write_SICB_ISR1(val)            bfin_write32(SICB_ISR1,val)
#define pSICB_IWR0 (volatile unsigned long *)SICB_IWR0
#define bfin_read_SICB_IWR0()                bfin_read32(SICB_IWR0)
#define bfin_write_SICB_IWR0(val)            bfin_write32(SICB_IWR0,val)
#define pSICB_IWR1 (volatile unsigned long *)SICB_IWR1
#define bfin_read_SICB_IWR1()                bfin_read32(SICB_IWR1)
#define bfin_write_SICB_IWR1(val)            bfin_write32(SICB_IWR1,val)
/* Watchdog Timer registers for Core A (0xFFC0 0200-0xFFC0 02FF) */
#define pWDOGA_CTL (volatile unsigned short *)WDOGA_CTL
#define bfin_read_WDOGA_CTL()                bfin_read16(WDOGA_CTL)
#define bfin_write_WDOGA_CTL(val)            bfin_write16(WDOGA_CTL,val)
#define pWDOGA_CNT (volatile unsigned long *)WDOGA_CNT
#define bfin_read_WDOGA_CNT()                bfin_read32(WDOGA_CNT)
#define bfin_write_WDOGA_CNT(val)            bfin_write32(WDOGA_CNT,val)
#define pWDOGA_STAT (volatile unsigned long *)WDOGA_STAT
#define bfin_read_WDOGA_STAT()               bfin_read32(WDOGA_STAT)
#define bfin_write_WDOGA_STAT(val)           bfin_write32(WDOGA_STAT,val)

/* Watchdog Timer registers for Core B (0xFFC0 1200-0xFFC0 12FF) */
#define pWDOGB_CTL (volatile unsigned short *)WDOGB_CTL
#define bfin_read_WDOGB_CTL()                bfin_read16(WDOGB_CTL)
#define bfin_write_WDOGB_CTL(val)            bfin_write16(WDOGB_CTL,val)
#define pWDOGB_CNT (volatile unsigned long *)WDOGB_CNT
#define bfin_read_WDOGB_CNT()                bfin_read32(WDOGB_CNT)
#define bfin_write_WDOGB_CNT(val)            bfin_write32(WDOGB_CNT,val)
#define pWDOGB_STAT (volatile unsigned long *)WDOGB_STAT
#define bfin_read_WDOGB_STAT()               bfin_read32(WDOGB_STAT)
#define bfin_write_WDOGB_STAT(val)           bfin_write32(WDOGB_STAT,val)

/* UART Controller (0xFFC00400 - 0xFFC004FF) */
#define pUART_THR (volatile unsigned short *)UART_THR
#define bfin_read_UART_THR()                 bfin_read16(UART_THR)
#define bfin_write_UART_THR(val)             bfin_write16(UART_THR,val)
#define pUART_RBR (volatile unsigned short *)UART_RBR
#define bfin_read_UART_RBR()                 bfin_read16(UART_RBR)
#define bfin_write_UART_RBR(val)             bfin_write16(UART_RBR,val)
#define pUART_DLL (volatile unsigned short *)UART_DLL
#define bfin_read_UART_DLL()                 bfin_read16(UART_DLL)
#define bfin_write_UART_DLL(val)             bfin_write16(UART_DLL,val)
#define pUART_IER (volatile unsigned short *)UART_IER
#define bfin_read_UART_IER()                 bfin_read16(UART_IER)
#define bfin_write_UART_IER(val)             bfin_write16(UART_IER,val)
#define pUART_DLH (volatile unsigned short *)UART_DLH
#define bfin_read_UART_DLH()                 bfin_read16(UART_DLH)
#define bfin_write_UART_DLH(val)             bfin_write16(UART_DLH,val)
#define pUART_IIR (volatile unsigned short *)UART_IIR
#define bfin_read_UART_IIR()                 bfin_read16(UART_IIR)
#define bfin_write_UART_IIR(val)             bfin_write16(UART_IIR,val)
#define pUART_LCR (volatile unsigned short *)UART_LCR
#define bfin_read_UART_LCR()                 bfin_read16(UART_LCR)
#define bfin_write_UART_LCR(val)             bfin_write16(UART_LCR,val)
#define pUART_MCR (volatile unsigned short *)UART_MCR
#define bfin_read_UART_MCR()                 bfin_read16(UART_MCR)
#define bfin_write_UART_MCR(val)             bfin_write16(UART_MCR,val)
#define pUART_LSR (volatile unsigned short *)UART_LSR
#define bfin_read_UART_LSR()                 bfin_read16(UART_LSR)
#define bfin_write_UART_LSR(val)             bfin_write16(UART_LSR,val)
#define pUART_MSR (volatile unsigned short *)UART_MSR
#define bfin_read_UART_MSR()                 bfin_read16(UART_MSR)
#define bfin_write_UART_MSR(val)             bfin_write16(UART_MSR,val)
#define pUART_SCR (volatile unsigned short *)UART_SCR
#define bfin_read_UART_SCR()                 bfin_read16(UART_SCR)
#define bfin_write_UART_SCR(val)             bfin_write16(UART_SCR,val)
#define pUART_GCTL (volatile unsigned short *)UART_GCTL
#define bfin_read_UART_GCTL()                bfin_read16(UART_GCTL)
#define bfin_write_UART_GCTL(val)            bfin_write16(UART_GCTL,val)

/* SPI Controller (0xFFC00500 - 0xFFC005FF) */
#define pSPI_CTL (volatile unsigned short *)SPI_CTL
#define bfin_read_SPI_CTL()                  bfin_read16(SPI_CTL)
#define bfin_write_SPI_CTL(val)              bfin_write16(SPI_CTL,val)
#define pSPI_FLG (volatile unsigned short *)SPI_FLG
#define bfin_read_SPI_FLG()                  bfin_read16(SPI_FLG)
#define bfin_write_SPI_FLG(val)              bfin_write16(SPI_FLG,val)
#define pSPI_STAT (volatile unsigned short *)SPI_STAT
#define bfin_read_SPI_STAT()                 bfin_read16(SPI_STAT)
#define bfin_write_SPI_STAT(val)             bfin_write16(SPI_STAT,val)
#define pSPI_TDBR (volatile unsigned short *)SPI_TDBR
#define bfin_read_SPI_TDBR()                 bfin_read16(SPI_TDBR)
#define bfin_write_SPI_TDBR(val)             bfin_write16(SPI_TDBR,val)
#define pSPI_RDBR (volatile unsigned short *)SPI_RDBR
#define bfin_read_SPI_RDBR()                 bfin_read16(SPI_RDBR)
#define bfin_write_SPI_RDBR(val)             bfin_write16(SPI_RDBR,val)
#define pSPI_BAUD (volatile unsigned short *)SPI_BAUD
#define bfin_read_SPI_BAUD()                 bfin_read16(SPI_BAUD)
#define bfin_write_SPI_BAUD(val)             bfin_write16(SPI_BAUD,val)
#define pSPI_SHADOW (volatile unsigned short *)SPI_SHADOW
#define bfin_read_SPI_SHADOW()               bfin_read16(SPI_SHADOW)
#define bfin_write_SPI_SHADOW(val)           bfin_write16(SPI_SHADOW,val)

/* Timer 0-7 registers (0xFFC0 0600-0xFFC0 06FF) */
#define pTIMER0_CONFIG (volatile unsigned short *)TIMER0_CONFIG
#define bfin_read_TIMER0_CONFIG()            bfin_read16(TIMER0_CONFIG)
#define bfin_write_TIMER0_CONFIG(val)        bfin_write16(TIMER0_CONFIG,val)
#define pTIMER0_COUNTER (volatile unsigned long *)TIMER0_COUNTER
#define bfin_read_TIMER0_COUNTER()           bfin_read32(TIMER0_COUNTER)
#define bfin_write_TIMER0_COUNTER(val)       bfin_write32(TIMER0_COUNTER,val)
#define pTIMER0_PERIOD (volatile unsigned long *)TIMER0_PERIOD
#define bfin_read_TIMER0_PERIOD()            bfin_read32(TIMER0_PERIOD)
#define bfin_write_TIMER0_PERIOD(val)        bfin_write32(TIMER0_PERIOD,val)
#define pTIMER0_WIDTH (volatile unsigned long *)TIMER0_WIDTH
#define bfin_read_TIMER0_WIDTH()             bfin_read32(TIMER0_WIDTH)
#define bfin_write_TIMER0_WIDTH(val)         bfin_write32(TIMER0_WIDTH,val)
#define pTIMER1_CONFIG (volatile unsigned short *)TIMER1_CONFIG
#define bfin_read_TIMER1_CONFIG()            bfin_read16(TIMER1_CONFIG)
#define bfin_write_TIMER1_CONFIG(val)        bfin_write16(TIMER1_CONFIG,val)
#define pTIMER1_COUNTER (volatile unsigned long *)TIMER1_COUNTER
#define bfin_read_TIMER1_COUNTER()           bfin_read32(TIMER1_COUNTER)
#define bfin_write_TIMER1_COUNTER(val)       bfin_write32(TIMER1_COUNTER,val)
#define pTIMER1_PERIOD (volatile unsigned long *)TIMER1_PERIOD
#define bfin_read_TIMER1_PERIOD()            bfin_read32(TIMER1_PERIOD)
#define bfin_write_TIMER1_PERIOD(val)        bfin_write32(TIMER1_PERIOD,val)
#define pTIMER1_WIDTH (volatile unsigned long *)TIMER1_WIDTH
#define bfin_read_TIMER1_WIDTH()             bfin_read32(TIMER1_WIDTH)
#define bfin_write_TIMER1_WIDTH(val)         bfin_write32(TIMER1_WIDTH,val)
#define pTIMER2_CONFIG (volatile unsigned short *)TIMER2_CONFIG
#define bfin_read_TIMER2_CONFIG()            bfin_read16(TIMER2_CONFIG)
#define bfin_write_TIMER2_CONFIG(val)        bfin_write16(TIMER2_CONFIG,val)
#define pTIMER2_COUNTER (volatile unsigned long *)TIMER2_COUNTER
#define bfin_read_TIMER2_COUNTER()           bfin_read32(TIMER2_COUNTER)
#define bfin_write_TIMER2_COUNTER(val)       bfin_write32(TIMER2_COUNTER,val)
#define pTIMER2_PERIOD (volatile unsigned long *)TIMER2_PERIOD
#define bfin_read_TIMER2_PERIOD()            bfin_read32(TIMER2_PERIOD)
#define bfin_write_TIMER2_PERIOD(val)        bfin_write32(TIMER2_PERIOD,val)
#define pTIMER2_WIDTH (volatile unsigned long *)TIMER2_WIDTH
#define bfin_read_TIMER2_WIDTH()             bfin_read32(TIMER2_WIDTH)
#define bfin_write_TIMER2_WIDTH(val)         bfin_write32(TIMER2_WIDTH,val)
#define pTIMER3_CONFIG (volatile unsigned short *)TIMER3_CONFIG
#define bfin_read_TIMER3_CONFIG()            bfin_read16(TIMER3_CONFIG)
#define bfin_write_TIMER3_CONFIG(val)        bfin_write16(TIMER3_CONFIG,val)
#define pTIMER3_COUNTER (volatile unsigned long *)TIMER3_COUNTER
#define bfin_read_TIMER3_COUNTER()           bfin_read32(TIMER3_COUNTER)
#define bfin_write_TIMER3_COUNTER(val)       bfin_write32(TIMER3_COUNTER,val)
#define pTIMER3_PERIOD (volatile unsigned long *)TIMER3_PERIOD
#define bfin_read_TIMER3_PERIOD()            bfin_read32(TIMER3_PERIOD)
#define bfin_write_TIMER3_PERIOD(val)        bfin_write32(TIMER3_PERIOD,val)
#define pTIMER3_WIDTH (volatile unsigned long *)TIMER3_WIDTH
#define bfin_read_TIMER3_WIDTH()             bfin_read32(TIMER3_WIDTH)
#define bfin_write_TIMER3_WIDTH(val)         bfin_write32(TIMER3_WIDTH,val)
#define pTIMER4_CONFIG (volatile unsigned short *)TIMER4_CONFIG
#define bfin_read_TIMER4_CONFIG()            bfin_read16(TIMER4_CONFIG)
#define bfin_write_TIMER4_CONFIG(val)        bfin_write16(TIMER4_CONFIG,val)
#define pTIMER4_COUNTER (volatile unsigned long *)TIMER4_COUNTER
#define bfin_read_TIMER4_COUNTER()           bfin_read32(TIMER4_COUNTER)
#define bfin_write_TIMER4_COUNTER(val)       bfin_write32(TIMER4_COUNTER,val)
#define pTIMER4_PERIOD (volatile unsigned long *)TIMER4_PERIOD
#define bfin_read_TIMER4_PERIOD()            bfin_read32(TIMER4_PERIOD)
#define bfin_write_TIMER4_PERIOD(val)        bfin_write32(TIMER4_PERIOD,val)
#define pTIMER4_WIDTH (volatile unsigned long *)TIMER4_WIDTH
#define bfin_read_TIMER4_WIDTH()             bfin_read32(TIMER4_WIDTH)
#define bfin_write_TIMER4_WIDTH(val)         bfin_write32(TIMER4_WIDTH,val)
#define pTIMER5_CONFIG (volatile unsigned short *)TIMER5_CONFIG
#define bfin_read_TIMER5_CONFIG()            bfin_read16(TIMER5_CONFIG)
#define bfin_write_TIMER5_CONFIG(val)        bfin_write16(TIMER5_CONFIG,val)
#define pTIMER5_COUNTER (volatile unsigned long *)TIMER5_COUNTER
#define bfin_read_TIMER5_COUNTER()           bfin_read32(TIMER5_COUNTER)
#define bfin_write_TIMER5_COUNTER(val)       bfin_write32(TIMER5_COUNTER,val)
#define pTIMER5_PERIOD (volatile unsigned long *)TIMER5_PERIOD
#define bfin_read_TIMER5_PERIOD()            bfin_read32(TIMER5_PERIOD)
#define bfin_write_TIMER5_PERIOD(val)        bfin_write32(TIMER5_PERIOD,val)
#define pTIMER5_WIDTH (volatile unsigned long *)TIMER5_WIDTH
#define bfin_read_TIMER5_WIDTH()             bfin_read32(TIMER5_WIDTH)
#define bfin_write_TIMER5_WIDTH(val)         bfin_write32(TIMER5_WIDTH,val)
#define pTIMER6_CONFIG (volatile unsigned short *)TIMER6_CONFIG
#define bfin_read_TIMER6_CONFIG()            bfin_read16(TIMER6_CONFIG)
#define bfin_write_TIMER6_CONFIG(val)        bfin_write16(TIMER6_CONFIG,val)
#define pTIMER6_COUNTER (volatile unsigned long *)TIMER6_COUNTER
#define bfin_read_TIMER6_COUNTER()           bfin_read32(TIMER6_COUNTER)
#define bfin_write_TIMER6_COUNTER(val)       bfin_write32(TIMER6_COUNTER,val)
#define pTIMER6_PERIOD (volatile unsigned long *)TIMER6_PERIOD
#define bfin_read_TIMER6_PERIOD()            bfin_read32(TIMER6_PERIOD)
#define bfin_write_TIMER6_PERIOD(val)        bfin_write32(TIMER6_PERIOD,val)
#define pTIMER6_WIDTH (volatile unsigned long *)TIMER6_WIDTH
#define bfin_read_TIMER6_WIDTH()             bfin_read32(TIMER6_WIDTH)
#define bfin_write_TIMER6_WIDTH(val)         bfin_write32(TIMER6_WIDTH,val)
#define pTIMER7_CONFIG (volatile unsigned short *)TIMER7_CONFIG
#define bfin_read_TIMER7_CONFIG()            bfin_read16(TIMER7_CONFIG)
#define bfin_write_TIMER7_CONFIG(val)        bfin_write16(TIMER7_CONFIG,val)
#define pTIMER7_COUNTER (volatile unsigned long *)TIMER7_COUNTER
#define bfin_read_TIMER7_COUNTER()           bfin_read32(TIMER7_COUNTER)
#define bfin_write_TIMER7_COUNTER(val)       bfin_write32(TIMER7_COUNTER,val)
#define pTIMER7_PERIOD (volatile unsigned long *)TIMER7_PERIOD
#define bfin_read_TIMER7_PERIOD()            bfin_read32(TIMER7_PERIOD)
#define bfin_write_TIMER7_PERIOD(val)        bfin_write32(TIMER7_PERIOD,val)
#define pTIMER7_WIDTH (volatile unsigned long *)TIMER7_WIDTH
#define bfin_read_TIMER7_WIDTH()             bfin_read32(TIMER7_WIDTH)
#define bfin_write_TIMER7_WIDTH(val)         bfin_write32(TIMER7_WIDTH,val)

/* Timer registers 8-11 (0xFFC0 1600-0xFFC0 16FF) */
#define pTMRS8_ENABLE (volatile unsigned short *)TMRS8_ENABLE
#define bfin_read_TMRS8_ENABLE()             bfin_read16(TMRS8_ENABLE)
#define bfin_write_TMRS8_ENABLE(val)         bfin_write16(TMRS8_ENABLE,val)
#define pTMRS8_DISABLE (volatile unsigned short *)TMRS8_DISABLE
#define bfin_read_TMRS8_DISABLE()            bfin_read16(TMRS8_DISABLE)
#define bfin_write_TMRS8_DISABLE(val)        bfin_write16(TMRS8_DISABLE,val)
#define pTMRS8_STATUS (volatile unsigned long *)TMRS8_STATUS
#define bfin_read_TMRS8_STATUS()             bfin_read32(TMRS8_STATUS)
#define bfin_write_TMRS8_STATUS(val)         bfin_write32(TMRS8_STATUS,val)
#define pTIMER8_CONFIG (volatile unsigned short *)TIMER8_CONFIG
#define bfin_read_TIMER8_CONFIG()            bfin_read16(TIMER8_CONFIG)
#define bfin_write_TIMER8_CONFIG(val)        bfin_write16(TIMER8_CONFIG,val)
#define pTIMER8_COUNTER (volatile unsigned long *)TIMER8_COUNTER
#define bfin_read_TIMER8_COUNTER()           bfin_read32(TIMER8_COUNTER)
#define bfin_write_TIMER8_COUNTER(val)       bfin_write32(TIMER8_COUNTER,val)
#define pTIMER8_PERIOD (volatile unsigned long *)TIMER8_PERIOD
#define bfin_read_TIMER8_PERIOD()            bfin_read32(TIMER8_PERIOD)
#define bfin_write_TIMER8_PERIOD(val)        bfin_write32(TIMER8_PERIOD,val)
#define pTIMER8_WIDTH (volatile unsigned long *)TIMER8_WIDTH
#define bfin_read_TIMER8_WIDTH()             bfin_read32(TIMER8_WIDTH)
#define bfin_write_TIMER8_WIDTH(val)         bfin_write32(TIMER8_WIDTH,val)
#define pTIMER9_CONFIG (volatile unsigned short *)TIMER9_CONFIG
#define bfin_read_TIMER9_CONFIG()            bfin_read16(TIMER9_CONFIG)
#define bfin_write_TIMER9_CONFIG(val)        bfin_write16(TIMER9_CONFIG,val)
#define pTIMER9_COUNTER (volatile unsigned long *)TIMER9_COUNTER
#define bfin_read_TIMER9_COUNTER()           bfin_read32(TIMER9_COUNTER)
#define bfin_write_TIMER9_COUNTER(val)       bfin_write32(TIMER9_COUNTER,val)
#define pTIMER9_PERIOD (volatile unsigned long *)TIMER9_PERIOD
#define bfin_read_TIMER9_PERIOD()            bfin_read32(TIMER9_PERIOD)
#define bfin_write_TIMER9_PERIOD(val)        bfin_write32(TIMER9_PERIOD,val)
#define pTIMER9_WIDTH (volatile unsigned long *)TIMER9_WIDTH
#define bfin_read_TIMER9_WIDTH()             bfin_read32(TIMER9_WIDTH)
#define bfin_write_TIMER9_WIDTH(val)         bfin_write32(TIMER9_WIDTH,val)
#define pTIMER10_CONFIG (volatile unsigned short *)TIMER10_CONFIG
#define bfin_read_TIMER10_CONFIG()           bfin_read16(TIMER10_CONFIG)
#define bfin_write_TIMER10_CONFIG(val)       bfin_write16(TIMER10_CONFIG,val)
#define pTIMER10_COUNTER (volatile unsigned long *)TIMER10_COUNTER
#define bfin_read_TIMER10_COUNTER()          bfin_read32(TIMER10_COUNTER)
#define bfin_write_TIMER10_COUNTER(val)      bfin_write32(TIMER10_COUNTER,val)
#define pTIMER10_PERIOD (volatile unsigned long *)TIMER10_PERIOD
#define bfin_read_TIMER10_PERIOD()           bfin_read32(TIMER10_PERIOD)
#define bfin_write_TIMER10_PERIOD(val)       bfin_write32(TIMER10_PERIOD,val)
#define pTIMER10_WIDTH (volatile unsigned long *)TIMER10_WIDTH
#define bfin_read_TIMER10_WIDTH()            bfin_read32(TIMER10_WIDTH)
#define bfin_write_TIMER10_WIDTH(val)        bfin_write32(TIMER10_WIDTH,val)
#define pTIMER11_CONFIG (volatile unsigned short *)TIMER11_CONFIG
#define bfin_read_TIMER11_CONFIG()           bfin_read16(TIMER11_CONFIG)
#define bfin_write_TIMER11_CONFIG(val)       bfin_write16(TIMER11_CONFIG,val)
#define pTIMER11_COUNTER (volatile unsigned long *)TIMER11_COUNTER
#define bfin_read_TIMER11_COUNTER()          bfin_read32(TIMER11_COUNTER)
#define bfin_write_TIMER11_COUNTER(val)      bfin_write32(TIMER11_COUNTER,val)
#define pTIMER11_PERIOD (volatile unsigned long *)TIMER11_PERIOD
#define bfin_read_TIMER11_PERIOD()           bfin_read32(TIMER11_PERIOD)
#define bfin_write_TIMER11_PERIOD(val)       bfin_write32(TIMER11_PERIOD,val)
#define pTIMER11_WIDTH (volatile unsigned long *)TIMER11_WIDTH
#define bfin_read_TIMER11_WIDTH()            bfin_read32(TIMER11_WIDTH)
#define bfin_write_TIMER11_WIDTH(val)        bfin_write32(TIMER11_WIDTH,val)
#define pTMRS4_ENABLE (volatile unsigned short *)TMRS4_ENABLE
#define bfin_read_TMRS4_ENABLE()             bfin_read16(TMRS4_ENABLE)
#define bfin_write_TMRS4_ENABLE(val)         bfin_write16(TMRS4_ENABLE,val)
#define pTMRS4_DISABLE (volatile unsigned short *)TMRS4_DISABLE
#define bfin_read_TMRS4_DISABLE()            bfin_read16(TMRS4_DISABLE)
#define bfin_write_TMRS4_DISABLE(val)        bfin_write16(TMRS4_DISABLE,val)
#define pTMRS4_STATUS (volatile unsigned long *)TMRS4_STATUS
#define bfin_read_TMRS4_STATUS()             bfin_read32(TMRS4_STATUS)
#define bfin_write_TMRS4_STATUS(val)         bfin_write32(TMRS4_STATUS,val)

/* Programmable Flag 0 registers (0xFFC0 0700-0xFFC0 07FF) */
#define pFIO0_FLAG_D (volatile unsigned short *)FIO0_FLAG_D
#define bfin_read_FIO0_FLAG_D()              bfin_read16(FIO0_FLAG_D)
#define bfin_write_FIO0_FLAG_D(val)          bfin_write16(FIO0_FLAG_D,val)
#define pFIO0_FLAG_C (volatile unsigned short *)FIO0_FLAG_C
#define bfin_read_FIO0_FLAG_C()              bfin_read16(FIO0_FLAG_C)
#define bfin_write_FIO0_FLAG_C(val)          bfin_write16(FIO0_FLAG_C,val)
#define pFIO0_FLAG_S (volatile unsigned short *)FIO0_FLAG_S
#define bfin_read_FIO0_FLAG_S()              bfin_read16(FIO0_FLAG_S)
#define bfin_write_FIO0_FLAG_S(val)          bfin_write16(FIO0_FLAG_S,val)
#define pFIO0_FLAG_T (volatile unsigned short *)FIO0_FLAG_T
#define bfin_read_FIO0_FLAG_T()              bfin_read16(FIO0_FLAG_T)
#define bfin_write_FIO0_FLAG_T(val)          bfin_write16(FIO0_FLAG_T,val)
#define pFIO0_MASKA_D (volatile unsigned short *)FIO0_MASKA_D
#define bfin_read_FIO0_MASKA_D()             bfin_read16(FIO0_MASKA_D)
#define bfin_write_FIO0_MASKA_D(val)         bfin_write16(FIO0_MASKA_D,val)
#define pFIO0_MASKA_C ((volatile unsigned short *)FIO0_MASKA_C)
#define bfin_read_FIO0_MASKA_C()             bfin_read16(FIO0_MASKA_C)
#define bfin_write_FIO0_MASKA_C(val)         bfin_write16(FIO0_MASKA_C,val)
#define pFIO0_MASKA_S ((volatile unsigned short *)FIO0_MASKA_S)
#define bfin_read_FIO0_MASKA_S()             bfin_read16(FIO0_MASKA_S)
#define bfin_write_FIO0_MASKA_S(val)         bfin_write16(FIO0_MASKA_S,val)
#define pFIO0_MASKA_T (volatile unsigned short *)FIO0_MASKA_T
#define bfin_read_FIO0_MASKA_T()             bfin_read16(FIO0_MASKA_T)
#define bfin_write_FIO0_MASKA_T(val)         bfin_write16(FIO0_MASKA_T,val)
#define pFIO0_MASKB_D (volatile unsigned short *)FIO0_MASKB_D
#define bfin_read_FIO0_MASKB_D()             bfin_read16(FIO0_MASKB_D)
#define bfin_write_FIO0_MASKB_D(val)         bfin_write16(FIO0_MASKB_D,val)
#define pFIO0_MASKB_C (volatile unsigned short *)FIO0_MASKB_C
#define bfin_read_FIO0_MASKB_C()             bfin_read16(FIO0_MASKB_C)
#define bfin_write_FIO0_MASKB_C(val)         bfin_write16(FIO0_MASKB_C,val)
#define pFIO0_MASKB_S (volatile unsigned short *)FIO0_MASKB_S
#define bfin_read_FIO0_MASKB_S()             bfin_read16(FIO0_MASKB_S)
#define bfin_write_FIO0_MASKB_S(val)         bfin_write16(FIO0_MASKB_S,val)
#define pFIO0_MASKB_T (volatile unsigned short *)FIO0_MASKB_T
#define bfin_read_FIO0_MASKB_T()             bfin_read16(FIO0_MASKB_T)
#define bfin_write_FIO0_MASKB_T(val)         bfin_write16(FIO0_MASKB_T,val)
#define pFIO0_DIR (volatile unsigned short *)FIO0_DIR
#define bfin_read_FIO0_DIR()                 bfin_read16(FIO0_DIR)
#define bfin_write_FIO0_DIR(val)             bfin_write16(FIO0_DIR,val)
#define pFIO0_POLAR (volatile unsigned short *)FIO0_POLAR
#define bfin_read_FIO0_POLAR()               bfin_read16(FIO0_POLAR)
#define bfin_write_FIO0_POLAR(val)           bfin_write16(FIO0_POLAR,val)
#define pFIO0_EDGE (volatile unsigned short *)FIO0_EDGE
#define bfin_read_FIO0_EDGE()                bfin_read16(FIO0_EDGE)
#define bfin_write_FIO0_EDGE(val)            bfin_write16(FIO0_EDGE,val)
#define pFIO0_BOTH (volatile unsigned short *)FIO0_BOTH
#define bfin_read_FIO0_BOTH()                bfin_read16(FIO0_BOTH)
#define bfin_write_FIO0_BOTH(val)            bfin_write16(FIO0_BOTH,val)
#define pFIO0_INEN (volatile unsigned short *)FIO0_INEN
#define bfin_read_FIO0_INEN()                bfin_read16(FIO0_INEN)
#define bfin_write_FIO0_INEN(val)            bfin_write16(FIO0_INEN,val)
/* Programmable Flag 1 registers (0xFFC0 1500-0xFFC0 15FF) */
#define pFIO1_FLAG_D (volatile unsigned short *)FIO1_FLAG_D
#define bfin_read_FIO1_FLAG_D()              bfin_read16(FIO1_FLAG_D)
#define bfin_write_FIO1_FLAG_D(val)          bfin_write16(FIO1_FLAG_D,val)
#define pFIO1_FLAG_C (volatile unsigned short *)FIO1_FLAG_C
#define bfin_read_FIO1_FLAG_C()              bfin_read16(FIO1_FLAG_C)
#define bfin_write_FIO1_FLAG_C(val)          bfin_write16(FIO1_FLAG_C,val)
#define pFIO1_FLAG_S (volatile unsigned short *)FIO1_FLAG_S
#define bfin_read_FIO1_FLAG_S()              bfin_read16(FIO1_FLAG_S)
#define bfin_write_FIO1_FLAG_S(val)          bfin_write16(FIO1_FLAG_S,val)
#define pFIO1_FLAG_T (volatile unsigned short *)FIO1_FLAG_T
#define bfin_read_FIO1_FLAG_T()              bfin_read16(FIO1_FLAG_T)
#define bfin_write_FIO1_FLAG_T(val)          bfin_write16(FIO1_FLAG_T,val)
#define pFIO1_MASKA_D (volatile unsigned short *)FIO1_MASKA_D
#define bfin_read_FIO1_MASKA_D()             bfin_read16(FIO1_MASKA_D)
#define bfin_write_FIO1_MASKA_D(val)         bfin_write16(FIO1_MASKA_D,val)
#define pFIO1_MASKA_C (volatile unsigned short *)FIO1_MASKA_C
#define bfin_read_FIO1_MASKA_C()             bfin_read16(FIO1_MASKA_C)
#define bfin_write_FIO1_MASKA_C(val)         bfin_write16(FIO1_MASKA_C,val)
#define pFIO1_MASKA_S (volatile unsigned short *)FIO1_MASKA_S
#define bfin_read_FIO1_MASKA_S()             bfin_read16(FIO1_MASKA_S)
#define bfin_write_FIO1_MASKA_S(val)         bfin_write16(FIO1_MASKA_S,val)
#define pFIO1_MASKA_T (volatile unsigned short *)FIO1_MASKA_T
#define bfin_read_FIO1_MASKA_T()             bfin_read16(FIO1_MASKA_T)
#define bfin_write_FIO1_MASKA_T(val)         bfin_write16(FIO1_MASKA_T,val)
#define pFIO1_MASKB_D (volatile unsigned short *)FIO1_MASKB_D
#define bfin_read_FIO1_MASKB_D()             bfin_read16(FIO1_MASKB_D)
#define bfin_write_FIO1_MASKB_D(val)         bfin_write16(FIO1_MASKB_D,val)
#define pFIO1_MASKB_C (volatile unsigned short *)FIO1_MASKB_C
#define bfin_read_FIO1_MASKB_C()             bfin_read16(FIO1_MASKB_C)
#define bfin_write_FIO1_MASKB_C(val)         bfin_write16(FIO1_MASKB_C,val)
#define pFIO1_MASKB_S (volatile unsigned short *)FIO1_MASKB_S
#define bfin_read_FIO1_MASKB_S()             bfin_read16(FIO1_MASKB_S)
#define bfin_write_FIO1_MASKB_S(val)         bfin_write16(FIO1_MASKB_S,val)
#define pFIO1_MASKB_T (volatile unsigned short *)FIO1_MASKB_T
#define bfin_read_FIO1_MASKB_T()             bfin_read16(FIO1_MASKB_T)
#define bfin_write_FIO1_MASKB_T(val)         bfin_write16(FIO1_MASKB_T,val)
#define pFIO1_DIR (volatile unsigned short *)FIO1_DIR
#define bfin_read_FIO1_DIR()                 bfin_read16(FIO1_DIR)
#define bfin_write_FIO1_DIR(val)             bfin_write16(FIO1_DIR,val)
#define pFIO1_POLAR (volatile unsigned short *)FIO1_POLAR
#define bfin_read_FIO1_POLAR()               bfin_read16(FIO1_POLAR)
#define bfin_write_FIO1_POLAR(val)           bfin_write16(FIO1_POLAR,val)
#define pFIO1_EDGE (volatile unsigned short *)FIO1_EDGE
#define bfin_read_FIO1_EDGE()                bfin_read16(FIO1_EDGE)
#define bfin_write_FIO1_EDGE(val)            bfin_write16(FIO1_EDGE,val)
#define pFIO1_BOTH (volatile unsigned short *)FIO1_BOTH
#define bfin_read_FIO1_BOTH()                bfin_read16(FIO1_BOTH)
#define bfin_write_FIO1_BOTH(val)            bfin_write16(FIO1_BOTH,val)
#define pFIO1_INEN (volatile unsigned short *)FIO1_INEN
#define bfin_read_FIO1_INEN()                bfin_read16(FIO1_INEN)
#define bfin_write_FIO1_INEN(val)            bfin_write16(FIO1_INEN,val)
/* Programmable Flag registers (0xFFC0 1700-0xFFC0 17FF) */
#define pFIO2_FLAG_D (volatile unsigned short *)FIO2_FLAG_D
#define bfin_read_FIO2_FLAG_D()              bfin_read16(FIO2_FLAG_D)
#define bfin_write_FIO2_FLAG_D(val)          bfin_write16(FIO2_FLAG_D,val)
#define pFIO2_FLAG_C (volatile unsigned short *)FIO2_FLAG_C
#define bfin_read_FIO2_FLAG_C()              bfin_read16(FIO2_FLAG_C)
#define bfin_write_FIO2_FLAG_C(val)          bfin_write16(FIO2_FLAG_C,val)
#define pFIO2_FLAG_S (volatile unsigned short *)FIO2_FLAG_S
#define bfin_read_FIO2_FLAG_S()              bfin_read16(FIO2_FLAG_S)
#define bfin_write_FIO2_FLAG_S(val)          bfin_write16(FIO2_FLAG_S,val)
#define pFIO2_FLAG_T (volatile unsigned short *)FIO2_FLAG_T
#define bfin_read_FIO2_FLAG_T()              bfin_read16(FIO2_FLAG_T)
#define bfin_write_FIO2_FLAG_T(val)          bfin_write16(FIO2_FLAG_T,val)
#define pFIO2_MASKA_D (volatile unsigned short *)FIO2_MASKA_D
#define bfin_read_FIO2_MASKA_D()             bfin_read16(FIO2_MASKA_D)
#define bfin_write_FIO2_MASKA_D(val)         bfin_write16(FIO2_MASKA_D,val)
#define pFIO2_MASKA_C (volatile unsigned short *)FIO2_MASKA_C
#define bfin_read_FIO2_MASKA_C()             bfin_read16(FIO2_MASKA_C)
#define bfin_write_FIO2_MASKA_C(val)         bfin_write16(FIO2_MASKA_C,val)
#define pFIO2_MASKA_S (volatile unsigned short *)FIO2_MASKA_S
#define bfin_read_FIO2_MASKA_S()             bfin_read16(FIO2_MASKA_S)
#define bfin_write_FIO2_MASKA_S(val)         bfin_write16(FIO2_MASKA_S,val)
#define pFIO2_MASKA_T (volatile unsigned short *)FIO2_MASKA_T
#define bfin_read_FIO2_MASKA_T()             bfin_read16(FIO2_MASKA_T)
#define bfin_write_FIO2_MASKA_T(val)         bfin_write16(FIO2_MASKA_T,val)
#define pFIO2_MASKB_D (volatile unsigned short *)FIO2_MASKB_D
#define bfin_read_FIO2_MASKB_D()             bfin_read16(FIO2_MASKB_D)
#define bfin_write_FIO2_MASKB_D(val)         bfin_write16(FIO2_MASKB_D,val)
#define pFIO2_MASKB_C (volatile unsigned short *)FIO2_MASKB_C
#define bfin_read_FIO2_MASKB_C()             bfin_read16(FIO2_MASKB_C)
#define bfin_write_FIO2_MASKB_C(val)         bfin_write16(FIO2_MASKB_C,val)
#define pFIO2_MASKB_S (volatile unsigned short *)FIO2_MASKB_S
#define bfin_read_FIO2_MASKB_S()             bfin_read16(FIO2_MASKB_S)
#define bfin_write_FIO2_MASKB_S(val)         bfin_write16(FIO2_MASKB_S,val)
#define pFIO2_MASKB_T (volatile unsigned short *)FIO2_MASKB_T
#define bfin_read_FIO2_MASKB_T()             bfin_read16(FIO2_MASKB_T)
#define bfin_write_FIO2_MASKB_T(val)         bfin_write16(FIO2_MASKB_T,val)
#define pFIO2_DIR (volatile unsigned short *)FIO2_DIR
#define bfin_read_FIO2_DIR()                 bfin_read16(FIO2_DIR)
#define bfin_write_FIO2_DIR(val)             bfin_write16(FIO2_DIR,val)
#define pFIO2_POLAR (volatile unsigned short *)FIO2_POLAR
#define bfin_read_FIO2_POLAR()               bfin_read16(FIO2_POLAR)
#define bfin_write_FIO2_POLAR(val)           bfin_write16(FIO2_POLAR,val)
#define pFIO2_EDGE (volatile unsigned short *)FIO2_EDGE
#define bfin_read_FIO2_EDGE()                bfin_read16(FIO2_EDGE)
#define bfin_write_FIO2_EDGE(val)            bfin_write16(FIO2_EDGE,val)
#define pFIO2_BOTH (volatile unsigned short *)FIO2_BOTH
#define bfin_read_FIO2_BOTH()                bfin_read16(FIO2_BOTH)
#define bfin_write_FIO2_BOTH(val)            bfin_write16(FIO2_BOTH,val)
#define pFIO2_INEN (volatile unsigned short *)FIO2_INEN
#define bfin_read_FIO2_INEN()                bfin_read16(FIO2_INEN)
#define bfin_write_FIO2_INEN(val)            bfin_write16(FIO2_INEN,val)
/* SPORT0 Controller (0xFFC00800 - 0xFFC008FF) */
#define pSPORT0_TCR1 (volatile unsigned short *)SPORT0_TCR1
#define bfin_read_SPORT0_TCR1()              bfin_read16(SPORT0_TCR1)
#define bfin_write_SPORT0_TCR1(val)          bfin_write16(SPORT0_TCR1,val)
#define pSPORT0_TCR2 (volatile unsigned short *)SPORT0_TCR2
#define bfin_read_SPORT0_TCR2()              bfin_read16(SPORT0_TCR2)
#define bfin_write_SPORT0_TCR2(val)          bfin_write16(SPORT0_TCR2,val)
#define pSPORT0_TCLKDIV (volatile unsigned short *)SPORT0_TCLKDIV
#define bfin_read_SPORT0_TCLKDIV()           bfin_read16(SPORT0_TCLKDIV)
#define bfin_write_SPORT0_TCLKDIV(val)       bfin_write16(SPORT0_TCLKDIV,val)
#define pSPORT0_TFSDIV (volatile unsigned short *)SPORT0_TFSDIV
#define bfin_read_SPORT0_TFSDIV()            bfin_read16(SPORT0_TFSDIV)
#define bfin_write_SPORT0_TFSDIV(val)        bfin_write16(SPORT0_TFSDIV,val)
#define pSPORT0_TX (volatile unsigned long *)SPORT0_TX
#define bfin_read_SPORT0_TX()                bfin_read32(SPORT0_TX)
#define bfin_write_SPORT0_TX(val)            bfin_write32(SPORT0_TX,val)
#define pSPORT0_RX (volatile unsigned long *)SPORT0_RX
#define bfin_read_SPORT0_RX()                bfin_read32(SPORT0_RX)
#define bfin_write_SPORT0_RX(val)            bfin_write32(SPORT0_RX,val)
#define pSPORT0_TX32 ((volatile long *)SPORT0_TX)
#define bfin_read_SPORT0_TX32()              bfin_read32(SPORT0_TX32)
#define bfin_write_SPORT0_TX32(val)          bfin_write32(SPORT0_TX32,val)
#define pSPORT0_RX32 ((volatile long *)SPORT0_RX)
#define bfin_read_SPORT0_RX32()              bfin_read32(SPORT0_RX32)
#define bfin_write_SPORT0_RX32(val)          bfin_write32(SPORT0_RX32,val)
#define pSPORT0_TX16 ((volatile unsigned short *)SPORT0_TX)
#define bfin_read_SPORT0_TX16()              bfin_read16(SPORT0_TX16)
#define bfin_write_SPORT0_TX16(val)          bfin_write16(SPORT0_TX16,val)
#define pSPORT0_RX16 ((volatile unsigned short *)SPORT0_RX)
#define bfin_read_SPORT0_RX16()              bfin_read16(SPORT0_RX16)
#define bfin_write_SPORT0_RX16(val)          bfin_write16(SPORT0_RX16,val)
#define pSPORT0_RCR1 (volatile unsigned short *)SPORT0_RCR1
#define bfin_read_SPORT0_RCR1()              bfin_read16(SPORT0_RCR1)
#define bfin_write_SPORT0_RCR1(val)          bfin_write16(SPORT0_RCR1,val)
#define pSPORT0_RCR2 (volatile unsigned short *)SPORT0_RCR2
#define bfin_read_SPORT0_RCR2()              bfin_read16(SPORT0_RCR2)
#define bfin_write_SPORT0_RCR2(val)          bfin_write16(SPORT0_RCR2,val)
#define pSPORT0_RCLKDIV (volatile unsigned short *)SPORT0_RCLKDIV
#define bfin_read_SPORT0_RCLKDIV()           bfin_read16(SPORT0_RCLKDIV)
#define bfin_write_SPORT0_RCLKDIV(val)       bfin_write16(SPORT0_RCLKDIV,val)
#define pSPORT0_RFSDIV (volatile unsigned short *)SPORT0_RFSDIV
#define bfin_read_SPORT0_RFSDIV()            bfin_read16(SPORT0_RFSDIV)
#define bfin_write_SPORT0_RFSDIV(val)        bfin_write16(SPORT0_RFSDIV,val)
#define pSPORT0_STAT (volatile unsigned short *)SPORT0_STAT
#define bfin_read_SPORT0_STAT()              bfin_read16(SPORT0_STAT)
#define bfin_write_SPORT0_STAT(val)          bfin_write16(SPORT0_STAT,val)
#define pSPORT0_CHNL (volatile unsigned short *)SPORT0_CHNL
#define bfin_read_SPORT0_CHNL()              bfin_read16(SPORT0_CHNL)
#define bfin_write_SPORT0_CHNL(val)          bfin_write16(SPORT0_CHNL,val)
#define pSPORT0_MCMC1 (volatile unsigned short *)SPORT0_MCMC1
#define bfin_read_SPORT0_MCMC1()             bfin_read16(SPORT0_MCMC1)
#define bfin_write_SPORT0_MCMC1(val)         bfin_write16(SPORT0_MCMC1,val)
#define pSPORT0_MCMC2 (volatile unsigned short *)SPORT0_MCMC2
#define bfin_read_SPORT0_MCMC2()             bfin_read16(SPORT0_MCMC2)
#define bfin_write_SPORT0_MCMC2(val)         bfin_write16(SPORT0_MCMC2,val)
#define pSPORT0_MTCS0 (volatile unsigned long *)SPORT0_MTCS0
#define bfin_read_SPORT0_MTCS0()             bfin_read32(SPORT0_MTCS0)
#define bfin_write_SPORT0_MTCS0(val)         bfin_write32(SPORT0_MTCS0,val)
#define pSPORT0_MTCS1 (volatile unsigned long *)SPORT0_MTCS1
#define bfin_read_SPORT0_MTCS1()             bfin_read32(SPORT0_MTCS1)
#define bfin_write_SPORT0_MTCS1(val)         bfin_write32(SPORT0_MTCS1,val)
#define pSPORT0_MTCS2 (volatile unsigned long *)SPORT0_MTCS2
#define bfin_read_SPORT0_MTCS2()             bfin_read32(SPORT0_MTCS2)
#define bfin_write_SPORT0_MTCS2(val)         bfin_write32(SPORT0_MTCS2,val)
#define pSPORT0_MTCS3 (volatile unsigned long *)SPORT0_MTCS3
#define bfin_read_SPORT0_MTCS3()             bfin_read32(SPORT0_MTCS3)
#define bfin_write_SPORT0_MTCS3(val)         bfin_write32(SPORT0_MTCS3,val)
#define pSPORT0_MRCS0 (volatile unsigned long *)SPORT0_MRCS0
#define bfin_read_SPORT0_MRCS0()             bfin_read32(SPORT0_MRCS0)
#define bfin_write_SPORT0_MRCS0(val)         bfin_write32(SPORT0_MRCS0,val)
#define pSPORT0_MRCS1 (volatile unsigned long *)SPORT0_MRCS1
#define bfin_read_SPORT0_MRCS1()             bfin_read32(SPORT0_MRCS1)
#define bfin_write_SPORT0_MRCS1(val)         bfin_write32(SPORT0_MRCS1,val)
#define pSPORT0_MRCS2 (volatile unsigned long *)SPORT0_MRCS2
#define bfin_read_SPORT0_MRCS2()             bfin_read32(SPORT0_MRCS2)
#define bfin_write_SPORT0_MRCS2(val)         bfin_write32(SPORT0_MRCS2,val)
#define pSPORT0_MRCS3 (volatile unsigned long *)SPORT0_MRCS3
#define bfin_read_SPORT0_MRCS3()             bfin_read32(SPORT0_MRCS3)
#define bfin_write_SPORT0_MRCS3(val)         bfin_write32(SPORT0_MRCS3,val)
/* SPORT1 Controller (0xFFC00900 - 0xFFC009FF) */
#define pSPORT1_TCR1 (volatile unsigned short *)SPORT1_TCR1
#define bfin_read_SPORT1_TCR1()              bfin_read16(SPORT1_TCR1)
#define bfin_write_SPORT1_TCR1(val)          bfin_write16(SPORT1_TCR1,val)
#define pSPORT1_TCR2 (volatile unsigned short *)SPORT1_TCR2
#define bfin_read_SPORT1_TCR2()              bfin_read16(SPORT1_TCR2)
#define bfin_write_SPORT1_TCR2(val)          bfin_write16(SPORT1_TCR2,val)
#define pSPORT1_TCLKDIV (volatile unsigned short *)SPORT1_TCLKDIV
#define bfin_read_SPORT1_TCLKDIV()           bfin_read16(SPORT1_TCLKDIV)
#define bfin_write_SPORT1_TCLKDIV(val)       bfin_write16(SPORT1_TCLKDIV,val)
#define pSPORT1_TFSDIV (volatile unsigned short *)SPORT1_TFSDIV
#define bfin_read_SPORT1_TFSDIV()            bfin_read16(SPORT1_TFSDIV)
#define bfin_write_SPORT1_TFSDIV(val)        bfin_write16(SPORT1_TFSDIV,val)
#define pSPORT1_TX (volatile unsigned long *)SPORT1_TX
#define bfin_read_SPORT1_TX()                bfin_read32(SPORT1_TX)
#define bfin_write_SPORT1_TX(val)            bfin_write32(SPORT1_TX,val)
#define pSPORT1_RX (volatile unsigned long *)SPORT1_RX
#define bfin_read_SPORT1_RX()                bfin_read32(SPORT1_RX)
#define bfin_write_SPORT1_RX(val)            bfin_write32(SPORT1_RX,val)
#define pSPORT1_TX32 ((volatile long *)SPORT1_TX)
#define bfin_read_SPORT1_TX32()              bfin_read32(SPORT1_TX32)
#define bfin_write_SPORT1_TX32(val)          bfin_write32(SPORT1_TX32,val)
#define pSPORT1_RX32 ((volatile long *)SPORT1_RX)
#define bfin_read_SPORT1_RX32()              bfin_read32(SPORT1_RX32)
#define bfin_write_SPORT1_RX32(val)          bfin_write32(SPORT1_RX32,val)
#define pSPORT1_TX16 ((volatile unsigned short *)SPORT1_TX)
#define bfin_read_SPORT1_TX16()              bfin_read16(SPORT1_TX16)
#define bfin_write_SPORT1_TX16(val)          bfin_write16(SPORT1_TX16,val)
#define pSPORT1_RX16 ((volatile unsigned short *)SPORT1_RX)
#define bfin_read_SPORT1_RX16()              bfin_read16(SPORT1_RX16)
#define bfin_write_SPORT1_RX16(val)          bfin_write16(SPORT1_RX16,val)
#define pSPORT1_RCR1 (volatile unsigned short *)SPORT1_RCR1
#define bfin_read_SPORT1_RCR1()              bfin_read16(SPORT1_RCR1)
#define bfin_write_SPORT1_RCR1(val)          bfin_write16(SPORT1_RCR1,val)
#define pSPORT1_RCR2 (volatile unsigned short *)SPORT1_RCR2
#define bfin_read_SPORT1_RCR2()              bfin_read16(SPORT1_RCR2)
#define bfin_write_SPORT1_RCR2(val)          bfin_write16(SPORT1_RCR2,val)
#define pSPORT1_RCLKDIV (volatile unsigned short *)SPORT1_RCLKDIV
#define bfin_read_SPORT1_RCLKDIV()           bfin_read16(SPORT1_RCLKDIV)
#define bfin_write_SPORT1_RCLKDIV(val)       bfin_write16(SPORT1_RCLKDIV,val)
#define pSPORT1_RFSDIV (volatile unsigned short *)SPORT1_RFSDIV
#define bfin_read_SPORT1_RFSDIV()            bfin_read16(SPORT1_RFSDIV)
#define bfin_write_SPORT1_RFSDIV(val)        bfin_write16(SPORT1_RFSDIV,val)
#define pSPORT1_STAT (volatile unsigned short *)SPORT1_STAT
#define bfin_read_SPORT1_STAT()              bfin_read16(SPORT1_STAT)
#define bfin_write_SPORT1_STAT(val)          bfin_write16(SPORT1_STAT,val)
#define pSPORT1_CHNL (volatile unsigned short *)SPORT1_CHNL
#define bfin_read_SPORT1_CHNL()              bfin_read16(SPORT1_CHNL)
#define bfin_write_SPORT1_CHNL(val)          bfin_write16(SPORT1_CHNL,val)
#define pSPORT1_MCMC1 (volatile unsigned short *)SPORT1_MCMC1
#define bfin_read_SPORT1_MCMC1()             bfin_read16(SPORT1_MCMC1)
#define bfin_write_SPORT1_MCMC1(val)         bfin_write16(SPORT1_MCMC1,val)
#define pSPORT1_MCMC2 (volatile unsigned short *)SPORT1_MCMC2
#define bfin_read_SPORT1_MCMC2()             bfin_read16(SPORT1_MCMC2)
#define bfin_write_SPORT1_MCMC2(val)         bfin_write16(SPORT1_MCMC2,val)
#define pSPORT1_MTCS0 (volatile unsigned long *)SPORT1_MTCS0
#define bfin_read_SPORT1_MTCS0()             bfin_read32(SPORT1_MTCS0)
#define bfin_write_SPORT1_MTCS0(val)         bfin_write32(SPORT1_MTCS0,val)
#define pSPORT1_MTCS1 (volatile unsigned long *)SPORT1_MTCS1
#define bfin_read_SPORT1_MTCS1()             bfin_read32(SPORT1_MTCS1)
#define bfin_write_SPORT1_MTCS1(val)         bfin_write32(SPORT1_MTCS1,val)
#define pSPORT1_MTCS2 (volatile unsigned long *)SPORT1_MTCS2
#define bfin_read_SPORT1_MTCS2()             bfin_read32(SPORT1_MTCS2)
#define bfin_write_SPORT1_MTCS2(val)         bfin_write32(SPORT1_MTCS2,val)
#define pSPORT1_MTCS3 (volatile unsigned long *)SPORT1_MTCS3
#define bfin_read_SPORT1_MTCS3()             bfin_read32(SPORT1_MTCS3)
#define bfin_write_SPORT1_MTCS3(val)         bfin_write32(SPORT1_MTCS3,val)
#define pSPORT1_MRCS0 (volatile unsigned long *)SPORT1_MRCS0
#define bfin_read_SPORT1_MRCS0()             bfin_read32(SPORT1_MRCS0)
#define bfin_write_SPORT1_MRCS0(val)         bfin_write32(SPORT1_MRCS0,val)
#define pSPORT1_MRCS1 (volatile unsigned long *)SPORT1_MRCS1
#define bfin_read_SPORT1_MRCS1()             bfin_read32(SPORT1_MRCS1)
#define bfin_write_SPORT1_MRCS1(val)         bfin_write32(SPORT1_MRCS1,val)
#define pSPORT1_MRCS2 (volatile unsigned long *)SPORT1_MRCS2
#define bfin_read_SPORT1_MRCS2()             bfin_read32(SPORT1_MRCS2)
#define bfin_write_SPORT1_MRCS2(val)         bfin_write32(SPORT1_MRCS2,val)
#define pSPORT1_MRCS3 (volatile unsigned long *)SPORT1_MRCS3
#define bfin_read_SPORT1_MRCS3()             bfin_read32(SPORT1_MRCS3)
#define bfin_write_SPORT1_MRCS3(val)         bfin_write32(SPORT1_MRCS3,val)
/* Asynchronous Memory Controller - External Bus Interface Unit */
#define pEBIU_AMGCTL (volatile unsigned short *)EBIU_AMGCTL
#define bfin_read_EBIU_AMGCTL()              bfin_read16(EBIU_AMGCTL)
#define bfin_write_EBIU_AMGCTL(val)          bfin_write16(EBIU_AMGCTL,val)
#define pEBIU_AMBCTL0 (volatile unsigned long *)EBIU_AMBCTL0
#define bfin_read_EBIU_AMBCTL0()             bfin_read32(EBIU_AMBCTL0)
#define bfin_write_EBIU_AMBCTL0(val)         bfin_write32(EBIU_AMBCTL0,val)
#define pEBIU_AMBCTL1 (volatile unsigned long *)EBIU_AMBCTL1
#define bfin_read_EBIU_AMBCTL1()             bfin_read32(EBIU_AMBCTL1)
#define bfin_write_EBIU_AMBCTL1(val)         bfin_write32(EBIU_AMBCTL1,val)
/* SDRAM Controller External Bus Interface Unit (0xFFC00A00 - 0xFFC00AFF) */
#define pEBIU_SDGCTL (volatile unsigned long *)EBIU_SDGCTL
#define bfin_read_EBIU_SDGCTL()              bfin_read32(EBIU_SDGCTL)
#define bfin_write_EBIU_SDGCTL(val)          bfin_write32(EBIU_SDGCTL,val)
#define pEBIU_SDBCTL (volatile unsigned long *)EBIU_SDBCTL
#define bfin_read_EBIU_SDBCTL()              bfin_read32(EBIU_SDBCTL)
#define bfin_write_EBIU_SDBCTL(val)          bfin_write32(EBIU_SDBCTL,val)
#define pEBIU_SDRRC (volatile unsigned short *)EBIU_SDRRC
#define bfin_read_EBIU_SDRRC()               bfin_read16(EBIU_SDRRC)
#define bfin_write_EBIU_SDRRC(val)           bfin_write16(EBIU_SDRRC,val)
#define pEBIU_SDSTAT (volatile unsigned short *)EBIU_SDSTAT
#define bfin_read_EBIU_SDSTAT()              bfin_read16(EBIU_SDSTAT)
#define bfin_write_EBIU_SDSTAT(val)          bfin_write16(EBIU_SDSTAT,val)
/* Parallel Peripheral Interface (PPI) 0 registers (0xFFC0 1000-0xFFC0 10FF) */
#define pPPI0_CONTROL (volatile unsigned short *)PPI0_CONTROL
#define bfin_read_PPI0_CONTROL()             bfin_read16(PPI0_CONTROL)
#define bfin_write_PPI0_CONTROL(val)         bfin_write16(PPI0_CONTROL,val)
#define pPPI0_STATUS (volatile unsigned short *)PPI0_STATUS
#define bfin_read_PPI0_STATUS()              bfin_read16(PPI0_STATUS)
#define bfin_write_PPI0_STATUS(val)          bfin_write16(PPI0_STATUS,val)
#define pPPI0_COUNT (volatile unsigned short *)PPI0_COUNT
#define bfin_read_PPI0_COUNT()               bfin_read16(PPI0_COUNT)
#define bfin_write_PPI0_COUNT(val)           bfin_write16(PPI0_COUNT,val)
#define pPPI0_DELAY (volatile unsigned short *)PPI0_DELAY
#define bfin_read_PPI0_DELAY()               bfin_read16(PPI0_DELAY)
#define bfin_write_PPI0_DELAY(val)           bfin_write16(PPI0_DELAY,val)
#define pPPI0_FRAME (volatile unsigned short *)PPI0_FRAME
#define bfin_read_PPI0_FRAME()               bfin_read16(PPI0_FRAME)
#define bfin_write_PPI0_FRAME(val)           bfin_write16(PPI0_FRAME,val)
/* Parallel Peripheral Interface (PPI) 1 registers (0xFFC0 1300-0xFFC0 13FF) */
#define pPPI1_CONTROL (volatile unsigned short *)PPI1_CONTROL
#define bfin_read_PPI1_CONTROL()             bfin_read16(PPI1_CONTROL)
#define bfin_write_PPI1_CONTROL(val)         bfin_write16(PPI1_CONTROL,val)
#define pPPI1_STATUS (volatile unsigned short *)PPI1_STATUS
#define bfin_read_PPI1_STATUS()              bfin_read16(PPI1_STATUS)
#define bfin_write_PPI1_STATUS(val)          bfin_write16(PPI1_STATUS,val)
#define pPPI1_COUNT (volatile unsigned short *)PPI1_COUNT
#define bfin_read_PPI1_COUNT()               bfin_read16(PPI1_COUNT)
#define bfin_write_PPI1_COUNT(val)           bfin_write16(PPI1_COUNT,val)
#define pPPI1_DELAY (volatile unsigned short *)PPI1_DELAY
#define bfin_read_PPI1_DELAY()               bfin_read16(PPI1_DELAY)
#define bfin_write_PPI1_DELAY(val)           bfin_write16(PPI1_DELAY,val)
#define pPPI1_FRAME (volatile unsigned short *)PPI1_FRAME
#define bfin_read_PPI1_FRAME()               bfin_read16(PPI1_FRAME)
#define bfin_write_PPI1_FRAME(val)           bfin_write16(PPI1_FRAME,val)
/*DMA traffic control registers */
#define pDMA1_TC_PER (volatile unsigned short *)DMA1_TC_PER
#define bfin_read_DMA1_TC_PER()              bfin_read16(DMA1_TC_PER)
#define bfin_write_DMA1_TC_PER(val)          bfin_write16(DMA1_TC_PER,val)
#define pDMA1_TC_CNT (volatile unsigned short *)DMA1_TC_CNT
#define bfin_read_DMA1_TC_CNT()              bfin_read16(DMA1_TC_CNT)
#define bfin_write_DMA1_TC_CNT(val)          bfin_write16(DMA1_TC_CNT,val)
#define pDMA2_TC_PER (volatile unsigned short *)DMA2_TC_PER
#define bfin_read_DMA2_TC_PER()              bfin_read16(DMA2_TC_PER)
#define bfin_write_DMA2_TC_PER(val)          bfin_write16(DMA2_TC_PER,val)
#define pDMA2_TC_CNT (volatile unsigned short *)DMA2_TC_CNT
#define bfin_read_DMA2_TC_CNT()              bfin_read16(DMA2_TC_CNT)
#define bfin_write_DMA2_TC_CNT(val)          bfin_write16(DMA2_TC_CNT,val)
/* DMA1 Controller registers (0xFFC0 1C00-0xFFC0 1FFF) */
#define pDMA1_0_CONFIG (volatile unsigned short *)DMA1_0_CONFIG
#define bfin_read_DMA1_0_CONFIG()            bfin_read16(DMA1_0_CONFIG)
#define bfin_write_DMA1_0_CONFIG(val)        bfin_write16(DMA1_0_CONFIG,val)
#define pDMA1_0_NEXT_DESC_PTR (volatile void **)DMA1_0_NEXT_DESC_PTR
#define bfin_read_DMA1_0_NEXT_DESC_PTR()     bfin_read32(DMA1_0_NEXT_DESC_PTR)
#define bfin_write_DMA1_0_NEXT_DESC_PTR(val) bfin_write32(DMA1_0_NEXT_DESC_PTR,val)
#define pDMA1_0_START_ADDR (volatile void **)DMA1_0_START_ADDR
#define bfin_read_DMA1_0_START_ADDR()        bfin_read32(DMA1_0_START_ADDR)
#define bfin_write_DMA1_0_START_ADDR(val)    bfin_write32(DMA1_0_START_ADDR,val)
#define pDMA1_0_X_COUNT (volatile unsigned short *)DMA1_0_X_COUNT
#define bfin_read_DMA1_0_X_COUNT()           bfin_read16(DMA1_0_X_COUNT)
#define bfin_write_DMA1_0_X_COUNT(val)       bfin_write16(DMA1_0_X_COUNT,val)
#define pDMA1_0_Y_COUNT (volatile unsigned short *)DMA1_0_Y_COUNT
#define bfin_read_DMA1_0_Y_COUNT()           bfin_read16(DMA1_0_Y_COUNT)
#define bfin_write_DMA1_0_Y_COUNT(val)       bfin_write16(DMA1_0_Y_COUNT,val)
#define pDMA1_0_X_MODIFY (volatile signed short *)DMA1_0_X_MODIFY
#define bfin_read_DMA1_0_X_MODIFY()          bfin_read16(DMA1_0_X_MODIFY)
#define bfin_write_DMA1_0_X_MODIFY(val)      bfin_write16(DMA1_0_X_MODIFY,val)
#define pDMA1_0_Y_MODIFY (volatile signed short *)DMA1_0_Y_MODIFY
#define bfin_read_DMA1_0_Y_MODIFY()          bfin_read16(DMA1_0_Y_MODIFY)
#define bfin_write_DMA1_0_Y_MODIFY(val)      bfin_write16(DMA1_0_Y_MODIFY,val)
#define pDMA1_0_CURR_DESC_PTR (volatile void **)DMA1_0_CURR_DESC_PTR
#define bfin_read_DMA1_0_CURR_DESC_PTR()     bfin_read32(DMA1_0_CURR_DESC_PTR)
#define bfin_write_DMA1_0_CURR_DESC_PTR(val) bfin_write32(DMA1_0_CURR_DESC_PTR,val)
#define pDMA1_0_CURR_ADDR (volatile void **)DMA1_0_CURR_ADDR
#define bfin_read_DMA1_0_CURR_ADDR()         bfin_read32(DMA1_0_CURR_ADDR)
#define bfin_write_DMA1_0_CURR_ADDR(val)     bfin_write32(DMA1_0_CURR_ADDR,val)
#define pDMA1_0_CURR_X_COUNT (volatile unsigned short *)DMA1_0_CURR_X_COUNT
#define bfin_read_DMA1_0_CURR_X_COUNT()      bfin_read16(DMA1_0_CURR_X_COUNT)
#define bfin_write_DMA1_0_CURR_X_COUNT(val)  bfin_write16(DMA1_0_CURR_X_COUNT,val)
#define pDMA1_0_CURR_Y_COUNT (volatile unsigned short *)DMA1_0_CURR_Y_COUNT
#define bfin_read_DMA1_0_CURR_Y_COUNT()      bfin_read16(DMA1_0_CURR_Y_COUNT)
#define bfin_write_DMA1_0_CURR_Y_COUNT(val)  bfin_write16(DMA1_0_CURR_Y_COUNT,val)
#define pDMA1_0_IRQ_STATUS (volatile unsigned short *)DMA1_0_IRQ_STATUS
#define bfin_read_DMA1_0_IRQ_STATUS()        bfin_read16(DMA1_0_IRQ_STATUS)
#define bfin_write_DMA1_0_IRQ_STATUS(val)    bfin_write16(DMA1_0_IRQ_STATUS,val)
#define pDMA1_0_PERIPHERAL_MAP (volatile unsigned short *)DMA1_0_PERIPHERAL_MAP
#define bfin_read_DMA1_0_PERIPHERAL_MAP()    bfin_read16(DMA1_0_PERIPHERAL_MAP)
#define bfin_write_DMA1_0_PERIPHERAL_MAP(val) bfin_write16(DMA1_0_PERIPHERAL_MAP,val)
#define pDMA1_1_CONFIG (volatile unsigned short *)DMA1_1_CONFIG
#define bfin_read_DMA1_1_CONFIG()            bfin_read16(DMA1_1_CONFIG)
#define bfin_write_DMA1_1_CONFIG(val)        bfin_write16(DMA1_1_CONFIG,val)
#define pDMA1_1_NEXT_DESC_PTR (volatile void **)DMA1_1_NEXT_DESC_PTR
#define bfin_read_DMA1_1_NEXT_DESC_PTR()     bfin_read32(DMA1_1_NEXT_DESC_PTR)
#define bfin_write_DMA1_1_NEXT_DESC_PTR(val) bfin_write32(DMA1_1_NEXT_DESC_PTR,val)
#define pDMA1_1_START_ADDR (volatile void **)DMA1_1_START_ADDR
#define bfin_read_DMA1_1_START_ADDR()        bfin_read32(DMA1_1_START_ADDR)
#define bfin_write_DMA1_1_START_ADDR(val)    bfin_write32(DMA1_1_START_ADDR,val)
#define pDMA1_1_X_COUNT (volatile unsigned short *)DMA1_1_X_COUNT
#define bfin_read_DMA1_1_X_COUNT()           bfin_read16(DMA1_1_X_COUNT)
#define bfin_write_DMA1_1_X_COUNT(val)       bfin_write16(DMA1_1_X_COUNT,val)
#define pDMA1_1_Y_COUNT (volatile unsigned short *)DMA1_1_Y_COUNT
#define bfin_read_DMA1_1_Y_COUNT()           bfin_read16(DMA1_1_Y_COUNT)
#define bfin_write_DMA1_1_Y_COUNT(val)       bfin_write16(DMA1_1_Y_COUNT,val)
#define pDMA1_1_X_MODIFY (volatile signed short *)DMA1_1_X_MODIFY
#define bfin_read_DMA1_1_X_MODIFY()          bfin_read16(DMA1_1_X_MODIFY)
#define bfin_write_DMA1_1_X_MODIFY(val)      bfin_write16(DMA1_1_X_MODIFY,val)
#define pDMA1_1_Y_MODIFY (volatile signed short *)DMA1_1_Y_MODIFY
#define bfin_read_DMA1_1_Y_MODIFY()          bfin_read16(DMA1_1_Y_MODIFY)
#define bfin_write_DMA1_1_Y_MODIFY(val)      bfin_write16(DMA1_1_Y_MODIFY,val)
#define pDMA1_1_CURR_DESC_PTR (volatile void **)DMA1_1_CURR_DESC_PTR
#define bfin_read_DMA1_1_CURR_DESC_PTR()     bfin_read32(DMA1_1_CURR_DESC_PTR)
#define bfin_write_DMA1_1_CURR_DESC_PTR(val) bfin_write32(DMA1_1_CURR_DESC_PTR,val)
#define pDMA1_1_CURR_ADDR (volatile void **)DMA1_1_CURR_ADDR
#define bfin_read_DMA1_1_CURR_ADDR()         bfin_read32(DMA1_1_CURR_ADDR)
#define bfin_write_DMA1_1_CURR_ADDR(val)     bfin_write32(DMA1_1_CURR_ADDR,val)
#define pDMA1_1_CURR_X_COUNT (volatile unsigned short *)DMA1_1_CURR_X_COUNT
#define bfin_read_DMA1_1_CURR_X_COUNT()      bfin_read16(DMA1_1_CURR_X_COUNT)
#define bfin_write_DMA1_1_CURR_X_COUNT(val)  bfin_write16(DMA1_1_CURR_X_COUNT,val)
#define pDMA1_1_CURR_Y_COUNT (volatile unsigned short *)DMA1_1_CURR_Y_COUNT
#define bfin_read_DMA1_1_CURR_Y_COUNT()      bfin_read16(DMA1_1_CURR_Y_COUNT)
#define bfin_write_DMA1_1_CURR_Y_COUNT(val)  bfin_write16(DMA1_1_CURR_Y_COUNT,val)
#define pDMA1_1_IRQ_STATUS (volatile unsigned short *)DMA1_1_IRQ_STATUS
#define bfin_read_DMA1_1_IRQ_STATUS()        bfin_read16(DMA1_1_IRQ_STATUS)
#define bfin_write_DMA1_1_IRQ_STATUS(val)    bfin_write16(DMA1_1_IRQ_STATUS,val)
#define pDMA1_1_PERIPHERAL_MAP (volatile unsigned short *)DMA1_1_PERIPHERAL_MAP
#define bfin_read_DMA1_1_PERIPHERAL_MAP()    bfin_read16(DMA1_1_PERIPHERAL_MAP)
#define bfin_write_DMA1_1_PERIPHERAL_MAP(val) bfin_write16(DMA1_1_PERIPHERAL_MAP,val)
#define pDMA1_2_CONFIG (volatile unsigned short *)DMA1_2_CONFIG
#define bfin_read_DMA1_2_CONFIG()            bfin_read16(DMA1_2_CONFIG)
#define bfin_write_DMA1_2_CONFIG(val)        bfin_write16(DMA1_2_CONFIG,val)
#define pDMA1_2_NEXT_DESC_PTR (volatile void **)DMA1_2_NEXT_DESC_PTR
#define bfin_read_DMA1_2_NEXT_DESC_PTR()     bfin_read32(DMA1_2_NEXT_DESC_PTR)
#define bfin_write_DMA1_2_NEXT_DESC_PTR(val) bfin_write32(DMA1_2_NEXT_DESC_PTR,val)
#define pDMA1_2_START_ADDR (volatile void **)DMA1_2_START_ADDR
#define bfin_read_DMA1_2_START_ADDR()        bfin_read32(DMA1_2_START_ADDR)
#define bfin_write_DMA1_2_START_ADDR(val)    bfin_write32(DMA1_2_START_ADDR,val)
#define pDMA1_2_X_COUNT (volatile unsigned short *)DMA1_2_X_COUNT
#define bfin_read_DMA1_2_X_COUNT()           bfin_read16(DMA1_2_X_COUNT)
#define bfin_write_DMA1_2_X_COUNT(val)       bfin_write16(DMA1_2_X_COUNT,val)
#define pDMA1_2_Y_COUNT (volatile unsigned short *)DMA1_2_Y_COUNT
#define bfin_read_DMA1_2_Y_COUNT()           bfin_read16(DMA1_2_Y_COUNT)
#define bfin_write_DMA1_2_Y_COUNT(val)       bfin_write16(DMA1_2_Y_COUNT,val)
#define pDMA1_2_X_MODIFY (volatile signed short *)DMA1_2_X_MODIFY
#define bfin_read_DMA1_2_X_MODIFY()          bfin_read16(DMA1_2_X_MODIFY)
#define bfin_write_DMA1_2_X_MODIFY(val)      bfin_write16(DMA1_2_X_MODIFY,val)
#define pDMA1_2_Y_MODIFY (volatile signed short *)DMA1_2_Y_MODIFY
#define bfin_read_DMA1_2_Y_MODIFY()          bfin_read16(DMA1_2_Y_MODIFY)
#define bfin_write_DMA1_2_Y_MODIFY(val)      bfin_write16(DMA1_2_Y_MODIFY,val)
#define pDMA1_2_CURR_DESC_PTR (volatile void **)DMA1_2_CURR_DESC_PTR
#define bfin_read_DMA1_2_CURR_DESC_PTR()     bfin_read32(DMA1_2_CURR_DESC_PTR)
#define bfin_write_DMA1_2_CURR_DESC_PTR(val) bfin_write32(DMA1_2_CURR_DESC_PTR,val)
#define pDMA1_2_CURR_ADDR (volatile void **)DMA1_2_CURR_ADDR
#define bfin_read_DMA1_2_CURR_ADDR()         bfin_read32(DMA1_2_CURR_ADDR)
#define bfin_write_DMA1_2_CURR_ADDR(val)     bfin_write32(DMA1_2_CURR_ADDR,val)
#define pDMA1_2_CURR_X_COUNT (volatile unsigned short *)DMA1_2_CURR_X_COUNT
#define bfin_read_DMA1_2_CURR_X_COUNT()      bfin_read16(DMA1_2_CURR_X_COUNT)
#define bfin_write_DMA1_2_CURR_X_COUNT(val)  bfin_write16(DMA1_2_CURR_X_COUNT,val)
#define pDMA1_2_CURR_Y_COUNT (volatile unsigned short *)DMA1_2_CURR_Y_COUNT
#define bfin_read_DMA1_2_CURR_Y_COUNT()      bfin_read16(DMA1_2_CURR_Y_COUNT)
#define bfin_write_DMA1_2_CURR_Y_COUNT(val)  bfin_write16(DMA1_2_CURR_Y_COUNT,val)
#define pDMA1_2_IRQ_STATUS (volatile unsigned short *)DMA1_2_IRQ_STATUS
#define bfin_read_DMA1_2_IRQ_STATUS()        bfin_read16(DMA1_2_IRQ_STATUS)
#define bfin_write_DMA1_2_IRQ_STATUS(val)    bfin_write16(DMA1_2_IRQ_STATUS,val)
#define pDMA1_2_PERIPHERAL_MAP (volatile unsigned short *)DMA1_2_PERIPHERAL_MAP
#define bfin_read_DMA1_2_PERIPHERAL_MAP()    bfin_read16(DMA1_2_PERIPHERAL_MAP)
#define bfin_write_DMA1_2_PERIPHERAL_MAP(val) bfin_write16(DMA1_2_PERIPHERAL_MAP,val)
#define pDMA1_3_CONFIG (volatile unsigned short *)DMA1_3_CONFIG
#define bfin_read_DMA1_3_CONFIG()            bfin_read16(DMA1_3_CONFIG)
#define bfin_write_DMA1_3_CONFIG(val)        bfin_write16(DMA1_3_CONFIG,val)
#define pDMA1_3_NEXT_DESC_PTR (volatile void **)DMA1_3_NEXT_DESC_PTR
#define bfin_read_DMA1_3_NEXT_DESC_PTR()     bfin_read32(DMA1_3_NEXT_DESC_PTR)
#define bfin_write_DMA1_3_NEXT_DESC_PTR(val) bfin_write32(DMA1_3_NEXT_DESC_PTR,val)
#define pDMA1_3_START_ADDR (volatile void **)DMA1_3_START_ADDR
#define bfin_read_DMA1_3_START_ADDR()        bfin_read32(DMA1_3_START_ADDR)
#define bfin_write_DMA1_3_START_ADDR(val)    bfin_write32(DMA1_3_START_ADDR,val)
#define pDMA1_3_X_COUNT (volatile unsigned short *)DMA1_3_X_COUNT
#define bfin_read_DMA1_3_X_COUNT()           bfin_read16(DMA1_3_X_COUNT)
#define bfin_write_DMA1_3_X_COUNT(val)       bfin_write16(DMA1_3_X_COUNT,val)
#define pDMA1_3_Y_COUNT (volatile unsigned short *)DMA1_3_Y_COUNT
#define bfin_read_DMA1_3_Y_COUNT()           bfin_read16(DMA1_3_Y_COUNT)
#define bfin_write_DMA1_3_Y_COUNT(val)       bfin_write16(DMA1_3_Y_COUNT,val)
#define pDMA1_3_X_MODIFY (volatile signed short *)DMA1_3_X_MODIFY
#define bfin_read_DMA1_3_X_MODIFY()          bfin_read16(DMA1_3_X_MODIFY)
#define bfin_write_DMA1_3_X_MODIFY(val)      bfin_write16(DMA1_3_X_MODIFY,val)
#define pDMA1_3_Y_MODIFY (volatile signed short *)DMA1_3_Y_MODIFY
#define bfin_read_DMA1_3_Y_MODIFY()          bfin_read16(DMA1_3_Y_MODIFY)
#define bfin_write_DMA1_3_Y_MODIFY(val)      bfin_write16(DMA1_3_Y_MODIFY,val)
#define pDMA1_3_CURR_DESC_PTR (volatile void **)DMA1_3_CURR_DESC_PTR
#define bfin_read_DMA1_3_CURR_DESC_PTR()     bfin_read32(DMA1_3_CURR_DESC_PTR)
#define bfin_write_DMA1_3_CURR_DESC_PTR(val) bfin_write32(DMA1_3_CURR_DESC_PTR,val)
#define pDMA1_3_CURR_ADDR (volatile void **)DMA1_3_CURR_ADDR
#define bfin_read_DMA1_3_CURR_ADDR()         bfin_read32(DMA1_3_CURR_ADDR)
#define bfin_write_DMA1_3_CURR_ADDR(val)     bfin_write32(DMA1_3_CURR_ADDR,val)
#define pDMA1_3_CURR_X_COUNT (volatile unsigned short *)DMA1_3_CURR_X_COUNT
#define bfin_read_DMA1_3_CURR_X_COUNT()      bfin_read16(DMA1_3_CURR_X_COUNT)
#define bfin_write_DMA1_3_CURR_X_COUNT(val)  bfin_write16(DMA1_3_CURR_X_COUNT,val)
#define pDMA1_3_CURR_Y_COUNT (volatile unsigned short *)DMA1_3_CURR_Y_COUNT
#define bfin_read_DMA1_3_CURR_Y_COUNT()      bfin_read16(DMA1_3_CURR_Y_COUNT)
#define bfin_write_DMA1_3_CURR_Y_COUNT(val)  bfin_write16(DMA1_3_CURR_Y_COUNT,val)
#define pDMA1_3_IRQ_STATUS (volatile unsigned short *)DMA1_3_IRQ_STATUS
#define bfin_read_DMA1_3_IRQ_STATUS()        bfin_read16(DMA1_3_IRQ_STATUS)
#define bfin_write_DMA1_3_IRQ_STATUS(val)    bfin_write16(DMA1_3_IRQ_STATUS,val)
#define pDMA1_3_PERIPHERAL_MAP (volatile unsigned short *)DMA1_3_PERIPHERAL_MAP
#define bfin_read_DMA1_3_PERIPHERAL_MAP()    bfin_read16(DMA1_3_PERIPHERAL_MAP)
#define bfin_write_DMA1_3_PERIPHERAL_MAP(val) bfin_write16(DMA1_3_PERIPHERAL_MAP,val)
#define pDMA1_4_CONFIG (volatile unsigned short *)DMA1_4_CONFIG
#define bfin_read_DMA1_4_CONFIG()            bfin_read16(DMA1_4_CONFIG)
#define bfin_write_DMA1_4_CONFIG(val)        bfin_write16(DMA1_4_CONFIG,val)
#define pDMA1_4_NEXT_DESC_PTR (volatile void **)DMA1_4_NEXT_DESC_PTR
#define bfin_read_DMA1_4_NEXT_DESC_PTR()     bfin_read32(DMA1_4_NEXT_DESC_PTR)
#define bfin_write_DMA1_4_NEXT_DESC_PTR(val) bfin_write32(DMA1_4_NEXT_DESC_PTR,val)
#define pDMA1_4_START_ADDR (volatile void **)DMA1_4_START_ADDR
#define bfin_read_DMA1_4_START_ADDR()        bfin_read32(DMA1_4_START_ADDR)
#define bfin_write_DMA1_4_START_ADDR(val)    bfin_write32(DMA1_4_START_ADDR,val)
#define pDMA1_4_X_COUNT (volatile unsigned short *)DMA1_4_X_COUNT
#define bfin_read_DMA1_4_X_COUNT()           bfin_read16(DMA1_4_X_COUNT)
#define bfin_write_DMA1_4_X_COUNT(val)       bfin_write16(DMA1_4_X_COUNT,val)
#define pDMA1_4_Y_COUNT (volatile unsigned short *)DMA1_4_Y_COUNT
#define bfin_read_DMA1_4_Y_COUNT()           bfin_read16(DMA1_4_Y_COUNT)
#define bfin_write_DMA1_4_Y_COUNT(val)       bfin_write16(DMA1_4_Y_COUNT,val)
#define pDMA1_4_X_MODIFY (volatile signed short *)DMA1_4_X_MODIFY
#define bfin_read_DMA1_4_X_MODIFY()          bfin_read16(DMA1_4_X_MODIFY)
#define bfin_write_DMA1_4_X_MODIFY(val)      bfin_write16(DMA1_4_X_MODIFY,val)
#define pDMA1_4_Y_MODIFY (volatile signed short *)DMA1_4_Y_MODIFY
#define bfin_read_DMA1_4_Y_MODIFY()          bfin_read16(DMA1_4_Y_MODIFY)
#define bfin_write_DMA1_4_Y_MODIFY(val)      bfin_write16(DMA1_4_Y_MODIFY,val)
#define pDMA1_4_CURR_DESC_PTR (volatile void **)DMA1_4_CURR_DESC_PTR
#define bfin_read_DMA1_4_CURR_DESC_PTR()     bfin_read32(DMA1_4_CURR_DESC_PTR)
#define bfin_write_DMA1_4_CURR_DESC_PTR(val) bfin_write32(DMA1_4_CURR_DESC_PTR,val)
#define pDMA1_4_CURR_ADDR (volatile void **)DMA1_4_CURR_ADDR
#define bfin_read_DMA1_4_CURR_ADDR()         bfin_read32(DMA1_4_CURR_ADDR)
#define bfin_write_DMA1_4_CURR_ADDR(val)     bfin_write32(DMA1_4_CURR_ADDR,val)
#define pDMA1_4_CURR_X_COUNT (volatile unsigned short *)DMA1_4_CURR_X_COUNT
#define bfin_read_DMA1_4_CURR_X_COUNT()      bfin_read16(DMA1_4_CURR_X_COUNT)
#define bfin_write_DMA1_4_CURR_X_COUNT(val)  bfin_write16(DMA1_4_CURR_X_COUNT,val)
#define pDMA1_4_CURR_Y_COUNT (volatile unsigned short *)DMA1_4_CURR_Y_COUNT
#define bfin_read_DMA1_4_CURR_Y_COUNT()      bfin_read16(DMA1_4_CURR_Y_COUNT)
#define bfin_write_DMA1_4_CURR_Y_COUNT(val)  bfin_write16(DMA1_4_CURR_Y_COUNT,val)
#define pDMA1_4_IRQ_STATUS (volatile unsigned short *)DMA1_4_IRQ_STATUS
#define bfin_read_DMA1_4_IRQ_STATUS()        bfin_read16(DMA1_4_IRQ_STATUS)
#define bfin_write_DMA1_4_IRQ_STATUS(val)    bfin_write16(DMA1_4_IRQ_STATUS,val)
#define pDMA1_4_PERIPHERAL_MAP (volatile unsigned short *)DMA1_4_PERIPHERAL_MAP
#define bfin_read_DMA1_4_PERIPHERAL_MAP()    bfin_read16(DMA1_4_PERIPHERAL_MAP)
#define bfin_write_DMA1_4_PERIPHERAL_MAP(val) bfin_write16(DMA1_4_PERIPHERAL_MAP,val)
#define pDMA1_5_CONFIG (volatile unsigned short *)DMA1_5_CONFIG
#define bfin_read_DMA1_5_CONFIG()            bfin_read16(DMA1_5_CONFIG)
#define bfin_write_DMA1_5_CONFIG(val)        bfin_write16(DMA1_5_CONFIG,val)
#define pDMA1_5_NEXT_DESC_PTR (volatile void **)DMA1_5_NEXT_DESC_PTR
#define bfin_read_DMA1_5_NEXT_DESC_PTR()     bfin_read32(DMA1_5_NEXT_DESC_PTR)
#define bfin_write_DMA1_5_NEXT_DESC_PTR(val) bfin_write32(DMA1_5_NEXT_DESC_PTR,val)
#define pDMA1_5_START_ADDR (volatile void **)DMA1_5_START_ADDR
#define bfin_read_DMA1_5_START_ADDR()        bfin_read32(DMA1_5_START_ADDR)
#define bfin_write_DMA1_5_START_ADDR(val)    bfin_write32(DMA1_5_START_ADDR,val)
#define pDMA1_5_X_COUNT (volatile unsigned short *)DMA1_5_X_COUNT
#define bfin_read_DMA1_5_X_COUNT()           bfin_read16(DMA1_5_X_COUNT)
#define bfin_write_DMA1_5_X_COUNT(val)       bfin_write16(DMA1_5_X_COUNT,val)
#define pDMA1_5_Y_COUNT (volatile unsigned short *)DMA1_5_Y_COUNT
#define bfin_read_DMA1_5_Y_COUNT()           bfin_read16(DMA1_5_Y_COUNT)
#define bfin_write_DMA1_5_Y_COUNT(val)       bfin_write16(DMA1_5_Y_COUNT,val)
#define pDMA1_5_X_MODIFY (volatile signed short *)DMA1_5_X_MODIFY
#define bfin_read_DMA1_5_X_MODIFY()          bfin_read16(DMA1_5_X_MODIFY)
#define bfin_write_DMA1_5_X_MODIFY(val)      bfin_write16(DMA1_5_X_MODIFY,val)
#define pDMA1_5_Y_MODIFY (volatile signed short *)DMA1_5_Y_MODIFY
#define bfin_read_DMA1_5_Y_MODIFY()          bfin_read16(DMA1_5_Y_MODIFY)
#define bfin_write_DMA1_5_Y_MODIFY(val)      bfin_write16(DMA1_5_Y_MODIFY,val)
#define pDMA1_5_CURR_DESC_PTR (volatile void **)DMA1_5_CURR_DESC_PTR
#define bfin_read_DMA1_5_CURR_DESC_PTR()     bfin_read32(DMA1_5_CURR_DESC_PTR)
#define bfin_write_DMA1_5_CURR_DESC_PTR(val) bfin_write32(DMA1_5_CURR_DESC_PTR,val)
#define pDMA1_5_CURR_ADDR (volatile void **)DMA1_5_CURR_ADDR
#define bfin_read_DMA1_5_CURR_ADDR()         bfin_read32(DMA1_5_CURR_ADDR)
#define bfin_write_DMA1_5_CURR_ADDR(val)     bfin_write32(DMA1_5_CURR_ADDR,val)
#define pDMA1_5_CURR_X_COUNT (volatile unsigned short *)DMA1_5_CURR_X_COUNT
#define bfin_read_DMA1_5_CURR_X_COUNT()      bfin_read16(DMA1_5_CURR_X_COUNT)
#define bfin_write_DMA1_5_CURR_X_COUNT(val)  bfin_write16(DMA1_5_CURR_X_COUNT,val)
#define pDMA1_5_CURR_Y_COUNT (volatile unsigned short *)DMA1_5_CURR_Y_COUNT
#define bfin_read_DMA1_5_CURR_Y_COUNT()      bfin_read16(DMA1_5_CURR_Y_COUNT)
#define bfin_write_DMA1_5_CURR_Y_COUNT(val)  bfin_write16(DMA1_5_CURR_Y_COUNT,val)
#define pDMA1_5_IRQ_STATUS (volatile unsigned short *)DMA1_5_IRQ_STATUS
#define bfin_read_DMA1_5_IRQ_STATUS()        bfin_read16(DMA1_5_IRQ_STATUS)
#define bfin_write_DMA1_5_IRQ_STATUS(val)    bfin_write16(DMA1_5_IRQ_STATUS,val)
#define pDMA1_5_PERIPHERAL_MAP (volatile unsigned short *)DMA1_5_PERIPHERAL_MAP
#define bfin_read_DMA1_5_PERIPHERAL_MAP()    bfin_read16(DMA1_5_PERIPHERAL_MAP)
#define bfin_write_DMA1_5_PERIPHERAL_MAP(val) bfin_write16(DMA1_5_PERIPHERAL_MAP,val)
#define pDMA1_6_CONFIG (volatile unsigned short *)DMA1_6_CONFIG
#define bfin_read_DMA1_6_CONFIG()            bfin_read16(DMA1_6_CONFIG)
#define bfin_write_DMA1_6_CONFIG(val)        bfin_write16(DMA1_6_CONFIG,val)
#define pDMA1_6_NEXT_DESC_PTR (volatile void **)DMA1_6_NEXT_DESC_PTR
#define bfin_read_DMA1_6_NEXT_DESC_PTR()     bfin_read32(DMA1_6_NEXT_DESC_PTR)
#define bfin_write_DMA1_6_NEXT_DESC_PTR(val) bfin_write32(DMA1_6_NEXT_DESC_PTR,val)
#define pDMA1_6_START_ADDR (volatile void **)DMA1_6_START_ADDR
#define bfin_read_DMA1_6_START_ADDR()        bfin_read32(DMA1_6_START_ADDR)
#define bfin_write_DMA1_6_START_ADDR(val)    bfin_write32(DMA1_6_START_ADDR,val)
#define pDMA1_6_X_COUNT (volatile unsigned short *)DMA1_6_X_COUNT
#define bfin_read_DMA1_6_X_COUNT()           bfin_read16(DMA1_6_X_COUNT)
#define bfin_write_DMA1_6_X_COUNT(val)       bfin_write16(DMA1_6_X_COUNT,val)
#define pDMA1_6_Y_COUNT (volatile unsigned short *)DMA1_6_Y_COUNT
#define bfin_read_DMA1_6_Y_COUNT()           bfin_read16(DMA1_6_Y_COUNT)
#define bfin_write_DMA1_6_Y_COUNT(val)       bfin_write16(DMA1_6_Y_COUNT,val)
#define pDMA1_6_X_MODIFY (volatile signed short *)DMA1_6_X_MODIFY
#define bfin_read_DMA1_6_X_MODIFY()          bfin_read16(DMA1_6_X_MODIFY)
#define bfin_write_DMA1_6_X_MODIFY(val)      bfin_write16(DMA1_6_X_MODIFY,val)
#define pDMA1_6_Y_MODIFY (volatile signed short *)DMA1_6_Y_MODIFY
#define bfin_read_DMA1_6_Y_MODIFY()          bfin_read16(DMA1_6_Y_MODIFY)
#define bfin_write_DMA1_6_Y_MODIFY(val)      bfin_write16(DMA1_6_Y_MODIFY,val)
#define pDMA1_6_CURR_DESC_PTR (volatile void **)DMA1_6_CURR_DESC_PTR
#define bfin_read_DMA1_6_CURR_DESC_PTR()     bfin_read32(DMA1_6_CURR_DESC_PTR)
#define bfin_write_DMA1_6_CURR_DESC_PTR(val) bfin_write32(DMA1_6_CURR_DESC_PTR,val)
#define pDMA1_6_CURR_ADDR (volatile void **)DMA1_6_CURR_ADDR
#define bfin_read_DMA1_6_CURR_ADDR()         bfin_read32(DMA1_6_CURR_ADDR)
#define bfin_write_DMA1_6_CURR_ADDR(val)     bfin_write32(DMA1_6_CURR_ADDR,val)
#define pDMA1_6_CURR_X_COUNT (volatile unsigned short *)DMA1_6_CURR_X_COUNT
#define bfin_read_DMA1_6_CURR_X_COUNT()      bfin_read16(DMA1_6_CURR_X_COUNT)
#define bfin_write_DMA1_6_CURR_X_COUNT(val)  bfin_write16(DMA1_6_CURR_X_COUNT,val)
#define pDMA1_6_CURR_Y_COUNT (volatile unsigned short *)DMA1_6_CURR_Y_COUNT
#define bfin_read_DMA1_6_CURR_Y_COUNT()      bfin_read16(DMA1_6_CURR_Y_COUNT)
#define bfin_write_DMA1_6_CURR_Y_COUNT(val)  bfin_write16(DMA1_6_CURR_Y_COUNT,val)
#define pDMA1_6_IRQ_STATUS (volatile unsigned short *)DMA1_6_IRQ_STATUS
#define bfin_read_DMA1_6_IRQ_STATUS()        bfin_read16(DMA1_6_IRQ_STATUS)
#define bfin_write_DMA1_6_IRQ_STATUS(val)    bfin_write16(DMA1_6_IRQ_STATUS,val)
#define pDMA1_6_PERIPHERAL_MAP (volatile unsigned short *)DMA1_6_PERIPHERAL_MAP
#define bfin_read_DMA1_6_PERIPHERAL_MAP()    bfin_read16(DMA1_6_PERIPHERAL_MAP)
#define bfin_write_DMA1_6_PERIPHERAL_MAP(val) bfin_write16(DMA1_6_PERIPHERAL_MAP,val)
#define pDMA1_7_CONFIG (volatile unsigned short *)DMA1_7_CONFIG
#define bfin_read_DMA1_7_CONFIG()            bfin_read16(DMA1_7_CONFIG)
#define bfin_write_DMA1_7_CONFIG(val)        bfin_write16(DMA1_7_CONFIG,val)
#define pDMA1_7_NEXT_DESC_PTR (volatile void **)DMA1_7_NEXT_DESC_PTR
#define bfin_read_DMA1_7_NEXT_DESC_PTR()     bfin_read32(DMA1_7_NEXT_DESC_PTR)
#define bfin_write_DMA1_7_NEXT_DESC_PTR(val) bfin_write32(DMA1_7_NEXT_DESC_PTR,val)
#define pDMA1_7_START_ADDR (volatile void **)DMA1_7_START_ADDR
#define bfin_read_DMA1_7_START_ADDR()        bfin_read32(DMA1_7_START_ADDR)
#define bfin_write_DMA1_7_START_ADDR(val)    bfin_write32(DMA1_7_START_ADDR,val)
#define pDMA1_7_X_COUNT (volatile unsigned short *)DMA1_7_X_COUNT
#define bfin_read_DMA1_7_X_COUNT()           bfin_read16(DMA1_7_X_COUNT)
#define bfin_write_DMA1_7_X_COUNT(val)       bfin_write16(DMA1_7_X_COUNT,val)
#define pDMA1_7_Y_COUNT (volatile unsigned short *)DMA1_7_Y_COUNT
#define bfin_read_DMA1_7_Y_COUNT()           bfin_read16(DMA1_7_Y_COUNT)
#define bfin_write_DMA1_7_Y_COUNT(val)       bfin_write16(DMA1_7_Y_COUNT,val)
#define pDMA1_7_X_MODIFY (volatile signed short *)DMA1_7_X_MODIFY
#define bfin_read_DMA1_7_X_MODIFY()          bfin_read16(DMA1_7_X_MODIFY)
#define bfin_write_DMA1_7_X_MODIFY(val)      bfin_write16(DMA1_7_X_MODIFY,val)
#define pDMA1_7_Y_MODIFY (volatile signed short *)DMA1_7_Y_MODIFY
#define bfin_read_DMA1_7_Y_MODIFY()          bfin_read16(DMA1_7_Y_MODIFY)
#define bfin_write_DMA1_7_Y_MODIFY(val)      bfin_write16(DMA1_7_Y_MODIFY,val)
#define pDMA1_7_CURR_DESC_PTR (volatile void **)DMA1_7_CURR_DESC_PTR
#define bfin_read_DMA1_7_CURR_DESC_PTR()     bfin_read32(DMA1_7_CURR_DESC_PTR)
#define bfin_write_DMA1_7_CURR_DESC_PTR(val) bfin_write32(DMA1_7_CURR_DESC_PTR,val)
#define pDMA1_7_CURR_ADDR (volatile void **)DMA1_7_CURR_ADDR
#define bfin_read_DMA1_7_CURR_ADDR()         bfin_read32(DMA1_7_CURR_ADDR)
#define bfin_write_DMA1_7_CURR_ADDR(val)     bfin_write32(DMA1_7_CURR_ADDR,val)
#define pDMA1_7_CURR_X_COUNT (volatile unsigned short *)DMA1_7_CURR_X_COUNT
#define bfin_read_DMA1_7_CURR_X_COUNT()      bfin_read16(DMA1_7_CURR_X_COUNT)
#define bfin_write_DMA1_7_CURR_X_COUNT(val)  bfin_write16(DMA1_7_CURR_X_COUNT,val)
#define pDMA1_7_CURR_Y_COUNT (volatile unsigned short *)DMA1_7_CURR_Y_COUNT
#define bfin_read_DMA1_7_CURR_Y_COUNT()      bfin_read16(DMA1_7_CURR_Y_COUNT)
#define bfin_write_DMA1_7_CURR_Y_COUNT(val)  bfin_write16(DMA1_7_CURR_Y_COUNT,val)
#define pDMA1_7_IRQ_STATUS (volatile unsigned short *)DMA1_7_IRQ_STATUS
#define bfin_read_DMA1_7_IRQ_STATUS()        bfin_read16(DMA1_7_IRQ_STATUS)
#define bfin_write_DMA1_7_IRQ_STATUS(val)    bfin_write16(DMA1_7_IRQ_STATUS,val)
#define pDMA1_7_PERIPHERAL_MAP (volatile unsigned short *)DMA1_7_PERIPHERAL_MAP
#define bfin_read_DMA1_7_PERIPHERAL_MAP()    bfin_read16(DMA1_7_PERIPHERAL_MAP)
#define bfin_write_DMA1_7_PERIPHERAL_MAP(val) bfin_write16(DMA1_7_PERIPHERAL_MAP,val)
#define pDMA1_8_CONFIG (volatile unsigned short *)DMA1_8_CONFIG
#define bfin_read_DMA1_8_CONFIG()            bfin_read16(DMA1_8_CONFIG)
#define bfin_write_DMA1_8_CONFIG(val)        bfin_write16(DMA1_8_CONFIG,val)
#define pDMA1_8_NEXT_DESC_PTR (volatile void **)DMA1_8_NEXT_DESC_PTR
#define bfin_read_DMA1_8_NEXT_DESC_PTR()     bfin_read32(DMA1_8_NEXT_DESC_PTR)
#define bfin_write_DMA1_8_NEXT_DESC_PTR(val) bfin_write32(DMA1_8_NEXT_DESC_PTR,val)
#define pDMA1_8_START_ADDR (volatile void **)DMA1_8_START_ADDR
#define bfin_read_DMA1_8_START_ADDR()        bfin_read32(DMA1_8_START_ADDR)
#define bfin_write_DMA1_8_START_ADDR(val)    bfin_write32(DMA1_8_START_ADDR,val)
#define pDMA1_8_X_COUNT (volatile unsigned short *)DMA1_8_X_COUNT
#define bfin_read_DMA1_8_X_COUNT()           bfin_read16(DMA1_8_X_COUNT)
#define bfin_write_DMA1_8_X_COUNT(val)       bfin_write16(DMA1_8_X_COUNT,val)
#define pDMA1_8_Y_COUNT (volatile unsigned short *)DMA1_8_Y_COUNT
#define bfin_read_DMA1_8_Y_COUNT()           bfin_read16(DMA1_8_Y_COUNT)
#define bfin_write_DMA1_8_Y_COUNT(val)       bfin_write16(DMA1_8_Y_COUNT,val)
#define pDMA1_8_X_MODIFY (volatile signed short *)DMA1_8_X_MODIFY
#define bfin_read_DMA1_8_X_MODIFY()          bfin_read16(DMA1_8_X_MODIFY)
#define bfin_write_DMA1_8_X_MODIFY(val)      bfin_write16(DMA1_8_X_MODIFY,val)
#define pDMA1_8_Y_MODIFY (volatile signed short *)DMA1_8_Y_MODIFY
#define bfin_read_DMA1_8_Y_MODIFY()          bfin_read16(DMA1_8_Y_MODIFY)
#define bfin_write_DMA1_8_Y_MODIFY(val)      bfin_write16(DMA1_8_Y_MODIFY,val)
#define pDMA1_8_CURR_DESC_PTR (volatile void **)DMA1_8_CURR_DESC_PTR
#define bfin_read_DMA1_8_CURR_DESC_PTR()     bfin_read32(DMA1_8_CURR_DESC_PTR)
#define bfin_write_DMA1_8_CURR_DESC_PTR(val) bfin_write32(DMA1_8_CURR_DESC_PTR,val)
#define pDMA1_8_CURR_ADDR (volatile void **)DMA1_8_CURR_ADDR
#define bfin_read_DMA1_8_CURR_ADDR()         bfin_read32(DMA1_8_CURR_ADDR)
#define bfin_write_DMA1_8_CURR_ADDR(val)     bfin_write32(DMA1_8_CURR_ADDR,val)
#define pDMA1_8_CURR_X_COUNT (volatile unsigned short *)DMA1_8_CURR_X_COUNT
#define bfin_read_DMA1_8_CURR_X_COUNT()      bfin_read16(DMA1_8_CURR_X_COUNT)
#define bfin_write_DMA1_8_CURR_X_COUNT(val)  bfin_write16(DMA1_8_CURR_X_COUNT,val)
#define pDMA1_8_CURR_Y_COUNT (volatile unsigned short *)DMA1_8_CURR_Y_COUNT
#define bfin_read_DMA1_8_CURR_Y_COUNT()      bfin_read16(DMA1_8_CURR_Y_COUNT)
#define bfin_write_DMA1_8_CURR_Y_COUNT(val)  bfin_write16(DMA1_8_CURR_Y_COUNT,val)
#define pDMA1_8_IRQ_STATUS (volatile unsigned short *)DMA1_8_IRQ_STATUS
#define bfin_read_DMA1_8_IRQ_STATUS()        bfin_read16(DMA1_8_IRQ_STATUS)
#define bfin_write_DMA1_8_IRQ_STATUS(val)    bfin_write16(DMA1_8_IRQ_STATUS,val)
#define pDMA1_8_PERIPHERAL_MAP (volatile unsigned short *)DMA1_8_PERIPHERAL_MAP
#define bfin_read_DMA1_8_PERIPHERAL_MAP()    bfin_read16(DMA1_8_PERIPHERAL_MAP)
#define bfin_write_DMA1_8_PERIPHERAL_MAP(val) bfin_write16(DMA1_8_PERIPHERAL_MAP,val)
#define pDMA1_9_CONFIG (volatile unsigned short *)DMA1_9_CONFIG
#define bfin_read_DMA1_9_CONFIG()            bfin_read16(DMA1_9_CONFIG)
#define bfin_write_DMA1_9_CONFIG(val)        bfin_write16(DMA1_9_CONFIG,val)
#define pDMA1_9_NEXT_DESC_PTR (volatile void **)DMA1_9_NEXT_DESC_PTR
#define bfin_read_DMA1_9_NEXT_DESC_PTR()     bfin_read32(DMA1_9_NEXT_DESC_PTR)
#define bfin_write_DMA1_9_NEXT_DESC_PTR(val) bfin_write32(DMA1_9_NEXT_DESC_PTR,val)
#define pDMA1_9_START_ADDR (volatile void **)DMA1_9_START_ADDR
#define bfin_read_DMA1_9_START_ADDR()        bfin_read32(DMA1_9_START_ADDR)
#define bfin_write_DMA1_9_START_ADDR(val)    bfin_write32(DMA1_9_START_ADDR,val)
#define pDMA1_9_X_COUNT (volatile unsigned short *)DMA1_9_X_COUNT
#define bfin_read_DMA1_9_X_COUNT()           bfin_read16(DMA1_9_X_COUNT)
#define bfin_write_DMA1_9_X_COUNT(val)       bfin_write16(DMA1_9_X_COUNT,val)
#define pDMA1_9_Y_COUNT (volatile unsigned short *)DMA1_9_Y_COUNT
#define bfin_read_DMA1_9_Y_COUNT()           bfin_read16(DMA1_9_Y_COUNT)
#define bfin_write_DMA1_9_Y_COUNT(val)       bfin_write16(DMA1_9_Y_COUNT,val)
#define pDMA1_9_X_MODIFY (volatile signed short *)DMA1_9_X_MODIFY
#define bfin_read_DMA1_9_X_MODIFY()          bfin_read16(DMA1_9_X_MODIFY)
#define bfin_write_DMA1_9_X_MODIFY(val)      bfin_write16(DMA1_9_X_MODIFY,val)
#define pDMA1_9_Y_MODIFY (volatile signed short *)DMA1_9_Y_MODIFY
#define bfin_read_DMA1_9_Y_MODIFY()          bfin_read16(DMA1_9_Y_MODIFY)
#define bfin_write_DMA1_9_Y_MODIFY(val)      bfin_write16(DMA1_9_Y_MODIFY,val)
#define pDMA1_9_CURR_DESC_PTR (volatile void **)DMA1_9_CURR_DESC_PTR
#define bfin_read_DMA1_9_CURR_DESC_PTR()     bfin_read32(DMA1_9_CURR_DESC_PTR)
#define bfin_write_DMA1_9_CURR_DESC_PTR(val) bfin_write32(DMA1_9_CURR_DESC_PTR,val)
#define pDMA1_9_CURR_ADDR (volatile void **)DMA1_9_CURR_ADDR
#define bfin_read_DMA1_9_CURR_ADDR()         bfin_read32(DMA1_9_CURR_ADDR)
#define bfin_write_DMA1_9_CURR_ADDR(val)     bfin_write32(DMA1_9_CURR_ADDR,val)
#define pDMA1_9_CURR_X_COUNT (volatile unsigned short *)DMA1_9_CURR_X_COUNT
#define bfin_read_DMA1_9_CURR_X_COUNT()      bfin_read16(DMA1_9_CURR_X_COUNT)
#define bfin_write_DMA1_9_CURR_X_COUNT(val)  bfin_write16(DMA1_9_CURR_X_COUNT,val)
#define pDMA1_9_CURR_Y_COUNT (volatile unsigned short *)DMA1_9_CURR_Y_COUNT
#define bfin_read_DMA1_9_CURR_Y_COUNT()      bfin_read16(DMA1_9_CURR_Y_COUNT)
#define bfin_write_DMA1_9_CURR_Y_COUNT(val)  bfin_write16(DMA1_9_CURR_Y_COUNT,val)
#define pDMA1_9_IRQ_STATUS (volatile unsigned short *)DMA1_9_IRQ_STATUS
#define bfin_read_DMA1_9_IRQ_STATUS()        bfin_read16(DMA1_9_IRQ_STATUS)
#define bfin_write_DMA1_9_IRQ_STATUS(val)    bfin_write16(DMA1_9_IRQ_STATUS,val)
#define pDMA1_9_PERIPHERAL_MAP (volatile unsigned short *)DMA1_9_PERIPHERAL_MAP
#define bfin_read_DMA1_9_PERIPHERAL_MAP()    bfin_read16(DMA1_9_PERIPHERAL_MAP)
#define bfin_write_DMA1_9_PERIPHERAL_MAP(val) bfin_write16(DMA1_9_PERIPHERAL_MAP,val)
#define pDMA1_10_CONFIG (volatile unsigned short *)DMA1_10_CONFIG
#define bfin_read_DMA1_10_CONFIG()           bfin_read16(DMA1_10_CONFIG)
#define bfin_write_DMA1_10_CONFIG(val)       bfin_write16(DMA1_10_CONFIG,val)
#define pDMA1_10_NEXT_DESC_PTR (volatile void **)DMA1_10_NEXT_DESC_PTR
#define bfin_read_DMA1_10_NEXT_DESC_PTR()    bfin_read32(DMA1_10_NEXT_DESC_PTR)
#define bfin_write_DMA1_10_NEXT_DESC_PTR(val) bfin_write32(DMA1_10_NEXT_DESC_PTR,val)
#define pDMA1_10_START_ADDR (volatile void **)DMA1_10_START_ADDR
#define bfin_read_DMA1_10_START_ADDR()       bfin_read32(DMA1_10_START_ADDR)
#define bfin_write_DMA1_10_START_ADDR(val)   bfin_write32(DMA1_10_START_ADDR,val)
#define pDMA1_10_X_COUNT (volatile unsigned short *)DMA1_10_X_COUNT
#define bfin_read_DMA1_10_X_COUNT()          bfin_read16(DMA1_10_X_COUNT)
#define bfin_write_DMA1_10_X_COUNT(val)      bfin_write16(DMA1_10_X_COUNT,val)
#define pDMA1_10_Y_COUNT (volatile unsigned short *)DMA1_10_Y_COUNT
#define bfin_read_DMA1_10_Y_COUNT()          bfin_read16(DMA1_10_Y_COUNT)
#define bfin_write_DMA1_10_Y_COUNT(val)      bfin_write16(DMA1_10_Y_COUNT,val)
#define pDMA1_10_X_MODIFY (volatile signed short *)DMA1_10_X_MODIFY
#define bfin_read_DMA1_10_X_MODIFY()         bfin_read16(DMA1_10_X_MODIFY)
#define bfin_write_DMA1_10_X_MODIFY(val)     bfin_write16(DMA1_10_X_MODIFY,val)
#define pDMA1_10_Y_MODIFY (volatile signed short *)DMA1_10_Y_MODIFY
#define bfin_read_DMA1_10_Y_MODIFY()         bfin_read16(DMA1_10_Y_MODIFY)
#define bfin_write_DMA1_10_Y_MODIFY(val)     bfin_write16(DMA1_10_Y_MODIFY,val)
#define pDMA1_10_CURR_DESC_PTR (volatile void **)DMA1_10_CURR_DESC_PTR
#define bfin_read_DMA1_10_CURR_DESC_PTR()    bfin_read32(DMA1_10_CURR_DESC_PTR)
#define bfin_write_DMA1_10_CURR_DESC_PTR(val) bfin_write32(DMA1_10_CURR_DESC_PTR,val)
#define pDMA1_10_CURR_ADDR (volatile void **)DMA1_10_CURR_ADDR
#define bfin_read_DMA1_10_CURR_ADDR()        bfin_read32(DMA1_10_CURR_ADDR)
#define bfin_write_DMA1_10_CURR_ADDR(val)    bfin_write32(DMA1_10_CURR_ADDR,val)
#define pDMA1_10_CURR_X_COUNT (volatile unsigned short *)DMA1_10_CURR_X_COUNT
#define bfin_read_DMA1_10_CURR_X_COUNT()     bfin_read16(DMA1_10_CURR_X_COUNT)
#define bfin_write_DMA1_10_CURR_X_COUNT(val) bfin_write16(DMA1_10_CURR_X_COUNT,val)
#define pDMA1_10_CURR_Y_COUNT (volatile unsigned short *)DMA1_10_CURR_Y_COUNT
#define bfin_read_DMA1_10_CURR_Y_COUNT()     bfin_read16(DMA1_10_CURR_Y_COUNT)
#define bfin_write_DMA1_10_CURR_Y_COUNT(val) bfin_write16(DMA1_10_CURR_Y_COUNT,val)
#define pDMA1_10_IRQ_STATUS (volatile unsigned short *)DMA1_10_IRQ_STATUS
#define bfin_read_DMA1_10_IRQ_STATUS()       bfin_read16(DMA1_10_IRQ_STATUS)
#define bfin_write_DMA1_10_IRQ_STATUS(val)   bfin_write16(DMA1_10_IRQ_STATUS,val)
#define pDMA1_10_PERIPHERAL_MAP (volatile unsigned short *)DMA1_10_PERIPHERAL_MAP
#define bfin_read_DMA1_10_PERIPHERAL_MAP()   bfin_read16(DMA1_10_PERIPHERAL_MAP)
#define bfin_write_DMA1_10_PERIPHERAL_MAP(val) bfin_write16(DMA1_10_PERIPHERAL_MAP,val)
#define pDMA1_11_CONFIG (volatile unsigned short *)DMA1_11_CONFIG
#define bfin_read_DMA1_11_CONFIG()           bfin_read16(DMA1_11_CONFIG)
#define bfin_write_DMA1_11_CONFIG(val)       bfin_write16(DMA1_11_CONFIG,val)
#define pDMA1_11_NEXT_DESC_PTR (volatile void **)DMA1_11_NEXT_DESC_PTR
#define bfin_read_DMA1_11_NEXT_DESC_PTR()    bfin_read32(DMA1_11_NEXT_DESC_PTR)
#define bfin_write_DMA1_11_NEXT_DESC_PTR(val) bfin_write32(DMA1_11_NEXT_DESC_PTR,val)
#define pDMA1_11_START_ADDR (volatile void **)DMA1_11_START_ADDR
#define bfin_read_DMA1_11_START_ADDR()       bfin_read32(DMA1_11_START_ADDR)
#define bfin_write_DMA1_11_START_ADDR(val)   bfin_write32(DMA1_11_START_ADDR,val)
#define pDMA1_11_X_COUNT (volatile unsigned short *)DMA1_11_X_COUNT
#define bfin_read_DMA1_11_X_COUNT()          bfin_read16(DMA1_11_X_COUNT)
#define bfin_write_DMA1_11_X_COUNT(val)      bfin_write16(DMA1_11_X_COUNT,val)
#define pDMA1_11_Y_COUNT (volatile unsigned short *)DMA1_11_Y_COUNT
#define bfin_read_DMA1_11_Y_COUNT()          bfin_read16(DMA1_11_Y_COUNT)
#define bfin_write_DMA1_11_Y_COUNT(val)      bfin_write16(DMA1_11_Y_COUNT,val)
#define pDMA1_11_X_MODIFY (volatile signed short *)DMA1_11_X_MODIFY
#define bfin_read_DMA1_11_X_MODIFY()         bfin_read16(DMA1_11_X_MODIFY)
#define bfin_write_DMA1_11_X_MODIFY(val)     bfin_write16(DMA1_11_X_MODIFY,val)
#define pDMA1_11_Y_MODIFY (volatile signed short *)DMA1_11_Y_MODIFY
#define bfin_read_DMA1_11_Y_MODIFY()         bfin_read16(DMA1_11_Y_MODIFY)
#define bfin_write_DMA1_11_Y_MODIFY(val)     bfin_write16(DMA1_11_Y_MODIFY,val)
#define pDMA1_11_CURR_DESC_PTR (volatile void **)DMA1_11_CURR_DESC_PTR
#define bfin_read_DMA1_11_CURR_DESC_PTR()    bfin_read32(DMA1_11_CURR_DESC_PTR)
#define bfin_write_DMA1_11_CURR_DESC_PTR(val) bfin_write32(DMA1_11_CURR_DESC_PTR,val)
#define pDMA1_11_CURR_ADDR (volatile void **)DMA1_11_CURR_ADDR
#define bfin_read_DMA1_11_CURR_ADDR()        bfin_read32(DMA1_11_CURR_ADDR)
#define bfin_write_DMA1_11_CURR_ADDR(val)    bfin_write32(DMA1_11_CURR_ADDR,val)
#define pDMA1_11_CURR_X_COUNT (volatile unsigned short *)DMA1_11_CURR_X_COUNT
#define bfin_read_DMA1_11_CURR_X_COUNT()     bfin_read16(DMA1_11_CURR_X_COUNT)
#define bfin_write_DMA1_11_CURR_X_COUNT(val) bfin_write16(DMA1_11_CURR_X_COUNT,val)
#define pDMA1_11_CURR_Y_COUNT (volatile unsigned short *)DMA1_11_CURR_Y_COUNT
#define bfin_read_DMA1_11_CURR_Y_COUNT()     bfin_read16(DMA1_11_CURR_Y_COUNT)
#define bfin_write_DMA1_11_CURR_Y_COUNT(val) bfin_write16(DMA1_11_CURR_Y_COUNT,val)
#define pDMA1_11_IRQ_STATUS (volatile unsigned short *)DMA1_11_IRQ_STATUS
#define bfin_read_DMA1_11_IRQ_STATUS()       bfin_read16(DMA1_11_IRQ_STATUS)
#define bfin_write_DMA1_11_IRQ_STATUS(val)   bfin_write16(DMA1_11_IRQ_STATUS,val)
#define pDMA1_11_PERIPHERAL_MAP (volatile unsigned short *)DMA1_11_PERIPHERAL_MAP
#define bfin_read_DMA1_11_PERIPHERAL_MAP()   bfin_read16(DMA1_11_PERIPHERAL_MAP)
#define bfin_write_DMA1_11_PERIPHERAL_MAP(val) bfin_write16(DMA1_11_PERIPHERAL_MAP,val)
/* Memory DMA1 Controller registers (0xFFC0 1E80-0xFFC0 1FFF) */
#define pMDMA1_D0_CONFIG (volatile unsigned short *)MDMA1_D0_CONFIG
#define bfin_read_MDMA1_D0_CONFIG()          bfin_read16(MDMA1_D0_CONFIG)
#define bfin_write_MDMA1_D0_CONFIG(val)      bfin_write16(MDMA1_D0_CONFIG,val)
#define pMDMA1_D0_NEXT_DESC_PTR (volatile void **)MDMA1_D0_NEXT_DESC_PTR
#define bfin_read_MDMA1_D0_NEXT_DESC_PTR()   bfin_read32(MDMA1_D0_NEXT_DESC_PTR)
#define bfin_write_MDMA1_D0_NEXT_DESC_PTR(val) bfin_write32(MDMA1_D0_NEXT_DESC_PTR,val)
#define pMDMA1_D0_START_ADDR (volatile void **)MDMA1_D0_START_ADDR
#define bfin_read_MDMA1_D0_START_ADDR()      bfin_read32(MDMA1_D0_START_ADDR)
#define bfin_write_MDMA1_D0_START_ADDR(val)  bfin_write32(MDMA1_D0_START_ADDR,val)
#define pMDMA1_D0_X_COUNT (volatile unsigned short *)MDMA1_D0_X_COUNT
#define bfin_read_MDMA1_D0_X_COUNT()         bfin_read16(MDMA1_D0_X_COUNT)
#define bfin_write_MDMA1_D0_X_COUNT(val)     bfin_write16(MDMA1_D0_X_COUNT,val)
#define pMDMA1_D0_Y_COUNT (volatile unsigned short *)MDMA1_D0_Y_COUNT
#define bfin_read_MDMA1_D0_Y_COUNT()         bfin_read16(MDMA1_D0_Y_COUNT)
#define bfin_write_MDMA1_D0_Y_COUNT(val)     bfin_write16(MDMA1_D0_Y_COUNT,val)
#define pMDMA1_D0_X_MODIFY (volatile signed short *)MDMA1_D0_X_MODIFY
#define bfin_read_MDMA1_D0_X_MODIFY()        bfin_read16(MDMA1_D0_X_MODIFY)
#define bfin_write_MDMA1_D0_X_MODIFY(val)    bfin_write16(MDMA1_D0_X_MODIFY,val)
#define pMDMA1_D0_Y_MODIFY (volatile signed short *)MDMA1_D0_Y_MODIFY
#define bfin_read_MDMA1_D0_Y_MODIFY()        bfin_read16(MDMA1_D0_Y_MODIFY)
#define bfin_write_MDMA1_D0_Y_MODIFY(val)    bfin_write16(MDMA1_D0_Y_MODIFY,val)
#define pMDMA1_D0_CURR_DESC_PTR (volatile void **)MDMA1_D0_CURR_DESC_PTR
#define bfin_read_MDMA1_D0_CURR_DESC_PTR()   bfin_read32(MDMA1_D0_CURR_DESC_PTR)
#define bfin_write_MDMA1_D0_CURR_DESC_PTR(val) bfin_write32(MDMA1_D0_CURR_DESC_PTR,val)
#define pMDMA1_D0_CURR_ADDR (volatile void **)MDMA1_D0_CURR_ADDR
#define bfin_read_MDMA1_D0_CURR_ADDR()       bfin_read32(MDMA1_D0_CURR_ADDR)
#define bfin_write_MDMA1_D0_CURR_ADDR(val)   bfin_write32(MDMA1_D0_CURR_ADDR,val)
#define pMDMA1_D0_CURR_X_COUNT (volatile unsigned short *)MDMA1_D0_CURR_X_COUNT
#define bfin_read_MDMA1_D0_CURR_X_COUNT()    bfin_read16(MDMA1_D0_CURR_X_COUNT)
#define bfin_write_MDMA1_D0_CURR_X_COUNT(val) bfin_write16(MDMA1_D0_CURR_X_COUNT,val)
#define pMDMA1_D0_CURR_Y_COUNT (volatile unsigned short *)MDMA1_D0_CURR_Y_COUNT
#define bfin_read_MDMA1_D0_CURR_Y_COUNT()    bfin_read16(MDMA1_D0_CURR_Y_COUNT)
#define bfin_write_MDMA1_D0_CURR_Y_COUNT(val) bfin_write16(MDMA1_D0_CURR_Y_COUNT,val)
#define pMDMA1_D0_IRQ_STATUS (volatile unsigned short *)MDMA1_D0_IRQ_STATUS
#define bfin_read_MDMA1_D0_IRQ_STATUS()      bfin_read16(MDMA1_D0_IRQ_STATUS)
#define bfin_write_MDMA1_D0_IRQ_STATUS(val)  bfin_write16(MDMA1_D0_IRQ_STATUS,val)
#define pMDMA1_D0_PERIPHERAL_MAP (volatile unsigned short *)MDMA1_D0_PERIPHERAL_MAP
#define bfin_read_MDMA1_D0_PERIPHERAL_MAP()  bfin_read16(MDMA1_D0_PERIPHERAL_MAP)
#define bfin_write_MDMA1_D0_PERIPHERAL_MAP(val) bfin_write16(MDMA1_D0_PERIPHERAL_MAP,val)
#define pMDMA1_S0_CONFIG (volatile unsigned short *)MDMA1_S0_CONFIG
#define bfin_read_MDMA1_S0_CONFIG()          bfin_read16(MDMA1_S0_CONFIG)
#define bfin_write_MDMA1_S0_CONFIG(val)      bfin_write16(MDMA1_S0_CONFIG,val)
#define pMDMA1_S0_NEXT_DESC_PTR (volatile void **)MDMA1_S0_NEXT_DESC_PTR
#define bfin_read_MDMA1_S0_NEXT_DESC_PTR()   bfin_read32(MDMA1_S0_NEXT_DESC_PTR)
#define bfin_write_MDMA1_S0_NEXT_DESC_PTR(val) bfin_write32(MDMA1_S0_NEXT_DESC_PTR,val)
#define pMDMA1_S0_START_ADDR (volatile void **)MDMA1_S0_START_ADDR
#define bfin_read_MDMA1_S0_START_ADDR()      bfin_read32(MDMA1_S0_START_ADDR)
#define bfin_write_MDMA1_S0_START_ADDR(val)  bfin_write32(MDMA1_S0_START_ADDR,val)
#define pMDMA1_S0_X_COUNT (volatile unsigned short *)MDMA1_S0_X_COUNT
#define bfin_read_MDMA1_S0_X_COUNT()         bfin_read16(MDMA1_S0_X_COUNT)
#define bfin_write_MDMA1_S0_X_COUNT(val)     bfin_write16(MDMA1_S0_X_COUNT,val)
#define pMDMA1_S0_Y_COUNT (volatile unsigned short *)MDMA1_S0_Y_COUNT
#define bfin_read_MDMA1_S0_Y_COUNT()         bfin_read16(MDMA1_S0_Y_COUNT)
#define bfin_write_MDMA1_S0_Y_COUNT(val)     bfin_write16(MDMA1_S0_Y_COUNT,val)
#define pMDMA1_S0_X_MODIFY (volatile signed short *)MDMA1_S0_X_MODIFY
#define bfin_read_MDMA1_S0_X_MODIFY()        bfin_read16(MDMA1_S0_X_MODIFY)
#define bfin_write_MDMA1_S0_X_MODIFY(val)    bfin_write16(MDMA1_S0_X_MODIFY,val)
#define pMDMA1_S0_Y_MODIFY (volatile signed short *)MDMA1_S0_Y_MODIFY
#define bfin_read_MDMA1_S0_Y_MODIFY()        bfin_read16(MDMA1_S0_Y_MODIFY)
#define bfin_write_MDMA1_S0_Y_MODIFY(val)    bfin_write16(MDMA1_S0_Y_MODIFY,val)
#define pMDMA1_S0_CURR_DESC_PTR (volatile void **)MDMA1_S0_CURR_DESC_PTR
#define bfin_read_MDMA1_S0_CURR_DESC_PTR()   bfin_read32(MDMA1_S0_CURR_DESC_PTR)
#define bfin_write_MDMA1_S0_CURR_DESC_PTR(val) bfin_write32(MDMA1_S0_CURR_DESC_PTR,val)
#define pMDMA1_S0_CURR_ADDR (volatile void **)MDMA1_S0_CURR_ADDR
#define bfin_read_MDMA1_S0_CURR_ADDR()       bfin_read32(MDMA1_S0_CURR_ADDR)
#define bfin_write_MDMA1_S0_CURR_ADDR(val)   bfin_write32(MDMA1_S0_CURR_ADDR,val)
#define pMDMA1_S0_CURR_X_COUNT (volatile unsigned short *)MDMA1_S0_CURR_X_COUNT
#define bfin_read_MDMA1_S0_CURR_X_COUNT()    bfin_read16(MDMA1_S0_CURR_X_COUNT)
#define bfin_write_MDMA1_S0_CURR_X_COUNT(val) bfin_write16(MDMA1_S0_CURR_X_COUNT,val)
#define pMDMA1_S0_CURR_Y_COUNT (volatile unsigned short *)MDMA1_S0_CURR_Y_COUNT
#define bfin_read_MDMA1_S0_CURR_Y_COUNT()    bfin_read16(MDMA1_S0_CURR_Y_COUNT)
#define bfin_write_MDMA1_S0_CURR_Y_COUNT(val) bfin_write16(MDMA1_S0_CURR_Y_COUNT,val)
#define pMDMA1_S0_IRQ_STATUS (volatile unsigned short *)MDMA1_S0_IRQ_STATUS
#define bfin_read_MDMA1_S0_IRQ_STATUS()      bfin_read16(MDMA1_S0_IRQ_STATUS)
#define bfin_write_MDMA1_S0_IRQ_STATUS(val)  bfin_write16(MDMA1_S0_IRQ_STATUS,val)
#define pMDMA1_S0_PERIPHERAL_MAP (volatile unsigned short *)MDMA1_S0_PERIPHERAL_MAP
#define bfin_read_MDMA1_S0_PERIPHERAL_MAP()  bfin_read16(MDMA1_S0_PERIPHERAL_MAP)
#define bfin_write_MDMA1_S0_PERIPHERAL_MAP(val) bfin_write16(MDMA1_S0_PERIPHERAL_MAP,val)
#define pMDMA1_D1_CONFIG (volatile unsigned short *)MDMA1_D1_CONFIG
#define bfin_read_MDMA1_D1_CONFIG()          bfin_read16(MDMA1_D1_CONFIG)
#define bfin_write_MDMA1_D1_CONFIG(val)      bfin_write16(MDMA1_D1_CONFIG,val)
#define pMDMA1_D1_NEXT_DESC_PTR (volatile void **)MDMA1_D1_NEXT_DESC_PTR
#define bfin_read_MDMA1_D1_NEXT_DESC_PTR()   bfin_read32(MDMA1_D1_NEXT_DESC_PTR)
#define bfin_write_MDMA1_D1_NEXT_DESC_PTR(val) bfin_write32(MDMA1_D1_NEXT_DESC_PTR,val)
#define pMDMA1_D1_START_ADDR (volatile void **)MDMA1_D1_START_ADDR
#define bfin_read_MDMA1_D1_START_ADDR()      bfin_read32(MDMA1_D1_START_ADDR)
#define bfin_write_MDMA1_D1_START_ADDR(val)  bfin_write32(MDMA1_D1_START_ADDR,val)
#define pMDMA1_D1_X_COUNT (volatile unsigned short *)MDMA1_D1_X_COUNT
#define bfin_read_MDMA1_D1_X_COUNT()         bfin_read16(MDMA1_D1_X_COUNT)
#define bfin_write_MDMA1_D1_X_COUNT(val)     bfin_write16(MDMA1_D1_X_COUNT,val)
#define pMDMA1_D1_Y_COUNT (volatile unsigned short *)MDMA1_D1_Y_COUNT
#define bfin_read_MDMA1_D1_Y_COUNT()         bfin_read16(MDMA1_D1_Y_COUNT)
#define bfin_write_MDMA1_D1_Y_COUNT(val)     bfin_write16(MDMA1_D1_Y_COUNT,val)
#define pMDMA1_D1_X_MODIFY (volatile signed short *)MDMA1_D1_X_MODIFY
#define bfin_read_MDMA1_D1_X_MODIFY()        bfin_read16(MDMA1_D1_X_MODIFY)
#define bfin_write_MDMA1_D1_X_MODIFY(val)    bfin_write16(MDMA1_D1_X_MODIFY,val)
#define pMDMA1_D1_Y_MODIFY (volatile signed short *)MDMA1_D1_Y_MODIFY
#define bfin_read_MDMA1_D1_Y_MODIFY()        bfin_read16(MDMA1_D1_Y_MODIFY)
#define bfin_write_MDMA1_D1_Y_MODIFY(val)    bfin_write16(MDMA1_D1_Y_MODIFY,val)
#define pMDMA1_D1_CURR_DESC_PTR (volatile void **)MDMA1_D1_CURR_DESC_PTR
#define bfin_read_MDMA1_D1_CURR_DESC_PTR()   bfin_read32(MDMA1_D1_CURR_DESC_PTR)
#define bfin_write_MDMA1_D1_CURR_DESC_PTR(val) bfin_write32(MDMA1_D1_CURR_DESC_PTR,val)
#define pMDMA1_D1_CURR_ADDR (volatile void **)MDMA1_D1_CURR_ADDR
#define bfin_read_MDMA1_D1_CURR_ADDR()       bfin_read32(MDMA1_D1_CURR_ADDR)
#define bfin_write_MDMA1_D1_CURR_ADDR(val)   bfin_write32(MDMA1_D1_CURR_ADDR,val)
#define pMDMA1_D1_CURR_X_COUNT (volatile unsigned short *)MDMA1_D1_CURR_X_COUNT
#define bfin_read_MDMA1_D1_CURR_X_COUNT()    bfin_read16(MDMA1_D1_CURR_X_COUNT)
#define bfin_write_MDMA1_D1_CURR_X_COUNT(val) bfin_write16(MDMA1_D1_CURR_X_COUNT,val)
#define pMDMA1_D1_CURR_Y_COUNT (volatile unsigned short *)MDMA1_D1_CURR_Y_COUNT
#define bfin_read_MDMA1_D1_CURR_Y_COUNT()    bfin_read16(MDMA1_D1_CURR_Y_COUNT)
#define bfin_write_MDMA1_D1_CURR_Y_COUNT(val) bfin_write16(MDMA1_D1_CURR_Y_COUNT,val)
#define pMDMA1_D1_IRQ_STATUS (volatile unsigned short *)MDMA1_D1_IRQ_STATUS
#define bfin_read_MDMA1_D1_IRQ_STATUS()      bfin_read16(MDMA1_D1_IRQ_STATUS)
#define bfin_write_MDMA1_D1_IRQ_STATUS(val)  bfin_write16(MDMA1_D1_IRQ_STATUS,val)
#define pMDMA1_D1_PERIPHERAL_MAP (volatile unsigned short *)MDMA1_D1_PERIPHERAL_MAP
#define bfin_read_MDMA1_D1_PERIPHERAL_MAP()  bfin_read16(MDMA1_D1_PERIPHERAL_MAP)
#define bfin_write_MDMA1_D1_PERIPHERAL_MAP(val) bfin_write16(MDMA1_D1_PERIPHERAL_MAP,val)
#define pMDMA1_S1_CONFIG (volatile unsigned short *)MDMA1_S1_CONFIG
#define bfin_read_MDMA1_S1_CONFIG()          bfin_read16(MDMA1_S1_CONFIG)
#define bfin_write_MDMA1_S1_CONFIG(val)      bfin_write16(MDMA1_S1_CONFIG,val)
#define pMDMA1_S1_NEXT_DESC_PTR (volatile void **)MDMA1_S1_NEXT_DESC_PTR
#define bfin_read_MDMA1_S1_NEXT_DESC_PTR()   bfin_read32(MDMA1_S1_NEXT_DESC_PTR)
#define bfin_write_MDMA1_S1_NEXT_DESC_PTR(val) bfin_write32(MDMA1_S1_NEXT_DESC_PTR,val)
#define pMDMA1_S1_START_ADDR (volatile void **)MDMA1_S1_START_ADDR
#define bfin_read_MDMA1_S1_START_ADDR()      bfin_read32(MDMA1_S1_START_ADDR)
#define bfin_write_MDMA1_S1_START_ADDR(val)  bfin_write32(MDMA1_S1_START_ADDR,val)
#define pMDMA1_S1_X_COUNT (volatile unsigned short *)MDMA1_S1_X_COUNT
#define bfin_read_MDMA1_S1_X_COUNT()         bfin_read16(MDMA1_S1_X_COUNT)
#define bfin_write_MDMA1_S1_X_COUNT(val)     bfin_write16(MDMA1_S1_X_COUNT,val)
#define pMDMA1_S1_Y_COUNT (volatile unsigned short *)MDMA1_S1_Y_COUNT
#define bfin_read_MDMA1_S1_Y_COUNT()         bfin_read16(MDMA1_S1_Y_COUNT)
#define bfin_write_MDMA1_S1_Y_COUNT(val)     bfin_write16(MDMA1_S1_Y_COUNT,val)
#define pMDMA1_S1_X_MODIFY (volatile signed short *)MDMA1_S1_X_MODIFY
#define bfin_read_MDMA1_S1_X_MODIFY()        bfin_read16(MDMA1_S1_X_MODIFY)
#define bfin_write_MDMA1_S1_X_MODIFY(val)    bfin_write16(MDMA1_S1_X_MODIFY,val)
#define pMDMA1_S1_Y_MODIFY (volatile signed short *)MDMA1_S1_Y_MODIFY
#define bfin_read_MDMA1_S1_Y_MODIFY()        bfin_read16(MDMA1_S1_Y_MODIFY)
#define bfin_write_MDMA1_S1_Y_MODIFY(val)    bfin_write16(MDMA1_S1_Y_MODIFY,val)
#define pMDMA1_S1_CURR_DESC_PTR (volatile void **)MDMA1_S1_CURR_DESC_PTR
#define bfin_read_MDMA1_S1_CURR_DESC_PTR()   bfin_read32(MDMA1_S1_CURR_DESC_PTR)
#define bfin_write_MDMA1_S1_CURR_DESC_PTR(val) bfin_write32(MDMA1_S1_CURR_DESC_PTR,val)
#define pMDMA1_S1_CURR_ADDR (volatile void **)MDMA1_S1_CURR_ADDR
#define bfin_read_MDMA1_S1_CURR_ADDR()       bfin_read32(MDMA1_S1_CURR_ADDR)
#define bfin_write_MDMA1_S1_CURR_ADDR(val)   bfin_write32(MDMA1_S1_CURR_ADDR,val)
#define pMDMA1_S1_CURR_X_COUNT (volatile unsigned short *)MDMA1_S1_CURR_X_COUNT
#define bfin_read_MDMA1_S1_CURR_X_COUNT()    bfin_read16(MDMA1_S1_CURR_X_COUNT)
#define bfin_write_MDMA1_S1_CURR_X_COUNT(val) bfin_write16(MDMA1_S1_CURR_X_COUNT,val)
#define pMDMA1_S1_CURR_Y_COUNT (volatile unsigned short *)MDMA1_S1_CURR_Y_COUNT
#define bfin_read_MDMA1_S1_CURR_Y_COUNT()    bfin_read16(MDMA1_S1_CURR_Y_COUNT)
#define bfin_write_MDMA1_S1_CURR_Y_COUNT(val) bfin_write16(MDMA1_S1_CURR_Y_COUNT,val)
#define pMDMA1_S1_IRQ_STATUS (volatile unsigned short *)MDMA1_S1_IRQ_STATUS
#define bfin_read_MDMA1_S1_IRQ_STATUS()      bfin_read16(MDMA1_S1_IRQ_STATUS)
#define bfin_write_MDMA1_S1_IRQ_STATUS(val)  bfin_write16(MDMA1_S1_IRQ_STATUS,val)
#define pMDMA1_S1_PERIPHERAL_MAP (volatile unsigned short *)MDMA1_S1_PERIPHERAL_MAP
#define bfin_read_MDMA1_S1_PERIPHERAL_MAP()  bfin_read16(MDMA1_S1_PERIPHERAL_MAP)
#define bfin_write_MDMA1_S1_PERIPHERAL_MAP(val) bfin_write16(MDMA1_S1_PERIPHERAL_MAP,val)
/* DMA2 Controller registers (0xFFC0 0C00-0xFFC0 0DFF) */
#define pDMA2_0_CONFIG (volatile unsigned short *)DMA2_0_CONFIG
#define bfin_read_DMA2_0_CONFIG()            bfin_read16(DMA2_0_CONFIG)
#define bfin_write_DMA2_0_CONFIG(val)        bfin_write16(DMA2_0_CONFIG,val)
#define pDMA2_0_NEXT_DESC_PTR (volatile void **)DMA2_0_NEXT_DESC_PTR
#define bfin_read_DMA2_0_NEXT_DESC_PTR()     bfin_read32(DMA2_0_NEXT_DESC_PTR)
#define bfin_write_DMA2_0_NEXT_DESC_PTR(val) bfin_write32(DMA2_0_NEXT_DESC_PTR,val)
#define pDMA2_0_START_ADDR (volatile void **)DMA2_0_START_ADDR
#define bfin_read_DMA2_0_START_ADDR()        bfin_read32(DMA2_0_START_ADDR)
#define bfin_write_DMA2_0_START_ADDR(val)    bfin_write32(DMA2_0_START_ADDR,val)
#define pDMA2_0_X_COUNT (volatile unsigned short *)DMA2_0_X_COUNT
#define bfin_read_DMA2_0_X_COUNT()           bfin_read16(DMA2_0_X_COUNT)
#define bfin_write_DMA2_0_X_COUNT(val)       bfin_write16(DMA2_0_X_COUNT,val)
#define pDMA2_0_Y_COUNT (volatile unsigned short *)DMA2_0_Y_COUNT
#define bfin_read_DMA2_0_Y_COUNT()           bfin_read16(DMA2_0_Y_COUNT)
#define bfin_write_DMA2_0_Y_COUNT(val)       bfin_write16(DMA2_0_Y_COUNT,val)
#define pDMA2_0_X_MODIFY (volatile signed short *)DMA2_0_X_MODIFY
#define bfin_read_DMA2_0_X_MODIFY()          bfin_read16(DMA2_0_X_MODIFY)
#define bfin_write_DMA2_0_X_MODIFY(val)      bfin_write16(DMA2_0_X_MODIFY,val)
#define pDMA2_0_Y_MODIFY (volatile signed short *)DMA2_0_Y_MODIFY
#define bfin_read_DMA2_0_Y_MODIFY()          bfin_read16(DMA2_0_Y_MODIFY)
#define bfin_write_DMA2_0_Y_MODIFY(val)      bfin_write16(DMA2_0_Y_MODIFY,val)
#define pDMA2_0_CURR_DESC_PTR (volatile void **)DMA2_0_CURR_DESC_PTR
#define bfin_read_DMA2_0_CURR_DESC_PTR()     bfin_read32(DMA2_0_CURR_DESC_PTR)
#define bfin_write_DMA2_0_CURR_DESC_PTR(val) bfin_write32(DMA2_0_CURR_DESC_PTR,val)
#define pDMA2_0_CURR_ADDR (volatile void **)DMA2_0_CURR_ADDR
#define bfin_read_DMA2_0_CURR_ADDR()         bfin_read32(DMA2_0_CURR_ADDR)
#define bfin_write_DMA2_0_CURR_ADDR(val)     bfin_write32(DMA2_0_CURR_ADDR,val)
#define pDMA2_0_CURR_X_COUNT (volatile unsigned short *)DMA2_0_CURR_X_COUNT
#define bfin_read_DMA2_0_CURR_X_COUNT()      bfin_read16(DMA2_0_CURR_X_COUNT)
#define bfin_write_DMA2_0_CURR_X_COUNT(val)  bfin_write16(DMA2_0_CURR_X_COUNT,val)
#define pDMA2_0_CURR_Y_COUNT (volatile unsigned short *)DMA2_0_CURR_Y_COUNT
#define bfin_read_DMA2_0_CURR_Y_COUNT()      bfin_read16(DMA2_0_CURR_Y_COUNT)
#define bfin_write_DMA2_0_CURR_Y_COUNT(val)  bfin_write16(DMA2_0_CURR_Y_COUNT,val)
#define pDMA2_0_IRQ_STATUS (volatile unsigned short *)DMA2_0_IRQ_STATUS
#define bfin_read_DMA2_0_IRQ_STATUS()        bfin_read16(DMA2_0_IRQ_STATUS)
#define bfin_write_DMA2_0_IRQ_STATUS(val)    bfin_write16(DMA2_0_IRQ_STATUS,val)
#define pDMA2_0_PERIPHERAL_MAP (volatile unsigned short *)DMA2_0_PERIPHERAL_MAP
#define bfin_read_DMA2_0_PERIPHERAL_MAP()    bfin_read16(DMA2_0_PERIPHERAL_MAP)
#define bfin_write_DMA2_0_PERIPHERAL_MAP(val) bfin_write16(DMA2_0_PERIPHERAL_MAP,val)
#define pDMA2_1_CONFIG (volatile unsigned short *)DMA2_1_CONFIG
#define bfin_read_DMA2_1_CONFIG()            bfin_read16(DMA2_1_CONFIG)
#define bfin_write_DMA2_1_CONFIG(val)        bfin_write16(DMA2_1_CONFIG,val)
#define pDMA2_1_NEXT_DESC_PTR (volatile void **)DMA2_1_NEXT_DESC_PTR
#define bfin_read_DMA2_1_NEXT_DESC_PTR()     bfin_read32(DMA2_1_NEXT_DESC_PTR)
#define bfin_write_DMA2_1_NEXT_DESC_PTR(val) bfin_write32(DMA2_1_NEXT_DESC_PTR,val)
#define pDMA2_1_START_ADDR (volatile void **)DMA2_1_START_ADDR
#define bfin_read_DMA2_1_START_ADDR()        bfin_read32(DMA2_1_START_ADDR)
#define bfin_write_DMA2_1_START_ADDR(val)    bfin_write32(DMA2_1_START_ADDR,val)
#define pDMA2_1_X_COUNT (volatile unsigned short *)DMA2_1_X_COUNT
#define bfin_read_DMA2_1_X_COUNT()           bfin_read16(DMA2_1_X_COUNT)
#define bfin_write_DMA2_1_X_COUNT(val)       bfin_write16(DMA2_1_X_COUNT,val)
#define pDMA2_1_Y_COUNT (volatile unsigned short *)DMA2_1_Y_COUNT
#define bfin_read_DMA2_1_Y_COUNT()           bfin_read16(DMA2_1_Y_COUNT)
#define bfin_write_DMA2_1_Y_COUNT(val)       bfin_write16(DMA2_1_Y_COUNT,val)
#define pDMA2_1_X_MODIFY (volatile signed short *)DMA2_1_X_MODIFY
#define bfin_read_DMA2_1_X_MODIFY()          bfin_read16(DMA2_1_X_MODIFY)
#define bfin_write_DMA2_1_X_MODIFY(val)      bfin_write16(DMA2_1_X_MODIFY,val)
#define pDMA2_1_Y_MODIFY (volatile signed short *)DMA2_1_Y_MODIFY
#define bfin_read_DMA2_1_Y_MODIFY()          bfin_read16(DMA2_1_Y_MODIFY)
#define bfin_write_DMA2_1_Y_MODIFY(val)      bfin_write16(DMA2_1_Y_MODIFY,val)
#define pDMA2_1_CURR_DESC_PTR (volatile void **)DMA2_1_CURR_DESC_PTR
#define bfin_read_DMA2_1_CURR_DESC_PTR()     bfin_read32(DMA2_1_CURR_DESC_PTR)
#define bfin_write_DMA2_1_CURR_DESC_PTR(val) bfin_write32(DMA2_1_CURR_DESC_PTR,val)
#define pDMA2_1_CURR_ADDR (volatile void **)DMA2_1_CURR_ADDR
#define bfin_read_DMA2_1_CURR_ADDR()         bfin_read32(DMA2_1_CURR_ADDR)
#define bfin_write_DMA2_1_CURR_ADDR(val)     bfin_write32(DMA2_1_CURR_ADDR,val)
#define pDMA2_1_CURR_X_COUNT (volatile unsigned short *)DMA2_1_CURR_X_COUNT
#define bfin_read_DMA2_1_CURR_X_COUNT()      bfin_read16(DMA2_1_CURR_X_COUNT)
#define bfin_write_DMA2_1_CURR_X_COUNT(val)  bfin_write16(DMA2_1_CURR_X_COUNT,val)
#define pDMA2_1_CURR_Y_COUNT (volatile unsigned short *)DMA2_1_CURR_Y_COUNT
#define bfin_read_DMA2_1_CURR_Y_COUNT()      bfin_read16(DMA2_1_CURR_Y_COUNT)
#define bfin_write_DMA2_1_CURR_Y_COUNT(val)  bfin_write16(DMA2_1_CURR_Y_COUNT,val)
#define pDMA2_1_IRQ_STATUS (volatile unsigned short *)DMA2_1_IRQ_STATUS
#define bfin_read_DMA2_1_IRQ_STATUS()        bfin_read16(DMA2_1_IRQ_STATUS)
#define bfin_write_DMA2_1_IRQ_STATUS(val)    bfin_write16(DMA2_1_IRQ_STATUS,val)
#define pDMA2_1_PERIPHERAL_MAP (volatile unsigned short *)DMA2_1_PERIPHERAL_MAP
#define bfin_read_DMA2_1_PERIPHERAL_MAP()    bfin_read16(DMA2_1_PERIPHERAL_MAP)
#define bfin_write_DMA2_1_PERIPHERAL_MAP(val) bfin_write16(DMA2_1_PERIPHERAL_MAP,val)
#define pDMA2_2_CONFIG (volatile unsigned short *)DMA2_2_CONFIG
#define bfin_read_DMA2_2_CONFIG()            bfin_read16(DMA2_2_CONFIG)
#define bfin_write_DMA2_2_CONFIG(val)        bfin_write16(DMA2_2_CONFIG,val)
#define pDMA2_2_NEXT_DESC_PTR (volatile void **)DMA2_2_NEXT_DESC_PTR
#define bfin_read_DMA2_2_NEXT_DESC_PTR()     bfin_read32(DMA2_2_NEXT_DESC_PTR)
#define bfin_write_DMA2_2_NEXT_DESC_PTR(val) bfin_write32(DMA2_2_NEXT_DESC_PTR,val)
#define pDMA2_2_START_ADDR (volatile void **)DMA2_2_START_ADDR
#define bfin_read_DMA2_2_START_ADDR()        bfin_read32(DMA2_2_START_ADDR)
#define bfin_write_DMA2_2_START_ADDR(val)    bfin_write32(DMA2_2_START_ADDR,val)
#define pDMA2_2_X_COUNT (volatile unsigned short *)DMA2_2_X_COUNT
#define bfin_read_DMA2_2_X_COUNT()           bfin_read16(DMA2_2_X_COUNT)
#define bfin_write_DMA2_2_X_COUNT(val)       bfin_write16(DMA2_2_X_COUNT,val)
#define pDMA2_2_Y_COUNT (volatile unsigned short *)DMA2_2_Y_COUNT
#define bfin_read_DMA2_2_Y_COUNT()           bfin_read16(DMA2_2_Y_COUNT)
#define bfin_write_DMA2_2_Y_COUNT(val)       bfin_write16(DMA2_2_Y_COUNT,val)
#define pDMA2_2_X_MODIFY (volatile signed short *)DMA2_2_X_MODIFY
#define bfin_read_DMA2_2_X_MODIFY()          bfin_read16(DMA2_2_X_MODIFY)
#define bfin_write_DMA2_2_X_MODIFY(val)      bfin_write16(DMA2_2_X_MODIFY,val)
#define pDMA2_2_Y_MODIFY (volatile signed short *)DMA2_2_Y_MODIFY
#define bfin_read_DMA2_2_Y_MODIFY()          bfin_read16(DMA2_2_Y_MODIFY)
#define bfin_write_DMA2_2_Y_MODIFY(val)      bfin_write16(DMA2_2_Y_MODIFY,val)
#define pDMA2_2_CURR_DESC_PTR (volatile void **)DMA2_2_CURR_DESC_PTR
#define bfin_read_DMA2_2_CURR_DESC_PTR()     bfin_read32(DMA2_2_CURR_DESC_PTR)
#define bfin_write_DMA2_2_CURR_DESC_PTR(val) bfin_write32(DMA2_2_CURR_DESC_PTR,val)
#define pDMA2_2_CURR_ADDR (volatile void **)DMA2_2_CURR_ADDR
#define bfin_read_DMA2_2_CURR_ADDR()         bfin_read32(DMA2_2_CURR_ADDR)
#define bfin_write_DMA2_2_CURR_ADDR(val)     bfin_write32(DMA2_2_CURR_ADDR,val)
#define pDMA2_2_CURR_X_COUNT (volatile unsigned short *)DMA2_2_CURR_X_COUNT
#define bfin_read_DMA2_2_CURR_X_COUNT()      bfin_read16(DMA2_2_CURR_X_COUNT)
#define bfin_write_DMA2_2_CURR_X_COUNT(val)  bfin_write16(DMA2_2_CURR_X_COUNT,val)
#define pDMA2_2_CURR_Y_COUNT (volatile unsigned short *)DMA2_2_CURR_Y_COUNT
#define bfin_read_DMA2_2_CURR_Y_COUNT()      bfin_read16(DMA2_2_CURR_Y_COUNT)
#define bfin_write_DMA2_2_CURR_Y_COUNT(val)  bfin_write16(DMA2_2_CURR_Y_COUNT,val)
#define pDMA2_2_IRQ_STATUS (volatile unsigned short *)DMA2_2_IRQ_STATUS
#define bfin_read_DMA2_2_IRQ_STATUS()        bfin_read16(DMA2_2_IRQ_STATUS)
#define bfin_write_DMA2_2_IRQ_STATUS(val)    bfin_write16(DMA2_2_IRQ_STATUS,val)
#define pDMA2_2_PERIPHERAL_MAP (volatile unsigned short *)DMA2_2_PERIPHERAL_MAP
#define bfin_read_DMA2_2_PERIPHERAL_MAP()    bfin_read16(DMA2_2_PERIPHERAL_MAP)
#define bfin_write_DMA2_2_PERIPHERAL_MAP(val) bfin_write16(DMA2_2_PERIPHERAL_MAP,val)
#define pDMA2_3_CONFIG (volatile unsigned short *)DMA2_3_CONFIG
#define bfin_read_DMA2_3_CONFIG()            bfin_read16(DMA2_3_CONFIG)
#define bfin_write_DMA2_3_CONFIG(val)        bfin_write16(DMA2_3_CONFIG,val)
#define pDMA2_3_NEXT_DESC_PTR (volatile void **)DMA2_3_NEXT_DESC_PTR
#define bfin_read_DMA2_3_NEXT_DESC_PTR()     bfin_read32(DMA2_3_NEXT_DESC_PTR)
#define bfin_write_DMA2_3_NEXT_DESC_PTR(val) bfin_write32(DMA2_3_NEXT_DESC_PTR,val)
#define pDMA2_3_START_ADDR (volatile void **)DMA2_3_START_ADDR
#define bfin_read_DMA2_3_START_ADDR()        bfin_read32(DMA2_3_START_ADDR)
#define bfin_write_DMA2_3_START_ADDR(val)    bfin_write32(DMA2_3_START_ADDR,val)
#define pDMA2_3_X_COUNT (volatile unsigned short *)DMA2_3_X_COUNT
#define bfin_read_DMA2_3_X_COUNT()           bfin_read16(DMA2_3_X_COUNT)
#define bfin_write_DMA2_3_X_COUNT(val)       bfin_write16(DMA2_3_X_COUNT,val)
#define pDMA2_3_Y_COUNT (volatile unsigned short *)DMA2_3_Y_COUNT
#define bfin_read_DMA2_3_Y_COUNT()           bfin_read16(DMA2_3_Y_COUNT)
#define bfin_write_DMA2_3_Y_COUNT(val)       bfin_write16(DMA2_3_Y_COUNT,val)
#define pDMA2_3_X_MODIFY (volatile signed short *)DMA2_3_X_MODIFY
#define bfin_read_DMA2_3_X_MODIFY()          bfin_read16(DMA2_3_X_MODIFY)
#define bfin_write_DMA2_3_X_MODIFY(val)      bfin_write16(DMA2_3_X_MODIFY,val)
#define pDMA2_3_Y_MODIFY (volatile signed short *)DMA2_3_Y_MODIFY
#define bfin_read_DMA2_3_Y_MODIFY()          bfin_read16(DMA2_3_Y_MODIFY)
#define bfin_write_DMA2_3_Y_MODIFY(val)      bfin_write16(DMA2_3_Y_MODIFY,val)
#define pDMA2_3_CURR_DESC_PTR (volatile void **)DMA2_3_CURR_DESC_PTR
#define bfin_read_DMA2_3_CURR_DESC_PTR()     bfin_read32(DMA2_3_CURR_DESC_PTR)
#define bfin_write_DMA2_3_CURR_DESC_PTR(val) bfin_write32(DMA2_3_CURR_DESC_PTR,val)
#define pDMA2_3_CURR_ADDR (volatile void **)DMA2_3_CURR_ADDR
#define bfin_read_DMA2_3_CURR_ADDR()         bfin_read32(DMA2_3_CURR_ADDR)
#define bfin_write_DMA2_3_CURR_ADDR(val)     bfin_write32(DMA2_3_CURR_ADDR,val)
#define pDMA2_3_CURR_X_COUNT (volatile unsigned short *)DMA2_3_CURR_X_COUNT
#define bfin_read_DMA2_3_CURR_X_COUNT()      bfin_read16(DMA2_3_CURR_X_COUNT)
#define bfin_write_DMA2_3_CURR_X_COUNT(val)  bfin_write16(DMA2_3_CURR_X_COUNT,val)
#define pDMA2_3_CURR_Y_COUNT (volatile unsigned short *)DMA2_3_CURR_Y_COUNT
#define bfin_read_DMA2_3_CURR_Y_COUNT()      bfin_read16(DMA2_3_CURR_Y_COUNT)
#define bfin_write_DMA2_3_CURR_Y_COUNT(val)  bfin_write16(DMA2_3_CURR_Y_COUNT,val)
#define pDMA2_3_IRQ_STATUS (volatile unsigned short *)DMA2_3_IRQ_STATUS
#define bfin_read_DMA2_3_IRQ_STATUS()        bfin_read16(DMA2_3_IRQ_STATUS)
#define bfin_write_DMA2_3_IRQ_STATUS(val)    bfin_write16(DMA2_3_IRQ_STATUS,val)
#define pDMA2_3_PERIPHERAL_MAP (volatile unsigned short *)DMA2_3_PERIPHERAL_MAP
#define bfin_read_DMA2_3_PERIPHERAL_MAP()    bfin_read16(DMA2_3_PERIPHERAL_MAP)
#define bfin_write_DMA2_3_PERIPHERAL_MAP(val) bfin_write16(DMA2_3_PERIPHERAL_MAP,val)
#define pDMA2_4_CONFIG (volatile unsigned short *)DMA2_4_CONFIG
#define bfin_read_DMA2_4_CONFIG()            bfin_read16(DMA2_4_CONFIG)
#define bfin_write_DMA2_4_CONFIG(val)        bfin_write16(DMA2_4_CONFIG,val)
#define pDMA2_4_NEXT_DESC_PTR (volatile void **)DMA2_4_NEXT_DESC_PTR
#define bfin_read_DMA2_4_NEXT_DESC_PTR()     bfin_read32(DMA2_4_NEXT_DESC_PTR)
#define bfin_write_DMA2_4_NEXT_DESC_PTR(val) bfin_write32(DMA2_4_NEXT_DESC_PTR,val)
#define pDMA2_4_START_ADDR (volatile void **)DMA2_4_START_ADDR
#define bfin_read_DMA2_4_START_ADDR()        bfin_read32(DMA2_4_START_ADDR)
#define bfin_write_DMA2_4_START_ADDR(val)    bfin_write32(DMA2_4_START_ADDR,val)
#define pDMA2_4_X_COUNT (volatile unsigned short *)DMA2_4_X_COUNT
#define bfin_read_DMA2_4_X_COUNT()           bfin_read16(DMA2_4_X_COUNT)
#define bfin_write_DMA2_4_X_COUNT(val)       bfin_write16(DMA2_4_X_COUNT,val)
#define pDMA2_4_Y_COUNT (volatile unsigned short *)DMA2_4_Y_COUNT
#define bfin_read_DMA2_4_Y_COUNT()           bfin_read16(DMA2_4_Y_COUNT)
#define bfin_write_DMA2_4_Y_COUNT(val)       bfin_write16(DMA2_4_Y_COUNT,val)
#define pDMA2_4_X_MODIFY (volatile signed short *)DMA2_4_X_MODIFY
#define bfin_read_DMA2_4_X_MODIFY()          bfin_read16(DMA2_4_X_MODIFY)
#define bfin_write_DMA2_4_X_MODIFY(val)      bfin_write16(DMA2_4_X_MODIFY,val)
#define pDMA2_4_Y_MODIFY (volatile signed short *)DMA2_4_Y_MODIFY
#define bfin_read_DMA2_4_Y_MODIFY()          bfin_read16(DMA2_4_Y_MODIFY)
#define bfin_write_DMA2_4_Y_MODIFY(val)      bfin_write16(DMA2_4_Y_MODIFY,val)
#define pDMA2_4_CURR_DESC_PTR (volatile void **)DMA2_4_CURR_DESC_PTR
#define bfin_read_DMA2_4_CURR_DESC_PTR()     bfin_read32(DMA2_4_CURR_DESC_PTR)
#define bfin_write_DMA2_4_CURR_DESC_PTR(val) bfin_write32(DMA2_4_CURR_DESC_PTR,val)
#define pDMA2_4_CURR_ADDR (volatile void **)DMA2_4_CURR_ADDR
#define bfin_read_DMA2_4_CURR_ADDR()         bfin_read32(DMA2_4_CURR_ADDR)
#define bfin_write_DMA2_4_CURR_ADDR(val)     bfin_write32(DMA2_4_CURR_ADDR,val)
#define pDMA2_4_CURR_X_COUNT (volatile unsigned short *)DMA2_4_CURR_X_COUNT
#define bfin_read_DMA2_4_CURR_X_COUNT()      bfin_read16(DMA2_4_CURR_X_COUNT)
#define bfin_write_DMA2_4_CURR_X_COUNT(val)  bfin_write16(DMA2_4_CURR_X_COUNT,val)
#define pDMA2_4_CURR_Y_COUNT (volatile unsigned short *)DMA2_4_CURR_Y_COUNT
#define bfin_read_DMA2_4_CURR_Y_COUNT()      bfin_read16(DMA2_4_CURR_Y_COUNT)
#define bfin_write_DMA2_4_CURR_Y_COUNT(val)  bfin_write16(DMA2_4_CURR_Y_COUNT,val)
#define pDMA2_4_IRQ_STATUS (volatile unsigned short *)DMA2_4_IRQ_STATUS
#define bfin_read_DMA2_4_IRQ_STATUS()        bfin_read16(DMA2_4_IRQ_STATUS)
#define bfin_write_DMA2_4_IRQ_STATUS(val)    bfin_write16(DMA2_4_IRQ_STATUS,val)
#define pDMA2_4_PERIPHERAL_MAP (volatile unsigned short *)DMA2_4_PERIPHERAL_MAP
#define bfin_read_DMA2_4_PERIPHERAL_MAP()    bfin_read16(DMA2_4_PERIPHERAL_MAP)
#define bfin_write_DMA2_4_PERIPHERAL_MAP(val) bfin_write16(DMA2_4_PERIPHERAL_MAP,val)
#define pDMA2_5_CONFIG (volatile unsigned short *)DMA2_5_CONFIG
#define bfin_read_DMA2_5_CONFIG()            bfin_read16(DMA2_5_CONFIG)
#define bfin_write_DMA2_5_CONFIG(val)        bfin_write16(DMA2_5_CONFIG,val)
#define pDMA2_5_NEXT_DESC_PTR (volatile void **)DMA2_5_NEXT_DESC_PTR
#define bfin_read_DMA2_5_NEXT_DESC_PTR()     bfin_read32(DMA2_5_NEXT_DESC_PTR)
#define bfin_write_DMA2_5_NEXT_DESC_PTR(val) bfin_write32(DMA2_5_NEXT_DESC_PTR,val)
#define pDMA2_5_START_ADDR (volatile void **)DMA2_5_START_ADDR
#define bfin_read_DMA2_5_START_ADDR()        bfin_read32(DMA2_5_START_ADDR)
#define bfin_write_DMA2_5_START_ADDR(val)    bfin_write32(DMA2_5_START_ADDR,val)
#define pDMA2_5_X_COUNT (volatile unsigned short *)DMA2_5_X_COUNT
#define bfin_read_DMA2_5_X_COUNT()           bfin_read16(DMA2_5_X_COUNT)
#define bfin_write_DMA2_5_X_COUNT(val)       bfin_write16(DMA2_5_X_COUNT,val)
#define pDMA2_5_Y_COUNT (volatile unsigned short *)DMA2_5_Y_COUNT
#define bfin_read_DMA2_5_Y_COUNT()           bfin_read16(DMA2_5_Y_COUNT)
#define bfin_write_DMA2_5_Y_COUNT(val)       bfin_write16(DMA2_5_Y_COUNT,val)
#define pDMA2_5_X_MODIFY (volatile signed short *)DMA2_5_X_MODIFY
#define bfin_read_DMA2_5_X_MODIFY()          bfin_read16(DMA2_5_X_MODIFY)
#define bfin_write_DMA2_5_X_MODIFY(val)      bfin_write16(DMA2_5_X_MODIFY,val)
#define pDMA2_5_Y_MODIFY (volatile signed short *)DMA2_5_Y_MODIFY
#define bfin_read_DMA2_5_Y_MODIFY()          bfin_read16(DMA2_5_Y_MODIFY)
#define bfin_write_DMA2_5_Y_MODIFY(val)      bfin_write16(DMA2_5_Y_MODIFY,val)
#define pDMA2_5_CURR_DESC_PTR (volatile void **)DMA2_5_CURR_DESC_PTR
#define bfin_read_DMA2_5_CURR_DESC_PTR()     bfin_read32(DMA2_5_CURR_DESC_PTR)
#define bfin_write_DMA2_5_CURR_DESC_PTR(val) bfin_write32(DMA2_5_CURR_DESC_PTR,val)
#define pDMA2_5_CURR_ADDR (volatile void **)DMA2_5_CURR_ADDR
#define bfin_read_DMA2_5_CURR_ADDR()         bfin_read32(DMA2_5_CURR_ADDR)
#define bfin_write_DMA2_5_CURR_ADDR(val)     bfin_write32(DMA2_5_CURR_ADDR,val)
#define pDMA2_5_CURR_X_COUNT (volatile unsigned short *)DMA2_5_CURR_X_COUNT
#define bfin_read_DMA2_5_CURR_X_COUNT()      bfin_read16(DMA2_5_CURR_X_COUNT)
#define bfin_write_DMA2_5_CURR_X_COUNT(val)  bfin_write16(DMA2_5_CURR_X_COUNT,val)
#define pDMA2_5_CURR_Y_COUNT (volatile unsigned short *)DMA2_5_CURR_Y_COUNT
#define bfin_read_DMA2_5_CURR_Y_COUNT()      bfin_read16(DMA2_5_CURR_Y_COUNT)
#define bfin_write_DMA2_5_CURR_Y_COUNT(val)  bfin_write16(DMA2_5_CURR_Y_COUNT,val)
#define pDMA2_5_IRQ_STATUS (volatile unsigned short *)DMA2_5_IRQ_STATUS
#define bfin_read_DMA2_5_IRQ_STATUS()        bfin_read16(DMA2_5_IRQ_STATUS)
#define bfin_write_DMA2_5_IRQ_STATUS(val)    bfin_write16(DMA2_5_IRQ_STATUS,val)
#define pDMA2_5_PERIPHERAL_MAP (volatile unsigned short *)DMA2_5_PERIPHERAL_MAP
#define bfin_read_DMA2_5_PERIPHERAL_MAP()    bfin_read16(DMA2_5_PERIPHERAL_MAP)
#define bfin_write_DMA2_5_PERIPHERAL_MAP(val) bfin_write16(DMA2_5_PERIPHERAL_MAP,val)
#define pDMA2_6_CONFIG (volatile unsigned short *)DMA2_6_CONFIG
#define bfin_read_DMA2_6_CONFIG()            bfin_read16(DMA2_6_CONFIG)
#define bfin_write_DMA2_6_CONFIG(val)        bfin_write16(DMA2_6_CONFIG,val)
#define pDMA2_6_NEXT_DESC_PTR (volatile void **)DMA2_6_NEXT_DESC_PTR
#define bfin_read_DMA2_6_NEXT_DESC_PTR()     bfin_read32(DMA2_6_NEXT_DESC_PTR)
#define bfin_write_DMA2_6_NEXT_DESC_PTR(val) bfin_write32(DMA2_6_NEXT_DESC_PTR,val)
#define pDMA2_6_START_ADDR (volatile void **)DMA2_6_START_ADDR
#define bfin_read_DMA2_6_START_ADDR()        bfin_read32(DMA2_6_START_ADDR)
#define bfin_write_DMA2_6_START_ADDR(val)    bfin_write32(DMA2_6_START_ADDR,val)
#define pDMA2_6_X_COUNT (volatile unsigned short *)DMA2_6_X_COUNT
#define bfin_read_DMA2_6_X_COUNT()           bfin_read16(DMA2_6_X_COUNT)
#define bfin_write_DMA2_6_X_COUNT(val)       bfin_write16(DMA2_6_X_COUNT,val)
#define pDMA2_6_Y_COUNT (volatile unsigned short *)DMA2_6_Y_COUNT
#define bfin_read_DMA2_6_Y_COUNT()           bfin_read16(DMA2_6_Y_COUNT)
#define bfin_write_DMA2_6_Y_COUNT(val)       bfin_write16(DMA2_6_Y_COUNT,val)
#define pDMA2_6_X_MODIFY (volatile signed short *)DMA2_6_X_MODIFY
#define bfin_read_DMA2_6_X_MODIFY()          bfin_read16(DMA2_6_X_MODIFY)
#define bfin_write_DMA2_6_X_MODIFY(val)      bfin_write16(DMA2_6_X_MODIFY,val)
#define pDMA2_6_Y_MODIFY (volatile signed short *)DMA2_6_Y_MODIFY
#define bfin_read_DMA2_6_Y_MODIFY()          bfin_read16(DMA2_6_Y_MODIFY)
#define bfin_write_DMA2_6_Y_MODIFY(val)      bfin_write16(DMA2_6_Y_MODIFY,val)
#define pDMA2_6_CURR_DESC_PTR (volatile void **)DMA2_6_CURR_DESC_PTR
#define bfin_read_DMA2_6_CURR_DESC_PTR()     bfin_read32(DMA2_6_CURR_DESC_PTR)
#define bfin_write_DMA2_6_CURR_DESC_PTR(val) bfin_write32(DMA2_6_CURR_DESC_PTR,val)
#define pDMA2_6_CURR_ADDR (volatile void **)DMA2_6_CURR_ADDR
#define bfin_read_DMA2_6_CURR_ADDR()         bfin_read32(DMA2_6_CURR_ADDR)
#define bfin_write_DMA2_6_CURR_ADDR(val)     bfin_write32(DMA2_6_CURR_ADDR,val)
#define pDMA2_6_CURR_X_COUNT (volatile unsigned short *)DMA2_6_CURR_X_COUNT
#define bfin_read_DMA2_6_CURR_X_COUNT()      bfin_read16(DMA2_6_CURR_X_COUNT)
#define bfin_write_DMA2_6_CURR_X_COUNT(val)  bfin_write16(DMA2_6_CURR_X_COUNT,val)
#define pDMA2_6_CURR_Y_COUNT (volatile unsigned short *)DMA2_6_CURR_Y_COUNT
#define bfin_read_DMA2_6_CURR_Y_COUNT()      bfin_read16(DMA2_6_CURR_Y_COUNT)
#define bfin_write_DMA2_6_CURR_Y_COUNT(val)  bfin_write16(DMA2_6_CURR_Y_COUNT,val)
#define pDMA2_6_IRQ_STATUS (volatile unsigned short *)DMA2_6_IRQ_STATUS
#define bfin_read_DMA2_6_IRQ_STATUS()        bfin_read16(DMA2_6_IRQ_STATUS)
#define bfin_write_DMA2_6_IRQ_STATUS(val)    bfin_write16(DMA2_6_IRQ_STATUS,val)
#define pDMA2_6_PERIPHERAL_MAP (volatile unsigned short *)DMA2_6_PERIPHERAL_MAP
#define bfin_read_DMA2_6_PERIPHERAL_MAP()    bfin_read16(DMA2_6_PERIPHERAL_MAP)
#define bfin_write_DMA2_6_PERIPHERAL_MAP(val) bfin_write16(DMA2_6_PERIPHERAL_MAP,val)
#define pDMA2_7_CONFIG (volatile unsigned short *)DMA2_7_CONFIG
#define bfin_read_DMA2_7_CONFIG()            bfin_read16(DMA2_7_CONFIG)
#define bfin_write_DMA2_7_CONFIG(val)        bfin_write16(DMA2_7_CONFIG,val)
#define pDMA2_7_NEXT_DESC_PTR (volatile void **)DMA2_7_NEXT_DESC_PTR
#define bfin_read_DMA2_7_NEXT_DESC_PTR()     bfin_read32(DMA2_7_NEXT_DESC_PTR)
#define bfin_write_DMA2_7_NEXT_DESC_PTR(val) bfin_write32(DMA2_7_NEXT_DESC_PTR,val)
#define pDMA2_7_START_ADDR (volatile void **)DMA2_7_START_ADDR
#define bfin_read_DMA2_7_START_ADDR()        bfin_read32(DMA2_7_START_ADDR)
#define bfin_write_DMA2_7_START_ADDR(val)    bfin_write32(DMA2_7_START_ADDR,val)
#define pDMA2_7_X_COUNT (volatile unsigned short *)DMA2_7_X_COUNT
#define bfin_read_DMA2_7_X_COUNT()           bfin_read16(DMA2_7_X_COUNT)
#define bfin_write_DMA2_7_X_COUNT(val)       bfin_write16(DMA2_7_X_COUNT,val)
#define pDMA2_7_Y_COUNT (volatile unsigned short *)DMA2_7_Y_COUNT
#define bfin_read_DMA2_7_Y_COUNT()           bfin_read16(DMA2_7_Y_COUNT)
#define bfin_write_DMA2_7_Y_COUNT(val)       bfin_write16(DMA2_7_Y_COUNT,val)
#define pDMA2_7_X_MODIFY (volatile signed short *)DMA2_7_X_MODIFY
#define bfin_read_DMA2_7_X_MODIFY()          bfin_read16(DMA2_7_X_MODIFY)
#define bfin_write_DMA2_7_X_MODIFY(val)      bfin_write16(DMA2_7_X_MODIFY,val)
#define pDMA2_7_Y_MODIFY (volatile signed short *)DMA2_7_Y_MODIFY
#define bfin_read_DMA2_7_Y_MODIFY()          bfin_read16(DMA2_7_Y_MODIFY)
#define bfin_write_DMA2_7_Y_MODIFY(val)      bfin_write16(DMA2_7_Y_MODIFY,val)
#define pDMA2_7_CURR_DESC_PTR (volatile void **)DMA2_7_CURR_DESC_PTR
#define bfin_read_DMA2_7_CURR_DESC_PTR()     bfin_read32(DMA2_7_CURR_DESC_PTR)
#define bfin_write_DMA2_7_CURR_DESC_PTR(val) bfin_write32(DMA2_7_CURR_DESC_PTR,val)
#define pDMA2_7_CURR_ADDR (volatile void **)DMA2_7_CURR_ADDR
#define bfin_read_DMA2_7_CURR_ADDR()         bfin_read32(DMA2_7_CURR_ADDR)
#define bfin_write_DMA2_7_CURR_ADDR(val)     bfin_write32(DMA2_7_CURR_ADDR,val)
#define pDMA2_7_CURR_X_COUNT (volatile unsigned short *)DMA2_7_CURR_X_COUNT
#define bfin_read_DMA2_7_CURR_X_COUNT()      bfin_read16(DMA2_7_CURR_X_COUNT)
#define bfin_write_DMA2_7_CURR_X_COUNT(val)  bfin_write16(DMA2_7_CURR_X_COUNT,val)
#define pDMA2_7_CURR_Y_COUNT (volatile unsigned short *)DMA2_7_CURR_Y_COUNT
#define bfin_read_DMA2_7_CURR_Y_COUNT()      bfin_read16(DMA2_7_CURR_Y_COUNT)
#define bfin_write_DMA2_7_CURR_Y_COUNT(val)  bfin_write16(DMA2_7_CURR_Y_COUNT,val)
#define pDMA2_7_IRQ_STATUS (volatile unsigned short *)DMA2_7_IRQ_STATUS
#define bfin_read_DMA2_7_IRQ_STATUS()        bfin_read16(DMA2_7_IRQ_STATUS)
#define bfin_write_DMA2_7_IRQ_STATUS(val)    bfin_write16(DMA2_7_IRQ_STATUS,val)
#define pDMA2_7_PERIPHERAL_MAP (volatile unsigned short *)DMA2_7_PERIPHERAL_MAP
#define bfin_read_DMA2_7_PERIPHERAL_MAP()    bfin_read16(DMA2_7_PERIPHERAL_MAP)
#define bfin_write_DMA2_7_PERIPHERAL_MAP(val) bfin_write16(DMA2_7_PERIPHERAL_MAP,val)
#define pDMA2_8_CONFIG (volatile unsigned short *)DMA2_8_CONFIG
#define bfin_read_DMA2_8_CONFIG()            bfin_read16(DMA2_8_CONFIG)
#define bfin_write_DMA2_8_CONFIG(val)        bfin_write16(DMA2_8_CONFIG,val)
#define pDMA2_8_NEXT_DESC_PTR (volatile void **)DMA2_8_NEXT_DESC_PTR
#define bfin_read_DMA2_8_NEXT_DESC_PTR()     bfin_read32(DMA2_8_NEXT_DESC_PTR)
#define bfin_write_DMA2_8_NEXT_DESC_PTR(val) bfin_write32(DMA2_8_NEXT_DESC_PTR,val)
#define pDMA2_8_START_ADDR (volatile void **)DMA2_8_START_ADDR
#define bfin_read_DMA2_8_START_ADDR()        bfin_read32(DMA2_8_START_ADDR)
#define bfin_write_DMA2_8_START_ADDR(val)    bfin_write32(DMA2_8_START_ADDR,val)
#define pDMA2_8_X_COUNT (volatile unsigned short *)DMA2_8_X_COUNT
#define bfin_read_DMA2_8_X_COUNT()           bfin_read16(DMA2_8_X_COUNT)
#define bfin_write_DMA2_8_X_COUNT(val)       bfin_write16(DMA2_8_X_COUNT,val)
#define pDMA2_8_Y_COUNT (volatile unsigned short *)DMA2_8_Y_COUNT
#define bfin_read_DMA2_8_Y_COUNT()           bfin_read16(DMA2_8_Y_COUNT)
#define bfin_write_DMA2_8_Y_COUNT(val)       bfin_write16(DMA2_8_Y_COUNT,val)
#define pDMA2_8_X_MODIFY (volatile signed short *)DMA2_8_X_MODIFY
#define bfin_read_DMA2_8_X_MODIFY()          bfin_read16(DMA2_8_X_MODIFY)
#define bfin_write_DMA2_8_X_MODIFY(val)      bfin_write16(DMA2_8_X_MODIFY,val)
#define pDMA2_8_Y_MODIFY (volatile signed short *)DMA2_8_Y_MODIFY
#define bfin_read_DMA2_8_Y_MODIFY()          bfin_read16(DMA2_8_Y_MODIFY)
#define bfin_write_DMA2_8_Y_MODIFY(val)      bfin_write16(DMA2_8_Y_MODIFY,val)
#define pDMA2_8_CURR_DESC_PTR (volatile void **)DMA2_8_CURR_DESC_PTR
#define bfin_read_DMA2_8_CURR_DESC_PTR()     bfin_read32(DMA2_8_CURR_DESC_PTR)
#define bfin_write_DMA2_8_CURR_DESC_PTR(val) bfin_write32(DMA2_8_CURR_DESC_PTR,val)
#define pDMA2_8_CURR_ADDR (volatile void **)DMA2_8_CURR_ADDR
#define bfin_read_DMA2_8_CURR_ADDR()         bfin_read32(DMA2_8_CURR_ADDR)
#define bfin_write_DMA2_8_CURR_ADDR(val)     bfin_write32(DMA2_8_CURR_ADDR,val)
#define pDMA2_8_CURR_X_COUNT (volatile unsigned short *)DMA2_8_CURR_X_COUNT
#define bfin_read_DMA2_8_CURR_X_COUNT()      bfin_read16(DMA2_8_CURR_X_COUNT)
#define bfin_write_DMA2_8_CURR_X_COUNT(val)  bfin_write16(DMA2_8_CURR_X_COUNT,val)
#define pDMA2_8_CURR_Y_COUNT (volatile unsigned short *)DMA2_8_CURR_Y_COUNT
#define bfin_read_DMA2_8_CURR_Y_COUNT()      bfin_read16(DMA2_8_CURR_Y_COUNT)
#define bfin_write_DMA2_8_CURR_Y_COUNT(val)  bfin_write16(DMA2_8_CURR_Y_COUNT,val)
#define pDMA2_8_IRQ_STATUS (volatile unsigned short *)DMA2_8_IRQ_STATUS
#define bfin_read_DMA2_8_IRQ_STATUS()        bfin_read16(DMA2_8_IRQ_STATUS)
#define bfin_write_DMA2_8_IRQ_STATUS(val)    bfin_write16(DMA2_8_IRQ_STATUS,val)
#define pDMA2_8_PERIPHERAL_MAP (volatile unsigned short *)DMA2_8_PERIPHERAL_MAP
#define bfin_read_DMA2_8_PERIPHERAL_MAP()    bfin_read16(DMA2_8_PERIPHERAL_MAP)
#define bfin_write_DMA2_8_PERIPHERAL_MAP(val) bfin_write16(DMA2_8_PERIPHERAL_MAP,val)
#define pDMA2_9_CONFIG (volatile unsigned short *)DMA2_9_CONFIG
#define bfin_read_DMA2_9_CONFIG()            bfin_read16(DMA2_9_CONFIG)
#define bfin_write_DMA2_9_CONFIG(val)        bfin_write16(DMA2_9_CONFIG,val)
#define pDMA2_9_NEXT_DESC_PTR (volatile void **)DMA2_9_NEXT_DESC_PTR
#define bfin_read_DMA2_9_NEXT_DESC_PTR()     bfin_read32(DMA2_9_NEXT_DESC_PTR)
#define bfin_write_DMA2_9_NEXT_DESC_PTR(val) bfin_write32(DMA2_9_NEXT_DESC_PTR,val)
#define pDMA2_9_START_ADDR (volatile void **)DMA2_9_START_ADDR
#define bfin_read_DMA2_9_START_ADDR()        bfin_read32(DMA2_9_START_ADDR)
#define bfin_write_DMA2_9_START_ADDR(val)    bfin_write32(DMA2_9_START_ADDR,val)
#define pDMA2_9_X_COUNT (volatile unsigned short *)DMA2_9_X_COUNT
#define bfin_read_DMA2_9_X_COUNT()           bfin_read16(DMA2_9_X_COUNT)
#define bfin_write_DMA2_9_X_COUNT(val)       bfin_write16(DMA2_9_X_COUNT,val)
#define pDMA2_9_Y_COUNT (volatile unsigned short *)DMA2_9_Y_COUNT
#define bfin_read_DMA2_9_Y_COUNT()           bfin_read16(DMA2_9_Y_COUNT)
#define bfin_write_DMA2_9_Y_COUNT(val)       bfin_write16(DMA2_9_Y_COUNT,val)
#define pDMA2_9_X_MODIFY (volatile signed short *)DMA2_9_X_MODIFY
#define bfin_read_DMA2_9_X_MODIFY()          bfin_read16(DMA2_9_X_MODIFY)
#define bfin_write_DMA2_9_X_MODIFY(val)      bfin_write16(DMA2_9_X_MODIFY,val)
#define pDMA2_9_Y_MODIFY (volatile signed short *)DMA2_9_Y_MODIFY
#define bfin_read_DMA2_9_Y_MODIFY()          bfin_read16(DMA2_9_Y_MODIFY)
#define bfin_write_DMA2_9_Y_MODIFY(val)      bfin_write16(DMA2_9_Y_MODIFY,val)
#define pDMA2_9_CURR_DESC_PTR (volatile void **)DMA2_9_CURR_DESC_PTR
#define bfin_read_DMA2_9_CURR_DESC_PTR()     bfin_read32(DMA2_9_CURR_DESC_PTR)
#define bfin_write_DMA2_9_CURR_DESC_PTR(val) bfin_write32(DMA2_9_CURR_DESC_PTR,val)
#define pDMA2_9_CURR_ADDR (volatile void **)DMA2_9_CURR_ADDR
#define bfin_read_DMA2_9_CURR_ADDR()         bfin_read32(DMA2_9_CURR_ADDR)
#define bfin_write_DMA2_9_CURR_ADDR(val)     bfin_write32(DMA2_9_CURR_ADDR,val)
#define pDMA2_9_CURR_X_COUNT (volatile unsigned short *)DMA2_9_CURR_X_COUNT
#define bfin_read_DMA2_9_CURR_X_COUNT()      bfin_read16(DMA2_9_CURR_X_COUNT)
#define bfin_write_DMA2_9_CURR_X_COUNT(val)  bfin_write16(DMA2_9_CURR_X_COUNT,val)
#define pDMA2_9_CURR_Y_COUNT (volatile unsigned short *)DMA2_9_CURR_Y_COUNT
#define bfin_read_DMA2_9_CURR_Y_COUNT()      bfin_read16(DMA2_9_CURR_Y_COUNT)
#define bfin_write_DMA2_9_CURR_Y_COUNT(val)  bfin_write16(DMA2_9_CURR_Y_COUNT,val)
#define pDMA2_9_IRQ_STATUS (volatile unsigned short *)DMA2_9_IRQ_STATUS
#define bfin_read_DMA2_9_IRQ_STATUS()        bfin_read16(DMA2_9_IRQ_STATUS)
#define bfin_write_DMA2_9_IRQ_STATUS(val)    bfin_write16(DMA2_9_IRQ_STATUS,val)
#define pDMA2_9_PERIPHERAL_MAP (volatile unsigned short *)DMA2_9_PERIPHERAL_MAP
#define bfin_read_DMA2_9_PERIPHERAL_MAP()    bfin_read16(DMA2_9_PERIPHERAL_MAP)
#define bfin_write_DMA2_9_PERIPHERAL_MAP(val) bfin_write16(DMA2_9_PERIPHERAL_MAP,val)
#define pDMA2_10_CONFIG (volatile unsigned short *)DMA2_10_CONFIG
#define bfin_read_DMA2_10_CONFIG()           bfin_read16(DMA2_10_CONFIG)
#define bfin_write_DMA2_10_CONFIG(val)       bfin_write16(DMA2_10_CONFIG,val)
#define pDMA2_10_NEXT_DESC_PTR (volatile void **)DMA2_10_NEXT_DESC_PTR
#define bfin_read_DMA2_10_NEXT_DESC_PTR()    bfin_read32(DMA2_10_NEXT_DESC_PTR)
#define bfin_write_DMA2_10_NEXT_DESC_PTR(val) bfin_write32(DMA2_10_NEXT_DESC_PTR,val)
#define pDMA2_10_START_ADDR (volatile void **)DMA2_10_START_ADDR
#define bfin_read_DMA2_10_START_ADDR()       bfin_read32(DMA2_10_START_ADDR)
#define bfin_write_DMA2_10_START_ADDR(val)   bfin_write32(DMA2_10_START_ADDR,val)
#define pDMA2_10_X_COUNT (volatile unsigned short *)DMA2_10_X_COUNT
#define bfin_read_DMA2_10_X_COUNT()          bfin_read16(DMA2_10_X_COUNT)
#define bfin_write_DMA2_10_X_COUNT(val)      bfin_write16(DMA2_10_X_COUNT,val)
#define pDMA2_10_Y_COUNT (volatile unsigned short *)DMA2_10_Y_COUNT
#define bfin_read_DMA2_10_Y_COUNT()          bfin_read16(DMA2_10_Y_COUNT)
#define bfin_write_DMA2_10_Y_COUNT(val)      bfin_write16(DMA2_10_Y_COUNT,val)
#define pDMA2_10_X_MODIFY (volatile signed short *)DMA2_10_X_MODIFY
#define bfin_read_DMA2_10_X_MODIFY()         bfin_read16(DMA2_10_X_MODIFY)
#define bfin_write_DMA2_10_X_MODIFY(val)     bfin_write16(DMA2_10_X_MODIFY,val)
#define pDMA2_10_Y_MODIFY (volatile signed short *)DMA2_10_Y_MODIFY
#define bfin_read_DMA2_10_Y_MODIFY()         bfin_read16(DMA2_10_Y_MODIFY)
#define bfin_write_DMA2_10_Y_MODIFY(val)     bfin_write16(DMA2_10_Y_MODIFY,val)
#define pDMA2_10_CURR_DESC_PTR (volatile void **)DMA2_10_CURR_DESC_PTR
#define bfin_read_DMA2_10_CURR_DESC_PTR()    bfin_read32(DMA2_10_CURR_DESC_PTR)
#define bfin_write_DMA2_10_CURR_DESC_PTR(val) bfin_write32(DMA2_10_CURR_DESC_PTR,val)
#define pDMA2_10_CURR_ADDR (volatile void **)DMA2_10_CURR_ADDR
#define bfin_read_DMA2_10_CURR_ADDR()        bfin_read32(DMA2_10_CURR_ADDR)
#define bfin_write_DMA2_10_CURR_ADDR(val)    bfin_write32(DMA2_10_CURR_ADDR,val)
#define pDMA2_10_CURR_X_COUNT (volatile unsigned short *)DMA2_10_CURR_X_COUNT
#define bfin_read_DMA2_10_CURR_X_COUNT()     bfin_read16(DMA2_10_CURR_X_COUNT)
#define bfin_write_DMA2_10_CURR_X_COUNT(val) bfin_write16(DMA2_10_CURR_X_COUNT,val)
#define pDMA2_10_CURR_Y_COUNT (volatile unsigned short *)DMA2_10_CURR_Y_COUNT
#define bfin_read_DMA2_10_CURR_Y_COUNT()     bfin_read16(DMA2_10_CURR_Y_COUNT)
#define bfin_write_DMA2_10_CURR_Y_COUNT(val) bfin_write16(DMA2_10_CURR_Y_COUNT,val)
#define pDMA2_10_IRQ_STATUS (volatile unsigned short *)DMA2_10_IRQ_STATUS
#define bfin_read_DMA2_10_IRQ_STATUS()       bfin_read16(DMA2_10_IRQ_STATUS)
#define bfin_write_DMA2_10_IRQ_STATUS(val)   bfin_write16(DMA2_10_IRQ_STATUS,val)
#define pDMA2_10_PERIPHERAL_MAP (volatile unsigned short *)DMA2_10_PERIPHERAL_MAP
#define bfin_read_DMA2_10_PERIPHERAL_MAP()   bfin_read16(DMA2_10_PERIPHERAL_MAP)
#define bfin_write_DMA2_10_PERIPHERAL_MAP(val) bfin_write16(DMA2_10_PERIPHERAL_MAP,val)
#define pDMA2_11_CONFIG (volatile unsigned short *)DMA2_11_CONFIG
#define bfin_read_DMA2_11_CONFIG()           bfin_read16(DMA2_11_CONFIG)
#define bfin_write_DMA2_11_CONFIG(val)       bfin_write16(DMA2_11_CONFIG,val)
#define pDMA2_11_NEXT_DESC_PTR (volatile void **)DMA2_11_NEXT_DESC_PTR
#define bfin_read_DMA2_11_NEXT_DESC_PTR()    bfin_read32(DMA2_11_NEXT_DESC_PTR)
#define bfin_write_DMA2_11_NEXT_DESC_PTR(val) bfin_write32(DMA2_11_NEXT_DESC_PTR,val)
#define pDMA2_11_START_ADDR (volatile void **)DMA2_11_START_ADDR
#define bfin_read_DMA2_11_START_ADDR()       bfin_read32(DMA2_11_START_ADDR)
#define bfin_write_DMA2_11_START_ADDR(val)   bfin_write32(DMA2_11_START_ADDR,val)
#define pDMA2_11_X_COUNT (volatile unsigned short *)DMA2_11_X_COUNT
#define bfin_read_DMA2_11_X_COUNT()          bfin_read16(DMA2_11_X_COUNT)
#define bfin_write_DMA2_11_X_COUNT(val)      bfin_write16(DMA2_11_X_COUNT,val)
#define pDMA2_11_Y_COUNT (volatile unsigned short *)DMA2_11_Y_COUNT
#define bfin_read_DMA2_11_Y_COUNT()          bfin_read16(DMA2_11_Y_COUNT)
#define bfin_write_DMA2_11_Y_COUNT(val)      bfin_write16(DMA2_11_Y_COUNT,val)
#define pDMA2_11_X_MODIFY (volatile signed short *)DMA2_11_X_MODIFY
#define bfin_read_DMA2_11_X_MODIFY()         bfin_read16(DMA2_11_X_MODIFY)
#define bfin_write_DMA2_11_X_MODIFY(val)     bfin_write16(DMA2_11_X_MODIFY,val)
#define pDMA2_11_Y_MODIFY (volatile signed short *)DMA2_11_Y_MODIFY
#define bfin_read_DMA2_11_Y_MODIFY()         bfin_read16(DMA2_11_Y_MODIFY)
#define bfin_write_DMA2_11_Y_MODIFY(val)     bfin_write16(DMA2_11_Y_MODIFY,val)
#define pDMA2_11_CURR_DESC_PTR (volatile void **)DMA2_11_CURR_DESC_PTR
#define bfin_read_DMA2_11_CURR_DESC_PTR()    bfin_read32(DMA2_11_CURR_DESC_PTR)
#define bfin_write_DMA2_11_CURR_DESC_PTR(val) bfin_write32(DMA2_11_CURR_DESC_PTR,val)
#define pDMA2_11_CURR_ADDR (volatile void **)DMA2_11_CURR_ADDR
#define bfin_read_DMA2_11_CURR_ADDR()        bfin_read32(DMA2_11_CURR_ADDR)
#define bfin_write_DMA2_11_CURR_ADDR(val)    bfin_write32(DMA2_11_CURR_ADDR,val)
#define pDMA2_11_CURR_X_COUNT (volatile unsigned short *)DMA2_11_CURR_X_COUNT
#define bfin_read_DMA2_11_CURR_X_COUNT()     bfin_read16(DMA2_11_CURR_X_COUNT)
#define bfin_write_DMA2_11_CURR_X_COUNT(val) bfin_write16(DMA2_11_CURR_X_COUNT,val)
#define pDMA2_11_CURR_Y_COUNT (volatile unsigned short *)DMA2_11_CURR_Y_COUNT
#define bfin_read_DMA2_11_CURR_Y_COUNT()     bfin_read16(DMA2_11_CURR_Y_COUNT)
#define bfin_write_DMA2_11_CURR_Y_COUNT(val) bfin_write16(DMA2_11_CURR_Y_COUNT,val)
#define pDMA2_11_IRQ_STATUS (volatile unsigned short *)DMA2_11_IRQ_STATUS
#define bfin_read_DMA2_11_IRQ_STATUS()       bfin_read16(DMA2_11_IRQ_STATUS)
#define bfin_write_DMA2_11_IRQ_STATUS(val)   bfin_write16(DMA2_11_IRQ_STATUS,val)
#define pDMA2_11_PERIPHERAL_MAP (volatile unsigned short *)DMA2_11_PERIPHERAL_MAP
#define bfin_read_DMA2_11_PERIPHERAL_MAP()   bfin_read16(DMA2_11_PERIPHERAL_MAP)
#define bfin_write_DMA2_11_PERIPHERAL_MAP(val) bfin_write16(DMA2_11_PERIPHERAL_MAP,val)
/* Memory DMA2 Controller registers (0xFFC0 0E80-0xFFC0 0FFF) */
#define pMDMA2_D0_CONFIG (volatile unsigned short *)MDMA2_D0_CONFIG
#define bfin_read_MDMA2_D0_CONFIG()          bfin_read16(MDMA2_D0_CONFIG)
#define bfin_write_MDMA2_D0_CONFIG(val)      bfin_write16(MDMA2_D0_CONFIG,val)
#define pMDMA2_D0_NEXT_DESC_PTR (volatile void **)MDMA2_D0_NEXT_DESC_PTR
#define bfin_read_MDMA2_D0_NEXT_DESC_PTR()   bfin_read32(MDMA2_D0_NEXT_DESC_PTR)
#define bfin_write_MDMA2_D0_NEXT_DESC_PTR(val) bfin_write32(MDMA2_D0_NEXT_DESC_PTR,val)
#define pMDMA2_D0_START_ADDR (volatile void **)MDMA2_D0_START_ADDR
#define bfin_read_MDMA2_D0_START_ADDR()      bfin_read32(MDMA2_D0_START_ADDR)
#define bfin_write_MDMA2_D0_START_ADDR(val)  bfin_write32(MDMA2_D0_START_ADDR,val)
#define pMDMA2_D0_X_COUNT (volatile unsigned short *)MDMA2_D0_X_COUNT
#define bfin_read_MDMA2_D0_X_COUNT()         bfin_read16(MDMA2_D0_X_COUNT)
#define bfin_write_MDMA2_D0_X_COUNT(val)     bfin_write16(MDMA2_D0_X_COUNT,val)
#define pMDMA2_D0_Y_COUNT (volatile unsigned short *)MDMA2_D0_Y_COUNT
#define bfin_read_MDMA2_D0_Y_COUNT()         bfin_read16(MDMA2_D0_Y_COUNT)
#define bfin_write_MDMA2_D0_Y_COUNT(val)     bfin_write16(MDMA2_D0_Y_COUNT,val)
#define pMDMA2_D0_X_MODIFY (volatile signed short *)MDMA2_D0_X_MODIFY
#define bfin_read_MDMA2_D0_X_MODIFY()        bfin_read16(MDMA2_D0_X_MODIFY)
#define bfin_write_MDMA2_D0_X_MODIFY(val)    bfin_write16(MDMA2_D0_X_MODIFY,val)
#define pMDMA2_D0_Y_MODIFY (volatile signed short *)MDMA2_D0_Y_MODIFY
#define bfin_read_MDMA2_D0_Y_MODIFY()        bfin_read16(MDMA2_D0_Y_MODIFY)
#define bfin_write_MDMA2_D0_Y_MODIFY(val)    bfin_write16(MDMA2_D0_Y_MODIFY,val)
#define pMDMA2_D0_CURR_DESC_PTR (volatile void **)MDMA2_D0_CURR_DESC_PTR
#define bfin_read_MDMA2_D0_CURR_DESC_PTR()   bfin_read32(MDMA2_D0_CURR_DESC_PTR)
#define bfin_write_MDMA2_D0_CURR_DESC_PTR(val) bfin_write32(MDMA2_D0_CURR_DESC_PTR,val)
#define pMDMA2_D0_CURR_ADDR (volatile void **)MDMA2_D0_CURR_ADDR
#define bfin_read_MDMA2_D0_CURR_ADDR()       bfin_read32(MDMA2_D0_CURR_ADDR)
#define bfin_write_MDMA2_D0_CURR_ADDR(val)   bfin_write32(MDMA2_D0_CURR_ADDR,val)
#define pMDMA2_D0_CURR_X_COUNT (volatile unsigned short *)MDMA2_D0_CURR_X_COUNT
#define bfin_read_MDMA2_D0_CURR_X_COUNT()    bfin_read16(MDMA2_D0_CURR_X_COUNT)
#define bfin_write_MDMA2_D0_CURR_X_COUNT(val) bfin_write16(MDMA2_D0_CURR_X_COUNT,val)
#define pMDMA2_D0_CURR_Y_COUNT (volatile unsigned short *)MDMA2_D0_CURR_Y_COUNT
#define bfin_read_MDMA2_D0_CURR_Y_COUNT()    bfin_read16(MDMA2_D0_CURR_Y_COUNT)
#define bfin_write_MDMA2_D0_CURR_Y_COUNT(val) bfin_write16(MDMA2_D0_CURR_Y_COUNT,val)
#define pMDMA2_D0_IRQ_STATUS (volatile unsigned short *)MDMA2_D0_IRQ_STATUS
#define bfin_read_MDMA2_D0_IRQ_STATUS()      bfin_read16(MDMA2_D0_IRQ_STATUS)
#define bfin_write_MDMA2_D0_IRQ_STATUS(val)  bfin_write16(MDMA2_D0_IRQ_STATUS,val)
#define pMDMA2_D0_PERIPHERAL_MAP (volatile unsigned short *)MDMA2_D0_PERIPHERAL_MAP
#define bfin_read_MDMA2_D0_PERIPHERAL_MAP()  bfin_read16(MDMA2_D0_PERIPHERAL_MAP)
#define bfin_write_MDMA2_D0_PERIPHERAL_MAP(val) bfin_write16(MDMA2_D0_PERIPHERAL_MAP,val)
#define pMDMA2_S0_CONFIG (volatile unsigned short *)MDMA2_S0_CONFIG
#define bfin_read_MDMA2_S0_CONFIG()          bfin_read16(MDMA2_S0_CONFIG)
#define bfin_write_MDMA2_S0_CONFIG(val)      bfin_write16(MDMA2_S0_CONFIG,val)
#define pMDMA2_S0_NEXT_DESC_PTR (volatile void **)MDMA2_S0_NEXT_DESC_PTR
#define bfin_read_MDMA2_S0_NEXT_DESC_PTR()   bfin_read32(MDMA2_S0_NEXT_DESC_PTR)
#define bfin_write_MDMA2_S0_NEXT_DESC_PTR(val) bfin_write32(MDMA2_S0_NEXT_DESC_PTR,val)
#define pMDMA2_S0_START_ADDR (volatile void **)MDMA2_S0_START_ADDR
#define bfin_read_MDMA2_S0_START_ADDR()      bfin_read32(MDMA2_S0_START_ADDR)
#define bfin_write_MDMA2_S0_START_ADDR(val)  bfin_write32(MDMA2_S0_START_ADDR,val)
#define pMDMA2_S0_X_COUNT (volatile unsigned short *)MDMA2_S0_X_COUNT
#define bfin_read_MDMA2_S0_X_COUNT()         bfin_read16(MDMA2_S0_X_COUNT)
#define bfin_write_MDMA2_S0_X_COUNT(val)     bfin_write16(MDMA2_S0_X_COUNT,val)
#define pMDMA2_S0_Y_COUNT (volatile unsigned short *)MDMA2_S0_Y_COUNT
#define bfin_read_MDMA2_S0_Y_COUNT()         bfin_read16(MDMA2_S0_Y_COUNT)
#define bfin_write_MDMA2_S0_Y_COUNT(val)     bfin_write16(MDMA2_S0_Y_COUNT,val)
#define pMDMA2_S0_X_MODIFY (volatile signed short *)MDMA2_S0_X_MODIFY
#define bfin_read_MDMA2_S0_X_MODIFY()        bfin_read16(MDMA2_S0_X_MODIFY)
#define bfin_write_MDMA2_S0_X_MODIFY(val)    bfin_write16(MDMA2_S0_X_MODIFY,val)
#define pMDMA2_S0_Y_MODIFY (volatile signed short *)MDMA2_S0_Y_MODIFY
#define bfin_read_MDMA2_S0_Y_MODIFY()        bfin_read16(MDMA2_S0_Y_MODIFY)
#define bfin_write_MDMA2_S0_Y_MODIFY(val)    bfin_write16(MDMA2_S0_Y_MODIFY,val)
#define pMDMA2_S0_CURR_DESC_PTR (volatile void **)MDMA2_S0_CURR_DESC_PTR
#define bfin_read_MDMA2_S0_CURR_DESC_PTR()   bfin_read32(MDMA2_S0_CURR_DESC_PTR)
#define bfin_write_MDMA2_S0_CURR_DESC_PTR(val) bfin_write32(MDMA2_S0_CURR_DESC_PTR,val)
#define pMDMA2_S0_CURR_ADDR (volatile void **)MDMA2_S0_CURR_ADDR
#define bfin_read_MDMA2_S0_CURR_ADDR()       bfin_read32(MDMA2_S0_CURR_ADDR)
#define bfin_write_MDMA2_S0_CURR_ADDR(val)   bfin_write32(MDMA2_S0_CURR_ADDR,val)
#define pMDMA2_S0_CURR_X_COUNT (volatile unsigned short *)MDMA2_S0_CURR_X_COUNT
#define bfin_read_MDMA2_S0_CURR_X_COUNT()    bfin_read16(MDMA2_S0_CURR_X_COUNT)
#define bfin_write_MDMA2_S0_CURR_X_COUNT(val) bfin_write16(MDMA2_S0_CURR_X_COUNT,val)
#define pMDMA2_S0_CURR_Y_COUNT (volatile unsigned short *)MDMA2_S0_CURR_Y_COUNT
#define bfin_read_MDMA2_S0_CURR_Y_COUNT()    bfin_read16(MDMA2_S0_CURR_Y_COUNT)
#define bfin_write_MDMA2_S0_CURR_Y_COUNT(val) bfin_write16(MDMA2_S0_CURR_Y_COUNT,val)
#define pMDMA2_S0_IRQ_STATUS (volatile unsigned short *)MDMA2_S0_IRQ_STATUS
#define bfin_read_MDMA2_S0_IRQ_STATUS()      bfin_read16(MDMA2_S0_IRQ_STATUS)
#define bfin_write_MDMA2_S0_IRQ_STATUS(val)  bfin_write16(MDMA2_S0_IRQ_STATUS,val)
#define pMDMA2_S0_PERIPHERAL_MAP (volatile unsigned short *)MDMA2_S0_PERIPHERAL_MAP
#define bfin_read_MDMA2_S0_PERIPHERAL_MAP()  bfin_read16(MDMA2_S0_PERIPHERAL_MAP)
#define bfin_write_MDMA2_S0_PERIPHERAL_MAP(val) bfin_write16(MDMA2_S0_PERIPHERAL_MAP,val)
#define pMDMA2_D1_CONFIG (volatile unsigned short *)MDMA2_D1_CONFIG
#define bfin_read_MDMA2_D1_CONFIG()          bfin_read16(MDMA2_D1_CONFIG)
#define bfin_write_MDMA2_D1_CONFIG(val)      bfin_write16(MDMA2_D1_CONFIG,val)
#define pMDMA2_D1_NEXT_DESC_PTR (volatile void **)MDMA2_D1_NEXT_DESC_PTR
#define bfin_read_MDMA2_D1_NEXT_DESC_PTR()   bfin_read32(MDMA2_D1_NEXT_DESC_PTR)
#define bfin_write_MDMA2_D1_NEXT_DESC_PTR(val) bfin_write32(MDMA2_D1_NEXT_DESC_PTR,val)
#define pMDMA2_D1_START_ADDR (volatile void **)MDMA2_D1_START_ADDR
#define bfin_read_MDMA2_D1_START_ADDR()      bfin_read32(MDMA2_D1_START_ADDR)
#define bfin_write_MDMA2_D1_START_ADDR(val)  bfin_write32(MDMA2_D1_START_ADDR,val)
#define pMDMA2_D1_X_COUNT (volatile unsigned short *)MDMA2_D1_X_COUNT
#define bfin_read_MDMA2_D1_X_COUNT()         bfin_read16(MDMA2_D1_X_COUNT)
#define bfin_write_MDMA2_D1_X_COUNT(val)     bfin_write16(MDMA2_D1_X_COUNT,val)
#define pMDMA2_D1_Y_COUNT (volatile unsigned short *)MDMA2_D1_Y_COUNT
#define bfin_read_MDMA2_D1_Y_COUNT()         bfin_read16(MDMA2_D1_Y_COUNT)
#define bfin_write_MDMA2_D1_Y_COUNT(val)     bfin_write16(MDMA2_D1_Y_COUNT,val)
#define pMDMA2_D1_X_MODIFY (volatile signed short *)MDMA2_D1_X_MODIFY
#define bfin_read_MDMA2_D1_X_MODIFY()        bfin_read16(MDMA2_D1_X_MODIFY)
#define bfin_write_MDMA2_D1_X_MODIFY(val)    bfin_write16(MDMA2_D1_X_MODIFY,val)
#define pMDMA2_D1_Y_MODIFY (volatile signed short *)MDMA2_D1_Y_MODIFY
#define bfin_read_MDMA2_D1_Y_MODIFY()        bfin_read16(MDMA2_D1_Y_MODIFY)
#define bfin_write_MDMA2_D1_Y_MODIFY(val)    bfin_write16(MDMA2_D1_Y_MODIFY,val)
#define pMDMA2_D1_CURR_DESC_PTR (volatile void **)MDMA2_D1_CURR_DESC_PTR
#define bfin_read_MDMA2_D1_CURR_DESC_PTR()   bfin_read32(MDMA2_D1_CURR_DESC_PTR)
#define bfin_write_MDMA2_D1_CURR_DESC_PTR(val) bfin_write32(MDMA2_D1_CURR_DESC_PTR,val)
#define pMDMA2_D1_CURR_ADDR (volatile void **)MDMA2_D1_CURR_ADDR
#define bfin_read_MDMA2_D1_CURR_ADDR()       bfin_read32(MDMA2_D1_CURR_ADDR)
#define bfin_write_MDMA2_D1_CURR_ADDR(val)   bfin_write32(MDMA2_D1_CURR_ADDR,val)
#define pMDMA2_D1_CURR_X_COUNT (volatile unsigned short *)MDMA2_D1_CURR_X_COUNT
#define bfin_read_MDMA2_D1_CURR_X_COUNT()    bfin_read16(MDMA2_D1_CURR_X_COUNT)
#define bfin_write_MDMA2_D1_CURR_X_COUNT(val) bfin_write16(MDMA2_D1_CURR_X_COUNT,val)
#define pMDMA2_D1_CURR_Y_COUNT (volatile unsigned short *)MDMA2_D1_CURR_Y_COUNT
#define bfin_read_MDMA2_D1_CURR_Y_COUNT()    bfin_read16(MDMA2_D1_CURR_Y_COUNT)
#define bfin_write_MDMA2_D1_CURR_Y_COUNT(val) bfin_write16(MDMA2_D1_CURR_Y_COUNT,val)
#define pMDMA2_D1_IRQ_STATUS (volatile unsigned short *)MDMA2_D1_IRQ_STATUS
#define bfin_read_MDMA2_D1_IRQ_STATUS()      bfin_read16(MDMA2_D1_IRQ_STATUS)
#define bfin_write_MDMA2_D1_IRQ_STATUS(val)  bfin_write16(MDMA2_D1_IRQ_STATUS,val)
#define pMDMA2_D1_PERIPHERAL_MAP (volatile unsigned short *)MDMA2_D1_PERIPHERAL_MAP
#define bfin_read_MDMA2_D1_PERIPHERAL_MAP()  bfin_read16(MDMA2_D1_PERIPHERAL_MAP)
#define bfin_write_MDMA2_D1_PERIPHERAL_MAP(val) bfin_write16(MDMA2_D1_PERIPHERAL_MAP,val)
#define pMDMA2_S1_CONFIG (volatile unsigned short *)MDMA2_S1_CONFIG
#define bfin_read_MDMA2_S1_CONFIG()          bfin_read16(MDMA2_S1_CONFIG)
#define bfin_write_MDMA2_S1_CONFIG(val)      bfin_write16(MDMA2_S1_CONFIG,val)
#define pMDMA2_S1_NEXT_DESC_PTR (volatile void **)MDMA2_S1_NEXT_DESC_PTR
#define bfin_read_MDMA2_S1_NEXT_DESC_PTR()   bfin_read32(MDMA2_S1_NEXT_DESC_PTR)
#define bfin_write_MDMA2_S1_NEXT_DESC_PTR(val) bfin_write32(MDMA2_S1_NEXT_DESC_PTR,val)
#define pMDMA2_S1_START_ADDR (volatile void **)MDMA2_S1_START_ADDR
#define bfin_read_MDMA2_S1_START_ADDR()      bfin_read32(MDMA2_S1_START_ADDR)
#define bfin_write_MDMA2_S1_START_ADDR(val)  bfin_write32(MDMA2_S1_START_ADDR,val)
#define pMDMA2_S1_X_COUNT (volatile unsigned short *)MDMA2_S1_X_COUNT
#define bfin_read_MDMA2_S1_X_COUNT()         bfin_read16(MDMA2_S1_X_COUNT)
#define bfin_write_MDMA2_S1_X_COUNT(val)     bfin_write16(MDMA2_S1_X_COUNT,val)
#define pMDMA2_S1_Y_COUNT (volatile unsigned short *)MDMA2_S1_Y_COUNT
#define bfin_read_MDMA2_S1_Y_COUNT()         bfin_read16(MDMA2_S1_Y_COUNT)
#define bfin_write_MDMA2_S1_Y_COUNT(val)     bfin_write16(MDMA2_S1_Y_COUNT,val)
#define pMDMA2_S1_X_MODIFY (volatile signed short *)MDMA2_S1_X_MODIFY
#define bfin_read_MDMA2_S1_X_MODIFY()        bfin_read16(MDMA2_S1_X_MODIFY)
#define bfin_write_MDMA2_S1_X_MODIFY(val)    bfin_write16(MDMA2_S1_X_MODIFY,val)
#define pMDMA2_S1_Y_MODIFY (volatile signed short *)MDMA2_S1_Y_MODIFY
#define bfin_read_MDMA2_S1_Y_MODIFY()        bfin_read16(MDMA2_S1_Y_MODIFY)
#define bfin_write_MDMA2_S1_Y_MODIFY(val)    bfin_write16(MDMA2_S1_Y_MODIFY,val)
#define pMDMA2_S1_CURR_DESC_PTR (volatile void **)MDMA2_S1_CURR_DESC_PTR
#define bfin_read_MDMA2_S1_CURR_DESC_PTR()   bfin_read32(MDMA2_S1_CURR_DESC_PTR)
#define bfin_write_MDMA2_S1_CURR_DESC_PTR(val) bfin_write32(MDMA2_S1_CURR_DESC_PTR,val)
#define pMDMA2_S1_CURR_ADDR (volatile void **)MDMA2_S1_CURR_ADDR
#define bfin_read_MDMA2_S1_CURR_ADDR()       bfin_read32(MDMA2_S1_CURR_ADDR)
#define bfin_write_MDMA2_S1_CURR_ADDR(val)   bfin_write32(MDMA2_S1_CURR_ADDR,val)
#define pMDMA2_S1_CURR_X_COUNT (volatile unsigned short *)MDMA2_S1_CURR_X_COUNT
#define bfin_read_MDMA2_S1_CURR_X_COUNT()    bfin_read16(MDMA2_S1_CURR_X_COUNT)
#define bfin_write_MDMA2_S1_CURR_X_COUNT(val) bfin_write16(MDMA2_S1_CURR_X_COUNT,val)
#define pMDMA2_S1_CURR_Y_COUNT (volatile unsigned short *)MDMA2_S1_CURR_Y_COUNT
#define bfin_read_MDMA2_S1_CURR_Y_COUNT()    bfin_read16(MDMA2_S1_CURR_Y_COUNT)
#define bfin_write_MDMA2_S1_CURR_Y_COUNT(val) bfin_write16(MDMA2_S1_CURR_Y_COUNT,val)
#define pMDMA2_S1_IRQ_STATUS (volatile unsigned short *)MDMA2_S1_IRQ_STATUS
#define bfin_read_MDMA2_S1_IRQ_STATUS()      bfin_read16(MDMA2_S1_IRQ_STATUS)
#define bfin_write_MDMA2_S1_IRQ_STATUS(val)  bfin_write16(MDMA2_S1_IRQ_STATUS,val)
#define pMDMA2_S1_PERIPHERAL_MAP (volatile unsigned short *)MDMA2_S1_PERIPHERAL_MAP
#define bfin_read_MDMA2_S1_PERIPHERAL_MAP()  bfin_read16(MDMA2_S1_PERIPHERAL_MAP)
#define bfin_write_MDMA2_S1_PERIPHERAL_MAP(val) bfin_write16(MDMA2_S1_PERIPHERAL_MAP,val)
/* Internal Memory DMA Registers (0xFFC0_1800 - 0xFFC0_19FF) */
#define pIMDMA_D0_CONFIG (volatile unsigned short *)IMDMA_D0_CONFIG
#define bfin_read_IMDMA_D0_CONFIG()          bfin_read16(IMDMA_D0_CONFIG)
#define bfin_write_IMDMA_D0_CONFIG(val)      bfin_write16(IMDMA_D0_CONFIG,val)
#define pIMDMA_D0_NEXT_DESC_PTR (volatile void **)IMDMA_D0_NEXT_DESC_PTR
#define bfin_read_IMDMA_D0_NEXT_DESC_PTR()   bfin_read32(IMDMA_D0_NEXT_DESC_PTR)
#define bfin_write_IMDMA_D0_NEXT_DESC_PTR(val) bfin_write32(IMDMA_D0_NEXT_DESC_PTR,val)
#define pIMDMA_D0_START_ADDR (volatile void **)IMDMA_D0_START_ADDR
#define bfin_read_IMDMA_D0_START_ADDR()      bfin_read32(IMDMA_D0_START_ADDR)
#define bfin_write_IMDMA_D0_START_ADDR(val)  bfin_write32(IMDMA_D0_START_ADDR,val)
#define pIMDMA_D0_X_COUNT (volatile unsigned short *)IMDMA_D0_X_COUNT
#define bfin_read_IMDMA_D0_X_COUNT()         bfin_read16(IMDMA_D0_X_COUNT)
#define bfin_write_IMDMA_D0_X_COUNT(val)     bfin_write16(IMDMA_D0_X_COUNT,val)
#define pIMDMA_D0_Y_COUNT (volatile unsigned short *)IMDMA_D0_Y_COUNT
#define bfin_read_IMDMA_D0_Y_COUNT()         bfin_read16(IMDMA_D0_Y_COUNT)
#define bfin_write_IMDMA_D0_Y_COUNT(val)     bfin_write16(IMDMA_D0_Y_COUNT,val)
#define pIMDMA_D0_X_MODIFY (volatile signed short *)IMDMA_D0_X_MODIFY
#define bfin_read_IMDMA_D0_X_MODIFY()        bfin_read16(IMDMA_D0_X_MODIFY)
#define bfin_write_IMDMA_D0_X_MODIFY(val)    bfin_write16(IMDMA_D0_X_MODIFY,val)
#define pIMDMA_D0_Y_MODIFY (volatile signed short *)IMDMA_D0_Y_MODIFY
#define bfin_read_IMDMA_D0_Y_MODIFY()        bfin_read16(IMDMA_D0_Y_MODIFY)
#define bfin_write_IMDMA_D0_Y_MODIFY(val)    bfin_write16(IMDMA_D0_Y_MODIFY,val)
#define pIMDMA_D0_CURR_DESC_PTR (volatile void **)IMDMA_D0_CURR_DESC_PTR
#define bfin_read_IMDMA_D0_CURR_DESC_PTR()   bfin_read32(IMDMA_D0_CURR_DESC_PTR)
#define bfin_write_IMDMA_D0_CURR_DESC_PTR(val) bfin_write32(IMDMA_D0_CURR_DESC_PTR,val)
#define pIMDMA_D0_CURR_ADDR (volatile void **)IMDMA_D0_CURR_ADDR
#define bfin_read_IMDMA_D0_CURR_ADDR()       bfin_read32(IMDMA_D0_CURR_ADDR)
#define bfin_write_IMDMA_D0_CURR_ADDR(val)   bfin_write32(IMDMA_D0_CURR_ADDR,val)
#define pIMDMA_D0_CURR_X_COUNT (volatile unsigned short *)IMDMA_D0_CURR_X_COUNT
#define bfin_read_IMDMA_D0_CURR_X_COUNT()    bfin_read16(IMDMA_D0_CURR_X_COUNT)
#define bfin_write_IMDMA_D0_CURR_X_COUNT(val) bfin_write16(IMDMA_D0_CURR_X_COUNT,val)
#define pIMDMA_D0_CURR_Y_COUNT (volatile unsigned short *)IMDMA_D0_CURR_Y_COUNT
#define bfin_read_IMDMA_D0_CURR_Y_COUNT()    bfin_read16(IMDMA_D0_CURR_Y_COUNT)
#define bfin_write_IMDMA_D0_CURR_Y_COUNT(val) bfin_write16(IMDMA_D0_CURR_Y_COUNT,val)
#define pIMDMA_D0_IRQ_STATUS (volatile unsigned short *)IMDMA_D0_IRQ_STATUS
#define bfin_read_IMDMA_D0_IRQ_STATUS()      bfin_read16(IMDMA_D0_IRQ_STATUS)
#define bfin_write_IMDMA_D0_IRQ_STATUS(val)  bfin_write16(IMDMA_D0_IRQ_STATUS,val)
#define pIMDMA_S0_CONFIG (volatile unsigned short *)IMDMA_S0_CONFIG
#define bfin_read_IMDMA_S0_CONFIG()          bfin_read16(IMDMA_S0_CONFIG)
#define bfin_write_IMDMA_S0_CONFIG(val)      bfin_write16(IMDMA_S0_CONFIG,val)
#define pIMDMA_S0_NEXT_DESC_PTR (volatile void **)IMDMA_S0_NEXT_DESC_PTR
#define bfin_read_IMDMA_S0_NEXT_DESC_PTR()   bfin_read32(IMDMA_S0_NEXT_DESC_PTR)
#define bfin_write_IMDMA_S0_NEXT_DESC_PTR(val) bfin_write32(IMDMA_S0_NEXT_DESC_PTR,val)
#define pIMDMA_S0_START_ADDR (volatile void **)IMDMA_S0_START_ADDR
#define bfin_read_IMDMA_S0_START_ADDR()      bfin_read32(IMDMA_S0_START_ADDR)
#define bfin_write_IMDMA_S0_START_ADDR(val)  bfin_write32(IMDMA_S0_START_ADDR,val)
#define pIMDMA_S0_X_COUNT (volatile unsigned short *)IMDMA_S0_X_COUNT
#define bfin_read_IMDMA_S0_X_COUNT()         bfin_read16(IMDMA_S0_X_COUNT)
#define bfin_write_IMDMA_S0_X_COUNT(val)     bfin_write16(IMDMA_S0_X_COUNT,val)
#define pIMDMA_S0_Y_COUNT (volatile unsigned short *)IMDMA_S0_Y_COUNT
#define bfin_read_IMDMA_S0_Y_COUNT()         bfin_read16(IMDMA_S0_Y_COUNT)
#define bfin_write_IMDMA_S0_Y_COUNT(val)     bfin_write16(IMDMA_S0_Y_COUNT,val)
#define pIMDMA_S0_X_MODIFY (volatile signed short *)IMDMA_S0_X_MODIFY
#define bfin_read_IMDMA_S0_X_MODIFY()        bfin_read16(IMDMA_S0_X_MODIFY)
#define bfin_write_IMDMA_S0_X_MODIFY(val)    bfin_write16(IMDMA_S0_X_MODIFY,val)
#define pIMDMA_S0_Y_MODIFY (volatile signed short *)IMDMA_S0_Y_MODIFY
#define bfin_read_IMDMA_S0_Y_MODIFY()        bfin_read16(IMDMA_S0_Y_MODIFY)
#define bfin_write_IMDMA_S0_Y_MODIFY(val)    bfin_write16(IMDMA_S0_Y_MODIFY,val)
#define pIMDMA_S0_CURR_DESC_PTR (volatile void **)IMDMA_S0_CURR_DESC_PTR
#define bfin_read_IMDMA_S0_CURR_DESC_PTR()   bfin_read32(IMDMA_S0_CURR_DESC_PTR)
#define bfin_write_IMDMA_S0_CURR_DESC_PTR(val) bfin_write32(IMDMA_S0_CURR_DESC_PTR,val)
#define pIMDMA_S0_CURR_ADDR (volatile void **)IMDMA_S0_CURR_ADDR
#define bfin_read_IMDMA_S0_CURR_ADDR()       bfin_read32(IMDMA_S0_CURR_ADDR)
#define bfin_write_IMDMA_S0_CURR_ADDR(val)   bfin_write32(IMDMA_S0_CURR_ADDR,val)
#define pIMDMA_S0_CURR_X_COUNT (volatile unsigned short *)IMDMA_S0_CURR_X_COUNT
#define bfin_read_IMDMA_S0_CURR_X_COUNT()    bfin_read16(IMDMA_S0_CURR_X_COUNT)
#define bfin_write_IMDMA_S0_CURR_X_COUNT(val) bfin_write16(IMDMA_S0_CURR_X_COUNT,val)
#define pIMDMA_S0_CURR_Y_COUNT (volatile unsigned short *)IMDMA_S0_CURR_Y_COUNT
#define bfin_read_IMDMA_S0_CURR_Y_COUNT()    bfin_read16(IMDMA_S0_CURR_Y_COUNT)
#define bfin_write_IMDMA_S0_CURR_Y_COUNT(val) bfin_write16(IMDMA_S0_CURR_Y_COUNT,val)
#define pIMDMA_S0_IRQ_STATUS (volatile unsigned short *)IMDMA_S0_IRQ_STATUS
#define bfin_read_IMDMA_S0_IRQ_STATUS()      bfin_read16(IMDMA_S0_IRQ_STATUS)
#define bfin_write_IMDMA_S0_IRQ_STATUS(val)  bfin_write16(IMDMA_S0_IRQ_STATUS,val)
#define pIMDMA_D1_CONFIG (volatile unsigned short *)IMDMA_D1_CONFIG
#define bfin_read_IMDMA_D1_CONFIG()          bfin_read16(IMDMA_D1_CONFIG)
#define bfin_write_IMDMA_D1_CONFIG(val)      bfin_write16(IMDMA_D1_CONFIG,val)
#define pIMDMA_D1_NEXT_DESC_PTR (volatile void **)IMDMA_D1_NEXT_DESC_PTR
#define bfin_read_IMDMA_D1_NEXT_DESC_PTR()   bfin_read32(IMDMA_D1_NEXT_DESC_PTR)
#define bfin_write_IMDMA_D1_NEXT_DESC_PTR(val) bfin_write32(IMDMA_D1_NEXT_DESC_PTR,val)
#define pIMDMA_D1_START_ADDR (volatile void **)IMDMA_D1_START_ADDR
#define bfin_read_IMDMA_D1_START_ADDR()      bfin_read32(IMDMA_D1_START_ADDR)
#define bfin_write_IMDMA_D1_START_ADDR(val)  bfin_write32(IMDMA_D1_START_ADDR,val)
#define pIMDMA_D1_X_COUNT (volatile unsigned short *)IMDMA_D1_X_COUNT
#define bfin_read_IMDMA_D1_X_COUNT()         bfin_read16(IMDMA_D1_X_COUNT)
#define bfin_write_IMDMA_D1_X_COUNT(val)     bfin_write16(IMDMA_D1_X_COUNT,val)
#define pIMDMA_D1_Y_COUNT (volatile unsigned short *)IMDMA_D1_Y_COUNT
#define bfin_read_IMDMA_D1_Y_COUNT()         bfin_read16(IMDMA_D1_Y_COUNT)
#define bfin_write_IMDMA_D1_Y_COUNT(val)     bfin_write16(IMDMA_D1_Y_COUNT,val)
#define pIMDMA_D1_X_MODIFY (volatile signed short *)IMDMA_D1_X_MODIFY
#define bfin_read_IMDMA_D1_X_MODIFY()        bfin_read16(IMDMA_D1_X_MODIFY)
#define bfin_write_IMDMA_D1_X_MODIFY(val)    bfin_write16(IMDMA_D1_X_MODIFY,val)
#define pIMDMA_D1_Y_MODIFY (volatile signed short *)IMDMA_D1_Y_MODIFY
#define bfin_read_IMDMA_D1_Y_MODIFY()        bfin_read16(IMDMA_D1_Y_MODIFY)
#define bfin_write_IMDMA_D1_Y_MODIFY(val)    bfin_write16(IMDMA_D1_Y_MODIFY,val)
#define pIMDMA_D1_CURR_DESC_PTR (volatile void **)IMDMA_D1_CURR_DESC_PTR
#define bfin_read_IMDMA_D1_CURR_DESC_PTR()   bfin_read32(IMDMA_D1_CURR_DESC_PTR)
#define bfin_write_IMDMA_D1_CURR_DESC_PTR(val) bfin_write32(IMDMA_D1_CURR_DESC_PTR,val)
#define pIMDMA_D1_CURR_ADDR (volatile void **)IMDMA_D1_CURR_ADDR
#define bfin_read_IMDMA_D1_CURR_ADDR()       bfin_read32(IMDMA_D1_CURR_ADDR)
#define bfin_write_IMDMA_D1_CURR_ADDR(val)   bfin_write32(IMDMA_D1_CURR_ADDR,val)
#define pIMDMA_D1_CURR_X_COUNT (volatile unsigned short *)IMDMA_D1_CURR_X_COUNT
#define bfin_read_IMDMA_D1_CURR_X_COUNT()    bfin_read16(IMDMA_D1_CURR_X_COUNT)
#define bfin_write_IMDMA_D1_CURR_X_COUNT(val) bfin_write16(IMDMA_D1_CURR_X_COUNT,val)
#define pIMDMA_D1_CURR_Y_COUNT (volatile unsigned short *)IMDMA_D1_CURR_Y_COUNT
#define bfin_read_IMDMA_D1_CURR_Y_COUNT()    bfin_read16(IMDMA_D1_CURR_Y_COUNT)
#define bfin_write_IMDMA_D1_CURR_Y_COUNT(val) bfin_write16(IMDMA_D1_CURR_Y_COUNT,val)
#define pIMDMA_D1_IRQ_STATUS (volatile unsigned short *)IMDMA_D1_IRQ_STATUS
#define bfin_read_IMDMA_D1_IRQ_STATUS()      bfin_read16(IMDMA_D1_IRQ_STATUS)
#define bfin_write_IMDMA_D1_IRQ_STATUS(val)  bfin_write16(IMDMA_D1_IRQ_STATUS,val)
#define pIMDMA_S1_CONFIG (volatile unsigned short *)IMDMA_S1_CONFIG
#define bfin_read_IMDMA_S1_CONFIG()          bfin_read16(IMDMA_S1_CONFIG)
#define bfin_write_IMDMA_S1_CONFIG(val)      bfin_write16(IMDMA_S1_CONFIG,val)
#define pIMDMA_S1_NEXT_DESC_PTR (volatile void **)IMDMA_S1_NEXT_DESC_PTR
#define bfin_read_IMDMA_S1_NEXT_DESC_PTR()   bfin_read32(IMDMA_S1_NEXT_DESC_PTR)
#define bfin_write_IMDMA_S1_NEXT_DESC_PTR(val) bfin_write32(IMDMA_S1_NEXT_DESC_PTR,val)
#define pIMDMA_S1_START_ADDR (volatile void **)IMDMA_S1_START_ADDR
#define bfin_read_IMDMA_S1_START_ADDR()      bfin_read32(IMDMA_S1_START_ADDR)
#define bfin_write_IMDMA_S1_START_ADDR(val)  bfin_write32(IMDMA_S1_START_ADDR,val)
#define pIMDMA_S1_X_COUNT (volatile unsigned short *)IMDMA_S1_X_COUNT
#define bfin_read_IMDMA_S1_X_COUNT()         bfin_read16(IMDMA_S1_X_COUNT)
#define bfin_write_IMDMA_S1_X_COUNT(val)     bfin_write16(IMDMA_S1_X_COUNT,val)
#define pIMDMA_S1_Y_COUNT (volatile unsigned short *)IMDMA_S1_Y_COUNT
#define bfin_read_IMDMA_S1_Y_COUNT()         bfin_read16(IMDMA_S1_Y_COUNT)
#define bfin_write_IMDMA_S1_Y_COUNT(val)     bfin_write16(IMDMA_S1_Y_COUNT,val)
#define pIMDMA_S1_X_MODIFY (volatile signed short *)IMDMA_S1_X_MODIFY
#define bfin_read_IMDMA_S1_X_MODIFY()        bfin_read16(IMDMA_S1_X_MODIFY)
#define bfin_write_IMDMA_S1_X_MODIFY(val)    bfin_write16(IMDMA_S1_X_MODIFY,val)
#define pIMDMA_S1_Y_MODIFY (volatile signed short *)IMDMA_S1_Y_MODIFY
#define bfin_read_IMDMA_S1_Y_MODIFY()        bfin_read16(IMDMA_S1_Y_MODIFY)
#define bfin_write_IMDMA_S1_Y_MODIFY(val)    bfin_write16(IMDMA_S1_Y_MODIFY,val)
#define pIMDMA_S1_CURR_DESC_PTR (volatile void **)IMDMA_S1_CURR_DESC_PTR
#define bfin_read_IMDMA_S1_CURR_DESC_PTR()   bfin_read32(IMDMA_S1_CURR_DESC_PTR)
#define bfin_write_IMDMA_S1_CURR_DESC_PTR(val) bfin_write32(IMDMA_S1_CURR_DESC_PTR,val)
#define pIMDMA_S1_CURR_ADDR (volatile void **)IMDMA_S1_CURR_ADDR
#define bfin_read_IMDMA_S1_CURR_ADDR()       bfin_read32(IMDMA_S1_CURR_ADDR)
#define bfin_write_IMDMA_S1_CURR_ADDR(val)   bfin_write32(IMDMA_S1_CURR_ADDR,val)
#define pIMDMA_S1_CURR_X_COUNT (volatile unsigned short *)IMDMA_S1_CURR_X_COUNT
#define bfin_read_IMDMA_S1_CURR_X_COUNT()    bfin_read16(IMDMA_S1_CURR_X_COUNT)
#define bfin_write_IMDMA_S1_CURR_X_COUNT(val) bfin_write16(IMDMA_S1_CURR_X_COUNT,val)
#define pIMDMA_S1_CURR_Y_COUNT (volatile unsigned short *)IMDMA_S1_CURR_Y_COUNT
#define bfin_read_IMDMA_S1_CURR_Y_COUNT()    bfin_read16(IMDMA_S1_CURR_Y_COUNT)
#define bfin_write_IMDMA_S1_CURR_Y_COUNT(val) bfin_write16(IMDMA_S1_CURR_Y_COUNT,val)
#define pIMDMA_S1_IRQ_STATUS (volatile unsigned short *)IMDMA_S1_IRQ_STATUS
#define bfin_read_IMDMA_S1_IRQ_STATUS()      bfin_read16(IMDMA_S1_IRQ_STATUS)
#define bfin_write_IMDMA_S1_IRQ_STATUS(val)  bfin_write16(IMDMA_S1_IRQ_STATUS,val)

#define pMDMA_S0_CONFIG		pMDMA1_S0_CONFIG
#define PMDMA_S0_IRQ_STATUS	pMDMA1_S0_IRQ_STATUS
#define pMDMA_S0_X_MODIFY	pMDMA1_S0_X_MODIFY
#define pMDMA_S0_Y_MODIFY	pMDMA1_S0_Y_MODIFY
#define pMDMA_S0_X_COUNT	pMDMA1_S0_X_COUNT
#define pMDMA_S0_Y_COUNT	pMDMA1_S0_Y_COUNT
#define pMDMA_S0_START_ADDR	pMDMA1_S0_START_ADDR
#define pMDMA_D0_CONFIG		pMDMA1_D0_CONFIG
#define pMDMA_D0_IRQ_STATUS	pMDMA1_D0_IRQ_STATUS
#define pMDMA_D0_X_MODIFY	pMDMA1_D0_X_MODIFY
#define pMDMA_D0_Y_MODIFY	pMDMA1_D0_Y_MODIFY
#define pMDMA_D0_X_COUNT	pMDMA1_D0_X_COUNT
#define pMDMA_D0_Y_COUNT	pMDMA1_D0_Y_COUNT
#define pMDMA_D0_START_ADDR	pMDMA1_D0_START_ADDR

#endif				/* _CDEF_BF561_H */
