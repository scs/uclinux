/* Copyright (C) 2003 Analog Devices, Inc. All Rights Reserved.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.
 *
 * Blackfin BF533/2.6 support : LG Soft India
 */

#include <asm/blackfin.h>
#include <asm/mach/irq.h>

#define ASSEMBLY 

.text

/******************************************** Watchdog Timer APIs **************************/

.global _unmask_wdog_wakeup_evt
_unmask_wdog_wakeup_evt:
	[--SP] = ( R7:0, P5:0 );
	
	P0.h = (SIC_IWR >> 16);
	P0.l = (SIC_IWR & 0xFFFF);
	R7 = [P0];
	BITSET(R7,(IRQ_WATCH - IVG7));
	[P0] = R7;
	SSYNC;

	( R7:0, P5:0 ) = [SP++];	
	RTS;

WRITE_TO_STAT:
	/* When watch dog timer is enabled, a write to STAT will load the contents of CNT to STAT */
	R7 = 0x0000(z);
	P0.h = (WDOG_STAT >> 16);
	P0.l = (WDOG_STAT & 0xFFFF);
	[P0] = R7;
	SSYNC;
	JUMP SKIP_WRITE_TO_STAT;

.global _program_wdog_timer
_program_wdog_timer:	
	[--SP] = ( R7:0, P5:0 );

	P0.h = (WDOG_CNT >> 16);
	P0.l = (WDOG_CNT & 0xFFFF);
	[P0] = R0;
	SSYNC;

	P0.h = (WDOG_CTL >> 16);
	P0.l = (WDOG_CTL & 0xFFFF);
	R7 = W[P0](Z);
	CC = BITTST(R7,1);
	if !CC JUMP WRITE_TO_STAT;
	CC = BITTST(R7,2);
	if !CC JUMP WRITE_TO_STAT;

SKIP_WRITE_TO_STAT:
	P0.h = (WDOG_CTL >> 16);
        P0.l = (WDOG_CTL & 0xFFFF);
        R7 = W[P0](Z);
        BITCLR(R7,1);	/* Enable GP event */
        BITSET(R7,2);
        W[P0] = R7.L;
        SSYNC;
        NOP;

        R7 = W[P0](Z);
        BITCLR(R7,4);	/* Enable the wdog counter */
        W[P0] = R7.L;
        SSYNC;
	
	( R7:0, P5:0 ) = [SP++];
	RTS;

.global _clear_wdog_wakeup_evt
_clear_wdog_wakeup_evt:
	[--SP] = ( R7:0, P5:0 );

	P0.h = (WDOG_CTL >> 16);
	P0.l = (WDOG_CTL & 0xFFFF);
	R7 = 0x0AD6(Z);
	W[P0] = R7.L;
	SSYNC;

	R7 = W[P0](Z);
	BITSET(R7,15);
	W[P0] = R7.L;
	SSYNC;

	R7 = W[P0](Z);
	BITSET(R7,1);
	BITSET(R7,2);
	W[P0] = R7.L;
	SSYNC;

	( R7:0, P5:0 ) = [SP++];
	RTS;

.global _disable_wdog_timer
_disable_wdog_timer:
	[--SP] = ( R7:0, P5:0 );
	P0.h = (WDOG_CTL >> 16);
	P0.l = (WDOG_CTL & 0xFFFF);
	R7 = 0xAD6(Z);
	W[P0] = R7.L;
	SSYNC;
	( R7:0, P5:0 ) = [SP++];
	RTS;

.global _sleep_mode
_sleep_mode:
	[--SP] = ( R7:0, P5:0 );

        P0.H = hi(SIC_IWR);
        P0.L = lo(SIC_IWR);
	R0 = IWR_ENABLE(IRQ_RTC - IVG7)(Z);
        [P0] = R0;
        SSYNC;

        P0.H = hi(RTC_ISTAT);
        P0.L = lo(RTC_ISTAT);
        R0 = (SWEF|AEF|SEF|MEF|HEF|DEF|DAEF|WCOM)(Z);	/* Clear all the interrupts,bits sticky */
        w[P0] = R0.L;
        SSYNC;        

	P0.H = hi(PLL_CTL);
        P0.L = lo(PLL_CTL);
        R1 = W[P0](z);
        BITSET (R1, 3);
	W[P0] = R1.L;

        CLI R2;
        SSYNC;
        IDLE;
        STI R2;

CHECK_AGAIN1:
	P1.H = hi(PLL_STAT);
	P1.L = lo(PLL_STAT);
	R5 = W[P1] (Z);
	CC = BITTST(R5,5);
	IF !CC JUMP CHECK_AGAIN1;
	
	P0.H = hi(PLL_CTL);
	P0.L = lo(PLL_CTL);
	R7 = w[p0](z);
	BITCLR (R7, 3);
	BITCLR (R7, 5);
	w[p0] = R7.L;
	IDLE;

        ( R7:0, P5:0 ) = [SP++];
        RTS;

.global _deep_sleep
_deep_sleep:
	[--SP] = ( R7:0, P5:0 );

        P0.H = hi(SIC_IWR);
        P0.L = lo(SIC_IWR);
	R0 = IWR_ENABLE(IRQ_RTC - IVG7)(Z);
        [P0] = R0;
        SSYNC;

        P0.H = hi(RTC_ISTAT);
        P0.L = lo(RTC_ISTAT);
        R0 = (SWEF|AEF|SEF|MEF|HEF|DEF|DAEF|WCOM)(Z);	/* Clear all the interrupts,bits sticky */
        w[P0] = R0;
        SSYNC;        
        
        P0.H = hi(PLL_CTL);
        P0.L = lo(PLL_CTL);
        R1 = W[P0](z);
        BITSET (R1, 5);
       	W[P0] = R1.L;

        CLI R2;
        SSYNC;
        IDLE;
        STI R2;

CHECK_AGAIN2:
	P1.H = hi(PLL_STAT);
	P1.L = lo(PLL_STAT);
	R5 = W[P1] (Z);
	CC = BITTST(R5,5);
	IF !CC JUMP CHECK_AGAIN2;

	P0.H = hi(PLL_CTL);
	P0.L = lo(PLL_CTL);
	R7 = w[p0](z);
	BITCLR (R7, 3);
	BITCLR (R7, 5);
	w[p0] = R7;
	IDLE;

        ( R7:0, P5:0 ) = [SP++];
        RTS;

.global _hibernate_mode
_hibernate_mode:
	[--SP] = ( R7:0, P5:0 );
	
 	P0.H = hi(SIC_IWR);
        P0.L = lo(SIC_IWR);
	R0 = IWR_ENABLE(IRQ_RTC - IVG7)(Z);
        [P0] = R0;
        SSYNC;
        
        P0.H = hi(RTC_ISTAT);
        P0.L = lo(RTC_ISTAT);
        R0 = (SWEF|AEF|SEF|MEF|HEF|DEF|DAEF|WCOM)(Z);	/* Clear all the interrupts,bits sticky */
        w[P0] = R0;
        SSYNC;        

	P0.H = hi(VR_CTL);
        P0.L = lo(VR_CTL);
        R1 = W[P0](z);
        BITSET (R1, 8);
	BITCLR (R1, 0);
	BITCLR (R1, 1);
	W[P0] = R1.L;
	SSYNC;
	
        CLI R2;
        IDLE;

	/* Actually, adding anything may not be necessary...SDRAM contents are lost */

	STI R2;

	P0.H = hi(VR_CTL);
        P0.L = lo(VR_CTL);
        R1 = W[P0](z);
        BITCLR (R1, 8);
        BITSET (R1, 0);
        BITSET (R1, 1);
        W[P0] = R1.L;
        SSYNC;
	
	IDLE;

        ( R7:0, P5:0 ) = [SP++];
        RTS;
