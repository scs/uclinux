/* Copyright (C) 2003 Analog Devices, Inc. All Rights Reserved.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.
 *
 * Blackfin BF533/2.6 support : LG Soft India
 */

#include <asm/board/defBF532.h>

.text

/******************************************** Watchdog Timer APIs **************************/

.global unmask_wdog_wakeup_evt
unmask_wdog_wakeup_evt:
	[--SP] = ( R7:0, P5:0 );
	
	P0.h = (SIC_IWR >> 16);
	P0.l = (SIC_IWR & 0xFFFF);
	R7 = [P0];
	BITSET(R7,23);
	[P0] = R7;
	SSYNC;
	
	P0.h = (SIC_IMASK >> 16);
	P0.l = (SIC_IMASK & 0xFFFF);
	R7 = [P0];
	BITSET(R7,23);
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

.global program_wdog_timer
program_wdog_timer:	
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

.global clear_wdog_wakeup_evt
clear_wdog_wakeup_evt:
	[--SP] = R7;
	[--SP] = P0;
	
	P0.h = (WDOG_CTL >> 16);
	P0.l = (WDOG_CTL & 0xFFFF);
	R7 = W[P0](Z);
	BITSET(R7,15);
	W[P0] = R7.L;
	SSYNC;		/* But this sticky bit does not clear.... */
	P0 = [SP++];
	R7 = [SP++];
	RTS;

.global disable_wdog_timer
disable_wdog_timer:
	[--SP] = R7;
	[--SP] = P0;
	R7 = 0xAD6;
	P0.h = (WDOG_CTL >> 16);
	P0.l = (WDOG_CTL & 0xFFFF);
	W[P0] = R7.L;
	SSYNC;
	P0 = [SP++];
	R7 = [SP++];
	RTS;

.global sleep_mode
sleep_mode:
	[--SP] = ( R7:0, P5:0 );

        P0.H = hi(SIC_IWR);
        P0.L = lo(SIC_IWR);
        R0 = [P0];
        BITSET(R0,7);
        [P0] = R0;
        SSYNC;

        P0.H = hi(RTC_PREN);
        P0.L = lo(RTC_PREN);
        R0 = PREN(Z);
        w[P0] = R0.L;
        SSYNC;

        P0.H = hi(RTC_ISTAT);
        P0.L = lo(RTC_ISTAT);
        R0 = (SWEF|AEF|SEF|MEF|HEF|DEF|DAEF|WCOM)(Z);	/* Clear all the interrupts,bits sticky */
        w[P0] = R0.L;
        SSYNC;        
        
        P0.H = hi(RTC_ICTL);
        P0.L = lo(RTC_ICTL);
        R1 = 1;
        w[P0] = R1.L;
        SSYNC;

        P0.H = hi(RTC_ISTAT);
        P0.L = lo(RTC_ISTAT);
Poll_WC2:
	nop;
	nop;
        R1 = w[P0](z);
        R1 = R1 & R0;
        CC = AZ;
        IF CC JUMP Poll_WC2;

	nop;
	nop;	
	r0 = w[p0](z);
	bitset(r0,15);
	w[p0] = r0.l;
	ssync;

	P0.H = hi(PLL_LOCKCNT);
	P0.L = lo(PLL_LOCKCNT);
	R0 = 0x300 (Z);
	W[P0] = R0.L;
	SSYNC;

	P0.H = hi(PLL_CTL);
        P0.L = lo(PLL_CTL);
        R1 = W[P0](z);
        BITSET (R1, 3);

        P2.H = hi(SIC_IMASK);
        P2.L = lo(SIC_IMASK);
        R0 = [P2];
        BITSET (R0, 7);
        [P2] = R0;
        SSYNC;

        P2.H = hi(IMASK);
        P2.L = lo(IMASK);
        R0 = [P2];
        BITSET (R0, 8);
        [P2] = R0;
        CSYNC;

	W[P0] = R1.L;
	SSYNC;

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

.global deep_sleep
deep_sleep:
	[--SP] = ( R7:0, P5:0 );

        P0.H = hi(SIC_IWR);
        P0.L = lo(SIC_IWR);
        R0 = [P0];
        BITSET(R0,7);
        [P0] = R0;
        SSYNC;

        P0.H = hi(RTC_PREN);
        P0.L = lo(RTC_PREN);
        R0 = PREN(Z);
        w[P0] = R0.L;
        SSYNC;

        R0 = WCOM(z);
        P0.L = hi(RTC_ISTAT);
        P0.L = lo(RTC_ISTAT);
Poll_WC4:
        R1 = w[P0](z);
        R1 = R1 & R0;
        CC = AZ;
        IF CC JUMP Poll_WC4;
        nop;
	nop;	
	r0 = w[p0](z);
	bitset(r0,15);
	w[p0] = r0.l;
	ssync;

        P0.H = hi(RTC_ISTAT);
        P0.L = lo(RTC_ISTAT);
        R0 = (SWEF|AEF|SEF|MEF|HEF|DEF|DAEF|WCOM)(Z);	/* Clear all the interrupts,bits sticky */
        w[P0] = R0;
        SSYNC;        
        
        P0.H = hi(RTC_ICTL);
        P0.L = lo(RTC_ICTL);
        R1 = 1;
        w[P0] = R1.L;
        SSYNC;

        P0.H = hi(RTC_ISTAT);
        P0.L = lo(RTC_ISTAT);
Poll_WC5:
        R1 = w[P0](z);
        R1 = R1 & R0;
        CC = AZ;
        IF CC JUMP Poll_WC5;
	
	nop;
	nop;	
	r0 = w[p0](z);
	bitset(r0,15);
	w[p0] = r0.l;
	ssync;

	P0.H = hi(PLL_LOCKCNT);
	P0.L = lo(PLL_LOCKCNT);
	R0 = 0x300 (Z);
	W[P0] = R0.L;
	SSYNC;

	P0.H = hi(PLL_CTL);
        P0.L = lo(PLL_CTL);
        R1 = W[P0](z);
        BITSET (R1, 5);

        P2.H = hi(SIC_IMASK);
        P2.L = lo(SIC_IMASK);
        R0 = [P2];
        BITSET (R0, 7);
        [P2] = R0;
        SSYNC;

        P2.H = hi(IMASK);
        P2.L = lo(IMASK);
        R0 = [P2];
        BITSET (R0, 8);
        [P2] = R0;
        CSYNC;

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

.global hibernate_mode
hibernate_mode:
	[--SP] = ( R7:0, P5:0 );
	
 	P0.H = hi(SIC_IWR);
        P0.L = lo(SIC_IWR);
        R0 = [P0];
        BITSET(R0,7);
        [P0] = R0;
        SSYNC;

        P0.H = hi(RTC_PREN);
        P0.L = lo(RTC_PREN);
        R0 = PREN(Z);
        w[P0] = R0.L;
        SSYNC;

        R0 = WCOM(z);
        P0.H = hi(RTC_ISTAT);
        P0.L = lo(RTC_ISTAT);
Poll_WC7:
        R1 = w[P0](z);
        R1 = R1 & R0;
        CC = AZ;
        IF CC JUMP Poll_WC7;
        nop;
	nop;	
	r0 = w[p0](z);
	bitset(r0,15);
	w[p0] = r0.l;
	ssync;

        P0.H = hi(RTC_ISTAT);
        P0.L = lo(RTC_ISTAT);
        R0 = (SWEF|AEF|SEF|MEF|HEF|DEF|DAEF|WCOM)(Z);	/* Clear all the interrupts,bits sticky */
        w[P0] = R0;
        SSYNC;        
        
        P0.H = hi(RTC_ICTL);
        P0.L = lo(RTC_ICTL);
        R1 = 1;
        w[P0] = R1.L;
        SSYNC;

        P0.H = hi(RTC_ISTAT);
        P0.L = lo(RTC_ISTAT);
Poll_WC8:
        R1 = w[P0](z);
        R1 = R1 & R0;
        CC = AZ;
        IF CC JUMP Poll_WC8;
        nop;
	nop;	
	r0 = w[p0](z);
	bitset(r0,15);
	w[p0] = r0.l;
	ssync;

	P0.H = hi(PLL_LOCKCNT);
	P0.L = lo(PLL_LOCKCNT);
	R0 = 0x300 (Z);
	W[P0] = R0.L;
	SSYNC;

	P0.H = hi(VR_CTL);
        P0.L = lo(VR_CTL);
        R1 = W[P0](z);
        BITSET (R1, 8);
	BITSET (R1, 0);
	BITSET (R1, 1);
	W[P0] = R1.L;
	
        CLI R2;
        SSYNC;
        IDLE;
        STI R2;

	/* Actually, adding anything may not be necessary...SDRAM contents are lost */

        ( R7:0, P5:0 ) = [SP++];
        RTS;

