/* Copyright (C) 2003 Analog Devices, Inc. All Rights Reserved.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.
 *
 * Blackfin BF533/2.6 support : LG Soft India
 */

#include <asm/board/defBF532.h>

.text

/***************************Operating Modes***************************/

.global sleep_mode
sleep_mode:
	[--SP] = ( R7:0, P5:0 );

	P0.H = hi(EVT8);
	P0.L = lo(EVT8);
	R0.l = RTC_Int;
	R0.h = RTC_Int;
	[P0] = R0;
	SSYNC;	
		
        P0.H = 0xffc0;
        P0.L = 0x0124;
        R0 = [P0];
        BITSET(R0,7);
        [P0] = R0;
        SSYNC;

        P0.H = 0xffc0 ;
        P0.L = 0x0314;
        R0 = 1(Z);
        w[P0] = R0;
        SSYNC;

        R0 = 0x8000(z);
        P0.L = 0x0308;
Poll_WC13:
        R1 = w[P0](z);
        R1 = R1 & R0;
        CC = AZ;
        IF CC JUMP Poll_WC13;
        
        P0.L = 0x030C;
        R1 = 0x10(z);
        w[P0] = R1.L;
        SSYNC;
        
        P0.H = 0xffc0 ;
        P0.L = 0x0308;
        R0 = 0x807F(Z);
        w[P0] = R0;
        SSYNC;        
        
        P0.L = 0x0304;
        R1 = 1;
        w[P0] = R1.L;
        SSYNC;

        P0.L = 0x0308;
Poll_WC11:
        R1 = w[P0](z);
        R1 = R1 & R0;
        CC = AZ;
        IF CC JUMP Poll_WC11;

	P0.H = hi(PLL_LOCKCNT);
	P0.L = lo(PLL_LOCKCNT);
	R0 = 0x300 (Z);
	W[P0] = R0.L;
	SSYNC;

	P0.H = 0xffc0;
        P0.L = 0x0000;
        R1 = W[P0](z);
        BITSET (R1, 3);

        P2.H = 0xffc0;
        P2.L = 0x010c;
        R0 = [P2];
        BITSET (R0, 7);
        [P2] = R0;
        SSYNC;

        P2.H = 0xffe0;
        P2.L = 0x2104;
        R0 = [P2];
        BITSET (R0, 8);
        [P2] = R0;
        CSYNC;

	W[P0] = R1.L;

        CLI R2;
        SSYNC;
        IDLE;
        STI R2;

CHECK_AGAIN3:
	P1.H = hi(PLL_STAT);
	P1.L = lo(PLL_STAT);
	R5 = W[P1] (Z);
	CC = BITTST(R5,5);
	IF !CC JUMP CHECK_AGAIN3;
        ( R7:0, P5:0 ) = [SP++];
        RTS;
        
.global RTC_Int
RTC_Int:
	[--SP] = ( R7:0, P5:0 );
	
	P0.H = hi(PLL_CTL);
	P0.L = lo(PLL_CTL);
	R7 = w[p0](z);
	BITCLR (R7, 3);
	BITCLR (R7, 5);
	w[p0] = R7;
	IDLE;

	P0.H = 0xffc0 ;
        P0.L = 0x0308;
        R0 = 0x807F(Z);
        w[P0] = R0;
        SSYNC;        
        
        P0.L = 0x0304;
        R1 = 0;
        w[P0] = R1.L;
        SSYNC;

        P0.L = 0x0308;
Poll_WC110:
        R1 = w[P0](z);
        R1 = R1 & R0;
        CC = AZ;
        IF CC JUMP Poll_WC110;
	( R7:0, P5:0 ) = [SP++];
	RTI;

.global active_mode
active_mode:
	[--SP] = ( R7:0, P5:0 );

	P0.H = hi(SIC_IWR);
	P0.L = lo(SIC_IWR);
	R0 = [P0];
	BITSET (R0, 0);
	/* BITSET (R0, 23); */
	[P0] = R0;
	SSYNC;
#if 0
	/* Program the watchdog timer */
	P0.H = hi(WDOG_CTL);
	P0.L = lo(WDOG_CTL);
	R0 = 0xAD6;
	W[P0] = R0;
	SSYNC;

	P0.H = hi(WDOG_CNT);
	P0.L = lo(WDOG_CNT);
	R0.H = 0x0000;
	R0.L = 0x1000;
	[P0] = R0;
	SSYNC;

	P0.H = hi(WDOG_CTL);
	P0.L = lo(WDOG_CTL);
	R0 = 0xAA4;
	W[P0] = R0;
	SSYNC;
#endif

	P1.H = hi(PLL_LOCKCNT);
	P1.L = lo(PLL_LOCKCNT);
	R1 = 0x300 (Z);
	W[P1] = R1.L;
	SSYNC;

	SSYNC;
	P2.H = hi(EBIU_SDGCTL);
	P2.L = lo(EBIU_SDGCTL);
	R0 = [P2];
	BITSET (R0, 24);
	[P2] = R0;
	SSYNC;

	P1.H = hi(PLL_CTL);
	P1.L = lo(PLL_CTL);
	R1 = W[P1](z);
	BITSET (R1, 8);
	W[P1] = R1.L;
	
	CLI r2;
	SSYNC;
	IDLE;
	STI r2;

CHECK_AGAIN:
	P1.H = hi(PLL_STAT);
	P1.L = lo(PLL_STAT);
	R1 = W[P1] (Z);
	CC = BITTST(R1,5);
	IF !CC JUMP CHECK_AGAIN;

	P2.H = hi(EBIU_SDRRC);
	P2.L = lo(EBIU_SDRRC);
#if CONFIG_EZKIT
	R0 = 0x1A3 (Z);		/* NRA taken as 4096 */
#endif
#if CONFIG_BLKFIN_STAMP
	R0 = 0xA9 (Z);		
#endif
	W[P2] = R0;
	SSYNC;

	P2.H = hi(EBIU_SDGCTL);
	P2.L = lo(EBIU_SDGCTL);
	R0 = [P2];
	BITCLR (R0, 24);
	[P2] = R0;
	SSYNC;

#if 0
	R7 = 0x8006;
	P0.h = (WDOG_CTL >> 16);
	P0.l = (WDOG_CTL & 0xFFFF);
	W[P0] = R7;
	SSYNC;
#endif
	( R7:0, P5:0 ) = [SP++];
	rts;

.global deep_sleep
deep_sleep:
	[--SP] = ( R7:0, P5:0 );

	P0.H = hi(EVT8);
	P0.L = lo(EVT8);
	R0.l = RTC_Int;
	R0.h = RTC_Int;
	[P0] = R0;
	SSYNC;	
		
        P0.H = 0xffc0;
        P0.L = 0x0124;
        R0 = [P0];
        BITSET(R0,7);
        [P0] = R0;
        SSYNC;

        P0.H = 0xffc0 ;
        P0.L = 0x0314;
        R0 = 1(Z);
        w[P0] = R0;
        SSYNC;

        R0 = 0x8000(z);
        P0.L = 0x0308;
Poll_WC131:
        R1 = w[P0](z);
        R1 = R1 & R0;
        CC = AZ;
        IF CC JUMP Poll_WC131;
        
        P0.L = 0x030C;
        R1 = 0x32(z);
        w[P0] = R1.L;
        SSYNC;
        
        P0.H = 0xffc0 ;
        P0.L = 0x0308;
        R0 = 0x807F(Z);
        w[P0] = R0;
        SSYNC;        
        
        P0.L = 0x0304;
        R1 = 1;
        w[P0] = R1.L;
        SSYNC;

        P0.L = 0x0308;
Poll_WC112:
        R1 = w[P0](z);
        R1 = R1 & R0;
        CC = AZ;
        IF CC JUMP Poll_WC112;

	P0.H = hi(PLL_LOCKCNT);
	P0.L = lo(PLL_LOCKCNT);
	R0 = 0x300 (Z);
	W[P0] = R0.L;
	SSYNC;

	P0.H = 0xffc0;
        P0.L = 0x0000;
        R1 = W[P0](z);
        BITSET (R1, 5);

        P2.H = 0xffc0;
        P2.L = 0x010c;
        R0 = [P2];
        BITSET (R0, 7);
        [P2] = R0;
        SSYNC;

        P2.H = 0xffe0;
        P2.L = 0x2104;
        R0 = [P2];
        BITSET (R0, 8);
        [P2] = R0;
        CSYNC;

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

        ( R7:0, P5:0 ) = [SP++];
        RTS;

.global fullon_mode
fullon_mode:
	[--SP] = ( R7:0, P5:0 );
	
	P0.H = hi(SIC_IWR);
	P0.L = lo(SIC_IWR);
	R0 = [P0];
	BITSET (R0, 0);
	/* BITSET (R0, 23); */
	[P0] = R0;
	SSYNC;

#if 0
	/* Program the watchdog timer */
	P0.H = hi(WDOG_CTL);
	P0.L = lo(WDOG_CTL);
	R0 = 0xAD6;
	W[P0] = R0;
	SSYNC;

	P0.H = hi(WDOG_CNT);
	P0.L = lo(WDOG_CNT);
	R0.H = 0x0000;
	R0.L = 0x1000;
	[P0] = R0;
	SSYNC;

	P0.H = hi(WDOG_CTL);
	P0.L = lo(WDOG_CTL);
	R0 = 0xAA4;
	W[P0] = R0;
	SSYNC;
#endif

	P1.H = hi(PLL_LOCKCNT);
	P1.L = lo(PLL_LOCKCNT);
	R1 = 0x300 (Z);
	W[P1] = R1.L;
	SSYNC;

	SSYNC;
	P2.H = hi(EBIU_SDGCTL);
	P2.L = lo(EBIU_SDGCTL);
	R0 = [P2];
	BITSET (R0, 24);
	[P2] = R0;
	SSYNC;

	P1.H = hi(PLL_CTL);
	P1.L = lo(PLL_CTL);
	R1 = W[P1](z);
	BITCLR (R1, 8);
	BITCLR (R1, 5);
	BITCLR (R1, 3);
	W[P1] = R1.L;
	
	CLI r2;
	SSYNC;
	IDLE;
	STI r2;

CHECK_AGAIN44:
	P1.H = hi(PLL_STAT);
	P1.L = lo(PLL_STAT);
	R1 = W[P1] (Z);
	CC = BITTST(R1,5);
	IF !CC JUMP CHECK_AGAIN44;

	P2.H = hi(EBIU_SDRRC);
	P2.L = lo(EBIU_SDRRC);
#if CONFIG_EZKIT
	R0 = 0x817 (Z);
#endif
#if CONFIG_BLKFIN_STAMP
	R0 = 0x305 (Z);
#endif
	W[P2] = R0;
	SSYNC;

	P2.H = hi(EBIU_SDGCTL);
	P2.L = lo(EBIU_SDGCTL);
	R0 = [P2];
	BITCLR (R0, 24);
	[P2] = R0;
	SSYNC;
#if 0
	R7 = 0x8006;
	P0.h = (WDOG_CTL >> 16);
	P0.l = (WDOG_CTL & 0xFFFF);
	W[P0] = R7;
	SSYNC;
#endif
	( R7:4, P5:5 ) = [SP++];

	rts;

.global hibernate_mode
hibernate_mode:
	[--SP] = ( R7:0, P5:0 );
	
	P0.H = hi(EVT8);
	P0.L = lo(EVT8);
	R0.l = RTC_Int;
	R0.h = RTC_Int;
	[P0] = R0;
	SSYNC;	
		
        P0.H = 0xffc0;
        P0.L = 0x0124;
        R0 = [P0];
        BITSET(R0,7);
        [P0] = R0;
        SSYNC;

        P0.H = 0xffc0 ;
        P0.L = 0x0314;
        R0 = 1(Z);
        w[P0] = R0;
        SSYNC;

        R0 = 0x8000(z);
        P0.L = 0x0308;
Poll_WC132:
        R1 = w[P0](z);
        R1 = R1 & R0;
        CC = AZ;
        IF CC JUMP Poll_WC132;
        
        P0.L = 0x030C;
        R1 = 0x32(z);
        w[P0] = R1.L;
        SSYNC;
        
        P0.H = 0xffc0 ;
        P0.L = 0x0308;
        R0 = 0x807F(Z);
        w[P0] = R0;
        SSYNC;        
        
        P0.L = 0x0304;
        R1 = 1;
        w[P0] = R1.L;
        SSYNC;

        P0.L = 0x0308;
Poll_WC112q:
        R1 = w[P0](z);
        R1 = R1 & R0;
        CC = AZ;
        IF CC JUMP Poll_WC112q;

	P0.H = hi(PLL_LOCKCNT);
	P0.L = lo(PLL_LOCKCNT);
	R0 = 0x300 (Z);
	W[P0] = R0.L;
	SSYNC;

	P0.H = 0xffc0;
        P0.L = 0x0008;
        R1 = W[P0](z);
        BITSET (R1, 8);
	BITSET (R1, 0);
	BITSET (R1, 1);

        P2.H = 0xffc0;
        P2.L = 0x010c;
        R0 = [P2];
        BITSET (R0, 7);
        [P2] = R0;
        SSYNC;

        P2.H = 0xffe0;
        P2.L = 0x2104;
        R0 = [P2];
        BITSET (R0, 8);
        [P2] = R0;
        CSYNC;

	W[P0] = R1.L;
	
        CLI R2;
        SSYNC;
        IDLE;
        STI R2;

        ( R7:0, P5:0 ) = [SP++];
        RTS;

/*******************************************************************************************/

#if 0
.global pll_seq_trans
pll_seq_trans:
	[--SP] = ( R7:4, P5:5 );
	CLI R7;
	IDLE;
	SSYNC;
	STI R7;
	( R7:4, P5:5 ) = [SP++];	
	RTS;

.global unmask_wdog_wakeup_evt
unmask_wdog_wakeup_evt:
	[--SP] = ( R7:4, P5:5 );
	R7.l = 0x0;
	R7.h = 0x10;
	P0.h = (SIC_IWR >> 16);
	P0.l = (SIC_IWR & 0xFFFF);
	R5 = [P0];
	R5 = R5 | R7;
	[P0] = R7;
	SSYNC;
	( R7:4, P5:5 ) = [SP++];	
	RTS;

.global program_wdog_timer
program_wdog_timer:	
	[--SP] = ( R7:4, P5:5 );
	R7 = 0x1000(z);
	P0.h = (WDOG_CNT >> 16);
	P0.l = (WDOG_CNT & 0xFFFF);
	[P0] = R7;
	SSYNC;

	R7 = 0x0000(z);
	P0.h = (WDOG_STAT >> 16);
	P0.l = (WDOG_STAT & 0xFFFF);
	[P0] = R7;
	SSYNC;
	
	R7 = 0x0004(z);
	P0.h = (WDOG_CTL >> 16);
	P0.l = (WDOG_CTL & 0xFFFF);
	W[P0] = R7;
	SSYNC;

	( R7:4, P5:5 ) = [SP++];	
	RTS;

.global pll_bypass_on
pll_bypass_on:
	[--SP] = R7;
	P0.h = (PLL_CTL >> 16);
	P0.l = (PLL_CTL & 0xFFFF);
	R7 = w[P0](z);
	BITSET(R7,8);
	w[P0] = R7;
	SSYNC;
	
.global pll_bypass_off
pll_bypass_off:
	[--SP] = R7;
	P0.h = (PLL_CTL >> 16);
	P0.l = (PLL_CTL & 0xFFFF);
	R7 = w[P0](z);
	BITCLR(R7,8);
	w[P0] = R7;
	SSYNC;
	R7 = [SP++];
	RTS;

.global clear_wdog_wakeup_evt
clear_wdog_wakeup_evt:
	[--SP] = R7;
	R7 = 0x8006;
	P0.h = (WDOG_CTL >> 16);
	P0.l = (WDOG_CTL & 0xFFFF);
	W[P0] = R7;
	SSYNC;
	R7 = [SP++];
	RTS;

.global set_pll_ctl
set_pll_ctl:
	[--SP] = R7; 
	P0.h = (PLL_CTL >> 16);
	P0.l = (PLL_CTL & 0xFFFF);
	R7 = w[P0](z);
	R0 = R0 << 8 (S) ;
	R0 = R0 | R7;
	w[P0] = R0;
	SSYNC;
	R7 = [SP++];
	RTS;

.global set_vr_ctl
set_vr_ctl:
	[--SP] = R7;
	P0.h = (VR_CTL >> 16);
	P0.l = (VR_CTL & 0xFFFF);
	R7 = [P0];
	R0 = R0 << 4 (S);
	R0 = R0 | R7;
	W[P0] = R0;
	SSYNC;
	R7 = [SP++];
	RTS;

.global set_clr_stopck
set_clr_stopck:
	[--SP] = R7;
	P0.h = (PLL_CTL >> 16);
	P0.l = (PLL_CTL & 0xFFFF);
	CC = R0 == 1;
	if !CC JUMP set1;
	R7 = w[P0](z);
	BITCLR(R7,3);
	w[P0] = R7;
	SSYNC;
	jump finish1;
set1:
	R7 = w[P0](z);
	BITSET(R7,3);
	w[P0] = R7;
	SSYNC;
finish1:
	R7 = [SP++];
	RTS;

.global set_clr_pdwn
set_clr_pdwn:
	[--SP] = R7;
	P0.h = (PLL_CTL >> 16);
	P0.l = (PLL_CTL & 0xFFFF);
	CC = R0 == 1;
	if !CC JUMP on;
	R7 = w[P0](z);
	BITCLR(R7,5);
	w[P0] = R7;
	SSYNC;
	jump finish2;
on:
	R7 = w[P0](z);
	BITSET(R7,5);
	w[P0] = R7;
	SSYNC;
finish2:
	R7 = [SP++];
	RTS;

.global set_clr_plloff
set_clr_plloff:
	[--SP] = R7;
	P0.h = (PLL_CTL >> 16);
	P0.l = (PLL_CTL & 0xFFFF);
	CC = R0 == 1;
	if !CC JUMP set2;
	R7 = w[P0](z);
	BITCLR(R7,1);
	w[P0] = R7;
	SSYNC;
	jump finish3;
set2:
	R7 = w[P0](z);
	BITSET(R7,1);
	w[P0] = R7;
	SSYNC;
finish3:
	R7 = [SP++];
	RTS;
#endif
