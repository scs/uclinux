/* Copyright (C) 2003 Analog Devices, Inc. All Rights Reserved.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.
 *
 * Blackfin BF533/2.6 support : LG Soft India
 */

/* Dynamic Power Management support routines
 */

#include <linux/config.h>
#include <asm/blackfin.h>

.text

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
	P0.h = PLL_CTL >> 16;
	P0.l = PLL_CTL & 0xFFFF;
	R7 = w[P0](z);
	BITSET(R7,8);
	w[P0] = R7;
	SSYNC;
	R7 = [SP++];
	RTS;

.global pll_bypass_off
pll_bypass_off:
	[--SP] = R7;
	P0.h = PLL_CTL >> 16;
	P0.l = PLL_CTL & 0xFFFF;
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
	P0.h = PLL_CTL >> 16;
	P0.l = PLL_CTL & 0xFFFF;
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
	P0.h = PLL_CTL >> 16;
	P0.l = PLL_CTL & 0xFFFF;
	CC = R0 == 1;
	if !CC JUMP set1;
	R7 = w[P0](z);
	BITCLR(R7,3);
	w[P0] = R7;
	SSYNC;
	jump finish1;
set1:
	R7 = [P0](z);
	BITSET(R7,3);
	w[P0] = R7;
	SSYNC;
finish1:
	R7 = [SP++];
	RTS;

.global set_clr_pdwn
set_clr_pdwn:
	[--SP] = R7;
	P0.h = PLL_CTL >> 16;
	P0.l = PLL_CTL & 0xFFFF;
	CC = R0 == 1;
	if !CC JUMP on;
	R7 = w[P0](z);
	BITCLR(R7,5);
	w[P0] = R7;
	SSYNC;
	jump finish2;
on:
	R7 = [P0];
	BITSET(R7,5);
	[P0] = R7;
	SSYNC;
finish2:
	R7 = [SP++];
	RTS;

.global set_clr_plloff
set_clr_plloff:
	[--SP] = R7;
	P0.h = PLL_CTL >> 16;
	P0.l = PLL_CTL & 0xFFFF;
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
	[P0] = R7;
	SSYNC;
finish3:
	R7 = [SP++];
	RTS;

.global transit_sleep_mode
transit_sleep_mode:
	[--SP] = ( R7:4, P5:5 );
	
	P0.h = (SIC_IWR >> 16);
	P0.l = (SIC_IWR & 0xFFFF);
	R7 = [P0];
	bitset(r7,0);
	[P0] = R7;
	SSYNC;
	
	R7 = 0xF000(z);
	P0.h = (WDOG_CNT >> 16);
	P0.l = (WDOG_CNT & 0xFFFF);
	[P0] = R7;
	SSYNC;

	R7 = 0x0f14(z);
	P0.h = (WDOG_CTL >> 16);
	P0.l = (WDOG_CTL & 0xFFFF);
	W[P0] = R7;
	SSYNC;

	P0.h = (PLL_CTL >> 16);
	P0.l = (PLL_CTL & 0xFFFF);
	R5 = W[P0](z);
	BITSET(R5,3);
	w[P0] = R5;

	CLI R7;
	SSYNC;
	IDLE;
	STI R7;

	R7 = 0x8006;
	P0.h = (WDOG_CTL >> 16);
	P0.l = (WDOG_CTL & 0xFFFF);
	W[P0] = R7;
	SSYNC;
	R7 = [SP++];

	( R7:4, P5:5 ) = [SP++];	
	RTS;
