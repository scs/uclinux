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
	R7.l = 0x0;
	R7.h = 0x10;
	P0.h = (SIC_IWR >> 16);
	P0.l = (SIC_IWR & 0xFFFF);
	R5 = [P0];
	R5 = R5 | R7;
	[P0] = R7;
	SSYNC;
	( R7:0, P5:0 ) = [SP++];	
	RTS;

WRITE_TO_STAT:
	/* When watch dog timer is enabled, a write to STAT will load the contents of CNT to STAT */
	[--SP] = ( R7:0, P5:0 );
	R7 = 0x0000(z);
	P0.h = (WDOG_STAT >> 16);
	P0.l = (WDOG_STAT & 0xFFFF);
	[P0] = R7;
	SSYNC;
	( R7:0, P5:0 ) = [SP++];	
	RTS;

.global program_wdog_timer
program_wdog_timer:	
	[--SP] = ( R7:0, P5:0 );
	R7 = 0x1000(z);
	P0.h = (WDOG_CNT >> 16);
	P0.l = (WDOG_CNT & 0xFFFF);
	[P0] = R7;
	SSYNC;

	P0.h = (WDOG_CTL >> 16);
	P0.l = (WDOG_CTL & 0xFFFF);
	R7 = W[P0](Z);
	CC = BITTST(R7,1);
	if !CC JUMP WRITE_TO_STAT;
	CC = BITTST(R7,2);
	if !CC JUMP WRITE_TO_STAT;

SKIP_WRITE_TO_STAT:
	R7 = 0x0004(z);	/* Enable gp events */
	P0.h = (WDOG_CTL >> 16);
	P0.l = (WDOG_CTL & 0xFFFF);
	W[P0] = R7;
	SSYNC;

	( R7:0, P5:0 ) = [SP++];	
	RTS;

.global clear_wdog_wakeup_evt
clear_wdog_wakeup_evt:
	[--SP] = R7;
	[--SP] = P0;
	R7 = 0x8006;
	P0.h = (WDOG_CTL >> 16);
	P0.l = (WDOG_CTL & 0xFFFF);
	W[P0] = R7;
	SSYNC;
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
	W[P0] = R7;
	SSYNC;
	P0 = [SP++];
	R7 = [SP++];
	RTS;
