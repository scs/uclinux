/* Copyright (C) 2003 Analog Devices, Inc. All Rights Reserved. 
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License. 
 *
 * Blackfin BF533/2.6 support : LG Soft India	
 */

/* This function can be called to invalidate instruction and data caches
 * when flushing is not required.
 */

#include <linux/linkage.h>
#include <asm/cplb.h>
#include <asm/entry.h>
#include <asm/blackfin.h>

.text
 
ENTRY(_cache_invalidate)

	/********************************************
	 * Icache or DcacheA or DcacheB Invalidation
	 * or any combination thereof
	 * R0 has bits
	 * CPLB_ENABLE_ICACHE_P,CPLB_ENABLE_DCACHE_P,CPLB_ENABLE_DCACHE2_P
	 * set as required
	 ********************************************/
	
	LINK 0;
	[--SP] = R7;

	R7 = R0;
	CC = BITTST(R7,CPLB_ENABLE_ICACHE_P);
	IF !CC JUMP no_icache;
	CALL _icache_invalidate;
no_icache:
	CC = BITTST(R7,CPLB_ENABLE_DCACHE_P);
	IF !CC JUMP no_dcache_a;
	R0 = 0;         /* specifies bank A */
	CALL _dcache_invalidate;
no_dcache_a:
	CC = BITTST(R7,CPLB_ENABLE_DCACHE2_P);
	IF !CC JUMP no_dcache_b;
	R0 = 0;
	BITSET(R0, 23);		/* specifies bank B */
	CALL  _dcache_invalidate;
no_dcache_b:
	R7 = [SP++];
	UNLINK;
	RTS;

_dcache_invalidate:

	/***********************************
	* DCACHE Invalidation
	***********************************/

	/* R0 has bit 23 set to specify bank A or bank B*/
	[--SP] = ( R7:4, P5:5);

	R7 = R0;
	P0.L = (DMEM_CONTROL & 0xFFFF);
	P0.H = (DMEM_CONTROL >> 16);

	/* Save the existing value of DMEM_CONTROL, so that we
    	 * don't clobber it by invalidation.
	 */
	
	R6 = [P0];
	R0 = (ACACHE_BCACHE | ENDCPLB | ENDM);

	/* Enable both as cache although we are going to invalidate only 1.
	 * This is because if only 1 bank is configured as cache it must be
	 * bank A. However if a user has both banks as cache and wishes to
	 * invalidate only bank B, we cannot enable it alone as cache.
	 * Bank A must already be cache in this case, so no SRAM data is lost.
	 * At RESET both will currently be enabled as SRAM.
	 */
	
	SSYNC;
	CLI R5;		/* work around anomaly #32/#52 on BF531/2/3*/
	.align 8;	/* when writing to DMEM_CONTROL.*/
	[P0]=R0;
	SSYNC;
	STI R5;

	I0.L = (DTEST_COMMAND & 0xFFFF);
	I0.H = (DTEST_COMMAND >> 16);
	I1.L = (DTEST_DATA0 & 0xFFFF);
	I1.H = (DTEST_DATA0 >> 16);

	R0=0;
	[I1]=R0;

	/*  D-CACHE:
	 *    2 superbanks,
	 *    each superbank has 4 sub-banks, 
	 *    each sub-bank has 2 ways, 
	 *    each way has 64 lines,
	 */
	
	R3.L=0;
	R3.H=1;	/* sub-bank increment*/
	P2=4;	/* number of sub-banks*/
	R2=64;
	P5=R2;	/* number of lines in each way*/
	R2=32;	/* line index increment*/


	R4=2;	/* initial value for DTEST_COMMAND for way 0*/

		/* write to tag for sub-bank 0, way 0, line 0
		 * for BF535, bit 24 is reserved, but for BF532 it signifies
		 * 0 = access data, 1= access instruction
		 */

	R5.H=0x400;	/* Initial value for DTEST_COMMAND for way 1*/
	R5.L=2;		/* write to tag for sub-bank 0, way 1, line 0*/
	R4=R4|R7;	/* include superbank specifier*/
	R5=R5|R7; 
	LSETUP(lbl0c,lbl3c) LC1=P2;	/* 4 sub-banks*/
lbl0c:	R0=R4;
	R1=R5;
	LSETUP(lbl1c,lbl2c) LC0=P5;	/* 64 lines*/
lbl1c:	R0 = R0+|+R2 || [I0]=R0;
lbl2c:	R1 = R1+|+R2 || [I0]=R1;
	R4=R4+R3;
lbl3c:	R5=R5+R3;

	/* Restore the original value of DMEM_CONTROL*/
	CSYNC;
	CLI R5;
	.align 8;
	[P0] = R6;
	SSYNC;
	STI R5;
	( R7:4, P5:5) = [SP++];
	RTS;

/* Invalidate the Entire Instruction cache by 
 * disabling IMC bit
 */
ENTRY(_icache_invalidate)
ENTRY(invalidate_entire_icache)

	[--SP] = ( R7:4, P5:5); 

	P0.L = (IMEM_CONTROL & 0xFFFF);
	P0.H = (IMEM_CONTROL >> 16);

	R7 = [P0];

	SSYNC;
	
	/* Clear the IMC bit , All valid bits in the instruction
	 * cache are set to the invalid state
	 */		
	BITCLR(R7,2);
	[P0] = R7;
	CSYNC;

	/* Configures the instruction cache agian */

	R6 = [P0];
	
	R7 = (IMC | ENICPLB | ENIM);
	R7 = R7 | R6;

	[P0] = R7;
	CSYNC;
	
	( R7:4, P5:5) = [SP++];
	RTS;


/* Invalidate the Entire Data cache by 
 * clearing DMC[1:0] bits
 */
ENTRY(invalidate_entire_dcache)

	[--SP] = ( R7:4, P5:5); 

	P0.L = (DMEM_CONTROL & 0xFFFF);
	P0.H = (DMEM_CONTROL >> 16);

	R7 = [P0];

	SSYNC;
	
	/* Clear the DMC[1:0] bits, All valid bits in the data
	 * cache are set to the invalid state
	 */		
	BITCLR(R7,2);
	BITCLR(R7,3);
	[P0] = R7;
	CSYNC;

	/* Configures the data cache again */

	R6 = [P0];
	
	R7 = (ACACHE_BCACHE | ENDCPLB | ENDM);
	R7 = R7 | R6;

	[P0] = R7;
	CSYNC;
	
	( R7:4, P5:5) = [SP++];
	RTS;

/*
 * blackfin_cache_clean_invalidate_range(start, end, flags)
 * Clean and invalidate all cache lines assocoiated with this
 * area of memory.
 * 
 * start:	Start address
 * end:		End address
 */ 						
ENTRY(blackfin_icache_flush_range)
	P0 = R0 ;
	P1 = R1 ;
1:
	IFLUSH [P0++];
	CC = P0 < P1 (iu);
	IF CC JUMP 1b (bp);
	RTS;

/* Throw away all D-cached data in specified region without any obligation to write
 * them back. However, we must clean the D-cached entries around the boundaries 
 * of the start and/or end address is not cache aligned. 
 *  
 *  Start: start address, 
 *  end  : end address.
 */

ENTRY(blackfin_dcache_invalidate_range)
	P0 = R0;
	P1 = R1;
1:
	FLUSHINV[P0++];
	CC = P0 < P1 (iu);
	IF CC JUMP 1b (bp);
	RTS;
	
ENTRY(blackfin_dcache_flush_range)
	P0 = R0;
	P1 = R1;
1:
	FLUSH[P0++];
	CC = P0 < P1 (iu);
	IF CC JUMP 1b (bp);
	SSYNC;
	RTS;

ENTRY(blackfin_dflush_page)
	P1 = 128;		/*128*32(cacheline) = 4K Page*/
	LSETUP (fl1, fl1) LC0 = P1;
fl1:	FLUSH [P0++];
	SSYNC;
	RTS;
