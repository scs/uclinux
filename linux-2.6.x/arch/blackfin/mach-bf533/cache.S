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
 
.globl _cache_invalidate
.type _cache_invalidate, STT_FUNC;

.globl _icache_invalidate
.type _icache_invalidate, STT_FUNC;

.globl blackfin_cache_clean_invalidate_range
.type blackfin_cache_clean_invalidate_range, STT_FUNC;


.align 2;

.global blackfin_dflush_page
.type blackfin_dflush_page, STT_FUNC;


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
._cache_invalidate.end:


.align 2;

_icache_invalidate:
	/***********************************
         * Icache Invalidation
    	 ***********************************/
	[--SP] = ( R7:4, P5:5);

    	/* Enable, and as cache. This will already be the case if this is a
    	 * user request, but for use at RESET it will be enabled as SRAM.
    	 */ 	      
	
	P0.L = (IMEM_CONTROL & 0xFFFF);
	P0.H = (IMEM_CONTROL >> 16);

    	/* Save the current settings of IMEM_CONTROL, so that we don't
    	 * clobber it by invalidation.
    	 */
	R7 = [P0];
	R0 = (IMC | ENIM);
	CLI R6;			/* Avoid Anomalies #32/#52 on*/
	.align 8;		/* BF531/2/3 when writing to enable*/
	[P0]=R0;		/* CPLBs or cache.*/
	SSYNC;
	STI R6;

	I0.L = (ITEST_COMMAND & 0xFFFF);
	I0.H = (ITEST_COMMAND >> 16);

    	/* When the TEST_COMMAND register is written, the tag or line
    	 * contents for the line it addresses is read or written to/from the
    	 * TEST_DATA0/TEST_DATA1 registers respectively.
    	 *
    	 * To invalidate a line we write zero to the tag for the line.
    	 */
       
	I1.L = (ITEST_DATA0 & 0xFFFF);
	I1.H = (ITEST_DATA0 >> 16);
	R0=0;
	[I1]=R0;

	
	/* I-CACHE:
    	 * 4 sub-banks, 
    	 * each sub-bank has 4 ways, 
    	 * each way has 32 lines
	 */
    	  
	R2=32;		/* line index increment*/
	R3.L=0;	
	R3.H=1;		/* sub-bank increment*/
	P2=4;		/* number of sub-banks, outer loop iterations*/
             		/* (Should be 2 for D-cache)*/
	P5=R2;		/* number of lines in each way*/
	R4=2;		/* initial value for ITEST_COMMAND for way 0 */
			/* write to tag for sub-bank 0, way 0, line 0*/
	R5.H=0x400;	/* initial value for ITEST_COMMAND for way 1*/
	R5.L=2;		/* write to tag for sub-bank 0, way 1, line 0*/
	LSETUP(lbl0a,lbl3a) LC1=P2; /* for each of 4 sub-banks*/
lbl0a:  R0=R4;
	R1=R5;
	LSETUP(lbl1a,lbl2a) LC0=P5;	/* for each of 32 lines*/
lbl1a:	R0 = R0+|+R2 ; 			/* way 0*/
	[I0] = R0;
	CSYNC;				/* Requires CSYNC - BFin*/
lbl2a:	R1 = R1+|+R2; 			/* way 1*/
	[I0] = R1;
	CSYNC;				/* Requires CSYNC - BFin*/
	R4=R4+R3;			/* next sub-bank way 0*/
	
lbl3a:  R5=R5+R3;			/* next sub-bank way 1*/

    	/* and now do it all again for ways 2 and 3*/
	R4.H=0x800;
	R4.L=2;				/* initial value for ITEST_COMMAND for way 2*/                
	R5.H=0xc00;
	R5.L=2;				/* initial value for ITEST_COMMAND for way 3*/
	LSETUP(lbl0b,lbl3b) LC1=P2;
lbl0b:	R0=R4;
	R1=R5;
	LSETUP(lbl1b,lbl2b) LC0=P5;
lbl1b:	R0 = R0+|+R2; 
	[I0] = R0;
	CSYNC;
lbl2b:	R1 = R1+|+R2;
	[I0] = R1;
	CSYNC;
	R4=R4+R3;

lbl3b:  R5=R5+R3;

	/* Restore the previous value of IMEM_CONTROL*/

	CSYNC;
	CLI R6;
	.align 8;
	[P0] = R7;
	SSYNC;
	STI R6;
	( R7:4, P5:5) = [SP++];
	RTS;

._icache_invalidate.end:



.align 2;
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
	R0 = (ACACHE_BCACHE | ENDM);

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
._dcache_invalidate.end:


/* Invalidate the Entire Instruction cache by 
 * disabling IMC bit
 */

.global invalidate_entire_icache
.type invalidate_entire_icache, STT_FUNC;

invalidate_entire_icache:

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
	
	R7 = (IMC | ENICPLB);
	R7 = R7 | R6;

	[P0] = R7;
	CSYNC;
	
	( R7:4, P5:5) = [SP++];
	RTS;


/* Invalidate the Entire Data cache by 
 * clearing DMC[1:0] bits
 */

.global invalidate_entire_dcache
.type invalidate_entire_dcache, STT_FUNC;

invalidate_entire_dcache:

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
	
	R7 = (DMC_ENABLE | ENDCPLB);
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
 * flags:	nonzero for Instruction cache
 */ 						
	.align 5
blackfin_cache_clean_invalidate_range:

	[--SP] = ( R7:0, P5:0 );
	R4 = 1;
	R3 = R1 - R0;
	P2 = R0 ;
BACK:	CSYNC;
	FLUSHINV [P2++];
	R3 = R3 - R4; 
	CC = R3 < 0;
	IF !CC JUMP BACK;
	
	CC = R2 ; 
	IF !CC JUMP RET;

	[--sp] = RETS;
	CALL _icache_invalidate;
	RETS = [sp++];

RET:	( R7:0, P5:0 ) = [SP++];
	RTS;
	

/* Throw away all D-cached data in specified region without any obligation to write
 * them back. However, we must clean the D-cached entries around the boundaries 
 * of the start and/or end address is not cache aligned. 
 *  
 *  Start: virtual start address, 
 *  end  : virtual end address.
 */

blackfin_dcache_invalidate_range:
	
	[--SP] = ( R7:0, P5:0 );
	R4 = 1;
	P5 = R0;
	R3 = R1 - R0;
	
AGAIN:	CSYNC;
	FLUSHINV[P5++];
	R3 = R3 - R4;
	CC = R3 < 0;
	IF !CC JUMP AGAIN;
	
	( R7:0, P5:0 ) = [SP++];
	RTS;
	
ENTRY(blackfin_dflush_page)
	
	[--SP] = ( R7:0, P5:0 );
	P0 = R0;
	P1 = 32;
	P1 = P1 << 2;		/*Assuming 4K Page*/
	
	P1 += -1;
	FLUSHINV [P0++];
	LSETUP (fl1, fl2) LC0 = P1;
fl1:	CSYNC;
fl2:	FLUSHINV [P0++];	
	CSYNC;
	JUMP over;

over:
	SSYNC;
	( R7:0, P5:0 ) = [SP++];
	RTS;
