/* Copyright (C) 2004 LG Soft India. All Rights Reserved.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.
 *
 * Blackfin BF533/2.6 support : LG Soft India
 */

#include <linux/linkage.h>
#include <asm/cplb.h>
#include <asm/board/bf533.h>

.text

.global cache_grab_lock
.type	cache_grab_lock, STT_FUNC;

.global cache_lock
.type	cache_lock, STT_FUNC;

/* When you come here, it is assumed that 
 * R0 - Which way to be locked
 */	

#ifdef CONFIG_BLKFIN_CACHE_LOCK

ENTRY(cache_grab_lock)
	
	[--SP]=( R7:0,P5:0 );
	
	P1.H = (IMEM_CONTROL >> 16);
	P1.L = (IMEM_CONTROL & 0xFFFF);
	P5.H = (ICPLB_ADDR0 >> 16);
	P5.L = (ICPLB_ADDR0 & 0xFFFF);
	P4.H = (ICPLB_DATA0 >> 16);
	P4.L = (ICPLB_DATA0 & 0xFFFF);
	R7 = R0;

	/* If the code of interest already resides in the cache
	 * invalidate the entire cache itself.
  	 * invalidate_entire_icache;
	 */
	
	SP += -12;
	[--SP] = RETS;
	CALL invalidate_entire_icache;
	RETS = [SP++];
	SP += 12;

	/* Disable the Interrupts*/
	
	CLI R3;
	
LOCK_WAY:					
	
	/* Way0 - 0xFFA133E0
	 * Way1 - 0xFFA137E0
	 * Way2 - 0xFFA13BE0	Total Way Size = 4K
	 * Way3 - 0xFFA13FE0
	 */

	/* Procedure Ex. -Set the locks for other ways by setting ILOC[3:1]
	 * Only Way0 of the instruction cache can now be
	 * replaced by a new code
	 */
	
	R5 = R7;
	CC = BITTST(R7,0);
	IF CC JUMP CLEAR1;	
	R7 = 0;
	BITSET(R7,0);
	JUMP DONE1;
	
CLEAR1:	
	R7 = 0;
	BITCLR(R7,0);
DONE1:	R4 = R7 << 3;
	R7 = [P1];
	R7 = R7 | R4;
	[P1] = R7;
	
	R7 = R5;
	CC = BITTST(R7,1);
	IF CC JUMP CLEAR2;
	R7 = 0;
	BITSET(R7,1);
	JUMP DONE2;
	
CLEAR2:	
	R7 = 0;
	BITCLR(R7,1);
DONE2:	R4 = R7 << 3;
	R7 = [P1];
	R7 = R7 | R4;
	[P1] = R7;	

	R7 = R5;
	CC = BITTST(R7,2);
	IF CC JUMP CLEAR3;
	R7 = 0;
	BITSET(R7,2);
	JUMP DONE3;
CLEAR3:	
	R7 = 0;
	BITCLR(R7,2);
DONE3:	R4 = R7 << 3;
	R7 = [P1];
	R7 = R7 | R4;
	[P1] = R7;	
	

	R7 = R5;
	CC = BITTST(R7,3);
	IF CC JUMP CLEAR4;	
	R7 = 0;
	BITSET(R7,3);
	JUMP DONE4;
CLEAR4:	
	R7 = 0;
	BITCLR(R7,3);
DONE4:	R4 = R7 << 3;
	R7 = [P1];
	R7 = R7 | R4;
	[P1] = R7;	

	STI R3;

	( R7:0,P5:0 ) = [SP++];
	
	RTS;

/* After the execution of critical code, the code is now locked into 	  	
 * the cache way. Now we need to set ILOC.
 * 
 * R0 - Which way to be locked
 */

cache_lock: 
	
	[--SP]=( R7:0,P5:0 );

	P1.H = (IMEM_CONTROL >> 16);
	P1.L = (IMEM_CONTROL & 0xFFFF);
	
	/* Disable the Interrupts*/
	CLI R3;

	R7 = [P1];
	R2 = 0xFF87;
	R7 = R7 & R2;
	R0 = R0 << 3;
	R7 = R0 | R7;

	[P1] = R7;

	/* Renable the Interrupts */
	STI R3;

	( R7:0,P5:0 ) = [SP++];
	RTS;

#endif	/*BLKFIN_CACHE_LOCK*/

/* Return the ILOC bits of IMEM_CONTROL 
 */

.global read_iloc
.type read_iloc, STT_FUNC;

read_iloc:

	P1.H = (IMEM_CONTROL >> 16);
	P1.L = (IMEM_CONTROL & 0xFFFF);
	R1 = 0xF;
	R0 = [P1];
	R0 = R0 >> 3;
	R0 = R0 & R1;
	
	RTS;

