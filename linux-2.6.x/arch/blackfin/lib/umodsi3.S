/* Copyright (C) 2003 Analog Devices, Inc. All Rights Reserved. 
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License. 
 *
 * Blackfin BF533/2.6 support : LG Soft India	
 *
 * libgcc1 routines for Blackfin 533
 * Copyright (C) 2004-2005 LG Soft India. 
 */

	.text
	.extern __udivsi3;
	.globl	__umodsi3
__umodsi3:
	
	CC=R0==0;
	IF CC JUMP RETURN_R0;		/* Return 0, if NR == 0 */
	CC= R1==0;
	IF CC JUMP RETURN_ZERO_VAL;	/* Return 0, if DR == 0 */
	CC=R0==R1;             
	IF CC JUMP RETURN_ZERO_VAL;	/* Return 0, if NR == DR */
	CC = R1 == 1;
	IF CC JUMP RETURN_ZERO_VAL;	/* Return 0, if  DR == 1 */
	CC = R0<R1 (IU);
	IF CC JUMP RETURN_R0;		/* Return dividend (R0),IF NR<DR */

	[--SP] = (R7:6);		/* Push registers and */
	[--SP] = RETS;			/* Return address */
	R7 = R0;			/* Copy of R0 */   
	R6 = R1;
	SP += -12;			/* Should always provide this space */
	CALL __udivsi3;		/* Compute unsigned quotient using ___udiv32()*/
	SP += 12;
	R0 *= R6;			/* Quotient * divisor */
	R0 = R7 - R0;			/* Dividend - ( quotient *divisor) */
	RETS = [SP++];			/* Pop return address */
	( R7:6) = [SP++];		/* And registers */
	RTS;				/* Return remainder */
RETURN_ZERO_VAL:
	R0 = 0;
RETURN_R0:
	RTS;


