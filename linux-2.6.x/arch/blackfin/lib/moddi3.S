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
	.globl __umoddi3

__umoddi3:
	[SP +0] = R0;
	[SP +4] = R1;
	[SP +8] = R2;
	R3 = [SP +12];

	P0 = R4;		// Working space

	// If  x < y, then return x.
	CC = R1 < R3 (IU);
	R4 = CC;
	CC = R1 == R3;
	R4 = ROT R4 BY 1;
	CC = R0 < R2 (IU);
	R4 = ROT R4 BY 1;
	CC = R4 < 3;
	R4 = P0;
	IF !CC JUMP RET_X;
	
	LINK 16;

	// Compute d = x / y
	[SP +12] = R3;
	CALL  ___udivdi3;

	// then compute z = d * y
	R2 = [FP +16];
	R3 = [FP +20];
	[SP +12] = R3;
	CALL  __muldi3;

	UNLINK;

	// r = x - z, so r = -z + x

	R0 = -R0;
	//CC = CARRY;
	CC = AC;
	CC = !CC;
	R3 = CC;
	R1 = -R1;
	R1 = R1 - R3;	// z now negated

	R2 = [SP +0];
	R3 = [SP +4];

	R0 = R0 + R2;
/*	CC = CARRY;*/		
	CC = AC;	/*Assembler issues ?*/
	R2 = CC;
	R1 = R1 + R3;
	R1 = R1 + R2;

RET_X:
	RTS;

	.text
	.globl __moddi3
___moddi3:
	[SP +0] = R0;
	[SP +4] = R1;
	[SP +8] = R2;
	R3 = [SP +12];
	P0 = R4;		// Workspace
	CC = R1 < 0;		// Negate either, if negative
	IF !CC JUMP no_neg_x;
	R0 = -R0;
	CC = AC;
	CC = !CC;
	R4 = CC;
	R1 = -R1;
	R1 = R1 - R4;

no_neg_x:
	CC = R3 < 0;
	IF !CC JUMP no_neg_y;
	R2 = -R2;
	CC = AC;	/*Assembler issues ?*/
	CC = !CC;
	R3 = -R3;
	R3 = R3 - R4;

no_neg_y:

	// Both operands are now positive

	// If x < y, then we can return x.

	CC = R1 < R3;
	R4 = CC;
	CC = R1 == R3;
	R4 = ROT R4 BY 1;
	CC = R0 < R1 (IU);
	R4 = ROT R4 BY 1;
	CC = R4 < 3;
	R4 = P0;
	IF !CC JUMP return_x;

	LINK 16;

	// Compute d = x / y
	[SP +12] = R3;
	CALL __divdi3;

	// then compute z = d * y
	R2 = [FP +16];
	R3 = [FP +20];
	[SP +12] = R3;
	CALL __mulli3;

	UNLINK;

	// r = x - z, so r = -z + x

	R0 = -R0;
	CC = AC;
	CC = !CC;
	R3 = CC;
	R1 = -R1;
	R1 = R1 - R3;	// z now negated

	R2 = [SP +0];
	R3 = [SP +4];

	R0 = R0 + R2;
	CC = AC;
	R2 = CC;
	R1 = R1 + R3;
	R1 = R1 + R2;

return_x:
	RTS;
