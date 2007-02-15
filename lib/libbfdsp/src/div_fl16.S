/*
** Float16 division.  Divides 2 non-IEEE-754 floating point numbers (16.16)
**
** Copyright (C) 2003 Analog Devices, Inc
** This file is subject to the terms and conditions of the GNU Library General
** Public License. See the file "COPYING.LIB" in the main directory of this
** archive for more details.

** Non-LGPL License also available as part of VisualDSP++
** http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

*/

.text;
.align 2;
_div_fl16:
	P0 = R7;	// store for later

	// Identities
	CC = R1 == 0;
	IF CC JUMP div_by_zero;
	R2 = 1;			// R2 = 1.0
	BITSET(R2,30);		// R2 = 0x40000001
	CC = R1 == R2;
	IF CC JUMP ret_x;	// x/1.0 => x
	CC = R0 == R1;
	IF CC R0 = R2;
	IF CC JUMP ret_x;	// x/x => 1.0

	// Save signs of X and Y
	R7 = R0 ^ R1;

	R7.L = R0.L - R1.L (NS);	// Save result's exponent

	// Extend the mantissas
	R0.L = R0.L - R0.L (NS);	// Leave R0 in high half
	R1 >>>= 16;
	// Make sure both q and d are positive
	R0 = ABS R0;
	R1 = ABS R1;

	// Initialise divisor flags
	R2 = 0;
	CC = R2;
	AQ = CC;
	DIVQ(R0, R1);
	DIVQ(R0, R1);
	DIVQ(R0, R1);
	DIVQ(R0, R1);
	DIVQ(R0, R1);
	DIVQ(R0, R1);
	DIVQ(R0, R1);
	DIVQ(R0, R1);
	DIVQ(R0, R1);
	DIVQ(R0, R1);
	DIVQ(R0, R1);
	DIVQ(R0, R1);
	DIVQ(R0, R1);
	DIVQ(R0, R1);
	DIVQ(R0, R1);
	DIVQ(R0, R1);
	R2 = R0.L (Z);

	// Recover exponent, and extend
	R0 = R7.L (X);

	// Check for overflow
	R3 = R2 >> 1 (V);
	CC = BITTST(R2, 15);
	IF CC R2 = R3;
	R3 = CC;
	R0 = R0 + R3;
	R2 = R2.L (X);

	// Check for zero result.

	CC = R2 == 0;
	IF CC R0 = R2;
	IF CC JUMP ret_x;

	// If signs of X and Y differed, change sign of result
	R3 = -R2;
	CC = BITTST(R7, 31);
	IF CC R2 = R3;

	// Now normalise
#if defined(__WORKAROUND_SIGNBITS) || defined(__WORKAROUND_DREG_COMP_LATENCY)
	NOP;
#endif
	R3.L = SIGNBITS R2.L;
	R0.H = ASHIFT R2.L BY R3.L;
	R0.L = R0.L - R3.L (NS);

ret_x:
	R7 = P0;
	RTS;

div_by_zero:
	R0 = 0;
	BITSET(R0,31);		// R0 = 0x80000000
	R7 = P0;
	RTS;
._div_fl16.end:
.global _div_fl16;
.type _div_fl16, STT_FUNC;
