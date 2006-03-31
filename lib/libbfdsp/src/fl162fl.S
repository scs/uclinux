/*
** Convert float16 to float
** Copyright (C) 2003 Analog Devices, Inc
** This file is subject to the terms and conditions of the GNU Library General
** Public License. See the file "COPYING.LIB" in the main directory of this
** archive for more details.

** Non-LGPL License also available as part of VisualDSP++
** http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

*/

.section program;
.align 2;

_fl16_to_fl:
	CC = R0 == 0;
	IF CC JUMP finished;

	// Save the sign
	R1 = R0 >> 31;
	R1 <<= 31;

	// Compute the exponent
	R2 = R0.L (X);
	R3 = 126;	// 127 - 1, because of hidden bit
	R2 = R2 + R3;

	// Check for mantissa == -1 (outside range of float mantissa)
	R3 = R0;
	R3.H = 0x8000;
	CC = R3 == R0;
	IF CC JUMP minusone;

	// Negate mantissa, if sign is negative
	R3 = - R0 (V);
	CC = R1;
	IF CC R0 = R3;

assemble:
	R0.L = R0.L - R0.L (NS);	// clear exponent
	R0 <<= 2;			// remove sign and hidden bit
	R0 >>= 9;
	R2 <<= 23;
	R0 = R1 | R0;
	R0 = R0 | R2;
finished:
	RTS;

minusone:
	R2 += 1;
	R0.H = 0x4000;
	JUMP assemble;
._fl16_to_fl.end:
.global _fl16_to_fl;
.type _fl16_to_fl, STT_FUNC;
