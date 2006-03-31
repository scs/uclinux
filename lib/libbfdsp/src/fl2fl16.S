/*
** Convert a float to a float16.
** Copyright (C) 2003 Analog Devices, Inc
** This file is subject to the terms and conditions of the GNU Library General
** Public License. See the file "COPYING.LIB" in the main directory of this
** archive for more details.

** Non-LGPL License also available as part of VisualDSP++
** http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

*/

.section program;
.align 2;
_fl_to_fl16:
	R1 = R0 << 1;
	CC = R1 == 0;
	IF CC R0 = R1;		// +0.0 or -0.0 both come out as 0.0
	IF CC JUMP finished;	// in float16.

	// extract sign
	R1 = R0 >> 31;
	R1 <<= 31;

	// extract exponent
	R2 = R0 << 1;
	R2 >>= 24;
	R3 = 126;		// because float16 includes hidden bit
	R2 = R2 - R3;

	BITSET(R0, 23);		// make hidden bit explicit
	R0 <<= 8;		// move mantissa to top, removing exp and sign
	R0 >>= 1;		// then back to make space for sign

	R3 = - R0 (V);		// negate the mantissa if the sign
	CC = R1;		// bit is set.
	IF CC R0 = R3;

	R0.L = R2.L >> 0;	// move the exponent in.
finished:
	RTS;
._fl_to_fl16.end:
.global _fl_to_fl16;
.type _fl_to_fl16, STT_FUNC;

