/*
** Float16 multiply.  Takes 2 non-IEEE-754 floats and multiplies them (16.16)
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
_mul_fl16:
	R2.L = R0.L + R1.L (NS);
	R0 = R0.H * R1.H;		// Produce 32-bit result first
	R0.L = R0.L - R0.L (NS);	// And lose bottom bits of precision

	// Normalise, in case it's needed
	R3.L = SIGNBITS R0.H;
	R1.H = ASHIFT R0.H BY R3.L;
	R1.L = R2.L - R3.L (NS);

	// Which isn't true if the result is zero.
	CC = R0 == 0;
	IF !CC R0 = R1;
finished:
	RTS;
._mul_fl16.end:
.global _mul_fl16;
.type _mul_fl16, STT_FUNC;
