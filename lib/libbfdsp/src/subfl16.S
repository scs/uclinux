/*
** Float16 subtract. Subtracts 2 non-IEEE-754 floats (16.16).
**
** Copyright (C) 2005 Analog Devices, Inc
** This file is subject to the terms and conditions of the GNU Library General
** Public License. See the file "COPYING.LIB" in the main directory of this
** archive for more details.

** Non-LGPL License also available as part of VisualDSP++
** http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

*/

#if defined(__ADSPBF535__) || defined(__AD6532__)
#define CARRY AC
#else
#define CARRY AC0
#endif

.section program;
.align 2;

___float32_sub:
	// Compare exponents
	R2.L = R0.L - R1.L (NS);
	R2 = R2.L (X);
	CC = R2 < 0;
	IF CC JUMP adjust_x;

	// Adjust y
	R3 = R1;
#ifdef __WORKAROUND_SHIFT
	R1 = 31;
	R1 = MIN(R1,R2);
	R3 >>>= R1;
#else
	R3 >>>= R2;
#endif
	R1.H = R3.H >> 0;
	JUMP adjusted;

adjust_x:

#ifdef __WORKAROUND_SHIFT
	R3 = -32;
	R3 = MAX(R2,R3);
	R3 = ASHIFT R0 BY R3.L;
	R0 = R0 - R2;
#else
	R3 = R0;
	R2 = -R2;
	R3 >>>= R2;
	R0 = R0 + R2;		// inc result exponent (mantissa may change)
#endif
	R0.H = R3.H >> 0;	// but now store adjusted mantissa

adjusted:
	// result will be R0. Either R0's or R1's mantissa has been adjusted
	// down to match exponents. R0's exponent is the required final
	// value.

	R0.H = R0.H - R1.H (NS);

	CC = AV0;
	IF CC JUMP overflow;

	// Check if mantissa is non-zero, for normalising.

	R2 = R0;
	R2 >>>= 16;
	CC = R2 == 0;	// if mantissa is zero, then set exponent
	IF CC R0 = R2;	// to zero, too, and finish.
	IF CC JUMP finish;

	// normalise
	R3.L = SIGNBITS R2.L;
	R0.H = ASHIFT R0.H BY R3.L;
	R0.L = R0.L - R3.L (NS);
finish:
	RTS;

overflow:
	CC = CARRY;
	R2 = R0;
	R2 = ROT R2 BY -1;	// and rotate it in
	R0 += 1;		// increment exponent (may change mantissa)
	R0.H = R2.H >> 0;	// but we overwrite with new mantissa anyway.
	RTS;
.___float32_sub.end:
.global ___float32_sub;
.type ___float32_sub, STT_FUNC;
