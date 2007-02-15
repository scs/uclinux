/*
** Float16 compare.  Compares 2 non-IEEE-754 floating point numbers (16.16)
**
** Copyright (C) 2005 Analog Devices, Inc
** This file is subject to the terms and conditions of the GNU Library General
** Public License. See the file "COPYING.LIB" in the main directory of this
** archive for more details.

** Non-LGPL License also available as part of VisualDSP++
** http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

*/

.text;
.align 2;

___float32_cmp:
	CC = R0 < 0;
	R2 = CC;
	CC = R1 < 0;
	R3 = CC;
	CC = R2 == R3;
	IF !CC JUMP diff_signs;

	// signs are the same. Examine exponents.
	R0 = R0 -|- R1;
	R1 = R0.L (X);	// difference between exponents
	R0 >>>= 16;	// difference between mantissas
	CC = R1 == 0;	// If exponents are the different, they decide.
	IF !CC R0 = R1;	// Otherwise, mantissas decide.
	R1 = -R0;	// If x was negative (and therefore y also negative)
	CC = R2 == 0;	// then we have to negate our result
	IF !CC R0 = R1;	//
	RTS;

diff_signs:
	// Signs are different, so we return a number that
	// derives its sign from whether X was negative.
	R0 = R2 << 31;
	R0 += 1;
	RTS;
.___float32_cmp.end:
.global ___float32_cmp;
.type ___float32_cmp, STT_FUNC;
