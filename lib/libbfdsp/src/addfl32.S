/*
** Copyright (C) 2005 Analog Devices, Inc
** This file is subject to the terms and conditions of the GNU Library General
** Public License. See the file "COPYING.LIB" in the main directory of this
** archive for more details.

** Non-LGPL License also available as part of VisualDSP++
** http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

**
** Float32 add.  Addition of two non-IEEE-754 64-bit floats (32.32 format)
**
** [ man, exp ] add( [ man, exp ], [ man, exp ] )
*/

#if defined(__ADSPBF535__) || defined(__AD6532__)
#define CARRY AC
#define OVERFLOW AV0
#else
#define CARRY AC0
#define OVERFLOW V
#endif

.section program;
.align 2;
_add_fl32:
	P0 = R6;
	P1 = R7;
	// R0 = expX, R1 = manX, R2 = expY
	R3 = [SP + 12];	// manY

	// Compare exponents
	// If expX < expY, swap args.
	CC = R0 < R2;
	IF !CC JUMP no_swap;
	R6 = R0;
	R7 = R1;
	R0 = R2;
	R1 = R3;
	R2 = R6;
	R3 = R7;
no_swap:
	R6 = R0 - R2;	// Get D, the difference between exponents.
			// Don't need to ABS, since we've swapped,
			// so we know D>=0, expX >= expY.
#ifdef __WORKAROUND_SHIFT
	R7 = 0x1f;
	R6 = MIN(R6, R7);
#endif
	// Adjust Y's mantissa down, so exponents are equal.
	R3 >>>= R6;
	R6 = P0;	// Finished with the extras
	R7 = P1;
	// And add mantissas.
	R1 = R1 + R3;
	CC = OVERFLOW;
	IF CC JUMP overflow;

	// No overflow. Check whether the result needs normalising.
	CC = R1 == 0;		// If mantissa is zero
	IF CC R0 = R1;		// make exponent zero too
	IF CC JUMP finish;	// and skip to end.

	R3.L = SIGNBITS R1;	// else normalise
	R3 = R3.L (X);
	R0 = R0 - R3;
	R1 <<= R3;
finish:
	RTS;
overflow:
	CC = CARRY;
	R1 = ROT R1 BY -1;	// Rotate bit into mantissa
	R0 += 1;		// Increase exponent
	RTS;
._add_fl32.end:
.global _add_fl32;
.type _add_fl32, STT_FUNC;
