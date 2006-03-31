/************************************************************************
 *
 * subfl32.s : $Revision$
 *
 * (c) Copyright 2000-2005 Analog Devices, Inc.
** This file is subject to the terms and conditions of the GNU Library General
** Public License. See the file "COPYING.LIB" in the main directory of this
** archive for more details.

** Non-LGPL License also available as part of VisualDSP++
** http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 *
 ************************************************************************/

/*
** 32-bit float subtract
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

_sub_fl32:
#ifdef __WORKAROUND_SHIFT
   P1 = R7;
#endif
   // R0 = expX, R1 = manX, R2 = expY
   R3 = [SP + 12];     // manY

   // Compare exponents
   R2 = R0 - R2;
   CC = R2 < 0;
#ifdef __WORKAROUND_SHIFT
   R7 = 31;
#endif
   IF CC JUMP adjust_x;

   // Adjust y
#ifdef __WORKAROUND_SHIFT
   R7 = MIN(R2,R7);
   R3 >>>= R7;
#else
   R3 >>>= R2;
#endif
   JUMP adjusted;
adjust_x:
   R2 = -R2;
#ifdef __WORKAROUND_SHIFT
   R7 = MIN(R2,R7);
   R1 >>>= R7;
#else
   R1 >>>= R2;
#endif
   R0 = R0 + R2;
adjusted:
   // Result will be in R0,R1. Either manX or manY will
   // have been adjusted down to match the exponents.
   // X's exponent (R0) is the required final value.

#ifdef __WORKAROUND_SHIFT
   R7 = P1;
#endif
   // add mantissas.
   R1 = R1 + R3;
   CC = OVERFLOW;
   IF CC JUMP overflow;

   // No overflow. Check whether the result needs normalising.
   CC = R1 == 0;       // If mantissa is zero
   IF CC R0 = R1;      // make exponent zero too
   IF CC JUMP finish;  // and skip to end.

   R3.L = SIGNBITS R1; // else normalise
   R3 = R3.L (X);
   R0 = R0 - R3;
   R1 <<= R3;
finish:
   RTS;
overflow:
   CC = CARRY;
   R1 = ROT R1 BY -1;  // Rotate bit into mantissa
   R0 += 1;            // Increase exponent
   RTS;
._sub_fl32.end:
.global _sub_fl32;
.type _sub_fl32, STT_FUNC;

// end of file
