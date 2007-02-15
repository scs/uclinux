/************************************************************************
 *
 * mulfl32.s : $Revision$
 *
 * (c) Copyright 2000-2003 Analog Devices, Inc.
** This file is subject to the terms and conditions of the GNU Library General
** Public License. See the file "COPYING.LIB" in the main directory of this
** archive for more details.

** Non-LGPL License also available as part of VisualDSP++
** http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 *
 ************************************************************************/

/*
** 32-bit float  multiply.
*/

#if defined(__ADSPBF535__) || defined(__AD6532__)
#define OVERFLOW AV0
#else
#define OVERFLOW V
#endif

.text;
.align 2;
_mul_fl32:
   R3 = [SP+12];   // get mantissa of second input
   R0 = R0 + R2;   // Add exponents

   // 32-bit fractional multiply
   // R1 = R1 * R3
   R2 = PACK(R1.L, R3.L);
   CC = R2 == 0;
   CC = !CC;
   A1 = R1.L * R3.L (FU);
   A1 = A1 >> 16;
   A0 = R1.H * R3.H, A1 += R1.H * R3.L (M);
   CC &= OVERFLOW;
   A1 += R3.H * R1.L (M);
   A1 = A1 >>> 15;
   R3 = CC;
   R1 = (A0 += A1);
   R1 = R1 + R3;

   // Normalise
#if defined(__WORKAROUND_SIGNBITS) || defined(__WORKAROUND_DREG_COMP_LATENCY)
   NOP;
#endif
   R2.L = SIGNBITS R1;
   R2 = R2.L (X);
   R1 <<= R2;
   R0 = R0 - R2;

   CC = R1 == 0;
   IF CC R0 = R1;
   RTS;
._mul_fl32.end:
.global _mul_fl32;
.type _mul_fl32, STT_FUNC;

// end of file
