/******************************************************************************
  Copyright(c) 2000-2004 Analog Devices Inc. IPDC BANGALORE, India.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 ******************************************************************************
  File name   :   tan_fr16.asm

  Module name :   fractional Tangent

  Label name  : __tan_fr16

  Description :   This program finds Tangent of fractional input.

  Domain      :   [0x9b78,0x6488]  (i.e -(pi/4) ...... (pi/4))
		  The function returns 0 for any input argument that is
		  outside the defined domain.

  Registers used :

  Operand in  R0
  R0 - fractional input no = x.
  R1,R2,R3,P0,I0,A0,A1

  CYCLE COUNT    :  9            N == 0
		 : 13            N >  0X6488
		 : 48            For other N
  'N' - INPUT VALUE IN FRACTIONAL FORMAT

  CODE SIZE      : 114 BYTES

  DATE           : 26-02-01

**************************************************************/

.section .rodata;
 .align 4;
 .tancoef0:
 .short 0x0000
 .short 0x4000
 .short 0x3fff
 .short 0x1B78
 .short 0xf9de
 .short 0xFF61

.text;
.global __tan_fr16;
.align 2;

__tan_fr16:

      CC = R0 == 0;                      // CHECK IF R0 == 0
      IF CC JUMP RET_ZERO;               // IF TRUE, RETURN ZERO

      R2 = ABS R0;                       // GET ABSOLUTE VALUE
      R1 = 0X6488;                       // BOUNDARY VALUE = PI/4
      CC = R1 < R2;                      // CHECK IF INPUT EXCEEDS PI/4
      IF CC JUMP RET_ERROR;              // IF TRUE, RETURN ZERO

      I0.L = .tancoef0;                  // POINTER TO ARRAY OF COEFFICIENT 0
      I0.H = .tancoef0;
      P2 = R0;                           // STORE SIGN

      R2.H = R2.L * R2.L || R1 = [I0++]; // R2.H(Y) = X * X AND GET FIRST COEFF
      A1 = R1;                           // INITIALISE A1 WITH MODIFIED 32 BIT
					 // FIRST COEFFICIENT
      A0 = 0 || R3 = [I0++];             // INITIALISE A0 = 0
					 // AND GET NEXT TWO COEFFICIENTS

      R0 = (A0 += R2.L * R3.L), R1 = (A1 -= R2.H * R3.H) || R3 = [I0++];
					 // A0 += B*X , A1 -= C*Y
					 // AND FETCH NEXT TWO COEFFICIENTS
      R2.L = R2.H * R2.L, R2.H = R2.H * R2.H;
					 // X = X * Y, Y = Y * Y
      P0 = 15;                           // TO PERFORM DIVQ 15 TIMES
      R0 = (A0 += R2.L * R3.L), R1 = (A1 -= R2.H * R3.H);
					 // A0 += D*X^3, A1 -= E*X^4
					 // AND FETCH NEXT TWO COEFFICIENTS
      R1.L = R1(RND);                    // SAVE IN FRACT 16 BIT

      R1.H = 0;                          // CLEAR RH1
      R0 = R0 >>> 1;                     // SAVE IN 32 BIT FORMAT

      R2 = R0^R1;                        // GET SIGN INFORMATION
      R1 = ABS R1;                       // ABS VALUE OF DENOM.
      R0 = ABS R0;                       // ABS VALUE OF NUM.
      R0 <<= 1;                          // ARRANGING FOR PROPER DIVISION.
      DIVS (R0, R1);                     // DIVS IS CALLED ONCE TO CLEAR AQ FLAG

      LSETUP(DIV_START,DIV_START) LC0=P0;
DIV_START: DIVQ (R0, R1);                // DIVQ IS DONE FOR 15 TIMES

      R0 = R0.L (X);
      R1 = -R0;                          // NEGATED RESULT
      R3 = P2;                           // INPUT VALUE
      R2 = R2 | R3;                      // OR INPUT WITH SIGN INF.
      CC = R2 < 0;                       // CHECK R2 < 0
      IF CC R0 = R1;                     // IF TRUE RESULT IS NEGATED
RET_ZERO:
      RTS;

RET_ERROR:
      R0 = 0;                            // RETURN 0 FOR A DOMAIN ERROR
      RTS;

.__tan_fr16.end:
