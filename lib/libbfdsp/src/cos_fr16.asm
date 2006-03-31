/******************************************************************************
  Copyright(c) 2000-2004 Analog Devices Inc. IPDC BANGALORE, India.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 ******************************************************************************
  File name   :   cos_fr16.asm

  Module name :   Fractional cosine

  Label Name  :   __cos_fr16

  Description :   This program finds the cosine of a given fractional
		  input value.

  cosine Approximation: y = cos (x * PI/2)

  Registers used :

  R0 -> INPUT value,
  R1,R2,R3,P0,P1,P2,A0

  CYCLE COUNT    : 24 CYCLES

  CODE SIZE      : 78 BYTES

  DATE           : 26-02-01

**************************************************************/
.section .rodata;
 .align 2;
 .coscoef:
 .short 0x6480
 .short 0x0059
 .short 0xD54D
 .short 0x0252
 .short 0x0388

.text;
.global __cos_fr16;
.align 2;

__cos_fr16:

      R0 = ABS R0;              // GET THE ABSOLUTE VALUE OF INPUT
      P0.L = .coscoef;          // POINTER TO COSINE COEFFICIENT
      P0.H = .coscoef;
      P1 = 2;                   // SET LOOP COUNTER VALUE = 2
      R3 = -32768;              // INITIALISE R3 = -1.0
      R0 = R3-R0;               // R0 = -1 - R0
      R1 = R0;                  // COPY RO TO R1 REG (Y = X)
      A0 = 0 || R3 = W[P0++] (Z);   // SET ACCUMULATOR = 0 AND GET FIRST COEFFICIENT
      LSETUP(COSSTRT,COSEND) LC0 = P1;
				// SET A LOOP FOR LOOP COUNTER VALUE = 2
COSSTRT:  R0.H = R0.L * R1.L;                // EVEN POWERS OF X
	  A0 += R1.L * R3.L || R3 = W[P0++] (Z);
	  R1.L = R0.L * R0.H;                // ODD POWERS OF X
COSEND:   A0 += R0.H * R3.L || R3 = W[P0++] (Z);

      R0 = 0x7fff;              // INITIALISE R0 TO 0X7FFF
      R2 = (A0 += R1.L * R3.L);
      R2 = R2 >> 15;            // SAVE IN FRACT16
      CC = R0 < R2;             // IF R2 > 0x7FFF
      IF CC R2 = R0;            // IF TRUE THEN INITIALISE R2 = 0X7FFF
      R0 = R2.L(X);             // COPY OUTPUT VALUE TO R0
      RTS;

.__cos_fr16.end:
