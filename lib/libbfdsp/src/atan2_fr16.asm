/******************************************************************************
  Copyright(c) 2001-2004 Analog Devices Inc.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

******************************************************************************
  File Name      : atan2_fr16.asm
  Include File   : math.h
  Label Name     : __atan2_fr16

  Description    : This program finds the arc tangent of quotient(y/x).
		   
		   Approximation: z = atan2(y/x) = atan(y/x)/PI

		   The boundary conditions are as follows:
		   -----------------------------------
		    y           x           o/p
		   -----------------------------------
		    0           0            0
		    1(0x7FFF)   0           0.5(0x4000)
		   -1(0x8000)   0          -0.5(0xC000)

		    0           1(0x7FFF)    0
		    1(0x7FFF)   1(0x7FFF)   0.25(0x2000)
		   -1(0x8000)   1(0x7FFF)  -0.25(0xE000)

		    0          -1(0x8000)   -1  (0x8000)
		    1(0x7FFF)  -1(0x8000)   0.75(0x6000)
		   -1(0x8000)  -1(0x8000)  -0.75(0xA000)
		   -------------------------------------

		    For the boundary condition (y=0, x=-1), the function 
		    could return either -1 or +1. Since +1 is not available 
		    as a fractional number, -1(0x8000) is returned.

  Operand        : R0 - Input y
		   R1 - Input x

  Registers Used : R0-3, R5-7, P0, I0

  Cycle count    : 37,  if y == 0
		   36,  if y != 0, x == 0
		   39,  if y != 0, x == y
		   94,  otherwise
		   n = 20: 80 Cycles  (BF532, Cycle Accurate Simulator)
  Code size      : 166 Bytes
******************************************************************************/
.section .rodata;

.align 2;
.atan2coef:
 .short 0x28BE
 .short 0xFFFB
 .short 0xF2AE
 .short 0xFE6E
 .short 0x0D5B
 .short 0xF691
 .short 0x023F;
 

.text;
.global   __atan2_fr16;

.align 2;
__atan2_fr16:
	  [--SP] = (R7:5);               // PUSH R7 TO R5 REG TO STACK 
	  R6 = R0;                       // Y 
	  R7 = R1;                       // X 
	  R0 = R0.L(Z);                  // ZERO EXTEND FOR GETTING ABSOLUTE 
					 // OF 0X8000 CORRECTLY
	  R1 = R1.L(Z);                  // ZERO EXTEND FOR GETTING ABSOLUTE 
					 // OF 0X8000 CORRECTLY
	  R2 = ABS R0(V);                // ABSOLUTE OF Y
	  R3 = ABS R1(V);                // ABSOLUTE OF X
	  R0 = MIN(R2,R3);               // MINIMUM OF Y AND X - NUMERATOR 
	  R1 = MAX(R2,R3);               // MAXIMUM OF Y AND X - DENOMINATOR 
	  CC = R0 == 0;                  // CHECK IF NUMERATOR IS ZERO
	  IF CC JUMP RET_ZERO;           // IF TRUE, JUMP

	  CC = R2 < R3;                  // CHECK IF |Y| < |X| 
	  R5 = CC;                       // STORE IT IN R5 
	  CC = R0 == R1;                 // CHECK IF MAGNITUDES OF
					 // X AND Y ARE EQUAL 
	  R2 = 0X2000;                   // 0.25 IN FRACT16 
	  IF CC JUMP EQUAL;              // IF TRUE, MAGNITUDE OF RESULT IN R2 

	  [--SP] = RETS;                 // PUSH RETS
	  CALL.X __div16;                  // CALL DIV16 FUNCTION AND RESULT 
					 // WILL BE IN R0 REG
	  RETS = [SP++];                 // POP RETS

	  I0.L = .atan2coef;             // POINTER TO ARRAY OF COEFFICIENTS
	  I0.H = .atan2coef;
	  P0 = 3;                        // INITIALISE LOOP COUNTER VALUE
	  R3 = R0;                       // MAKE A COPY OF QUOTIENT 
					 // IN R3 (A = B)
	  A0 = 0 || R1.L = W[I0++];      // INITIALISE A0 = 0 AND 
					 // GET FIRST COEFFICIENT

	  // SETUP LOOP COUNTER FOR VALUE P0 = 3
	  LSETUP(ST_ATAN2,END_ATAN)LC0 = P0;
ST_ATAN2:   R3.H = R3.L * R0.L;
	    A0 += R1.L * R0.L || R1.L = W[I0++];
	    R0.L = R3.L * R3.H;
END_ATAN:   A0 += R1.L * R3.H || R1.L = W[I0++];

	  R2 = (A0 += R1.L * R0.L);
	  R2.L = R2(RND);                // ROUND R2 
	  R2 =  R2.L(X);                 // SIGN EXTEND R2
	  R1 = 0X4000;                   // 0.5 IN FRACT16 
	  R1 = R1 - R2;                  // 0.5 - RESULT (COMPLEMENTARY ANGLE)
	  CC = R5;                       // CONDITION |Y| < |X| 
	  IF !CC R2 = R1;                // RESULT = 0.5 - RESULT 
EQUAL:    CC = R7 < 0;                   // CHECK IF X < 0 
	  R1 = 0X7FFF;                   // 1 IN FRACT16 
	  R1 = R1 - R2;                  // 1 - RESULT (180 - ANGLE)
	  IF CC R2 = R1;                 // IF TRUE, RESULT = 1 - RESULT
	  R1 = -R2;                      // -RESULT 
	  CC = R6 < 0;                   // CHECK IF Y < 0
	  IF CC R2 = R1;                 // IF TRUE COMPLEMENTED RESULT
	  R0 = R2.L (X);                 // EXTEND INTO RETURN REGISTER 
	  (R7:5) = [SP++];               // POP R7-R5
	  RTS;

RET_ZERO: CC = R6 == 0;                  // CHECK IF Y IS ZERO 
	  IF CC JUMP Y_IS_ZERO;          // IF TRUE JUMP 

	  R0 = 0X4000;                   // 0.5 IN FRACT16 (90 DEGREE)
	  R1 = -R0;                      // -0.5  
	  CC = R6 < 0;                   // CHECK IF Y < 0 
	  IF CC R0 = R1;                 // IF TRUE RESULT = -0.5 ELSE 0.5 
	  JUMP RET;                      // RETURN 

Y_IS_ZERO:  
	  R1 = 1;
	  R1 <<= 15;                     // 0X8000 - -1 IN FRACT16 
					 // (-180 DEGREES)
	  R0 = R7 & R1;                  // IF Y = 0, THEN IF X < 0, 
					 // RESULT = 0X8000, ELSE 0  
RET:      R0 = R0.L (X);                 // ENSURE RESULT IS SIGN-EXTENDED
	  (R7:5) = [SP++];               // POP R7-R5
	  RTS;

.__atan2_fr16.end: 

.extern  __div16;

