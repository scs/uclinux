/******************************************************************************
  Copyright(c) 2000-2004 Analog Devices Inc.  

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

******************************************************************************
  File Name      : mean_fr16.asm
  Include File   : stats.h
  Label name     : __mean_fr16
 
  Description    : This function calculates the mean value of an array
		      mean=1/N(x1+x2........+xn). 

		   It is implemented as
		      mean=x1*(1/N) + x2*(1/N)..........+xn*(1/N)

  Operand        : R0 - Address of input array X, 
		   R1 - Number of samples

  Registers Used : R0-2, A0, P3-4

  Cycle count    : 60 + Number of samples
		   n = 20: 80 Cycles  (BF532, Cycle Accurate Simulator)
  Code size      : 58 Bytes
******************************************************************************/

.text;
.global  __mean_fr16;

.align 2;
__mean_fr16:

		   CC = R1 <= 0;           // EXIT IF NUMBER OF SAMPLES <=0 
		   IF CC JUMP RET_ZERO;
  
		   [--SP] = P3;            // PUSH REGISTERS ONTO STACK
		   [--SP] = P4;          
		   [--SP] = RETS;          // PUSH RETS ONTO STACK

		   P3 = R0;                // ADDRESS INPUT ARRAY X 
		   P4 = R1;                // SET LOOP COUNTER TO N
		   R0 = 0x1;               // SET NUMERATOR

		   CALL.X __div16;           // COMPUTE 1/N USING 16-BIT DIVISION
	 
		   RETS = [SP++];          // POP RETS FROM STACK

		   // MEAN = MEAN + X[i] * 1/N
		   A1 = A0 = 0 || R1 = W[P3++](Z);    
		   LSETUP( MEAN_START, MEAN_START ) LC0 = P4;
MEAN_START:          R2 = (A0 += R1.L * R0.L) || R1 = W[P3++](Z); 

		   R0.L = R2(RND);         
		   R0 = R0.L(X);           // SIGN EXTENDING THE RESULT
	 
		   P4   = [SP++];          // POP REGISTERS FROM STACK
		   P3   = [SP++];
		   RTS;
    
RET_ZERO:          R0 = 0;                 // RETURN ZERO IF N <= 0 
		   RTS;

.__mean_fr16.end:

.extern __div16;

