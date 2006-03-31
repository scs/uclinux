/*****************************************************************************
Copyright(c) 2000-2004 Analog Devices Inc.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

******************************************************************************
  File Name      : crosscorr_fr16.asm
  Include File   : stats.h 
  Label Name     : __crosscorr_fr16

  Description    : This function computes cross-correlation of two input 
		   vectors A and B, and stores the result to output vector c. 

  Operand        : R0 - Address of input array A, 
		   R1 - Address of input array B, 
		   R2 - Number of elements in array A
		   Stack - Lag count
		   Stack - Address of out array

 Registers Used  : R0-R3, R7, I0-I3, P0-P3

 Cycle Count     : n = 40, lag = 10:  1479 Cycles
		  (measured for a ADSP-BF532 using version 3.5.0.21 of
		   the ADSP-BF53x Family Simulator and includes the
		   overheads involved in calling the library procedure
		   as well as the costs associated with argument passing)

 Code Size       : 120 Bytes
******************************************************************************/

.text;

.global   __crosscorr_fr16;
.extern   __divfract32;

.align 2;
__crosscorr_fr16:
		   [--SP] = R7;            // PUSH R7, RETS ONTO STACK
		   [--SP] = RETS;         
		   R7 = [SP+20];           // GET LAG COUNT

		   CC = R2 <= 0;           // CHECK IF NUMBER OF ELEMENTS <=0
		   IF CC JUMP RET_ZERO;    // IF TRUE, TERMINATE

		   CC = R7 <= 0;           // CHECK IF LAG COUNT <=0
		   IF CC JUMP RET_ZERO;    // IF TRUE, TERMINATE

		   [--SP] = R0;
		   [--SP] = R1;
		   [--SP] = R2;

		   R0 = 1;
		   R1 = R2;
		   CALL.X __divfract32;      // CALCULATE 1/N

		   P0 = R7;                // SET COUNTER TO LAGS
		   R7 = R7 -|- R7 || P2 = [SP++];            
					   // ZERO R7 AND 
					   // SET COUNTER TO NUMBER OF ELEMENTS

		   R0 <<= 1;               // SHIFT LEFT TO GET IN 1.31 FORMAT
		   R7.L = R0(RND) || R2 = [SP++];            
					   // ROUND THE RESULT TO 16 BIT
					   // AND GET ADDRESS INPUT ARRAY B
		   I3 = R2;

		   R2 = [SP++];            // ADDRESS INPUT ARRAY A
		   I0 = R2;
		   P1 = R2;

		   R2 = [SP+24];           // ADDRESS OF OUTPUT ARRAY
		   I1 = R2;
	   
		   //LOOP FOR LAG COUNT TIMES (i)
		   LSETUP( CO_START, CO_END ) LC1 = P0;
CO_START:            R0 = R0 - R0 (NS) || R1.L = W[I0++];
					   // INITIALISE TO STORE SUM,
					   // GET ELEMENT OF ARRAY A
		     I2 = I3;              // ADDRESS TO GET VALUE B[j+i]
		     R2.L = W[I2++];       // ELEMENT OF ARRAY B

		     // LOOP FOR N TIMES  (j)
		     LSETUP( CORR_START, CORR_END ) LC0 = P2;
CORR_START:            R3.L = R1.L * R2.L || R1.L = W[I0++];
					   // MULTIPLY THE PREVIOUS INPUT 
					   // AND GET THE NEXT ONE
		       R3 = R3.L(X);       // GET SIGN EXTENDED
CORR_END:              R0 = R0 + R3(NS) || R2.L = W[I2++];
					   // STORE SUM IN R0 
					   // AND FETCH THE NEXT ELEMENT

		     R0 *= R7;             // SUM* (1/N)
		     R0.L = R0(RND) || R1.L = W[I3++];
					   // ROUND THE RESULT TO 16 BITS AND 
					   // DUMMY FETCH TO INCREMENT POINTER
		     W[I1++] = R0.L;       // STORE THE RESULT IN OUTPUT ARRAY
		     P2 += -1;             // DECREMENT THE INNER LOOP COUNTER
CO_END:              I0 = P1;              // GET THE BASE ADDRESS OF ARRAY(A)

RET_ZERO:          RETS = [SP++];          // POP R7, RETS FROM STACK
		   R7 = [SP++];      
		   RTS;

.__crosscorr_fr16.end:
