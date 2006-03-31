/*****************************************************************************
Copyright(c) 2000-2004 Analog Devices Inc.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

******************************************************************************
  File Name      : autocoh_fr16.asm
  Include File   : stats.h
  Label Name     : __autocoh_fr16

  Description    : This function computes the autocoherence 
		   of input elements contained within input vector a 
		   and stores the result to output vector c.

  Operand        : R0 - Input array, 
		   R1 - Number of elements in Input array, 
		   R2 - Lag count
		   Stack - Output Array

  Registers Used : R0-3, R6-7, I0-I2, P0-P3

  Cycle Count    : n = 40, lag = 10:  1660 Cycles
		   (BF532, Cycle Accurate Simulator)
  Code Size      : 180 Bytes
******************************************************************************/

.text;
.global   __autocoh_fr16;

.align 2;
__autocoh_fr16:
		   CC = R1 <= 0;            // CHECK NUMBER OF ELEMENTS <= 0
		   IF CC JUMP RET_ZERO;     // IF TRUE, TERMINATE 
		   
		   CC = R2 <= 0;            // CHECK LAG COUNT <= 0  
		   IF CC JUMP RET_ZERO;     // IF TRUE, TERMINATE
		    
		   [--SP] = R7;             // PUSH R7 ONTO STACK 
		   [--SP] = R6;             // PUSH R6 ONTO STACK
		   [--SP] = RETS;           // PUSH RETS REGISTER ONTO STACK
		   [--SP] = R0;
		   [--SP] = R1;
		   [--SP] = R2;

		   R0 = 1;               
		   CALL.X __divfract32;       // CALCULATE 1/N
		  
		   R7 = 0;
		   R7.L = R0(RND) || P0 = [SP++]; 
					    // ROUND 1/N VALUE AND
					    // SET LOOP COUNTER TO LAG NUMBER

		   R0 <<= 1;                // CONVERT 1/N VALUE TO 1.31 FORMAT
		   R1 = R1 -|- R1 || P1 = [SP++];
					    // ZERO R1 AND
					    // SET LOOP COUNTER TO N
		   R1.L = R0(RND) || R2 = [SP++];  
					    // ROUND 1/N VALUE AND           
					    // GET ADDRESS OF INPUT ARRAY
		   I0 = R2;      
		   I3 = R2;          
		   L0 = 0;
		   L3 = 0;
		   P2 = R2;                

		   R0 = R0 -|- R0 || R2 = [SP+24]; 
					    // ZERO R0 AND           
					    // GET ADDRESS OF OUTPUT ARRAY
		   I1 = R2;              
		   L1 = 0;

		   // MEAN = MEAN + X[i] * 1/N
		   A1 = A0 = 0 || R3 = W[P2++](Z);
		   LSETUP( MEAN_START, MEAN_START ) LC0 = P1;
MEAN_START:          R2 = (A0 += R7.L * R3.L) || R3 = W[P2++](Z);

		   P2 = I0;                 // RESEST POINTER TO INPUT ARRAY
		   R0.L = R2(RND);

		   R6 = 0;
		   R6.L = (A0 = R0.L * R0.L); 
					    // MEAN * MEAN

		   L2 = 0;
		   // LOOP FOR LAG COUNT TIMES (i)
		   LSETUP( CO_START, CO_END ) LC1 = P0;
CO_START:            I2 = P2;               // ADDRESS TO GET VALUE  A[j+i]
		     R0 = 0;                // CLEAR R1 TO STORE SUM
		     /* MULTI SLOT NOT USED TO AVOID DCache Bank Collision */
		     R7.L = W[I0++];
		     R2.L = W[I2++];        // GET VALUE OF A[j+i]

		     // LOOP FOR N TIMES (j)
		     LSETUP( CORR_START, CORR_END ) LC0 = P1; 
CORR_START:            R3.L = R7.L * R2.L || R7.L = W[I0++];
					    // MULTIPLY PREVIOUS INPUT 
					    // AND FETCH THE NEXT ONE
		       R3 = R3.L (X);       // SIGN EXTENDED THE RESULT
CORR_END:              R0 = R0 + R3(NS) || R2.L = W[I2++];
					    // SUM THE RESULT 
					    // AND FETCH NEXT DATA
		    
		     R0 *= R1;              // SUM * (1/N)
		     R0.L = R0(RND);        // ROUND THE RESULT TO 16 BIT
		     R0 = R0 - R6(NS) || R7 = W[P2++] (Z);
					    // R0=FINAL RESULT AND DUMMY FETCH 
					    // TO INCREMENT THE POINTER
		     W[I1++] = R0.L;        // STORE THE RESULT TO OUTPUT ARRAY
		     P1 += -1;              // DECREMENT THE INEER LOOP COUNTER 
CO_END:              I0 = I3;               // GET THE BASE ADDRESS 
					    // FOR THE NEXT ITERATION 

		   RETS = [SP++];           // POP RETS REGISTER FROM STACK
		   R6 = [SP++];             // POP R6 FROM STACK
		   R7 = [SP++];             // POP R7 FROM STACK

RET_ZERO:          RTS;

.__autocoh_fr16.end:

.extern __divfract32;

