/*****************************************************************************
Copyright(c) 2000-2004 Analog Devices Inc.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

******************************************************************************
  File Name      : crosscoh_fr16.asm
  Include File   : stats.h
  Label Name     : __crosscoh_fr16

  Description    : This function computes the cross-coherence of two input
		   vectors A and vector B and stores the result in vector C.

  Operand        : R0 - Address of array A, 
		   R1 - Address of input array B, 
		   R2 - Number of input elements
		   Stack - Lag count
		   Stack - Address of out array C

  Registers Used : R0-7, I0-I3, P0-2.

  Cycle Count    : n = 40, lag = 10:  1585 Cycles
		  (measured for a ADSP-BF532 using version 3.5.0.21 of
		   the ADSP-BF53x Family Simulator and includes the
		   overheads involved in calling the library procedure
		   as well as the costs associated with argument passing)

  Code size      : 198 bytes
******************************************************************************/
.text;

.global   __crosscoh_fr16;
.extern   __divfract32;

.align 2;
__crosscoh_fr16:    
		   [--SP] = (R7:4);         // PUSH R4-7 ONTO STACK
		   [--SP] = RETS;           // PUSH RETS REGISTER ONTO STACK
		   [--SP] = R0;
		   [--SP] = R1;
		   [--SP] = R2;

		   R7 = [SP+44];            // GET LAG COUNT
		   CC = R7 <= 0;            // CHECK LAG COUNT <= 0
		   IF CC JUMP ERROR_RETURN; // IF TRUE, TERMINATE

		   CC = R2 <= 0;            // CHECK NUMBER OF ELEMENTS <= 0
		   IF CC JUMP ERROR_RETURN; // IF TRUE, TERMINATE

		   R1 = R2;
		   R0 = 1;
		   CALL.X __divfract32;       // CALCULATE 1/N

		   I2 = R7;                 // SAVE LAG NUMBER
		   R6 = 0;
		   R6.L = R0(RND) || P2 = [SP++];
					    // ROUND 1/N VALUE AND
					    // SET LOOP COUNTER TO N

		   R0 <<= 1;                // CONVERT 1/N VALUE TO 1.31 FORMAT
		   R1 = R1 -|- R1 || R2 = [SP++];
					    // ZERO R1 AND
					    // GET ADDRESS OF INPUT ARRAY B
		   I3 = R2;
		   P0 = R2;

		   R1.L = R0(RND) || R2 = [SP++];
					    // ROUND 1/N VALUE AND
					    // GET ADDRESS OF INPUT ARRAY A
		   I0 = R2;
		   P1 = R2;

		   R0 = R0 -|- R0 || R2 = [SP+36];
					    // ZERO R0 AND
					    // GET ADDRESS OF OUTPUT ARRAY
		   I1 = R2;

		   // MEAN = MEAN + X[i] * 1/N
		   R7 = R7 -|- R7 || R3 = W[P1++](Z);
		   A1 = A0 = 0 || R4 = W[P0++](Z);
		   LSETUP( MEAN_START, MEAN_END ) LC0 = P2;
MEAN_START:          R2 = (A0 += R6.L * R3.L) || R3 = W[P1++](Z);  // MEAN A
MEAN_END:            R5 = (A1 += R6.L * R4.L) || R4 = W[P0++](Z);  // MEAN B

		   P0 = I2;                 // SET LOOP COUNTER TO LAG NUMBER
		   P1 = I0;                 // RESEST POINTER TO INPUT ARRAY A
		   
		   R0.L = R2(RND);
		   R7.L = R5(RND);

		   R6 = 0;
		   R6.L = (A0 = R0.L * R7.L);
					    // MEAN A * MEAN B

		   // LOOP FOR LAG COUNT TIMES (i)
		   LSETUP( CO_START, CO_END ) LC1 = P0; 
CO_START:            R0 = R0 - R0 (NS) || R7.L = W[I0++];
					   // ACCUMULATE SUM IN R0
					   // FETCH VALUE OF A[i]
		     I2 = I3;              // ADDRESS TO GET VALUE B[j+i]
		     R2.L = W[I2++];       // FETCH VALUE B[j+i]

		     // LOOP FOR N TIMES (j)
		     LSETUP( CORR_START, CORR_END ) LC0 = P2;
CORR_START:            R3.L = R7.L * R2.L || R7.L = W[I0++]; 
					   // MULTIPLY THE PREVIUS VALUE 
					   // AND FETCH NEXT VALUES
		       R3 = R3.L (X);      // GET SIGN EXTENDED
CORR_END:              R0 = R0 + R3(NS) || R2.L = W[I2++];              
					   // ACCUMULATE SUM IN R0

		     R0 *= R1;             // SUM * (1/N)
		     R0.L = R0(RND);       // ROUND THE RESULT TO 16 BIT
		     R0 = R0 - R6(NS)|| R7.L = W[I3++];
					   // GET THE RESULT IN R0 AND 
					   // DUMMY FETCH TO INCREMENT POINTER
		     W[I1++] = R0.L;       // STORE RESULT IN OUTPUT ARRAY
		     P2 += -1;             // DEREMENT THE INNER LOOP COUNTER
CO_END:              I0 = P1;              // GET THE BASE ADDRESS OF A 
					   // FOR THE NEXT ITERATION

RET_RETURN:        RETS = [SP++];
		   (R7:4) = [SP++];        // POP RETS, R7-R4 FROM STACK
		   RTS;

ERROR_RETURN:      SP += 12;               // NEED TO ADJUST SP =>
					   // 2 MISSED READS FROM STACK
		   JUMP RET_RETURN;

.__crosscoh_fr16.end:
