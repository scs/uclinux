/*****************************************************************************
  Copyright(c) 2000-2004 Analog Devices Inc.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

******************************************************************************
  File Name      : histogram_fr16.asm
  Include File   : stats.h
  Label Name     :  __histogram_fr16

  Description    : The function counts the number of input samples that fall
		   into each of the output bins.
		   The size of the output vector is equal to the number of 
		   bins.

		   The function uses the stack as temporary output array
		   (size = number of bins + 2).

  Operands       : R0 - Address of input array A, 
		   R1 - Address of output array C,
		   R2 - Maximum value
		   Stack - Minimum value
		   Stack - Number of input samples
		   Stack - Number of bins

  Registers Used : R0-7, I1, I3, P0-3

  Cycle count    : 3018 Cycles (all input samples evenly 
				distributed accross all bins)

		   1450 Cycles (all input samples located in bin 0)
		   4586 Cycles (all input samples located in bin max)

		   n = 32, bin = 8 (BF532, Cycle Accurate Simulator)
  Code Size      : 140 Bytes
******************************************************************************/

.text;
.global   __histogram_fr16;

.extern ___udiv32;

.align 2;
__histogram_fr16:
		   [--SP] = (R7:4);        // PUSH R7-R4, P3, RETS ONTO STACK
		   [--SP] = P3;
		   [--SP] = RETS;
		   R7 = [SP+36];           // MINIMUM VALUE FOR BINS
		   P3 = [SP+40];           // NUMBER OF INPUT SAMPLES
		   R5 = [SP+44];           // NUMBER OF BINS
		   R4 = R0;                // ADDRESS OF INPUT ARRAY
		   R6 = R1;                // ADDRESS OF OUTPUT ARRAY

		   CC = P3 <= 0;           // CHECK IF INPUT SAMPLES IS ZERO
		   IF CC JUMP HISTO_RETURN;// IF TRUE, BRANCH TO RET_ZERO

		   CC = R5 <= 0;           // CHECK IF BIN VALUE IS ZERO 
		   IF CC JUMP HISTO_RETURN;// IF TRUE, BRANCH TO ZERO

		   CC = R2 <= R7;          // CHECK IF MAXIMUM < MINIMUM 
		   IF CC JUMP HISTO_RETURN;// IF TRUE, BRANCH TO RET_ZERO


		   R0 = R2 - R7 (NS);      // RANGE = MAX. BIN - MIN. BIN
		   R1 = R5;                // NUMBER OF BINS
		   CALL.X ___udiv32;         // SIZE/BIN = RANGE/NUMBER OF BINS

		   CC = R0 == 0;           // CHECK IF SIZE/BIN == 0 
		   IF CC JUMP HISTO_RETURN;// IF TRUE, BRANCH TO RET_ZERO

		   P2 = R5;                // SET LOOP COUNTER=NUMBER OF BIN
		   P1 = R4;                // ADDRESS OF INPUR ARRAY
		   P0 = R6;                // ADDRESS OF OUTPUT ARRAY C
		   R6 = SP;                // ADDRESS OF TEMPORARY ARRAY
		   I1 = R6;             
		   I3 = R6;
		   P2 += 2;
		   R4 = R4 -|- R4 || I1 -= 4;
		   R1 = 0;
	      
		   // LOOP FOR NUMBER OF BINS
		   LSETUP( INIT, INIT ) LC0 = P2;
INIT:                [I1--] = R1;          // INITIALISE TEMP ARRAY TO ZERO
		   
		   R1.L = 0x8000;          // MAXIMUM UPPER LIMIT
		   // LOOP FOR NUMBER OF SAMPLES
		   LSETUP( HISTO_START, HISTO_END ) LC0 = P3;
HISTO_START:         R5 = W[P1++](X);      // GET INPUT VALUE                     
		     I1 = I3;              // ADDRESS OF OUTPUT ARRAY
		     R3 = R7;              // MINIMUM VALUE OF BIN
		     R2 = P2;

ITERATE_BINS:        R2 += -1;             
		     CC = R2 == 0;         // CHECK FOR MAX BIN REACHED
		     IF CC R3 = R1;        // WILL FORCE SUBSEQUENT CC TO TRUE                     

		     CC = R5 < R3;         // CHECK IF INPUT VALUE < MAXIMUM    
					   // VALUE OF CURRENT BIN
		     R3 = R3 + R0(NS) || I1 -= 4;
					   // INCREASE MIN VALUE TO NEXT BIN
					   // AND SET POINTER TO CURRENT BIN
		     IF !CC JUMP ITERATE_BINS; 
					   // IF RIGHT BIN NOT FOUND CONTINUE

#if defined(__WORKAROUND_CSYNC) || defined(__WORKAROUND_SPECULATIVE_LOADS)
		     NOP;
		     NOP;
		     NOP;
#endif

		     R4.L = W[I1];         // GET THE PREVIOUS COUNT
		     R4 += 1;              // INCREMENT THE COUNT
HISTO_END:           W[I1] = R4.L;         // STORE INCREMENTED VALUE BACK

		   R6 += -4;
		   P3 = R6;                // POINTER TO TEMP ARRAY ON STACK
		   P2 += -2;               // SET LOOP COUNTER=NUMBER OF BIN

		   R0 = [P3--];            // COUNT BELOW MINIMUM
		   // LOOP FOR NUMBER OF BINS 
		   LSETUP( START_COPY, END_COPY ) LC0 = P2;
START_COPY:          R4 = [P3--];          // MOVE RESULT FROM STACK 
END_COPY:            [P0++] = R4;          // TO THE OUTPUT ARRAY

		   R4 = [P3];              // COUNT BEYOND MAXIMIUM
		   R0 = R0 + R4;
		   
HISTO_RETURN:      RETS = [SP++];          // POP RETS, P3, R7-R4 FROM STACK
		   P3 = [SP++];
		   (R7:4) = [SP++];        
		   RTS;

.__histogram_fr16.end:
