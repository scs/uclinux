/*****************************************************************************
Copyright(c) 2000-2004 Analog Devices Inc.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

******************************************************************************
  File Name      : autocorr_fr16.asm
  Include File   : stats.h
  Label Name     : __autocorr_fr16

  Description    : This function computes autocorrelation of input vector A,
		   and stores result to output vector C. 

  Operand        : R0 - Input array, 
		   R1 - Number of elements in input array, 
		   R2 - Lag count
		   Stack - Output Array

  Registers Used : R0-R3, R7, I0-I3, P0-P2.

  Cycle Count    : n = 20, lag = 10:  884 Cycles  
		   (BF532, Cycle Accurate Simulator)
  Code Size      : 126 Bytes
******************************************************************************/
.text;
.global   __autocorr_fr16;

.align 2;
__autocorr_fr16:
		   CC = R1 <= 0;           // CHECK  NUMBER OF ELEMENTS <=0
		   IF CC JUMP RET_ZERO;    // IF TRUE, TERMINATE

		   CC = R2 <= 0;           // CHECK LAG COUNT <=0
		   IF CC JUMP RET_ZERO;    // IF TRUE, TERMINATE

		   [--SP] = R7;            // PUSH R7 ONTO STACK
		   [--SP] = RETS;          // PUSH RETS, R2 ONTO STACK
		   [--SP] = R0;
		   [--SP] = R1;
		   [--SP] = R2;

		   R0 = 1;
		   CALL.X __divfract32;      // CALCULATE 1/N

		   R1 = R1 -|- R1 || P0 = [SP++];            
					   // ZERO R1 AND
					   // SET LOOP COUNTER TO LAG COUNT
		   P1 = [SP++];            // SET LOOP COUNTER TO N

		   R0 <<= 1;         
		   R1.L = R0(RND) || R2 = [SP++]; 
					   // CONVERT TO 1.31 FORMAT        
					   // AND GET ADDRESS INPUT ARRAY
		   P2 = R2;
		   I0 = R2;
		   I3 = R2;
		   L0 = 0;
		   L3 = 0;

		   R2 = [SP+20];           // ADDRESS OUTPUT ARRAY
		   I1 = R2;          
		   L1 = 0;

		   L2 = 0;
		   // LOOP FOR LAG COUNT TIMES (i)
		   LSETUP( AUTO_START, AUTO_END ) LC1 = P0;
AUTO_START:          R0 = 0;               // CLEAR R0 TO STORE SUM
		     I2 = P2;              // ADDRESS TO GET VALUE OF A[j+i]
		     /* FETCHED SEPERATLY TO AVOID DCACHE BANK COLLUSION 
			since both  i0 and i2 are pointing to same bank */
		     R7.L = W[I0++];       // VALUE OF A[j]
		     R2.L = W[I2++];       // VALUE OF A[j+i]

		     // LOOP FOR N TIMES (j)
		     LSETUP( ACORR_START, ACORR_END ) LC0 = P1;
ACORR_START:           R3.L = R7.L * R2.L || R7.L = W[I0++]; 
					   // DO MULTIPLICATION 
					   // AND FETCH NEXT DATA
		       R3 = R3.L (X);      // GET SIGN EXTENDED
ACORR_END:             R0 = R0 + R3 (NS)|| R2.L = W[I2++];  
					   // STORE THE SUM
	       
		     R0 *= R1;             // SUM * (1/N)
		     R0.L = R0(RND) || R7 = W[P2++](Z);
					   // R0=FINAL RESULT AND DUMMY FETCH
					   // TO INCREMENT THE POINTER
		     W[I1++] = R0.L;       // INCREMENT TO HAVE N-i LOOP
		     P1 += -1;
AUTO_END:            I0 = I3;              // GET THE BASE ADDRESS 
					   // FOR THE NEXT ITERATION 
		   
		   RETS = [SP++];          // POP RETS, R7 FROM STACK
		   R7 = [SP++];            

RET_ZERO:          RTS;                    // RETURN

.__autocorr_fr16.end:

.extern __divfract32;


