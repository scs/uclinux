/******************************************************************************
  Copyright(c) 2000-2004 Analog Devices Inc. 

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

******************************************************************************
  File Name      : rms_fr16.asm
  Include File   : stats.h
  Label Name     : __rms_fr16
 
  Description    : This function calculates the root mean square value of 
		   an array:
		      rms = sqrt( (x1^2 + x2^2 + ........ + xn^2)/N ). 

		   Result (x1^2 + x2^2 + ........ + xn^2) in A0:
		   |--------|---------------|---------------|
		   40       32              16              1
		   A0.X     A0.W

		   In order to preserve accuracy, 
		   need to handle three different cases:
		   A) 40-bit result stored in A0.X and A0.W
		   B) 32-bit result stored in A0.W
		   C) 16-bit result stored in A0.W [BIT 1..16 only]

  Operand        : R0 - Address of input array X, 
		   R1 - Number of samples (=N)

  Registers Used : R0-4, P0-1, A0

  Cycle count    : Case A) 40 + N + CALL DIV32 + CALL SQRT_FR16
		   Case B) 47 + N + CALL DIV32 + CALL SQRT_FR16
		   Case C) 43 + N + CALL DIV32 + CALL SQRT_FR16

		   N = 20, case A):  
		   591 Cycles  (BF532, Cycle Accurate Simulator)
  Code size      : 94 Bytes 
******************************************************************************/

.text;
.global  __rms_fr16;

.extern  ___div32;
.extern  __sqrt_fr16;

.align 2;
__rms_fr16:

		   P0 = R0;                // ADDRESS INPUT ARRAY X
		   P1 = R1;                // SET LOOP COUNTER TO N
		   CC = R1 <= 1;           // EXIT IF NUMBER OF SAMPLES <=1
		   IF CC JUMP RET_SHORT;

		   [--SP] = RETS;          // PUSH RETS ONTO STACK
		   [--SP] = R4;            // PRESERVE RESERVED REGISTER

		   // RMS = RMS + ( X[i] * X[i] )
		   A1 = A0 = 0 || R2 = W[P0++](Z);    
		   LSETUP( RMS_LOOP, RMS_LOOP ) LC0 = P1;
RMS_LOOP:            A0 += R2.L * R2.L  || R2 = W[P0++](Z);
		   
		   // RESULT IN A0:
		   // |--------|---------------|---------------|
		   // 40       32              16              1
		   // A0.X     A0.W
		   //          
		   // TO PRESERVE ACCURACY, NEED TO DISTINGUISH THREE CASES:
		   // a) 40-BIT RESULT STORED IN A0.X AND A0.W
		   // b) 32-BIT RESULT STORED IN A0.W 
		   // c) 16-BIT RESULT STORED IN A0.W [BIT 1..16 ONLY]
		   R0 = A0.w;              // PRESERVE A0.W
		   R2 = A0.x;              // PRESERVE A0.X
		   R4 = 8;
 
		   A0 = A0 >> 16;          
		   CC = AZ;      
		   IF CC JUMP RMS_DO_SQRT; // C)  IF A0 = 0 AFTER SHIFT OP =>
					   // SUMMED SQUARES IN BIT 1..16 ONLY 
					   // CONTINUE WITH A0.W, NO SHIFT

		   R0 = R0 >> 8;           // SPLIT SHIFT OP FOR BEST ACCURACY
		   R4 = 4;
		   CC = R2 == 0;  
		   IF CC JUMP RMS_DO_SQRT; // B)  IF A0.X = 0 AND CASE c) DEALT 
					   // WITH => SUMMED SQRES IN BIT 1..32

		   R4 = 0;
		   R0 = A0;                // A)  AT THIS POINT: 
					   // SUMMED SQUARES IN A0:  BIT 1..40 

RMS_DO_SQRT:
		   // AT THIS POINT 40-BIT RESULT SCALED TO FIT DIVISION OP:
		   //   A) R0 = A0 >> 16;  DISCARDED 16 LEAST SIGNIFICANT BITS
		   //      R4 = 0;         => NO SUBSEQUENT SHIFT OP REQUIRED
		   //
		   //   B) R0 = A0.w >> 8; DISCARDED  8 LEAST SIGNIFICANT BITS
		   //      R4 = 4;         => NEED FURTHER SHIFT OP AFTER SQRT 
		   //
		   //   C) R0 = A0.w;      USING ACCUMULATED RESULT AS IS
		   //      R4 = 8;         => NEED SHIFT OP AFTER SQRT

		   CALL.X ___div32;        // COMPUTE SUM(A^2)/N 
		   

		   CALL.X __sqrt_fr16;     // COMPUTE SQRT(RESULT)


		   // PERFORM SECOND PART OF SCALING
		   //   A)  NO SHIFT CORRECTION REQUIRED
		   //
		   //   B)  NEED TO COMPENSATE FOR PARTIAL SHIFT OP:
		   //                   SQRT( (A0/(2^16)) / N ) = 
		   //         1/(2^4) * SQRT( (A0/(2^8 )) / N )
		   //
		   //   C)  NEED TO COMPENSATE FOR MISSING SHIFT OP:
		   //                   SQRT( (A0/(2^16)) / N ) = 
		   //         1/(2^8) * SQRT( A0 / N )
		   //  

		   R0 >>= R4; 


		   R4   = [SP++];          // RESTORE PRESERVED REGISTER
		   RETS = [SP++];          // POP RETS FROM STACK
		   RTS;

    
RET_SHORT:         CC = R1 == 1;
		   IF CC JUMP RET_SINGLE;        
		   R0 = 0;                 // RETURN ZERO IF N <= 0 
		   RTS;


RET_SINGLE:        R0 = W[P0] (Z);         // LOAD X[0] ZERO EXTENDED        
		   R0 = ABS R0 (V);        // N = 1 => SQRT(X1^2/1) = | X1 |
		   RTS;

.__rms_fr16.end:

