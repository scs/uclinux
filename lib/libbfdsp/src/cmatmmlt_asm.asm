/******************************************************************************
  Copyright(c) 2000-2004 Analog Devices Inc.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 ******************************************************************************
  File Name      : cmatmmlt_asm.asm
  Include File   : matrix.h
  Label Name     : __cmatmmlt_fr16

  Description    : This function computes the product of two complex
		   matrices A[n][k] and B[k][m] and stores the result
		   in matrix C[n][m].

  Operand        : R0 - Address input matrix A
		   R1 - Number of rows in matrix A
		   R2 - Number of columns in matrix A
		   Stack1 - Address input matrix B
		   Stack2 - Number of columns in matrix B
		   Stack3 - Address output matrix C

  Registers Used : R0-3, R6-7, P0-2, I0-2, M0-2

  Cycle Count    : 54 + (Ar * (10 + (Bc * (5 + (2 * Ac)))))
			where Ar are the rows in A
			      Ac are the columns in A (= rows in B)
			      Bc are the columns in B

		  (measured for a ADSP-BF532 using version 3.5.0.21 of
		   the ADSP-BF53x Family Simulator and includes the
		   overheads involved in calling the library procedure
		   as well as the costs associated with argument passing)

		   For example: 479 cycles for A[5][5] * B[5][5] 

  Code Size      : 120 Bytes.
******************************************************************************/

#if defined(__ADSPLPBLACKFIN__) && defined(__WORKAROUND_AVOID_DAG1)
#define __WORKAROUND_BF532_ANOMALY38__
#endif

.text;
.global   __cmatmmlt_fr16;

.align 2;
__cmatmmlt_fr16:

		   [--SP] = (R7:6);
		   I0 = R0;                 // Address input matrix A
		   P1 = [SP+20];            // Address input matrix B
		   R3 = [SP+28];            // Address output matrix C
		   I2 = R3;

		   R0 = R1;                 // Check if n, k, m are all zero
		   R0 *= R2;
		   R3 = [SP+24];            // Columns matrix B
		   R0 *= R3;
		   CC = R0 == 0;
		   IF CC JUMP MLT_STOP;     // If n, k, m are all zero terminate

		   P0 = R2;
		   P2 = R3;
		   R0 = R2 << 2;            // Compute the space required for
					    // one row of input matrix A
		   R0 += 4;
		   M0 = R0;
		   R2 += 1;
		   R0 = R3 << 2;            // Compute the space required for
					    // one row of input matrix B
		   M2 = R0;
		   R0 *= R2;
		   R0 = -R0;
		   R0 += 4;
		   M1 = R0;

		   R6 = -1;

REPEAT:            I1 = P1;                 // Address input matrix B

#if defined(__WORKAROUND_BF532_ANOMALY38__)

	       /* Start of BF532 Anomaly#38 Safe Code */

		   LSETUP( PROD_OUT_ST, END_PROD_OUT ) LC0 = P2;
PROD_OUT_ST:         A1 = A0 = 0 || R0 = [I0++];
		     R7 = [I1++M2];

		     LSETUP (CVDOTST,CVDOTEND) LC1 = P0;
CVDOTST:               R3 = (A1 += R0.H * R7.L), R2 = (A0 += R0.L * R7.L);
		       R3 = (A1 += R0.L * R7.H), R2 = (A0 -= R0.H * R7.H)
			    || R0 = [I0++];
CVDOTEND:              R7 = [I1++M2];

#else          /* End of BF532 Anomaly#38 Safe Code */

		   // Set loop for Row-Column fetch
		   LSETUP( ST_PROD_OUT, END_PROD_OUT ) LC0 = P2;
ST_PROD_OUT:         A1 = A0 = 0 || R0 = [I0++] || R7 = [I1++M2];

		     // Set loop for Row-Column multiplication
		     //     (C1 + jC2) = ( A1[] +jA2[] ).( B1[] + jB2[] )
		     //      C1 = Sum( A1[i]*B1[i] - A2[i]*B2[i] )
		     LSETUP (CVDOTST,CVDOTEND) LC1 = P0;
CVDOTST:               R3 = (A1 += R0.H * R7.L), R2 = (A0 += R0.L * R7.L);
CVDOTEND:              R3 = (A1 += R0.L * R7.H), R2 = (A0 -= R0.H * R7.H)
			    || R0 = [I0++] || R7 = [I1++M2];

#endif        /* End of Alternative to BF532 Anomaly#38 Safe Code */


		     R0.L = R2(RND);
		     R0.H = R3(RND) || I1+=M1;
END_PROD_OUT:        [I2++] = R0 || I0 -= M0;
					    // Save result in output matrix C

		   I0 += M0;
		   R1 = R1 + R6 (NS) || I0 -= 4;
					    // Move I0 by M0 - 4 and
					    // Decrement R1 by 1
		   CC = R1 <= 0;
		   IF !CC JUMP REPEAT (BP); // Iterate for Number of rows in
					    // matrix A

MLT_STOP:
	   (R7:6) = [SP++];
		   RTS;

.__cmatmmlt_fr16.end:
