/******************************************************************************
  Copyright(c) 2000-2004 Analog Devices Inc.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

******************************************************************************
  File Name      : var_fr16.asm
  Include File   : stats.h
  Label Name     : __var_fr16

  Description    : This function calculates the variance of the data
		   contained in the input array a[]:

		   variance =
			   (n*sum(a[i]*a[i]) -(sum(a[i])*sum(a[i]))/(n*(n-1))

		   Alternative formula used:

		   variance =
		      ((n*sum(a[i]*a[i]))/n - n*(sum(a[i]/n)*sum(a[i]/n))/(n-1)
			    =
		      (sum(a[i]*a[i]) - n*(sum(a[i]/n)*sum(a[i]/n))/(n-1)

  Operand        : R0 - Address of input array A,
		   R1 - Number of samples

  Registers Used : R0-R3, I0, P0, P1, A0, A1

  Cycle count    : 25                  N == 0
		   510 + (2 * N)       for other N (Number of samples)
		  (measured for a ADSP-BF532 using version 3.5.0.21 of
		   the ADSP-BF53x Family Simulator and includes the
		   overheads involved in calling the library procedure
		   as well as the costs associated with argument passing)

  Code size      : 78 Bytes
******************************************************************************/

.text;
.global   __var_fr16;

.extern ___div32;

.align 2;
__var_fr16:
	CC = R1 <= 1;
	IF CC JUMP VAR_RETURN;         // EXIT IF NO. ELEMENTS <= 1

	I0 = R0;                       // ADDRESS INPUT ARRAY
	P1 = R1;                       // SET LOOP COUNT TO N

     /* Compute the reciprocal of N in fractional 1.15 format */

	R0 = 1;                        // SET NUMERATOR
	P0 = 15;                       // LOOP COUNTER TO PERFORM DIVQ 15 TIMES
	R0 <<= 16;                     // ARRANGING FOR PROPER DIVISION.
	DIVS (R0, R1);                 // CALL DIVS TO CLEAR AQ FLAG

	LSETUP( DIV_START, DIV_START ) LC0 = P0;

DIV_START:  DIVQ (R0, R1);             // DIVQ IS PERFORMED 15 TIMES

     /* Compute Variance
     **
     **     A0 = A0 + A[i] * 1/N
     **     A1 = A1 + A[i] * A[i]
     */
	A1 = A0 = 0 || R1.L = W[I0++];
	LSETUP( VAR_START, VAR_END ) LC0 = P1;

VAR_START:  R2 = (A0 += R1.L * R0.L);
VAR_END:    A1 += R1.L * R1.L || R1.L = W[I0++];

	R2 >>= 16;
	R1 = P1;

	R2.L = R2.L * R2.L;
	A1 = A1 >> 16;
	R2.L = R1.L * R2.L(IS);        // R2 = N * MEAN(A)^2
	R3 = A1;                       // R3 = SUM(A^2)

	R0 = R3 - R2(NS);              // DIFF SUMS R3 AND R2
				       // (= NUMERATOR)

	R1 += -1;                      // DENOMINATOR = N-1
	JUMP.X ___div32;                 // COMPUTE (DIFF SUMS) / (N-1)
				       // USING 32-BIT DIVISION

	// Note that ___div32 performs the return to the caller

     /* Return Zero if N <= 1 */

VAR_RETURN:
	R0 = 0;
	RTS;

.__var_fr16.end:
