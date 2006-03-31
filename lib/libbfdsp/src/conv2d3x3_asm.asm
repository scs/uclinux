/******************************************************************************
  Copyright(c) 2000-2004 Analog Devices Inc. IPDC BANGALORE, India.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 ******************************************************************************

  File Name    : conv2d3x3.asm
  Module Name  : Two dimensional Circular Convolution
  Label name   :  __conv2d3x3_fr16
  Description  : This file contains two dimension circular convolution of a
		 given sequence with 3x3 matrix.

		 The whole implementation is in Assembly language for BLACKFIN
		 Processor. In this implementation circular convolution of two
		 matrices `a` and `b` is calculated. The dimension of 'a' is
		 na x ma and that of 'b' is 3 x 3. The dimension of the output
		 matrix c will na x ma.

		 The innermost loop has been unrolled to address Anomaly#38
		 of the ADSP-BF532.

		 There is no restriction on the size array A. The whole
		 implementation is for 16 bit fract input output. The format of
		 representation is 1Q15 format.
		 All the input buffer variables are in different memory bank.

Cycle count :
		3033 cycles (for na x ma = 5 x 7 with 3x3 window )
	       12753 cycles (for na x ma = 10x15 with 3x3 window )

Code size   :  172 bytes

******************************************************************************/

.text;
.global        __conv2d3x3_fr16;
.align         2;

__conv2d3x3_fr16:

    /******************** Function Prologue **************************/
	[--SP] = (R7:4, P5:5);
	P0 = 0x3;
	P1 = R1;              // Rows in array A
	P2 = R2;              // Columns in array A
	R4 = R2 << 1;
	R1 = [SP+32];         // Address of B
	R2 = [SP+36];         // Address of C

	CC = P1 <= 0;         // Terminate if dimension of matrix A <= 0
	If CC Jump Terminate;
	CC = P2 <= 0;
	If CC Jump Terminate;

	P5 = R1;             // Address of B
	I2 = R2;
	[SP + 32] = P1;      // Number of rows in array A
	I1 = R1;
	I2 = R2;

	L3 = R4;             // Storage area for (Columns << 1)
	B3 = R0;             // Storage area for Address of array A
	R6 = 1;              // Set R6 to 1 (to enable increments in
			     //     multi-issue instructions)

/**************************************************************************/
	R1 = -1;             // Counter for number of rows of A say i
Loop_na:
	R2 = -1;             // Counter for number of columns of A say j

	lsetup (L1strt, L1end) LC0 = P2;

L1strt:
	I1 = P5;             // I1 stores the address of A
	R3 = R1;
	A0 = 0;

	lsetup (L2strt, L2end) LC1 = P0;
			     // Loopset for counter 3
L2strt:
	B0 = B3;             // Circular addressing for number of rows
		    //The implementation for 2d circular array
	M0 = R3;             // M0 stores the address offset.
	L0 = P1;             // L0 stores the number of rows
	I0 = B0;             // I0 points to the address of A
	R7 = B0;
	I0 += M0;            // It will modify the content of I0
	R5 = I0;
	R5 = R5 - R7;        // Take the difference in modified content and base
	R5.L = R5.L * R4.L (IS) || R0.H = W[I1++];
			     // PRELOAD R0.h for convolution calculation
	R7 = R7 + R5;
	I0 = R7;             // I0 holds the new address modified on the basis
	R7 = R2 << 1 || R0.L = W[I1++];
			     // PRELOAD R0.l for convolution calculation
	M0 = R7;
	B0 = I0;             // of circular addressing on rows. B0 holds I0.
	L0 = L3;             // Circular addressing on number of columns.
	I0 += M0 || R5.H = W[I1++];
			     // PRELOAD R5.h for convolution calculation
	R3 = R3 + R6 (NS) || R5.L = W[I0++];
			     // Increment R3 by 1,
			     // PRELOAD R5.l for convolution calculation

    /* Convolution Calculation:
    ** (note that R0.h, R0.l, and R5.h have already been preloaded from array A)
    */
	    R7.L = (A0 += R0.H * R5.L) || R5.L = W[I0++];
	    R7.L = (A0 += R0.L * R5.L) || R5.L = W[I0++];
L2end:      R7.L = (A0 += R5.H * R5.L);

L1end:  R2 = R2 + R6 (NS) || W[I2++] = R7.L;
			     // Increment j by 1,
			     // The value is stored back on C array.

	R1 = R1 + R6 (NS) || R5 = [SP + 32];
			     // Increment i by 1,
			     // Load number of rows in array A
	R5 += -1;
	CC = R1 < R5;        // Counter checking for i loop
	If CC Jump Loop_na (BP);

Terminate:
	(R7:4, P5:5) = [SP++];
	L0 = 0;
	L3 = 0;
	RTS;                 // Return

.__conv2d3x3_fr16.end:
