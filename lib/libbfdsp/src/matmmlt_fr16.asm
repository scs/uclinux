/*****************************************************************
    Copyright(c) 2000-2004 Analog Devices Inc. IPDC BANGALORE, India.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 *****************************************************************

    File name   :   matmmlt_fr16.asm
    Module name :   Matrix - Matrix multiplication
    Label name  :   __matmmlt_fr16
    Description :   This program computes the product of two matrices
		    of order n x k and k x m

    Registers used   :

    R0 - Starting address of matrix A
    R1 - Number of row elements in matrix A
    R2 - Number of column elements in matrix A

    Other registers used:
    R0 to R3, P0 to P2, P4 & P5, I0 & I1

    Note            :   The two input matrices have to be declared in
			two different data memory banks to avoid data
			bank collision.

    Cycle count     :   571 cycles  Dimension of matrix A - 3 x 25
				    Dimension of matrix B - 25 x 3

    Code size       :   134 bytes

 *******************************************************************/

#if defined(__ADSPLPBLACKFIN__) && defined(__WORKAROUND_AVOID_DAG1)
#define __WORKAROUND_BF532_ANOMALY38__
#endif

.text;
.align 2;
.global __matmmlt_fr16;
__matmmlt_fr16:
	[--SP] = (P5:4);
	I0 = R0;                    // Store the address of the 1st input matrix
	R3 = [SP+20];               // Fetch the address of the 2nd input matrix
	I1 = R3;
	R3 = [SP+28];               // Fetch the address of the output matrix
	I2 = R3;                    // Store the address of the output matrix
	R0 = R1;                    // Check if n, k, m are all zero or one
	R0 *= R2;
	R3 = [SP+24];               // Store the column length of the 2nd matrix
	R0 *= R3;
	CC = R0 == 0;               // If n, k, m are all zero terminate
	IF CC JUMP MLT_STOP;
	CC = R0 == 1;               // If n, k, m are all one do scalar multiplication
	IF CC JUMP MLT_SCALAR;
	P0 = R2;
	P5 = R3;
	R0 = R2 << 1;               // Compute the space required for one row of the 1st input matrix
	M1 = R0;
	R0 += 2;
	M0 = R0;
	R2 += 1;
	R0 = R3 << 1;               // Compute the space required for one row of the 2nd input matrix
	P2 = R0;
	R0 *= R2;
	R0 = -R0;
	R0 += 2;
	P4 = R0;

REPEAT:
	CC = R1 <= 0;                                       // Set loop for number of rows in the 1st matrix
	IF CC JUMP MLT_STOP;
	P1 = I1;                                            // Initialize P1 to point to the 1st element of the 2nd matrix

#if defined(__WORKAROUND_BF532_ANOMALY38__)

	/* Start of BF532 Anomaly#38 Safe Code */

	LSETUP(ST_PROD_OUT, END_PROD_OUT) LC0 = P5;         // Set loop for Row-Column fetch
ST_PROD_OUT:    A0 = 0 || R0.L = W[I0++];                   // Fetch the elements of the rows and columns
		R3.L = W[P1++P2];
		LSETUP (VDOTST,VDOTEND) LC1 = P0;           // Set loop for Row-Column multiplication
VDOTST:             R2 = (A0+=R0.L*R3.L) || R0.L = W[I0++];
VDOTEND:            R3.L = W[P1++P2];
		R0.H = R2(RND) || R3.L = W[P1++P4];         // Offset for pointing P1 to the next column
END_PROD_OUT:   W[I2++] = R0.H || I0 -= M0;                 // Store the elements of the product matrix
	I0 += M1;                                           // Offset for pointing I0 to the next row of the 1st matrix
	R1 += -1;
	JUMP REPEAT;                                        // Goto LOOP and repeat the process if required

#else   /* End of BF532 Anomaly#38 Safe Code */

	LSETUP(ST_PROD_OUT, END_PROD_OUT) LC0 = P5;         // Set loop for Row-Column fetch
ST_PROD_OUT:    A0 = 0 || R0.L = W[I0++] || R3.L = W[P1++P2];   // Fetch the elements of the rows and columns
		LSETUP (VDOTST,VDOTST) LC1 = P0;                // Set loop for Row-Column multiplication
VDOTST:             R2 = (A0+=R0.L*R3.L) || R0.L = W[I0++] || R3.L = W[P1++P2];
		R0.H = R2(RND) || R3.L = W[P1++P4];             // Offset for pointing P1 to the next column
END_PROD_OUT:   W[I2++] = R0.H || I0 -= M0;                     // Store the elements of the product matrix
	I0 += M1;                                           // Offset for pointing I0 to the next row of the 1st matrix
	R1 += -1;
	JUMP REPEAT;                                        // Goto LOOP and repeat the process if required

#endif /* End of Alternative to BF532 Anomaly#38 Safe Code */

MLT_SCALAR:
	R0.L = W[I0];               // Perform scalar multiplication if n, k, m are all unity
	R1.L = W[I1];
	R2.L = R0.L*R1.L;
	W[I2] = R2.L;

MLT_STOP:
	(P5:4) = [SP++];
	RTS;                        // Terminate and return

.__matmmlt_fr16.end:
