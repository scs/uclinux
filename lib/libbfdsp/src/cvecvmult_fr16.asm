/*****************************************************************
Copyright(c) 2000-2004 Analog Devices Inc. IPDC BANGALORE, India.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 *****************************************************************  

    File name   : cvecvmult_fr16.asm  
    Module name : Complex vector - vector multiplication
    Label name  :  __cvecvmlt_fr16
    Description : This program multiplies two 16 bit vectors element by element 

    Registers used :   

	R0 - Starting address of the first 16 bits input vector
	R1 - Starting address of the second 16 bits input vector
	R2 - Starting address of the 16 bits output vector

	Other registers used:
	R0 to R3, I0, I1 & I2

	Note: The two input vectors have to be declared in two 
	      different data memory banks to avoid data bank collision.

	Cycle count: 94 cycles (Vector length - 25)

	Code size  : 76 bytes

 *******************************************************************/

.text;
.align 2;
.global __cvecvmlt_fr16;
__cvecvmlt_fr16:

	I0 = R0;                            // Store the address of the first input vector 
	I1 = R1;                            // Store the address of the second input vector 
	I2 = R2;                            // Store the address of the output vector 
	R2 = [SP+12];                       // Fetch the size of the vector from the stack 
	CC = R2 <= 0;                       // Check if the vector length is negative or zero 
	IF CC JUMP FINISH;                  // Terminate if the vector length is zero 
	P0 = R2;                            // Set loop counter
	R0 = [I0++];                        // Fetch 1st element from first vector
	R1 = [I1++];                        // Fetch 1st element from second vector
	R2.H = R0.H*R1.L, R2.L = R0.L*R1.L; // Compute the multiplication of the first elements of the vectors
	R3.H = R0.L*R1.H, R3.L = R0.H*R1.H || R0 = [I0++];
	R2 = R2 +|- R3 || R1 = [I1++];

	LSETUP(vs_start, vs_end) LC0 = P0;
vs_start:   R2.H = R0.H*R1.L, R2.L = R0.L*R1.L || [I2++] = R2; // (C1[i] + jC2[i]) = ( A1[i] +jA2[i] )*( B1[i] + jB2[i] ) 
	    R3.H = R0.L*R1.H, R3.L = R0.H*R1.H || R0 = [I0++]; // C1[i] = A1[i]*B1[i] - A2[i]*B2[i] 
vs_end:     R2 = R2 +|- R3 || R1 = [I1++];                     // C2[i] = A1[i]*B2[i] + A2[i]*B1[i] 

FINISH:
	RTS;

.__cvecvmlt_fr16.end:
