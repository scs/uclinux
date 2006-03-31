/*****************************************************************
    Copyright(c) 2000-2004 Analog Devices Inc. IPDC BANGALORE, India.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 *****************************************************************                

    File name   :   transpm_fr16.asm  
    Module name :   Matrix transposition
    Label name  :   __transpm_fr16.asm 
    Description :   This program finds the transpose of the input matrix of order n x m.  
     

    Registers used   :   
    R0 - Starting address of the input matrix       (16 bits)
    R1 - Number of rows in the input matrix         (32 bits)
    R2 - Number of columns in the input matrix      (32 bits)

    Other registers used:
    R0 to R3, I0, I1, P0 to P2 & P5 

    Note            :   The input and output matrices have to be declared
			in two different data memory banks to avoid data 
			bank collision.

    Cycle count     :   75 cycles   (Matrix size - 4 x 6)

    Code size       :   72 bytes
Modified on 26.3.2001 for L regs. initialization
 *******************************************************************/   

.text;
.align 2;
.global __transpm_fr16;
__transpm_fr16:

		P0 = R0;                                    // Store the address of the input matrix
		R3 = [SP+12];                               // Fetch the address of the output matrix
		I1 = R3;                                    // Store the address of the output matrix
		L1=0;
		R0 = R2;
		R0 *= R1;               
		CC = R0 == 0;                               // Terminate if the number of rows or columns are zero
		IF CC JUMP FINISH;          
		CC = R0 == 1;                               // Check if rows = columns = 1
		IF CC JUMP SCALAR;                          // If TRUE branch to SCALAR
		R3 = R2 << 1;                               // Compute the space required for one row of the matrix
		P2 = R2;
		P1 = R3;                                    // Offset for fetching the column elements 
		[--SP] = P5;
		P5 = R1;
		I0 = P0;                                    // Save address
		L0=0;
		LSETUP(START_TR_OUT, END_TR_OUT) LC0 = P2;  
START_TR_OUT:       R0 =W[P0++P1](X);
		    LSETUP(START_TR_IN, START_TR_IN) LC1 = P5;
START_TR_IN:            R0 =W[P0++P1](X) || W[I1++] = R0.L; // Fetch and store the column elements one by one 
		I0+=2;                                      // Point to the next column                                     
END_TR_OUT:     P0 = I0;                                    // Offset computation for pointing the next column
		P5 = [SP++];                
FINISH:         RTS;        
SCALAR:         R0 = W[P0++] (Z);                               // If rows = columns = 1
		W[I1++] = R0.L;                             // Put the input in the output
		RTS;
.__transpm_fr16.end:
	    
	
