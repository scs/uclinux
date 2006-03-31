/*****************************************************************
    Copyright(c) 2000-2004 Analog Devices Inc. IPDC BANGALORE, India.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 *****************************************************************                

    File name   :   cvecsmlt_fr16.asm
    Module name :   Complex vector - scalar multiplication
    Label name  :   __cvecsmlt_fr16
    Description :   This program multiplies a 16 bit scalar and a 16 bit vector
     
    
    
    Registers used   :   

    R0  - Address of the input vector               
    RL1 - real part of input scalar                 (16 bits)
    RH1 - imaginary part of input scalar            (16 bits)
    R2  - No. of elements in the vector             (32 bits)
    

    Other registers used:
    R0 to R3, I0 & I1   
    
    Cycle count     :   92 cycles   (Vector length - 25)
    
    Code size       :   64 bytes
 *******************************************************************/   

.text;
.align 2;
.global __cvecsmlt_fr16;
__cvecsmlt_fr16:

	    I0 = R0;                                    // Store the address of the input vector 
	    I1 = R2;                                    // Store the address of the output vector
	    R2 = [SP+12];                               // Fetch the size of the vector from the stack 
	    CC = R2 <= 0;                               // Chech if the the vector length is negative or zero 
	    IF CC JUMP FINISH;                          // Terminate if the vector length is zero 

#if defined(__WORKAROUND_CSYNC) || defined(__WORKAROUND_SPECULATIVE_LOADS)
			NOP;
			NOP;
			NOP;
#endif

	    R0 = [I0++];                                // Store the real and imaginary parts of the input vector 
	    P0 = R2;                                    // Set loop counter
	    R2.H = R0.H*R1.L, R2.L = R0.L*R1.L;         // Do the multiplication of the first element outside the loop
	    R3.H = R0.L*R1.H, R3.L = R0.H*R1.H || R0 = [I0++];
	    R2 = R2 +|- R3;                              
	    LSETUP(vs_start, vs_end) LC0 = P0;                  // Initialize the loop and loop counter 
vs_start:   R2.H = R0.H*R1.L, R2.L = R0.L*R1.L || [I1++] = R2;  // (C1[i] + jC2[i]) = ( A1[i] +jA2[i] )*(B1 + jB2) 
	    R3.H = R0.L*R1.H, R3.L = R0.H*R1.H || R0 = [I0++];  // C1[i] = A1[i]*B1 - A2[i]*B2 
vs_end:     R2 = R2 +|- R3;                                     // C2[i] = A1[i]*B2 + A2[i]*B1
FINISH:     RTS;

.__cvecsmlt_fr16.end:
