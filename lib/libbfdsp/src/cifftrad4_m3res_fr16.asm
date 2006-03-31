/******************************************************************************
  Copyright(c) 2000-2004 Analog Devices Inc. IPDC BANGALORE, India. 

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 ******************************************************************************
  File Name    : cifftrad4.asm
  Module Name  : one dimensional radix 4 forward IFFT for complex data.
  Label name   :  __ifftrad4_fr16
  
  Description  : The assembly function implements the radix4 IFFT DIF algorithm.
		 The input length should be an integer power of four greater than 
		 or equal to four. The twiddle factor array to be passed to the 
		 function must be initialized with cos and sine values alternately.
		 
		 The length of the twiddle factor array should be 3*MAX_N/4, 
		 where MAX_N is the length of the maximum input array for which we 
		 want to compute IFFT. For IFFT lengths less than 3*MAX_N/4, the same 
		 twiddle factor array can be used by chosing the stride factor appropriately, 
		 i.e., for an N-point IFFT where N < MAX_N, the stride factor is MAX_N/N. 
		 For IFFT length equal to MAX_N the stride factor is unity. 
		 
		 The input and the output arrays are in normal order. Input data is 
		 scaled by 4 before each stage of radix 4 fft including the first stage
		 to avoid overflow (Static scaling)
 
  Registers Used : R0 to R7, P0 to P2, P5, M0 to M2, I0 to I3, B0 & B1

    Note            :   The input and temporary buffers have to be declared in 
			two different data memory banks to avoid data 
			bank collision.


  Cycle count   :   1856 cycles (IFFT length - 64)

  Code size     :   532 bytes

  Code Modified on 11.01.2002 for removing the usuage of M3 register


******************************************************************************/


.text;
.align 2;
.global                 __ifftrad4_fr16;
__ifftrad4_fr16:
    LINK 20;
    [--SP] = (R7:4, P5:5);                      // Push the contents of R4-R7 and P5...
    R3 = [FP+28];                               // FFT length n and State initialization
    CC = R3 < 4 (IU);                           // If FFT length < 4, terminate 
    IF CC JUMP TERMINATE;
    I0 = R0;                                    // Save Input address
    I1 = R1;                                // Address of the temporary buffer
    [FP - 16] = R1;                             // Store address of temporary buffer
    B0 = R2;                                    // Address of the output
    R1 = [FP+24];                               // Stride factor
    L0 = 0;                                     // Initialize L registers
    L1 = 0;                                     //          -do-
    L2 = 0;                                     //          -do-
    L3 = 0;                                     //          -do-
    R1 = R1 << 1 || R0 = [FP+20];               // Compute (Stride factor << 1)
    B1 = R0;                                    // Address of the twiddle factor array
    P5 = R3;                                    // Save FFT length
    [FP - 12] = R1 || R0 = [I0++];
    R2 = 1;
    R0 = PACK (R0.L, R0.H); 
    R1 = R0 >>> 2 (V) || R0 = [I0++] || [FP - 4] = R2;// [FP - 4] has the no. of groups in the first stage
    R0 = PACK (R0.L, R0.H); 
    LSETUP (ST_CP, END_CP) LC0 = P5;            // Copy input array to temporary buffer
ST_CP:  R1 = R0 >>> 2 (V) || [I1++] = R1 || R0 = [I0++];// Scale the inputs by 4 to avoid overflow
END_CP: R0 = PACK (R0.L, R0.H); 

STAGE_LOOP: CC = R3 <= 4 (IU);                  // If State > 4 do LOOP, else goto LAST_STAGE
    IF CC JUMP LAST_STAGE;
    P2 = 0;                                     // Group initialization
    P1 = [FP - 4];                              // Initialize Group loop count
    R1 = [FP - 4];                              // Offset computation to fetch the twiddle factor...
    R0 = [FP - 12];                             // corresponding to the outputs of the butterfly                    
    R0 = R0.L*R1.L (IS);                        // Compute Twid_Offset = (1 << 2*Stage)(Stride factor << 1)
    R0 = R3 << 2 || [FP - 8] = R0;
    M1 = R3;                                    // Initialize Group size offset
    R1 = R3 >> 2 || [FP - 20] = R0;             // Compute Group size = (State >> 2)
    P0 = R1;                                    // Initialize butterfly loop counter
	LSETUP (ST_MIDDLE, END_MIDDLE) LC0 = P1;// Do group loop
ST_MIDDLE:R0 = P2;                              // Offset computation for fetching the... 
	R0 = R0 << 2 || R2 = [FP - 20];         // butterfly inputs of every group...
	M0 = R2;
	I3 = 0;                                 // Initialize Butterfly count for each group
	R0 = R0.L*R3.L (IS) || R1 = [FP - 16];  // Offset =4*Group*Group size offset
	R0 = R0 + R1;                           // Add Start address of each group and the Offset address
	I0 = R0;
	I1 = R0;                                // Effective address for fetching the butterfly inputs
	I2 = B1;                                // Save twiddle factor address
	I0 -= 4;
	I0 += M0;
	R0 = [FP - 8];                          // Load Twid Offset

	LSETUP (ST_BFLY, END_BFLY) LC1 = P0;    // Do butterfly loop
ST_BFLY:    R4 = [I1 ++ M1];    // Fetch the input of each butterfly in the group   
	    R1 = I3;                            // Twiddle factor array offset computation
	    R1 = R0.L*R1.L (IS) || R5 = [I1 ++ M1];// Fetch the input of each butterfly in the group    
	    M0 = R2;
	    M2 = R1;                            // Save Twiddle factor Offset in M2 
	    R0 = R4 +|+ R5, R1 = R4 -|- R5 || R6 = [I1 ++ M1];// Compute the first o/p of the Butterfly
	    R0 = R0 +|+ R6 || R7 = [I1 ++ M1];  
	    R2 = R0 +|+ R7 || I1 -= M0 || R0 = [I0++];          // Butterfly Offset, I0 -> Dummy fetch
	    R2 = R2 >>> 2 (V) || I0 -= M0 || R0 = [I2 ++ M2];   // I0 -> Dummy fetch
	    R0 = R1 +|+ R6 || [I0++M1] = R2;    // Compute the third o/p of the Butterfly           
	    R0 = R0 -|- R7 || R2 = [I2]; 
	    R4 = R4 -|- R6;                     // Compute the second and fourth o/ps of the Butterfly
	    R1.H = R0.H*R2.L, R1.L = R0.L*R2.L || I2 -= M2;// Multiply twiddle factor and the Butterfly o/p
	    R0.H = R0.L*R2.H, R0.L = R0.H*R2.H; 
	    R2 = M2;                            // Offset computation to fetch the twiddle factor...
	    R0 = R1 -|+ R0; 
	    R0 = R0 >>> 2 (V);
	    R1 = R2 >> 1 || [I0++M1] = R0;      // corresponding to the second output of the butterfly...
	    M2 = R1;                            // Twid_Offset = Butterfly count*(1 << 2*Stage)*(Stride factor << 1)        
	    R1 = R1 + R2;                       
	    M0 = R1;                            // Twid_Offset = 3*Butterfly count*(1 << 2*Stage)*(Stride factor << 1)      
	    R6 = R5 -|- R7;
	    R6 = PACK (R6.L, R6.H) || I2 += M2; // Interchange real and imaginary parts
	    R5 = R4 +|- R6, R4 = R4 -|+ R6 || R2 = [I2];// Compute the second output of the Butterfly
	    R6.H = R4.H*R2.L, R6.L = R4.L*R2.L || I2 -= M2; // Multply twiddle factor and the Butterfly o/p
	    R7.H = R4.L*R2.H, R7.L = R4.H*R2.H || I2 += M0;// Compute the fourth output of the Butterfly
	    R4 = R6 -|+ R7 || R2 = [I2];
	    R4 = R4 >>> 2 (V) || I2 -= M0;
	    R6.H = R5.H*R2.L, R6.L = R5.L*R2.L || [I0++M1] = R4 ;// Multiply twiddle factor and the Butterfly o/p
	    R7.H = R5.L*R2.H, R7.L = R5.H*R2.H || R2 = [FP - 20];
	    R0 = R6 -|+ R7 || I1 += 4;                      
	    R0 = R0 >>> 2 (V) || I3 += 4;
END_BFLY:   [I0 ++ M1] = R0 || R0 = [FP - 8];   // Store the fourth o/p of the Butterfly
						// and Reload Twid Offset
END_MIDDLE:P2 += 1;
	R3 = R3 >> 2 || R7 = [FP - 4];          // Update the State count & Compute no. of Groups in the stage
	R7 <<= 2;
	[FP - 4] = R7;
	JUMP STAGE_LOOP;                            
//*************************************** LAST STAGE*****************************************************       

LAST_STAGE: P1 = [FP-4];                    // Initialize loop counter
	    R0 = [FP - 16] || NOP;          // Save Temporary buffer address
	    I1 = R0;
	    M1 = 12;
	    LSETUP (ST_LAST_STAGE, END_LAST_STAGE) LC0 = P1;
ST_LAST_STAGE:  R4 = [I1++];                    // Fetch the Butterfly inputs
		R5 = [I1++];                            
		R0 = R4 +|+ R5, R1 = R4 -|- R5 || R6 = [I1++];// Compute first output of the butterfly
		R0 = R0 +|+ R6 || R7 = [I1] || I1 -= M1;            
		R2 = R0 +|+ R7; 
		R2 = PACK (R2.L, R2.H);
		R0 = R1 +|+ R6 || [I1++] = R2;          
		R0 = R0 -|- R7;                         
		R0 = PACK (R0.L, R0.H);
		R0 = R4 -|- R6 || [I1++] = R0;  // Store third output and compute second and fourth outputs of the butterfly
		R1 = R5 -|- R7;
		R1 = PACK (R1.L, R1.H);
		R4 = R0 -|+ R1;
		R4 = PACK (R4.L, R4.H);         
		R4 = R0 +|- R1 || [I1++] = R4;  // Store second output of the butterfly 
		R4 = PACK (R4.L, R4.H);         
END_LAST_STAGE: [I1++] = R4;                    // Store fourth output of the butterfly

//********************************************** Bit-reversal *************************************************************
	    R3 = P5;                            // Initialize FFT length
	    R0 = R3 << 1;                       // Compute 2*FFT length
	    M0 = R0;                            // Store 2*FFT length as a modifier value for bit-reversal
	    R0 = [FP - 16];
	    M1 = R0;                            // Initialize the temporary buffer address
	    I1 = R0;
	    I2 = B0;                            // Initialize the output buffer address
	    I0 = 0;                             // Initialize address to zero for bit-reversal
	    LSETUP (REV_ST, REV_END) LC0=P5;    // Do bit-reversal for other elements of the temporary buffer
REV_ST:         MNOP || I0 += M0 (BREV) || R0 = [I1];// Do bit-reversal
		I1 = I0;                        // Store the bit-reversed value 
REV_END:        MNOP || I1 += M1 || [I2++] = R0;// Store the fetched element
TERMINATE:
	    (R7:4, P5:5) = [SP++];              // Pop the registers before returning.
	    UNLINK;
	    RTS;                                // Return.
.__ifftrad4_fr16.end:
