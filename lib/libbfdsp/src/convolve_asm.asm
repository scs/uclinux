/******************************************************************************
  Copyright(c) 2000-2004 Analog Devices Inc. IPDC BANGALORE, India. 

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 ******************************************************************************
  File Name    : convolve.asm
  Module Name  : Convolution
  Label name   :  __convolve_fr16
  Description  : This file contains one dimension convolution of two given 
		 sequences. The whole implementation is in Assembly language for
		 Blackfin Processor. In this implementation convolution of two 
		 vectors `a` and `b`, where `n` is the length of input vector 
		`a`, m is the input vector of `b`, the length of output vector 
		`c` is `n+m-1` .
		
		 c[i] = sum(a[j]*b[i-j])  where i = 0, 1,2, ... ,n+m-2

		There is no restriction on the size of both the arrays. The 
		whole implementation is for 16 bit fract input output. The 
		format of representation is 1Q15 format.
 
  Registers Used : R0, R1, R2, R4, R5, R6, R7, P0, A0, A1
  Other Register Used : I0, I1, I2 set and LC0 and LC1

  Cycle count:
		169 cycles (for n=10 , m=5)    
		502 cycles (for n=25 , m=8)
 
  Code size:    118 bytes

Modified on 26.3.2001 for label end after RTS
******************************************************************************/

#if defined(__ADSPLPBLACKFIN__) && defined(__WORKAROUND_AVOID_DAG1)
#define __WORKAROUND_BF532_ANOMALY38__
#endif

.text;
.global                 __convolve_fr16;
.align                  2;

__convolve_fr16:
	[--SP] = (R7:4);
	B0 = R0;
	I1 = R2;                       // The address of array B
	P0 = [SP+28];                  // Size of array B
	R2 = [SP+32];                  // Address of output array C
	P1 = R1;                       // Size of array A
	I2 = R2;                       // I2 is address of output array.
	CC = P0 <= 0;                  // Check if size of array B <=0.
	If CC Jump Terminate;
	CC = R1 <= 0;                  // Check if size of array A <=0;
	if CC Jump Terminate;               
				       // If any array size <= 0  then terminate
	P2 = P0 + P1;
	P2 +=  -1;                     // P2 = size of C
	R7.L = 0;
	lsetup(Init_strt, Init_strt) LC0 = P2; 
Init_strt:  W[I2++] = R7.L;

	R1 = R1 << 1;
	L0 = R1;
	I3 = R2;
	
	I0 = B0;                       // Address for array A 

#if defined(__WORKAROUND_BF532_ANOMALY38__)

       /* Start of BF532 Anomaly#38 Safe Code */

/*********** Convolution Loop (BF532 Anomaly#38 Safe) *************************/

	lsetup(L1_strt, L1_end) LC0 = P0; // Loop setting for array B
L1_strt:        
	    I2 = I3;                      // Address for array C
	    R4.L = W[I1++];               // Load data from array B
	    R7.H = W[I2++];
	    A0 = R7 || R5.L = W[I0++];    // Load R5 with data from array A

	    lsetup(L2_strt, L2_end) LC1 = P1; //Loop setting for Array A 
L2_strt:
		R6.L = (A0 += R4.L * R5.L) || R7.H = W[I2--];
					   // Multiply element of array A and B
		R5.L = W[I0++];
L2_end:         A0 = R7 || I2 += 4 || W[I2] = R6.L;

L1_end:     I3 += 2 || R5.L = W[I0--];

#else  /* End of BF532 Anomaly#38 Safe Code */


/***************************** Convolution Loop ******************************/

	lsetup(L1_strt, L1_end) LC0 = P0; // Loop setting for array B
L1_strt:        
	    I2 = I3;                      // Address for array C
	    R4.L = W[I1++] || R7.H = W[I2++];  // Load data from array B
	    A0 = R7 || R5.L = W[I0++];         // Load R5 with data from array A

	    lsetup(L2_strt, L2_end) LC1 = P1;  //Loop setting for Array A. 
L2_strt:
		R6.L = (A0 += R4.L * R5.L) || R7.H = W[I2--] || R5.L = W[I0++];
					   // Multiply element of array A and B
L2_end:         A0 = R7 || I2 += 4 || W[I2] = R6.L;
L1_end:     I3 += 2 || R5.L = W[I0--];

/*****************************************************************************/

#endif /* End of Alternative to BF532 Anomaly#38 Safe Code */

    Terminate:
	(R7:4) = [SP++];         //Pop up the registers before returning.
	L0 = 0;
	RTS;                     //Return.

.__convolve_fr16.end:
