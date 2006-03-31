/*************************************************************************
 *
 * cfftf_fr16.asm : $Revision$
 *
 * (c) Copyright 2003-2004 Analog Devices, Inc.
 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 *
 ************************************************************************/

/*-----------------------------------------------------------------------*/
#if 0

   Function: CFFTF - fast N-point radix-4 complex input FFT

   Synopsis:

      #include <filter.h>

      void cfftf_fr16(const complex_fract16 in[],   /* Input sequence   */
		      complex_fract16       out[],  /* Output sequence  */
		      const complex_fract16 twid[], /* Twiddle sequence */
		      int wst,                      /* Twiddle stride   */
		      int n);                       /* FFT size         */

   Description:

      The cfftf_fr16 function transforms the time domain complex input signal
      sequence to the frequency domain by using the accelerated version of
      the Discrete Fourier Transform known as a Fast Fourier Transform or FFT.
      It will decimate in frequently using an optimized radix-4 algorithm.

      The size of the input array in and the output array out is n where n
      represents the number of points in the FFT. The cfftf_fr16 function has
      been designed for optimum performance and requires that the input array
      in be aligned on an address boundary that is a multiple of four times
      the FFT size. For certain applications, this alignment constraint may
      not be appropriate; in such cases the application should call the
      cfftrad4_fr16 function instead with no loss of facility (apart from
      performance).

      The twiddle table is passed in the argument twid, which must contain at
      least (3*n)/4 complex twiddle factors. The table should be initialized
      with complex twiddle factors in which the real coefficients are positive
      cosine values and the imaginary coefficients are negative sine values.
      The function twidfftf_fr16 may be used to initialize the array. If the
      twiddle table contains more factors than required for a particular FFT
      size, then the stride factor wst has to be set appropriately; otherwise
      it should be set to 1.

      It is recommended that the output array is not allocated in the same
      4K memory sub-bank as either the input array or the twiddle table as
      the performance of the function may otherwise degrade due to data
      bank collisions.

      The function will use static scaling of intermediate results to prevent
      overflow. The final output will be scaled by 1/n.

      The number of points in the FFT, n, must be a power of 4 and must be at
      least 16.


   Example:

      #include <filter.h>

      #define FFTSIZE 64

      #pragma align 256
      segment ("seg_1") complex_fract16 input[FFTSIZE];

      #pragma align 4
      segment ("seg_2") complex_fract16 output[FFTSIZE];

      #pragma align 4
      segment ("seg_3") complex_fract16 twid[(3*FFTSIZE)/4];

      twidfftf_fr16(twid,FFTSIZE);
      cfftf_fr16(input,
		 output,
		 twid,1,FFTSIZE);

  ----------------------------------------------------------------------------

   Specification:

      This is an assembly routine for an optimized Complex radix-4 C-callable
      FFT running on the Blackfin family of DSPs.

      [I] Usage:

	  1. Inputs:

		     R0 -> pointer to input data for a FFT
		     R1 -> pointer to output array for a FFT
		     R2 -> pointer to the twiddle table

	      [SP + 28] -> stride through the twiddle table
	      [SP + 32] -> N, the number of FFT points

	  2. The twiddle factor array to be passed to the function must be
	     initialized with alternate real(cos) and imaginary(-sine) values.
	     The length of the twiddle factor array should be 3*N/4 - 2,
	     where N is the number of FFT points.
		      w = e^(-2*j*pi*[0 : 3*N/4-3]/N)

	  3. Static scaling is used to avoid overflow in the intermediate
	     results, and hence the final output will be scaled by 1/N. (The
	     input data is scaled by 4 in the first stage and the output of
	     each stage FFT except the last stage is scaled by 4.

      [II] Assumptions:

	  1. There should be at least 2 stages since first stage is done
	     separately. In the first stage, bit reversal is done and so it
	     is separated out. In the last stage, scaling of the output is
	     not required and so is separated out, but if N = 16, computation
	     for intermediate stages is skipped by a conditional jump. In
	     brief, FFT length should be at least 16 and should be a power
	     4.

	  2. The input array base address in[] should have 'x' zeros in the
	     LSB for bit reversing properly where x = log (4*N) to the base 2.

	     Use:
		 #pragma align   64    for FFT size of   16
		 #pragma align  256    for FFT size of   64
		 #pragma align 1024    for FFT size of  256
		 #pragma align 4096    for FFT size of 1024

	  3. The twiddle table and the output array must be aligned on a
	     32-bit word boundary.

	  4. The twiddle table and output array should be allocated in
	     separate 4K memory sub-banks to avoid data bank collisions

	  5. The input array and output array should be allocated in
	     separate 4K memory sub-banks to avoid data bank collisions

      [III] Technical Data:

	  1. Registers used:

		A0, A1, R0-R7, I0-I3, B1-B3, M0-M3, L1, L3, P0-P2, LC0, LC1, CC

		! This functions makes use of the register M3. 

	  2. Cycle Counts:

		  166 cycles for FFT size of   16
		  627 cycles for FFT size of   64
		 2972 cycles for FFT size of  256
		14581 cycles for FFT size of 1024

		(measured using the BF532 cycle accurate simulator)

	  3. Code Size:
		  518 Bytes

_______________________________________________________________________________
#endif


.text;
.align 2;
.global      __cfftf_fr16;

__cfftf_fr16:
	[--SP] = (R7:4);           // Save registers R4-R7
	R3 = R2;                   // R3 = Address of twiddle factor array

	R4 = 16;
	R2 = [SP + 32];
	P1 = R2;                   // P1 = N, length of FFT
	CC = R2 < R4;             
	IF CC JUMP CFFTF_EXIT;     // Terminate if invalid input length 

	I0 = R0;                   // Address of input array

	I1 = R1;                   // Address of output buffer (read pointer)
	B1 = R1;                   // Base address of circular buffer
	R0 = R2 << 2;              // R0 = 4*N
	L1 = R0;                   // Circular buffering enabled

	B3 = R1;
	I3 = R1;                   // Address of output buffer (write pointer)
	L3 = R0;

	R0 = [SP + 28];            // Twiddle stride
	B2 = R0;
	CC = R0 <= 0;
	IF CC JUMP CFFTF_EXIT;     // Terminate if invalid twiddle stride

	M0 = 16;                   // Modifier to decrement outpoint pointer 
				   // for 3 dummy writes
	R0 = R2 << 1 || I1 -= M0;  // R0 = 2*N , 
				   // Decrement output pointer by 12 for skewing
	M3 = R0;                   // M3 = 2*N
	I2 = R3;                   // Address of twiddle factor array

	P1 = P1 >> 2;              // P1 = N/4;
	M2 = 0;                    // To avoid overflow of I2 during dummy
				   // increments at the start
	P0 = 16;                   // Modifier for fetching input
	P2 = 0;                    // Loop counter for number of butterflies per group


 
// Start of first stage with input fetching by bit reversal 
// Input is scaled by four. The output is also scaled by four by ASR option

	LSETUP(STAGE1_ST,STAGE1_END) LC0 = P1;
				   // There are N/4 butterflies in first stage
STAGE1_ST:
	R5 = R1 +|- R3 , R3 = R1 -|+ R3(ASR) ||   I0 += M3 (BREV) || R7 = [I0];
				   // y3 = B +|- D, y1 = B -|+ D, 
				   // Do bit-reversal, fetch x0
	R7 = R7 >>> 2(V) || [I1++] = R6 || R6 = [I0];
				   // Scale x0, , Store y0 of this butterfly,
				   // fetch x2
	R6 = R6 >>> 2(V) || [I1++] = R3 || I0 += M3 (BREV);
				   // Scale x2, Store y1 of previous butterfly, 
				   // Do bit-reversal
	R0 = R7 +|+ R6 , R1 = R7 -|- R6(ASR) || I0 += M3 (BREV) || R7 = [I0];
				   // A = x0 +|+ x2, B = x0 -|- x2, 
				   // Do bit-reversal, fetch x1
	R7 = R7 >>> 2(V) || I0 += M3 (BREV) || R6 = [I0];
				   // Scale x1, Do bit-reversal and fetch x3
	R6 = R6 >>> 2(V) || [I1++] = R4;
				   // Scale x3, Store y2 of previous butterfly
	R5 = R7 +|+ R6 , R3 = R7 -|- R6 (ASR,CO) || [I1++] = R5;
				   // C = x1 +|+ x3, D = x1 -|- x3(CO), 
				   // Store y3 of previous butterfly
STAGE1_END:
	R6 = R0 +|+ R5 , R4 = R0 -|- R5(ASR);
				   // y0 = A +|+ C, y2 = A -|- C

	R5 = R1 +|- R3 , R3 = R1 -|+ R3(ASR) || [I1++] = R6;
				   // y3 = B +|- D, y1 = B -|+ D, 
				   // Store y0 of this butterfly
	 [I1++] = R3;              // Store y1 of last butterfly
	 [I1++] = R4;              // Store y2 of last butterfly
	 [I1++] = R5;              // Store y3 of last butterfly
// End of first stage with input fetching by bit reversal 



// Start of intermediate stages. All the stages except first and last done here.

INTER_STG:
// This loop(INTER_STAGES) is for (number of stages - 2)
	P2 += 1;                   // Butterfly counter is incremented
	P2 = P2 << 2;              // Number of butterflies is multiplied by 4.
	P2 += -1;                  // Loop counter is decremented as first
				   // butterfly already done.

	R1 = B2;                   // Load stride
	R2 = P1;                   // R2 is initialised to P1(=N/4) and is
				   // divided by four after each stage.
	R2 *= R1;
	M1 = R2;                   // For restoring twiddle factor pointer

	R0 = P0;                   // Let P0 = a
	M0 = P0;                   // Modifier of input for butterfly, M0 = a
	R1 = R0 << 2;
	P0 = R1;                   // a is multiplied by four
	R1 = R0 - R1;
	R1 += 4;
	M3 = R1;                   // M3 = -3a + 4 (a before modification)

	P1 = P1 >> 2;              // P1 initialised to N/4 and is divided by 4 
				   // after each stage
	CC = P1 == 1;              // Check whether loop has been executed 
				   //   (no: of stages - 2) times
	IF CC JUMP FINISH;         // If true, jump to finish


	LSETUP(GROUP_ST,GROUP_END) LC0 = P1;
				   // Executed for all groups in the stage
GROUP_ST:
// First butterfly is done outside as the twiddle factors are one in this butterfly.
	R4 = PACK(R2.H,R2.L) || R7 = [I1++M0] || I2 -= M2;
				   // R4 = R2 , Fetch x0 , Modify I2
	R6 = [I1++M0] || I2 -= M2; // Fetch x2 ,  Modify I2
	M2 = R4;                   // Modifier for twiddle factor array
	R7 = R7 +|+ R6, R1 = R7 -|- R6(ASR) || R0 = [I1++M0];
				   // A = x0 +|+ x2, B = x0 -|- x2, Fetch x1
	R6 = [I1++M3];             // Fetch x3
	R5 = R0 +|+ R6, R3 = R0 -|- R6(ASR,CO) || R0 = [I1++M0];
				   // C = x1 +|+ x3, D = x1 -|- x3(CO), 
				   // Fetch x0 of next butterfly
	R5 = R7 +|+ R5, R6 = R7 -|- R5(ASR) || R7 = [I1++M0] || I2 += M2;
				   // y0 = A +|+ C, y2 = A -|- C, 
				   // Fetch x2 of next butterfly, Skip W0
	R3 = R1 +|- R3, R1 = R1 -|+ R3(ASR) || [I3++M0] = R5 || R5 = [I2++M2];
				   // y3 = B +|- D, y1 = B -|+ D, 
				   // Store y0 of this butterfly, Fetch W1
	R4 = R4 + R2(S) || [I3++M0] = R1 || R1 = [I2++M2];
				   // Add R2 to R4, Store y1 of this butterfly,
				   // Fetch W2


	LSETUP(INTER_STG_BFLY_ST,INTER_STG_BFLY_END) LC1 = P2;
				   // Loop for (butterflies-1) in the group
INTER_STG_BFLY_ST:
	A0=R7.L*R1.L, A1=R7.L*R1.H || [I3++M0] = R6;
				   // Complex mul. of x2 and W2, 
				   // Store y2 of previous butterfly
	R1.L=(A0-=R7.H*R1.H), R1.H=(A1+=R7.H*R1.L) || R7 = [I1++M0];
				   // C2 = x2 * W2, Fetch x1

	A0=R7.L*R5.L, A1=R7.L*R5.H || [I3++M3] = R3 || R3 = [I2];
				   // Complex mul. of x1 and W1, Fetch W3
	R7.L=(A0-=R7.H*R5.H), R7.H=(A1+=R7.H*R5.L) || R6 = [I1++M3] || I2 -= M2;
				   // C1 = x1 * W1, Fetch x3, Modify I1, I2
	A0=R6.L*R3.L, A1=R6.L*R3.H || I2 -= M2;
				   // Complex mul. of x3 and W3, Modify I2
	M2=R4;                     // Modifier of I2 is updated
	R6.L=(A0-=R6.H*R3.H), R6.H=(A1+=R6.H*R3.L) || I2 += M1;
				   // C3 = x3 * W3, Restore I2
	R5 = R7 +|+ R6, R3 = R7 -|- R6(ASR,CO);
				   // C = C1 +|+ C3, D = C1 -|- C3(CO)
	R7 = R0 +|+ R1, R1 = R0 -|- R1(ASR) || R0 = [I1++M0];
				   // A = x0 +|+ C2, B = x0 -|- C2, 
				   // Fetch x0 of next butterfly
	R5 = R7+|+R5, R6 = R7-|-R5(ASR) || R7 = [I1++M0];
				   // y0 = A +|+ C, y2 = A -|- C, 
				   // Fetch x2 of next butterfly
	R3 = R1+|-R3, R1 = R1-|+R3(ASR) || [I3++M0] = R5 ||  R5 = [I2++M2];
				   // y3 = B +|- D, y1 = B -|+ D, 
				   // Store y0 of this butterfly, Fetch W1
INTER_STG_BFLY_END:
	R4 = R4 + R2(S) || [I3++M0] = R1 || R1 = [I2++M2];
				   // R4(copy of M2) is modified, Store y1,
				   // Fetch W2

	A0=R6.L*R6.L, A1=R6.L*R6.H || [I3++M0] = R6 || I2 -= M2;
				   // Store y2 of last butterfly, Modify I2
GROUP_END:
	[I3++] = R3 || I1 += M0;   // Store y3 of last butterfly, Modify I1

	JUMP INTER_STG;



FINISH:
	R4 = PACK(R2.H,R2.L) || I2 -= M2 || R7 = [I1++M0];
				   // R4 = R2, Modify twiddle pointer, Fetch x0
	R6 = [I1++M0] || I2 -= M2; // Modify twiddle factor array pointer,
				   // Fetch x2
	M2 = R4;                   // Modifier for twiddle factor array
	R7 = R7 +|+ R6, R1 = R7 -|- R6 || R0 = [I1++M0];
				   // A = x0 +|+ x2, B = x0 -|- x2, Fetch x1
	R6 = [I1++M3];             // Fetch x3
	R5 = R0 +|+ R6, R3 = R0 -|- R6(CO) || R0 = [I1++M0];
				   // C = x1 +|+ x3, D = x1 -|- x3(CO), 
				   // Fetch x0 of next butterfly
	R5 = R7 +|+ R5, R6 = R7 -|- R5 || R7 = [I1++M0] || I2 += M2;
				   // y0 = A +|+ C, y2 = A -|- C, 
				   // Fetch x2 of next butterfly, Skip W0
	R3 = R1 +|- R3, R1 = R1 -|+ R3 || [I3++M0] = R5 || R5 = [I2++M2];
				   // y3 = B +|- D, y1 = B -|+ D, 
				   // Store y0 of this butterfly, Fetch W1
	R4 = R4 + R2(S) || [I3++M0] = R1 || R1 = [I2++M2];
				   // R2 is added to R4,
				   // Store y1 of this butterfly, Fetch W2


	LSETUP(BUTTERFLY2_ST,BUTTERFLY2_END) LC1 = P2;
BUTTERFLY2_ST:
	A0=R7.L*R1.L, A1=R7.L*R1.H || [I3++M0] = R6;
				   // Complex mul. of x2 and W2, 
				   // Store y2 of previous butterfly
	R1.L=(A0-=R7.H*R1.H), R1.H=(A1+=R7.H*R1.L) || R7 = [I1++M0];
				   // C2 = x2 * W2, Fetch x1
	A0=R7.L*R5.L, A1=R7.L*R5.H || [I3++M3] = R3 || R3 = [I2];
				   // Complex mul. of x1 and W1, Fetch W3
	R7.L=(A0-=R7.H*R5.H), R7.H=(A1+=R7.H*R5.L) || R6 = [I1++M3] || I2 -= M2;
				   // C1 = x1 * W1, Fetch x3, Modify I1, I2
	A0=R6.L*R3.L, A1=R6.L*R3.H || I2 -= M2;
				   // Complex mul. of x3 and W3, Modify I2
	M2=R4;                     // Modifier of I2 is updated
	R6.L=(A0-=R6.H*R3.H), R6.H=(A1+=R6.H*R3.L) || I2 += M1;
				   // C3 = x3 * W3, Restore I2
	R5 = R7 +|+ R6, R3 = R7 -|- R6(CO);
				   // C = C1 +|+ C3, D = C1 -|- C3(CO)
	R7 = R0 +|+ R1, R1 = R0 -|- R1 || R0 = [I1++M0];
				   // A = x0 +|+ C2, B = x0 -|- C2, 
				   // Fetch x0 of next butterfly
	R5 = R7+|+R5, R6 = R7-|-R5 || R7 = [I1++M0];
				   // y0 = A +|+ C, y2 = A -|- C, 
				   // Fetch x2 of next butterfly
	R3 = R1+|-R3, R1 = R1-|+R3 || [I3++M0] = R5 ||  R5 = [I2++M2];
				   // y3 = B +|- D, y1 = B -|+ D, 
				   // Store y0 of this butterfly, Fetch W1
BUTTERFLY2_END:
	R4 = R4 + R2(S) || [I3++M0] = R1 || R1 = [I2++M2];
				   // R4(copy of M2) is modified, 
				   // Store y1, Fetch W2
	[I3++M0] = R6;             // Store y2 of last butterfly
	[I3++M3] = R3;             // Store y3 of last butterfly

CFFTF_EXIT:
	(R7:4) = [SP++];           // Restore all registers that were saved
	L1 = 0;                    // Circular buffering disabled
	L3 = 0;
	RTS;

.__cfftf_fr16.end:
