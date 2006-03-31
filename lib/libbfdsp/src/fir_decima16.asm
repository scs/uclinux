/******************************************************************************
  Copyright(c) 2000-2004 Analog Devices Inc.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 ******************************************************************************
  File Name      : fir_decima16.asm
  Include File   : filter.h
  Label Name     : __fir_decima_fr16

  Description    : This function performs FIR based Decimation Filter.
		   

		   The function produces the filtered decimated output 
		   for a given input data. The characteristics of the filter
		   are dependant on the coefficient values, 
		   the number of taps(L) and decimation index(M) supplied 
		   by the calling program.

		   The coefficients stored in vector `h` are applied to the 
		   elements of vector `x[]`. 

		   For filtering, 40 bit accumulator is used. 
		   The most significant 16 bits of the result are stored in 
		   the output vetor `y[ ]` computed according to a decimation 
		   index `L`.

		   Assumptions:
		   1. It also assumes that  
		      L > M. If L <= M, Ceil(L/M)-1 = 0, 
		      i.e., Stage1 need not be done.
			   
		      But loop using LC0 does the loop at least once.
	
		   2. It also assumes that number of input samples is an 
		      integral multiple of decimation factor.
			   
		   This is for correct updation of delay line.


		   The implementation of a zero phase decimator is 
		   demonstrated in the program. The implementation 
		   provided below does not use a delay line once it 
		   does not require samples older than x(0). 
		   This has been done to avoid overhead due to 
		   unnecessary duplication of input data.

		   The equation for decimation by M can be expressed as:
		   y(n) = h(0) * x(n*M) + 
			  h(1) * x(n*M-1) + 
			       ...          + 
			  h(L-1) * x(n*M+1-L)

		   This implementation is divided into two stages.

		   In the first stage, it finds the output samples which 
		   require delay line, i.e. for the first Ceil(L/M) 
		   output samples
		   y(0) = h(0) * x(0) + h(1) * x(-1) + ... + 
			  h(L-1) * x(-L+1)
		   y(1) = h(0) * x(M) + h(1) * x(M-1) + ... + 
			  h(L-1) * x(M-L+1)
		   ...

		   y(f) = h(0) * x(f*M) + h(1) * x(f*M-1) + ... + 
			  h(L-1) * x(f*M-L+1)

			  where f = Ceil(L/M) - 1.

		   This stage has been separated out due to the use of 
		   delay line. 
		   There are two inner loops. One finds sum of terms 
		   containing inputs present in delay line and the other, 
		   ones in input buffer.


		   In the second stage, all the remaining output samples 
		   are calculated. i.e. y(Ceil(L/M)) to y(Nout - 1) are 
		   computed in stage 3.

		   
		   After filtering the input, the delay line is updated 
		   by the last L-1 input samples.


		   Prototype:         
			void fir_decima_gen(const fract16         x[], 
						  fract16         y[], 
						  int             N,
						  fir_state_fr16  s);

			Structure of type fir_state_fr16 containing
			      fract16 *h;    //  filter coefficients
			      fract16 *d;    //  start of delay line
			      fract16 *p;    //  read/write pointer
			      int k;         //  number of coefficients
			      int l;         //  decimation index

  Operand        : R0 - Input Array,
		   R1 - Output Array,
		   R2 - Number of samples
		   Stack - Filter details (stored in fir_state_fr16)

  Registers Used : R0-7, I0-I3, P0-5
		   
		   R0.L -> Input samples
		   R0.H -> Delay line samples
		   R1.L -> Filter coefficient
		   R2   -> Initialized to 4 and then incremented 
			   by 2*M each time in stage 1. 
			   Copy of modifier register
		   R3   -> Initialized to 2*M. Used to update modifier.
		   R7.H -> Output sample is taken to this register and 
			   then saved.
			   Also used as temporary register

		   I0   -> Address of the input samples.
		   I1   -> Delay line pointer. 
			   This is a circular buffer of length 2*L + 4.
		   I2   -> Pointer to FIR filter coefficients.  
			   This is a circular buffer with length = 2*L.
		   I3   -> Address of output array. 
			   This is a circular buffer with length = 2*No

		   P0   -> Initialized to Ceil(L/M).                             
			   [Stage 1(given below) counter]. Then modified to M.
		   P1   -> Initialized to L-1. 
			   Then decremented by M in stage 1. 
			   [Stage 1 delay line counter].
		   P2   -> Initialized to No-Ceil(L/M).                          
			   [Stage 2(given below) outer loop counter].
		   P5   -> Initialised to 1 and incremented by M in stage 1.     
			   [Stage 1 input counter].
			   It is also used as inner loop counter of stage 2.     
			   [Stage 2 inner loop counter].

  Cycle Count    : Stage 1:    Ceil(L/M) * (L + 9)
		   Stage 2:    (Nout - (Ceil(L/M)) ) * (L + 2)

		   For Ni=256, L=16 and M=2
		     Nout=Ni/M = 128
		     Ceil(L/M) = 8

		     Total Cycle Count:   2517
		     a) Initializations:   157
		     b) Stage 1:           200
		     c) Stage 2:          2160

  Code Size      : 354 Bytes.
******************************************************************************/

#if defined(__ADSPLPBLACKFIN__) && defined(__WORKAROUND_AVOID_DAG1)
#define __WORKAROUND_BF532_ANOMALY38__
#endif

.text;
.global   __fir_decima_fr16;

.align 2;
__fir_decima_fr16:                     

		   [--SP] = ( R7:4, P5:3 ); // Push R7 and P5
		   P4 = [SP+40];            // Address filter structure 's'

		   I0 = R0;                 // Address input buffer
		   B0 = R0;
		   I3 = R1;                 // Address output buffer
		   B3 = R1;                 // Output buffer as circular buffer
		   R3 = R2 << 1 || P5 = [P4++];
		   L0 = R3;                 // Circular buffering of input 
					    // buffer is disabled

		   R4 = PACK( R2.H, R2.L ) || R0 = [P4++];
					    // Address filter coefficients (h)
					    // Address delay line
		   R3 = [P4++];             // Read/Write Pointer

		   P1 = [P4++];             // Number of Coefficients (L)
		   B1 = R0;                 // Delay line as circular buffer
		   I1 = R3;                 // Address delay line

		   R3 = [P4--];             // Decimation Factor (M)

		   // Computation of N/M
		   P0 = 16;
		   R2 = R2 + R3;
		   R2 += -1;
		  
		   DIVS( R2, R3 );
		   LSETUP( _fir_decima_divNM, _fir_decima_divNM ) LC0 = P0;
_fir_decima_divNM:   DIVQ( R2, R3 );

		   R2 = R2.L;
		   CC = R2 == 0;            //Check for number of input samples
		   IF CC JUMP _fir_decima_end1;

		   P2 = R2;                 // Number of output samples
		   R2 <<= 1;                // R2 = 2*No
		   L3 = R2;                 // Length of output buffer = 2*No

		   CC = P1==0;              // Check for number of coefficients
		   IF CC JUMP _fir_decima_end1;

		   CC = R3==0;              // Check for decimation factor
		   IF CC JUMP _fir_decima_end1;

		   R0 = P1;
		   R2 = P1;                 // R2 = L
		   CC=R0 < R3;              // Check for number of coefficients
					    // (=L) < decimation factor (=M)
		   IF CC JUMP _fir_decima_end1;

		   // Computation of L/M
		   DIVS( R0, R3 );
		   LSETUP( _fir_decima_divLM, _fir_decima_divLM) LC0 = P0;
_fir_decima_divLM:   DIVQ( R0, R3 );

		   // Set the appropriate loop counter in stage 1 
		   // and modifier just before entering stage2
		   R0 = R0.L;               // L / M
		   R7 = 1;
		   R1 = R0.L * R3.L(IS);    // L / M*M
		   R6 = R2 - R1;            // L % M
		   R7 = R6 ^ R7;
		   CC = R6 < 2;

		   R1 = R0;
		   R1 += 1;
		   IF !CC R0 = R1;

		   R1 = R3 - R6;
		   P0 = R0;
		   IF !CC R7 = R1;

		   R7 = R7 << 1 || R1 = [P4--];
					    // Dummy Modification
		   M2 = R7;

		   CC = P0 < P2;            // If L/M < number of outputs
		   IF !CC P0 = P2;
		   R5 = CC;

		   I2 = P5;                 // Address coefficients
		   B2 = P5;                 // Coefficients as circular buffer
		   R2 = R2 + R2;            // R2 = 2*L
		   L2 = R2;                 // Length of coefficient array = 2*L
		   R2 += -2;                // R2 = 2*L - 2
		   L1 = R2;                 // Length of delay line buffer is 
					    // set to:  2*L - 2*(L-1 elements)
		   P2 -= P0;                // Stage 2 counter = No - Ceil(L/M)
		   P1 += -1;                // Stage 1a counter (delay line) = 
					    // inner loop counter Stage 2 = L-1
		   P3 = P1;
		   P5 = 1;                  // Stage 1b counter (input buffer)=1

		   R2 = 4;                  // R2 = 4 (copy of modifier M0)
		   M0 = R2;                 // Modifier M0 is initilaized to 4
		   M1 = 6;

		   R0.L = W[I2--] || I3 -= 2;            
					    // Coefficient pointer and 
					    // output pointer are modified
	    
/*** STAGE 1 ******************************************************************/
		   
		   // Stage 1 counter = Ceil(L/M)
		   LSETUP( _fir_decima_STG1_ST, _fir_decima_STG1_END ) LC0 = P0;

		   P0 = R3;                 // P0 initialized to M
		   R3 = R3 + R3(S) || R1.L = W[I2--] || I1 -= M0;
					    // R3 = 2*M as input data is fract16
					    // Read the last coeffient to R1.L 
					    // and modify delay line pointer

_fir_decima_STG1_ST: A1 = 0 || I1 += M0 || R0.L = W[I0++];
					    // Modify delay line pointer, and
					    // read from input buffer to R0.L
		     R0.H = W[I1++] || W[I3++] = R7.H;
					    // Read from delay line to R0.H, and
					    // store previous result
#if defined(__WORKAROUND_BF532_ANOMALY38__)

       /* Start of BF532 Anomaly#38 Safe Code */
       
		     // Loop for terms containing samples from delay line
		     LSETUP( _fir_decima_STG1A_ST, _fir_decima_STG1A_END ) LC1 = P1;
_fir_decima_STG1A_ST:  A1 += R0.H * R1.L || R0.H = W[I1++];
_fir_decima_STG1A_END: R1.L = W[I2--];

		     // Loop for terms containing samples from input buffer
		     LSETUP( _fir_decima_STG1B_ST, _fir_decima_STG1B_END) LC1 = P5;
_fir_decima_STG1B_ST:  R7.H = (A1 += R0.L * R1.L) || R0.L = W[I0++];
_fir_decima_STG1B_END: R1.L = W[I2--];

#else  /* End of BF532 Anomaly#38 Safe Code */

		     // Loop for terms containing samples from delay line
		     LSETUP( _fir_decima_STG1A, _fir_decima_STG1A ) LC1 = P1;
_fir_decima_STG1A:     A1 += R0.H * R1.L || R0.H = W[I1++] || R1.L = W[I2--];
					    // Find sum of terms containing 
					    // samples from delay line

		     // Loop for terms containing samples from input buffer
		     LSETUP( _fir_decima_STG1B, _fir_decima_STG1B) LC1 = P5;
_fir_decima_STG1B:     R7.H = (A1 += R0.L * R1.L) || R0.L = W[I0++] || R1.L = W[I2--];
					    // Find sum of terms containing 
					    // samples from delay line buffer
#endif /* End of Alternative to BF532 Anomaly#38 Safe Code */

		     R2 = R2 + R3(S) || I0 -= M0;  
					    // Add 2*M to copy of modifier, 
					    // modify input poionter
		     I1 -= M1;              // Modify the delay line pointer
		     M0 = R2;               // Adjust modifier
		     P1 -= P0;              // Decrement counter delay line loop
_fir_decima_STG1_END:
		     P5 = P5 + P0;          // Increment count input buffer loop

		   CC = BITTST( R5, 0 );
		   IF !CC JUMP _fir_decima_partial_update;

		   R2 = P3;
		   R2 <<= 1;
		   R2 = R2 - R3(S) || I0+=M2;
					    // R2 =2*l - 2*M + 4
		   R2 += 2;                 // R2 =2*l - 2*M
		   M0 = R2;                 // Modifier M0 = 2*L - 2*M

/*** STAGE 2 ******************************************************************/

		   // Loop for Nout - Ceil(L/M) 
		   LSETUP( _fir_decima_STG2_ST, _fir_decima_STG2_END ) LC0 = P2;
_fir_decima_STG2_ST: A1 = 0 || R0.L = W[I0++] || W[I3++] = R7.H;
					    // Read input into R0.L and store
					    // output present in R7.H
#if defined(__WORKAROUND_BF532_ANOMALY38__)

       /* Start of BF532 Anomaly#38 Safe Code */
       
		     // LC1 is the number of coefficients(L) - 1
		     LSETUP( _fir_decima_STG2A_ST, _fir_decima_STG2A_END) LC1 = P3;
_fir_decima_STG2A_ST:  A1 += R0.L * R1.L || R0.L = W[I0++];
_fir_decima_STG2A_END: R1.L = W[I2--];

#else  /* End of BF532 Anomaly#38 Safe Code */
       
		     // LC1 is the number of coefficients(L) - 1
		     LSETUP( _fir_decima_STG2A, _fir_decima_STG2A) LC1 = P3;
_fir_decima_STG2A:     A1 += R0.L * R1.L || R0.L = W[I0++] || R1.L = W[I2--];
					    // A1 += x(1) * h(-L+1) and
					    // read x(2) into R0.L  and 
					    // read h(-L+2) R1.L (first time)
#endif /* End of Alternative to BF532 Anomaly#38 Safe Code */

_fir_decima_STG2_END:
		     R7.H = (A1 += R0.L * R1.L) || 
			    I0 -= M0 || R1.L = W[I2--];
					    // Last operation is unrolled, 
					    // modify I0, read next coefficient

/*** EPILOG *******************************************************************/

_fir_decima_partial_update:
		   P0 = R4;
		   I0 = B0;
		   R0 = [P4];               //R/W pointer
		   I1 = R0;

		   M0 = L2;
		   CC = P0 < P3;
		   IF CC P3 = P0;
		   IF CC JUMP _fir_decima_update;

		   I0 -= M0;
		   I0 += 2;

_fir_decima_update:
		   W[I3++] = R7.H || R0.L = W[I0++];
					    // Read last input sample and
					    // store final output sample

		   LSETUP( _fir_decima_DELUPDATE, _fir_decima_DELUPDATE) LC0=P3;
_fir_decima_DELUPDATE: 
		     R0.L = W[I0++] || W[I1++] = R0.L;
					    // Update delay line buffer 
					    // with last input samples
		   R0 = I1;
		   [P4] = R0;

_fir_decima_end1:
	   (R7:4, P5:3) = [SP++];   // Pop R7 and P5
		   L0 = 0;
		   L1 = 0;
		   L2 = 0;
		   L3 = 0;
		   RTS;

.__fir_decima_fr16.end:

