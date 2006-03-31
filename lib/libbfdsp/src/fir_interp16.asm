/******************************************************************************
  Copyright(c) 2004 Analog Devices Inc.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

******************************************************************************
  File Name      : fir_interp16.asm
  Include File   : filter.h
  Label name     : __fir_interp_fr16                                         */


#if defined(__DOCUMENTATION__)

  Synopsis:

      #include <filter.h>
      void fir_interp_fr16(const_fract16  x[],  /* input data              */
			   fract16        y[],  /* output vector           */
			   int            n,    /* number of input samples */
			   fir_state_fr16 *s)   /* filter state            */

      The function uses the following structure to maintain the
      state of the filter.

      typedef struct
      {
	  fract16 *h;     /* filter coefficients                  */
	  fract16 *d;     /* start of delay line                  */
	  fract16 *p;     /* read/write pointer                   */
	  int      k;     /* number of coefficients per polyphase */
	  int      l;     /* interpolation/decimation index       */
      } fir_state_fr16;


  Description:

      The fir_interp_fr16 function performs a FIR-based interpolation filter.
      It generates the interpolated filtered response of the input data x and
      stores the result in the output vector y. The number of input samples is
      specified by the argument n, and the size of the output vector should be
      n*l where l is the interpolation index.

      The filter characteristics are dependent upon the number of polyphase
      filter coefficients and their values, and on the interpolation factor
      supplied by the calling program. The fir_interp_fr16 function assumes
      that the coefficients are stored in the following order:

	  coeffs[(np * ncoeffs) + nc]

	  where: np = {0, 1, ..., nphases-1}
		 nc = {0, 1, ..., ncoeffs-1}

      A pointer to the coefficients is passed into the function via the
      argument s, which is a structured variable that represents the filter
      state. This structured variable must be declared and initialized
      before calling the function. The header file filter.h contains the
      macro fir_init that can be used to initialize the variable and is
      defined as:

	  #define fir_init(state, coeffs, delay, ncoeffs, index) \
	      (state).h = (coeffs);  \
	      (state).d = (delay);   \
	      (state).p = (delay);   \
	      (state).k = (ncoeffs); \
	      (state).l = (index)

      The interpolation factor is supplied to the function in s->l. A pointer
      to the coefficients should be stored in s->h, and s->k should be set to
      the number of coefficients per polyphase filter.

      Each filter should have its own delay line which is a vector of type
      fract16 and whose length is equal to the number of coefficients in each
      polyphase. The vector should be cleared to zero before calling the
      function for the first time and should not otherwise be modified by the
      user program. The structure member s->d should be set to the start of
      the delay line, and the function uses s->p to keep track of its current
      position within the vector.

      See the VisualDSP++ C/C++ Compiler and Library Manual for an example
      of how this function may be called.

#endif /* __DOCUMENTATION__ */

/* Arguments:
      R0      - Address of input array X
      R1      - Address of output array Y
      R2      - Number of input samples
      [SP+12] - Filter state structure

   Registers Used:

      A0      - Work register
      A1      - Work register

      I0      - Address of the input data
      M0      - Used as an offset to the next set of polyphase coefficients

      B1      - Address of Delay Line (used as a circular buffer)
      I1      - Pointer into Delay Line
      L1      - Length of Delay Line (== 2 * (ncoeffs/nphases) )
      M1      - Set to 6 (offset applied to Delay Line ptr when re-iterating
		the outer loop of the main algorithm)

      I2      - Address of output vector (2nd algorithm only)

      B3      - Ptr to last coefficient in the set of coefficients for the
		1st polyphase
      I3      - Pointer to next coefficient

      R0      - Work register, and current coefficient
      R1      - Work register
      R2      - Number of input samples (=nsamples)
      R3      - Set to 1 if nsamples is odd
      R5      - A value from the delay line
      R6      - Work register
      R7      - Set to 1

      P0      - Number of polyphases
      P1      - Pointer to the filter state, then set to the number of
		polyphases as an offset and used to update the output vector
      P2      - Number of coefficients per polyphase
      P3      - Pointer to write to the output vector
      P4      - Pointer to the Read-Write pointer
      P5      - Offset used to set the ptr to the output vector

   Cycle Counts:
      [1] k >= 3 and N > 2 and N is even :
	      86 + ( (N/2) * (13 + (l * (3 + (2*k)))))
      [2] k >= 3 and N > 2 and N is odd  :
	     107 + ( (N/2) * (13 + (l * (3 + (2*k))))) + (l * (3 + (2 * k)))
      [3] k <  3 or  N<= 2               :
	      78 + ( N * (11 + (l * (3 + k))))

   Code Size  : 266 Bytes

******************************************************************************/

#if defined(__ADSPLPBLACKFIN__) && defined(__WORKAROUND_AVOID_DAG1)
#define __WORKAROUND_BF532_ANOMALY38__
#endif

.text;
.global  __fir_interp_fr16;

.align 2;
__fir_interp_fr16:

    P1 = [SP+12];                 // Read the address of the filter state

    [--SP] = (R7:5,P5:3);

    P3 = [P1++];                  // Address of coefficients
    R3 = [P1++];                  // Address of delay line
    P4 = P1;                      // Save &Read-Write pointer
    R5 = [P1++];                  // Read-Write pointer
    P2 = [P1++];                  // Number of coefficents per polyphase
    P0 = [P1];                    // Number of polyphases

    CC = R2 <=  0;                // Exit if number of samples <= 0
    IF CC JUMP RESTORE_RETURN;

    CC = P2 <=  0;                // Exit if number of coeffs per polyphase <= 0
    IF CC JUMP RESTORE_RETURN;

    CC = P0 <=  0;                // Exit if number of polyphases <= 0
    IF CC JUMP RESTORE_RETURN;

    I0 = R0;                      // Address of input
    I1 = R5;                      // Delay Line ptr = Read-Write ptr

    P5 = P2 + P2;                 // Number of coefficents per polyphase as a
				  // 16-bit word offset

    B1 = R3;                      // Delay Line is a circular buffer
    L1 = P5;                      // Length of Delay Line == 2*(ncoeffs/nphases)

    P5 = P2;                      // Copy coeffs per polyphase
    P5 += -1;                     // Calc (coeffs per polyphase - 1)
    P3 = P3 + (P5 << 1);          // Point to last coeff in 1st Polyphase
    B3 = P3;                      //   and Save this address

    P3 = R1;                      // Address of output vector
    I1 += 2;                      // Position Delay Line pointer

    P1 = P2 << 2;                 // Calc (4 * coeffs per polyphase)
    R7 = 1;

// Core Algorithm requires number of samples >= 2
    CC = R7 < R2;
    IF !CC JUMP HANDLE_SMALL_INPUTS;

// Core Algorithm requires number of coefficients per polyphase >= 3
    CC = P2 < 3;
    IF CC JUMP HANDLE_SMALL_INPUTS;

    M0 = P1;                      // Use (4 * coeffs per polyphase) to select
				  // the next set of polyphase coefficients

    P1 = P0 << 1;                 // Calc (2 * number of polyphases)
    P3 -= P1;                     // Anticipate that the ptr to the output
				  // vector will first be incremented by P1

    P5 = 0;                       // Calc the negative of
    P5-= P1;                      //      (2 * number of polyphases) - 2
    P5+= 2;                       // and used to reset the ptr to output vector

    M1 = 6;                       // Offset applied to Delay Line ptr
				  // when re-iterating the outer loop

#if 0
/* ===============================================================
 *  CORE ALGORITHM
 *
 *    e = 0;
 *    f = fir_state.p;
 *    f++;
 *
 *    /+ PROCESS TWO INPUT SAMPLES AT A TIME +/
 *    for (i = 0; i < n/2; i++)
 *
 *      /+ LOAD INPUT SAMPLES +/
 *      read( in[i] );
 *      read( in[i+1] );
 *
 *      g = f;
 *      /+ ITERATE NUMBER OF POYPHASES +/
 *      for (j = 0; j < L; j++)
 *
 *        sumEven = sumOdd = 0;
 *
 *        /* ITERATE ((NUMBER OF COEFFS/ POLYPHASES) - 2) +/
 *        for (m = 0; m < (k-2); m++)
 *          sumEven += delay[g++]   * h[ ((L - j - 1) + m) ];
 *          sumOdd  += delay[g]     * h[ ((L - j - 1) + m) ];
 *        end
 *
 *        sumEven += delay[g] * h[ ((L - j - 1) + (k-2)) ];
 *        sumOdd  += in[i]    * h[ ((L - j - 1) + (k-2)) ];
 *
 *        sumEven += in[i]    * h[ ((L - j - 1) + (k-1)) ];
 *        sumOdd  += in[i+1]  * h[ ((L - j - 1) + (k-1)) ];
 *
 *        output[e] = sumEven;
 *        output[e+L] = sumOdd;
 *        e++;
 *      end
 *
 *      delay[f++] = in[i];
 *      delay[f++] = in[i+1];
 *
 *    end
 */
#endif

    R3 = R2 & R7;                      // Set R3 to 1 if nsamples is odd
    R2 >>= 1;                          // Half nsamples as a loop counter

    P2 += -2;                          // Decrement innermost loop counter
				       // (as the loop is partially unrolled)
CORE_LOOP_INPUTS:

    I3 = B3;                           // Initialize the ptr to coefficients
    R2 = R2 - R7(S) || R6.L = W[I0++]; // Decrement outer loop counter,
				       // and Read next input sample
    R6.H = W[I0++];                    // Then read the next input sample
    P3 = P3 + P1;                      // Initialize the ptr to output vector

    LSETUP(CORE_POLYPHASE_START, CORE_POLYPHASE_END) LC0 = P0;
CORE_POLYPHASE_START:

#if defined(__WORKAROUND_BF532_ANOMALY38__)
	/* Start of BF532 Anomaly#38 Safe Code */

	A1 = A0 = 0 || R0.L = W[I3--];
	R5.L = W[I1++];

       LSETUP(CORE_COEFF_START, CORE_COEFF_END) LC1 = P2;
CORE_COEFF_START:  R1.L = (A0 += R5.L * R0.L) || R5.H = W[I1];
		   R1.H = (A1 += R5.H * R0.L) || R0.L = W[I3--];
CORE_COEFF_END:
		   R5.L = W[I1++];

#else   /* End of BF532 Anomaly#38 Safe Code */

	A1 = A0 = 0 || R0.L = W[I3--] || R5.L = W[I1++];

       LSETUP(CORE_COEFF_EVEN, CORE_COEFF_ODD) LC1 = P2;
CORE_COEFF_EVEN:  R1.L = (A0 += R5.L * R0.L) || R5.H = W[I1];
CORE_COEFF_ODD:   R1.H = (A1 += R5.H * R0.L) || R0.L = W[I3--]
					     || R5.L = W[I1++];

#endif

// ((#COEFFS/ #POLYPHASES) - 2):
// SUM ODD: DATA DELAY LINE = INPUT[i]
       R1.L = (A0 += R5.L * R0.L) || I1 += 2;
       R1.H = (A1 += R6.L * R0.L) || R0.L = W[I3--];

// ((#COEFFS/ #POLYPHASES) - 1):
// SUM EVEN: DATA DELAY LINE = INPUT[i]
// SUM ODD:  DATA DELAY LINE = INPUT[i+1]
       R1.L = (A0 += R6.L * R0.L)|| I3 += M0;
       R1.H = (A1 += R6.H * R0.L) || W[P3 ++ P1] = R1.L;

CORE_POLYPHASE_END:
       W[P3++P5] = R1.H;               // Write sum to output


    // WRITE INPUT DATA TO DELAY LINE
    W[I1--] = R6.H;
    I1 += M1 || W[I1] = R6.L;

    CC = R2 <= 0;
    IF !CC JUMP CORE_LOOP_INPUTS (BP);

// Return if number of samples is even
    CC = R3 == 0;
    IF CC JUMP SAVE_AND_EXIT (BP);

// Fall through for odd sample length
    R2 = 1;                            // Set number of remaining elements
    P2 += 2;                           // Restore number of coeffs per phase

    P3 = P3 + P1;
    P1 = P2 << 2;                      // Code below requires P1 set to
				       // 4 * (coeffs per polyphase)

#if 0
/* ===============================================================
 *  ALGORITHM FOR
 *   - LAST ITERATION ODD SAMPLES
 *   - SMALL SAMPLE SIZES
 *   - SMALL NUMBER OF COEFFICIENTS / POLYPHASE
 *
 *    f = 0;
 *    g = fir_state.p;
 *
 *    /+ ITERATE NUMBER OF INPUT SAMPLES +/
 *    for (i = 0; i < n; i++)
 *
 *      /+ LOAD INPUT SAMPLES +/
 *      read( in[i] );
 *      delay[g] = in[i];
 *
 *      /+ ITERATE NUMBER OF POYPHASES +/
 *      for (j = 0; j < L; j++)
 *
 *        sum = 0;
 *
 *        /* ITERATE (NUMBER OF COEFFS/ POLYPHASES) +/
 *        for (m = 0; m < k; m++)
 *          sum += delay[g++] * h[ ((L - j - 1) + m) ];
 *        end
 *
 *        output[f++] = sum;
 *
 *      end
 *    end
 */
#endif

HANDLE_SMALL_INPUTS:
    I2 = P3;                           // Copy &output

    P1 += 2;                           // Calc (4 * coeffs per polyphase) + 2
    M0 = P1;                           // Used as offset to next set
				       //      of polyphase coefficients

LOOP_SMALL_INPUTS:
    I3 = B3;                           // Reset ptr to the coeffs to the
    R1.L = W[I0++] || I1 -= 2;         // Read next input value,
				       // and set Delay Line ptr
    W[I1++] = R1.L;                    // Store input in the Delay Line
    R2 = R2 - R7(S) || R5.L = W[I1++]; // Decrement outer loop counter,
				       // and read next value from Delay Line

    LSETUP(LOOP_POLYPHASE_START, LOOP_POLYPHASE_END) LC0 = P0;
LOOP_POLYPHASE_START:

	A0 = 0 || R0.L = W[I3--];      // Initialize Sum,
				       // and preload last coeff of current
				       //     set of polyphase coefficients

#if defined(__WORKAROUND_BF532_ANOMALY38__)
	/* Start of BF532 Anomaly#38 Safe Code */

       LSETUP(LOOP_COEFF_START, LOOP_COEFF_END) LC1 = P2;
LOOP_COEFF_START:  R1.L = (A0 += R5.L * R0.L) || R5.L = W[I1++];
LOOP_COEFF_END:    R0.L = W[I3--];

#else   /* End of BF532 Anomaly#38 Safe Code */

	LSETUP(LOOP_COEFF, LOOP_COEFF) LC1 = P2;
LOOP_COEFF:  R1.L = (A0 += R5.L * R0.L) || R5.L = W[I1++] || R0.L = W[I3--];

#endif

LOOP_POLYPHASE_END:
	I3 += M0 || W[I2++] = R1.L;    // Point to the end of the next set of
				       // polyphase coefficients,
				       //       and save result in output[f++]

    CC = R2 <= 0;
    IF !CC JUMP LOOP_SMALL_INPUTS (BP);


SAVE_AND_EXIT:
    I1 -= 2;
    R1 = I1;
    [P4] = R1;                         // Update the Read-Write pointer
    L1 = 0;                            // Reset L-register to zero


RESTORE_RETURN:

    (R7:5,P5:3) = [SP++];
    RTS;

.__fir_interp_fr16.end:
