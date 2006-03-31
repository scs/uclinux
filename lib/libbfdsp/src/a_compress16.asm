/******************************************************************************
 Copyright(c) 2001-2004 Analog Devices Inc.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

*******************************************************************************

File Name      : a_compress.asm
Function Name  : __a_compress

Module Name    : FILTER Library

Synopsis       : #include <filter.h>
		 void a_compress (const short input[], short output[], int n);

Description    : This function computes A-law compression of the given
		 input vector.

Operands       : R0 - Address of input vector,
		 R1 - Address of output vector,
		 R2 - Number of elements

Registers Used : R0 - Current input data
		 R1 - ABS(Current input value)
		 R2 - Output value
		 R3 - Exponent of input data
		 R4 - 4095 (maximum input value)
		 R5 -   63 (constant used to test for input data less than 64)
		 R6 -   26 (constant used to convert signbits to chord)
		 R7 - 0x55 (pattern used for inverting bit values)
		 I1 - Pointer to current output
		 P0 - Loop counter through input data
		 P1 - Pointer to current input

*******************************************************************************
*/

.text;
.global          __a_compress;
.align 2;

__a_compress:

   /* Initialize Registers */

      [--SP] = (R7:4);                      // Preserve R7-R4 on the stack
      P1 = R0;                              // Address of input vector
      I1 = R1;                              // Address of output vector
      P0 = R2;                              // Number of elements

      R7 = 0x55;                            // Initialize R7 to 0x55
      R6 = 26;                              // Initialize R6 to 26
      R5 = 63;                              // Initialize R5 to 63
      R4 = 4095;                            // Initialize R4 to 4095
      R3 = 0;                               // Initialize R3 to 0

   /* Cycle through the Input Data */

      LSETUP(LOOP_START,LOOP_FINISH) LC0 = P0;

LOOP_START:
	 R0 = W[P1++] (X);                  // Next input data

     /* Clip to Maximum */

	 R1 = ABS R0;                       // R0 = ABS(input data)
	 R1 = MIN(R1, R4);                  // R0 = MIN(ABS(input data),4095)

      /* IF (Input Data < 64) ... */

	 R2 = R1 >> 1;

	 CC = R1 <= R5;
	 IF CC R1 = R2;                     // Drop the least significant bit
	 IF CC JUMP GET_SIGN;               // Jump to finalize the output

GET_CHORD:
      /* ... ELSE Get Chord and Step */

	 R3.L = SIGNBITS R1;                // Count redundant sign bits
	 R2 = R6 - R3;                      // Chord = 26 - Signbits(input)
	 R3 = R1;                           // Step =
	 R3 >>= R2;                         //        (ABS(input) >> chord)
	 BITCLR(R3,4);                      //        & 0xffffffef

	 R1 = R2 << 4;                      // Position Chord
	 R1 = R1 | R3;                      // R1 = (Chord<<4) | Step

GET_SIGN:
      /* Get Sign and Invert every other Bit */

	 CC = R0 < 0;                       // Test if input data is negative
	 IF CC JUMP NEGATIVE;               // Skip if it is
	 BITSET(R1,7);

NEGATIVE:
	 R1 = R1 ^ R7;                      // Invert every other bit

LOOP_FINISH:
	 W[I1++] = R1.L;                    // Store the result in output array

   /* Return */

      (R7:4) = [SP++];                      // Restore registers  
      RTS;

.__a_compress.end:
