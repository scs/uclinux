/******************************************************************************
 Copyright(c) 2001-2004 Analog Devices Inc.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

*******************************************************************************

File Name      : a_expand.asm
Function Name  : __a_expand

Module Name    : FILTER Library

Synopsis       : #include <filter.h>
		 void a_expand (const short input[], short output[], int n);

Description    : This function computes A-law expansion of the given
		 input vector.

Operands       : R0 - Address of input vector,
		 R1 - Address of output vector,
		 R2 - Number of elements

Registers Used : R0 - Current input value, and work register
		 R1 - Chord from input value
		 R2 - Step from input value, and output value
		 R3 - 0x0f   (pattern used to extract the step value)
		 R6 - 0x0403 (bit extraction mask for the chord - pos=4, len=3)
		 R7 - 0x55   (pattern used for inverting bit values)
		 I1 - Pointer to current output
		 P0 - Loop counter through input data
		 P1 - Pointer to current input

*******************************************************************************
*/

.text;
.global          __a_expand;
.align 2;

__a_expand:

   /* Initialize Registers */

      [--SP] = (R7:5);                      // Preserve R7-R6 on the stack
      P1 = R0;                              // Address of input vector
      I1 = R1;                              // Address of output vector
      P0 = R2;                              // Number of elements

      R7 = 0x55;                            // Initialize R7 to 0x55
      R6 = 0x0403;                          // Initialize R6 to 0x0403
      R3 = 0x0F;                            // Initialize R3 to 15

   /* Cycle through the Input Data */

      LSETUP(LOOP_START,LOOP_FINISH) LC0 = P0;

LOOP_START:
	 R0 = W[P1++] (Z);                      // Next input data

	 R0 = R0 ^ R7;                      // Undo bit inversion by a_compress

      /* Extract the Step */

	 R2 = R0 & R3;                      // Extract Step (bits 0,1,2,3)

      /* Prepare Step */

	 R2 <<= 1;                          // Step = Step << 1;
	 R2 += 1;                           // Step = Step + 1;

      /* Extract the Chord */
	 R1 = EXTRACT(R0,R6.L) (Z);         // Extract Chord (bits 4,5,6)

      /* IF (Chord \= 0) ... */

	 CC = R1 == 0;
	 R1 += -1;
	 R5 = R2; 
	 BITSET(R5,5);
	 R5 <<= R1;
	 IF !CC R2 = R5;

      /* Check Sign bit in Input */

	 CC = BITTST(R0,7);
	 R1 = -R2;
	 IF !CC R2 = R1;

LOOP_FINISH:
	 W[I1++] = R2.L;                    // Store the result in output array

   /* Return */

      (R7:5) = [SP++];                      // Restore registers
      RTS;

.__a_expand.end:
