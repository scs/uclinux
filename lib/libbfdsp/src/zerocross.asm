/******************************************************************************
  Copyright(c) 2000-2004 Analog Devices Inc. 

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

******************************************************************************
  File Name      : zerocross.asm
  Include File   : stats.h
  Label name     : __zerocross_fr16

  Description    : Counting the number of times the signal
		   contained in x[] crosses the zero line.

  Operand        : R0 - Address of input array x
		 : R1 - Number of samples

  Registers Used : R0-3, P0-2

  Cycle count    : n = 24, first value in array zero:   192 Cycles
		   (BF532, Cycle Accurate Simulator)

		   17 + 14*nz + 7*nr

		   where:
		     nz = Number of leading zeros in array
		     nr = Number of samples - nz

  Code size      : 52 Bytes
******************************************************************************/
.text;
.global   __zero_cross_fr16;

.align 2;
__zero_cross_fr16:
		   P0 = 1(z);              // Load constant
		   P2 = R1;                // Number of samples
		   P1 = R0;                // Pointer to input array
		   R0 = 0;                 // Reset result to 0

PROLOG:            P2 -= P0;               // Decrement samples by 1
		   CC = P2 < P0;           // Terminate if number of samples <1
		   IF CC JUMP RET_ZERO;

#if defined(__WORKAROUND_CSYNC) || defined(__WORKAROUND_SPECULATIVE_LOADS)
		   NOP;
		   NOP;
		   NOP;
#endif

		   R3 = W[P1++](Z);        // Read input
		   CC = R3 == 0;           // Loop until first non-zero value
		   IF CC JUMP PROLOG;

#if defined(__WORKAROUND_CSYNC) || defined(__WORKAROUND_SPECULATIVE_LOADS)
		   NOP;
		   NOP;
		   NOP;
#endif

		   //R3 is now non-zero
		   R1 = R3 >> 15 || R3 = W[P1++](Z);
					   // Remove all bits except sign
					   // and Read next input

		   LSETUP (ST_LOOP,END_LOOP) LC0=P2;
ST_LOOP:             R2 = R3 >> 15;        // Remove all bits except sign
		     CC = R3 == 0;         // For zero-value data
		     IF CC R2 = R1;        // force signs to be equal

		     R3 = W[P1++](Z);      // Read next input

		     R1 = R1 ^ R2;         // R1 = 1 if signs differ
		     R0 = R0 + R1;         // Increment counter if signs differ

END_LOOP:            R1 = R2;              // Copy new sign to old sign

RET_ZERO:          RTS;      

.__zero_cross_fr16.end:

