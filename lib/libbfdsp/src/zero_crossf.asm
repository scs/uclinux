/******************************************************************************
  Copyright(c) 2003-2004 Analog Devices Inc. 

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

*******************************************************************************
  File Name      : zero_crossf.asm
  Include File   : stats.h
  Label name     : __zero_crossf

  Description    : Counting the number of times the signal
		   contained in x[] crosses the zero line.

		   If the number of samples is less than two, zero is returned
		   If all input values are +/- zero, zero is returned

		   The function treats +/- Inf and +/-NaN like any other
		   number. Thus if x[i] = +Inf and x[i+1] = negative value, 
		   then a zero_crossing is counted.

  Operand        : R0 - Address of input array a[],
		   R1 - Number of samples

  Registers Used : R0-4, P0-2

  Cycle count    : n = 24, first value in array zero: 202 Cycles
		   (BF532, Cycle Accurate Simulator) 

		   26 + 15*nz + 7*nr 

		   where:
		     nz = Number of leading zeros in array
		     nr = Number of samples - nz
   
  Code size      : 66 Bytes 
******************************************************************************/

.text;
.global   __zero_crossf;

.align 2;
__zero_crossf:     
		   P0 = 1(Z);              // Load constant
		   P2 = R1;                // Number of samples
		   P1 = R0;                // Pointer to input array
		   R0 = 0;                 // Reset result to 0 
		   [--SP] = R4;            // Push R4 onto stack 

PROLOG:
		   P2 -= P0;               // Decrement samples by 1
		   CC = P2 < P0;           // Terminate if number of samples <1
		   IF CC JUMP RET_ZERO;

#if defined(__WORKAROUND_CSYNC) || defined(__WORKAROUND_SPECULATIVE_LOADS)
		   NOP;
		   NOP;
		   NOP;
#endif

		   R3 = [P1++];            // Read input 
		   R2 = R3 << 1;           // Remove sign
		   CC = R2 == 0;           // Loop until first non-zero value                   
		   IF CC JUMP PROLOG;

#if defined(__WORKAROUND_CSYNC) || defined(__WORKAROUND_SPECULATIVE_LOADS)
		   NOP;
		   NOP;
		   NOP;
#endif

		   //R3 is now non-zero
		   R1 = R3 >> 31 || R4 = [P1++];          
					   // Remove mantissa and exponent
					   // and Read next input

		   LSETUP (ST_LOOP,END_LOOP) LC0=P2;
ST_LOOP:             R3 = R4 << 1;         // Remove sign
		     R2 = R4 >> 31 || R4 = [P1++];
					   // Remove mantissa and exponent
					   // and read next input
		     CC = R3 == 0;         // For zero-value data
		     IF CC R2 = R1;        // force signs to be equal

		     R3 = R1 ^ R2;         // R3 = 1 if signs differ 
		     R0 = R0 + R3;         // Increment counter if signs differ

END_LOOP:            R1 = R2;              // Copy new sign to old sign
	  
RET_ZERO:          R4 = [SP++];            // Pop R4 from stack
		   RTS;

.__zero_cross_fr16.end:

