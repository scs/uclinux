/******************************************************************************
  Copyright(c) 2000-2004 Analog Devices Inc.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 ******************************************************************************
  File Name      : cssub.asm
  Module Name    : complex vector scalar subtraction
  Label name     :  __cvecssub_fr16
  Description    : This function computes complex vector/scalar subtraction
  Operand        : R0 - address of input complex vector A,
		   R1 - complex scalar B,
		   R2 - address of output complex vector
  Registers Used : R0,R1,R2,R3,I0,P0,P1.

  Notes          : Input and output vectors should be in different banks to
		   avoid memory bank collisions

  CYCLE COUNT    : 28          N == 0
		   26 + N      for other N
		  (measured for a ADSP-BF532 using version 3.5.0.21 of
		   the ADSP-BF53x Family Simulator and includes the
		   overheads involved in calling the library procedure
		   as well as the costs associated with argument passing)

  CODE SIZE      : 38 BYTES

******************************************************************************/

.text;
.global __cvecssub_fr16;
.align 2;

__cvecssub_fr16:
	R3 = [SP+12];                  // No. of elements in input vector
	CC = R3 <= 0;                  // Check if no. elements <= 0
	IF CC JUMP RET_ZERO;
	P0 = R0;                       // Address of input complex vector
	I0 = R2;                       // Address of output complex vector
	P1 = R3;                       // Set loop counter

	R2 = [P0++];                   // Load input[0]
	R3 = R2 -|- R1 || R2 = [P0++]; // Calculate output[0], Load input[1]

	LSETUP(ST_CSSUB,ST_CSSUB) LC0 = P1;
ST_CSSUB:  R3 = R2 -|- R1 || R2=[P0++] || [I0++] = R3;
			  // Do subtraction,
			  // Fetch next element,
			  // Store previous output

	[I0++] = R3;                  // Store last result in output vector

RET_ZERO:
	RTS;

.__cvecssub_fr16.end:
