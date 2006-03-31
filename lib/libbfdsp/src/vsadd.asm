/******************************************************************************
  Copyright(c) 2000-2004 Analog Devices Inc. IPDC BANGALORE, India. 

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

******************************************************************************
  File Name      : vsadd.asm
  Module Name    : vector scalar addition
  Label name     :  __vecsadd_fr16
  Description    : This function computes the sum of a vector and a scalar
  Operand        : R0 - Address of input vector,
		   R1 - scalar value,
		   R2 - Address of output vector
  Registers Used : R3,I0,P0,P1
  Notes          : Input and output vectors should be in different banks
		   to achieve the cycle count given below. Also the function
		   reads two elements beyond the end of the input vector to
		   achieve a 1-cycle loop

  CYCLE COUNT    : 10          N == 0
		 : 14 + N      for other N
  'N' - NUMBER OF ELEMENTS

  CODE SIZE      : 46 BYTES
  
  DATE           : 21-02-01
******************************************************************************/

.text;
.global       __vecsadd_fr16;
.align 2;

__vecsadd_fr16:
	R3 = [SP+12];              // NO. OF ELEMENTS IN INPUT VECTOR
	CC = R3 <= 0;              // CHECK IF NO. ELEMENTS(N) <= 0
	IF CC JUMP RET_ZERO;
	P0 = R0;                   // ADDRESS OF INPUT COMPLEX VECTOR
	P1 = R3;                   // SET LOOP COUNTER
	I0 = R2;                   // ADDRESS OF OUTPUT COMPLEX VECTOR
	R0 = W[P0++] (Z);          // FETCH INPUT[0]
	R3.L = R0.L + R1.L(NS) || R0 = W[P0++] (Z);  
				   // CALCULATE OUTPUT[0] AND FETCH INPUT[1]

	LSETUP(ST_VSADD,ST_VSADD) LC0 = P1;
ST_VSADD:   R3.L = R0.L + R1.L(NS) || R0 = W[P0++] (Z) || W[I0++] = R3.L;
				   // DO ADDITION, FETCH NEXT INPUT, STORE PREVIOUS OUTPUT 

RET_ZERO:
	RTS;

.__vecsadd_fr16.end:
