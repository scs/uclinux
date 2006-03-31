/******************************************************************************
  Copyright(c) 2000-2004 Analog Devices Inc. IPDC BANGALORE, India. 

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 ******************************************************************************
  File Name      : cvvadd.asm
  Module Name    : Vector Library
  Label name     :  __cvecvadd_fr16
  Description    : This function computes complex vector vector addition
  Operand        : R0 - address of complex input vector A,
		   R1 - address of complex input vector B,
		   R2 - address of complex output vector
  Registers Used : R0,R1,R2,R3,I0,I1,P0,P1.

  Notes          : Input vectors should be in different banks to achieve 
		   the cycle count given below.

  CYCLE COUNT    : 13            N == 0
		 : 10 + 2*N      for other N
  'N' - NUMBER OF ELEMENTS

  CODE SIZE      : 40 BYTES
  
  DATE           : 21-02-01
******************************************************************************/

.text;
.global __cvecvadd_fr16;
.align 2;

__cvecvadd_fr16:
	P1 = [SP+12];              // NO. OF ELEMENTS IN INPUT VECTOR
	P0 = R0;                   // ADDRESS OF INPUT COMPLEX VECTOR1
	I0 = R1;                   // ADDRESS OF INPUT COMPLEX VECTOR2
	CC = P1 <= 0;              // CHECK IF NO. ELEMENTS(N) <= 0
	IF CC JUMP RET_ZERO;
	P2 = R2;                   // ADDRESS OF OUTPUT COMPLEX VECTOR
	R1 = [P0++];               // GET INPUTS FROM VECTOR1 AND VECTOR2
	R2 = [I0++];

	LSETUP(ST_CVVADD,END_CVVADD) LC0 = P1;
ST_CVVADD:   R3 = R1 +|+ R2(S) || R1 = [P0++];
					 // DO ADDITION, FETCH NEXT INPUTS FROM VEC.1

END_CVVADD:  [P2++] = R3 || R2 = [I0++]; // STORE RESULT IN OUTPUT VECTOR

RET_ZERO:
	RTS;

.__cvecvadd_fr16.end:
