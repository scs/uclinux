/******************************************************************************
  Copyright(c) 2000-2004 Analog Devices Inc. IPDC BANGALORE, India. 

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 ******************************************************************************
  File name       : vmax.asm 
 
  Description     : This program finds maximum number in a given fractinal input vector.
		    This program operates on two data at a time.

  Registers used  :
  Operands in  R0 & R1 
  R0 - Index to input vector.
  R1 - NO  of elements. 
  R2,R3,P0,P1

  Special case   :
  If No.of vector elements are zero,function returns zero value.

  CYCLE COUNT    : 11             N == 0
		 : 15             N == 1
		 : 26 + N/2       for other even N
		 : 24 + (N-1)/2   for other odd N
		 
  'N' - NUMBER OF ELEMENTS

  CODE SIZE      : 60 BYTES
  Modified on  26-03-01 for label end after RTS
  
*********************************************************************************/

.text;
.global __vecmax_fr16;
.align 2;

__vecmax_fr16:
	    P0 = R0;                            // COPY THE ADDRESS OF INPUT VECTOR
	    R0 = 0;                             // SET MAX VALUE = 0 INITIALLY
	    CC = R1 <= 0;                       // CHECKS IF NO OF ELEMNETS IS ZERO
	    IF CC JUMP RET_ZERO;                // IF TRUE THEN RETURN ZERO AND EXIT

	    P1 = R1;                            // LOOP COUNTER = N-1 AS ONE ELEMENT IS FETCHED OUTSIDE
	    R0 = W[P0](X);                      // GET SIGN EXTENDED ELEMENT FROM VECTOR AS MAXIMUM VALUE
	    CC = R1 == 1;                       // CHECKS IF NO OF ELEMNETS IS ONE
	    IF CC JUMP RET_ZERO;                // IF TRUE THEN RETURN THE VALUE AND EXIT

	    R3 = [P0++];                        // GET NEXT ELEMENT
	    R0 = R3;
	    LSETUP(ST_VMAX,ST_VMAX) LC0 = P1>>1;// SET A LOOP FOR LOOP COUNTER VALUE = N
ST_VMAX:    R0 = MAX(R3,R0)(V) || R3 = [P0++];  // FIND THE MAXIMUM 
						// GET NEXT SIGN EXTENDED ELEMENT FROM INPUT VECTOR 
	    CC = BITTST(R1,0);
	    IF !CC JUMP EVEN_SMPL;
	    R3.H = 0X8000;
	    R0 = MAX(R3,R0)(V);
EVEN_SMPL:  R3 = 0;
	    R3.L = R0.H + R3.H(S);
	    R3 = R3.L(X);
	    R0 = R0.L(X);
	    CC = R0 < R3;
	    IF CC R0 = R3;

RET_ZERO:   

	    RTS;
.__vecmax_fr16.end:         
