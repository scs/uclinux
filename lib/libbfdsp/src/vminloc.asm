/******************************************************************************
  Copyright(c) 2000-2004 Analog Devices Inc. IPDC BANGALORE, India. 

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 ******************************************************************************
  File name      :  vminloc.asm 
 
  Description    : This program finds the location of minimum number 
			     in an given fractional input vector

  Registers used :
  Operands in  R0 & R1 
  R0 - INPUT value,     
  R1 - No of elements   
  R3,R7,P0,
 
  Special case   :
  If No.of vector elements are zero,function returns zero value.

  CYCLE COUNT    : 13            N == 0,1
		 : 32 + (N-1)/2  for other odd N
		 : 35 + N/2      for other even N
		 
  'N' - NUMBER OF ELEMENTS

  CODE SIZE      : 84 BYTES
 Modified on  26-03-01 for label end after RTS 
 Modified on 10.4.01 to modify the entry point label from 
 __vecminloc to __vecminloc_fr16
  
********************************************************************/
.text;
.global __vecminloc_fr16;
.align 2;

__vecminloc_fr16:
	    [--SP] = R7;                              // SAVE R7 TO STACK
	    P0 = R0;                                  // ADDRESS OF VECTOR
	    R0 = 0;                                   // MAKE LOCATION = 0 IF N = 0 OR 1
	    CC = R1 <= 1;
	    IF CC JUMP RET_ZERO;                      // RETURN ZERO IF N = 0 OR 1
#if defined(__WORKAROUND_CSYNC) || defined(__WORKAROUND_SPECULATIVE_LOADS)
	    NOP;
	    NOP;
	    NOP;
#endif

	    R2 = W[P0++](X);                          // TAKE FIRST ELEMENT
	    A0 = R2 || R2 = W[P0--](Z);                  // A0 = FIRST ELEMENT, TAKE SECOND ELEMENT
	    A1 = R2 || R2 = [P0++];                   // A1 = SECOND ELEMENT, TAKE FIRST TWO ELEMENTS IN R2

	    P1 = R1;                                  // P1 = NUMBER OF ELEMENTS (N)
	    R7 = R1;                                  // R7 = NUMBER OF ELEMENTS (N)
	    R0 = P0;                                  // R0 = ADDRESS OF THIRD ELEMENT
	    R1 = P0;                                  // R1 = ADDRESS OF THIRD ELEMENT
	    R3 = P0;                                  // R3 = ADDRESS OF THIRD ELEMENT

	    LSETUP(ST_VMINLOC,ST_VMINLOC) LC0 = P1>>1;// LOOP FOR N/2 TIMES
ST_VMINLOC: (R1,R0) = SEARCH R2(LT) || R2 = [P0++];   // SEARCH FOR FIRST MINIMUM, FETCH NEXT TWO ELEMENTS

	    CC = BITTST(R7,0);                        // CHECK WHETHER EVEN
	    IF !CC JUMP EVEN_SMPL;                    // IF EVEN JUMP

	    R2.H = 0X7FFF;                            // IF ODD, R2.H = MAX. VALUE
	    (R1,R0) = SEARCH R2(LT);                  // IF ODD CHECK WITH LAST ELEMENT
	    
EVEN_SMPL:  CC = A0 == A1; 
	    R1 += 2;                                  // ADDRESS OF ODD ELEMENT += 2
	    IF CC JUMP EQUAL;
	    CC = A0 < A1;                             // CHECK WHETHER ODD OR EVEN ELEMENT IS MAX.
	    JUMP DIFF;
EQUAL:      CC = R0 < R1;

DIFF:       IF !CC R0 = R1;                           // ASSIGN ADDRESS OF ODD ELEMENT(A1) TO R0 IF A1 IS GREATER
	    R0 = R0 - R3;                             // FIND OFFSET OF MAX. VALUE'S ADDRESS FROM START + 4
	    R0 >>= 1;                                 // OFFSET BY 2 (AS ELEMETS ARE OF SIZE 2 BYTES)
RET_ZERO:   R7 = [SP++];                              // RESTORE R7
	    RTS;
.__vecminloc_fr16.end:
		
