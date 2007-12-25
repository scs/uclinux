/*****************************************************************************
Analog Devices, Inc.
BSD-Style License

This file is part of the libgdots library, an optimized codec library
for the Blackfin processor.

Copyright (c) 2007 Analog Devices, Inc.
All rights reserved.

The libgdots library, is free software, as in zero cost - it does not provide
the freedoms provided to you by other free software licenses.

For more information, see the top level COPYING file.

******************************************************************************
Project:		G.729AB for Blackfin
Title:			Dspfunc
Description     :      common utility
Prototype       :      	_Log2()
			_Inv_sqrt()

*******************************************************************************/

#include "G729_const.h"
.extern tablog;
.extern tabsqr;
.text;
.align 8;	   
_Log2:
      .global _Log2;
      .type  _Log2,STT_FUNC;
	  R1 = 0;
	  CC = R0 <= 0;
	  IF CC R0 = R1;
	  IF CC JUMP Log2END;
	  R6.L = SIGNBITS R0;
	  
	  I0.H = tablog;
	  I0.L = tablog;
	  R4 = ASHIFT R0 BY R6.L;
	  R1 = R4 >>> 25(S);
	  R4 = R4 >>> 10(S); 
	  R1 += -32;
	  R2 = R1 << 1 (S);
	  M0 = R2;
	  R6.H = 30;
	  R0.H = R6.H - R6.L(S);
	  BITCLR(R4,15);
	  R3 = R3-|-R3 || I0 += M0;
	  R3.H = W[I0++];
	  A0 = R3 || R3.L = W[I0];
	  R4.H = R3.H - R3.L(S);
	  NOP;	 
	  R0.L = (A0 -= R4.H * R4.L)(T);
Log2END:
	   RTS;


.text;
.align 8;	   
	   
_Inv_sqrt:
      .global _Inv_sqrt;
      .type  _Inv_sqrt,STT_FUNC;
           	              // R0 R1 R2 R3 ARE USED
                          // P0, P1 ARE USED
	   CC = R0 <= 0;
	   IF CC JUMP Inv_sqrtEND;
       R3.L = SIGNBITS R0;
	   R3.H = 30;
	   R0 = ASHIFT R0 BY R3.L;
	   R3.L = R3.H - R3.L(S);
	   CC = !BITTST(R3,0);
	   R1 = R0 >>> 1(S);
       IF CC R0 = R1;
       R3.H = 1;
	   R3.L = R3.L >>> 1(S);
	   R1 = R0 >>> 25(S);
	   P0 = R1;
	   R0 = R0 >>> 10(S);   
	   P1.H = tabsqr;
	   P1.L = tabsqr;
	   P0 += -16;
	   P1 = P1 + (P0 << 1);
	   BITCLR(R0,15);
	   R3.L = R3.L + R3.H(S) || R1 = W[P1++](Z);
	   R2 = R1 << 16 || R1.H = W[P1];	   
	   R1.L = R1.L - R1.H(S);
	   A1 = R2;
	   R1 = (A1 -= R1.L * R0.L);
	   R3 = - R3(V);
	   R1 = ASHIFT R1 BY R3.L(S);
           RTS;
Inv_sqrtEND:
	   R1.H = 0X3FFF;
	   R1.L = 0XFFFF;
	   RTS;



	   
