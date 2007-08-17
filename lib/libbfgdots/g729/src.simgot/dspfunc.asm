// ****************************************************************************
// *** (c) Copyright 1999 Analog Devices  Corporations					   ***
// ***                                                                     ***
// *** Analog Devices Confidential & Sensitive. All Rights Reserved.	   ***
// ***                                                                     ***
// *** No part of this file may be modified or reproduced without explicit ***
// *** consent from Analog Devices Corporations.						   ***
// ***                                                                     ***
// *** All information contained in this file is subject to change without ***
// *** notice.                                                             ***
// ***                                                                     ***
// *** Function:                                                     	   ***
// ***                                                         			   ***
// *** Author: Xiangzhi,wu   xiangzhi.wu@analog.com    2001/04/04	       ***
// *** Performance:                       								   ***
// ****************************************************************************

/*****************************************************************************
Developed by Analog Devices Australia - Unit 3, 97 Lewis Road,
Wantirna, Victoria, Australia, 3152.  Email: ada.info@analog.com

Analog Devices, Inc.
BSD-Style License

libgdots
Copyright (c) 2007 Analog Devices, Inc.

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
  - Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
  - Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in
    the documentation and/or other materials provided with the
    distribution.
  - Neither the name of Analog Devices, Inc. nor the names of its
    contributors may be used to endorse or promote products derived
    from this software without specific prior written permission.
  - The use of this software may or may not infringe the patent rights
    of one or more patent holders.  This license does not release you
    from the requirement that you obtain separate licenses from these
    patent holders to use this software.

THIS SOFTWARE IS PROVIDED BY ANALOG DEVICES "AS IS" AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, NON-INFRINGEMENT,
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL ANALOG DEVICES BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, INTELLECTUAL PROPERTY RIGHTS, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
******************************************************************************
$RCSfile: Dspfunc.asm,v $
$Revision: 1.4 $
$Date: 2006/05/24 07:46:55 $

Project:		G.729AB for Blackfin
Title:			Dspfunc
Author(s):		wuxiangzhi,
Revised by:		E. HSU

Description     :      common utility 

Prototype       :      	_Log2()												
						_Inv_sqrt()					

******************************************************************************
Tab Setting:			4
Target Processor:		ADSP-21535
Target Tools Revision:	2.2.2.0
******************************************************************************

Modification History:
====================
$Log: Dspfunc.asm,v $
Revision 1.4  2006/05/24 07:46:55  adamliyi
Fixed the failing case for g729ab decoder for tstseq6. The issue is the uClinux GAS bug: it cannot treat the (m) option correctly.

Revision 1.4  2004/01/27 23:40:54Z  ehsu
Revision 1.3  2004/01/23 00:40:07Z  ehsu
Revision 1.2  2004/01/13 01:34:00Z  ehsu
Revision 1.1  2003/12/01 00:12:31Z  ehsu
Initial revision

Version         Date            Authors        		  Comments
0.0         04/04/2001          wuxiangzhi            Original

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
	  
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+548]; // tablog
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
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
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+552]; // tabsqr
	P1 = R0
	P3 = [SP++];
	R0 = [SP++];
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



	   
