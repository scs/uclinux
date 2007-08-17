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
$RCSfile: Gainped.asm,v $
$Revision: 1.4 $
$Date: 2006/05/24 07:46:55 $

Project:		G.729AB for Blackfin
Title:			Gainped
Author(s):		wuxiangzhi,
Revised by:		E. HSU

Description     :      Gain predicts      

Prototype       :      _Gain_predict() 
					   _Gain_update()						  					   
						
******************************************************************************
Tab Setting:			4
Target Processor:		ADSP-21535
Target Tools Revision:	2.2.2.0
******************************************************************************

Modification History:
====================
$Log: Gainped.asm,v $
Revision 1.4  2006/05/24 07:46:55  adamliyi
Fixed the failing case for g729ab decoder for tstseq6. The issue is the uClinux GAS bug: it cannot treat the (m) option correctly.

Revision 1.4  2004/01/27 23:41:30Z  ehsu
Revision 1.3  2004/01/23 00:40:36Z  ehsu
Revision 1.2  2004/01/13 01:34:39Z  ehsu
Revision 1.1  2003/12/01 00:13:02Z  ehsu
Initial revision

Version         Date            Authors        		  Comments
0.0         04/19/2001          wuxiangzhi            Original

*******************************************************************************/ 

.extern _Log2;
.extern pred;
.extern tabpow;

.text;
.align 8;
_Gain_predict:
	   .global _Gain_predict;
      .type  _Gain_predict,STT_FUNC;
	  LINK 4;
	  // B2 POINTS TO past_qua_en
	  // B3 POINTS TO code
	  I0 = B3;
	  P0 = 40;
	  //L_tmp = 0;
      //for(i=0; i<L_subfr; i++) L_tmp = L_mac(L_tmp, code[i], code[i]);
	  A1 = A0 = 0 || R7 = [I0++];
	  LSETUP(Gain_predict1,Gain_predict1) LC0 = P0 >> 1;
      Gain_predict1: A0 += R7.L * R7.L, A1 += R7.H * R7.H || R7 = [I0++];
	  R0 = (A0 += A1);
	  CALL _Log2;      //Log2(L_tmp, &exp, &frac);
	  //L_tmp = Mpy_32_16(exp, frac, -24660); 
	  R1.L = -24660;
	  R1.H = 1;
	  R2 = (A0 = R0.H * R1.L), R3 = (A1 = R0.L * R1.L);
	  //L_tmp = L_mac(L_tmp, 32588, 32);
	  R4.H = 32588;	  
	  A0 += R3.H * R1.H;
	  R4.L = 32;	  
	  R0 = (A0 += R4.H * R4.L);	  
	  I0 = B2;
	  //L_tmp = L_shl(L_tmp, 10);                    
      //for(i=0; i<4; i++) L_tmp = L_mac(L_tmp, pred[i], past_qua_en[i]);
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+596]; // pred
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
	  A0 = A0 << 10 || R7 = [I0++] || R6 = [I1++];
	  A0 += R7.L * R6.L, A1  = R7.H * R6.H  || R7 = [I0++] || R6 = [I1++];
	  A0 += R7.L * R6.L, A1 += R7.H * R6.H;
	  R1 = 5439;
	  R0 = (A0 += A1);       //*gcode0
	  R7.H = 14;
	  R0 = R0.H * R1.L;      //L_tmp = L_mult(*gcode0, 5439);
	  R7.L = 32;
	  R0 = R0 >>> 8(S);      //L_tmp = L_shr(L_tmp, 8);
	  R0.L = R0.L >> 1;
	  R0.H = R7.H - R0.H(S); //*exp_gcode0 = sub(14,exp);
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+608]; // tabpow
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
	  R1 = R0.L * R7.L;	  	  
	  R2 = R1 >> 16;
	  P4 = R2;
	  R1 = R1 >>> 1(S);	  
	  BITCLR(R1,15);
	  P3 = 2;	  
	  P5 = P5 + (P4 << 1);
	  R3.L = R3.L - R3.L (NS) || R3.H = W[P5++P3];
	  A0 = R3 || R3.L = W[P5];
	  R1.H = R3.H - R3.L(S);
	  NOP;
	  R2 = (A0 -= R1.H * R1.L);  
	  R0.L = R2(RND);         //R0.H = *exp_gcode0, R0.L = *gcode0
      UNLINK;
      RTS;

_Gain_update:
	  .global _Gain_update;
      .type  _Gain_update,STT_FUNC;
	   LINK 4;
	   // I3 POINTS TO past_qua_en
	   // R7 = L_gbk12
	   R0 = [I3++];
	   R0 = PACK(R0.L,R0.H) || R1 = [I3--];
	   R2 = PACK(R1.L, R0.L) || [I3++] = R0;
	   R0 = ROT R7 BY 0 || [I3--] = R2;
	   CALL _Log2;
	   R7.H = 13;	   
	   R0.H = R0.H - R7.H(S);
	   R0.L = R0.L << 1;
	   R0 = R0 << 13(S);
	   R7.L = 24660;
	   R0 = R0.H * R7.L;
	   W[I3] = R0.H;
       UNLINK;
	   RTS;





