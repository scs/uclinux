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
$RCSfile: Pitch_A.asm,v $
$Revision: 1.4 $
$Date: 2006/05/24 07:46:55 $

Project:		G.729AB for Blackfin
Title:			Pitch_A
Author(s):		wuxiangzhi,
Revised by:		E. HSU

Description     :      Pitch related functions      

Prototype       :      _Pitch_ol_fast() 
					   _Enc_lag3()						  
					   _G_pitch()
						
******************************************************************************
Tab Setting:			4
Target Processor:		ADSP-21535
Target Tools Revision:	2.2.2.0
******************************************************************************

Modification History:
====================
$Log: Pitch_A.asm,v $
Revision 1.4  2006/05/24 07:46:55  adamliyi
Fixed the failing case for g729ab decoder for tstseq6. The issue is the uClinux GAS bug: it cannot treat the (m) option correctly.

Revision 1.4  2004/01/27 23:41:44Z  ehsu
Revision 1.3  2004/01/23 00:40:53Z  ehsu
Revision 1.2  2004/01/13 01:34:51Z  ehsu
Revision 1.1  2003/12/01 00:13:16Z  ehsu
Initial revision

Version         Date            Authors        		  Comments
0.0         04/19/2001          wuxiangzhi            Original

*******************************************************************************/ 


#include "G729_const.h" 
.extern _Inv_sqrt;
.extern old_wsp;
.extern rri0i0;
.extern scal_sig;
.extern scaled_signal;

.text;
.align 8;
_Pitch_ol_fast:
      .global _Pitch_ol_fast;
      .type  _Pitch_ol_fast,STT_FUNC;
      
	  LINK 328;
	  B0.H = old_wsp;
	  B0.L = old_wsp;
	  B1.H = scaled_signal;
	  B1.L = scaled_signal;
	  P0 = 112;	  
	  I0 = B0;
	  //for(i= -pit_max; i< L_frame; i+=2)
      //sum = L_mac(sum, signal[i], signal[i]);
      A1 = A0 = 0 || R7 = [I0++]; //sum = 0;
	  LSETUP(Pitch_ol_fast1,Pitch_ol_fast1) LC0 = P0;
      Pitch_ol_fast1:A0 += R7.L * R7.L (W32) || R7 = [I0++];
      CC = AV0; 
      	I0 = B0;
		P0 = 223;	
		R1.H = 0x10;
	 	R1.L = 0;
	 	R6.L = -3;
	  	R4 = R0 -|- R0 || R7 = [I0++];
	  	R5.L = 3;
	  	R0 = A0 ;
	  	I1 = B1;	  	 
	  	IF CC R5=R6;
		R6 = R0 - R1;	 		 	
		CC |= AN;
		IF !CC R5 = R4;		 		 	
		R6 = ASHIFT R7 BY R5.L (V,S) || R7 = [I0++];
  	    LSETUP(Pitch_ol_fast3_1,Pitch_ol_fast3_1) LC0 = P0 >> 1;
        Pitch_ol_fast3_1: R6 = ASHIFT R7 BY R5.L (V,S) || R7 = [I0++] || [I1++] = R6;
		R5 = R5 -|- R5 || W[I1++] = R6.L;
       	B0.H = scal_sig;
	   	B0.L = scal_sig;
       	R5.H = MIN_32;          //0x8000;   
//	   	R5.L = 0;
	   	P3 = B0;
	   	P1 = -21;
	   	R7 = 20;
	   	R6 = 19;	  
	   	P5 = P3 + (P1 << 1);
	   	P2 = 4;	 	   	   
	  	I0 = B0;//added code to transfer scal_sig[] buffer to G729_scratch buffer
	  	P0 = 160;
	  	I1 = SP;
	  	R2.L = W[I0++] || I1 += 2;	        
      	B2 = I1;//B2 holds the address of G729_scratch through out the routine
      	LSETUP(Pitch_ol_copy,Pitch_ol_copy) LC1 = P0;
	  	Pitch_ol_copy: MNOP ||W[I1++]=R2.L || R2.L = W[I0++];
      	P0 = 20;
/*****************************************************
//      for (i = 20; i < 40; i++) {
//        p  = scal_sig; p1 = &scal_sig[-i]; sum = 0;
//        for (j=0; j<L_frame; j+=2, p+=2, p1+=2) sum = L_mac(sum, *p, *p1);
//        L_temp = L_sub(sum, max);
//        if (L_temp > 0) { max = sum; T1 = i;   } }
******************************************************/
     	M0=-160;
     	I0 = SP;
     	P3 = -164;
     	MNOP || R2 = [I0++] || R3 = [P5++P2];
	   LOOP Pitch_ol_fast5 LC0 = P0>>1;
	   P0 = 38;
	   LOOP_BEGIN Pitch_ol_fast5;
		  A1 = R2.H * R3.L, A0 = R2.H * R3.H  || R2 = [I0++] || R3 = [P5++P2];
		  LSETUP(Pitch_ol_fast5_2,Pitch_ol_fast5_2) LC1 = P0;
Pitch_ol_fast5_2: A1 += R2.H * R3.L,A0 += R2.H * R3.H || R2 = [I0++] || R3 = [P5++P2];
		  R1 = (A1 += R2.H * R3.L),R0 = (A0 += R2.H * R3.H) ;
		  R6 += 1;
		  CC = R5 < R0;
		  IF CC R7 = R6;
		  R5 = MAX(R5,R0) || R2 = [I0++M0] || R3 = [P5++P3]; 
			R6 += 1;
		  CC = R5 < R1;
		  IF CC R7 = R6;
		  R5 = MAX(R5,R1) || R2 = [I0++] || R3 = [P5++P2];		
	   LOOP_END Pitch_ol_fast5;
       R0 = - R7;
	   P4 = R0;
	   P0 = 40;
	   P5 = B0;
	   R1 = 1;              //sum = 1;
	   P5 = P5 + (P4 << 1); //p = &scal_sig[-T1];
	   // for(i=0; i<L_frame; i+=2, p+=2) sum = L_mac(sum, *p, *p);
	   A0 = R1 || R2.H = W[P5++P2];
	   LSETUP(Pitch_ol_fast6,Pitch_ol_fast6) LC0 = P0;
       Pitch_ol_fast6: R0 = (A0 += R2.H * R2.H ) || R2.H = W[P5++P2];
       CALL _Inv_sqrt; //sum = Inv_sqrt(sum); 
	   R1.L = R1.L >> 1;
	   R6 = 1;	   
	   R2 = R5.L * R1.H (FU);
	   A0 = R5.H * R1.H, R3 = (A1 = R5.H * R1.L);
	   R0 = (A0 += R2.H * R6.L);
	   R0 = (A0 += R3.H * R6.L);
	   
	   R5.H = MIN_32;         //0X8000
	   R5.L = 0;
	   P3 = B0;
	   P1 = -41;
	   R4 = 39;//40;
	   R6 = 40;
	   P0 = 40;
	   P5 = P3 + (P1 << 1);
	   P2 = 4;
//    for (i = 40; i < 80; i++) { p  = scal_sig; p1 = &scal_sig[-i]; sum = 0;
//        for (j=0; j<L_frame; j+=2, p+=2, p1+=2) sum = L_mac(sum, *p, *p1);
//        L_temp = L_sub(sum, max);
//        if (L_temp > 0) { max = sum; T2 = i;   }  }
		I0 = SP;
		P3 = -164;
		R7 = PACK(R0.L, R7.L) || R2 = [I0++] || R3 = [P5++P2];
	   LOOP Pitch_ol_fast7 LC0 = P0>>1;
	   P0 = 38;
	   LOOP_BEGIN Pitch_ol_fast7; 
		  A1 = R2.H * R3.L,A0 = R2.H * R3.H  || R2 = [I0++] || R3 = [P5++P2];
		  LSETUP(Pitch_ol_fast7_2,Pitch_ol_fast7_2) LC1 = P0;
Pitch_ol_fast7_2: A1 += R2.H * R3.L,A0 += R2.H * R3.H  || R2 = [I0++] || R3 = [P5++P2];
		  R1 = (A1 += R2.H * R3.L), R0 = (A0 += R2.H * R3.H) || R2=[I0++M0] || R3 = [P5++P3];
		  R4 += 1;
		  CC = R5 < R0;
		  IF CC R6 = R4;
		  R5 = MAX(R5,R0); 
		  R4 += 1;
		  CC = R5 < R1;
		  IF CC R6 = R4;
		  R5 = MAX(R5,R1) || R2 = [I0++] || R3 = [P5++P2];		
	   LOOP_END Pitch_ol_fast7;
       R0 = - R6;
	   P4 = R0;
	   P0 = 40;
	   P5 = B0;
	   R1 = 1;
	   P5 = P5 + (P4 << 1); //for(i=0; i<L_frame; i+=2, p+=2) sum = L_mac(sum, *p, *p);
	   A0 = R1 || R2.H = W[P5++P2];
	   LSETUP(Pitch_ol_fast8,Pitch_ol_fast8) LC0 = P0;
       Pitch_ol_fast8: R0 = (A0 += R2.H * R2.H ) || R2.H = W[P5++P2];	   
       CALL _Inv_sqrt;
	   R1.L = R1.L >> 1 || [FP-4] = R7;
	   R4 = 1;	   
	   R2 = R5.L * R1.H (FU);
	   A0 = R5.H * R1.H, R3 = (A1=R5.H * R1.L); 
	   A0 += R2.H * R4.L;
	   R0 = (A0 += R3.H * R4.L);	   	   
	   R5.H = MIN_32;          //0X8000
	   R5.L = 0;
	   P3 = B0;
//	   P1 = -81;
	   P1 = -82;
	   R4 = 80;
	   R7 = 80;
	   P0 = 32;              // Bug find // loop count 80 <i<143 //changed from 31 to 32
	   P4 = P3 + (P1 << 1);
	   	P2 = 4;	
		P5 = -172;	
	   	I0 = SP;	   	
		R6 = PACK(R0.L, R6.L) || R2 = [I0++] || R3.L = W[P4++P2];  
		R3.H = W[P4++P2];
	   LOOP Pitch_ol_fast9 LC0 = P0>>1;
	   P0 = 38;
	   LOOP_BEGIN Pitch_ol_fast9;		  	   	  	   			   			   		
			A1 = R2.H * R3.L , A0 = R2.H * R3.H || R2 = [I0++] || R3.L = W[P4++P2];
		  	LSETUP(Pitch_ol_fast9_1,Pitch_ol_fast9_2) LC1 = P0>>1;
Pitch_ol_fast9_1:	A1 += R2.H * R3.H, A0 += R2.H * R3.L || R2 = [I0++] || R3.H = W[P4++P2];		  
Pitch_ol_fast9_2:  	A1 += R2.H * R3.L, A0 += R2.H * R3.H || R2 = [I0++] || R3.L = W[P4++P2];
		  	R0 = (A0 += R2.H * R3.L), R1 = (A1 += R2.H * R3.H) || R2 = [I0++M0] || R3.L = W[P4++P5];
		  	CC = R5 < R0;
		  	IF CC R4 = R7;
		  	R5 = MAX(R5,R0) || R2 = [I0++] || R3.L = W[P4++P2];
		  	R7 += 2;	  		  
		  	CC = R5 < R1;
		  	IF CC R4 = R7;
		  	R5 = MAX(R5,R1) || R3.H = W[P4++P2];
		  	R7 += 2;
	   	LOOP_END Pitch_ol_fast9;	   	      
	   	R0 = - R4;
	   	P5 = B0;
	   	P4 = R0;
	   	R7 = R4;	   	  
		I0 = SP;
	   	R7 += 1;
	   	P5 = P5 + (P4 << 1);
	   	P5 += -2;
	   	MNOP || R2.L = W[P5++P2] || R3 = [I0++];
	   	R2.H = W[P5++P2];	   
	   	A1 = R2.H * R3.H, A0 = R2.L * R3.H  || R3 = [I0++] || R2.L = W[P5++P2] ;	   
	   	LSETUP(Pitch_ol_fast10,Pitch_ol_fast11) LC0 = P0 >> 1;
Pitch_ol_fast10: 	A1 += R2.L * R3.H, A0 += R2.H * R3.H  || R3 = [I0++] || R2.H = W[P5++P2];
Pitch_ol_fast11: 	A1 += R2.H * R3.H, A0 += R2.L * R3.H   || R3 = [I0++] || R2.L = W[P5++P2] ;
	   	R1 = (A1 += R2.L * R3.H), R0 = (A0 += R2.H * R3.H) || [FP-8]=R6;	   
	   	CC = R5 < R0;
	   	IF CC R4 = R7;
	   	R5 = MAX(R0,R5);	   
       	R7 += -2;	   
	   	CC = R5 < R1;
	   	IF CC R4 = R7;
	   	R5 = MAX(R1,R5);
	   	R0 = - R4;
	   	P4 = R0;
	   	R1 = 1;
	   	P0 = 40;
	   	P5 = B0;	   // R1 = 1;
	   	P5 = P5 + (P4 << 1);
	   	A0 = R1 || R2.H = W[P5++P2];
	   LSETUP(Pitch_ol_fast12,Pitch_ol_fast12) LC0 = P0;
       Pitch_ol_fast12: R0 = (A0 += R2.H * R2.H ) || R2.H = W[P5++P2];
	   CALL _Inv_sqrt;
	   R1.L = R1.L >> 1 || R7=[FP-4];
	   R0 = 1;
	   R2 = R5.L * R1.H(FU);	   
	   A0 = R5.H * R1.H, R3 = (A1=R5.H * R1.L); 
	   A0 += R2.H * R0.L || R2=[FP-4];
	   R0 = (A0 += R3.H * R0.L) || R3=[FP-8];
	   R1.L = R6.L << 1(S);
	   R4 = PACK(R0.L, R4.L);  // R4.L = T3 R4.H = max3
//	   	R3.H = R0.L >>> 2(S);
	   
	   	R0.H = 5;
	   	R0.L = R1.L - R4.L(S);
	   	R1 = ABS R0(V);
	   	R1.L = R1.L - R0.H(S);
	   	CC = BITTST(R1,15);
	   	R3.H = R4.H >>> 2(S);
		R3.H = R3.H + R6.H(S);
		IF CC R6=R3;
       	R0.L = R0.L + R6.L(S);
	   	R5.L = 7;
	   	R1 = ABS R0(V);
	   	R1.L = R1.L - R5.L(S);
	   	CC = BITTST(R1,15);
	   	IF CC R6=R3;
       	R0.L = R7.L << 1;
	   	R0.L = R0.L - R6.L(S);
	   	R1 = ABS R0(V);
	   	R1.L = R1.L - R0.H(S);
	   	R5.H = 6554;
	   	CC = BITTST(R1,15);
	   	R1 = R6.H * R5.H;
	   	R2.H = R7.H + R1.H(S);
	   	IF CC R7 = R2;
//	   IF !CC JUMP Pitch_ol_fast15;	       
//		   Pitch_ol_fast15: R7.H = R7.H + R1.H(S);
       R0.L = R0.L + R7.L(S);
	   R0 = ABS R0(V);
	   R0.L = R0.L - R5.L(S);
	   CC = BITTST(R0,15);
//	   IF !CC JUMP Pitch_ol_fast16;
//	       R1 = R6.H * R5.H;
//		   R7.H = R7.H + R1.H(S);
//Pitch_ol_fast16:
		IF CC R7 = R2;
       R0.L = R7.H - R6.H(S);
	   CC = BITTST(R0,15);
	   IF CC R7 = R6;
	   R0.L = R7.H - R4.H(S);
	   CC = BITTST(R0,15);
	   IF CC R7 = R4;
	   R0 = R7.L;
	  UNLINK;
	  RTS;

.text;
.align 8;

_Enc_lag3:
	  .global _Enc_lag3;
      .type  _Enc_lag3,STT_FUNC;
	  // R0 HIGH T0_frac LOW T0
	  // R1.H = T0_max R1.L =T0_min
	  CC = BITTST(R2,0);
	  IF CC JUMP Enc_lag3_2;
	     R7 = 85;
		 R6 = R0.L;
		 CC = R6 <= R7;
		 IF !CC JUMP Enc_lag3_1_1;
		   R7.H = 3;
		   R7 = R7.H * R0.L(IS);
		   R7 += -58;
		   R7.L = R7.L + R0.H(S);
		   JUMP Enc_lag3_1_2;
Enc_lag3_1_1:
           R7 = 112;
		   R7.L = R7.L + R0.L(S);
Enc_lag3_1_2:
          R4 = 5;
          R3 = 20;
		  R3.H = 9;
		  R6.L = R0.L - R4.L(S);
		  R6 = MAX(R6,R3)(V);
		  R5.H = 143;
		  R5.L = 134;
		  R6.H = R6.L + R3.H(S);
		  R3.L = R6.H - R5.H(S);
		  CC = BITTST(R3,15);
		  IF !CC R6 = R5;
		  JUMP Enc_lag3END;
Enc_lag3_2:
         R7.H = 3;
		 R7.L = R0.L - R1.L(S);
		 R6 = R1;
		 R7 = R7.L * R7.H(IS);
		 R7 += 2;
		 R7.L = R7.L + R0.H(S);
Enc_lag3END:
	  RTS;

  
	  
	  
	  
_G_pitch:
	   .global _G_pitch;
      .type  _G_pitch,STT_FUNC;
	   LINK 4;
	   B3.H = rri0i0;
	   B3.L = rri0i0;
	   I1 = B2;
	   I3 = B3;
	   R5 = [I1++];
/*	   for(i=0; i<L_subfr; i++) scaled_y1[i] = shr(y1[i], 2); */
	   R4 = R5 >>> 2(V,S) || R5 = [I1++];
	   LSETUP(G_pitch1,G_pitch1) LC0 = P0 >> 1;
	   G_pitch1:  R4 = R5 >>> 2(V,S) || R5 = [I1++] || [I3++] = R4;
	   I1 = B2;
	   R0 = 1;           //s = 1;
	   A0 = 0;           //Overflow = 0;
/*	   for(i=0; i<L_subfr; i++) s = L_mac(s, y1[i], y1[i]);  */
	   A1 = R0 || R5 = [I1++];
	   LSETUP(G_pitch2,G_pitch2) LC0 = P0 >> 1;
	   G_pitch2: A0 += R5.L * R5.L, A1 += R5.H * R5.H || R5 = [I1++];
/*********************************************************
	   if (Overflow == 0) {
       exp_yy = norm_l(s);
       yy     = round( L_shl(s, exp_yy) );
       } else {
       s = 1;                  // Avoid case of all zeros 
       for(i=0; i<L_subfr; i++) s = L_mac(s, scaled_y1[i], scaled_y1[i]);
       exp_yy = norm_l(s);
       yy     = round( L_shl(s, exp_yy) );
       exp_yy = sub(exp_yy, 4); }
***********************************************************/       
	   A0 += A1(W32);
//#ifdef FLAG533	  
//		CC = V;
//#else	   
	   CC = AV0;
//#endif	   
	   IF CC JUMP G_pitch4;
	   		R0 = A0;
	      R7.L = SIGNBITS R0;
		  R1 = ASHIFT R0 BY R7.L;
		  R7.H = R1(RND);
		  JUMP G_pitch5;
G_pitch4:
       I3 = B3;
	   A0 = 0;
	   A1 = R0 || R5 = [I3++];
	   LSETUP(G_pitch4_1,G_pitch4_1) LC0 = P0 >> 1;
	   G_pitch4_1: A0 += R5.L * R5.L, A1 += R5.H * R5.H || R5 = [I3++];
	   R1 = (A0 += A1);
	   R7.L = SIGNBITS R1;
	   R5.L = 4;
	   R1 = ASHIFT R1 BY R7.L;
	   R7.H = R1(RND);
	   R7.L =  R7.L - R5.L(S);// for(i=0; i<L_subfr; i++) s = L_mac(s, xn[i], y1[i]); 	   
G_pitch5:
       I0 = B0;
	   I1 = B2;	   
	   A1 = A0 = 0 || R4 = [I0++] || R5 = [I1++];
	   LSETUP(G_pitch6,G_pitch6) LC0 = P0 >> 1;
G_pitch6: 	A0 += R5.L * R4.L, A1 += R5.H * R4.H || R4 = [I0++] || R5 = [I1++];	   
/****************************************************
	   if (Overflow == 0) {
       exp_xy = norm_l(s);
       xy     = round( L_shl(s, exp_xy) );
       } else {
       s = 0;
       for(i=0; i<L_subfr; i++) s = L_mac(s, xn[i], scaled_y1[i]);
       exp_xy = norm_l(s);
       xy     = round( L_shl(s, exp_xy) );
       exp_xy = sub(exp_xy, 2); }	   
*****************************************************/       
	   A0 += A1 (W32);
	   CC = AV0;	   
	   IF CC JUMP G_pitch7;
	   	R0 = A0; 
	     R6.L = SIGNBITS R0;
		 CC = R0 == 0;
		 IF CC R6 = R0;
		 R1 = ASHIFT R0 BY R6.L;
		 R6.H = R1(RND);
		 JUMP G_pitch8;
G_pitch7:
        I0 = B0;
		I3 = B3;		
		A1 = A0 = 0 || R4 = [I0++] || R5 = [I3++];
	    LSETUP(G_pitch7_1,G_pitch7_1) LC0 = P0 >> 1;
G_pitch7_1: 	A0 += R5.L * R4.L, A1 += R5.H * R4.H || R4 = [I0++] || R5 = [I3++];
		R1 = (A0 += A1);
		R6.L = SIGNBITS R1;
		R5.L = 2;
		R1 = ASHIFT R1 BY R6.L;
		R6.L = R6.L - R5.L(S);
		R6.H = R1(RND);		
//	    g_coeff[0] = yy; g_coeff[1] = sub(15, exp_yy); g_coeff[2] = xy; g_coeff[3] = sub(15, exp_xy); 		
G_pitch8:
        R5 = 15;
        I2 = B1;
		R4.L = R5.L - R7.L(S) || W[I2++] = R7.H;
		R4.L = R5.L - R6.L(S) || W[I2++] = R4.L;
		R0 = R6 >>> 16 || W[I2++] = R6.H;
		R5 = -15;
		R2 = R0 -|- R0 || R1.L = W[i2]; // if (xy <= 0) { g_coeff[3] = -15;   return( (Word16) 0); } 
		CC = R0 <= 0;
		IF CC R1=R5;
		R0 = MAX(R2,R0) || W[I2] = R1.L;		  
		IF CC JUMP G_pitchEND;
G_pitch9:
        R0 = R0 >>> 1(S) || W[I2] = R4.L;
		R1 = R7 >>> 16;
       	P0 = 15;
       	R2 = R0 << 16;
       	DIVS(R2,R1);    // get sign bit
       	LSETUP(_LP_ST,_LP_ST)LC1=P0;
_LP_ST:  DIVQ(R2,R1); // if( sub(gain, 19661) > 0) { gain = 19661; } 
		R5.L = R7.L - R6.L(S);
		R0 = GPITCH_CONST1;      //19661;
		R2.L =  ASHIFT R2.L BY R5.L(S);
		R0 = MIN(R0,R2)(V);
G_pitchEND:
       UNLINK;
	   RTS;





