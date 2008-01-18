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
$RCSfile: Dec_ld8A.asm,v $
$Revision: 1.4 $
$Date: 2006/05/24 07:46:55 $

Project:		G.729AB for Blackfin
Title:			Dec_ld8a
Author(s):		wuxiangzhi,
Revised by:		E. HSU

Description     :      Main decoder function 

Prototype       :      	_Decod_ld8a()						
						_Dec_lag3()
						_Decod_ACELP()
						_Dec_gain()
						_Syn_filtD()

******************************************************************************
Tab Setting:			4
Target Processor:		ADSP-21535
Target Tools Revision:	2.2.2.0
******************************************************************************

Modification History:
====================
$Log: Dec_ld8A.asm,v $
Revision 1.4  2006/05/24 07:46:55  adamliyi
Fixed the failing case for g729ab decoder for tstseq6. The issue is the uClinux GAS bug: it cannot treat the (m) option correctly.

Revision 1.4  2004/01/27 23:40:35Z  ehsu
Revision 1.3  2004/01/23 00:39:53Z  ehsu
Revision 1.2  2004/01/13 01:33:52Z  ehsu
Revision 1.1  2003/12/01 00:12:21Z  ehsu
Initial revision

Version         Date            Authors        		  Comments
0.0         11/20/2002          wuxiangzhi            Original

*******************************************************************************/ 
.extern D_exc;                 
.extern D_exc_1;               
.extern D_gain_code;           
.extern D_gain_pitch;          
.extern D_lsp_old;             
.extern D_mem_syn;             
.extern D_old_T0;              
.extern D_old_exc;             
.extern D_old_exc_1;           
.extern D_past_ftyp;           
.extern D_past_qua_en;         
.extern D_seed;                
.extern D_sh_sid_sav;          
.extern D_sharp;               
.extern D_sid_sav;             
.extern _D_lsp;                
.extern _Dec_cng;              
.extern _Gain_predict;         
.extern _Gain_update;          
.extern _Int_qlpc;             
.extern _Pred_lt_3;            
.extern gbk1;                  
.extern gbk2;                  
.extern imap1;                 
.extern imap2;
.extern rri0i0;                
.extern seed_fer;              
.extern synth;                 
.extern synth_1;               

.text;
.align 8;
  	
_Syn_filtD:
//	  .global _Syn_filtD;
//      .type  _Syn_filtD,STT_FUNC;
	  // B0
	  // B1
	  // B2
	  // P0
	  // B3
	  // R7
	  	
	  	I1 = B1;                // I2 POINTS TO x	 
	  	I3 = B3;
	  	I0 = B0;	              //I0 points to a[0] 
	  	I2 = B2;	  
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+436]; // rri0i0
	P4 = R0
	P3 = [SP++];
	R0 = [SP++];
	  	P1 = 10;
	  	R3.L = 1; 
	  	R3.H = R3.L << 14 || R4 = [I3++];	  
		MNOP || [P4++] = R4 || R4 = [I3++];	
		MNOP || [P4++] = R4 || R4 = [I3++];	
		MNOP || [P4++] = R4 || R4 = [I3++];	
		MNOP || [P4++] = R4 || R7 = [I3];	
		I3 = P4;
		R2 = R5-|-R5|| R5 = [I1++] || [P4++] = R7;	  		 	     	  		  		
	  	R4 = [I0++];
	  	ASTAT = R2;   
	  	A1 = R5.H * R4.L , A0 = R5.L * R4.L (W32) || R6 = [I3] || I3 -= 2;
	  	M1 = -20;
//	  	A0 -= R6.H * R4.H(W32) || R4 = [I0++] ;   
	  	LOOP Syn_filt2 LC0 = P0>>1;
	  	LOOP_BEGIN Syn_filt2;	        
		  	A0 -= R6.H * R4.H(W32) || R4 = [I0++];  
 			A1 -= R6.H * R4.L, A0 -= R6.L * R4.L(W32) || R6.H = W[I3--];
		 	A1 -= R6.L * R4.H, A0 -= R6.H * R4.H(W32) || R4 = [I0++] || R6.L = W[I3--];
			A1 -= R6.H * R4.L, A0 -= R6.L * R4.L(W32) || R6.H = W[I3--];
		 	A1 -= R6.L * R4.H, A0 -= R6.H * R4.H(W32) || R4 = [I0++] || R6.L = W[I3--];
			A1 -= R6.H * R4.L, A0 -= R6.L * R4.L(W32) || R6.H = W[I3--];
		 	A1 -= R6.L * R4.H, A0 -= R6.H * R4.H(W32) || R4 = [I0++] || R6.L = W[I3--];
		 	A1 -= R6.H * R4.L, A0 -= R6.L * R4.L(W32) || R6.H = W[I3--];
		 	A1 -= R6.L * R4.H, A0 -= R6.H * R4.H(W32) || R4 = [I0++M1] || R6.L = W[I3--];		 	
          	A1 -= R6.H * R4.L, A0 -= R6.L * R4.L(W32) || I3 -= M1 || R4 = [I0++];
          	A0 = A0 << 3  ;
          	A0 = A0 (S);
	  		CC |= AV0;
          	R6.L = (A0 += R3.L*R3.H) (T)  ;		  	  		  
			NOP;
          	A1 -= R6.L * R4.H(W32) || W[I2++] = R6.L;
         	A1 = A1 << 3 ;
          	A1 = A1 (S) ;
	  		CC |= AV1;
          	R6.H = (A1 += R3.L*R3.H) (T) || R5 = [I1++];          	
		  	[P4++] = R6 || A1 = R5.H * R4.L , A0 = R5.L * R4.L (W32);
		  	W[I2++] = R6.H;// || A0 -= R6.H * R4.H(W32) || R4 = [I0++];  
	  LOOP_END Syn_filt2;
			I3 = B3;
		  	IF !CC JUMP Syn_filt8;		 
//		  	P1 = -480;
//	  		SP = SP + P1;	
	  		
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+16]; // D_old_exc
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
		  	P5 = I0;
		  	P1 = 234;
		  	R1 = [I0++];
		  	R0 = R1 >>> 2(V,S) ||  R1 = [I0++];
		LSETUP(Syn_filt7,Syn_filt7) LC0 = P1 >> 1;
Syn_filt7: R0 = R1 >>> 2(V,S) ||  R1 = [I0++] || [P5++] = R0;

	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+436]; // rri0i0
	P4 = R0
	P3 = [SP++];
	R0 = [SP++];
	    	I1 = B1;  	  	 
	  		R4 = [I3++];	  
			MNOP || [P4++] = R4 || R4 = [I3++];	
			MNOP || [P4++] = R4 || R4 = [I3++];	
			MNOP || [P4++] = R4 || R4 = [I3++];	
			MNOP || [P4++] = R4 || R4 = [I3];	
			I3 = P4;
			R2 = R5-|-R5|| R5 = [I1++] || [P4++] = R4;	          		  	             
	  		P2 = B0;
	  		I2 = B2;	  	  			  	
	  		R4 = [P2++];
	  		ASTAT = R2;   
	  		A1 = R5.H * R4.L , A0 = R5.L * R4.L (W32) || R6 = [I3] || I3 -= 2;
	  		A0 -= R6.H * R4.H(W32) || R4 = [P2++];  
	  	LOOP Syn_filt3 LC0 = P0>>1;
	  	P0 = -20;
	  	LOOP_BEGIN Syn_filt3;	        
		  	
 			A1 -= R6.H * R4.L, A0 -= R6.L * R4.L(W32) || R6.H = W[I3--];
		 	A1 -= R6.L * R4.H, A0 -= R6.H * R4.H(W32) || R4 = [P2++] || R6.L = W[I3--];
			A1 -= R6.H * R4.L, A0 -= R6.L * R4.L(W32) || R6.H = W[I3--];
		 	A1 -= R6.L * R4.H, A0 -= R6.H * R4.H(W32) || R4 = [P2++] || R6.L = W[I3--];
			A1 -= R6.H * R4.L, A0 -= R6.L * R4.L(W32) || R6.H = W[I3--];
		 	A1 -= R6.L * R4.H, A0 -= R6.H * R4.H(W32) || R4 = [P2++] || R6.L = W[I3--];
		 	A1 -= R6.H * R4.L, A0 -= R6.L * R4.L(W32) || R6.H = W[I3--];
		 	A1 -= R6.L * R4.H, A0 -= R6.H * R4.H(W32) || R4 = [P2++P0] || R6.L = W[I3--];		 	
          	A1 -= R6.H * R4.L, A0 -= R6.L * R4.L(W32)  || R4 = [P2++];
          	A0 = A0 << 3  || I3 -= M1;
          	A0 = A0 (S);
          	R6.L = (A0 += R3.L*R3.H) (T)  ;		  	  		  
//			R0 = R1 >>> 2(V,S) ||  R1 = [I0++] || [P5++] = R0;
			NOP;
          	A1 -= R6.L * R4.H(W32) || W[I2++] = R6.L;
         	A1 = A1 << 3 ;
          	A1 = A1 (S) ;
          	R6.H = (A1 += R3.L*R3.H) (T) || R5 = [I1++];          	
		  	[P4++] = R6 || A1 = R5.H * R4.L , A0 = R5.L * R4.L (W32);
		  	W[I2++] = R6.H || A0 -= R6.H * R4.H(W32) || R4 = [P2++];    
	  	LOOP_END Syn_filt3;			
//	  		P1 = 480;
//	  		SP = SP + P1;
	  		I3 = B3;
Syn_filt8:      
		  	P5 = B2;
          	P5 += 60;

		  	R6 = [P5++];
			MNOP || [I3++] = R6 || R6 = [P5++];
			MNOP || [I3++] = R6 || R6 = [P5++];
			MNOP || [I3++] = R6 || R6 = [P5++];
			MNOP || [I3++] = R6 || R6 = [P5++];
			[I3] = R6;
	  		
	   RTS;	
_Decod_ld8a:
	  .global _Decod_ld8a;
      .type  _Decod_ld8a,STT_FUNC;
      		P5 = R0;
	  		LINK 24+20;
	  		P0 = R0;	  
	  		[FP-24]= R3;
	  //*** [FP-12] T2
	  //*** BIT 2 OF [FP-16] IS i_subfr
	  //*** BIT 0 OF [FP-16] IS bfi
	  //*** BIT 1 OF [FP-16] IS  BIT 1 IS ftyp AND Vad
	  //*** [FP-20] T0 AND T0_frac	  
	  		R0 = W[P5](Z);
	  		R6 = ROT R0 BY 0 || R7 = [P5++];
	  		R1 = R7 >> 16 || [FP-8] = R1;
	  		[FP-4] = P5;
	  		CC = R0 == 1;
	  		IF !CC JUMP Decod_ld8k1;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+120]; // D_past_ftyp
	P4 = R0
	P3 = [SP++];
	R0 = [SP++];
	  		R2 = W[P4](Z);
	  		CC = R2 == 1;
			R1 = CC;
			W[P5-2] = R1;
Decod_ld8k1:
      		CC = R1 == 1;          
	    	BITSET(R6,1);
	    	IF CC R0 = R6;
      		[FP-16] = R0;		
	  		IF CC JUMP Decod_ld8AMain;
	  		R7 = [FP-8];
	  		CALL _Dec_cng;
Decod_ld8k5:
      		R0 = [FP-16];
	  		R0 = ROT R0 BY -3 || R6 = [FP-8];	  
	  		R1 = CC;
	  		R2 = 80;	  		
	  		R2 = R2.L * R1.L (IS) || R0 = [FP-8];	  			  
			R0 += 24;
			IF !CC R0 = R6;
			B0 = R0;								
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+24]; // D_exc
	R6 = R0
	P3 = [SP++];
	R0 = [SP++];
			R6 = R6 + R2;
			B1 = R6;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+4]; // synth
	R6 = R0
	P3 = [SP++];
	R0 = [SP++];
			R6 = R6 + R2;
			B2 = R6;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+32]; // D_mem_syn
	B3 = R0
	P3 = [SP++];
	R0 = [SP++];
		  	P0 = 40;
			CALL _Syn_filtD;
	      	R7 = [FP-16];
		  	CC = BITTST(R7,2);
		  	IF CC JUMP Decod_ld8k10;
		  	BITSET(R7,2);
		  	[FP-16] = R7;
		  	JUMP Decod_ld8k5;
Decod_ld8k10:
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+108]; // D_old_T0
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+104]; // D_sharp
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
		  	R7.L = W[I0];
		  	R6 = 3277;
		  	W[I1] = R6.L;
		  	[FP-12] = R7;
		  	JUMP Decod_ld8aLoopEnd;
Decod_ld8AMain:
      		R0 = 11111;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+144]; // D_seed
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
	  		R1 = SP;
	  		MNOP ||W[I0] = R0.L || R0 = [FP-4];
	  		R2 = [FP-16];
	  		CALL _D_lsp;  	  
	  		R0 = [FP-4];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+92]; // D_lsp_old
	B0 = R0
	P3 = [SP++];
	R0 = [SP++];
	  		R0 += 4;
	  		B1 = SP;
	  		R7 = [FP-8];
	  		B2 = R7;
	  		R7 += 24;
	  		B3 = R7;
	  		[FP-4] = R0;
	  		CALL _Int_qlpc;
	  		I0 = SP;
	  		I1 = B0;
	  		P0 = 5;
	  		R7 = [I0++];
	  		LSETUP(Decod_ld8a1,Decod_ld8a1) LC0 = P0;
Decod_ld8a1: 	MNOP || [I1++] = R7 || R7 = [I0++];
Decod_ld8aLoopBegin:
          	P0 = [FP-4];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+108]; // D_old_T0
	P2 = R0
	P3 = [SP++];
	R0 = [SP++];
		  	R7 = [FP-16];
		  	CC = BITTST(R7,2);
		  	R0 = W[P0++](Z);
		  	[FP-4] = P0;
		  	IF CC JUMP Decod_ld8aLoop2;
		    R1 = W[P0++](Z);
			CC = BITTST(R7,0);
			[FP-4] = P0;
			IF CC JUMP Decod_ld8aLoop1;
			CC = R1 == 0;
			IF !CC JUMP Decod_ld8aLoop1;
			CALL _Dec_lag3;
			W[P2] = R0.H;
			JUMP Decod_ld8aLoop1_1;
Decod_ld8aLoop1:
            R0 = W[P2](Z);   //T0
			R7 = 143;     //PIT_MAX
			R1 = 1;      
			R1 = R0 + R1;  //old_T0
			R1 = MIN(R7,R1)(V);
			R0 = PACK(R0.L, R0.H) || W[P2] = R1.L;  //bug find
Decod_ld8aLoop1_1:
            R1 = R0 >> 16 || [FP-20] = R0;
			[FP-12] = R1;   // T2[0]
			JUMP Decod_ld8aLoop3;
Decod_ld8aLoop2:
            CC = BITTST(R7,0);
			IF CC JUMP Decod_ld8aLoop2_1;
			R1 = [FP-20];
 			CALL _Dec_lag3;
			W[P2] = R0.H;
			JUMP Decod_ld8aLoop2_2;
Decod_ld8aLoop2_1:
            R0 = W[P2](Z);
			R7 = 143;
			R1 = 1;
			R1 = R0 + R1;
			R1 = MIN(R7,R1)(V);
			R0 = PACK(R0.L, R0.H) || W[P2] = R1.L;            
Decod_ld8aLoop2_2:
            R1 = [FP-12];
            R1 = PACK(R0.H,R1.L) || [FP-20] = R0;
			[FP-12] = R1;
Decod_ld8aLoop3:             
			 R7 = - R0(V);
			 P0 = 40;
			 R6 = R7 >> 16 || R0 = [FP-16];
			 R7 = R7.L(X);
			 R6 = R6.L(X);
             CC = BITTST(R0,2);
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+28]; // D_exc_1
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+24]; // D_exc
	P4 = R0
	P3 = [SP++];
	R0 = [SP++];
			 IF !CC P5 = P4;
Decod_ld8aLoop3_1:
			 	P3 = R7;
			 	P4 = R6;
			 	CALL _Pred_lt_3;
			 	R4 = 13849;
			 	A1 = R4 || R7 = [FP-16];
			 	R7 = ROT R7 BY -1 || P1 = [FP-4];			 				
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+112]; // seed_fer
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
			 	A0 = R4 || R3 = W[P5](Z);
			 	R5.H = 31821;			 
			 	R2 = (A0+=R3.L * R5.H)(IS) || P0 = [FP-4];			 				 	
			 	R7 = 13;			 
			 	R1 = EXTRACT(R2,R7.L)(Z) || R6 = W[P1++](Z);			 
			 	IF !CC R1=R6;
			 	R7 = (A1+=R2.L * R5.H)(IS) || R5 = W[P1++](Z);
			 	IF CC P1 = P0;
			 	IF !CC R7=R3;
			 	[FP-4] = P1;			 				 			 				
			 	R6 = 4;
			 	R0 = EXTRACT(R7,R6.L)(Z) || W[P5] = R7.L;
				IF !CC R0=R5;
			 	P5 = [FP-24];
			 	CALL _Decod_ACELP;			 
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+104]; // D_sharp
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
			 	MNOP || R7.L = W[I0] || R6 = [FP-20];
			 	R5 = R6 >> 16|| P2 = [FP-4];
			 	P1 = R5;
			 	P0 = 40;
			 	I0 = P5;	
			 	R7.L = R7.L << 1(S) || R0 = W[P2++](Z);			 
			 	[FP-4] = P2;
			 CC = P0 < P1;
			 IF CC JUMP Decod_ld8aLoop6;
			    P0 -= P1;
				P1 = P5 + (P1 << 1);
				I1 = P1;
				R7.H = W[I0++];
				LOOP Decod_ld8aLoop5_1 LC0 = P0;
				LOOP_BEGIN Decod_ld8aLoop5_1;
				    R6 = R7.H * R7.L || R5.L = W[I1]; 
					R5.L = R5.L + R6.H(S) || R7.H = W[I0++];
					W[I1++] = R5.L;
				LOOP_END Decod_ld8aLoop5_1;
Decod_ld8aLoop6:
               R1 = [FP-16];   //bfi  
               R2 = [FP-24];                                           
			   CALL _Dec_gain;		   			  			   
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+140]; // D_gain_pitch
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+132]; // D_gain_code
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+104]; // D_sharp
	I2 = R0
	P3 = [SP++];
	R0 = [SP++];

				R4.L = W[I0];        //sharp = gain_pitch
			   	R6.L = 13017;
			   	R5.L = 3277;
			   	R3 = MIN(R4,R6)(V) || R4.H = W[I1];
			   	R3 = MAX(R3,R5)(V) || R0 = [FP-16];    
			  	R2 = ROT R0 BY -3 || W[I2] = R3.L ;
			  	R1 = CC;
			  	R2 = 80;
			  	R2 = R2.L * R1.L (IS) || R6 = [FP-24];
			  	I1 = R6;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+24]; // D_exc
	R7 = R0
	P3 = [SP++];
	R0 = [SP++];
			  	R7 = R7 + R2;
			  	P4 = R7;
				B1 = R7;
				P0 = 19;	
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+4]; // synth
	R5 = R0
	P3 = [SP++];
	R0 = [SP++];
			  	R5 = R5 + R2 (S) || R6 = [P4];
			  	B2 = R5;			  			  				  	
			  	A0 = R6.L * R4.L, A1 = R6.H * R4.L || R6 = [I1++];
				R2 = (A0 += R6.L * R4.H), R3 = (A1 += R6.H * R4.H ) (S2RND) || R1=[FP-8];
				R2.L = R2(RND) || R5=[FP-8];
				R5 += 24;
				IF !CC R5=R1;
				B0 = R5;
				R2.H = R3(RND) || R6 = [P4+4];				  
			  	LOOP Decod_ld8aLoop8 LC0 = P0;
			  	LOOP_BEGIN Decod_ld8aLoop8;
			      	A0 = R6.L * R4.L, A1 = R6.H * R4.L || R6 = [I1++];
				  	R2 = (A0 += R6.L * R4.H), R3 = (A1 += R6.H * R4.H ) (S2RND) || [P4++] = R2;
				  	R2.L = R2(RND);
				  	R2.H = R3(RND) || R6 = [P4+4];				  
			  	LOOP_END Decod_ld8aLoop8;
			  	[P4] = R2;         		
         		
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+32]; // D_mem_syn
	B3 = R0
	P3 = [SP++];
	R0 = [SP++];
		  		P0 = 40;		  		
		  		CALL _Syn_filtD;
Decod_ld8aLoop13:
	      		R7 = [FP-16];
		  		CC = BITTST(R7,2);
		  		BITSET(R7,2);
		  		[FP-16] = R7;
		  IF !CC JUMP Decod_ld8aLoopBegin;
Decod_ld8aLoopEnd:

// wxz add for G729b
      R7 = [FP-16];
      CC = BITTST(R7,0);
	  IF CC JUMP Decod_ld8kEND2;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+24]; // D_exc
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
		 P0 = 40;
		 A1 = A0 = 0 || R7 = [I0++];
		 LSETUP(Decod_ld8kEND1,Decod_ld8kEND1) LC0 = P0;
         Decod_ld8kEND1: A0 += R7.L * R7.L, A1 += R7.H * R7.H || R7 = [I0++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+128]; // D_sh_sid_sav
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
		 R0 = (A0 += A1);
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+148]; // D_sid_sav
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
		 R7.L = SIGNBITS R0;
		 R0 = ASHIFT R0 BY R7.L(S);
		 R7.H = 16;
		 R0.L = R0(RND);
		 R7.L = R7.H - R7.L(S) || W[I1] = R0.L;
		 W[I0] = R7.L;
Decod_ld8kEND2:

	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+20]; // D_old_exc_1
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
		P0 = 154;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+16]; // D_old_exc
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
//	    R1 = ROT R6 BY -2 || 
	    R7 = [I0++] || R6 = [FP-16];
		LSETUP(Decod_ld8aLoopEnd1,Decod_ld8aLoopEnd1) LC0 = P0 >> 1;
        Decod_ld8aLoopEnd1: MNOP || [I1++] = R7 || R7 = [I0++];
		CC = BITTST(R6,1);
		R1 = CC;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+120]; // D_past_ftyp
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
		R0 = [FP-12];
		W[I0] = R1.L;   // R1 = VAD
	  UNLINK;
	  RTS;

_Dec_lag3:
	  .global _Dec_lag3;
      .type  _Dec_lag3,STT_FUNC;
	  CC = BITTST(R7,2);
	  IF CC JUMP Dec_lag3_2;
	  R6 = 197;
	  CC = R0 < R6;
	  IF !CC JUMP Dec_lag3_1;
	  R6.L = 10923;
	  R6.H = 2;	  	  
	  R6.H = R6.H + R0.L(S);
	  R5.H = 19;
	  R1 = R6.H * R6.L;
	  R1.L = R5.H + R1.H(S);
	  R5.L = 3;
	  R2 = R1.L * R5.L(IS);
	  R0 = R0 - R2(S);
	  R0 += 58;
	  R0 = PACK(R1.L, R0.L);
	  JUMP Dec_lag3END;
Dec_lag3_1:
      R1 = 112;
	  R0.H = R0.L - R1.L(S);
	  R0 = PACK(R0.H, R1.H);
	  JUMP Dec_lag3END;
Dec_lag3_2:
      R7.H = 5;
	  R7.L = 20;
	  R6.H = 9;
	  R5.L = R1.H - R7.H(S);
	  R3.H = 143;
	  R3.L = 134;
	  R5 = MAX(R5,R7)(V);
	  R5.H = R5.L + R6.H(S);
	  R4.L = R5.H - R3.H(S);
	  CC = BITTST(R4,15);
	  IF !CC R5 = R3;
	  R2.L = 2;
	  R2.H = 10923;
	  R2.L = R0.L + R2.L(S);
	  R7.L = 1;
	  R2 = R2.H * R2.L;
	  R3 = 3;
	  R2.L = R2.H - R7.L(S);
	  R4 = 2;
	  R0.H = R2.L + R5.L(S);
	  R0.L = R0.L - R4.L(S);
	  R3 = R2.L * R3.L(IS);
	  R0.L = R0.L - R3.L(S);
Dec_lag3END:
	   RTS;

_Decod_ACELP:
	   .global _Decod_ACELP;
      .type  _Decod_ACELP,STT_FUNC;
	   R7.H = 5;
	   R7.L = 3;
	   R2 = EXTRACT(R1,R7.L)(Z);  // P0
	   R1.L = R1.L >>> 3(S);
	   R2 = R2.L * R7.H(IS);
	   R3 = EXTRACT(R1,R7.L)(Z);  // P1
	   P0 = R2;
	   R1.L = R1.L >>> 3(S);
	   R3 = R3.L * R7.H(IS);
	   R2 = EXTRACT(R1,R7.L)(Z);  // P2
	   R3 += 1;
	   R2 = R2.L * R7.H(IS);
	   P1 = R3;
	   CC = BITTST(R1,3);
	   R1.L = R1.L >>> 4(S);
	   R2 += 2;
	   R3 = EXTRACT(R1,R7.L)(Z);   // P3
	   P2 = R2;
//	   R2 = 0;
//	   R4 = 1;
//	   IF CC R2 = R4;
	   R2 = CC;
	   R6.H = 8191;
	   R6.L = -8192;
	   R3 = R3.L * R7.H(IS);
	   I0 = P5;
	   R3 += 3;
	   P4 = 20;
	   R3 = R3 + R2;
	   R7 = 0;
	   P3 = R3;
	   LSETUP(Decod_ACELP1,Decod_ACELP1) LC0 = P4;
       Decod_ACELP1: [I0++] = R7;
	   P0 = P5 + (P0 << 1);
	   P1 = P5 + (P1 << 1);
	   P2 = P5 + (P2 << 1);
	   P3 = P5 + (P3 << 1);
	   R5 = PACK(R6.L,R6.H);
	   CC = BITTST(R0,0);
	   IF !CC R5 = R6;
       R5 = PACK(R6.L,R6.H) || W[P0] = R5.L;
	   CC = BITTST(R0,1);
	   IF !CC R5 = R6;
       R5 = PACK(R6.L,R6.H) || W[P1] = R5.L;
	   CC = BITTST(R0,2);
	   IF !CC R5 = R6;
       R5 = PACK(R6.L,R6.H) || W[P2] = R5.L;
	   CC = BITTST(R0,3);
	   IF !CC R5 = R6;
       R5 = PACK(R6.L,R6.H) || W[P3] = R5.L;
	   RTS;


_Dec_gain:
	  .global _Dec_gain;
      .type  _Dec_gain,STT_FUNC;
	  	LINK 8;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+140]; // D_gain_pitch
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
	  	R7 = ROT R1 BY -1 || [FP-4] = R0 || R6.L = W[I0];
	  	R0 = R2 -|- R2 || [FP-8] = R2;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+96]; // D_past_qua_en
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
	  	IF !CC JUMP Dec_gain2;	  	  
	  	I1 = P5;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+132]; // D_gain_code
	I2 = R0
	P3 = [SP++];
	R0 = [SP++];
	  	R7.H = 29491;	  
	  	R7.L = 32111;
	  	R4 = R6.L * R7.H || R6.H = W[I2];
	  	R3 = R6.H * R7.L || R1 = W[P5++](X);
	  	R4 = MIN(R4,R7)(V) || W[I2] = R3.H;	  	  	  	  
		R0 = R0 + R1(S) || R1 = W[P5++](X);
      	R0 = R0 + R1(S) || R1 = W[P5++](X);
      	R0 = R0 + R1(S) || R1 = W[P5++](X);
      	R0 = R0 + R1(S) || W[I0] = R4.H;
	  	R0 = R0 >>> 2(S) || R2 = [I1++];
	  	R1.H = 4096;
	  	R1.L = -14336;	 
	  	R0.L = R0.L - R1.H(S) || R3 = [I1];
	  	R0 = MAX(R0,R1)(V);	 
	  	R3 = PACK(R3.L, R2.H);
	  	R2 = PACK(R2.L,R0.L) || [I1--] = R3;
	  	[I1] = R2;
	  	JUMP Dec_gainEND;
Dec_gain2:
		B3 = R2;
		B2 = P5;
	   CALL _Gain_predict;  // R0.L = gcode0, R0.H = exp_gcode0
	   R1 = [FP-4];
	   R7.L = 4;
	   R6.L = 0X040C;
	   R2 = EXTRACT(R1,R7.L)(Z);
	   R3 = EXTRACT(R1,R6.L)(Z);
	   P2 = R2;
	   P3 = R3;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+428]; // imap1
	P0 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+432]; // imap2
	P1 = R0
	P3 = [SP++];
	R0 = [SP++];
	   P0 = P0 + (P3 << 1);
	   P1 = P1 + (P2 << 1);
	   R2 = W[P0](Z);
	   R3 = W[P1](Z);
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+140]; // D_gain_pitch
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+132]; // D_gain_code
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
	   P3 = R2;
	   P2 = R3;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+600]; // gbk1
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+604]; // gbk2
	P4 = R0
	P3 = [SP++];
	R0 = [SP++];
	   P3 = P5 + (P3 << 2);
	   P2 = P4 + (P2 << 2);
	   R7 = [P3];
	   R5 = R7 >> 16 || R6 = [P2];
	   R1.L = R7.L + R6.L(S);
	   R4 = R6 >> 16 || W[I0] = R1.L;
	   R7 = R5 + R4(S);
	   R6.H = 4;
	   R2 = R7 >>> 1(S);
	   R6.L = R6.H - R0.H(S);
	   R3 = R2.L * R0.L;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+96]; // D_past_qua_en
	I3 = R0
	P3 = [SP++];
	R0 = [SP++];
	   R3 = ASHIFT R3 BY R6.L(S);
	   W[I1] = R3.H;
	   CALL _Gain_update;
Dec_gainEND:
      UNLINK;
	  RTS;


   	  	    
