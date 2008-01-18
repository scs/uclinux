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
$RCSfile: PostFilt.asm,v $
$Revision: 1.4 $
$Date: 2006/05/24 07:46:55 $

Project:		G.729AB for Blackfin
Title:			Postfilt
Author(s):		wuxiangzhi,
Revised by:		E. HSU

Description     :      Performs adaptive postfiltering on the synthesis speech  

Prototype       :      	_Post_Filter()						
						_pit_pst_filt()
						_preemphasis()
						_agc()						

******************************************************************************
Tab Setting:			4
Target Processor:		ADSP-21535
Target Tools Revision:	2.2.2.0
******************************************************************************

Modification History:
====================
$Log: PostFilt.asm,v $
Revision 1.4  2006/05/24 07:46:55  adamliyi
Fixed the failing case for g729ab decoder for tstseq6. The issue is the uClinux GAS bug: it cannot treat the (m) option correctly.

Revision 1.4  2004/01/27 23:41:46Z  ehsu
Revision 1.3  2004/01/23 00:40:54Z  ehsu
Revision 1.2  2004/01/13 01:34:51Z  ehsu
Revision 1.1  2003/12/01 00:13:18Z  ehsu
Initial revision

Version         Date            Authors        		  Comments
0.0         11/20/2002          wuxiangzhi            Original

*******************************************************************************/ 

//   Aq_t_0[12];         // Ap3 use the buffer in Decoder
//   Aq_t_1[12];         // Ap4 use the buffer in Decoder
//   xn[30];         // res2_pst use the buffer in Decoder
//   xn_1[10];
//   xn2[40];        // syn_pst use the buffer in Decoder 
// 	 wxzcode[40];          /* Fixed codebook excitation          */
//   wxzr[11];       // h use the buffer in Decoder
//.extern Az_dec;  	          
//.extern Az_dec_1;     
//.extern Aq_t_0;   //SP           
//.extern Aq_t_1;   //SP + 24                
//.extern wxzr;     //SP + 48
//.extern xn;         //SP + 100        
//.extern xn2;        //SP + 180
//.extern wxzcode;  
.extern D_mem_pre;          
.extern D_mem_syn_pst;      
.extern D_past_gain;        
.extern D_res2;             
.extern D_res2_buf;         
.extern D_res2_buf_1;       
.extern D_scal_res2;        
.extern D_scal_res2_buf;    
.extern D_scal_res2_buf_1;  
.extern _Inv_sqrt;          
//.extern _Syn_filtD;         
.extern _Weight_Az;         
.extern rri0i0;             
.extern synth;              
.extern synth_1;            
.extern synth_2;            
.extern synth_buf;          
                                  

.text;
.align 8;

_PSyn_filtD:
	  	R2 = R5-|-R5|| R5 = [P3++] ;	 
	  	R3.L = 1; 
	  	R3.H = R3.L << 14 || I3 -= 4 || R4 = [I0++];	  	
	  	M1 = -20;
	  	ASTAT = R2;   
	  	A1 = R5.H * R4.L , A0 = R5.L * R4.L || R6 = [I3] || I3 -= 2;
	  	A0 -= R6.H * R4.H(W32) || R4 = [I0++];
	  	LOOP PSyn_filt2 LC0 = P0>>1;
	  	LOOP_BEGIN PSyn_filt2;	        		  	
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
          	R6.L = (A0 += R3.L*R3.H) (T)  ;		  	  		  
			NOP;
          	A1 -= R6.L * R4.H(W32);
         	A1 = A1 << 3 || W[I2++] = R6.L;
          	R6.H = (A1 += R3.L*R3.H) (T) || R5 = [P3++];          	
		  	[P4++] = R6 || A1 = R5.H * R4.L , A0 = R5.L * R4.L;
		  	W[I2++] = R6.H  || A0 -= R6.H * R4.H(W32) || R4 = [I0++];
	  LOOP_END PSyn_filt2;
	   RTS;	   	

_Post_Filter:
	  .global _Post_Filter;
      .type  _Post_Filter,STT_FUNC;
	  LINK 288;	 
	  // [FP-8]  t0_min, t0_max FIRST LOOP
	  // [FP-12] t0_min, t0_max SECOND LOOP
	  // [FP-16] VAD
	  R7 = R0-|-R0 || [FP-20]=R1;//Az_dec
	  R5.H = 3;
	  R5.L = 3;
	  R4 = R0 +|+ R5, R6 = R0 -|- R5(S) || [FP-4] = R7;  
	  R7.L = 137;
	  R7.H = 143;
	  R1 = PACK(R4.L,R6.L)||[FP-24]=R2;	  
	  R2 = PACK(R4.H,R6.H)||[FP-28]=R3;
	  R1 = MIN (R7,R1);
	  R2 = MIN (R7,R2) || [FP-8] = R1;
	  [FP-12] = R2;
Post_FilterLoopBegin:
      	R0 = [FP-4];      
      	R1 = [FP-20];      
	  	R2 = ROT R0 BY -1 || R3 = [FP-20];
	  	R1 += 24;
	  	IF CC R3 = R1;
	  	B3 = R3;	  
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+8]; // synth_1
	R7 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+4]; // synth
	R6 = R0
	P3 = [SP++];
	R0 = [SP++];
      	B0 = SP;	  
		IF CC R6=R7;
		B2 = R6;  
		I0 = R3;
		I1 = SP;
	  	R7.H = 18022;
	  	P0 = 10;
	  	CALL _Weight_Az;
		I0 = B3;
		M0 = 24;
		I1 = SP;
		I1 += M0;
	  	R7.H = 22938;
	  	P0 = 10;
	  	CALL _Weight_Az;
		P2 = B2;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+48]; // D_res2
	I3 = R0
	P3 = [SP++];
	R0 = [SP++];
	  	P3 = 24;
	  	P0 = 40;	  	
	  	M1 = -20;
	  	I1 = B0;
	  	R4.H=1;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+64]; // D_scal_res2
	I2 = R0
	P3 = [SP++];
	R0 = [SP++];
	  	M0 = 100;
	  	I0 = SP;	  	
	   	R4.L = R4.H << 14 || R6 = [I1++] || R7 = [P2--];
	   	A1  = R6.L * R7.H ;
	   	P5 = 180;
	   	P5 = SP + P5;
	   	A1 += R6.H * R7.L , A0  = R6.L * R7.L || R7 = [P2--] || R6.L = W[I1];
	   	A1 += R6.L * R7.H , A0 += R6.H * R7.H || R6 = [I1++];
	   	A1 += R6.H * R7.L , A0 += R6.L * R7.L || R7 = [P2--] || R6.L = W[I1];
	   	A1 += R6.L * R7.H , A0 += R6.H * R7.H || R6 = [I1++] || I0 += M0;
	   	B0 = I0;
	   	B1 = P5;
	   LOOP Residup LC0 = P0>>1;
	   LOOP_BEGIN Residup;	      		 		  		  		  		  		  
		  A1 += R6.H * R7.L , A0 += R6.L * R7.L || R7 = [P2--] || R6.L = W[I1];
		  A1 += R6.L * R7.H , A0 += R6.H * R7.H || R6 = [I1++];
		  A1 += R6.H * R7.L , A0 += R6.L * R7.L || R7 = [P2--] || R6.L = W[I1];
		  A1 += R6.L * R7.H , A0 += R6.H * R7.H || R6 = [I1++];
		  A1 += R6.H * R7.L , A0 += R6.L * R7.L || R7 = [P2++P3] || R6.L = W[I1];
		  A1 += R6.L * R7.H , A0 += R6.H * R7.H || R5 = [P2--] || R6 = [I1++M1];		  
		  A0 += R6.L * R7.L || R3 = [P2--] || R6 = [I1++] ;
		  A1 = A1 << 3 || R7 = [P2--];
	   	  A0 = A0 << 3 ; 
		  R0.H = (A1+=R4.H*R4.L),R0.L = (A0+=R4.H*R4.L) (T);
		  A1 = R6.L * R5.H , A0  = R6.L * R5.L || R6.L = W[I1] || W[I3++] = R0.L;
		  R1 = R0 >>> 2(V,S) || R2 = [I1++] || W[I3++] = R0.H;		  
		  A1 += R6.H * R5.L  || [I0++] = R0;
		  A1 += R2.H * R3.L , A0 += R2.L * R3.L || R2.L = W[I1] || W[I2++] = R1.L;		  
		  A1 += R6.L * R3.H , A0 += R6.H * R3.H || W[I2++] = R1.H || R6 = [I1++];		  
		  A1 += R2.L * R7.H , A0 += R2.H * R7.H || [P5++] = R1;
	   LOOP_END Residup;	   	  
	  	R6 = [FP-4];
	  	R7 = [FP-12] || R0 = ROT R6 BY -1;
	  	R1 = [FP-8];	 
	  	IF !CC R7=R1;		
      	R0 = [FP-16];    
	  	R3 = ROT R0 BY -2 ;
	  	IF !CC JUMP Post_FilterLoop5_3;
		I0 = B0;
		I2 = B1;
      	CALL _pit_pst_filt;
Post_FilterLoop5_3:
	  R7 = SP;
	  R7 += 24;
	  B0=R7;
	  R7 += 24;
	  	B1 = R7;
		I0 = SP;
		P0 = 5;
	  	R7 = R7-|-R7 || R6 = [I0++];
	  	I1 = B1;
	  LSETUP(Post_FilterLoop6,Post_FilterLoop6) LC0 = P0;
      Post_FilterLoop6: MNOP || [I1++] = R6 ||  R6 = [I0++];
	  W[I1++] = R6.L;
	  B2 = B1;	  
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+436]; // rri0i0
	I3 = R0
	P3 = [SP++];
	R0 = [SP++];
	  W[I1++] = R7.L;
	  LSETUP(Post_FilterLoop70,Post_FilterLoop71) LC0 = P0;
	  Post_FilterLoop70: [I3++] = R7;
      Post_FilterLoop71: [I1++] = R7;                  
      	P4 = I3;
	  	P3 = B1;                // I2 POINTS TO x	 	 	     
	  	I0 = B0;	              //I0 points to a[0] 
	  	I2 = B2;            
	  	P0 = 22;
	  	CALL _PSyn_filtD;
/*	  	
	  	R2 = R5-|-R5|| R5 = [P3++] ;	 
	  	R3.L = 1; 
	  	R3.H = R3.L << 14 || I3 -= 4 || R4 = [I0++];	  	
	  	M1 = -20;
	  	ASTAT = R2;   
	  	A1 = R5.H * R4.L , A0 = R5.L * R4.L || R6 = [I3] || I3 -= 2;
	  	A0 -= R6.H * R4.H(W32) || R4 = [I0++];
	  	LOOP PSyn_filt2 LC0 = P0>>1;
	  	LOOP_BEGIN PSyn_filt2;	        		  	
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
          	R6.L = (A0 += R3.L*R3.H) (T)  ;		  	  		  
			NOP;
          	A1 -= R6.L * R4.H(W32);
         	A1 = A1 << 3 || W[I2++] = R6.L;
          	R6.H = (A1 += R3.L*R3.H) (T) || R5 = [P3++];          	
		  	[P4++] = R6 || A1 = R5.H * R4.L , A0 = R5.L * R4.L;
		  	W[I2++] = R6.H  || A0 -= R6.H * R4.H(W32) || R4 = [I0++];
	  LOOP_END PSyn_filt2;	  	
*/	  
		I0 = B1;
	  	P0 = 20;	  	  
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+36]; // D_mem_syn_pst
	B3 = R0
	P3 = [SP++];
	R0 = [SP++];
	  	I2 = B3;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+436]; // rri0i0
	I3 = R0
	P3 = [SP++];
	R0 = [SP++];
		B2 = I3;
		P5 = 100;
		P5 = SP + P5;		
		P1 = 24;
	  	P1 = SP + P1;
	  	P3 = 176;
	  	P3 = P3 + SP;	  	
	  	I1 = P3;  	  	
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+116]; // D_mem_pre
	P2 = R0
	P3 = [SP++];
	R0 = [SP++];
	  LSETUP(Post_FilterLoop80,Post_FilterLoop81) LC0 = P0 >> 1;
	  	A1 = A0 = 0 || R7 = [I0++] || R4 = [I2++];
Post_FilterLoop80: A1 += R7.L * R7.L,A0 += R7.L * R7.H || R7.L = W[I0];
Post_FilterLoop81: A1 += R7.H * R7.H,R0  = (A0 += R7.L * R7.H) || R7 = [I0++];
      
      	A1 += R7.L * R7.L || [I3++] = R4 || R4 = [I2++];
      	R1 = (A1 += R7.H * R7.H) || [I3++] = R4 || R4 = [I2++];
      	R0 = R0 >>> 16 || [I3++] = R4 || R4 = [I2++];
 		R1 = R1 >>> 16 || [I3++] = R4 || R4 = [I2++];	  
 		R2 = R2 -|- R2 || [I3++] = R4 ;
	  	CC = R0 <= 0;
	  	IF CC JUMP Post_FilterLoop10;
	  	R0.H = 26214;
	  	R2.H = R0.L * R0.H (T);
	  	P0 = 15;
      	DIVS(R2,R1);    // get sign bit
      LSETUP(_LP_ST0,_LP_ST0)LC1=P0;
_LP_ST0: DIVQ(R2,R1);	  
Post_FilterLoop10: 
			  	
	  	R4 = [I1--];	  		  	
	  	R6.H = R2.L * R4.L (T) || R2.H = W[P2];	  	
	  	W[P2] = R4.H;		
	  	P2 = I3;
	  	R5.H = R4.H - R6.H(S) || R7 = [I1--] || I3 -= 4; 
	  	R1 = [FP-28];
	  	R0=[FP-24];
	  	P0 = 38;
	  	LOOP preemphasis1 LC0 = P0>>1;
	  	LOOP_BEGIN preemphasis1;	  		
	  	  	R6.H = R2.L * R7.L, R6.L = R2.L * R7.H (T);
	      	R5.L = R4.L - R6.L (S); 	  	  		      	
		  	R4 = ROT R7 BY 0 || R7=[I1--];
	      	R5.H = R4.H - R6.H(S) || [P3--] = R5;		
	  	LOOP_END preemphasis1;
      	R6.H = R2.H * R2.L (T) || R4.H = W[P3];
	  	R5.L = R4.H - R6.H(S) || R6 = [FP-4];	  	  		  		  	
      	R6 = ROT R6 BY -1 || [P3] = R5;	
		IF CC R0=R1;			     	  	
	  	I0 = R0;	  		
		B1 = R0;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+8]; // synth_1
	R6 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+4]; // synth
	R7 = R0
	P3 = [SP++];
	R0 = [SP++];
		IF CC R7 = R6;		
		B0 = R7;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+44]; // D_res2_buf_1
	P4 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+40]; // D_res2_buf
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+60]; // D_scal_res2_buf_1
	I2 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P2;
	P2 = M2;
	R0 = [P2+56]; // D_scal_res2_buf
	P3 = R0
	P2 = [SP++];
	R0 = [SP++];
	  	P0 = 40;	  	
	  	R2 = R5-|-R5|| R5 = [P5++] ;	 
	  	R3.L = 1; 
	  	R3.H = R3.L << 14 || R4 = [P1++];	  	
	  	M1 = -20;
	  	ASTAT = R2;   
	  	A1 = R5.H * R4.L , A0 = R5.L * R4.L || R6 = [I3] || I3 -= 2;
	  	A0 -= R6.H * R4.H(W32) || R4 = [P1++];
	  	LOOP XPSyn_filt2 LC0 = P0>>1;
	  	P0 = -20;
	  	LOOP_BEGIN XPSyn_filt2;	        		  	
		  	A1 -= R6.H * R4.L, A0 -= R6.L * R4.L(W32) || R6.H = W[I3--];
		 	A1 -= R6.L * R4.H, A0 -= R6.H * R4.H(W32) || R4 = [P1++] || R6.L = W[I3--];
			A1 -= R6.H * R4.L, A0 -= R6.L * R4.L(W32) || R6.H = W[I3--];
			A1 -= R6.L * R4.H, A0 -= R6.H * R4.H(W32) || R4 = [P1++] || R6.L = W[I3--];
			A1 -= R6.H * R4.L, A0 -= R6.L * R4.L(W32) || R6.H = W[I3--];
			A1 -= R6.L * R4.H, A0 -= R6.H * R4.H(W32) || R4 = [P1++] || R6.L = W[I3--];
			A1 -= R6.H * R4.L, A0 -= R6.L * R4.L(W32) || R6.H = W[I3--];
			A1 -= R6.L * R4.H, A0 -= R6.H * R4.H(W32) || R4 = [P1++P0] || R6.L = W[I3--];
          	A1 -= R6.H * R4.L, A0 -= R6.L * R4.L(W32) || R2 = [P1++] || R1 = [I2++];
          	A0 = A0 << 3  || [P3++] = R1;
          	R6.L = (A0 += R3.L*R3.H) (T) || R1 = [P4++]  ;		  	  		  
			[I1++] = R1;
          	A1 -= R6.L * R2.H(W32)|| R4 = [P1++];
         	A1 = A1 << 3 || W[I0++] = R6.L || I3 -= M1;
          	R6.H = (A1 += R3.L*R3.H) (T) || R5 = [P5++];          	
		  	[P2++] = R6 || A1 = R5.H * R2.L , A0 = R5.L * R2.L;
		  	W[I0++] = R6.H  || A0 -= R6.H * R2.H(W32);// || R4 = [P1++];
	  	LOOP_END XPSyn_filt2;	  		  		  				  		 	  
	  	P3 = B1;
	  	P3 += 60;	  	
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+56]; // D_scal_res2_buf
	[--SP] = R7;
	R7 = 80;
	R0 = R0 + R7;
	R7 = [SP++];
	I3 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+436]; // rri0i0
	//B2 = R0
	P3 = [SP++];
	R0 = [SP++];
      	CALL _agc;      	
	  	R0 = [FP-4]; W[I1] = R7.L;	  	
		R7 = ROT R0 BY -1 || W[I3] = R6.L;
	  	BITSET(R0,0);
	  	[FP-4] = R0;

// --- mods by David Rowe
// was 	IF !CC JUMP Post_FilterLoopBegin, however after passing thru
// perl script jump was out of range	
	
	  	IF CC JUMP jump_around ; 
		JUMP Post_FilterLoopBegin;
jump_around:

	
// -- end mods
			
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+12]; // synth_2
	I2 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+0]; // synth_buf
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
	  P0 = 5;
	  R7 = [I2++] || R6=[FP-24];
	  I0 = R6;
	  LSETUP(Post_Filter1,Post_Filter1) LC0 = P0;
	  Post_Filter1: MNOP || [I1++] = R7 || R7 = [I2++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+4]; // synth
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
	  P0 = 40;
	  R7 = [I0++];
	  LSETUP(Post_Filter2,Post_Filter2) LC0 = P0;
	  Post_Filter2: MNOP || [I1++] = R7 || R7 = [I0++];	  
	  UNLINK;
	  RTS;

_pit_pst_filt:
	  .global _pit_pst_filt;
      .type  _pit_pst_filt,STT_FUNC;
	  LINK 84;
	  R6 = R7.L;
	  R7 = R7 >> 16;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+64]; // D_scal_res2
	B0 = R0
	P3 = [SP++];
	R0 = [SP++];
	  R5.H = 0X8000;  //cor_max = MIN_32;
	  R5.L = 0;
	  P3 = R6;
	  P5 = R7;
	  P4 = B0;        // 1 stall RAW
	  P0 = 40;
	  P2 = P3;
	  P5 -= P3;
	  P4 -= P3;
	  P4 -= P3;
	  P5 += 1;
	  I3 = P4;        // Dcache collision in inner loop	  	  
	  M1 = 88;
	  M0 = -84;
	  I3 -= 2;
	  I1 = I3;
	  R7.L = W[I1++];
	   LOOP pit_pst_filt1 LC0 = P5>>1;
	  LOOP_BEGIN pit_pst_filt1;	      	   		
		  
		  A1 = A0 = 0 || R6 = [I2++] || R7.H = W[I1++];
		  LSETUP(pit_pst_filt1_1,pit_pst_filt1_2) LC1 = P0>>1;
		  pit_pst_filt1_1: A1 += R6.L * R7.L, A0 += R6.L * R7.H || R7.L = W[I1++];
		  pit_pst_filt1_2: R1=(A1 += R6.H * R7.H), R0 = (A0 += R6.H * R7.L) || R6 = [I2++] || R7.H = W[I1++];
		  CC = R5 < R0;
		  IF CC P3 = P2;
		  R5 = MAX(R5,R0) || I1-=M1 || R6=[I2++M0];
		  P2 += 1;		  
		  CC = R5 < R1;
		  IF CC P3 = P2;
		  R5 = MAX(R5,R1) || I3 -= 4 || R7.L = W[I1++];
		  P2 += 1;		  
	  LOOP_END pit_pst_filt1;
	  R0=P5;
	  CC=BITTST(R0,0);
	  IF !CC JUMP pit_pst_filt1_7;
//	  	  I1 += 2;
		  A0 = 0 || R6 = [I2++] || R7.L = W[I1++];
		  LSETUP(pit_pst_filt1_5,pit_pst_filt1_6) LC1 = P0>>1;
		  pit_pst_filt1_5: A0 += R6.L * R7.L        || R7.L = W[I1++];
		  pit_pst_filt1_6: R0 = (A0 += R6.H * R7.L) || R6 = [I2++] || R7.L = W[I1++];
		  CC = R5 < R0;
		  IF CC P3 = P2;
		  R5 = MAX(R5,R0);
pit_pst_filt1_7:	  
      R0 = 1;
      [FP-4] = P3;    // t0
	  P5 = B0;
	  P5 -= P3;
	  I3 = B0;
	  P5 -= P3;
	  A0 = R0 || R7 = W[P5++](Z);
	  LSETUP(pit_pst_filt2,pit_pst_filt2) LC0 = P0;
      pit_pst_filt2: R6 = (A0 += R7.L * R7.L) || R7 = W[P5++](Z);
	  P1 = 19;
	  A0 = R0 || R7.L = W[I3++];
	  A1 = R7.L * R7.L || R7 = [I3++];
	  LSETUP(pit_pst_filt3,pit_pst_filt3) LC0 = P1;
      pit_pst_filt3: A0 += R7.H * R7.H , A1 += R7.L * R7.L || R7 = [I3++];
	  A1 += R7.L * R7.L;
	  R0 = 0;
	  R4 = (A0 += A1);    //ener0
	  R5 = MAX(R5,R0);
	  R0 = MAX(R5,R6);
	  R0 = MAX(R0,R4);
	  R7.L = SIGNBITS R0;
	  R5 = ASHIFT R5 BY R7.L;  //cmax = round(L_shl(cor_max, j));
	  R6 = ASHIFT R6 BY R7.L;  //en = round(L_shl(ener, j));
	  R4 = ASHIFT R4 BY R7.L;  //en0 = round(L_shl(ener0, j));
	  R5.L = R5(RND);  // cmax
	  R6.L = R6(RND);  // en
	  R6.H = R4(RND);  // en0
	  R2 = R5.L * R5.L; //temp = L_mult(cmax, cmax);
	  R3 = R6.H * R6.L(IS);
	  CC = R2 < R3;	  
	  IF !CC JUMP pit_pst_filt5;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+48]; // D_res2
	I2 = R0
	P3 = [SP++];
	R0 = [SP++];
		 I1 = I0;
		 R7.L = W[I2++];
		 LSETUP(pit_pst_filt4,pit_pst_filt4) LC0 = P0;
         pit_pst_filt4: MNOP || W[I1++] = R7.L || R7.L = W[I2++];
		 JUMP pit_pst_filtEND;
pit_pst_filt5:
       R0.H = 0;
       R0.L = R5.L - R6.L(S); //if (sub(cmax, en) > 0) 	   
	   R0 = R0.L(x);                       
       CC = R0 <= 0;	                          
	      R7.H = 21845;
		  R7.L = 10923;
		  IF !CC JUMP pit_pst_filt7;
pit_pst_filt6:
          R7.L = 8192;
		  R0.L = R5.L * R7.L (T);
		  R1.L = R6.L >>> 1(S);
		  R1.L = R0.L + R1.L(S);
		  R7.H = 32767;
		  R7.L = 0;
//	      R0 = R0.L(X);
	      R1 = R1.L(X);
		  CC = R1 <= 0;
		  IF CC JUMP pit_pst_filt7;
			 P0 = 15;
      R2 = R0 << 16;
      DIVS(R2,R1);    // get sign bit
      LSETUP(_LP_ST1,_LP_ST1)LC1=P0;
_LP_ST1: DIVQ(R2,R1);	  
//	  R2 = R2.L(X);
			 R7.H = R7.H - R2.L(S);
			 R7 = PACK(R7.H, R2.L);
pit_pst_filt7:          
/*************************************************          
          for (i = 0; i < L_subfr; i++) { // signal_pst[i] = g0*signal[i] + gain*signal[i-t0]; 
             signal_pst[i] = add(mult(g0, signal[i]), mult(gain, signal[i-t0])); }
**************************************************/  
          P4 = [FP-4];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+48]; // D_res2
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
		  I1 = P5;
		  P5 -= P4;
		  P0 = 40;
		  P5 -= P4;
		  I2 = P5;
		  MNOP || R6.L = W[I1++] || R5.L = W[I2++];
		  R6.H = W[I1++];
		      R5.H = W[I2++];
		  LOOP pit_pst_filt8 LC0 = P0>>1;
		  LOOP_BEGIN pit_pst_filt8;		      
			  R0.L = R7.H * R6.L, R0.H = R7.H * R6.H (T) || R6.L = W[I1++];
			  R1.L = R7.L * R5.L, R1.H = R7.L * R5.H (T) || R5.L = W[I2++];
			  R2 = R0 +|+ R1 (S) || R6.H = W[I1++];
		      R5.H = W[I2++] || [I0++] = R2;
		  LOOP_END pit_pst_filt8;
pit_pst_filtEND:
	  UNLINK;
	  RTS;

_agc:
	  	.global _agc;
      	.type  _agc,STT_FUNC;
	  	LINK 4;		
	  	I0 = B1;
	  	P2 = B2;	  	  	  
	  	P0 = 10;	        
	  	A1 = A0 = 0 || R7 = [I0++];
	  	R6 = R7 >>> 2(V,S) || R5 = [I0++] || R1 = [P3++];	  	  
	  	LSETUP(agc1,agc2) LC0 = P0 >> 1;
agc1: 		R4 = R5 >>> 2(V,S) || R2 = [I2++];
	  		A0 += R6.L * R6.L, A1 += R6.H * R6.H || [P2++] = R6 || R7 = [I0++];
	  		A0 += R4.L * R4.L, A1 += R4.H * R4.H || [P2++] = R4 || R5 = [I0++];
	  		R6 = R7 >>> 2(V,S) || [I3++] = R2;  
	  		R4 = R5 >>> 2(V,S) || R2 = [P4++];
	  		A0 += R6.L * R6.L, A1 += R6.H * R6.H || [P2++] = R6 || R7 = [I0++];
	  		A0 += R4.L * R4.L, A1 += R4.H * R4.H || [P2++] = R4 || R5 = [I0++];
agc2:		R6 = R7 >>> 2(V,S) || [I1++] = R2;  
	  	I0 = B3;
	  	R0 = (A0 += A1) || [I0++] = R1 || R1 = [P3++];
	  	A1 = A0 = 0 || [I0++] = R1 || R1 = [P3++]; 
	  	R6.L = SIGNBITS R0 || [I0++] = R1 || R1 = [P3++];
	  	R5.H = 1;
	  	R6.L = R6.L - R5.H(S) || [I0++] = R1 || R1 = [P3++];	  
	  	R1 = ASHIFT R0 BY R6.L || [I0++] = R1 ; 	  
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+152]; // D_past_gain
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
	  	P1 = 46;
	  	CC = R0 == 0;
	   	IF CC JUMP agcEND;
//agc3:            
	  	I0 = B0;
	  	P2 = B2;
	  	R0.L = R1(RND)  || R7 = [I0++];                   
	  	R3 = R7 >>> 2(V,S) || R5 = [I0++];
	  	LSETUP(agc4,agc5) LC0 = P0 >> 1;
agc4: 		R4 = R5 >>> 2(V,S) || R2 = [I2++]; 
	  		A0 += R3.L * R3.L, A1 += R3.H * R3.H || R7 = [I0++] || [P2++] = R3; 
	  		A0 += R4.L * R4.L, A1 += R4.H * R4.H || R5 = [I0++] || [P2++] = R4; 
      		R3 = R7 >>> 2(V,S) || [I3++] = R2;       
      		R4 = R5 >>> 2(V,S) || R2 = [P4++]; 
	  		A0 += R3.L * R3.L, A1 += R3.H * R3.H || R7 = [I0++] || [P2++] = R3; 
	  		A0 += R4.L * R4.L, A1 += R4.H * R4.H || R5 = [I0++] || [P2++] = R4; 
agc5: 		R3 = R7 >>> 2(V,S) || [I1++] = R2;       
	  	R3 = (A0 += A1);
	  	CC = R3 == 0;
	  	IF CC JUMP agc7;
	  
	  	R5.L = SIGNBITS R3;
	  	R7 = ASHIFT R3 BY R5.L(S);
	  	R6.L = R6.L - R5.L(S);
	  	R1.L = R7(RND);
	  	R1 = R1.L;	  	  
      	P1 = 15;
      	R2 = R0 << 16;
      	DIVS(R2,R1);    // get sign bit
      	LSETUP(_LP_ST2,_LP_ST2)LC1=P1;
_LP_ST2: 	DIVQ(R2,R1);	  
	  	R2 = R2.L(X);	
	  	R6 = - R6(V);
	  	R2 = R2 << 7(S);
	  	R0 = ASHIFT R2 BY R6.L(S);
	  	CALL _Inv_sqrt;
	  	R1 = R1 << 9(S);
	  	R1.L = R1(RND);
	  	R0 = 0x0ccc;	  
	  	R3 = R0.L * R1.L;
agc7:
		R3.L = R7.L - R7.L (S);
	 	R6.H = 29491;     //AGC_FAC
	 	P0 = 40;
	 	P2 = B1;
	 	A1 = R3 || R7.H = W[P5];
	 	LOOP agc8 LC0 = P0>>1;
	 	LOOP_BEGIN agc8;
	     	R5 = (A1+= R6.H * R7.H) || R4 = [P2] || R2 = [I2++];
	     	A1 = R3 || [I3++] = R2;
		 	A0 = R4.L * R5.H || R2 = [P4++];		 
		 	R7 = (A1+=R6.H * R5.H) || [I1++] = R2;
		 	A0 = A0 << 3 || R2 = [I2++];
		 	A1 = R4.H * R7.H || [I3++] = R2;
		 	A1 = A1 << 3 || R2 = [P4++];
		 	R4.H = A1, R4.L = A0 (T) || [I1++] = R2;
		 	[P2++] = R4 || A1=R3;
	 	LOOP_END agc8;
	 	R0.L = R7.H >> 0;
		P1 = 1;	  
agcEND:			
	  	R7 = [P4++];
      	LOOP Post_FilterLoop13 LC0 = P1;
	  	LOOP_BEGIN Post_FilterLoop13;
	       	MNOP || [I1++] = R7 || R6 = [I2++];
		   	MNOP || [I3++] = R6 || R7 = [P4++];
	  	LOOP_END Post_FilterLoop13;      	
	  	W[P5] = R0.L || R6 = [I2++];				
      	UNLINK;
	  	RTS;
