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
$RCSfile: ACELP_Code_A.asm,v $
$Revision: 1.4 $
$Date: 2006/05/24 07:46:54 $

Project:		G.729AB for Blackfin
Title:			ACELP_CODE_A
Author(s):		wuxiangzhi,
Revised by:		E. HSU

Description     :      Find Algebraic codebook for G.729A

Prototype       :      	_ACELP_Code_A()						
						_Cor_h()

******************************************************************************
Tab Setting:			4
Target Processor:		ADSP-21535
Target Tools Revision:	2.2.2.0
******************************************************************************

Modification History:
====================
$Log: ACELP_Code_A.asm,v $
Revision 1.4  2006/05/24 07:46:54  adamliyi
Fixed the failing case for g729ab decoder for tstseq6. The issue is the uClinux GAS bug: it cannot treat the (m) option correctly.

Revision 1.4  2004/01/27 23:40:16Z  ehsu
Revision 1.3  2004/01/23 00:39:29Z  ehsu
Revision 1.2  2004/01/13 01:33:34Z  ehsu
Revision 1.1  2003/12/01 00:12:04Z  ehsu
Initial revision

Version         Date            Authors        		  Comments
0.0          11/01/2002         wuxiangzhi            Original

*******************************************************************************/ 

#include "G729_const.h" 
	    
	 .extern _Cor_h_X;
	 .extern _D4i40_17_fast;
	 .extern rri0i0;
	 .extern rri0i1;
	 .extern rri0i2;
	 .extern rri0i3;
	 .extern rri0i4;
	 .extern rri1i1;
	 .extern rri1i2;
	 .extern rri1i3;
	 .extern rri1i4;
	 .extern rri2i2;
	 .extern rri2i3;
	 .extern rri2i4;
	 .extern rri3i3;
	 .extern rri4i4;
	 .extern sharp;
	 

.text;
.align 8;
_ACELP_Code_A:
	  .global _ACELP_Code_A;
      .type  _ACELP_Code_A,STT_FUNC;
      LINK 108;  
      [FP-28]=R5;    
      [FP-24]=P2;
      [FP-20]=SP;
	  [FP-16]=P4;
      [FP-12]=P5;
	  P1 = R0;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+sharp@GOT17M4];
	I3 = R0
	P3 = [SP++];
	R0 = [SP++];
	  B0 = P4;
	  R7.L = W[I3];
	  P0 = 40;
	  R7.L = R7.L << 1(S) || [FP-4] = R0;
	  CC = P1 < P0;
	  IF !CC JUMP ACELP_Code_A2;
	      P2 = B0;
		  I0 = B0;
		  P2 = P2 + (P1 << 1);
		  MNOP || R7.H = W[I0++] || [FP-8] = R7;
	      P0 -= P1;
		  I1 = P2;
		  R6 = R7.H * R7.L || R5 = W[P2++](Z);
		  R4.L = R6.H + R5.L(S) || R7.H = W[I0++];
		  LOOP ACELP_Code_A1 LC0 = P0;
		  LOOP_BEGIN ACELP_Code_A1;
		      R6 = R7.H * R7.L || R5 = W[P2++](Z) || W[I1++] = R4.L;
              R4.L = R6.H + R5.L(S) || R7.H = W[I0++];
		  LOOP_END ACELP_Code_A1;
ACELP_Code_A2:
      	CALL _Cor_h;
      	R0 = [FP-28];
      	I1 = R0;
      	R0 = [FP-20];
      	I3 = R0;
	  	I0 = B0;
	  	CALL _Cor_h_X;	  	  	 
		P5 = [FP-12];
		P4 = [FP-16];
		P3 = [FP-20];
		P2 = [FP-24];		
	  	CALL _D4i40_17_fast;
//    if(T0 < L_SUBFR)
//    for (i = T0; i < L_SUBFR; i++) code[i] = add(code[i], mult(code[i-T0], sharp));      
	  	P1 = [FP-4];    // T0
	  	P0 = 40;        // L_SUBFR
	  	P5 = [FP-12];
	  	R7 = [FP-8];
	  	CC = P0 <= P1;  // if(T0 < L_SUBFR) previously condition failed when both are equal so added equal sign
	  	IF CC JUMP ACELP_Code_AEND;	  
	  	P0 -= P1;	  
	  	P1 = P5 + (P1 << 1);
	  	I0 = P5;
	  	I1 = P1;
	  	I2 = P1;
	  	R7.H = W[I0++];
	  	R6 = R7.H * R7.L || R5.L = W[I1++];
	  	R4.L = R6.H + R5.L(S) || R7.H = W[I0++];
	  	LOOP ACELP_Code_A3 LC0 = P0;
	  	LOOP_BEGIN ACELP_Code_A3;
	      	R6 = R7.H * R7.L || R5.L = W[I1++] || W[I2++] = R4.L;
          	R4.L = R6.H + R5.L(S) || R7.H = W[I0++];
	  	LOOP_END ACELP_Code_A3;
ACELP_Code_AEND:
//_ACELP_Code_A.END:
	  UNLINK;
	  RTS;
.text;
.align 8;

_Cor_h:
	  .global _Cor_h;
      .type  _Cor_h,STT_FUNC;
      link 92;      
	  I0 = B0;
	  P0 = L_SUBFR;           //40;	 
	  A1 = A0 = 0 || R7 = [I0++];
	  R1 = CORH_CONST1;       //32000;	  
	  //for(i=0; i<L_SUBFR; i++) cor = L_mac(cor, H[i], H[i]);
	  	LSETUP(Cor_h1,Cor_h1) LC0 = P0 >> 1;  
Cor_h1: 	A0 += R7.L * R7.L, A1 += R7.H * R7.H  || R7 = [I0++];
	  	I0 = B0;
      	R0 = (A0 += A1) || R7 = [I0++];
	  	B1 = SP;
	  	R2 = R0 >> 16;
	  	I1 = B1;
	  	R5.L = SIGNBITS R0 ; //k = norm_l(cor);
		R5.L = R5.L >>> 1(S);              //k = shr(k, 1);
		R4 = -1;		 
		CC = R2 < R1;
		IF !CC R5=R4;
		R6 = ASHIFT R7 BY R5.L(V,S)  || R7 = [I0++];
		LSETUP(Cor_h3_1,Cor_h3_1) LC0 = P0 >> 1;
Cor_h3_1: 	R6 = ASHIFT R7 BY R5.L(V,S)  || R7 = [I0++] || [I1++] = R6;		 
		I0 = B1;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+rri1i1@GOT17M4];
	P1 = R0
	P3 = [SP++];
	R0 = [SP++];
		P5 = 8;
		P1 += 12;	
//       ptr_h1 = h;
//       cor    = 0;
//       for(i=0;  i<NB_POS; i++) {
//          cor = L_mac(cor, *ptr_h1, *ptr_h1); ptr_h1++;
//          *p4-- = extract_h(cor);
//          cor = L_mac(cor, *ptr_h1, *ptr_h1); ptr_h1++;
//          *p3-- = extract_h(cor);
//          cor = L_mac(cor, *ptr_h1, *ptr_h1); ptr_h1++;
//          *p2-- = extract_h(cor);
//          cor = L_mac(cor, *ptr_h1, *ptr_h1); ptr_h1++;
//          *p1-- = extract_h(cor);
//          cor = L_mac(cor, *ptr_h1, *ptr_h1); ptr_h1++;
//          *p0-- = extract_h(cor); }
		A1 = A0 = 0 || R1 = [I0++];
		LOOP Cor_h5 LC0 = P5>>1;		
		LOOP_BEGIN Cor_h5;
		    R4 = (A0 += R1.L * R1.L) || R2 = [I0++];
		    R6 = (A0 += R1.H * R1.H) || R5 = [I0++];		
			R2 = (A0 += R2.L * R2.L),A1 = R2.H * R2.H || R3 = [I0++];
			R1 = (A0 += A1) || R7 = [I0++];
			R0 = (A0 += R5.L * R5.L) ;			
			R4.L = (A0 += R5.H * R5.H) (T);
			R6.L = (A0 += R3.L * R3.L) (T) || [P1+48] = R4 ;
			R2.L = (A0 += R3.H * R3.H) (T) || [P1+32] = R6 ;
			R1.L = (A0 += R7.L * R7.L) (T) || [P1+16] = R2 ;
			R0.L = (A0 += R7.H * R7.H) (T) || [P1--] = R1  || R1 = [I0++];
			[P1-12] = R0;
		LOOP_END Cor_h5;		
	  	P0 = 20;
//   	          for(i=k+(Word16)1; i<NB_POS; i++ ) {
//                  cor = L_mac(cor, *ptr_h1, *ptr_h2); ptr_h1++; ptr_h2++;
//                  cor = L_mac(cor, *ptr_h1, *ptr_h2); ptr_h1++; ptr_h2++;
//                  *p3 = extract_h(cor);
//                  cor = L_mac(cor, *ptr_h1, *ptr_h2); ptr_h1++; ptr_h2++;
//                  *p2 = extract_h(cor);
//                  cor = L_mac(cor, *ptr_h1, *ptr_h2); ptr_h1++; ptr_h2++;
//                  *p1 = extract_h(cor);
//                  cor = L_mac(cor, *ptr_h1, *ptr_h2); ptr_h1++; ptr_h2++;
//                  *p0 = extract_h(cor);
//                  p3 -= ldec; p2 -= ldec;  p1 -= ldec; p0 -= ldec;  }
	  	B2 = SP;  
        M1 = 10;
		P5 = 7;
		I2 = SP;
		R6 = 126;
		I2 += 2;			    
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+rri0i4@GOT17M4];
	[--SP] = R7;
	R7 = 126;
	R0 = R0 + R7;
	R7 = [SP++];
	R4 = R0
	P3 = [SP++];
	R0 = [SP++];
		[FP-4] = R4;			
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+rri2i3@GOT17M4];
	R3 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+rri1i2@GOT17M4];
	R2 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+rri0i1@GOT17M4];
	R1 = R0
	P3 = [SP++];
	R0 = [SP++];
		P4 = -18;		
		LOOP Cor_h6 LC0 = P5;     //for(k=0; k<NB_POS; k++) {
		LOOP_BEGIN Cor_h6;
			R0 = R6 + R3 (S) || P0 = [FP-4];
			I0 = B2;               //ptr_h1 = ptr_hd; I0-> G729_Scratch			
			I1 = I2;               //ptr_h2= ptr_hf          
			P3 = R0; 
			R0 = R6 + R2 (S) ;
			P2 = R0;			
			P0 += -2;
			R0 = R6 + R1 (S) || [FP-4] = P0;
			P1 = R0;	
			A0 = 0 || R4.L = W[I0++] || R7.H = W[I1++];
//			A0 = 0 ;				
			LOOP Cor_h6_1 LC1 = P5;
			LOOP_BEGIN Cor_h6_1;
			   A0 += R4.L * R7.H  || R4.L = W[I0++] || R7.H = W[I1++];
               R0 = (A0 += R4.L * R7.H ) || R4.L = W[I0++] || R7.H = W[I1++];
			   R0 = (A0 += R4.L * R7.H ) || W[P3++P4] = R0.H || R7.H = W[I1++];
			   MNOP || W[P2++P4] = R0.H || R4.L = W[I0++];
			   R0 = (A0 += R4.L * R7.H ) || R4.L = W[I0++] || R7.H = W[I1++];
			   R0 = (A0 += R4.L * R7.H ) || W[P1++P4] = R0.H || R7.H = W[I1++];
			   MNOP || W[P0++P4] = R0.H || R4.L = W[I0++];
			LOOP_END Cor_h6_1;
			P5 += -1;	
           	A0 += R4.L * R7.H  || R4.L = W[I0++] || R7.H = W[I1++];
		   	R0 = (A0 += R4.L * R7.H ) || R4.L = W[I0++] || R7.H = W[I1++];           
		   	R0 = (A0 += R4.L * R7.H ) || W[P3] = R0.H || R7.H = W[I1++];
		   	MNOP || W[P2] = R0.H || R4.L = W[I0++];
		   	R0 = (A0 += R4.L * R7.H ) || I2 += M1;
		   	W[P1] = R0.H;
		   	R6 += -16;           
		LOOP_END Cor_h6;			
            I0 = B2;               //ptr_h1 = ptr_hd; I0-> G729_Scratch			
			R0 = R6 + R3 (S) || R4 = [I0++];
			P3 = R0; 
			R0 = R6 + R2 (S) || R7 = [I2++] ;
			P2 = R0;
			R0 = R6 + R1 (S) || R6 = [I2];
			P1 = R0;															
			I2 = SP;
           	A0 = R4.L * R7.L  ||  I2 += 4 || R3 = [I0];	 
		   	R0 = (A0 += R4.H * R7.H ) ;       
		   	R0 = (A0 += R3.L * R6.L ) || W[P3] = R0.H;
		   	R0 = (A0 += R3.H * R6.H ) || W[P2] = R0.H;
		   	W[P1] = R0.H; 
			R7 = 7;     //K
			LC0=R7;
	[--SP] = R1;
	[--SP] = P3;
	P3 = M2;
	R1 = [P3+rri0i3@GOT17M4];
	[--SP] = R7;
	R7 = 126;
	R1 = R1 + R7;
	R7 = [SP++];
	R0 = R1
	P3 = [SP++];
	R1 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+rri1i4@GOT17M4];
	[--SP] = R7;
	R7 = 126;
	R0 = R0 + R7;
	R7 = [SP++];
	R1 = R0
	P3 = [SP++];
	R0 = [SP++];
			[FP-4] = R0;
	      	[FP-8] = R1;  
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+rri0i2@GOT17M4];
	[--SP] = R7;
	R7 = 142;
	R0 = R0 + R7;
	R7 = [SP++];
	R1 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+rri1i3@GOT17M4];
	[--SP] = R7;
	R7 = 142;
	R0 = R0 + R7;
	R7 = [SP++];
	R3 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+rri2i4@GOT17M4];
	[--SP] = R7;
	R7 = 142;
	R0 = R0 + R7;
	R7 = [SP++];
	R5 = R0
	P3 = [SP++];
	R0 = [SP++];
			R6 = -16;
			P5 = -18;
	    LOOP Cor_h7 LC0;	    
		LOOP_BEGIN Cor_h7;
			R5 = R5 + R6 (S) || P0=[FP-4];			
			R3 = R3 + R6 (S) || P1=[FP-8];							
			P4 = R5;
			P3 = R3;
			I0 = B2;
			I1 = I2;	
			P1 += -2;							
			P0 += -2;						
			[FP-8]=P1 || R1 = R1 + R6 (S) || R4.H = W[I0++];	
			P2 = R1;
			LC1 = R7;
			[FP-4]=P0 || A0 = 0  || R4.L = W[I1++];												
			LOOP Cor_h7_1 LC1;			
			LOOP_BEGIN Cor_h7_1;
		        R0 = (A0 += R4.H * R4.L ) || R4.H = W[I0++] || R4.L = W[I1++];
				R2 = (A0 += R4.H * R4.L ) || R4.H = W[I0++] || R4.L = W[I1++];
				R0 = (A0 += R4.H * R4.L ) || W[P4++P5] = R0.H  || R4.H = W[I0++];
			    MNOP || W[P3++P5] = R2.H || R4.L = W[I1++];
				R2 = (A0 += R4.H * R4.L ) || R4.H = W[I0++] || R4.L = W[I1++];
			    R0 = (A0 += R4.H * R4.L ) || W[P2++P5] = R0.H ||R4.H = W[I0++];
			    MNOP || W[P1++P5] = R2.H || R4.L = W[I1++];
			    W[P0++P5] = R0.H; 
			LOOP_END Cor_h7_1;								
		    R0 = (A0 += R4.H * R4.L ) || R4.H = W[I0++] || R4.L = W[I1++];
		    R0 = (A0 += R4.H * R4.L ) || W[P4] = R0.H || R4.L = W[I1++];
			W[P3] = R0.H || R4.H = W[I0++];
		    R0 = (A0 += R4.H * R4.L ) || I2 += M1;
			W[P2] = R0.H;
//			R6 += -16;
			R7 += -1;
		LOOP_END Cor_h7;
			I1 = I2;	
			I2 = SP;
			M0 = 6;
			R5 = R5 + R6 (S) || I2 += M0;					
	[--SP] = R1;
	[--SP] = P3;
	P3 = M2;
	R1 = [P3+rri0i3@GOT17M4];
	[--SP] = R7;
	R7 = 142;
	R1 = R1 + R7;
	R7 = [SP++];
	R0 = R1
	P3 = [SP++];
	R1 = [SP++];
	    	[FP-4]=R0 || R3 = R3 + R6 (S) ;							
			P4 = R5;
			P3 = R3;
			I0 = B2;											
			R1 = R1 + R6 (S) || R7 = [I0++]|| R4.L = W[I1++];	
			P2 = R1;																		
		    R0 = (A0 = R7.L * R4.L ) || R4.L = W[I1++] || R6.H = W[I0];
		    R0 = (A0 += R7.H * R4.L ) || W[P4] = R0.H || R4.L = W[I1++];			
		    W[P3] = R0.H || R0 = (A0 += R6.H * R4.L );
		    W[P2] = R0.H;
//			R5 = 124;
			R7 = 7;
			LC0 = R7;	
			
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+rri1i4@GOT17M4];
	[--SP] = R7;
	R7 = 142;
	R0 = R0 + R7;
	R7 = [SP++];
	R4 = R0
	P3 = [SP++];
	R0 = [SP++];
			[FP-8]=R4;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+rri2i4@GOT17M4];
	[--SP] = R7;
	R7 = 126;
	R0 = R0 + R7;
	R7 = [SP++];
	R6 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+rri0i2@GOT17M4];
	[--SP] = R7;
	R7 = 126;
	R0 = R0 + R7;
	R7 = [SP++];
	R3 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+rri1i3@GOT17M4];
	[--SP] = R7;
	R7 = 126;
	R0 = R0 + R7;
	R7 = [SP++];
	R1 = R0
	P3 = [SP++];
	R0 = [SP++];
	    	P5 = -18;
	    	R5 = -2;
		LOOP Cor_h8 LC0;		
		LOOP_BEGIN Cor_h8;
			R6 = R5 + R6 (S) || P3 = [FP-4];
			R1 = R5 + R1 (S) || P4 = [FP-8];
			P2 = R6;
			P1 = R1;
			I0 = B2;
			I1 = I2;
			P3 += -16;
			P4 += -16;
			R3 = R5 + R3 (S) || [FP-4] = P3 || R4.H = W[I0++];
			LC1 = R7;	
			[FP-8] = P4 || A0 = 0 || R4.L = W[I1++];
			P0 = R3;
			LOOP Cor_h8_1 LC1;			   			   
			LOOP_BEGIN Cor_h8_1;
			    R0 = (A0 += R4.H * R4.L ) || R4.H = W[I0++] || R4.L = W[I1++];
				R2 = (A0 += R4.H * R4.L ) || R4.H = W[I0++] || R4.L = W[I1++];
				R0 = (A0 += R4.H * R4.L ) || W[P4++P5] = R0.H  || R4.H = W[I0++];
			    MNOP || W[P3++P5] = R2.H || R4.L = W[I1++];
				R2 = (A0 += R4.H * R4.L ) || R4.H = W[I0++] || R4.L = W[I1++];
			    R0 = (A0 += R4.H * R4.L ) || W[P2++P5] = R0.H ||R4.H = W[I0++];
			    MNOP || W[P1++P5] = R2.H || R4.L = W[I1++];
			    W[P0++P5] = R0.H; 
			LOOP_END Cor_h8_1;
		    R0 = (A0 += R4.H * R4.L ) || R4.H = W[I0++] || R4.L = W[I1++];
			W[P4] = R0.H;            
		    R0 = (A0 += R4.H * R4.L ) || I2 += M1;
			W[P3] = R0.H;         
//			R5 += -2;
			R7 += -1;
		LOOP_END Cor_h8;		
			P3 = [FP-4];
			P4 = [FP-8];
			I0 = B2;
			I1 = I2;
			I2 = SP;
			M0 = 8;
			P3 += -16;
			P4 += -16;
			R7 = [I0] || R4.L = W[I1++];
		    R0 = (A0 = R7.L * R4.L ) || R4.L = W[I1++] || I2 += M0;
			W[P4] = R0.H || R0 = (A0 += R7.H * R4.L );
			W[P3] = R0.H;
//       		 for(i=k+(Word16)1; i<NB_POS; i++ ) {
//                 cor = L_mac(cor, *ptr_h1, *ptr_h2); ptr_h1++; ptr_h2++;
//                 *p3 = extract_h(cor);
//                 cor = L_mac(cor, *ptr_h1, *ptr_h2); ptr_h1++; ptr_h2++;
//                 cor = L_mac(cor, *ptr_h1, *ptr_h2); ptr_h1++; ptr_h2++;
//                 *p2 = extract_h(cor);
//                 cor = L_mac(cor, *ptr_h1, *ptr_h2); ptr_h1++; ptr_h2++;
//                 *p1 = extract_h(cor);
//                 cor = L_mac(cor, *ptr_h1, *ptr_h2); ptr_h1++; ptr_h2++;
//                 *p0 = extract_h(cor);
//                 p3 -= ldec; p2 -= ldec; p1 -= ldec; p0 -= ldec; }	 			 				
//			R5 = 124;
			P4 = 7;
			P5 = -18;       		
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+rri0i4@GOT17M4];
	[--SP] = R7;
	R7 = 142;
	R0 = R0 + R7;
	R7 = [SP++];
	R3 = R0
	P3 = [SP++];
	R0 = [SP++];
			[FP-4] = R3;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+rri2i3@GOT17M4];
	[--SP] = R7;
	R7 = 126;
	R0 = R0 + R7;
	R7 = [SP++];
	R2 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+rri1i2@GOT17M4];
	[--SP] = R7;
	R7 = 126;
	R0 = R0 + R7;
	R7 = [SP++];
	R1 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+rri0i1@GOT17M4];
	[--SP] = R7;
	R7 = 126;
	R0 = R0 + R7;
	R7 = [SP++];
	R3 = R0
	P3 = [SP++];
	R0 = [SP++];
				R5 = -2;
		LOOP Cor_h9 LC0 = P4;		 
		LOOP_BEGIN Cor_h9;
			R2 = R5 + R2 (S) || P3 = [FP-4];
			I0 = B2; 
			P2 = R2;
			R1 = R5 + R1;
			P1 = R1;
			P3 += -16;
			R3 = R5 + R3 (S) || [FP-4]=P3;
			P0 = R3;
			             
            I1 = I2;
			A0 = 0 || R7.L = W[I0++] || R4.L = W[I1++];                   
            LOOP Cor_h9_1 LC1=P4;
	        LOOP_BEGIN Cor_h9_1;
			    R0 = (A0 += R7.L * R4.L ) || R7.H = W[I0++] || R4.H = W[I1++];
				W[P3++P5] = R0.H;
			    A0 += R7.H * R4.H  || R7.H = W[I0++] || R4.L = W[I1++];
                R0 = (A0 += R7.H * R4.L ) || R7.H = W[I0++] || R4.L = W[I1++];
			    R0 = (A0 += R7.H * R4.L ) || W[P2++P5] = R0.H || R4.L = W[I1++];
				W[P1++P5] = R0.H || R7.H = W[I0++];
			    R0 = (A0 += R7.H * R4.L ) || R7.L = W[I0++] || R4.L = W[I1++];
				W[P0++P5] = R0.H;	
    		LOOP_END Cor_h9_1; 
		    R0 = (A0 += R7.L * R4.L ) || I2 += M1;
			W[P3] = R0.H;         
//			R5 += -2;            //l_fin_inf--;
			P4 += -1;            //ptr_hf += STEP;                    
		LOOP_END Cor_h9;		
		P3 = [FP-4];															
		R4.H = W[SP] || R4.L = W[I2]; //cor = 0;			 
		R0.L = (A0 = R4.H * R4.L )(T);			    					
      	unlink;
      	W[P3-16] = R0;    
	   	RTS;
