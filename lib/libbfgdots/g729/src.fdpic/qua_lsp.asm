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
$RCSfile: Qua_lsp.asm,v $
$Revision: 1.4 $
$Date: 2006/05/24 07:46:55 $

Project:		G.729AB for Blackfin
Title:			Qua_lsp
Author(s):		wuxiangzhi,
Revised by:		E. HSU

Description     :      LSP quantization 

Prototype       :      _Qua_lsp() 
					   _Lsp_qua_cs()	
					   _Lsp_select()
					   _Get_wegt()
						
******************************************************************************
Tab Setting:			4
Target Processor:		ADSP-21535
Target Tools Revision:	2.2.2.0
******************************************************************************

Modification History:
====================
$Log: Qua_lsp.asm,v $
Revision 1.4  2006/05/24 07:46:55  adamliyi
Fixed the failing case for g729ab decoder for tstseq6. The issue is the uClinux GAS bug: it cannot treat the (m) option correctly.

Revision 1.4  2004/01/27 23:41:50Z  ehsu
Revision 1.3  2004/01/23 00:40:56Z  ehsu
Revision 1.2  2004/01/13 01:34:52Z  ehsu
Revision 1.1  2003/12/01 00:13:22Z  ehsu
Initial revision

Version         Date            Authors        		  Comments
0.0         03/19/2001          wuxiangzhi            Original

*******************************************************************************/ 


.extern _Lsf_lsp2;           
.extern _Lsp_expand_1_2;     
.extern _Lsp_get_quant;      
.extern _Lsp_lsf2;           
.extern _Lsp_prev_extract;   
//.extern cand;                
.extern fg_0;                
.extern fg_1;                
.extern fg_sum;              
.extern fg_sum_1;            
.extern fg_sum_inv;          
.extern fg_sum_inv_1;        
.extern freq_prev;           
.extern lspcb1;              
.extern lspcb2;              
.extern rri0i0;              
.text;
.align 8;

_Qua_lsp:
	  .global _Qua_lsp;
      .type  _Qua_lsp,STT_FUNC;
	  LINK 56;
	  [FP-4] = R0;    // R0 = ADDRESS OF lsp
	  [FP-8] = R1;    // R1 = ADDRESS OF lsp_q
	  [FP-12] = R2;   // R2 = ADDRESS OF ana
	  R7=FP;
	  R7 += -56;
	  I1 = R7;
	  [FP-16]=R7;
	  I0 = R0;
	  P0 = 10;
	  CALL _Lsp_lsf2;
	  R0 = [FP-12]; 
	  R7 = [FP-16];
	  CALL _Lsp_qua_cs;
	  R7 = [FP-16];
	  I0 = R7;
      R0 = [FP-8];
	  P0 = 10;
	  I1 = R0;
	  CALL _Lsf_lsp2;
	  UNLINK;
	  RTS;

_Lsp_qua_cs:
	  .global _Lsp_qua_cs;
      .type  _Lsp_qua_cs,STT_FUNC;
      I0=R7;
      I3=R7;
	   LINK 104;
	   [FP-4] = R0;	   
	   [FP-36]=R7;
	   R6 = FP;
	   R7 = -104;
	   M0 = 16;
	   R7 = R7 + R6 (S) || I3 += M0;
	   B0 = R7;
	   [FP-44]=R7;
		R7 += 40;
		[FP-40]=R7;
	   CALL _Get_wegt;
	   R7 = 0;
	   [FP-8] = R7;    // LOOP TIMES
Lsp_qua_csL:
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+fg_1@GOT17M4];
	R5 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+fg_sum_inv_1@GOT17M4];
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+fg_sum_inv@GOT17M4];
	P4 = R0
	P3 = [SP++];
	R0 = [SP++];
	   R1 = ROT R7 BY -1 || P3=[FP-40];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+fg_0@GOT17M4];
	R4 = R0
	P3 = [SP++];
	R0 = [SP++];
		IF CC P4 = P5;
		IF CC R4 = R5;
		I2 = R4;
		P5 = [FP-36];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+freq_prev@GOT17M4];
	I3 = R0
	P3 = [SP++];
	R0 = [SP++];
	   	CALL _Lsp_prev_extract;
	   	R7=R0-|-R0 || P3=[FP-40];	   
	   	P0 = 128;
	  	P1 = 5;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+lspcb1@GOT17M4];
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
	  	R6.H = 0X7FFF;
	  	R6.L = 0XFFFF;
	  	R5 = R0-|-R0 || R2 = [I1++] || R3 = [P3];
	  	LOOP Lsp_pre_select1 LC0 = P0;
	  	LOOP_BEGIN Lsp_pre_select1;
//		  	A1 = A0 = 0 ;
		       R4 = R3 -|- R2(S) || R2 = [I1++] || R3 = [P3+4];
		       R0 = R3 -|- R2(S) || R2 = [I1++] || R3 = [P3+8];
			   A0  = R4.L * R4.L, A1  = R4.H * R4.H;			   		      
			   A0 += R0.L * R0.L, A1 += R0.H * R0.H;
			   R4 = R3 -|- R2(S) || R2 = [I1++] || R3 = [P3+12];
		       R0 = R3 -|- R2(S) || R2 = [I1++] || R3 = [P3+16];
			   A0 += R4.L * R4.L, A1 += R4.H * R4.H;			   		      
			   R4 = R3 -|- R2(S) || R2 = [I1++] || R3 = [P3+20];
			   A0 += R0.L * R0.L, A1 += R0.H * R0.H;			   		      
			   A0 += R4.L * R4.L, A1 += R4.H * R4.H;
		  	R0 = (A0 += A1) || R3 = [P3];
		  	CC = R0 < R6;
		  	IF CC R7 = R5;
		  	R6 = MIN(R6,R0);
		  	R5 +=1;
	  	LOOP_END Lsp_pre_select1;
	  	P4 = -16;
	  	P5 = -14; 
	  	P4 = FP + P4;
	  	P5 = FP + P5; 
	   	R0 = [FP-8];
	   	R6 = ROT R0 BY -1 || P2=[FP-44];
		IF CC P5=P4;
       	R7.H = 10;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+lspcb1@GOT17M4];
	R5 = R0
	P3 = [SP++];
	R0 = [SP++];
       	R6 = R7.H * R7.L || W[P5] = R7.L;     
       	R5 = R5 + R6 (S) || P3=[FP-40];
	   	I1 = R5;
	   [FP-12] = R5;
	   CALL _Lsp_select;	   
	   R4.H = R5.L >> 0 || R0 = [FP-8];
	   	P4 = -20;
	  	P5 = -18; 
	  	P4 = FP + P4;
	  	P5 = FP + P5; 
	   R2 = ROT R0 BY -1 || R7 = [FP-12];
		IF CC P5=P4;
		R5.H = 10;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+lspcb2@GOT17M4];
	R2 = R0
	P3 = [SP++];
	R0 = [SP++];
		R1 = R4.L * R5.H , R0 = R4.H * R5.H || P4 = [FP-36];				
		I2 = R7;
		R0 = R0 + R2 (S) || W[P5] = R4.H;		
		I0 = R0;
		P5 += -4;
		P4 += 20;
		R1 = R1 + R2 (S)  || W[P5] = R4.L || R7 = [I2++]; 			
		R1 += 10;
		I1 = R1;		
		R6 = [I0++];
		R6 = R7 +|+ R6(S) || R7 = [I2++] || R4 = [I0++];
		[P4] = R6 || R6 = PACK(R6.L,R6.H);
		R5 = R7 +|+ R4(S) || R7 = [I2++] || R4 = [I0];
		[P4+4] = R5 || R4.H = W[I1++];
	    R3 = R7 +|+ R4(S) || R7 = [I2++] || R4 = [I1++];		
		R5 = R7 +|+ R4(S) || R7 = [I2] ;
		[P4+8]  = R3 || R4 = [I1];
		[P4+12] = R5 || R5 = R7 +|+ R4(S) ;
		[P4+16] = R5 || R4 = ROT R6 BY 0 ;
		I0 = P4;
		R7 = 10;             // GAP1
		I1 = I0;
	   	P0 = 9;
//	   	MNOP || R6.H = W[I0] || I1 += 2;
//	   	R6.L = W[I1++]; 
       	R5.L = R4.H - R4.L(S) || I1 += 4;
   	   	LOOP Lsp_expand1 LC0 = P0;
	   	LOOP_BEGIN Lsp_expand1;
	 		
			R5 = R5+|+R7,R1 = R5-|-R7(S,ASR) || R6.L = W[I1--];
			CC = BITTST(R5,15);			
		    R3.H = R4.H - R5.L(S);
		    R3.L = R4.L + R5.L(S);
		    IF !CC R4 = R3;
		    W[I0++] = R4.H || R5.L = R4.L - R6.L(S);
            R4 = PACK(R4.L, R6.L) || I1 += 4 || W[I1] = R4.L;
       	LOOP_END Lsp_expand1;
		I0 = P4;
		R7 = 5;             // GAP2
		CALL _Lsp_expand_1_2;		
		R0 = [FP-8];
		P3 = -28;		
		R7=ROT R0 BY -1 || P1=[FP-40]; //CC = BITTST(R0,0);
		P5 = -32;
		IF CC P5 = P3;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+fg_sum_1@GOT17M4];
	R5 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+fg_sum@GOT17M4];
	R6 = R0
	P3 = [SP++];
	R0 = [SP++];
		P5 = FP + P5;
		IF CC R6=R5;
		I2 = R6;
		I0 = P4;		
		P3=[FP-44];
		P0 = 5;
	  A0 = 0 || R7 = [I0++] || R6 = [P1++];
	  R5 = R7 -|- R6(S) || R4 = [I2++];
	  LOOP Lsp_get_tdist1 LC0 = P0;
	  LOOP_BEGIN Lsp_get_tdist1;	      
	      	R3.L = R5.L * R4.L, R3.H = R5.H * R4.H (T) || R2 = [P3++];
			R7 = [I0++];
		  	R0 = R2.L * R3.L, R1 = R2.H * R3.H  || R6 = [P1++];
			R5 = R7 -|- R6(S) || R4 = [I2++];
		  	R0 = R0 << 4(S);
		  	R1 = R1 << 4(S);		  
		  	A0 += R0.H * R3.L;
		  	R0 = (A0 += R1.H * R3.H);
	  LOOP_END Lsp_get_tdist1;
		R7 = [FP-8];
		R1 = ROT R7 BY -1 || [P5--] = R0;
		BITSET(R7,0);
		[FP-8] = R7;
		IF !CC JUMP Lsp_qua_csL;
Lsp_qua_csLEND:
        R6 = R1-|-R1 || R1 = [P5];
		CC = R1 <= R0;
		IF CC R7 = R6;
		M0= -16;
	   	I0 = FP;
		R5 = ROT R7 BY -1 || I0 += M0;
	   	R7 = R0-|-R0 || R2=[I0--];
	   	R5 = R2 >>> 16 || R3 = [I0--];
	   	IF !CC R2=R5;
	   	R5=R3 >>> 16 || R4 = [I0];
	   	IF !CC R3=R5;
	   	R5 = R4 >>> 16;

	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+fg_1@GOT17M4];
	P0 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+fg_sum_1@GOT17M4];
	P1 = R0
	P3 = [SP++];
	R0 = [SP++];
		R0 = 128;
		IF CC JUMP Lsp_qua_cs2;
Lsp_qua_cs1:
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+fg_0@GOT17M4];
	P0 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+fg_sum@GOT17M4];
	P1 = R0
	P3 = [SP++];
	R0 = [SP++];
Lsp_qua_cs2:
	   R6.L = R3.L << 5(S) ||P5 = [FP-4];
	   IF  CC R7=R0;
	   IF !CC R4=R5;
	   R7 = R7 | R2;
	   R6 = R6 | R4;
	   W[P5++] = R7;
	   W[P5] = R6;
	[--SP] = R1;
	[--SP] = P3;
	P3 = M2;
	R1 = [P3+lspcb1@GOT17M4];
	R0 = R1
	P3 = [SP++];
	R1 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+lspcb2@GOT17M4];
	R1 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+freq_prev@GOT17M4];
	R5 = R0
	P3 = [SP++];
	R0 = [SP++];
	   R6=[FP-36];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+_Lsp_get_quant@GOT17M4];
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
	  CALL (P5);
	   UNLINK;
	   RTS;

_Lsp_select:
	  .global _Lsp_select;
      .type  _Lsp_select,STT_FUNC;
      SP += -8;
	  P0 = 5;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+rri0i0@GOT17M4];
	I3 = R0
	P3 = [SP++];
	R0 = [SP++];
	  I0 = I3;
	  R7 = [P3++]|| R6 = [I1++];
	  LOOP Lsp_select1 LC0 = P0;
	  LOOP_BEGIN Lsp_select1;
	      R5 = R7 -|- R6(S) || R7 = [P3++]|| R6 = [I1++];
		  [I3++] = R5;
	  LOOP_END Lsp_select1;
	  
	  R7.H = 0X7FFF;
	  R7.L = 0XFFFF;
	  R5 = R0-|-R0 || [SP+4]=R7;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+lspcb2@GOT17M4];
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
	  R3 = R0-|-R0 || [SP]=R7;
	  P1 = 32;	 
	  R4 = R0 -|- R0 || R1 = [I0++] || R2 = [I1++];
	  M3 = -16 (X);
	  R2 = R1 -|- R2(S) || R7 = [P2] ;
	  LOOP Lsp_select2 LC0 = P1;	  
 	  LOOP_BEGIN Lsp_select2;		  	
		    
 			R0.L = R2.L * R7.L, R0.H = R2.H * R7.H (T) || R7 = [I1++] || R1 = [I0++];
			R7 = R1 -|- R7(S) || R1 = [P2+4];
 			A0 = R2.L * R0.L, A1 = R2.H * R0.H  ;		  	 			
 			R0.L = R7.L * R1.L, R0.H = R7.H * R1.H (T) || R2 = [I1++] || R1 = [I0++];
			R2 = R1 -|- R2(S) || R1 = [P2+8];
 			A0 += R7.L * R0.L, A1 += R7.H * R0.H ;		    
		    R0.L = R2.L * R1.L, R0.H = R2.H * R1.H (T);
			A0 += A1 || R7=[SP+4];
			R0 = (A0 += R2.L * R0.L), A1 = R2.H * R0.H || R2 = [I1++] || R1 = [I0++];		
			R2 = R1 -|- R2(S) || R1 = [P2+12];
			CC = R0 < R7;			
			R6.L = R2.L * R1.L, R6.H = R2.H * R1.H (T) ;
			R7 = MIN(R0,R7) || R0 = [I1++] || R1 = [I0++M3];			 		     					    			
			R1 = R1 -|- R0(S) ; 
 			A0 = R2.L * R6.L, A1 += R2.H * R6.H || R6 = [P2+16];		  	 						
		  	R0.L = R1.L * R6.L, R0.H = R1.H * R6.H(T) || [SP+4]=R7;
			IF CC R5 = R3;
		  	A0 += R1.L * R0.L, A1 += R1.H * R0.H || R2 = [I1++] || R1 = [I0++];
			R0 = (A0+=A1) || R6=[SP];
		    CC = R0 < R6;
			IF CC R4 = R3;
			R6 = MIN(R0,R6) || R7 = [P2];
			R2 = R1 -|- R2(S)  || [SP]=R6;
			R3 += 1;
	  LOOP_END Lsp_select2;
	  SP += 8;
	  RTS;


_Get_wegt:
	  .global _Get_wegt;
      .type  _Get_wegt,STT_FUNC;
      SP += -20;
      P3=I0;
//	   I1 = I0;
	   P0 = 8;
//	   I1 += 2;
	   R7.H = 9221;
	   R5.H = 8192;
	   R5.L = R5.H >> 0 || R4 = [P3];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+rri0i0@GOT17M4];
	I2 = R0
	P3 = [SP++];
	R0 = [SP++];
//	   buf[0] = sub( flsp[1], (PI04+8192) ); //8192:1.0(Q13) 
//       for ( i = 1 ; i < M-1 ; i++ ) { tmp = sub( flsp[i+1], flsp[i-1] ); buf[i] = sub( tmp, 8192 ); }	   
	   R6.H = R4.H - R7.H(S) || R7 = [P3+4] ;
	   MNOP ||  R4 = [P3++];
	   LOOP Get_wegt1 LC0 = P0>>1;
	   LOOP_BEGIN Get_wegt1;		
			R6 = R7 -|- R4(S) || R7 = [P3+4] || W[I2++] = R6.H;
			R6 = R6 -|- R5(S) || R4 = [P3++];
			W[I2++] = R6.L;

	   LOOP_END Get_wegt1;
		W[I2++] = R6.H;	   
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+rri0i0@GOT17M4];
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
	   R7.H = W[I3];
	   R7.L = 15485;
//	   I1 = B0;    
//	   I3 = B0;
	   I3=SP;
	   R5.L = R7.L - R7.H(S) || R6 = [I0++] || I3 += 4;
	   P0 = 10;
	   R5.H = 0x5000;
	   R7.L  = 2048;
	   R7.H  = R7.L >> 0;
	   R4 = R7 -|- R7 || W[I2] = R5.L || I3 += 4;	  
/*****************************************	   
	  for ( i = 0 ; i < M ; i++ ) {
        if ( buf[i] > 0 ){ wegt[i] = 2048;                    
        } else {
           L_acc = L_mult( buf[i], buf[i] );        
           tmp = extract_h( L_shl( L_acc, 2 ) );    
           L_acc = L_mult( tmp, CONST10 );          
           tmp = extract_h( L_shl( L_acc, 2 ) );    
           wegt[i] = add( tmp, 2048 );              
        }
      }
**********************************************/	   
	   R6 = R6 << 1 (V,S);		
	   R1 = 0;    
	   I1=SP;
	   LOOP Get_wegt2 LC0 = P0>>1;
	   LOOP_BEGIN Get_wegt2;
	   		CC = BITTST(R6,15);
            R0.H = R6.L * R6.L ,  R0.L = R6.H * R6.H (T);            
            R1 = ROT R1 BY 16;
            CC = BITTST(R6,31);			
            R0 = R0 << 2 (V,S);
            R1 = ROT R1 BY 1;
			R2.L = R0.H * R5.H, R2.H = R0.L * R5.H (T) || R6 = [I0++];
			R6 = R6 << 1 (V,S) ;	
			R2.L = R2.L * R1.H,	R2.H = R2.H * R1.L (IU);
			R0 = R7 +|+ R2(S) ;	
			R4 = MAX(R4,R0)(V);			
			R1 = R0-|-R0 || [I1++] = R0;    
	   LOOP_END Get_wegt2;	   
	   R7.H = 0x4ccd;
	   R6 = R7 -|- R7 || R0 = [I3];
//	   I0 = B0;
//	   I0=SP;
	   R0 = R0.L * R7.H, R1 = R0.H * R7.H (S2RND);// || R7 = [I0++];   
	   R0 = PACK(R1.H,R0.H) ;
//	   R6 = R7 -|- R7;
	   [I3] = R0 || R4 = MAX(R4,R0)(V);		
//	   LSETUP(Get_wegt2_2,Get_wegt2_2) LC0 = P0 >> 1;
//	   Get_wegt2_2: R6 = MAX(R7,R6)(V) || R7 = [I0++];
//	   I0 = B0;
	   I0=SP;
	   I1 = B0;
	   R7.L = VIT_MAX(R4)(ASL);
	   R6.L = SIGNBITS R7.L || R5 = [I0++];
	   R4 = ASHIFT R5 BY R6.L(V,S) || R5 = [I0++];
	   LSETUP(Get_wegt3,Get_wegt3) LC0 = P0 >> 1;
	   Get_wegt3: R4 = ASHIFT R5 BY R6.L(V,S) || R5 = [I0++] || [I1++] = R4;
	   SP += 20;
	   RTS;


    

 
