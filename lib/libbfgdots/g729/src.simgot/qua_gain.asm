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
// *** Author: Xiangzhi,wu   xiangzhi.wu@analog.com    2001/04/19	       ***
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
$RCSfile: Qua_gain.asm,v $
$Revision: 1.4 $
$Date: 2006/05/24 07:46:55 $

Project:		G.729AB for Blackfin
Title:			Qua_gain
Author(s):		wuxiangzhi,
Revised by:		E. HSU

Description     :      Gain quantization 

Prototype       :      _Qua_gain() 
					   _Gbk_presel()						  
						
******************************************************************************
Tab Setting:			4
Target Processor:		ADSP-21535
Target Tools Revision:	2.2.2.0
******************************************************************************

Modification History:
====================
$Log: Qua_gain.asm,v $
Revision 1.4  2006/05/24 07:46:55  adamliyi
Fixed the failing case for g729ab decoder for tstseq6. The issue is the uClinux GAS bug: it cannot treat the (m) option correctly.

Revision 1.4  2004/01/27 23:41:48Z  ehsu
Revision 1.3  2004/01/23 00:40:55Z  ehsu
Revision 1.2  2004/01/13 01:34:52Z  ehsu
Revision 1.1  2003/12/01 00:13:21Z  ehsu
Initial revision

Version         Date            Authors        		  Comments
0.0         04/19/2001          wuxiangzhi            Original

*******************************************************************************/ 



.extern _Gain_predict;   
.extern _Gain_update;    
.extern gbk1;            
.extern gbk2;            
.extern map1;            
.extern map2;            
.extern past_qua_en;     
.extern thr1;            
.extern thr2;            

.text;
.align 8;

_Qua_gain:
	   .global _Qua_gain;
      .type  _Qua_gain,STT_FUNC;
	   LINK 56;	   
	   [FP-4] = R0;    // R0.L = gain_pit R0.H = gain_cod
	   [FP-8] = R1;    // [FP-8] BIT 1 OF R1 IS  tameflag                       	   
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+224]; // past_qua_en
	B2 = R0
	P3 = [SP++];
	R0 = [SP++];
	   CALL _Gain_predict;	   	   
	   I0 = B0;        //g_coeff
	   I1 = B1;        //exp_coeff
	   R2 = R2-|-R2 || R7 = [I0++] || [FP-12] = R0; 
	   MNOP || R5 = [I0++] || R6 = [I1++];
	   R1 = R7.L * R5.L || R4 = [I1++];//L_tmp1 = L_mult( g_coeff[0], g_coeff[2] );
	   //exp1 = add( add( exp_coeff[0], exp_coeff[2] ), 1-2 );
	   		R3.L = R6.L + R4.L(S) || R7 = [I0--];
	   		R3.H = 1;
	   		R0 = R7.L * R7.L || R6 = [I1--] || I0 -= 4;//L_tmp2 = L_mult( g_coeff[4], g_coeff[4] );
	   //exp2 = add( add( exp_coeff[4], exp_coeff[4] ), 1 );
	   		R5.L = R6.L + R6.L(S) || I1-= 4;
	   		R3.L = R3.L - R3.H(S);          //exp1
	   		R5.L = R5.L + R3.H(S);          //exp2
	   		R4.L = R3.L - R5.L(S);          //exp1 - exp2	   		
	   		CC = BITTST(R4,15);
	   		R7 = - R4(V);
	   		IF !CC R4=R7;
	   		R7=-32;
	   		R4=MAX(R7,R4)(V);
	   		R7 = ASHIFT R1 BY R4.L(S);
	   		IF !CC R1=R7;
        	R6 = ASHIFT R0 BY R4.L(S);
        	IF CC R0=R6;        	        	
      		R0 = R1 - R0(S);
        	R7 = MIN(R5,R3)(V);
		  	R6.L = SIGNBITS R0;
		  	R7.H = 16;
		  	R1 = ASHIFT R0 BY R6.L;
		  	R7.L = R7.L + R6.L(S) || R6 = [I0++];
		  	R1 = R1 >>> 16 || R5 = [I0++];
		  	R7.L = R7.L - R7.H(S) || R6.L = W[I0];
		  	R2.H = 16384;	     
          	P0 = 15;          
          	DIVS(R2,R1);    // get sign bit
          	LSETUP(_LP_ST,_LP_ST)LC1=P0;
_LP_ST:   		DIVQ(R2,R1);	  		  
		  	R4 = 29;
		  	R2 = - R2(V) || I1 += 2;
		  	R7.L = R4.L -R7.L(S)  || R4.L = W[I1++] || I0-=4;
		  	R7 = PACK(R2.L, R7.L) || R2 = [I1++] || I0-=4; // R7.L = exp_inv_denom R7.H = inv_denom
		  	R1 = R6.H * R5.L,  R0 = R6.L * R5.H || R4.H = W[I1] || I1-=4;
		  	R5.L = -1;
		  	R2 = R2 +|+ R4 (S);
		  	R3.L = R2.H - R5.L(S);
		  	R4.L = R2.L - R3.L(S);
		  	CC = BITTST(R4,15);
		  	R6 = R4 +|+ R5, R4=R4-|-R5 (S);
		  	IF CC R4=R6;
		  	R6 = -R4(V);
		  	IF !CC R4 = R5;
			IF !CC R5 = R6;
			R1 = ASHIFT R1 BY R5.L(S);
			R0 = ASHIFT R0 BY R4.L(S);
			R6 = MIN(R3,R2)(V);
            R0 = R1 - R0(S);
			R3.H = 1;
			R6.L = R6.L - R3.H(S);
			R6.H = 16;
			R5.L = SIGNBITS R0;
			R6.L = R6.L - R6.H(S);
			R0 = ASHIFT R0 BY R5.L(S);
			R6.L = R6.L + R5.L(S);
			R6.H = 24;
			R5.L = R6.L + R7.L(S);
			R0 = R0.H * R7.H || R2 = [FP-8];
			R5.L = R6.H - R5.L(S)||I1-=4 || R6 = [I0++];
			R2.H = 481;						
			R0 = ASHIFT R0 BY R5.L(S) || R5 = [I0++] ;
			R1= ROT R2 BY -2 || R5.L = W[I0];
			R1 = MIN(R0,R2)(V) || R4 = [I1++];									
			IF CC R0=R1;
							
			R0 = R0 >> 16 ; 				 				
			 R0 = R6.H * R5.L, R1 = R6.L * R5.H  ||[FP-16] = R0 || R5 = [I1++];
			 R3.L = R4.L + R5.H(S) || R5 = [I1++];
			 R2.L = R4.H + R5.L(S);
			 R2.L = R2.L + R3.H(S);
			 R4.L = R3.L - R2.L(S);
			 CC = BITTST(R4,15);
				R6=-32;
			 IF CC JUMP Qua_gain6;
		     R4.L = R4.L + R3.H(S);
		     R4 = - R4(V);
			 R0 = R0 >>> 1(S);
			 R4 = MAX(R6,R4)(V);
			 R1 = ASHIFT R1 BY R4.L(S);
			 JUMP Qua_gain7;
Qua_gain6:
             R4.L = R4.L - R3.H(S);
			 R1 = R1 >>> 1(S);
			 R4 = MAX(R6,R4)(V);
			 R0 = ASHIFT R0 BY R4.L(S);
Qua_gain7:
             R6 = MIN(R3,R2)(V);
             R0 = R1 - R0(S);
			 R6.H = 16;
			 R6.L = R6.L - R3.H(S);
			 R5.L = SIGNBITS R0;
			 R6.L = R6.L - R6.H(S);
			 R0 = ASHIFT R0 BY R5.L;
			 R6.L = R6.L + R5.L(S);
			 R6.H = 17;
			 R5.L = R6.L + R7.L(S);
			 R0 = R0.H * R7.H || R2 = [FP-16];
			 R5.L = R6.H - R5.L(S) || R1 = [FP-12];   // [FP-12] HIGH exp_gcode0 LOW gcode0 			 			 				  			 			 					 
			 R0 = ASHIFT R0 BY R5.L (S);
			 R5 = 4;
			 R6 = PACK(R0.H, R2.L);   // best_gain			 					 
			 R7 = R1 >> 16;
			 CC = R7 < R5;			 			 					
			 IF CC JUMP Qua_gain8;
			    R7.L = R5.L - R7.L(S);
				R7.L = ASHIFT R1.L BY R7.L(S);
				JUMP Qua_gain9;
Qua_gain8:
                R7.H = 20;
                R1 = R1.L(X);
				R7.L = R7.H - R7.L(S);
				R1 = ASHIFT R1 BY R7.L;
				R7 = R1 >> 16;
Qua_gain9:                				
				CALL _Gbk_presel;                              
			   I1 = SP;
			   I0 = B1;
			   I2 = B0;
			   R7.H = 14;
			   R7.L = 13;
			   MNOP || R6 = [I0++] || R0 = [FP-12];     // [FP-12] HIGH exp_gcode0 LOW gcode0
			   R5 = R6 +|+ R7(S) || R6 = [I0++];
//			   R0 = PACK(R0.H,R0.H) ;
			   R7.L = 21;
			   R7.H = 3;
			   R0.L = R0.H << 1(S) || [I1++] = R5;
			   R3.L = 4;			   
			   R2 = R0 -|- R7(S);
			   R3.L = R0.H - R3.L(S);
			   R1 = R6 +|+ R2(S) || R6 = [I0++];
			   R6.L = R6.L + R3.L(S) || [I1++] = R1;
			   R6.H=0;
			   [I1++]=R6 || R7 = MIN(R5,R1)(V);
			    B2 = I1;    
			   R5 = PACK(R7.H,R7.H);
			   I0 = SP;
			   R7 = MIN(R7,R5)(V);
			   P5 = 5;
			   R7 = MIN(R7,R6)(V);			   
			   R6.L = R6.L - R6.L (NS) ||  R7.H = W[I0++];        
			  R5.L = R7.L - R7.H(S) || R6.H = W[I2++];
			   R0 = ASHIFT R6 BY R5.L(S) || R7.H = W[I0++];
			   R0.L = R0.L >> 1;
			   LOOP Qua_gain11 LC0 = P5;
			   LOOP_BEGIN Qua_gain11;
			        R5.L = R7.L - R7.H(S) || R6.H = W[I2++] || [I1++] = R0;
					R0 = ASHIFT R6 BY R5.L(S) || R7.H = W[I0++];
					R0.L = R0.L >> 1;
			   LOOP_END Qua_gain11; 	   
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+600]; // gbk1
	P0 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+604]; // gbk2
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
			   P0 = P0 + (P1 << 2);
			   P5 = P5 + (P2 << 2);
              // [FP-12] HIGH exp_gcode0 LOW gcode0
			  R6 = [FP-12];
			  R5 = [FP-8];
			  R5.H = 16383;
			  I0 = P0;
			  I3 = P5;			  			   				   			   					  			  
			  R7.H = 0X7FFF;
			  R7.L = 0XFFFF;
			  R6.H = 1;
			  [FP-20] = R5 || R4 = R5-|-R5;
//			  I2 = B2;
//			  	L2 = 20;
			  	P0 = P1;
			  	P5 = P2;
			  	[FP-16] = R7||R4=R7-|-R7;
				LOOP Qua_gain12 LC0 = P3;
				P3=B2;
			  	LOOP_BEGIN Qua_gain12;
			  		I1 = I3;
			       	R4 = [I0++] || R2 = [FP-20];				   
				   	LOOP Qua_gain12_1 LC1 = P4;
				   	P4 = 0;
				   	LOOP_BEGIN Qua_gain12_1;
				   	    
				       	R1 = ROT R2 BY -2 || R3 = [I1++];
					   	R7 = R4 +|+ R3(CO) ;					   	
					    R1.H = R7.H - R2.H(S);
#ifdef FLAG533	  		
						CC &= AC0;
#else
						CC &= AC;
#endif										
						  R2.L = R7.H * R7.H (T) || R3 = [P3];
						  R5.H = R7.L >> 1;
						  A1 = R3.H * R2.L,	 R5.L =(A0 = R3.L * R2.L)(T) || R2 = [FP-20];						  
						  IF CC JUMP Qua_gain12_1END;	
						  A1 += R6.H * R5.L, R7.L =(A0 = R6.L * R5.H) (T)|| R2 = [P3+4];
						  NOP;
//						  R5.L = R7.L * R7.L,R5.H = R7.H * R7.L (T) ;
							R5.L = R7.L * R7.L,R5.H = R7.H * R7.L (T) ;
						  A1 += R2.H * R7.H, R0   =(A0 = R2.L * R7.H)     || R3 = [P3+8];
						  
						  A1 += R3.H * R5.L, R0.L =(A0 = R3.L * R5.L) (T) || R3 = [P3+12];
						  A1 += R3.H * R7.L, R2   =(A0 = R3.L * R7.L)     || R3 = [P3+16];
						  A1 += R3.H * R5.H, R2.L =(A0 = R3.L * R5.H) (T);						 
						  A0  = R0.H * R6.H, A1 += R0.L * R6.H;
						  A0 += R2.H * R6.H, A1 += R2.L * R6.H || R7 = [FP-16];
						  R0=(A0+=A1);
						  CC  = R0 < R7;
						   R7 = MIN(R0,R7)||R2 = [FP-20];
						   IF CC P1 = P0;
						   IF CC P2 = P4;
						   [FP-16] = R7;
Qua_gain12_1END:          P4 += 1;
				   LOOP_END Qua_gain12_1;
                   P0 += 1;
			  	LOOP_END Qua_gain12;
			  	P2 = P5 + P2;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+600]; // gbk1
	P0 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+604]; // gbk2
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
			   	P0 = P0 + (P1 << 2);
			   	P5 = P5 + (P2 << 2);
			   	R4 = [P0];
			   	R2 = R4 >> 16 || R5 = [P5];
			   	R0.L = R4.L + R5.L(S);
			   	R3 = R5 >> 16;
			   	R7 = R2 + R3 (S);
			   	R2 = R7 >>> 1(S) || R6 = [FP-12];			   
			   	R5.L = 4;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+224]; // past_qua_en
	I3 = R0
	P3 = [SP++];
	R0 = [SP++];
			   	R5.L = R5.L - R6.H(S);
			   	R1 = R2.L * R6.L;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+668]; // map1
	P0 = R0
	P3 = [SP++];
	R0 = [SP++];
			   	R1 = ASHIFT R1 BY R5.L(S);			   
			   	R0 = PACK(R1.H, R0.L);			   
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+672]; // map2
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
			   	P0 = P0 + (P1 << 1);
			   	P5 = P5 + (P2 << 1);			   												
			   	R6.H = W[P0];
			   	R6.H = R6.H << 4(S) || R6.L = W[P5];
			   	R6.L = R6.H + R6.L(S) || [FP-4] = R0;
			   	[FP-20] = R6;			   			   				
			   	CALL _Gain_update;			   
			   	R0 = [FP-4];
			   	R1 = [FP-20];			   			   				   
				UNLINK;
	   			RTS;

_Gbk_presel:
	   .global _Gbk_presel;
      .type  _Gbk_presel,STT_FUNC;
//      L0=0;
//      L1=0;
	  //*** R6.H = best_gain[1] R6.L = best_gain[0]
	  //*** R7.L = gcode0

	  
	  R4.L = 31881;
	  R0.H = 0;
	  R0.L = 0Xd951;
	  R3 = R4.L * R6.L; // L_cfbg
	  R0 = R0 + R3(S);
	  R2 = R6 >> 16;
	  R1 = R0.H * R7.L;
	  R2 = R2.L(X);
	  R2 = R2 << 7(S);
	  R0 = R2 - R1(S);
	  R4.H = -17103;    // INV_COEF
	  R0 = R0 << 2(S);
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+664]; // thr2
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
	  R5 = R0.H * R4.H;
	  R0.H = 0X19;
	  R0.L = 0Xcc12;
	  R0 = R3 - R0(S);
	  R3.L = 31548;     // coef[1][0]
	  R1 = R0.H * R7.L;
	  R2 = R4.L * R6.H;
/*	  
	  [--SP]	= ASTAT; 
		[--SP] = (R7:0,P5:0);         							
		P4 = 6;
		R3 = [FP-8];
		CC = BITTST(R3,0);								
		P3.H	= _memdump;
		P3.L	= _memdump;	
		P4 = P3 + (P4<<1);
		IF CC P3 = P4;				   													
		[P3] = R6;
//		[P3+4] = R4;
//		[P3+8] = R2;
//		[P3+12] = R1;
//		[P3+16] = R0;
		(R7:0,P5:0) = [SP++];
		ASTAT	= [SP++];	  
*/	  
	  
	  R1 = R1.H * R3.L;
	  R2 = R2 >>> 3(S);
	  R0 = R1 - R2(S);
	  R0 = R0 << 2(S);
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+660]; // thr1
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
	  R6 = R0.H * R4.H;
	  	  
	  	
	  
	  R3.L = -3;   // sft_y
	  R4.L = -5;   // sft_x
	  P3 = 4;
	  P4 = 8;
	  P1 = 0;
	  P2 = 0;
	  R7 = R7.L(X);
	  CC = R7 <= 0;	 
	   
	  IF CC JUMP Gbk_presel_2;
Gbk_presel_1:	     
			R7.H = W[I0++];
		 	R0 = R7.H * R7.L ;
		 	NOP;
		 	R0 = ASHIFT R0 BY R3.L(S);		 	
		 	CC = R0 < R6;
		 	IF !CC JUMP Gbk_presel_1_2;
			P1 += 1;
			CC = P1 <P3;
			IF CC JUMP Gbk_presel_1;
Gbk_presel_1_2:
/*
			[--SP]	= ASTAT; 
			[--SP] = (R7:0,P5:0);         							
			P4 = 6;
			R3 = [FP-8];
			CC = BITTST(R3,0);								
			P3.H	= _memdump;
			P3.L	= _memdump;	
			P4 = P3 + (P4<<1);
			IF CC P3 = P4;				   																								
			[P3+4] = P1;		
			(R7:0,P5:0) = [SP++];
			ASTAT	= [SP++];	  
*/
         	R4.H = W[I1++];
		 	R0 = R4.H * R7.L;
		 	NOP;
		 	R0 = ASHIFT R0 BY R4.L(S);
		 	CC = R0 < R5;
/*		 	
		 	[--SP]	= ASTAT; 
			[--SP] = (R7:0,P5:0);         							
			P4 = 6;
			R3 = [FP-8];
			CC = BITTST(R3,0);								
			P3.H	= _memdump;
			P3.L	= _memdump;	
			P4 = P3 + (P4<<1);
			IF CC P3 = P4;		
			[P3+8] = R0;
			(R7:0,P5:0) = [SP++];
			ASTAT	= [SP++];	  
*/			
		 	IF !CC JUMP Gbk_preselEND;		 	
		 	P2 += 1;
		 	CC = P2 < P4;
		 	IF CC JUMP Gbk_presel_1_2;
		 	RTS;         
Gbk_presel_2:	     
		 	R0 = R7.H * R7.L ; R7.H = W[I0++];
		 	R0 = ASHIFT R0 BY R3.L(S);
		 	CC = R6 < R0;
		 	IF !CC JUMP Gbk_presel_2_2;
			P1 += 1;
			CC = P1 < P3;
			IF CC JUMP Gbk_presel_2;
Gbk_presel_2_2:         
		 	R0 = R4.H * R7.L ; R4.H = W[I1++];
		 	R0 = ASHIFT R0 BY R4.L(S);
		 	CC = R5 < R0;
		 	IF !CC JUMP Gbk_preselEND;
		 	P2 += 1;
		 	CC = P2 < P4;
		 	IF CC JUMP Gbk_presel_2_2;         
Gbk_preselEND:	  RTS;





