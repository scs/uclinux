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
$RCSfile: g729comc.asm,v $
$Revision: 1.4 $
$Date: 2006/05/24 07:46:55 $

Project:		G.729AB for Blackfin
Title:			G729COMC
Author(s):		wuxiangzhi,
Revised by:		E. HSU

Description     :      Common modules for coder and decoder      

Prototype       :   _Pred_lt_3()
					_Qua_Sidgain()
					_Calc_exc_rand()					  					   
					__update_exc_err()
						
******************************************************************************
Tab Setting:			4
Target Processor:		ADSP-21535
Target Tools Revision:	2.2.2.0
******************************************************************************

Modification History:
====================
$Log: g729comc.asm,v $
Revision 1.4  2006/05/24 07:46:55  adamliyi
Fixed the failing case for g729ab decoder for tstseq6. The issue is the uClinux GAS bug: it cannot treat the (m) option correctly.

Revision 1.4  2004/01/27 23:41:27Z  ehsu
Revision 1.3  2004/01/23 00:40:34Z  ehsu
Revision 1.2  2004/01/13 01:34:37Z  ehsu
Revision 1.1  2003/12/01 00:12:59Z  ehsu
Initial revision

Version         Date            Authors        		  Comments
0.0         04/19/2001          wuxiangzhi            Original

*******************************************************************************/ 

.extern _Inv_sqrt;
//.extern _Log2;
.extern inter_3l;
.extern rri0i0;
.extern rri0i1;
.extern rri0i2;
.extern rri1i1;
.extern rri2i2;
.extern tab_zone;
.text;
.align 8;
_Pred_lt_3:
	  .global _Pred_lt_3;
      .type  _Pred_lt_3,STT_FUNC;
	  I3 = P5;               // I3 POINTS TO exc[0]
      P5 = P5 + (P4 << 1);
	  CC = P3 < 0;           //if (frac < 0)
	  P1 = 3;
	  P4 = -2;
	  P2 = P3 + P1;
	  P4 = P5 + P4;
	  IF CC P3 = P2;
	  IF CC P5 = P4;
      P4.H = inter_3l;
	  P4.L = inter_3l;
	  M3 = -20;
	  M0 = 28;
	  R7 = P5;
	  R3 = ROT R7 BY -2;
	  I2 = P5;	  
	  I1 = P5;
	  P2 = P4 + (P3 << 1);    // c1= &inter_3l[frac];
	  P1 -= P3;
	  P1 = P4 + (P1 << 1);    // c2=&inter_3l[sub(UP_SAMP,frac)];
	  P3 = 10;
	  P4 = 6;	  
	  P5 = -60;	  
/********************************************************	  
	  for (j=0; j<L_subfr; j++)  { x1 = x0++; x2 = x0;
         c1 = &inter_3l[frac]; c2 = &inter_3l[sub(UP_SAMP,frac)]; s = 0;
        for(i=0, k=0; i< L_INTER10; i++, k+=UP_SAMP) {
           s = L_mac(s, x1[-i], c1[k]); s = L_mac(s, x2[i],  c2[k]); }
        exc[j] = round(s); }
**********************************************************/	  
		IF CC JUMP ODDSTART;
	  	LOOP Pred_lt_3_2 LC0 = P0>>1;
	  		P0 = -66;	  			  		
	  	LOOP_BEGIN Pred_lt_3_2;
	  		A1 = A0 = 0 || R3 = [I1++] || R7.H = W[P2++P4];	  		
			R4 = [I2] || I2-=2;
			LOOP Pred_lt_3_2_1 LC1 = P3>>1;
			LOOP_BEGIN Pred_lt_3_2_1;
				A1 += R4.H * R7.H, A0 +=  R4.L * R7.H (W32) || R3.L = W[I1++] || R6.L = W[P1++P4];				
				A1 += R3.L * R6.L, A0 +=  R3.H * R6.L (W32) || R4.H = W[I2--] || R7.H = W[P2++P4];
				A1 += R4.L * R7.H, A0 +=  R4.H * R7.H (W32) || R3.H = W[I1++] || R6.L = W[P1++P4];
				R1 =(A1 += R3.H * R6.L), R0  =(A0 += R3.L * R6.L) || R4.L = W[I2--]|| R7.H = W[P2++P4];
	    	LOOP_END Pred_lt_3_2_1;
	    	R5.L = R0(RND) || R7.L = W[P1++P5] || R4=[I1++M3];
			R5.H = R1(RND) || R7.L = W[P2++P0] || R4.L=W[I2--];
			[I3++] = R5    || I2 += M0;
	  	LOOP_END Pred_lt_3_2;
	   	RTS;	   
ODDSTART:
		M1 = -18;
		LOOP Pred_lt_3_3 LC0 = P0>>1;
	  	P0 = -66;	  	
		R4.H = W[I1++] || I2 += 2;
  		R4.L = W[I1--] ;
	    	R4.H = W[I1--] ;
	  	LOOP_BEGIN Pred_lt_3_3;						
			A1 = A0 = 0 || R3.L = W[I2++] || R7.H = W[P2++P4];
			LOOP Pred_lt_3_2_4 LC1 = P3>>1;
			LOOP_BEGIN Pred_lt_3_2_4;
				A0 += R4.H * R7.H, A1 += R4.L * R7.H (W32) || R3.H = W[I2++] || R6.L = W[P1++P4];
				A0 += R3.L * R6.L, A1 += R3.H * R6.L (W32) || R4.L = W[I1--] || R7.H = W[P2++P4];
				A0 += R4.L * R7.H, A1 += R4.H * R7.H (W32) || R3.L = W[I2++] || R6.L = W[P1++P4];
				R0 =(A0 += R3.H * R6.L), R1 =(A1 += R3.L * R6.L) || R4.H = W[I1--] || R7.H = W[P2++P4];
	    	LOOP_END Pred_lt_3_2_4;
			R5.H = R1(RND) || R7.L = W[P2++P0] || R4=[I1++M0];
			R5.L = R0(RND) || R7.L = W[P1++P5] || R4.L = W[I1--] ;			
			[I3++] = R5 || I2 += M1;
	    	R4.H = W[I1--];
	  	LOOP_END Pred_lt_3_3;
	  	RTS;
			_Calc_exc_rand:
	   		.global _Calc_exc_rand;
      		.type  _Calc_exc_rand,STT_FUNC;
	  		LINK 112;
	  		[FP-4] = R0;  // LOW = cur_gain  BIT O OFHIGH = FLAG_COD BIT 1 OF i_subfr
	  		[FP-8] = R1;
	  		[FP-12] = R2;	  
	  		R7 = R0.L;
	  		CC = R7 == 0;
	  		IF !CC JUMP Calc_exc_rand2;
	     	I0 = R1;
	     	R2 = ROT R0 BY 17;
		 	P0 = 40;
		 	LSETUP(Calc_exc_rand1,Calc_exc_rand1) LC0 = P0;
Calc_exc_rand1: 	[I0++] = R7;
			IF CC JUMP 1f;
			JUMP Calc_exc_randEND;
1:
			P0 = 41;
			P5=B0;
			CALL __update_exc_err;
			P0 = 41;
			P5=B0;
			CALL __update_exc_err;
			JUMP  Calc_exc_randEND;
Calc_exc_rand2:
				.extern excconst;
				R6 = 13849;				
            	A1 = R6 || P5 = [FP-12];
				I1.H = excconst;
            	I1.L = excconst;
            	P0.H = rri0i0;
				P0.L = rri0i0;    // pos
				R3 = R0-|-R0 || R5 = [I1++];
//				R5.L = 0X0206;
				A0 = R6 || R7.L = W[P5];
//				R5.H = 31821;			 
				R1 = (A1+=R5.H * R7.L)(IS) || R4 = [I1++];
//				R4.L = 2;
				R7 = EXTRACT(R1,R4.L)(Z) || [FP-32]=P0;
				R7 += -1;			
				CC = R7 == 2;			
				IF CC R7 = R3;
				R2 = EXTRACT(R1,R5.L)(Z) || R3 = [I1++];
//				R5.L = 0X0803;
				R2 += 40;
				R0 = EXTRACT(R1,R3.L)(Z) || R5.L = W[I1++];
				R4 = PACK(R2.L, R7.L)    || R3.L = W[I1++];
//				R3.H = 5;
				R2 = R3.H * R0.L(IS) || [FP-16] = R4;   // R4.H = T0; R4.L = frac
//				R5.L = 0XB01;
				R4 = EXTRACT(R1,R5.L)(Z) || W[P0++] = R2;
//				R3.L = 0XC03;
				R2 = EXTRACT(R1,R3.L)(Z) || R5.L = W[I1++];
//				R5.L = 0XF01;
				P4.H = rri0i1;   // excg
				P4.L = rri0i1; 
				R4 = R2.L * R3.H(IS) || W[P0+14] = R4;			
				R4 += 1;
				R2 = EXTRACT(R1,R5.L)(Z) || W[P0++] = R4;
				R2 = R5.H * R1.L(IS) || W[P0+14] = R2;
// 				R5.L = 3;
				R1 = R2 + R6(S) || R5.L = W[I1++];
				R2 = EXTRACT(R1,R5.L)(Z) || R5.L = W[I1++];
//				R5.L = 0X301;
				R4 = R2.L * R3.H(IS) || R3.L = W[I1++];
				R4 += 2;
				R4 = EXTRACT(R1,R5.L)(Z) || W[P0++] = R4;
//            	R3.L = 0X0401;
				R2 = EXTRACT(R1,R3.L)(Z) || R5.L = W[I1++]; 
//				R5.L = 0X0503;
				R4 = EXTRACT(R1,R5.L)(Z) || W[P0+14] = R4;
//				R5.L = 0X801;
				P1 = 12;
				R4 = R3.H * R4.L(IS) || R3.L = W[I1++];
				R2 += 3;
				R2.L = R2.L + R4.l(S) || R5.L = W[I1++];
				R4 = EXTRACT(R1,R3.L)(Z) || W[P0++] = R2;
				R2 = (A0+=R5.H * R1.L)(IS) || W[P0+14] = R4;
//				R5.L = 0X1FFF;
				R1 = R2 & R5 ;
				R1.H = R1.L << 1(S) || R4 = [FP-4];							
				I1 = P4;
				P0 = 40;
				
				A0 = 0 ;
				R3 = R0-|-R0 || [FP-20] = R1;
			 LOOP Calc_exc_rand2_1 LC0 = P0;
			 LOOP_BEGIN Calc_exc_rand2_1;			      
				  LOOP Calc_exc_rand2_1_1 LC1 = P1;
				  LOOP_BEGIN Calc_exc_rand2_1_1;
				     R2 = R2.L * R5.H(IS);
					 R2 = R2 + R6(S);
					 R1 = R2.L(X);
					 R3 = R3 + R1(S);
				  LOOP_END Calc_exc_rand2_1_1;
				  R1 = R3 >>> 7(S);				  
				  R3 = 0;
				  R0 = (A0 += R1.L * R1.L) (IS) || W[I1++] = R1.L;
     		 LOOP_END Calc_exc_rand2_1;
			 W[P5] = R2.L ;
			 
			 CALL _Inv_sqrt;
			 R1.L = R1.L >> 1 || R0 = [FP-4]; // LOW = cur_gain  BIT O OFHIGH = FLAG_COD BIT 1 OF i_subfr
			 R0.H = 19043;                     //FRAC1           19043    
			 R7.H = 1;			 
			 R6 = R0.L * R0.H;
			 R5 = 1;
			 R6.L = R6(RND);
			 R6.L = R6.L + R0.L(S);          //1 stall after this instr
			 R7.L = 0X4000;
			 R2 = (A0 = R1.H * R6.L), R3 = (A1 = R1.L * R6.L);//1 stall after this
			 R6.H = 14;
			 R2 = (A0 += R3.H * R5.L) || P5 = [FP-8];     
			  I1 = P4;
			 R6.L = SIGNBITS R2 || R0 = [P4--];
			 R2 = ASHIFT R2 BY R6.L(S) || R0 = [P4];			
			 R6.L = R6.L - R6.H(S);
			 P0 = 40;
			 R4.L = R6.L - R5.L(S) ;    // P5 POINTS TO exc
			 R6 = - R6(V) ;
			 R5 = LSHIFT R5 BY R4.L || R3 = [P4+4];
			 R5.H = R5.L >> 0 || R4 = [FP-16];          // [FP-16] = LOW frac  HIGH T0
			 LOOP Calc_exc_rand2_2 LC0 = P0 >> 1;
			 LOOP_BEGIN Calc_exc_rand2_2;
			     A0 = R3.L * R2.H, A1 = R3.H * R2.H || R3 = [P4+8];
			     [P4++] = R0 || 
			     R0.L = (A0+=R7.L*R7.H),R0.H = (A1+=R7.L*R7.H) (T);
			     R0 = R0 +|+ R5 (S);
				 R0 = ASHIFT R0 BY R6.L(V,S);
			 LOOP_END Calc_exc_rand2_2;			 
		 
			 	R6.L = -1;
			 	[P4++] = R0 || R6 =  R4.H * R6.L, R7 = R4.L * R6.L (IS);
			 	P4 = R6;            // (T0);
			 	P3 = R7;
				CALL _Pred_lt_3;    // [FP-20] = LOW Gp   HIGH Gp2
				P3 = [FP-8];    // P5 POINTS TO exc
			  	R7 = R6 -|- R6 || R3 = [FP-20];
			  	R5.H = 1;
//			  	R5.L = 0X4000;              
			  	P0 = 20;
			  	I3.H = rri0i1;   // excg
			  	I3.L = rri0i1;
			  	I2.H = rri0i2;     // excs
			 	I2.L = rri0i2;
			 	P4 = I2;
			 	I0 = SP;
			  	
			  	R5.L = R5.H << 14 || R4 = [P3];
			  	LOOP Calc_exc_rand2_3 LC0 = P0;
 			  	LOOP_BEGIN Calc_exc_rand2_3;
			     	A0 = R4.L * R3.H, A1 = R4.H * R3.H || R4 = [I3++];
				 	R0.L = (A0 += R5.H*R5.L), R0.H = (A1 += R5.H*R5.L) (T) || [I0++]=R4;
				 	R0 = R0 +|+ R4 (S) || R4 = [P3+4];
				 	R1 = ABS R0 (V) || [P3++] = R0;
		         	R7 = MAX(R7,R1)(V) ;
			  	LOOP_END Calc_exc_rand2_3;			 	
			  	R7.L = VIT_MAX(R7)(ASR) || P5 = [FP-32];
			  	A1 = A0 = 0 || P2 = [FP-8];
			  	R7 = R7.L;
			  	CC = R7 == 0;			    			  	
				R5.L = SIGNBITS R7.L || R7 = W[P5](Z);							
				R5.H = 3;				
				R5.L = R5.H - R5.L(S) || R0 = [P2++];
				R6 = R4 -|- R4 || R3 = W[P5+2](Z);
				P3 = R7;
				R5 = MAX(R6,R5)(V) ||	R7 = W[P5+16](Z);
				IF !CC R6 = R5;                          
             	R6 = - R6(V) || [FP-24] = R6;      // sh               				 	
			 	
			 	LSETUP(Calc_exc_rand2_50,Calc_exc_rand2_51) LC0 = P0>>1;
			 	
Calc_exc_rand2_50: 	R1 = ASHIFT R0 BY R6.L(V,S) || R2 = [P2++];
				 	R4 = ASHIFT R2 BY R6.L(V,S) || R0 = [P2++];				 
				 	A0 += R1.L * R1.L, A1 += R1.H * R1.H || [I2++] = R1;
Calc_exc_rand2_51:	A0 += R4.L * R4.L, A1 += R4.H * R4.H || [I2++] = R4;
// 	R1 = ASHIFT R0 BY R6.L(V,S) || R2 = [P2++];				 			 				 	    			 					
				P2 = P4 + (P3 << 1);
				P3 = R3;
				R4 = ROT R7 BY -1 || R1 = [FP-4];
				R6.L = R6.L - R6.L (NS) || R4.L = W[P2];				
                R6 = R6 +|+ R4, R0 = R6 -|- R4(S) || R5 = W[P5+18](Z);  
				IF !CC R6 = R0;  								       
			 	R4 = ROT R5 BY -1 || R0 = W[P5+4](Z);
				P2 = P4 + (P3 << 1);
				P3 = R0;
				R5.H = 40;
			  	R2 = R5.H * R1.L ||	R4.L = W[P2];				
                R6 = R6 +|+ R4, R0 = R6 -|- R4(S) || R5 = W[P5+20](Z);  
				IF !CC R6 = R0;
				R4 = ROT R5 BY -1 || R0 = W[P5+6](Z);
				P2 = P4 + (P3 << 1);
				P3 = R0;				
			  	R2 = R2 >>> 6(S) ||	R4.L = W[P2];				
                R6 = R6 +|+ R4, R0 = R6 -|- R4(S) || R5 = W[P5+22](Z);  
				IF !CC R6=R0;  					
				R7 = ROT R5 BY -1 || R3 = [FP-24];
				R4.L = R3.L << 1(S);
				P2 = P4 + (P3 << 1);
				R2 = R1.L * R2.L || R7.L = W[P2];				
                R6 = R6 +|+ R7, R0 = R6 -|- R7(ASR,S) ;
				IF !CC R6=R0;  									
				R3.H = 1;								
			  	R4.L = R4.L + R3.H(S);                 	  
			  	R4 = - R4(V);
				R1 = (A0 += A1) ;
			  	R0 = ASHIFT R2 BY R4.L(S) || [FP-28] = R2;              //L_acc = L_shr(L_k, temp1)
			  	R3.L = R3.L + R3.H(S) || R7 = [P5];                  //sh = add(sh, 1);
			  	R0 = R0 - R1(S) || R2 = [P5+4];
			  	A0 = R0 || [FP-24] = R3;
			  	R0 = (A0 += R6.L * R6.L) || P5 = [FP-8];
			  	CC = R0 < 0;
			  	P1 = 4;	
			  	IF !CC JUMP Calc_exc_rand2_9;			  	
			  	I3 = SP;
			  	R5 = SP;
			    P0 = 20;
				R0 = R7.L * R3.H, R1 = R7.H * R3.H || R4 = [I3++];
				P2 = R0;
				P3 = R1;
                LSETUP(Calc_exc_rand2_8,Calc_exc_rand2_8) LC0 = P0;
Calc_exc_rand2_8: 		MNOP || [P5++] = R4 || R4 = [I3++];
				P2 = SP + P2;
				P3 = SP + P3;
				R0 = R2.L * R3.H, R1 = R2.H * R3.H || R7.L=W[P2] ;				 
				R0 = R0 + R5 (S) ;
				I2 = R0;
				R1 = R1 + R5 (S) || R7.H = W[P3];
				I3 = R1;
				I0.H = rri2i2;   // Temp BUFFER
				I0.L = rri2i2;				 
				R6.L = R6.L - R6.L (NS) || R2.L = W[I2];
				R5 = ABS R7(V) || [I0++] = R7 || R2.H = W[I3];				
				R1 = ABS R2(V);
				R7 = R5 | R1;
				R1 = R7 >> 16 ;
				R7 = R7 | R1;				 				 
				R7 = ROT R7 BY -15  || R5 = W[P3++](Z) || [I0--] = R2;
				R4 = CC;				
				R7.H =  24576;                  // K0              24576 
				R4 += 1;
				R2 = - R4(V) || R3.L = W[I0++];
				R4.L = R4.L  << 1(S);
				LOOP Calc_exc_rand2_8_1 LC0 = P1;
				LOOP_BEGIN Calc_exc_rand2_8_1;
				    R0.L = ASHIFT R3.L BY R2.L(S) ;  
					R1 = ROT R5 BY 17 || R5 = W[P3++] (Z);
					R6 = R6 +|+ R0, R1 = R6 -|- R0 (S) || R3.L = W[I0++];
					IF !CC R6=R1;
				LOOP_END Calc_exc_rand2_8_1;
				R5.L = R3.H - R4.L(S) || R0 = [FP-28];
				R0 = (A0 = R0.H * R7.H), R1 = (A1 = R0.L * R7.H) (m) || [FP-24] = R2;
				R2 = 0;
				R0 = (A0 -= R3.H * R1.H);   
				A0 = ASHIFT A0 BY R5.L;
				R0 = (A0+=R6.L * R6.L) || [FP-20] = R2;
Calc_exc_rand2_9:
                P0 = 14;
				R1.L = 0;       // Rez
				R4.H = 0X4000;  // Exp
				LOOP Calc_exc_rand2_10 LC0 = P0;        //temp2 = Sqrt(L_acc);
				LOOP_BEGIN Calc_exc_rand2_10;
				     R2.L = R4.H + R1.L(S);
				     R4.H = R4.H >>> 1(S);
					 R3 = R2.L * R2.L;
					 CC = R3 <= R0;
					 IF CC R1 = R2;
				LOOP_END Calc_exc_rand2_10;				                 
				R2 = R1 +|+ R6, R0 = R1 -|- R6 (S) || R7 = [FP-24]; 
				R2 = - R2(V);                            //x2 = negate(add(inter_exc, temp2));
				R3 = ABS R0(V);
				R4 = ABS R2(V);
				R7.H = 2;
				R5.H = R4.L - R3.L (S);
				CC = AN;
				IF CC R0 = R2;
				R7.L = R7.H - R7.L(S);
				R5 = 1;
				R3.L = R7.L - R5.L(S);
				R5.L = ASHIFT R5.L BY R3.L(S) || P4 = [FP-32];
				R7 = - R7(V) ;
				R0.L = R0.L + R5.L(S) || R4 = [FP-4];
				R0.L = ASHIFT R0.L BY R7.L(S) || P5 = [FP-8];  // P5 POINTS TO cur_exc
				R1 = 5000;				
				R0 = MIN(R0,R1)(V) || R3 = W[P4++](Z);
				P3 = R3;
				R2 = -5000;
				R0 = MAX(R0,R2)(V) || R2 = W[P4+14](Z);
				LOOP Calc_exc_rand2_11 LC0 = P1;
				LOOP_BEGIN Calc_exc_rand2_11;
					R7 = ROT R2 BY -1 || R3 = W[P4++](Z);	
					P2 = P5 + (P3 << 1);
					P3 = R3;
					R2.L = W[P2];
					R1 = R2 +|+ R0, R3 = R2 -|- R0 || R2 = W[P4+14](Z);
					IF !CC R1=R3;
                    W[P2] = R1.L;
				LOOP_END Calc_exc_rand2_11;
				R4 = ROT R4 BY 16 || R6 = [FP-16];
				IF !CC JUMP Calc_exc_rand2_12;
				R5 = R6 >> 16 ||R7 = [FP-20];
				P0 = R5;
				P5 = B0;
				CALL __update_exc_err;
Calc_exc_rand2_12:
				R0 = [FP-4];
				R7 = ROT R0 BY 15 || R1 = [FP-8];
				IF CC JUMP Calc_exc_randEND;
				BITSET(R0,17);
				R7 = 80;
				R1 = R1 + R7(S) || [FP-4] = R0;
				[FP-8] = R1;
				JUMP Calc_exc_rand2;
Calc_exc_randEND:
	  			UNLINK;
	  			RTS;	  			
.global __update_exc_err;			  			
__update_exc_err:
		P0 += -1;
		P4 = P0;
		P0 += -39;
		CC = P0 < 0;
		R3 = R7.L(X);
		R6 =  16384 (X);
		IF !CC JUMP  P5L1 ;		
		R3.H = R6.L >> 0 || R7 = [P5];
		R0 = R7 >>>  1;
		R4 = (A0=R7.H*R3.H),	A1=R7.H*R3.L ;		
		R0.L = R0.L - R4.L (NS) || R4 = [P5+8];
		R1 =   1;
		R7.H = R0.L*R3.L (T) || [P5+12] = R4;
		R2 =   -1;
		R7 = (A1+=R7.H*R1.L)(S2RND) || R4 = [P5+4];
		R7 = R6 + R7;
		R0 = R7 >>>  1 ;
		A1 = R0;
		R5 = (A1-=R7.H*R3.H);
		A0 = R7.H*R3.L || [P5+8] = R4;		
		R0.L = R5.L*R3.L (T) || R4 = [P5];				
		R7 = MAX (R2,R7) || [P5+4] = R4;
		R0 = (A0+=R0.L*R1.L)(S2RND);
		R0 = R6 + R0;
		R7 = MAX (R0,R7);
		[P5] = R7;
		RTS;
P5L1:
		P1.H = tab_zone;		
		P1.L = tab_zone;		
		P0 = P1 + (P0<<1);		
		R5 = W[P0] (X);
		P0 = R5 ;
		R7 =   -1;
		CC = R0 < R5;
		IF CC JUMP  P5L3 ;	
		P1 = P1 + (P4<<1);			
		R5 = R5 + R7 (NS) || R0 = W[P1] (X);
		P4 = P5 + (P0<<2);	
		R2 = R0 - R5 (S) || R4=[P4++];
		LC0= R2;					
		R1 =   1;
		R2 = R4.H*R6.L ;	
		R0 = R4 >>>  1;
		R4.L = R0.L - R2.L (NS);
		LSETUP(P5L6,P5L7) LC0;	   
P5L6:	R0.H = (A1 = R4.L*R3.L) , A0 = R4.H*R3.L || R4=[P4++];
		R2 = R4.H*R6.L ;	
		R0 = (A0+=R0.H*R1.L) (S2RND);
		R5 = R4 >>>  1;
		R0 = R6 + R0;
		R4.L = R5.L - R2.L (NS);	
P5L7:	R7 = MAX (R7,R0) ;			
//		JUMP P5L3;		
P5L3:
		R0 = [P5+8];
		[P5+12] = R0;
		R0 = [P5+4];
		[P5+8] = R0;
		R0 = [P5];
		[P5+4] = R0;
		[P5] = R7;
		RTS;		
   	     	  
