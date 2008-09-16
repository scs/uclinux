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
$RCSfile: Vad.asm,v $
$Revision: 1.4 $
$Date: 2006/05/24 07:46:55 $

Project:		G.729AB for Blackfin
Title:			Vad
Author(s):		wuxiangzhi,
Revised by:		E. HSU

Description     :      voice activity detection 

Prototype       :      	_vad()						
						_MakeDec()
						
******************************************************************************
Tab Setting:			4
Target Processor:		ADSP-21535
Target Tools Revision:	2.2.2.0
******************************************************************************

Modification History:
====================
$Log: Vad.asm,v $
Revision 1.4  2006/05/24 07:46:55  adamliyi
Fixed the failing case for g729ab decoder for tstseq6. The issue is the uClinux GAS bug: it cannot treat the (m) option correctly.

Revision 1.4  2004/01/27 23:41:57Z  ehsu
Revision 1.3  2004/01/23 00:41:02Z  ehsu
Revision 1.2  2004/01/13 01:34:56Z  ehsu
Revision 1.1  2003/12/01 00:13:31Z  ehsu
Initial revision

Version         Date            Authors        		  Comments
0.0         04/04/2001          wuxiangzhi            Original

*******************************************************************************/ 

#include "G729_const.h"

.extern MeanLSF;
.extern MeanSE;
.extern MeanSLE;
.extern MinValue;
.extern Min_buffer;
.extern Next_Min;
.extern Prev_Min;
.extern V_prev_energy;
.extern _Log2;
.extern count_ext;
.extern count_sil;
.extern count_update;
.extern factor_fx;
.extern lbf_corr;
.extern less_count;
.extern old_speech;
.extern pastVad_flag;
.extern shift_fx;

.text;
.align 8;

_vad:
      .global _vad;
//      .type  _vad,STT_FUNC;
	   LINK 8;
	   I2 = B2;
	   MNOP || R0 = [I2] || [FP-4] = R0;//  [FP-4] =  exp_R0 ;  
	   R0.L = R0.L << 1 || [FP-8] = R1; // frm_count
	   CALL _Log2;                      //Log2(acc0, &exp, &frac);	                 		
	   R6.H = 2;
	   R6.L = VAD_CONST1;               //9864;
       //** acc0 = Mpy_32_16(exp, frac, 9864);
	   R2 = ( A0 = R0.H * R6.L), R3 = (A1 = R0.L * R6.L) || R5 = [FP-4];
	   I0 = B2;
	   A0 += R3.H * R6.H(IS);
	   R5.L = R5.L - R6.H(S);
	   I1.H = lbf_corr;
	   I1.L = lbf_corr;
       R0 = (A0 += R6.L * R5.L);
	   R0 = R0 << 11(S);
	   R7.H = VAD_CONST2;              //4875;
	   P0 = 5;	   //** ENERGY = sub(ENERGY, 4875);
	   R7.H = R0.H - R7.H(S) || R5 = [I0++] || R4 = [I1++];
/****************************************************************       
acc0 = 0; for (i=1; i<=NP; i++) acc0 = L_mac(acc0, r_h[i], lbf_corr[i]);
****************************************************************/
	   R1 = (A1=R5.H * R4.L) || R5 = [I0++];
	   A0 = R5.H * R4.H || R4 = [I1++] || R5 = [I0++];
	   LOOP vad1 LC0 = P0;
	   LOOP_BEGIN vad1;
	       A0 += R5.H * R4.L || R5 = [I0++];
		   A0 += R5.H * R4.H || R4 = [I1++] || R5 = [I0++];
	   LOOP_END vad1;
	   R0 = (A0 += R5.H * R4.L) ;//acc0 = L_shl(acc0, 1);
		A0 = A0 << 1;
		R0 = (A0+=A1);
	   CALL _Log2;      //Log2(acc0, &exp, &frac);	   
	   //**acc0 = Mpy_32_16(exp, frac, 9864);
	   R6.H = 2;
	   R6.L = VAD_CONST1;     //9864
	   R2 = ( A0 = R0.H * R6.L), R3 = (A1 = R0.L * R6.L) || R5 = [FP-4];	   
	   R5.L = R5.L - R6.H(S); // i = sub(exp_R0, 1); // i = sub(i, 1);
	   A0 += R3.H * R6.H(IS);	   
       R0 = (A0 += R6.L * R5.L);//acc0 = L_mac(acc0, 9864, i);
	   R7.L = VAD_CONST2;       //4875;
	   R0 = R0 << 11(S);    
	   R5 = 129;	   //**ENERGY_low = sub(ENERGY_low, 4875);
	   R7.L = R0.H - R7.L(S) || R6 = [FP-8];	   
	   CC = R6 < R5;
	   R5 = 0;
	   R4 = 7;
	   IF CC R5 = R4;
	   R4 = R4 & R6;
	   CC = R4 == 0;
	   BITSET(R5,1);         //Bug find bit 1 of R5 must be set when frm_count& 7 ==0
	   R4 = R5;              //But it has cleared when frm_count > 129 and frm_count& 7 ==0
	   BITCLR(R4,1);         //added BITSET(R5,1);
//	   IF CC JUMP vad2;
//	    BITCLR(R5,1);
vad2:
		IF !CC R5=R4;
       //*** BIT 0 = 1 (R5) frm_count < 129
	   //*** BIT 1 = 1 (R5) frm_count & 7 == 0
	   I0.H = MinValue;
	   I0.L = MinValue;
	   I1.H = Prev_Min;
	   I1.L = Prev_Min;
	   I2.H = Next_Min;
	   I2.L = Next_Min;
       P5.H = Min_buffer;
	   P5.L = Min_buffer;
/*****************************************************	   
	   // Initialize and update Mins 
       if(sub(frm_count, 129) < 0){
          if (sub(ENERGY, Min) < 0){ Min = ENERGY; Prev_Min = ENERGY; }
          if((frm_count & 0x0007) == 0){
             i = sub(shr(frm_count,3),1);
             Min_buffer[i] = Min;  Min = MAX_16; }
       }
*****************************************************/	   
	   CC = BITTST(R5,0); //if(sub(frm_count, 129) < 0)
	   IF !CC JUMP vad4;
	       R4.L = W[I0];           // Min
		   R4.L = R7.H - R4.L(S);  //sub(ENERGY, Min)
		   CC = BITTST(R4,15);
		   IF !CC JUMP vad3;
		      W[I0] = R7.H;        //Min = ENERGY
			  W[I1] = R7.H;        //Prev_Min = ENERGY
vad3:	
           CC = BITTST(R5,1); // if((frm_count & 0x0007) == 0)
		   IF !CC JUMP vad4;
		      R4 = R6 >>> 3(S) || R3.L = W[I0];
			  P4 = R4;
			  NOP;
			  R3.H = 0X7FFF;
			  W[I0] = R3.H;
			  P4 += -1;
			  P4 = P5 + (P4 << 1);
			  W[P4] = R3.L;			  
/***************************************************			  
			  if((frm_count & 0x0007) == 0){ Prev_Min = Min_buffer[0];
                 for (i=1; i<16; i++){
                  if (sub(Min_buffer[i], Prev_Min) < 0) Prev_Min = Min_buffer[i];
                 }
              }
****************************************************/			  
vad4:       
          CC = BITTST(R5,1);    // if((frm_count & 0x0007) == 0)//Bug find logic error
		  IF !CC JUMP vad6;
		     I3 = P5;
		     
		     P0 = 15;
		     R4.L = W[I3++]; 
		     R3.L = W[I3++];
			 LSETUP(vad5,vad5) LC0 = P0;
			 vad5: R4 = MIN(R3,R4)(V) || R3.L = W[I3++];

/*				P0 = 7;
		     R3 = R4 -|- R4 || R4 = [I3++]; 		     
			 LSETUP(vad5,vad5) LC0 = P0;
			 vad5: R4 = MIN(R3,R4)(V) || R3 = [I3++];			 
			 R0.L = R4.H >> 0;
			 R4 = MIN(R0,R4)(V);
			 R4 = MIN(R3,R4)(V);
*/			 W[I1] = R4.L;
/********************************************************			 
			if(sub(frm_count, 129) >= 0){
              if(((frm_count & 0x0007) ^ (0x0001)) == 0){
                 Min = Prev_Min; Next_Min = MAX_16; }
              if (sub(ENERGY, Min) < 0)      Min = ENERGY;
              if (sub(ENERGY, Next_Min) < 0) Next_Min = ENERGY;    
              if((frm_count & 0x0007) == 0){
                 for (i=0; i<15; i++) Min_buffer[i] = Min_buffer[i+1]; 
                 Min_buffer[15] = Next_Min; 
                 Prev_Min = Min_buffer[0];
                 for (i=1; i<16; i++) 
                   if (sub(Min_buffer[i], Prev_Min) < 0) Prev_Min = Min_buffer[i];
              }    
             }
***********************************************************/			 
vad6:
           CC = BITTST(R5,0); // if(sub(frm_count, 129) >= 0)
		   IF CC JUMP vad8;		   
		   	R0 = 7;
			R1 = 1;
		   	R4 = R0 & R6;
		   	R4 = R1 ^ R4;
		   CC = R4 == 0;    // if(((frm_count & 0x0007) ^ (0x0001)) == 0)
		   IF !CC JUMP vad7_1;     //changed to !CC
   			  R4.H = MAX_16;       //0X7FFF;
		      MNOP || R4.L = W[I1] || W[I2] = R4.H;
			  W[I0] = R4.L;        //Min = Prev_Min
vad7_1:	
           	R4.H = W[I0];
		   	R3 = MIN(R7,R4)(V) || R4.H = W[I2];
		   	R3 = MIN(R7,R4)(V) || W[I0] = R3.H;
		   	W[I2] = R3.H;
		   	CC = BITTST(R5,1); // if((frm_count & 0x0007) == 0)
		   	IF !CC JUMP vad8;
		     I0 = P5;
			 I3 = P5;
			 P0 = 15;
			 I0 += 2 || R3.L = W[I2];
			 R5.L = R3.L >> 0 || R4.L = W[I0++] ;
			 LSETUP(vad7_2,vad7_2) LC0 = P0;
             vad7_2: R5 = MIN(R5,R4) || W[I3++] = R4.L ||  R4.L = W[I0++];
			 W[I3] = R3.L;          //Prev_Min = Min_buffer[0];					 
			 P0 = 15;              //Bug find, logic error
		     R4 =W[P5++](Z); 
		     R3 =W[P5++](Z);
			 LSETUP(vad7_3,vad7_3) LC0 = P0;
			 vad7_3: R3 = MIN(R3,R4)(V) || R4 = W[P5++](Z);
			 W[I1] = R3.L;	 
vad8:
             R4 = 32;
			 R5 = 0;
			 R3 = 1;
			 //if (sub(frm_count, INIT_FRAME) <= 0)
			 CC = R6 <= R4;  //bug find (modified to <= sign)
			 IF CC R5 = R3;
			 R3 = R5;
			 BITSET(R3,1);
			 CC = R6 == R4;
			 IF CC R5 = R3; //if (sub(frm_count, INIT_FRAME) == 0)
			 // BIT 0 = pastVad BIT 1 = ppastVad BIT 2 = flag BIT 3 =  v_flag
			 // BIT 4 = marker 
			 
			 I0.H = MeanLSF;
			 I0.L = MeanLSF;
			 I1 = B1;
			 P0 = 5;
			 A1 = A0 = 0 || R3 = [I1++] || R2 = [I0++];
			 R1 = R3 -|- R2(S) ;			  
			 LOOP vad9 LC0 = P0;
			 LOOP_BEGIN vad9;			   
			   A0 += R1.H * R1.H, A1 += R1.L * R1.L || R2 = [I0++] || R3 = [I1++];
			   R1 = R3 -|- R2(S) ;			   
		     LOOP_END vad9;
 			 P5.H = old_speech;
			 P5.L = old_speech;
			 P4 = 120;
			 I3.H = pastVad_flag;
			 I3.L = pastVad_flag;  // BIT 0 = pastVad BIT 1 = ppastVad BIT 2 = flag BIT 3 =  v_flag
			 P5 = P5 + (P4 << 1);
			 R4 = (A0 += A1) ||  R6.L = W[I3];
			 I0 = P5;
			 I1 = P5;
			 P0 = 80;
			 R4.L = 0;
			 I1 += 2;
			 R0 = 410;			
			 R3 = R3 -|- R3 || R2.H = W[I0++] || R2.L = W[I1++];
			 LOOP vad10 LC0 = P0;
			 LOOP_BEGIN vad10;
				 R1 = R2.H * R2.L || R2.L = W[I1++];
				 CC = BITTST(R1,31);
				 IF CC R3 = R0;
                 R4.L = R4.L + R3.L(S)|| R2.H = W[I0++];
                 R3 = R3 -|- R3;
			 LOOP_END vad10;
/*******************************************************			 
			 if (sub(frm_count, INIT_FRAME) <= 0)
                if(sub(ENERGY, 3072) < 0){
                   *marker = NOISE; less_count++;
                } else {
                 *marker = VOICE;
                  acc0 = L_deposit_h(MeanE);
                  acc0 = L_mac(acc0, ENERGY, 1024);
                  MeanE = extract_h(acc0);
                  acc0 = L_deposit_h(MeanSZC);
                  acc0 = L_mac(acc0, ZC, 1024);
                  MeanSZC = extract_h(acc0);
                  for (i=0; i<M; i++){
                    acc0 = L_deposit_h(MeanLSF[i]);
                    acc0 = L_mac(acc0, lsf[i], 1024);
                    MeanLSF[i] = extract_h(acc0);
                  }
              }
*********************************************************/			 
			 P5.H = less_count;
			 P5.L = less_count;
			 P4.H =  MeanSLE;
			 P4.L =  MeanSLE;
			 CC = BITTST(R5,0);
			 IF CC JUMP vad11;
			 CC = BITTST(R5,1);
			 IF !CC JUMP vad12;
vad11:
			 R3.L = 3072;
			 R3.L = R7.H - R3.L(S);
			 CC = BITTST(R3,15);
			 IF !CC JUMP vad11_1;
			   R3 = W[P5](Z);
			   BITCLR(R6,4);
			   R3 += 1;
			   W[P5] = R3.L;
			   JUMP vad12;
vad11_1:
              I0 = P4;
              BITSET(R6,4);
			  R3 = [I0++];
			  R2 = [I0--];
			  R6.H = 1024;
			  R3.L = 0;
			  R2.L = 0;
			  A1 = R3 || I0 += 2;
			  R3 = (A1 += R7.H * R6.H);
			  A0 = R2 || W[I0++] = R3.H;
			  R2 = (A0 += R4.L * R6.H) || I0 += 2;
			  W[I0] = R2.H;
			  R2.L = 0;
			  I0.H = MeanLSF;
			  I0.L = MeanLSF;
			  I1 = B1;     // I1 POINTS TO MeanLSF
			  I2 = I0;
			  P0 = 10;
			  R2.H = W[I0++];
			  LOOP vad11_2 LC0 = P0 >> 1;
			  LOOP_BEGIN vad11_2;
			     A0 = R2 || R2.H = W[I0++];
				 A1 = R2 || R3 = [I1++];
				 R0.L = (A0 += R3.L * R6.H), R0.H = (A1 += R3.H * R6.H) (T) || R2.H = W[I0++];
//				 R0 = PACK(R1.H, R0.H);
				 [I2++] = R0;
			  LOOP_END vad11_2;
/**********************************************************			  
		if (sub(frm_count, INIT_FRAME) >= 0){
    		if (sub(frm_count, INIT_FRAME) == 0){
      		 acc0 = L_mult(MeanE, factor_fx[less_count]);
      		 acc0 = L_shl(acc0, shift_fx[less_count]);
     		 MeanE = extract_h(acc0);

     		 acc0 = L_mult(MeanSZC, factor_fx[less_count]);
     		 acc0 = L_shl(acc0, shift_fx[less_count]);
     		 MeanSZC = extract_h(acc0);
	
     		 for (i=0; i<M; i++){
     		   acc0 = L_mult(MeanLSF[i], factor_fx[less_count]);
     		   acc0 = L_shl(acc0, shift_fx[less_count]);
     		   MeanLSF[i] = extract_h(acc0);
    		  }

    		  MeanSE = sub(MeanE, 2048);   // Q11 
    		  MeanSLE = sub(MeanE, 2458);  // Q11 
   		 	}
************************************************************/			  
vad12:
/*
.extern _memdump;	 
.extern _Count_Frame; 
		[--SP] = (R7:0,P5:0);			
		P2.H	= _memdump;
		P2.L	= _memdump;											
		P3.H = MeanSE;
		P3.L = MeanSE;		
		P1.H = MeanSLE;
		P1.L = MeanSLE;		
		P0.H = MeanSZC;
		P0.L = MeanSZC;				
		P4 = 2;	
		R5 = [FP-8];
		W[P2++]=R5;		
	  	R5=W[P3];  	
	  	W[P2++]=R5;	
	  	R5=W[P1];  	
	  	W[P2++]=R5;	
	  	R5=W[P0];  	
	  	W[P2++]=R5;	  		  				  		  	  		  	
	  	P0 = B0;		
		R3 = W[P0](X);
	  	W[P2++P4]=R3.L;		  		
	  	W[P2++P4]=R4.H;
	  	P3.H = count_update;
		P3.L = count_update;
		R3=W[P3];  	
	  	W[P2++P4]=R3.L;	
	  	P0.H = MinValue;
	    P0.L = MinValue;
	    R3=W[P0];  	
	  	W[P2++P4]=R3.L;
	  	P1.H = Prev_Min;
	   P1.L = Prev_Min;
	   R3=W[P1];  	
	  	W[P2++P4]=R3.L;
	   P3.H = Next_Min;
	   P3.L = Next_Min;
	  	R3=W[P3];  	
	  	W[P2++P4]=R3.L;
	  	W[P2++P4]=R7.H;	  							  	
		(R7:0,P5:0) = [SP++];  
*/
             CC = BITTST(R5,0);
			 IF !CC JUMP vad13;
			 CC = BITTST(R5,1);
	
/* DR original:		IF !CC JUMP vadEND; */
			IF CC JUMP vad_END_ ;
			JUMP vadEND ;
vad_END_:
	
vad13:
             CC = BITTST(R5,1);
			 IF !CC JUMP vad16;
			 R5 = W[P5](Z);
			 I0 = P4;
			 P3 = R5;
			 R3 = [I0++];
			 R2 = [I0--];
			 R3 = PACK(R3.H, R2.H) || I0 += 2;
			 P2.H = factor_fx;
			 P2.L = factor_fx;
			 P1.H = shift_fx;
			 P1.L = shift_fx;
			 P2 = P2 + (P3 << 1);
			 P1 = P1 + (P3 << 1);
			 R2.H = W[P2];
			 R0 = R3.H * R2.H, R1 = R3.L * R2.H || R2.L = W[P1];
			 I1.H = MeanLSF;
			 I1.L = MeanLSF;
			 P0 = 5;
			 I2 = I1;			 
			 R0 = ASHIFT R0 BY R2.L(S) || R3 = [I1++];
			 R1 = ASHIFT R1 BY R2.L(S) || W[I0++] = R0.H;
			 I0 += 2;
			 R0 = R3.H * R2.H, R1 = R3.L * R2.H || W[I0] = R1.H;			 			 
			 LOOP vad14 LC0 = P0;
			 LOOP_BEGIN vad14;			    				
			    R1 = ASHIFT R1 BY R2.L(S) || R3 = [I1++];  	
			    R0 = ASHIFT R0 BY R2.L(S) || W[I2++] = R1.H;
				R0 = R3.H * R2.H, R1 = R3.L * R2.H || W[I2++] = R0.H;
			 LOOP_END vad14;
  			 I0 = P4;
			 R3 = [I0++];
			 R0 = R3 >>> 16 || R2 = [I0]; //changed to arithmetic shift
			 R1.H = 2048;
			 R1.L = 2458;
			 R2.L = R3.H - R1.H(S);
			 R3.L = R3.H - R1.L(S) || [I0--] = R2;
			 [I0] = R3;
vad16:
             I0 = P4;        
			 R3 = [I0++];
			 R2 = [I0];
             R1 = R4;
			 R3 = PACK(R2.L, R3.L);
             R0 = R3 -|- R7(S);  
			 R1.L = R2.H - R4.L(S);
			 R2 = R7 >>> 16;        // bug find, changed to arithmetic shifting
			 R5 = 3072;
			 CC = R2 < R5;
//			 IF !CC JUMP vad17;
			   BITCLR(R6,4);
			 IF CC  JUMP vad18;
vad17:				
              CALL _MakeDec;
              
vad18:

              BITCLR(R6,3);
			  CC = BITTST(R6,0);
			  IF !CC JUMP vad19;
			  CC = BITTST(R6,4);
			  IF CC JUMP vad19;
			  R2 = R0 >>> 16(S);
			  R3 = -410;
			  CC = R2 < R3;
			  IF !CC JUMP vad19;
			  R2 = R7 >>> 16(S);
			  R3 = 3072;
			  CC = R3 < R2;
			  IF !CC JUMP vad19;
			  BITSET(R6,4);
			  BITSET(R6,3);
vad19:
           // BIT 0 = pastVad BIT 1 = ppastVad BIT 2 = flag BIT 3 =  v_flag
              CC = BITTST(R6,2);
              BITSET(R6,2);
			  IF !CC JUMP vad22;//vad21;
			  CC = BITTST(R6,0);
			  IF !CC JUMP vad22;
			  CC = BITTST(R6,1);
			  IF !CC JUMP vad22;
			  CC = BITTST(R6,4);
			  IF CC JUMP vad22;
			  I0.H = V_prev_energy;
			  I0.L = V_prev_energy;
			  R2.L = W[I0];
			  R3 = 614;
			  R2.L = R2.L - R7.H(S);
			  R2 = ABS R2(V);
			  R2 = R2.L;
			  CC = R2 <= R3; 
  		          IF !CC JUMP vad22;
			  P3.H = count_ext;
			  P3.L = count_ext;
			  R2 = W[P3](Z);
			  R2 += 1;
			  BITSET(R6,4);
			  BITSET(R6,3);
			  R3 = 4;
			  CC = R2 <= R3;
			  BITSET(R6,2);
			  R3 = 0;
			  IF !CC R2 = R3;
			  R3 = R6;
			  BITCLR(R3,2);
			  IF !CC R6 = R3;
//vad20:			  
              W[P3] = R2.L;
vad22:
             P3.H = count_sil;
			 P3.L = count_sil;
			 R5 = W[P3](Z);
			 R2 = W[P3](Z);
			 R2 += 1;
			 CC = BITTST(R6,4);
			 IF !CC R5 = R2;
vad23:
             CC = BITTST(R6,4);
			 IF !CC JUMP vad24;
			 R2 = 10;
			 CC = R2 < R5;
			 IF !CC JUMP vad24;
			 I0.H = V_prev_energy;
			 I0.L = V_prev_energy;
			 R2.L = W[I0];
			 R3 = 614;
			 R2.L = R7.H - R2.L(S);
			 R2 = R2.L(X);
			 CC = R2 <= R3;
//			 IF !CC JUMP vad24;
			 R2=R6;
			 BITCLR(R2,4);
			 IF CC R6=R2;
			 R2=0;
			 IF CC R5 = R2;
//			 R5 = 0;
vad24:
             R2 = 0;
			 CC = BITTST(R6,4);
			 IF CC R5 = R2;
			 W[P3] = R5.L;
			 			 
			 R2.L = 614;
			 P3.H = MeanSE;
			 P3.L = MeanSE;
			 R2.L = R7.H - R2.L(S) || R3 = W[P3](X);
			 R5 = [FP-8];
			 R2 = R2.L(X);
			 CC = R2 < R3;
			 IF !CC JUMP vad25;
			 R3 = 128;
			 CC = R3 < R5;
			 IF !CC JUMP vad25;
			 CC = BITTST(R6,3);
			 IF CC JUMP vad25;
			 P0 = B0;
			 R2 = 19661;
			 R5 = ROT R6 BY 0 || R3 = W[P0](X);
			 CC = R3 < R2;
			 BITCLR(R5,4);
			 IF CC R6 = R5;
//			 IF !CC JUMP vad25;
//			 BITCLR(R6,4);
vad25:		

             P0 = B0;
             R2 = 24576;
			 R3 = W[P0](X);
			 CC = R3 < R2;
			 IF !CC JUMP vad27;
			 P3.H = MeanSE;
			 P3.L = MeanSE;
			 R2.L = 614;
			 R2.L = R7.H - R2.L(S) || R3 = W[P3](X);
			 R2 = R2.L(X);
			 CC = R2 < R3;
			 IF !CC JUMP vad27;
			 R2 = R4 >>> 16;   //changed to arithmetic shift
			 R3 = 83;
			 CC = R2 < R3;
			 IF !CC JUMP vad27;			 			 
			 P3.H = count_update;
			 P3.L = count_update;						 
			 			 
			 R6.H = 0;
			 R1 = R6;
			 R5 = W[P3](Z);
			 R5 += 1;
			 R1.H = 1;
			 R0 = 20;
			 W[P3] = R5.L;
			 CC = R5 < R0;
			 IF CC R6 = R1;
			 IF CC JUMP vad26_1;
			 R1.H = 2;
			 R0 = 30;
			 CC = R5 < R0;
			 IF CC R6 = R1;
			 IF CC JUMP vad26_1;
			 R1.H = 4;
			 R0 = 40;
			 CC = R5 < R0;
			 IF CC R6 = R1;
			 IF CC JUMP vad26_1;
			 R1.H = 8;
			 R0 = 50;
			 CC = R5 < R0;
			 IF CC R6 = R1;
			 IF CC JUMP vad26_1;
			 R1.H = 16;
			 R0 = 60;
			 CC = R5 < R0;
			 IF CC R6 = R1;
vad26_1:
            CC = BITTST(R6,16);
			IF !CC JUMP vad26_2;
			    R1.H = 24576;
       			R1.L = 8192;
        		R2.H = 26214;
        		R2.L = 6554;
        		R3.H = 19661;
       			R3.L = 13017;
			IF CC JUMP vad26_3;
vad26_2:
               CC = BITTST(R6,17);
			   IF !CC JUMP vad26_2_1;
			       R1.H = 31130;
                   R1.L = 1638;
                   R2.H = 30147;
                   R2.L = 2621;
                   R3.H = 21299;
                   R3.L = 11469;
                   JUMP vad26_3;
vad26_2_1:
              CC = BITTST(R6,18);
			  IF !CC JUMP vad26_2_2;
              R1.H = 31785;
              R1.L = 983;
              R2.H = 30802;
              R2.L = 1966;
              R3.H = 22938;
              R3.L = 9830;
              JUMP vad26_3;
vad26_2_2:
              CC = BITTST(R6,19);
              R3.H = 24576;
              R3.L = 8192;
              R1.H = 32604;
              R1.L = 164;
              R0.H = 32440;
              R0.L = 328;
              IF CC R1 = R0;
              R0.H = 31457;
              R0.L = 1311;
              IF CC R2 = R0;          //			  IF !CC JUMP vad26_2_3;                            
			  IF CC JUMP vad26_3;
vad26_2_3:
              CC = BITTST(R6,20);                            
              R0.H = 32440;
              R0.L = 328;
              R2.H = 32702;
              R2.L = 66;
              IF CC R2 = R0;
vad26_3:
             I0.H = MeanSE;
			 I0.L = MeanSE;
			 I1.H = MeanSLE;
			 I1.L = MeanSLE;
			 R5.L = W[I0];
			 A0 = R1.H * R5.L || R5.L = W[I1];
			 R0 = (A0 += R1.L * R7.H);
			 A0 = R1.H * R5.L || W[I0++] = R0.H;
			 R0 = (A0 += R1.L * R7.L) || R5.L = W[I0];
			 A0 = R2.H * R5.L || W[I1] = R0.H;
			 R0 = (A0 += R2.L * R4.L);
			 W[I0] = R0.H;
			 P0 = 5;
			 I0.H = MeanLSF;
			 I0.L = MeanLSF;
			 I1 = B1;
			 I2 = I0;
			 R5 = [I0++];
			 LOOP vad26_3_1 LC0 = P0;
			 LOOP_BEGIN vad26_3_1;
			    A0 = R5.L * R3.H, A1 = R5.H * R3.H || R5 = [I1++];
				R0.L = (A0 += R5.L * R3.L), R0.H = (A1 += R5.H * R3.L) (T) || R5 = [I0++];
//				R0 = PACK(R1.H, R0.H);
				[I2++] = R0;
			 LOOP_END vad26_3_1;
/*********************************************************************			 
    	 if((sub(frm_count, 128) > 0) && (((sub(MeanSE,Min) < 0) &&
                   (sub(SD, 83) < 0)) || (sub(MeanSE,Min) > 2048))){
           MeanSE = Min; count_update = 0; }
**********************************************************************/    
vad27:		
             R0 = [FP-8];    //frm_count
			 R1 = 128;
			 CC = R0 <= R1;
			 IF CC JUMP vadEND;
			 I0.H = MeanSE;
			 I0.L = MeanSE;
			 I1.H = MinValue;
			 I1.L = MinValue;
			 MNOP || R2.H = W[I0] || R2.L = W[I1];
			 R3.L = R2.H - R2.L(S);
			 R3 = R3.L(X);
			 R5=2048;
			 CC = R5 < R3;
			 IF CC JUMP setcount_update;			 
			 CC = BITTST(R3,15);
			 IF !CC JUMP vadEND;
			 R4 = R4 >>> 16;   //R2 = R4>>16;changed to arithmetic shift
			                   // Reg changed to R4
			                   // Since R2 holds the Min value 
			                   // that has to assign to MeanSE
			                   // Previously it is over written.
			 R3 = 83;
			 CC = R4 < R3;
			 IF !CC JUMP vadEND;
setcount_update:			 
			 R3 = 0;
			 I2.H = count_update;
			 I2.L = count_update;
			 W[I0] = R2.L;
			 W[I2] = R3.L;
vadEND:
	   I3.H = pastVad_flag;
	   I3.L = pastVad_flag;  // BIT 0 = pastVad BIT 1 = ppastVad BIT 2 = flag BIT 3 =  v_flag
       I0.H = V_prev_energy;
	   I0.L = V_prev_energy;
       W[I3] = R6.L;
	   W[I0] = R7.H;
	   UNLINK;
	   RTS;

_MakeDec:
	   .global _MakeDec;
      .type  _MakeDec,STT_FUNC;
	  //*** R0.H = dSE
	  //*** R0.L = dSLE
	  //*** R1.H = SD
	  //*** R1.L = dSZC
	  [--SP]=R7;
	  [--SP]=R4;
		R7 = R6;
		BITSET(R7,4);
	  R2.H = -14680;	  	  
	  R2.L = 19065;
	  A1 = R1.L * R2.L, A0 = R1.L * R2.H;
	  R4.L = 8192;
	  R5 = 0;
	  R3.H = -28521;
	  R3.L = -19446;	  
	  R3 = (A1 += R4.L * R3.L),  R2 = (A0 += R4.L * R3.H);
	  R5 = PACK(R1.H,R5.L);
	  R2 = R2 >>> 8(S);
	  R2 = R2 + R5(S);
	  CC = R2 <= 0;
		IF !CC R6=R7;
		IF !CC JUMP MakeDecEND ;
	  R3 = R3 >>> 7(S);	  
	  R3 = R3 + R5(S);
	  CC = R3 <= 0;
		IF !CC R6=R7;
		IF !CC JUMP MakeDecEND ;
	  R3.L = 20480;
	  R3.H = -16384;	  
	  A1 = R1.L * R3.H, A0 = R1.L * R3.L;	  
	  R3.L = 19660;
	  R3 = (A1 += R4.L * R3.L),  R2 = (A0 -= R4.L * R3.H);
	  R5 = PACK(R0.H, R5.L);
	  R2 = R2 >>> 2(S);
	  R2 = R2 + R5(S);
	  CC = R2 < 0;
		 IF CC R6=R7;
		IF CC JUMP MakeDecEND;	  	  	 
	  R3 = R3 >>> 2(S);
	  R3 = R3 + R5(S);
	  CC = R3 < 0;
		IF CC R6=R7;
		IF CC JUMP MakeDecEND;
	  R4.H = 32767;	  	  
	  R4.L = 512;
	  A1 = R0.H * R4.L,  A0 = R0.H * R4.H;
	  R3.H = 30802;
	  R2.L = 1024;	  
	  R2.H = 64;
	  R3.L = 19988;
	  A1 += R2.H * R3.L, R2 = (A0 += R2.L * R3.H);
	  CC = R2 < 0;
		IF CC R6=R7;
		IF CC JUMP MakeDecEND;		
	  R4.L = -28160;	  	  	  	  
	  R3 = (A1 += R1.H * R4.L), A0 = R1.H * R4.H;
	  CC = R3 < 0;
		IF CC R6=R7;
		IF CC JUMP MakeDecEND;
	  R2.L = 32;
	  R3.H = -30199;	  
	  R2.H = 8192;
	  R3.L = 22938;
	  A1 = R2.H * R3.L, R2 = (A0 += R2.L * R3.H);
	  R4.H = -20480;
	  R4.L = 23831;
	  A0 = R1.L * R4.L,  R3 = (A1 += R1.L * R4.H);
	  CC = R2 <= 0;
		 IF !CC R6=R7;
		IF !CC JUMP MakeDecEND;
	  R3 = R3 >>> 2(S);
	  R3 = R3 + R5(S);
	  CC = R3 < 0;
		 IF CC R6=R7;
		IF CC JUMP MakeDecEND;	  	  
	  R2.L = 4096;
	  R3.H = 31576;	  
	  R2.H = 2048;
	  R3.L = 17367;
	  A1 = R2.H * R3.L,  R2 = (A0 += R2.L * R3.H);
	  R3.H = 32767;
	  R3.L = 24576;
	  A0 = R0.H * R3.L,  R3 = (A1 += R0.H * R3.H);		
	  R2 = R2 >>> 2(S);
	  R2 = R2 + R5(S);
	  CC = R2 < 0;
		 IF CC R6=R7;
		IF CC JUMP MakeDecEND;	  	  	  	  
	  CC = R3 < 0;
		 IF CC R6=R7;
		IF CC JUMP MakeDecEND;
		R2.L = 1024;
	  	R3.H = 29491;	  	  
	  	R3.L = 32;
	  	R2.H = 25395;
	  	A1   = R2.H * R3.L,	A0 += R2.L * R3.H;				  	
	  	R3.L = 16384;
	  	R3.H = 256;	  
	    A1  += R0.L * R3.H,	R2 = (A0 += R0.L * R3.L);	  
	  	CC = R2 < 0;
		IF CC R6=R7;
		IF CC JUMP MakeDecEND;				
	  	R5 = R0 << 16;	    
	  	R2.H = -22400;	  
	  	R3 = (A1 += R1.H * R2.H);	  	  
	  	CC = R3 < 0;
		IF CC R6=R7;
		IF CC JUMP MakeDecEND;						
		R2.H = 256;
	  	R3.L = -29959;
	  	R2.L = 512;
	  	R3.H = 28087;	  
	  	A1 = R2.L * R3.H,	A0 = R2.H * R3.L; 
		R2.H = -30427;	  
		R2.L = -23406;
	  	R3 = (A1 += R0.H * R2.L), R2 = (A0 += R0.H * R2.H);
	  	R2 = R2 + R5(S);
	  	CC = R2 <= 0;
		IF !CC R6=R7;
		IF !CC JUMP MakeDecEND;			  	  	  	  
	  	R3 = R3 + R5(S);
	  	CC = R3 < 0;
		IF CC R6=R7;
//		IF CC JUMP MakeDecEND;
		BITCLR(R7,4);  
		IF !CC R6=R7;
//        BITCLR(R6,4);      
MakeDecEND: R4=[SP++]; R7=[SP++];
	   RTS;

