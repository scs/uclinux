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
// *** Author: Xiangzhi,wu   xiangzhi.wu@analog.com    2003/03/24	       ***
// *** The programe is based on G729b.
// *** These functions are used if the vad is enable
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
$RCSfile: dtx.asm,v $
$Revision: 1.4 $
$Date: 2006/05/24 07:46:55 $

Project:		G.729AB for Blackfin
Title:			DTX
Author(s):		wuxiangzhi,
Revised by:		E. HSU

Description     :      DTX and Comfort Noise Generator

Prototype       :      	_Cod_cng()						
						_Calc_RCoeff()
						_lsfq_noise()
						_Qnt_e()
						_Calc_sum_acf()
						_Update_sumAcf()
						_Calc_pastfilt()
						_Cmp_filt()
						_Update_cng()

******************************************************************************
Tab Setting:			4
Target Processor:		ADSP-21535
Target Tools Revision:	2.2.2.0
******************************************************************************

Modification History:
====================
$Log: dtx.asm,v $
Revision 1.4  2006/05/24 07:46:55  adamliyi
Fixed the failing case for g729ab decoder for tstseq6. The issue is the uClinux GAS bug: it cannot treat the (m) option correctly.

Revision 1.4  2004/01/27 23:40:55Z  ehsu
Revision 1.3  2004/01/23 00:40:08Z  ehsu
Revision 1.2  2004/01/13 01:34:01Z  ehsu
Revision 1.1  2003/12/01 00:12:33Z  ehsu
Initial revision

Version         Date            Authors        		  Comments
0.0         03/24/2003          wuxiangzhi            Original

*******************************************************************************/ 
.extern  Acf; 
.extern  Acf_1;
.extern  Dtx_cur_gain; 
.extern  Dtx_sid_gain; 
.extern  L_exc_err; 
.extern  PtrTab_1; 
.extern  PtrTab_2_0; 
.extern  PtrTab_2_1; 
.extern  RCoeff; 
.extern  _Az_lsp; 
.extern  _Calc_exc_rand;
.extern  _Get_wegt; 
.extern  _Int_qlpc; 
.extern  _Levinson; 
.extern  _Lsf_lsp2; 
.extern  _Lsp_expand_1_2; 
.extern  _Lsp_lsf2; 
.extern  _Lsp_prev_compose; 
.extern  _Lsp_prev_extract; 
.extern  _Lsp_stability; 
//.extern  _Qua_Sidgain; 
.extern _Log2;
.extern  count_fr0; 
.extern  ener; 
.extern  exc; 
.extern  flag_chang; 
.extern  fr_cur;
.extern  freq_prev; 
.extern  lspSid_q; 
.extern  lsp_old_q; 
.extern  lspcb1; 
.extern  lspcb2; 
.extern  nb_ener; 
.extern  noise_fg; 
.extern  noise_fg_1; 
.extern  noise_fg_sum; 
.extern  noise_fg_sum_1; 
.extern  noise_fg_sum_inv; 
.extern  noise_fg_sum_inv_1; 
.extern  pastCoeff; 
.extern  pastVad_flag; 
.extern  prev_energy; 
.extern  rri0i0;
.extern  seed; 
.extern  sh_Acf; 
.extern  sh_RCoeff; 
.extern  sh_ener; 
.extern  sh_sumAcf; 
.extern  sumAcf; 
.extern  sumAcf_1; 
.extern  sumAcf_2; 
.extern  tab_Sidgain; 
.extern  wxzr; 

.text;
.align 8;
_Qua_Sidgain:
//      .global _Qua_Sidgain;
//      .type  _Qua_Sidgain,STT_FUNC;
	  LINK 4;
	  // P5 POINTS TO ener
	  // I0 POINTS TO sh_ener
	  // R1 = nb_ener
       R6.L = W[I0++];
	   R6.H = 1;
//	   if(nb_ener == 0) { L_acc = L_deposit_l(*ener);
//           L_acc = L_shl(L_acc, *sh_ener); 
//           L_Extract(L_acc, &hi, &lo);
//           L_x = Mpy_32_16(hi, lo, fact[0]); sh1 = 0; }  
//	  CC = R1 == 0;
	  R0 = W[P5](X);
	  R3 = ASHIFT R0 BY R6.L(S);
/*	  
	  IF !CC JUMP Qua_Sidgain1;
	     
		 
		 R3.L = R3.L >> 1;
		 R1.L = 410;
//		 NOP;
		 R2 = (A0 = R3.H * R1.L), R3 = ( A1 = R3.L * R1.L);
		 R7.L = 0;
		 R0 = (A0 += R6.H * R3.H);
		 
		 JUMP Qua_Sidgain3;
Qua_Sidgain1:
*/
       CC = R1 == 1;
//	   IF !CC JUMP Qua_Sidgain2;
	      R5.L = 16;
          R7.L = R6.L + R5.L(S);// || R0.H = W[P5];
		  R1.L = 26;   // fact[1]
		  R0 = R0.L * R1.L;
       IF CC JUMP Qua_Sidgain3;    
Qua_Sidgain2:
        R1   = R5-|-R5 || R5.L = W[I0--];
		R5.H = 15;
		P0   = 2;
	    R4   = MIN(R6,R5)(V);
		R7.L = R4.L + R5.H(S) || R6.L = W[I0++];
		LOOP Qua_Sidgain2_1 LC0 = P0;
		LOOP_BEGIN Qua_Sidgain2_1;
		   R5.L = R7.L - R6.L(S) || R0 = W[P5++](X);
		   R0   = ASHIFT R0 BY R5.L(S) || R6.L = W[I0++];
		   R1   = R1 + R0(S);
		LOOP_END Qua_Sidgain2_1;
		   R7.H = 13;
		   R2 = (A0 = R1.H * R7.H), R3 = (A1 = R1.L * R7.H) (m);
		   NOP;
		   R0 = (A0 += R3.H * R6.H);	   
Qua_Sidgain3:
					
           	CALL _Log2;                             
		   	R1.L = R0.H - R7.L(S);
		   	R5 = 1024;
		   	R1.L = R1.L << 10(S);
		   	R2 = R5.L * R0.L;
		   	R2.L = R2 (RND);
		   	R2.L = R2.L + R1.L(S);   
		   	R3 = -2721;
		   	R2  = R2.L(X);
		   	CC = R2 <= R3;
			R4.L = -12;
			R4.H = 0;
			IF CC R0 = R4;
            IF CC JUMP Qua_SidgainEND;
			R3 = 22111;
			CC = R3 < R2;
			R4.L = 66;
			R4.H = 31;
			IF CC R0 = R4;
            IF CC JUMP Qua_SidgainEND;
            R3 = 4762;
			CC = R2 <= R3;
			IF !CC JUMP Qua_Sidgain6;
			R2.H = 3401;
			R3.L = 24;			   
			R2.L = R2.H + R2.L(S);
			R3.H = 1;
			R0 = R2.L * R3.L;
			R0 = MAX(R0,R3)(V);
			R0.L = 8;
			R2.L = R0.H << 2(S);
			R0.L = R2.L - R0.L(S);
			JUMP Qua_SidgainEND;
Qua_Sidgain6:
            R2.H = 340;
			R3.L = 193;
			R2.L = R2.L - R2.H(S);
			R3.H = 6;
			R0 = R2.L * R3.L;
			R4.L = 1;
			R0.H = R0.H >>> 2(S);
			R0.H = R0.H - R4.L(S);
			R4.H = 4;
			R0 = MAX(R0,R3)(V);
			R0.L = R0.H << 1(S);
			R0.L = R0.L + R4.H(S);
Qua_SidgainEND:
      UNLINK;
	  RTS;
.text;
.align 8;	  
_Cod_cng:
	   	.global _Cod_cng;
      	.type  _Cod_cng,STT_FUNC;
	  	LINK 84;
	  	[FP-12]=R1;	  	
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+376]; // ener
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+288]; // sh_ener
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
	  	B3 = I1;
	  	MNOP || R7 = [I0] || [FP-4] = R0;
	  	R7 = PACK(R7.L, R7.L) || R6 = [I1] || [FP-16]=R2;
	  	R6 = PACK(R6.L, R6.L) || [I0] = R7;
	  	[I1] = R6;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+356]; // Acf
	B0 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+284]; // sh_Acf
	B1 = R0
	P3 = [SP++];
	R0 = [SP++];
	  	P0 = 24;
	  	P0 = SP+P0;
	  	B2 = P0;
	  	P0 = 2;
	  	CALL _Calc_sum_acf;
	  	P5 = B2;
	  	R0 = W[P5](Z);
	  	CC = R0 == 0;
	  	IF CC JUMP Cod_cng2;	  	
		R7.L = R7.L - R7.L (NS) || R6 = [FP-16];
		I0 = R6;
		B0 = R6;
		I1 = B2;
	  	R7.H = W[I1++];
	  	P0 = 11;
	  	LSETUP(Cod_cng1, Cod_cng1) LC0 = P0;
      Cod_cng1: MNOP || [I0++] = R7 || R7.H = W[I1++];
		P1 = 48;
		P1 = SP+P1;
		B2 = P1;
	  	B1 = SP;
	  	CALL _Levinson;
Cod_cng2:
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+376]; // ener
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+268]; // pastVad_flag
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
	  MNOP || W[I0] = R0.L || R7.L = W[I1];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+392]; // nb_ener
	I2 = R0
	P3 = [SP++];
	R0 = [SP++];
	  R1 = 1;
	  R0 = 2;
	  CC = BITTST(R7,0);
	  IF !CC JUMP Cod_cng3;
	      MNOP || W[I2] = R1.L || P0 = [FP-4];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+408]; // count_fr0
	I3 = R0
	P3 = [SP++];
	R0 = [SP++];
		  W[I3] = R0.H;
		  W[P0] = R0.L;
		  JUMP  Cod_cng4;
Cod_cng3:
          R2.H = W[I2];
		  R1.L = R2.H + R1.L(S);
		  R1 = MIN(R1,R0)(V);
		  W[I2] = R1.L;
		  R1 = R1.L;
Cod_cng4:
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+376]; // ener
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+288]; // sh_ener
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
		  CALL _Qua_Sidgain;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+268]; // pastVad_flag
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
		  MNOP || R7.L = W[I1] || [FP-8] = R0;

		  CC = BITTST(R7,0);
		  IF CC JUMP Cod_cng6;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+380]; // sh_RCoeff
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+376]; // ener
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+352]; // RCoeff
	B0 = R0
	P3 = [SP++];
	R0 = [SP++];
		  P5=24;
		P5=SP+P5;
		B1=P5;
//    	  B1.H = rh_nbe;   // curAcf
//	      B1.L = rh_nbe;
		  MNOP || R7.H = W[I0] || R6.H = W[I1];
		  R5.H = 4855;
		  CALL _Cmp_filt;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+400]; // flag_chang
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+280]; // prev_energy
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
		  R7 = W[P5](Z);
		  CC = R0 == 0;
		  IF CC JUMP Cod_cng5_1;
		     R7 = 1;
Cod_cng5_1:
          MNOP || R6.L = W[I0] || R5 = [FP-8];
		  R6.L = R6.L - R5.L(S) || P0 = [FP-4];   // P0 POINTS TO ana
		  R6 = ABS R6(V);
		  R6 = R6.L;
		  CC = R6 <= 2;
		  R5 = 1;
		  IF !CC R7 = R5;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+408]; // count_fr0
	P4 = R0
	P3 = [SP++];
	R0 = [SP++];
		  R6 = W[P4](Z);
		  R6 += 1;
		  CC = R6 < 3;
		  R0 = 0;
		  IF CC JUMP Cod_cng5_2;
		  R1 = 2;
		  CC = R7 == 0;
		  IF !CC R0 = R1;
Cod_cng5_2:
          R3 = 3;
          R3 = MIN(R3,R6)(V) || W[P0] = R0.L;
		  W[P5] = R7.L;
		  W[P4] = R3.L;
Cod_cng6:
          P0 = [FP-4];
          NOP;
          NOP;
          NOP;
          R0 = W[P0](Z);
		  CC = R0 == 2;
		  IF !CC JUMP Cod_cng8;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+400]; // flag_chang
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+408]; // count_fr0
	P4 = R0
	P3 = [SP++];
	R0 = [SP++];
		  R0 = 0;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+348]; // pastCoeff
	R7 = R0
	P3 = [SP++];
	R0 = [SP++];
    	  W[P5] = R0.L;
		  W[P4] = R0.L;
		  R6=[FP-16];
		  CALL _Calc_pastfilt;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+348]; // pastCoeff
	B0 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+352]; // RCoeff
	B1 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+380]; // sh_RCoeff
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
		  CALL _Calc_RCoeff;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+380]; // sh_RCoeff
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+376]; // ener
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+352]; // RCoeff
	B0 = R0
	P3 = [SP++];
	R0 = [SP++];
//    	  B1.H = rh_nbe;   // curAcf
//	      B1.L = rh_nbe;
	      P5=24;
		P5=SP+P5;
		B1=P5;
		  MNOP || R7.H = W[I0] || R6.H = W[I1];
		  R5.H = 3161;
		  CALL _Cmp_filt;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+348]; // pastCoeff
	B0 = R0
	P3 = [SP++];
	R0 = [SP++];
		  CC = R0 == 0;
		  IF CC JUMP Cod_cng7_1;
//	  	   B0.H = lsf_int;
//	       B0.L = lsf_int;  // curCoeff
	       B0 = SP;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+352]; // RCoeff
	B1 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+380]; // sh_RCoeff
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
		   CALL _Calc_RCoeff;
Cod_cng7_1:
//         B1.H = lsp_new;
//		   B1.L = lsp_new;
		   B1 = SP;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+220]; // lsp_old_q
	B2 = R0
	P3 = [SP++];
	R0 = [SP++];
		   CALL _Az_lsp;
		   R0 = [FP-4];
		   I0 = SP;
//		   I0.H = lsp_new;
//		   I0.L = lsp_new;
		   R0 += 2;
	   
		   CALL _lsfq_noise;

		   P0 = [FP-4];
		   R7 = [FP-8];   // [FP-8]    HIGH cur_igain LOW energyq
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+280]; // prev_energy
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
		   P0 += 8;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+520]; // tab_Sidgain
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
		   R6 = R7 >> 16 || W[I0] = R7.L;
		   P4 = R6;
		   W[P0] = R7.H;
		   
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+396]; // Dtx_sid_gain
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
		   P5 = P5 + (P4 << 1);
		   R6.L = W[P5];
		   W[I0] = R6.L;
		   
Cod_cng8:

	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+268]; // pastVad_flag
	I2 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+396]; // Dtx_sid_gain
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
		   R7.L = W[I2];  // // BIT 0 = pastVad BIT 1 = ppastVad BIT 2 = flag BIT 3 =  v_flag
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+388]; // Dtx_cur_gain
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
		   R6.L = W[I0];
		   CC = BITTST(R7,0);
		   R0 = R6;
		   IF CC JUMP Cod_cng9;
		      R5.L =  4096;  //A_GAIN1         4096 
		      R5.H = 28672; // A_GAIN0         28672
			  R4.H = 0;
			  R4.L = 0X8000;
			  R3 = R5.L * R6.L || R0.L = W[I1];
			  R2 = R5.H * R0.L;
			  R3 = R3 + R4(S);
			  R2 = R2 + R4(S);
			  R0.L = R3.H + R2.H(S);
Cod_cng9:
           W[I1] = R0.L;
		   R0.H = 1;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+176]; // exc
	R1 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+272]; // seed
	R2 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+228]; // L_exc_err
	B0 = R0
	P3 = [SP++];
	R0 = [SP++];
		   CALL _Calc_exc_rand;

	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+220]; // lsp_old_q
	B0 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+344]; // lspSid_q
	B1 = R0
	P3 = [SP++];
	R0 = [SP++];
		   R7=[FP-12];
		   B2=R7;
		   R7 += 24;
		   B3 = R7;
//		   B2.H = Aq_t_0;
//		   B2.L = Aq_t_0;
//		   B3.H = Aq_t_1;
//		   B3.L = Aq_t_1;
		   CALL _Int_qlpc;
		   P0 = 5;
		   I1 = B1;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+384]; // fr_cur
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
		   I0 = B0;
		   R7 = [I1++];
		   R0 = W[P5](Z);
		   LSETUP(Cod_cng10,Cod_cng10) LC0 = P0;
           Cod_cng10: MNOP || [I0++] = R7 || R7 = [I1++];
		   CC = R0 == 0;
		   IF !CC JUMP Cod_cngEND;
           CALL _Update_sumAcf;
Cod_cngEND:


	  UNLINK;
	  RTS;
	  
.text;
.align 8;		  
	  _Calc_RCoeff:
	   .global _Calc_RCoeff;
      .type  _Calc_RCoeff,STT_FUNC;
	  P0 = 10;
	  I0 = B0;	  	  
	  A1 = A0 = 0 || R7 = [I0++]; //L_acc = 0L;
	  LSETUP(Calc_RCoeff1,Calc_RCoeff1) LC0 = P0 >> 1;
	  Calc_RCoeff1: A0 += R7.L * R7.L, A1 += R7.H * R7.H || R7 = [I0++];
	  A0 += R7.L * R7.L;
	  R0 = (A0 += A1);
	  I2 = B0;
	  R7.L = SIGNBITS R0;                //sh1 = norm_l(L_acc);
	  I3 = B1;
	  R0 = ASHIFT R0 BY R7.L || I2 += 2; //L_acc = L_shl(L_acc, sh1);
	  R0.L = R0(RND) || W[P5] = R7.L;
	  W[I3++] = R0.L;                    //RCoeff[0] = round(L_acc);
/******************************************************	  
	  for(i=1; i<=M; i++) { L_acc = 0L;
          for(j=0; j<=M-i; j++)  L_acc = L_mac(L_acc, Coeff[j], Coeff[j+i]);          
          L_acc = L_shl(L_acc, sh1); RCoeff[i] = round(L_acc); }
*******************************************************/	  
		I0 = B0;
	  LOOP Calc_RCoeff2 LC0 = P0;
	  LOOP_BEGIN Calc_RCoeff2;	      
		  I1 = I2;
		  A0 = 0 || R6.H = W[I0++] || R6.L = W[I1++];
		  LSETUP(Calc_RCoeff2_1,Calc_RCoeff2_1) LC1 = P0;
          Calc_RCoeff2_1: R0 = (A0 += R6.H * R6.L) || R6.H = W[I0++] || R6.L = W[I1++];
		   I0 = B0;	
          R0 = ASHIFT R0 BY R7.L(S) || I2 += 2;
		  P0 += -1;
		  R0.L = R0(RND);
		  W[I3++] = R0.L;
	  LOOP_END Calc_RCoeff2;
	  RTS;
	  
.text;
.align 8;

_Calc_pastfilt:
	   .global _Calc_pastfilt;
      .type  _Calc_pastfilt,STT_FUNC;
	  LINK 52;
	  [FP-8] = R6;
	  [FP-4] = R7;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+364]; // sumAcf
	B0 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+292]; // sh_sumAcf
	B1 = R0
	P3 = [SP++];
	R0 = [SP++];
	  P0= 20;
	  P0 = SP + P0;
	  B2 = P0;
	  B3 = SP;
	  P0 = 3;
	  CALL _Calc_sum_acf;
	  /*  if(s_sumAcf[0] == 0L) { Coeff[0] = 4096; for(i=1; i<=M; i++) Coeff[i] = 0; return; } */
//	  P5= 20;
//	  P5 = SP + P5;
//	  I0 = P5;
		P2 = B2;
		I0 = B2;
	  P4 = [FP-4];    // P4 POINTS TO COEFF
	  R0 = W[P5](Z);
	  CC = R0 == 0;
	  IF !CC JUMP Calc_pastfilt2;
	  R1 = 4096;
	  P0 = 5;
	  [P4++] = R1;
	  LSETUP(Calc_pastfilt1,Calc_pastfilt1) LC0 = P0;
      Calc_pastfilt1: [P4++] = R0;
	  JUMP Calc_pastfiltEND;
Calc_pastfilt2:
      
		R7=[FP-8];
		B0=R7;
		I1 = R7;
		P0 = 11;
	  R7.L = 0;
	  R7.H = W[I0++];
	  //Set_zero(zero, MP1);
  	  LSETUP(alc_pastfilt3,alc_pastfilt3) LC0 = P0;
	  alc_pastfilt3: MNOP || [I1++] = R7 || R7.H = W[I0++];
	  B1 = P4;
	  B2 = SP;
	  CALL _Levinson; //Levinson(s_sumAcf, zero, Coeff, bid, &temp);
Calc_pastfiltEND:
	  UNLINK;
	  RTS;



_Cmp_filt:
	   .global _Cmp_filt;
      .type  _Cmp_filt,STT_FUNC;
	  //*** B0 POINTS TO RCOeff
	  //*** B1 POINTS TO acf
	  //*** R7.H = sh_RCoeff
	  //*** R6.H = alpha
	  //*** R5.H = FracThresh
	  P0 = 10;
	  R7.L = 0;   // sh[0];
	  R6.L = 0;   // sh[1]
	  R4 = 1;   // BIT 0 OF R4 = Overflow
      R5.L = 1;
Cmp_filt1:
	  	I0 = B0;
	  	I1 = B1;
	  	R3.H = W[I0++] ;
	  	R3.H = ASHIFT R3.H BY R7.L(S) || R3.L = W[I1++];
#ifdef FLAG533	  
  		CC = V;
#else	  
	  	CC = AV0;
#endif	  
	  	R3.L = ASHIFT R3.L BY R6.L(S) ;
#ifdef FLAG533	  
  		CC |= V;
#else	  
	  	CC |= AV0;
#endif	  
	  	A0 = R3.H * R3.L(IS) || R3.H = W[I0++];
	  	LOOP Cmp_filt1_1 LC0 = P0;
	  	LOOP_BEGIN Cmp_filt1_1;
		  	R3.H = ASHIFT R3.H BY R7.L(S) || R3.L = W[I1++];
#ifdef FLAG533	  
			CC |= V;
#else		  
		  	CC |= AV0;
#endif		  
		  	R3.L = ASHIFT R3.L BY R6.L(S) ;
#ifdef FLAG533	  
			CC |= V;
#else		  
		  	CC |= AV0;
#endif		  
	      	R0=(A0 += R3.H * R3.L) || R3.H = W[I0++];
#ifdef FLAG533	  
			CC |= V;
#else		  
		  	CC |= AV0;
#endif		  	      
	  	LOOP_END Cmp_filt1_1;
	  	IF !CC JUMP Cmp_filt2;
	  	CC = BITTST(R4,0);
	  	BITTGL(R4,0);
		 IF CC JUMP Cmp_filt1_2;
		    R6.L = R6.L - R5.L(S);
		   JUMP Cmp_filt1;
Cmp_filt1_2:
            R7.L = R7.L - R5.L(S);
            JUMP Cmp_filt1;
Cmp_filt2:
            R7.L = R7.L + R6.L(S); // temp2 
			R4 = R6.H * R5.H;
			R6 = R6 >>> 16;
			R3.L = R4 (RND);
			R5.L = 9;
			R3 = R3.L(X);
			R5.L = R7.H + R5.L(S); // temp1
			R1 = R6 + R3(S);
			R7.L = R5.L + R7.L(S);
			R1 = ASHIFT R1 BY R7.L(S);
			CC = R1 < R0;
			R0 = CC;
	  		RTS;

_Update_cng:
	  .global _Update_cng;
      .type  _Update_cng,STT_FUNC;
      LINK 4;	  
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+360]; // Acf_1
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+356]; // Acf
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
	  P4 = I0;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+284]; // sh_Acf
	I2 = R0
	P3 = [SP++];
	R0 = [SP++];
	  P0 = 6;
	  R5 = [I0++];
	  R7.H = 16;	  
	  LSETUP(Update_cng1,Update_cng1) LC0 = P0;
      Update_cng1: MNOP || [I1++] = R5 || R5 = [I0++];
	  R7.L = R7.L + R7.H(S) || R5 = [I3++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+384]; // fr_cur
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
	  R7 = - R7(V) || R4 = W[P5](Z);
	  R7.H = W[I2];
	  [I2] = R7;	  	  	  
	  	LSETUP(Update_cng2,Update_cng2) LC0 = P0;
Update_cng2: 	MNOP || [P4++] = R5 || R5 = [I3++];	        
      	R4 += 1;       
	  	CC = R4 == 2;
	  	W[P5] = R4.L || R5 = R5-|-R5;
	  	IF !CC JUMP Update_cngEND;
	 	W[P5] = R5.L || R5 = ROT R6 BY -5;
	 	IF !CC JUMP Update_cngEND;
		CALL _Update_sumAcf;
Update_cngEND:
      	UNLINK;
      	RTS;


_Update_sumAcf:
	   .global _Update_sumAcf;
      .type  _Update_sumAcf,STT_FUNC;
	  	LINK 4;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+284]; // sh_Acf
	I2 = R0
	P3 = [SP++];
	R0 = [SP++];
	  	B1 = I2;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+368]; // sumAcf_1
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+372]; // sumAcf_2
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
	  	R5 = [I2];
	  	P0 = 12;
	  	R6 = PACK(R5.L, R5.L ) || R7 = [I1--];
	  	LSETUP(Update_sumAcf1,Update_sumAcf1) LC0 = P0;
Update_sumAcf1: MNOP || [I0--] = R7 || R7 = [I1--];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+292]; // sh_sumAcf
	B3 = R0
	P3 = [SP++];
	R0 = [SP++];
	  	I0 = B3;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+356]; // Acf
	B0 = R0
	P3 = [SP++];
	R0 = [SP++];
	  	R7 = [I0++];
	  	R6 = [I0];
	  	R6 = PACK(R6.L,R7.H) || [I2] = R5;
	  	R7 = PACK(R7.L,R7.L) || [I0--] = R6;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+364]; // sumAcf
	B2 = R0
	P3 = [SP++];
	R0 = [SP++];
	  	[I0] = R7;
	  	P0 = 2;
	  	CALL _Calc_sum_acf;
	  	UNLINK;
	  	RTS;

_Calc_sum_acf:
	   .global _Calc_sum_acf;
      .type  _Calc_sum_acf,STT_FUNC;
	  //*** B0 POINTS TO Acf
	  //*** B1 POINTS TO sh_Acf
	  //*** B2 POINTS TO sum
	  //*** B3 POINTS TO sh_sum
	  //*** P0 = nb
	  I1 = B1;
	  R0 = R0 -|- R0 || R7 = [I1++];
	  R5 = PACK(R7.H,R7.H);
	  R7 = MIN(R7,R5)(V) || R5.L = W[I1];
	  CC = P0 == 2;
	  R4 = MIN(R7,R5)(V);
	  IF !CC R7 = R4;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+436]; // rri0i0
	I3 = R0
	P3 = [SP++];
	R0 = [SP++];
      R7.H = 14;
	  P1 = 11;
	  R7.L = R7.H + R7.L(S);
	  I0 = I3;
	  LSETUP(Calc_sum_acf2,Calc_sum_acf2) LC0 = P1;
	  Calc_sum_acf2: [I0++] = R0;       // L_tab[j] = 0L;
  	  P5 = B0;                          // ptr1 = acf;
	  I0 = B1;                          // I0 POINTS TO sh_acf
/*********************************************	  
	  for(i=0; i<nb; i++) {
         temp = sub(sh0, sh_acf[i]);
         for(j=0; j<MP1; j++) {
            L_temp = L_deposit_l(*ptr1++);
            L_temp = L_shl(L_temp, temp); 
            L_tab[j] = L_add(L_tab[j], L_temp);
         }
      } 
***********************************************/	  
	  R5.H = W[I0++];
	  LOOP Calc_sum_acf3 LC0 = P0;
	  LOOP_BEGIN Calc_sum_acf3;
	      R5.L = R7.L - R5.H(S) || R5.H = W[I0++];
		  R4 = W[P5++](X);
		  I1 = I3;
		  LOOP Calc_sum_acf3_1 LC1 = P1;
		  LOOP_BEGIN Calc_sum_acf3_1;
		     R4 = ASHIFT R4 BY R5.L(S) || R3 = [I1];
			 R3 = R4 + R3(S) ||  R4 = W[P5++](X);
			 [I1++] = R3;
		  LOOP_END Calc_sum_acf3_1;
	  LOOP_END Calc_sum_acf3;
	  R7.H = 16;
	  I0 = I3;
	  I1 = B2;                             // I1 POINTS TO sum
	  I2 = B3;                             // I2 POINTS TO sh_sumAcf
	  R7.H = R7.L - R7.H(S) || R4 = [I0++];//temp = sub(temp, 16);
	  R5.L = SIGNBITS R4;
	  R3 = ASHIFT R4 BY R5.L(S) || R4 = [I0++];
	  //**sum[i] = extract_h(L_shl(L_tab[i], temp));
	  LSETUP(Calc_sum_acf4,Calc_sum_acf4) LC0 = P1;
	  Calc_sum_acf4: R3 = ASHIFT R4 BY R5.L(S) || R4 = [I0++] || W[I1++] = R3.H;
	  R7.L = R5.L + R7.H(S);
	  W[I2] = R7.L;
	  RTS;

.text;

_lsfq_noise:
	  .global _lsfq_noise;
      .type  _lsfq_noise,STT_FUNC;
	   LINK 104;
	   [FP-4] = R0;
	   I1 = SP;
	   P0 = 10;
	   CALL _Lsp_lsf2;	   	   
	   	P5 = SP;
	   	P3 = SP;
	   	R7.L = 642;
	   
	   R0 = 40;
	   R1 = W[P5++](Z);
   	   P0 = 9;
	   R1 = MAX(R0,R1)(V);
//	   W[P5-2] = R1;
	   LOOP lsfq_noise1 LC0 = P0;
	   LOOP_BEGIN lsfq_noise1;
		   R2.L = R1.L + R7.L(S) || R0 = W[P5++](Z);
		   R1 = MAX(R0,R2)(V) || W[P3++] = R1;
//		   W[P5-2] = R1;
	   LOOP_END lsfq_noise1;	   
	   W[P3] = R1;
	   P5 = 18;
	   P5 = SP + P5;	   	   

	   R0 = 25681;
	   R2 = 321;
	   R1 = W[P5--](X);
	   R1 = MIN(R1,R0) || R3 = W[P5++](X);
	   R4 = R1 - R2(S) || W[P5--] = R1;
	   CC = R1 < R3;
	   IF CC R3 = R4;
	   W[P5] = R3.L;	   
	   I0 = SP;
	   M0=16;
	   I3=SP;
	   I3 += M0;
	   I2=I3;
	   I2 += 4;
	   B0=I2;
//	   I0.H = lsf;
//	   I0.L = lsf;
//	   B0.H = weight;
//	   B0.L = weight;
//	   I3.H = lsf_8;
//	   I3.L = lsf_8;
	   CALL _Get_wegt;
	   P3 = 60;
	   P3 = P3 + SP;	   	  
		P5=SP;
//	   P5.H = lsf;
//	   P5.L = lsf;
//	   P3.H = errlsf;
//	   P3.L = errlsf;	   
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+260]; // noise_fg
	I2 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+212]; // freq_prev
	I3 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+536]; // noise_fg_sum_inv
	P4 = R0
	P3 = [SP++];
	R0 = [SP++];
	   CALL _Lsp_prev_extract;
	   P5 = SP;
//	   P5.H = lsf;
//	   P5.L = lsf;		
//	   P3.H = errlsf_1;
//	   P3.L = errlsf_1;
	   P3 = 80;
	   P3 = P3 + SP;	   	  
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+264]; // noise_fg_1
	I2 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+212]; // freq_prev
	I3 = R0
	P3 = [SP++];
	R0 = [SP++];
	   
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+540]; // noise_fg_sum_inv_1
	P4 = R0
	P3 = [SP++];
	R0 = [SP++];
	   CALL _Lsp_prev_extract;
	   P3 = 60;
	   P3 = P3 + SP;	  
	   P1 = 40;
	   P1 = P1 + SP;
	   CALL _Qnt_e;
	   P0 = [FP-4];	   
	   R7 = 10;
	   I0 = P1;
	   P1 = 2;
	   W[P0++] = R1;
	   
	   W[P0++] = R0;
//	   I0.H = tmpbuf;
//	   I0.L = tmpbuf;
	   W[P0++P1] = R0.H;
	   CALL _Lsp_expand_1_2;
	   P0 = [FP-4];
//	   I0.H = tmpbuf;
//	   I0.L = tmpbuf;
	   
//	   P5.H = lsfq;
//	   P5.L = lsfq;
	   P5 = SP;
	   P3 = 40;
	   P3 = P3 + SP;
	   I0 = P3;
	   R7 = W[P0](Z);
	[--SP] = R0;
	[--SP] = P2;
	P2 = M2;
	R0 = [P2+264]; // noise_fg_1
	P3 = R0
	P2 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+516]; // noise_fg_sum_1
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
	   CC = BITTST(R7,0);
	   IF CC JUMP lsfq_noise2;
	[--SP] = R0;
	[--SP] = P2;
	P2 = M2;
	R0 = [P2+260]; // noise_fg
	P3 = R0
	P2 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+512]; // noise_fg_sum
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
lsfq_noise2:
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+212]; // freq_prev
	P4 = R0
	P3 = [SP++];
	R0 = [SP++];
	   CALL _Lsp_prev_compose;

	[--SP] = R1;
	[--SP] = P3;
	P3 = M2;
	R1 = [P3+212]; // freq_prev
	R0 = R1
	P3 = [SP++];
	R1 = [SP++];
	   R7 = 76;
	   R1 = R0;
	   R0 = R0 + R7;
	   R1 += 56;
	   I1 = R1;
	   I0 = R0;
	   
	   P0 = 15;
	   
       LSETUP(lsfq_noise3,lsfq_noise3) LC0 = P0;
       R7 = [I1--];
	   lsfq_noise3: MNOP || [I0--] = R7 || R7 = [I1--];
	   P0 = 40;
	   P0 = P0 + SP;
	   I1 = P0;
//	   I1.H = tmpbuf;
//	   I1.L = tmpbuf;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+212]; // freq_prev
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
	   P0 = 5;
	   R7 = [I1++];
       LSETUP(lsfq_noise4,lsfq_noise4) LC0 = P0;
	   lsfq_noise4: MNOP || [I0++] = R7 || R7 = [I1++];

//	   B0.H = lsfq;
//	   B0.L = lsfq;
	   B0 = SP;
	   CALL _Lsp_stability;
	   I0 = B0;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+344]; // lspSid_q
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
	   P0 = 10;
	   CALL _Lsf_lsp2;
	   UNLINK;
	   RTS;
_Qnt_e:
	  .global _Qnt_e;
      .type  _Qnt_e,STT_FUNC;
      	P2   = -100;
      	SP   = SP + P2;
      	R7.H = 0;
	  	R7.L = 0X7FFF;
	  	[SP] = R7;
      	[--SP] = P3;
      	[--SP] = P1;
      	[--SP] = B0;       	
	  	P0 = 32;
	  	P1 = 5;
	  	R6.H = 10;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+564]; // lspcb1
	R5 = R0
	P3 = [SP++];
	R0 = [SP++];
	  	P2   = [SP+8];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+500]; // PtrTab_1
	B2 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+436]; // rri0i0
	I3 = R0
	P3 = [SP++];
	R0 = [SP++];
      	I2   = B2;
	  	LOOP Qnt_e1_1 LC0 = P0;
	  	LOOP_BEGIN Qnt_e1_1;	      
		  A1 = R5 || R6.L = W[I2++];
		  R3 = (A1 += R6.H * R6.L);
		  I1 = R3;
		  I0 = P2;
		  A1 = A0 = 0 || R3 = [I0++] || R2 = [I1++];
		  LOOP Qnt_e1_1_1 LC1 = P1;
		  LOOP_BEGIN Qnt_e1_1_1;
               R4 = R3 -|- R2(S) || R3 = [I0++] ;
               NOP;
			   A0 += R4.L * R4.L, A1 += R4.H * R4.H || R2 = [I1++];
		  LOOP_END Qnt_e1_1_1;
		  R0 = (A0 += A1) ;
		  R7.H = 8644;
		  R1 = R0.H * R7.H;
	      W[I3++] = R1.H;
	  	LOOP_END Qnt_e1_1;
		P2 += 20;		
		I2   = B2;
	  	LOOP Qnt_e2_1 LC0 = P0;
	  	LOOP_BEGIN Qnt_e2_1;	      
		  A1 = R5 || R6.L = W[I2++];
		  R3 = (A1 += R6.H * R6.L);
		  I1 = R3;
		  I0 = P2;
		  A1 = A0 = 0 || R3 = [I0++] || R2 = [I1++];
		  LOOP Qnt_e2_1_1 LC1 = P1;
		  LOOP_BEGIN Qnt_e2_1_1;
               R4 = R3 -|- R2(S) || R3 = [I0++] ;
               NOP;
			   A0 += R4.L * R4.L, A1 += R4.H * R4.H || R2 = [I1++];
		  LOOP_END Qnt_e2_1_1;
		  R0 = (A0 += A1) ;
		  R7.H = 16572;
		  R1 = R0.H * R7.H;
	      W[I3++] = R1.H;
	  	LOOP_END Qnt_e2_1;
//	  	CC = BITTST(R7,0);
//	  	R7.H = 16572;
//		BITSET(R7,0);
//		P2 += 20;
		
//	  	IF !CC JUMP Qnt_e1;
       	P1 = 4;      	
       	P4 = 16;
       	P5 = 24;
       	P4 = P4 + SP;
       	P5 = P5 + SP;
       	I0 = P4;
       	I1 = P5;
//	   	I0.H = min_indx_p;
//	   	I0.L = min_indx_p;
//	   	I1.H = min_indx_m;
//	   	I1.L = min_indx_m;
	   	R7 = 0X7FFF;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+436]; // rri0i0
	P4 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+436]; // rri0i0
	R1 = R0
	P3 = [SP++];
	R0 = [SP++];
	   	A1 = R1;
	   	R6.L = 1;
       	R6.H = 32;	   	  
	   	LOOP Qnt_e3 LC0 = P1;
	   	LOOP_BEGIN Qnt_e3;           	
	       	R3 = R5 -|- R5 || R5 = [SP+12];
		   	R4 = W[P4++](X);
		   	LOOP Qnt_e3_2 LC1 = P0;
		   	LOOP_BEGIN Qnt_e3_2;
		       CC = R4 < R5;
			   IF CC R5 = R4;
			   IF CC R2 = R3;
			   R3.L = R3.L + R6.L(S) ||  R4 = W[P4++](X);
		   	LOOP_END Qnt_e3_2;
		   	R3.H = 1;
          	R3.L = 0;   
			LOOP Qnt_e3_22 LC1 = P0;
		   	LOOP_BEGIN Qnt_e3_22;
		       CC = R4 < R5;
			   IF CC R5 = R4;
			   IF CC R2 = R3;
			   R3.L = R3.L + R6.L(S) ||  R4 = W[P4++](X);
		   	LOOP_END Qnt_e3_22;                     
//           W[P5++] = R5;
           A1 += R6.L * R2.L , A0 = R6.H * R2.H || W[I0++] = R2.H ;		   
//		   R0 = R1 + R4;
		   R0 = (A0+=A1) || W[I1++] = R2.L;
		   I3 = R0;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+436]; // rri0i0
	P4 = R0
	P3 = [SP++];
	R0 = [SP++];
		   R1 = P4;
		   W[I3] = R7.L || A1=R1;
	   LOOP_END  Qnt_e3;
		P4 = 16;
       	P5 = 24;
       	P4 = P4 + SP;
       	P5 = P5 + SP;
       	I0 = P4;
       	I1 = P5;
//	   I0.H = min_indx_p;
//	   I0.L = min_indx_p;
//	   I1.H = min_indx_m;
//	   I1.L = min_indx_m;
	   P0 = 5;
	   P5 = 32;
	   P5 = SP + P5;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+500]; // PtrTab_1
	P4 = R0
	P3 = [SP++];
	R0 = [SP++];
	   R1 = [SP+8];
	   R5 = R0 -|- R0 || R0 = [SP+8];	  
	   R0 += 20;	   
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+564]; // lspcb1
	R7 = R0
	P3 = [SP++];
	R0 = [SP++];
	   R6.H = 10;
	   LOOP LQnt_e4 LC0 = P1;
	   LOOP_BEGIN LQnt_e4;
	   	  A0 = R7 ||	R4.L = W[I0++] || P3 = [SP+8];
	      R4 = ROT R4 BY -1 || R5.L = W[I1++];
		  P2 = R5;	      
		  NOP;
		  IF CC P3 = R0;
			NOP;
		  P2 = P4 + (P2 << 1);
		  R6.L = W[P2];
		  R4 = (A0+=R6.H * R6.L) || R3 = [P3++];
		  I3 = R4;
		  NOP; NOP;
		  LOOP LQnt_e4_2 LC1 = P0;
		  R4 = [I3++];
		  LOOP_BEGIN LQnt_e4_2;
		    	R2 = R3 -|- R4(S) || R3 = [P3++] || R4 = [I3++];
				[P5++] = R2;
          LOOP_END LQnt_e4_2;
	   LOOP_END LQnt_e4;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+512]; // noise_fg_sum
	B0 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+516]; // noise_fg_sum_1
	B1 = R0
	P3 = [SP++];
	R0 = [SP++];
	   R7	= [SP];
	   B3	= R7;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+568]; // lspcb2
	R7 = R0
	P3 = [SP++];
	R0 = [SP++];
	   R6.H = 10;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+436]; // rri0i0
	I3 = R0
	P3 = [SP++];
	R0 = [SP++];
       	P5 = 16;       	
       	P5 = P5 + SP;       	       	
	   	P1 = 4;
	   	LOOP Qnt_e5 LC0 = P1;
	   	P1= 32;
	   	P1 = SP + P1;
	   	LOOP_BEGIN Qnt_e5;
	       	R3 = W[P5++](Z);
		   	CC = BITTST(R3,0);
		   	R3 = B1;
		   	R2 = B0;
		   	IF CC R2 = R3;
		   	B2 = R2;
          	P0 = 16;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+504]; // PtrTab_2_0
	P4 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P2;
	P2 = M2;
	R0 = [P2+508]; // PtrTab_2_1
	P3 = R0
	P2 = [SP++];
	R0 = [SP++];
          	LOOP Qnt_e5_2 LC1 = P0;
          	P2=2;
		  	LOOP_BEGIN Qnt_e5_2;
		      	I0 = B2;
			  	A0 = 0 || R6.L = W[P4++P2];
			  	R3 = R6.L * R6.H || R2 = [I0++];
			  	R3 = R3 + R7 (S) || R4 = [I0++];	  		   
			  	I2 = R3;			  	 
				R2 = R2 << 1 (V) ;
				I1 = B3;  
              	R0.L = R2.L * R2.L, R0.H = R2.H * R2.H (T) || R3 = [I1++];
				R4 = R4 << 1 (V) || R2 = [P1];
              	R0.L = R0.L * R3.L, R0.H = R0.H * R3.H (T) || R3 = [I2++];			  	
              	R1 = R2 -|- R3(S);			  
			  	NOP;
			  	R2 = R0.L * R1.L, R3 = R0.H * R1.H || R5 = [I1++];
			  	R0.L = R4.L * R4.L, R0.H = R4.H * R4.H (T) || R4 = [P1+4];			  
			  	R3 = R3 << 3(S);			  			  
			  	R0.L = R0.L * R5.L, R0.H = R0.H * R5.H (T) ;
              	
				A0 += R1.H * R3.H || R3 = [I2++];
				R2 = R2 << 3(S);
			  	R4 = R4 -|- R3(S);			  			  
			  	A0 += R1.L * R2.H ;
			  	R2 = R0.L * R4.L, R3 = R0.H * R4.H;
			  	NOP;
			  	R2 = R2 << 3(S);
			  	R3 = R3 << 3(S);
			  	A0 += R4.L * R2.H;
			  	A0 += R4.H * R3.H || R2 = [I0++];
			  	R2 = R2 << 1 (V) || R5 = [I1++];
			  	NOP;
			  	R0.L = R2.L * R2.L, R0.H = R2.H * R2.H (T) || R6.L = W[P3++P2];
			  	R1 = R6.L * R6.H || R4.L = W[I2];
			  	R1 = R1 + R7;
			  R1 += 10;
			  I2 = R1;
			  R0.L = R0.L * R5.L, R0.H = R0.H * R5.H (T) || R5 = [P1+8] || R4.H = W[I2++];
			  R1 = R5 -|- R4(S);
			  NOP;
			  R4 = R0.L * R1.L, R5 = R0.H * R1.H;
			  NOP;
			  R4 = R4 << 3(S);
			  R5 = R5 << 3(S);
			  A0 += R1.L * R4.H;
			  A0 += R1.H * R5.H || R2 = [I0++];
Qnt_e5_2_2:   R2 = R2 << 1 (V) || R3 = [I1++];
				NOP;
				R0.L = R2.L * R2.L, R0.H = R2.H * R2.H (T) || R2 = [P1+12];
//			  P0 += 1;
				NOP;
				R0.L = R0.L * R3.L, R0.H = R0.H * R3.H (T) || R3 = [I2++];
			  R1 = R2 -|- R3(S);
			  NOP;
			  R4 = R0.L * R1.L, R5 = R0.H * R1.H;
				NOP;
			  R4 = R4 << 3(S);
			  R5 = R5 << 3(S);
			  A0 += R1.L * R4.H;
			  R0 =(A0 += R1.H * R5.H) || R2 = [I0++];
			  R2 = R2 << 1 (V) || R3 = [I1++];
			  NOP;
              R0.L = R2.L * R2.L, R0.H = R2.H * R2.H (T) || R2 = [P1+16];
//			  P0 += 1;
				NOP;
				R0.L = R0.L * R3.L, R0.H = R0.H * R3.H (T) || R3 = [I2++];
			  R1 = R2 -|- R3(S);
			  NOP;
			  R4 = R0.L * R1.L, R5 = R0.H * R1.H;
			  NOP;
			  R4 = R4 << 3(S);
			  R5 = R5 << 3(S);
			  A0 += R1.L * R4.H;
			  R0 =(A0 += R1.H * R5.H) || R2 = [I0++];
//			  CC = P0 < 2;
//			  IF CC JUMP Qnt_e5_2_2;
			  W[I3++] = R0.H;
		  LOOP_END Qnt_e5_2;
		  P1 += 20;
	   LOOP_END Qnt_e5;

	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+436]; // rri0i0
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
	   R6.H = 16;
	   R6.L = 1;
	   R7 = P5;
	   R1 = 0X7FFF;   // min[q]
//	   R3 = 0;
	   	P1 = 4;
	   	P0 = 16;
	   	R3 = R3 -|- R3 || R0 = W[P5++](X);
	   	LOOP Qnt_e6 LC0 = P1;
	   	LOOP_BEGIN Qnt_e6;
	       R3.L = 0;
		   LOOP Qnt_e6_1 LC1 = P0;
		   LOOP_BEGIN Qnt_e6_1;
		        CC = R0 < R1;
				IF CC R2 = R3;
				IF CC R1 = R0;
				R3.L = R3.L + R6.L(S) ||  R0 = W[P5++](X);
		   LOOP_END Qnt_e6_1;
		   R3.H = R3.H + R6.L(S);
   	  	LOOP_END Qnt_e6;
	  	R7 = R2.L;
	  	R6 = R2 >> 16;
	  	P2 = R7;      	  // cluster[1]
	  	P1 = R6;            // ptr
	  	P4 = 16;
       	P5 = 24;
       	P4 = P4 + SP;
       	P5 = P5 + SP;
	  	P5 = P5 + (P1 << 1);
	  	P4 = P4 + (P1 << 1);
	  	R0.H = R2.L >> 0 || R0.L = W[P5];
	  	R1.L = W[P4];
	  	R7 = R0.L;
	  	P3 = R7; 	  // cluster[1];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+500]; // PtrTab_1
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+564]; // lspcb1
	R6 = R0
	P3 = [SP++];
	R0 = [SP++];
	  	P5 = P5 + (P3 << 1);
	  	R5.H = 10;
	  	R5.L = W[P5];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+504]; // PtrTab_2_0
	P4 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+508]; // PtrTab_2_1
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+568]; // lspcb2
	R7 = R0
	P3 = [SP++];
	R0 = [SP++];
	  	P4 = P4 + (P2 << 1);
	  	P5 = P5 + (P2 << 1);
	  	R4 = R5.H * R5.L || R5.L = W[P4];
	  	R3 = R5.H * R5.L || R5.L = W[P5];
	  	
	  	R6 = R6 + R4 (S) || P4=[SP+4];	  
	  	I0 = R6;
	  	B0 = [SP++];
	  	R3 = R7 + R3 (S) || P1=[SP++];
	  	I2 = R3;      
	  	R2 = R5.H * R5.L || P3=[SP++];
	  	R2 += 10;	 
	  	R2 = R7 + R2 (S)  || R7 = [I0++] || R6 = [I2++];
	  	I3 = R2;    	  	
	  	R5 = R7 +|+ R6(S) || R7 = [I0++] || R6 = [I2++];
	  	[P4++] = R5;
	  	R5 = R7 +|+ R6(S) || R7 = [I0++] || R6 = [I2++];
	  	[P4++] = R5;
	    R6.H = W[I3++];
	    R5 = R7 +|+ R6(S) || R7 = [I0++] || R6 = [I3++];
		[P4++] = R5;
		R5 = R7 +|+ R6(S) || R7 = [I0++] || R6 = [I3++];
		[P4++] = R5;
	    R5 = R7 +|+ R6(S) || R7 = [I0++] || R6 = [I3++];
		[P4++] = R5;	  	  	  	  
	  	P2 = 100;
      	SP = SP + P2;
	  	RTS;







