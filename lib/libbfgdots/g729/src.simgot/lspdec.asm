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
// *** Author: Xiangzhi,wu   xiangzhi.wu@analog.com    2002/11/20	       ***
// *** Performance:                       								   ***
// ****************************************************************************
//#include "proc_select.h"
.extern D_freq_prev;                                    
.extern D_prev_lsp;                                     
.extern D_prev_ma;                                      
.extern _Lsf_lsp2;                                      
.extern _Lsp_get_quant;                                 
.extern _Lsp_prev_extract;                              
.extern fg_0;                                           
.extern fg_1;                                           
.extern fg_sum;                                         
.extern fg_sum_1;                                       
.extern fg_sum_inv;                                     
.extern fg_sum_inv_1;                                   
.extern lspcb1;                                         
.extern lspcb2;             

.text;
.align 8;
_D_lsp:
	  .global _D_lsp;
      .type  _D_lsp,STT_FUNC;
	  	LINK 24;
	  	[FP-4] = R1;   
	  	R7 = SP;
	  	CALL _Lsp_iqua_cs;
	  	R1 = [FP-4];
		I0 = SP;
	  	P0 = 10;
	  	I1 = R1;
	  	CALL _Lsf_lsp2;
	  	UNLINK;
	  	RTS;


_Lsp_iqua_cs:
	  .global _Lsp_iqua_cs;
      .type  _Lsp_iqua_cs,STT_FUNC;
	  	LINK 24;
	  	[FP-4] = R7 || R7 = ROT R2 BY -1;
	  	IF CC JUMP Lsp_iqua_cs2;
	      I0 = R0;		  
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+68]; // D_prev_ma
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
		  R6.L = 7;
		  R5.L = 5;
		  R0.L = W[I0++];
		  CC = BITTST(R0,7);
		  R7 = CC;
		  R3.L = 0X0505;
		  R2 = EXTRACT(R0,R6.L)(Z) || R1.L = W[I0];
		  R4 = EXTRACT(R1,R5.L)(Z) || W[I1] = R7.L;
		  R3 = EXTRACT(R1,R3.L)(Z) || R6   = [FP-4];
	[--SP] = R1;
	[--SP] = P3;
	P3 = M2;
	R1 = [P3+564]; // lspcb1
	R0 = R1
	P3 = [SP++];
	R1 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+568]; // lspcb2
	R1 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+576]; // fg_1
	P0 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+584]; // fg_sum_1
	P1 = R0
	P3 = [SP++];
	R0 = [SP++];
		  IF CC JUMP Lsp_iqua_cs1_1;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+572]; // fg_0
	P0 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+580]; // fg_sum
	P1 = R0
	P3 = [SP++];
	R0 = [SP++];
Lsp_iqua_cs1_1:
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+80]; // D_freq_prev
	R5 = R0
	P3 = [SP++];
	R0 = [SP++];
//		  R6   = [FP-4];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+684]; // _Lsp_get_quant
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
		  	CALL (P5);
			R7   = [FP-4];
			I0 = R7;
		  	P0 = 5;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+84]; // D_prev_lsp
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
		  	R7 = [I0++];
		  	LSETUP(Lsp_iqua_cs1_2,Lsp_iqua_cs1_2) LC0 = P0;
Lsp_iqua_cs1_2: 	MNOP || [I1++] = R7 || R7 = [I0++];
		  	JUMP Lsp_iqua_csEND;
Lsp_iqua_cs2:					
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+84]; // D_prev_lsp
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
		  R7   = [FP-4];
			I0 = R7;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+68]; // D_prev_ma
	I2 = R0
	P3 = [SP++];
	R0 = [SP++];
		  P0 = 5;
		  R7 = [I1++];
		  LSETUP(Lsp_iqua_cs2_1,Lsp_iqua_cs2_1) LC0 = P0;
          Lsp_iqua_cs2_1: MNOP || [I0++] = R7 || R7 = [I1++];
		  R7.L = W[I2];
		  CC = BITTST(R7,0);
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+576]; // fg_1
	I2 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+592]; // fg_sum_inv_1
	P4 = R0
	P3 = [SP++];
	R0 = [SP++];
		  IF CC JUMP Lsp_iqua_cs2_2;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+572]; // fg_0
	I2 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+588]; // fg_sum_inv
	P4 = R0
	P3 = [SP++];
	R0 = [SP++];
Lsp_iqua_cs2_2:
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+84]; // D_prev_lsp
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
		  P3 = SP;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+80]; // D_freq_prev
	I3 = R0
	P3 = [SP++];
	R0 = [SP++];
		  CALL _Lsp_prev_extract;
		  R6 = 76;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+80]; // D_freq_prev
	//R7 = R0
	P3 = [SP++];
	R0 = [SP++];
		  P0 = 15;
//		  I3 = R7;
			R7 = I3;
		  R6 = R6 + R7;
		  R7 += 56;		  
		  I1 = R7;
		  I0 = R6;
		  P1 = 5;
		  I2 = SP;
		  R0 = [I1--];
          LSETUP(Lsp_iqua_cs2_3,Lsp_iqua_cs2_3) LC0 = P0;
		  Lsp_iqua_cs2_3: MNOP || [I0--] = R0 || R0 = [I1--];
		  R0 = [I2++];
          LSETUP(Lsp_iqua_cs2_4,Lsp_iqua_cs2_4) LC0 = P1;
		  Lsp_iqua_cs2_4: MNOP || [I3++] = R0 || R0 = [I2++];
Lsp_iqua_csEND:
      UNLINK;
      RTS;
