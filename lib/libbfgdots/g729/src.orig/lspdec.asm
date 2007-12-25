/****************************************************************************
Analog Devices, Inc.
BSD-Style License

This file is part of the libgdots library, an optimized codec library
for the Blackfin processor.

Copyright (c) 2007 Analog Devices, Inc.
All rights reserved.

The libgdots library, is free software, as in zero cost - it does not provide
the freedoms provided to you by other free software licenses.

For more information, see the top level COPYING file.
*****************************************************************************/

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
		  I1.H = D_prev_ma;
		  I1.L = D_prev_ma;
		  R6.L = 7;
		  R5.L = 5;
		  R0.L = W[I0++];
		  CC = BITTST(R0,7);
		  R7 = CC;
		  R3.L = 0X0505;
		  R2 = EXTRACT(R0,R6.L)(Z) || R1.L = W[I0];
		  R4 = EXTRACT(R1,R5.L)(Z) || W[I1] = R7.L;
		  R3 = EXTRACT(R1,R3.L)(Z) || R6   = [FP-4];
		  R0.H = lspcb1;
		  R0.L = lspcb1;
		  R1.H = lspcb2;
		  R1.L = lspcb2;
		  P0.H = fg_1;
	  	  P0.L = fg_1;
		  P1.H = fg_sum_1;
		  P1.L = fg_sum_1;
		  IF CC JUMP Lsp_iqua_cs1_1;
		  P0.H = fg_0;
	  	  P0.L = fg_0;
		  P1.H = fg_sum;
		  P1.L = fg_sum;
Lsp_iqua_cs1_1:
          	R5.H = D_freq_prev;
		  	R5.L = D_freq_prev;
//		  R6   = [FP-4];
		  	P5.H = _Lsp_get_quant;
		  	P5.L = _Lsp_get_quant;
		  	CALL (P5);
			R7   = [FP-4];
			I0 = R7;
		  	P0 = 5;
		  	I1.H = D_prev_lsp;
		  	I1.L = D_prev_lsp;
		  	R7 = [I0++];
		  	LSETUP(Lsp_iqua_cs1_2,Lsp_iqua_cs1_2) LC0 = P0;
Lsp_iqua_cs1_2: 	MNOP || [I1++] = R7 || R7 = [I0++];
		  	JUMP Lsp_iqua_csEND;
Lsp_iqua_cs2:					
		  I1.H = D_prev_lsp;
		  I1.L = D_prev_lsp;
		  R7   = [FP-4];
			I0 = R7;
		  I2.H = D_prev_ma;
		  I2.L = D_prev_ma;
		  P0 = 5;
		  R7 = [I1++];
		  LSETUP(Lsp_iqua_cs2_1,Lsp_iqua_cs2_1) LC0 = P0;
          Lsp_iqua_cs2_1: MNOP || [I0++] = R7 || R7 = [I1++];
		  R7.L = W[I2];
		  CC = BITTST(R7,0);
		  I2.H = fg_1;
		  I2.L = fg_1;
		  P4.H = fg_sum_inv_1;
		  P4.L = fg_sum_inv_1;
		  IF CC JUMP Lsp_iqua_cs2_2;
		  I2.H = fg_0;
		  I2.L = fg_0;
		  P4.H = fg_sum_inv;
		  P4.L = fg_sum_inv;
Lsp_iqua_cs2_2:
          P5.H = D_prev_lsp;
		  P5.L = D_prev_lsp;
		  P3 = SP;
		  I3.H = D_freq_prev;
		  I3.L = D_freq_prev;
		  CALL _Lsp_prev_extract;
		  R6 = 76;
//		  R7.H = D_freq_prev;
//		  R7.L = D_freq_prev;
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
