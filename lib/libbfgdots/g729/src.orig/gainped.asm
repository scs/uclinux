/*****************************************************************************
Analog Devices, Inc.
BSD-Style License

This file is part of the libgdots library, an optimized codec library
for the Blackfin processor.

Copyright (c) 2007 Analog Devices, Inc.
All rights reserved.

The libgdots library, is free software, as in zero cost - it does not provide
the freedoms provided to you by other free software licenses.

For more information, see the top level COPYING file.

******************************************************************************
Project:		G.729AB for Blackfin
Title:			Gainped
Description     :      Gain predicts
Prototype       :      _Gain_predict()
			_Gain_update()

*******************************************************************************/ 

.extern _Log2;
.extern pred;
.extern tabpow;

.text;
.align 8;
_Gain_predict:
	   .global _Gain_predict;
      .type  _Gain_predict,STT_FUNC;
	  LINK 4;
	  // B2 POINTS TO past_qua_en
	  // B3 POINTS TO code
	  I0 = B3;
	  P0 = 40;
	  //L_tmp = 0;
      //for(i=0; i<L_subfr; i++) L_tmp = L_mac(L_tmp, code[i], code[i]);
	  A1 = A0 = 0 || R7 = [I0++];
	  LSETUP(Gain_predict1,Gain_predict1) LC0 = P0 >> 1;
      Gain_predict1: A0 += R7.L * R7.L, A1 += R7.H * R7.H || R7 = [I0++];
	  R0 = (A0 += A1);
	  CALL _Log2;      //Log2(L_tmp, &exp, &frac);
	  //L_tmp = Mpy_32_16(exp, frac, -24660); 
	  R1.L = -24660;
	  R1.H = 1;
	  R2 = (A0 = R0.H * R1.L), R3 = (A1 = R0.L * R1.L);
	  //L_tmp = L_mac(L_tmp, 32588, 32);
	  R4.H = 32588;	  
	  A0 += R3.H * R1.H;
	  R4.L = 32;	  
	  R0 = (A0 += R4.H * R4.L);	  
	  I0 = B2;
	  //L_tmp = L_shl(L_tmp, 10);                    
      //for(i=0; i<4; i++) L_tmp = L_mac(L_tmp, pred[i], past_qua_en[i]);
	  I1.H = pred;
	  I1.L = pred;	  
	  A0 = A0 << 10 || R7 = [I0++] || R6 = [I1++];
	  A0 += R7.L * R6.L, A1  = R7.H * R6.H  || R7 = [I0++] || R6 = [I1++];
	  A0 += R7.L * R6.L, A1 += R7.H * R6.H;
	  R1 = 5439;
	  R0 = (A0 += A1);       //*gcode0
	  R7.H = 14;
	  R0 = R0.H * R1.L;      //L_tmp = L_mult(*gcode0, 5439);
	  R7.L = 32;
	  R0 = R0 >>> 8(S);      //L_tmp = L_shr(L_tmp, 8);
	  R0.L = R0.L >> 1;
	  R0.H = R7.H - R0.H(S); //*exp_gcode0 = sub(14,exp);
	  P5.H = tabpow;	  
	  P5.L = tabpow;//R3.L = 0;
	  R1 = R0.L * R7.L;	  	  
	  R2 = R1 >> 16;
	  P4 = R2;
	  R1 = R1 >>> 1(S);	  
	  BITCLR(R1,15);
	  P3 = 2;	  
	  P5 = P5 + (P4 << 1);
	  R3.L = R3.L - R3.L (NS) || R3.H = W[P5++P3];
	  A0 = R3 || R3.L = W[P5];
	  R1.H = R3.H - R3.L(S);
	  NOP;
	  R2 = (A0 -= R1.H * R1.L);  
	  R0.L = R2(RND);         //R0.H = *exp_gcode0, R0.L = *gcode0
      UNLINK;
      RTS;

_Gain_update:
	  .global _Gain_update;
      .type  _Gain_update,STT_FUNC;
	   LINK 4;
	   // I3 POINTS TO past_qua_en
	   // R7 = L_gbk12
	   R0 = [I3++];
	   R0 = PACK(R0.L,R0.H) || R1 = [I3--];
	   R2 = PACK(R1.L, R0.L) || [I3++] = R0;
	   R0 = ROT R7 BY 0 || [I3--] = R2;
	   CALL _Log2;
	   R7.H = 13;	   
	   R0.H = R0.H - R7.H(S);
	   R0.L = R0.L << 1;
	   R0 = R0 << 13(S);
	   R7.L = 24660;
	   R0 = R0.H * R7.L;
	   W[I3] = R0.H;
       UNLINK;
	   RTS;





