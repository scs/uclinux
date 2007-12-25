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
Title:			lspgetq
Description     :      Common lsp quantization functions
Prototype       :      _Pitch_ol_fast()
			_Enc_lag3()
			_G_pitch()

*******************************************************************************/ 

.text;
.align 8;
_Lsp_prev_extract:
	   .global _Lsp_prev_extract;
      .type  _Lsp_prev_extract,STT_FUNC;
	  // P5 POINTS TO lsp
	  // P3 POINTS TO lsp_ele
	  // I2 POINTS TO fg
	  // I3 POINTS TO freq_prev
	  // P4 POINTS TO fg_sum_inv
	  P0 = 10;
	  P1 = 4;
	  M0 = 20;
	  M1 = -56;
//	  R4 = 0;
//      for ( j = 0 ; j < M ; j++ ) {
//      L_temp = L_deposit_h(lsp[j]);
//      for ( k = 0 ; k < MA_NP ; k++ )
//          L_temp = L_msu( L_temp, freq_prev[k][j], fg[k][j] );
//          temp = extract_h(L_temp);
//          L_temp = L_mult( temp, fg_sum_inv[j] );
//          lsp_ele[j] = extract_h( L_shl( L_temp, 3 ) ); }
	  I0 = I2;
	  I1 = I3;
	  R5 = [P5++] || A1=A0=0;
	  A1.H = R5.H || R7 = [I0++M0] || R6 = [I1++M0] ;
	  R5 = R5 << 16 ;
		  A0.H = R5.H ;
	  LOOP Lsp_prev_extract1 LC0 = P0 >> 1;
	  LOOP_BEGIN Lsp_prev_extract1;	      		  
		  	R2.L = (A0 -= R7.L * R6.L), R2.H = (A1 -= R7.H * R6.H) (T) || R7 = [I0++M0] || R6 = [I1++M0];
		  	R2.L = (A0 -= R7.L * R6.L), R2.H = (A1 -= R7.H * R6.H) (T) || R7 = [I0++M0] || R6 = [I1++M0];
		  	R2.L = (A0 -= R7.L * R6.L), R2.H = (A1 -= R7.H * R6.H) (T) || R7 = [I0++M1] || R6 = [I1++M1];
		  	R2.L = (A0 -= R7.L * R6.L), R2.H = (A1 -= R7.H * R6.H) (T) || R3 = [P4++];
		  	A1 = A0 = 0;
		  	R0 = R2.L * R3.L, R1 = R2.H * R3.H || R5 = [P5++];
			A1.H = R5.H || R7 = [I0++M0] || R6 = [I1++M0] ;
		  	R0 = R0 << 3(S);
		  	R1 = R1 << 3(S);
		  	R0 = PACK(R1.H, R0.H);
		  	[P3++] = R0 || R5 = R5 << 16 ;
		  	A0.H = R5.H ;
	  LOOP_END Lsp_prev_extract1;
	   RTS;

_Lsp_expand_1_2:
	   .global _Lsp_expand_1_2;
      .type  _Lsp_expand_1_2,STT_FUNC;
	   I1 = I0;
	   P0 = 9;
//	   for ( j = 1 ; j < M ; j++ ) {
//          diff = sub( buf[j-1], buf[j] );
//          tmp = shr( add( diff, gap), 1 );
//          if ( tmp > 0 ) {
//             buf[j-1] = sub( buf[j-1], tmp );
//             buf[j]   = add( buf[j], tmp ); }
//       } 
       MNOP || R6.H = W[I0] || I1 += 2;
       R6.L = W[I1++]; 
       R4 = R6;
       R5.L = R4.H - R4.L(S);
   	   LOOP Lsp_expand_1_2_1 LC0 = P0;
	   LOOP_BEGIN Lsp_expand_1_2_1;
//	 		R5.L = R4.H - R4.L(S);
			R5.L = R5.L + R7.L(S); 
			R5.L = R5.L >>> 1(S) || R6.L = W[I1--];
			CC = BITTST(R5,15);     //if (tmp > 0)
	        R3.H = R4.H - R5.L(S);  // sub( buf[j-1], tmp );
		    R3.L = R4.L + R5.L(S);  // add( buf[j], tmp );
		    IF !CC R4 = R3;
		    W[I1++] = R4.L || R5.L = R4.L - R6.L(S);
//		    MNOP ;
            R4 = PACK(R4.L, R6.L) || W[I0++] = R4.H || I1 += 2;
       LOOP_END Lsp_expand_1_2_1;
	   RTS;

_Lsp_get_quant:
	   .global _Lsp_get_quant;
      	.type  _Lsp_get_quant,STT_FUNC;
	 	LINK 36;
	 	R2.H = 10;
	 	R3 = PACK(R4.L, R3.L) || [FP-4] = R5;   // freq_prev
	 	R7 = R2.H * R2.L || [FP-8] = R6;        // lspq
	 	R4 = R3.L * R2.H, R5 = R3.H * R2.H || [FP-12] = P0; // fg
	 	R7 = R7 + R0 (S) || [FP-16] = P1;                           // fg_sum
	 	R5 = R5 + R1;	 	
	 	R4 = R4 + R1;	 	
	 	I0 = R7;
	 	I1 = R4;
	 	R5 += 10;
	 	I2 = R5;
	 	MNOP || R7 = [I0++] || R6 = [I1++];
	    R5 = R7 +|+ R6(S) || R7 = [I0++] || R6 = [I1++];
		[SP] = R5;
	 	R5 = R7 +|+ R6(S) || R7 = [I0++] || R6 = [I1++];
		[SP+4] = R5 ||	R6.H = W[I2++];
	    R5 = R7 +|+ R6(S) || R7 = [I0++] || R6 = [I2++];
		[SP+8] = R5;
	 	R5 = R7 +|+ R6(S) || R7 = [I0++] || R6 = [I2++];
		[SP+12] = R5 || R5 = R7 +|+ R6(S);// || R7 = [I0++] || R6 = [I2++];
		[SP+16] = R5;
		I0 = SP;	
	 	R7 = 10;
	 	CALL _Lsp_expand_1_2;
		I0 = SP;
	 	R7 = 5;
	 	CALL _Lsp_expand_1_2;
	 	R7 = [FP-16];
		I0 = SP;	
	 	P5 = [FP-8];
	 	P3 = [FP-12];
	 	P4 = [FP-4];
	 	I1 = R7;
	 	CALL _Lsp_prev_compose;
	 	R7 = [FP-4];     // R7 = ADDRESS OF freq_prev
	 	R6 = 76;
	 	I3 = R7;	
	 	R6 = R6 + R7;
	 	R7 += 56;
	 //I1 = R6;
	 	I0 = R7;
	 	I1 = R6;
	 	I2 = SP;
	 	P0 = 15;
/*********************************************	 
	 for ( k = MA_NP-1 ; k > 0 ; k-- ) Copy(freq_prev[k-1], freq_prev[k], M);
     Copy(lsp_ele, freq_prev[0], M);
***********************************************/	 
	 	R0 = [I0--];
	 	LSETUP(Lsp_get_quant3,Lsp_get_quant3) LC0 = P0;
Lsp_get_quant3: MNOP || [I1--] = R0 || R0 = [I0--];
	 	MNOP || R7 = [I2++] || R0 = [FP-8];
	 	P0 = 5;
	 	LSETUP(Lsp_get_quant4,Lsp_get_quant4) LC0 = P0;
Lsp_get_quant4: MNOP || [I3++] = R7 ||  R7 = [I2++];
	 	B0 = R0;
	 	CALL _Lsp_stability;
	 	UNLINK;
	 	RTS;
_Lsp_stability:
	  .global _Lsp_stability;
      .type  _Lsp_stability,STT_FUNC;
	  // B0 POINTS TO buf
	  I2 = B0;
	  P1 = B0;    //buf
	  P0 = 8;
	  R5.L = 40;
	  R5.H = 321;
	  R2 = [P1];
	  R0.H = R2.H - R2.L(S) || I2+=4;//
	  R7 = ROT R0 BY 1 || R4 = [P1];
	  R3 = PACK(R2.L, R2.H)|| R1.L = W[I2++];
		   IF CC R4 = R3;
		R0.H = R1.L - R2.L(S);
		R7 = MAX(R4,R5)(V);	   
	  R4 = PACK(R1.L, R4.H);
	  
	  LOOP Lsp_stability1 LC0 = P0;
	  LOOP_BEGIN Lsp_stability1;
      	   R3 = ROT R0 BY 1 ;
		   R3 = PACK(R2.L, R1.L)|| R1.L = W[I2++];
		   IF CC R4 = R3;
		   R0.H = R1.L - R2.L(S);
		   R6.L = R7.L + R5.H(S);
		   R7 = MAX(R4,R6)(V)|| W[P1++] = R7; 
	       R4 = PACK(R1.L, R4.H);
	   LOOP_END Lsp_stability1;	          
      R6.L = R7.L + R5.H(S) || R1 = W[P1+2](Z);
	  R7 = MAX(R1,R6)(V)|| W[P1++] = R7; 	  
	  R1.L = 25681;
	  R1 = MIN(R1,R7)(V);
	  W[P1] = R1.L;
	  RTS;

_Lsp_prev_compose:
	   .global _Lsp_prev_compose;
      .type  _Lsp_prev_compose,STT_FUNC;
	   // I0 POINTS TO lsp_ele
	   // P5 POINTS TO lsp
	   // P3 POINTS TO fg
	   // P4 POINTS TO freq_prev
	   // I1 POINTS TO fg_sum
	   	P0 = 5;
//	   	P1 = 4;
	   	M0 = 20;
	   	M1 = -56(X);
//	  for ( j = 0 ; j < M ; j++ ) {
//         L_acc = L_mult( lsp_ele[j], fg_sum[j] );
//         for ( k = 0 ; k < MA_NP ; k++ )
//             L_acc = L_mac( L_acc, freq_prev[k][j], fg[k][j] );
//             lsp[j] = extract_h(L_acc); }	   
	   	I2 = P4;
		I3 = P3;
		MNOP || R7 = [I0++] || R6 = [I1++];
	   	LOOP Lsp_prev_compose1 LC0 = P0;
	   	LOOP_BEGIN Lsp_prev_compose1;	   		
          	A0 = R7.L * R6.L, A1  = R7.H * R6.H || R7 = [I2++M0] || R6 = [I3++M0];
			A0+= R7.L * R6.L, A1 += R7.H * R6.H || R7 = [I2++M0] || R6 = [I3++M0];
		    A0+= R7.L * R6.L, A1 += R7.H * R6.H || R7 = [I2++M0] || R6 = [I3++M0];
		    A0+= R7.L * R6.L, A1 += R7.H * R6.H || R7 = [I2++M1] || R6 = [I3++M1];
		    R0.L = (A0+= R7.L * R6.L), R0.H = (A1 += R7.H * R6.H) (T) || R7 = [I0++] || R6 = [I1++];//|| R7 = [I2++M1] || R6 = [I3++M1];
		   	[P5++] = R0;
	   	LOOP_END Lsp_prev_compose1;
	   	RTS;
