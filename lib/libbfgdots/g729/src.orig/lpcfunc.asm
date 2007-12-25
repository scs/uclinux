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
Title:			lpcfunc
Description     :      common lpc related functions
Prototype       :      _Lsp_Az()
			_Get_lsp_pol()
			_Weight_Az()
			_Lsf_lsp2()
			_Int_qlpc()

*******************************************************************************/

#include "G729_const.h"

//.extern Dn;
.extern rri0i2;
.extern rri0i3;
.extern slope_cos;
.extern table2;

.text;
.align 8;	 
_Weight_Az:
	  .global _Weight_Az;
      .type  _Weight_Az,STT_FUNC;
      	R5 = 1;
		R5.H = R5.L << 14 || R1.L = W[I0++];
	  	R7.L = W[I0++];
      	W[I1++] = R1.L || A0 = R7.L * R7.H, A1 = R7.H * R7.H;      	
//      	R5.H=0x4000;
      	R0.L = (A0 += R5.L*R5.H),R0.H = (A1 += R5.L*R5.H) (T) || R7.L = W[I0++];
      	LOOP Weight_Az1 LC0 = P0>>1;
	  	LOOP_BEGIN Weight_Az1;	  		
	  		A0   = R5.L * R5.H,A1  = R5.L * R5.H || W[I1++] = R0.L;
	        R1.L = (A0 += R7.L * R0.H),R1.H = (A1 += R7.H * R0.H) (T) || R7.L = W[I0++];  		   
			A0   = R5.L * R5.H,A1  = R5.L * R5.H || W[I1++] = R1.L;
			R0.L = (A0 += R7.L * R1.H),R0.H = (A1 += R7.H * R1.H) (T) || R7.L = W[I0++];
	  	LOOP_END Weight_Az1;  	  
	  	RTS;
.text;
.align 8;	  
_Lsf_lsp2:
	  .global _Lsf_lsp2;
      .type  _Lsf_lsp2,STT_FUNC;
	  	P5.H = slope_cos;
	  	P5.L = slope_cos;	   
	  	R4 = 63;	  
	  	R7.H = 20861;
      	R4.H = R4.L >> 0 || R6 = [I0++];
      	R5.H = R6.L * R7.H, R5.L = R6.H * R7.H (T) ;	   
		P4.H = table2;	  
      	P4.L = table2;	
      	R3 = R5 >> 8 (V);
	  	R3 = MIN(R3,R4) (V);	
	  	R0.L = 1;
	  	LOOP Lsf_lsp2_1 LC0 = P0>>1;	  
	  	LOOP_BEGIN Lsf_lsp2_1 ;	        		  		  
		  	R2 = R3.H * R0.L, R3 = R3.L * R0.L (IS) || R6 = [I0++];
		  	P2 = R2;
		  	P3 = R3;
		  	R3 = R5 << 8 (V);
		  	R3 = R3 >> 5 (V);
		  	P0 = P5 + (P2 << 1);
		  	P2 = P4 + (P2 << 1);   
		  	P1 = P5 + (P3 << 1);		  	
		  	P3 = P4 + (P3 << 1);		  
		  	R2.H = W[P0]; 		
		  	R5.H = R6.L * R7.H, R5.L = R6.H * R7.H (T) || R2.L = W[P1];		  
		  	R3.L = R2.H * R3.H, R3.H = R2.L * R3.L (T) || R2.L = W[P2];
		  	R6 = R5 >> 8 (V) || R2.H = W[P3];
		  	R2 = R2 +|+ R3 (S) ;
		  	R3 = MIN(R6,R4) (V) || [I1++] = R2  ;	   
	  	LOOP_END Lsf_lsp2_1;
	  	RTS;
.text;
.align 8;	 
_Get_lsp_pol:
		P4.H = rri0i2;  // f1 USE THE BUFFER
	  	P4.L = rri0i2; 
	  	P5.H = rri0i3;    // f2 USE THE BUFFERE
	  	P5.L = rri0i3;
	  	R7.H = 4096;
	  	R7.L = 512;	 
	  	R4 = R7.H * R7.H(IS) || R6 = [I0++];
	  	A1 = A0 = 0 || [P5] = R4;
	  	R0 = (A0 -= R6.L * R7.L), R1 = (A1 -= R6.H * R7.L) || [P4] = R4;	  	
	  	[P4+4] = R0;	  
	  	[P5+4] = R1;	  
	  	P1 = 2;
	  	R7.H = 1;
	  	P0 = 8;   
	  	I2 = P5;	 
	  	I3 = P4;	  		  
	  	LOOP Get_lsp_pol1 LC0 = P0>>1;
	  	LOOP_BEGIN Get_lsp_pol1;
		  	R2 = [P4--];
		  	R0 = ROT R2 BY 0 || R1 = [P5--];
			R3 = ROT R1 BY 0 || R6 = [I0++];
		  	R0 = R0 + R2(S)  || R4 = [P4+8];
		  	R1 = R1 + R3(S)  || [P4+12] = R2;
		  	R2.H = R4.L >> 1 || R5 = [P5+8];		  		
		  	R2.L = R5.L >> 1 || [P5+12] = R3;
		  	LOOP Get_lsp_pol1_1 LC1 = P1>>1;
		  	LOOP_BEGIN Get_lsp_pol1_1;			  			  				  				  		
		  		R5   = PACK(R5.H,R4.H);			  	
			  	R3.H = R2.H * R6.L, R3.L = R2.L * R6.H (T);
			  	A0   = R5.L * R6.L, A1   = R5.H * R6.H || R4 = [P4--];
			  	R2   = (A0 += R3.H * R7.H), R3 = (A1 += R3.L * R7.H) (S2RND) || R5 = [P5--];
			  	R2   = R0 - R2(S) || R0 = [P4+12];
			  	R0   = R0 + R4(S) || R4 = [P4+8];
			  	R3   = R1 - R3(S) || R1 = [P5+12];
		  		R1   = R1 + R5(S) || R5 = [P5+8];
		  		[P4+16] = R2 ||	R2.H = R4.L >> 1;		  		
		  		[P5+16] = R3 || R2.L = R5.L >> 1;
		  	LOOP_END Get_lsp_pol1_1;
		  	R0 = [P4+12];
		  	A0 = R0 || R3 = [P5+12];
			R1 = (A1=R6.H * R7.L) , R0 = (A0-=R6.L * R7.L) || R4=[I2++] || I3+=4;
			[P4+12] = R0 || R1 = R3-R1(S);
			[P5+12] = R1;
			P1 += 2;
			P4 = I3;
			P5 = I2;
      	LOOP_END Get_lsp_pol1;      	      	      	
      	P2 += 10;
	  	P3 += 12;
	  	P0 = 5;
	  	R0 = [P4 + 4];
	  	R1 = [P4--];
	  	R2 = [P5+4];	
      	LOOP Lsp_Az1 LC0 = P0;
	  	LOOP_BEGIN Lsp_Az1;	      	  		  			
	      	R4 = R0 + R1(S) || R3 = [P5--] ;		  
		  	R5 = R2 - R3(S) || R0 = [P4 + 4]  ;
      		R2 = R4 + R5, R3 = R4 - R5(S) || [P5+8] = R5 ; 
			R2 = R2 << 3 (S) || R1 = [P4--];
			R3 = R3 << 3 (S) || [P4 + 12] = R4;
			R4.L = R2(RND) || R2 = [P5+4];		
			W[P2--] = R4 || R5.L = R3(RND);	      
		  	W[P3++] = R5;  
	  	LOOP_END Lsp_Az1;  	  
	  	R7.L = 4096;
	  	W[P2] = R7.L;	  	
	  	RTS;	  	  
_Int_qlpc:
	  .global _Int_qlpc;
      .type  _Int_qlpc,STT_FUNC;
	  	LINK 24;
	  	I0 = B0;
	  	I1 = B1;
	  	P0 = 4;
		I2 = SP;
	  	R7 = [I0++];
	  	R5 = R7 >>> 1(V,S) || R6 = [I1++];
		R4 = R6 >>> 1(V,S) || R7 = [I0++];
		R3 = R5 +|+ R4(S);		 	
	  	LOOP Int_qlpc1 LC0 = P0;
	  	LOOP_BEGIN Int_qlpc1;
	     	R5 = R7 >>> 1(V,S) || R6 = [I1++];
		 	R4 = R6 >>> 1(V,S) || R7 = [I0++];
		 	R3 = R5 +|+ R4(S) || [I2++] = R3;		 	
	  	LOOP_END Int_qlpc1;
	  	[I2++] = R3;
		I0 = SP;	  	
		P2 = B2;
	  	P3 = B2;
	  	CALL _Get_lsp_pol;
	  	I0 = B1;	  	
	  	P2 = B3;
	  	P3 = B3;
	  	CALL _Get_lsp_pol;
      	UNLINK;
	  	RTS;	  

