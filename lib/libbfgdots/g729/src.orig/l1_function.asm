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
Title:			L1_function
Description     :      coder core modules
Prototype       :      _D4i40_17_fast()
			_Pitch_fr3_fast()
			_Autocorr()
			_Az_lsp()
			_Chebps_11()
			_Chebps_10()
			_Cor_h_X()
*******************************************************************************/

#include "G729_const.h"


.extern _Pred_lt_3;
.extern grid;
.extern hamwindow;
.extern rri0i0;
.extern rri0i1;
.extern rri0i2;
.extern rri0i3;
.extern rri0i4;
.extern rri1i1;
.extern rri1i2;
.extern rri1i3;
.extern rri1i4;
.extern rri2i2;
.extern rri2i3;
.extern rri2i4;
.extern rri3i3;
.extern rri4i4;

.text;
.align 8;

_D4i40_17_fast:
	  	.global _D4i40_17_fast;
      	.type  _D4i40_17_fast,STT_FUNC;
       	LINK 228;       	
       	[FP-48]=P5;
       	[FP-52]=P4;
       	[FP-56]=P3;
       	[FP-60]=P2;
       	P0 = L_SUBFR;          //40;
       	I0 = P3;
		I1 = SP;
		M0 = 80;		
		I2 = SP;
	   	R7.L = 0X7FFF;
	   	R7.H = 0X8000;
	   	R6.L = 0X8000;
	   	R6.H = 0X7FFF;	   
	   	R5 = 0x100(z); //added code to make round mode bit 1
       	ASTAT = R5;	      
	   	R5 = ROT R7 BY 0 || R4.L = W[I0++] || I1 += M0;
	   	P1 = I1;
	   	R3 = ROT R4 BY 17 ;
	   	LOOP D4i40_17_fast1 LC0 = P0;
	   	LOOP_BEGIN D4i40_17_fast1;
			IF CC R5 = R6;
 		    R3 = ABS R4(V)    || W[I1++] = R5.L;					 		    
 		    R5 = ROT R7 BY 0  || W[I2++] = R5.H || R4.L = W[I0--];	
 		    R3 = ROT R4 BY 17 || I0 += 4 || W[I0] = R3.L;
 	   	LOOP_END D4i40_17_fast1;	   
       	P0 = 8;
	   	P2 = SP;
	   	I0.H = rri0i1;
	   	I0.L = rri0i1;
	   	I1.H = rri0i2;
	   	I1.L = rri0i2;
	   	I2.H = rri0i3;
	   	I2.L = rri0i3;
	   	I3.H = rri0i4;
	   	I3.L = rri0i4;
	   	B0 = I2;
	   	P5 = P1;
	  	P3 = 10;
	   	R7.L = W[P5++P3];
       	P4 = P1;                 //psign = sign_dn;  	   
	   	LOOP D4i40_17_fast2 LC0 = P0;
	   	LOOP_BEGIN D4i40_17_fast2;
	   	  	R2= ROT R7 BY 17 || R0 = [I0] || R7.L = W[P5++P3];
		  	IF CC P4 = P2;        //psign = sign_dn_inv;
		  NOP;
		  NOP;
		  	LOOP D4i40_17_fast2_1 LC1 = P0 >> 1;
		  		R5 = [P4++];
		  	LOOP_BEGIN D4i40_17_fast2_1;
		       	R4.L = R0.L * R5.H (T) || R1 = [I1] || R5 = [P4++];
			   	R1.L = R1.L * R5.L (T) || R2 = [I2] || R6 = [P4++];
			   	R2.L = R2.L * R5.H (T) || R3 = [I3] || R5 = [P4++];
			   	R3.L = R3.L * R6.L (T) || I0 += 4;
			   	R4.H = R0.H * R5.L (T) || R0 = [I0--];			   
			   	R1.H = R1.H * R5.H (T) || R5 = [P4++] || [I0++] = R4;			   
			   	R2.H = R2.H * R5.L (T) || [I1++] = R1 ;			   
			   	R3.H = R3.H * R5.H (T) || R5 = [P4++] || [I2++] = R2;
			   	[I3++] = R3;
		  	LOOP_END D4i40_17_fast2_1;
		    	P4 = P1;              //psign = sign_dn;     
	   	LOOP_END D4i40_17_fast2;	   
	   	I0.H = rri1i2;
	   	I0.L = rri1i2;
	   	I1.H = rri1i3;
	   	I1.L = rri1i3;
	   	I2.H = rri1i4;
	   	I2.L = rri1i4;
	   	B1 = I1;
	   	P1 += 2;
	   	P5 = P1;
	   	P1 += 2;
	   	P2 += 4;	   
	   	P4 = P1;
	   	R7.L = W[P5++P3];
       	LOOP D4i40_17_fast3 LC0 = P0;
	   	LOOP_BEGIN D4i40_17_fast3;
	      	R2 = ROT R7 BY 17 || R7.L = W[P5++P3] || R0 = [I0];
		  	IF CC P4 = P2;
		  NOP;
		  NOP;
		  	LOOP D4i40_17_fast3_1 LC1 = P0>>1;
		  	R5 = [P4++];
		  	R4.L = R0.L * R5.L (T) || R1 = [I1] ;
		  	LOOP_BEGIN D4i40_17_fast3_1;
			   	R1.L = R1.L * R5.H (T) || R2 = [I2]   || R5 = [P4++];
			   	R2.L = R2.L * R5.L (T) || R5 = [P4++] || R3 = [I0++];
			   	R4.H = R0.H * R5.H (T) || R5 = [P4++] || R0 = [I0--]; 			   
			   	R1.H = R1.H * R5.L (T) || [I0++] = R4 || R4 = [P4++];			   
			   	R2.H = R2.H * R5.H (T) || R5 = [P4++] || [I1++] = R1 ;
			   	R4.L = R0.L * R5.L (T) || R1 = [I1]   || [I2++] = R2;
		  	LOOP_END D4i40_17_fast3_1;
		  	P4 = P1;
	   	LOOP_END D4i40_17_fast3;
	   	I0.H = rri2i3;
	   	I0.L = rri2i3;
	   	I1.H = rri2i4;
	   	I1.L = rri2i4;
	   	B2 = I0;
	   	P5 = P1;
	   	P3 = 8;
	   	P1 += 2;
	   	P2 += 2;
	   	I3 = I0; 
       	P4 = P1;
	   	R7.L = W[P5];
	   	LOOP D4i40_17_fast4 LC0 = P0;
	   	LOOP_BEGIN D4i40_17_fast4;
	      	CC = BITTST(R7,15);
		  	IF CC P4 = P2;
		  	P5 += 10;
		  	MNOP || R7.L = W[P5]|| R6.L = W[I0];		  
		  	LOOP D4i40_17_fast4_1 LC1 = P0 ;
		  	R5 = W[P4++](Z);
		  	LOOP_BEGIN D4i40_17_fast4_1;
		       R4 = R6.L * R5.L || R6.L = W[I1] || R5 = W[P4++P3](Z);
			   R4 = R6.L * R5.L || W[I0++] = R4.H || R5 = W[P4++](Z);
			   MNOP || W[I1++] = R4.H || R6.L = W[I0];//|| R6.L = W[I2++];
		  	LOOP_END D4i40_17_fast4_1;
		  	P4 = P1;
		LOOP_END D4i40_17_fast4;
 	   	R0.H = -1;
	   	R0.L = 1;
//	   	R1.L = 0;
//	   	R1.H = 1;
//	   	R2.L = 2;
	   	R2.H = 3;	   
//	   	B0.H = rri0i3;
//	   	B0.L = rri0i3;
//	   	B1.H = rri1i3;
//	   	B1.L = rri1i3;
//	   	B2.H = rri2i3;
//	   	B2.L = rri2i3;
	   	B3.H = rri3i3;
	   	B3.L = rri3i3;
	   	R1.H = R0.L >> 0 || [FP-36]=R0;
	   	R1.L = R1.L - R1.L (S) || [FP-4] = R0;   // HIGH = psk LOW = alpk
	   	R2.L = R0.L << 1 || [FP-8] = R1;   // HIGH = ip1 LOW = ip0
	   	R3 = R3 -|- R3 || [FP-12] = R2;   // HIGH = ip3 LOW = ip2
	   	[FP-16] = R3;   // HIGH = iy  LOW = ix
	   	[FP-20] = R3;   // ps
	   	P3=[FP-56];	   
	   	P5 = 3;         // TRACK
	   	R5.L = 0X4000;       
	   	R5.H = 5;
	   	[FP-28] = P5;   // TRACK
	   	P1 = 16;
	   	M0 = 16;
		[FP-40] = P3;
		R2.H = rri2i2;
		R2.L = rri2i2;
		[FP-64] = R2;
		R2.H = rri0i0;
		R2.L = rri0i0;
		[FP-68] = R2;
D4i40_17_fastLoopBegin:
	   	R3 = [FP-36];
	   	P0 = 2;
	   	P4 = -1;        // prev_i0
	   	  
	   	LOOP D4i40_17_fastLoop1 LC0 = P0;
	   	P0 = 10;	
	   	LOOP_BEGIN D4i40_17_fastLoop1;
		   		P3=[FP-40];
		   		[FP-24] = R3; 
		   		R4 = -1;    // max		   
		   		P2 = 2;     // j
//		    for (j=2; j<L_SUBFR; j+=STEP) 
//              if ((sub(dn[j], max) > 0) && (sub(prev_i0,j) != 0)) {   max = dn[j]; i0 = j; }     		   
		 		R1.L = 6554;
				LOOP D4i40_17_fastLoop1_1 LC1 = P1 >> 1;
		   		P3 += 4;
		   		LOOP_BEGIN D4i40_17_fastLoop1_1;
		        	R3 = W[P3++P0](X); // dn[j] 		        
		        	CC = P2 == P4;     // sub(dn[j],max) > 0   
					CC = !CC;
					R2 = R4 - R3 (S) || R7 = [FP-28]; //(sub(prev_i0,j)!= 0))
					CC &= AN;
					IF CC P5 = P2;
					IF CC R4 = R3;				
					P2 += 5;
		   		LOOP_END D4i40_17_fastLoop1_1;  		  	   		   		   		   				  
		   		R1.H = 1;
		   		R6 = P5;                  
		   		R3 = R6.L * R1.L || P2 = [FP-40];  
		   		R4 = B2;   
		   		R6 = PACK(R7.L, R6.L) || R2 = [FP-64];   
		   		P4 = P5;		    	
		   		P5 = P2 + (P5 << 1);     // Dn[i0]
		   		R3 = R3.H * R1.H || R7.H = W[P5];
		   		R2 = R2 + R3 (S) || R1 = [FP-16];
		   		I2 = R2;                // I0 POINTS TO rri2i2+j
		   		R3 = R3 << 3     || P5 = [FP-28];  //track		   		
		   		I1 = B3;		   		            
		   		R2 = R4 + R3 (S)  || R0 = [FP-20];
		   		I0 = R2;   	
		   		R6.H = R6.H - R5.H (S) || R3.H = W[I2];		   			   			   				  	  		                 
	       		R4 = R3.H * R5.L (IS) || R3 = [FP-24];		   		
		   		P5 = P2 + (P5 << 1);	
		   		LOOP D4i40_17_fastLoop1_2 LC1 = P1 >> 1; 
		   		LOOP_BEGIN D4i40_17_fastLoop1_2;
		       		A0 = R4 || R7.L = W[P5++P0];
			   		R7.L = R7.L + R7.H(S) || R2.L = W[I1++];
			   		A0 += R2.L * R5.L (IS)|| R2.L = W[I0++];
			   		R2.L = (A0 += R2.L * R5.L);
			   		R2.H = R7.L * R7.L (T);			   		
			   		R6.H = R6.H + R5.H(S);// || R4 = [FP-36];
			   		A1 = R3.L * R2.H, A0 = R3.H * R2.L; 
			   		CC = A0 < A1;
			   		IF CC R3 = R2;
			   		IF CC R1 = R6;
			   		IF CC R0 = R7;               
				LOOP_END D4i40_17_fastLoop1_2;
//		        [FP-24] = R3;  // R2.H = sq2 R2.L = alp_16
				[FP-16] = R1;  // R6.H = i1  R6.L = i0
				[FP-20] = R0;  // ps
	   	LOOP_END D4i40_17_fastLoop1;
	   	R7.L = 6554;
		R4 = R3.L * R5.L(IS) || R3 = [FP-36];//R6 = [FP-16];
	   	R0.L = R1.L * R7.L, R0.H = R1.H * R7.L (T) || [FP-32] = R1; // HIGH i0 LOW i1	   	
	   	R6 = B1;
	   	R0 = R0.L * R3.L, R1 = R0.H * R3.L || [FP-24] = R3;	   	
	   	R2.H = rri1i2;
	   	R2.L = rri1i2;
	   	R2 = R2 + R0 (S) || P0=[FP-40];
	   	P2 = R2;
	   	I0.H = rri1i1;
	   	I0.L = rri1i1;
	   	I1 = SP;
	   	R3.L = 0X1000;
	   	R6 = R6 + R1 (S) || R7.L = W[P2++P1];	   
	   	P3 = R6;
	   	R2.H = rri0i2;
	   	R2.L = rri0i2;
	   	R6 = B0;
	   	R2 = R2 + R0 (S) || R0 = [FP-16];
	   	R6 = R6 + R1 (S) || R7.H = W[P3++P1];	   
	   	P4 = R2;
	   	P5 = R6;   	   	   
		A0 = R7.L * R5.L(IS) || R6=[FP-68];
		I2 = R6;
		A0 += R7.H * R5.L(IS) || R3.H = W[I0++] || [FP-44] = R4;
		R7.L = (A0 += R3.H * R3.L) || R3.H = W[P2++P1];
	   	LOOP D4i40_17_fastLoop2 LC0 = P1 >> 1;
	   	LOOP_BEGIN D4i40_17_fastLoop2;
	    	A0 = R3.H * R5.L(IS) || R3.H = W[P3++P1] || W[I1++] = R7.L;
			A0 += R3.H * R5.L(IS) || R3.H = W[I0++];
			R7.L = (A0 += R3.H * R3.L) || R3.H = W[P2++P1];			
	   	LOOP_END D4i40_17_fastLoop2;	   	
		I3.H = rri0i1;
	   	I3.L = rri0i1;
	   	P2 = 10;
	   	R6.L = R6.L - R6.L (NS) || R1 = [FP-24];	   
	   	LOOP D4i40_17_fastLoop3 LC0 = P1 >> 1;
	   	LOOP_BEGIN D4i40_17_fastLoop3;	        
	        A0  = R4 || R2.L = W[P4++P1];
			A0 += R2.L * R3.L || R2.L = W[P5++P1];
			A0 += R2.L * R3.L || R2.L = W[I2++] || R7 = [FP-20];  // R0 = ps0
			R4 = (A0 += R2.L * R3.L)(IS) || R7.H = W[P0++P2];
			R7.H = R7.H + R7.L(S) || P3 = [FP-40];
	   		I0 = SP;
			R6.H = -4;			
			LOOP D4i40_17_fastLoop3_1 LC1 = P1 >> 1;
			P3 += 2;
			LOOP_BEGIN D4i40_17_fastLoop3_1;
				A0 = R4 || R7.L = W[P3++P2];
				R7.L = R7.H + R7.L(S) || R2.L = W[I3++];
				A0 += R2.L * R3.L || R2.L = W[I0++];
				R2.L = (A0 += R2.L * R5.L);
				R2.H = R7.L * R7.L(T);				
				R6.H = R6.H + R5.H(S);
				A0 = R1.L * R2.H, A1 = R1.H * R2.L;
				CC = A0 <= A1;
				IF !CC R1 = R2;
				IF !CC R0 = R6;				   
			LOOP_END D4i40_17_fastLoop3_1;			   
    		R6.L = R6.L + R5.H(S) || R4=[FP-44];  
	   	LOOP_END D4i40_17_fastLoop3;	 	   	
	   	R7 = [FP-4];   
	   	R6 = R7.L * R1.H, R7 = R7.H * R1.L || [FP-16] = R0;//[FP-24] = R1;  
	   	CC = R7 < R6;
	   	IF !CC JUMP D4i40_17_fastLoop4;
	       	R6 = [FP-32];
	       	[FP-4] = R1;
		   	[FP-8] = R0;
		   	[FP-12] = R6;
D4i40_17_fastLoop4:
	   	R3 = [FP-36];
	   	P0 = 2;
	   	P4 = -1;      // prev_i0
	   	
	   	
	   	LOOP D4i40_17_fastLoop5 LC0 = P0;
	   	P0 = 10;
	   	LOOP_BEGIN D4i40_17_fastLoop5;
			P3 = [FP-40];
	       	P2 = [FP-28];  			
	       	[FP-24] = R3;  
		   	R4 = -1;  // max		   	
		   	R0.H = 6554;
		   	LOOP D4i40_17_fastLoop5_1 LC1 = P1 >> 1;
		   	P3 = P3 + (P2 << 1);
		   	LOOP_BEGIN D4i40_17_fastLoop5_1;
		        R3 = W[P3++P0](X); // dn[j] 
		        CC = P2 == P4;     // sub(dn[j],max) > 0   
				CC = !CC;
				R2 = R4 - R3 (S) || R1 = [FP-16];      //(sub(prev_i0,j)!= 0))
				CC &= AN;
				IF CC P5 = P2;
				IF CC R4 = R3;
				P2 += 5;     
		   	LOOP_END D4i40_17_fastLoop5_1;
		   	R4 = B0;
		   	R6 = P5;
		    P4 = R6;		    
			R2 = R0.H * R6.L || P5 = [FP-40];			
			R0 = B3;
			R3.L = 1;										
			R2 = R2.H * R3.L;
			P2 = P5 + (P4 << 1);
			R0 = R0 + R2 (S) || R7.H = W[P2];
			I2 = R0;			
			
			R6.H = -5;  
			P3.H = rri0i0;
			P3.L = rri0i0;
			
			R4 = R4 + R2 (S) || R3.H = W[I2] || R0 = [FP - 20];			
			I0 = R4;			   			
			R4 = R3.H * R5.L(IS) || R3 = [FP-24] ;
			LOOP D4i40_17_fastLoop5_2 LC1 = P1 >> 1;
			LOOP_BEGIN D4i40_17_fastLoop5_2;
			    A0 = R4 || R7.L = W[P5++P0] ;
				R7.L = R7.H + R7.L(S) || R2 = W[P3++](Z);				   
				A0 += R2.L * R5.L(IS) || R2.L = W[I0];
				R2.L = (A0 += R2.L * R5.L );
				R2.H = R7.L * R7.L(T) || I0 += M0 ;				
				R6.H = R6.H + R5.H(S);
				A1 = R3.L * R2.H, A0 = R3.H * R2.L;				   
				CC = A0 < A1;
			    IF CC R3 = R2;
                IF CC R1 = R6;
            	IF CC R0 = R7;                   
			LOOP_END D4i40_17_fastLoop5_2;
//			[FP-24] = R3;  // R2.H = sq2 R2.L = alp_16
		    [FP-16] = R1;  // R6.H = i1  R6.L = i0
		   	[FP-20] = R0;  // ps2
		LOOP_END D4i40_17_fastLoop5;	   
	   	R6.L = 6554;	   	
	   	R0 = R1.L * R6.L, R1 = R1.H * R6.L || [FP-32] = R1;
	   	R4 = R3.L * R5.L(IS) || R7 = [FP-36];
	   	R1 = R1 >>> 15 || [FP-44]=R4;
	   	R6 = B2;
	   	R0 = R0.H * R7.L || [FP-24] = R7;  	   	
	   	R1 = R1 << 3 || P4 = [FP-40];	   
	   	R6 = R6 + R0 (S) || P5 = [FP-64];
	   	P0 = R6;
	   	R2.H = rri0i2;
	   	R2.L = rri0i2;
	   	R3.L = 0X1000;
	   	I3 = SP;
	   	R2 = R2 + R1 (S) || R3.H = W[P0++P1];	   	   
	   	I0 = R2;	   	
	   	R2.H = rri0i1;
	   	R2.L = rri0i1;
	   	R6 = B1;	   
	   	R6 = R6 + R0 (S) || R0 = [FP-16]; 
	   	P3 = R6;
	   	R2 = R2 + R1 (S) || R1 = [FP-24];	   
	   	I1 = R2;
		LOOP D4i40_17_fastLoop6 LC0 = P1 >> 1;
		LOOP_BEGIN D4i40_17_fastLoop6;
			A0 = R3.H * R5.L(IS) || R2.L = W[I0++];
			A0 += R2.L * R5.L(IS) || R2 = W[P5++](Z);
			R7.L = (A0 += R2.L * R3.L)|| R3.H = W[P0++P1];		  
			W[I3++] = R7.L;
		LOOP_END D4i40_17_fastLoop6;
	   	I2.H = rri1i1;
	   	I2.L = rri1i1;	   	
	   	I3.H = rri1i2;
	   	I3.L = rri1i2;
	   	R6.L = 1;	   	
	   	P2 = 10;
	   	P4 += 2;		   
	   	LOOP D4i40_17_fastLoop7 LC0 = P1 >> 1;
       	LOOP_BEGIN D4i40_17_fastLoop7;	       
	    	A0 = R4 || R3.H = W[P3++P1];
		   	A0 += R3.H * R3.L || R3.H = W[I1++] || R7 = [FP-20];
		   	A0 += R3.H * R3.L  || R7.H = W[P4++P2]; //ps
		   	R7.H = R7.L + R7.H(S) || R2.L = W[I2++];
		   	R4 = (A0 += R2.L * R3.L)(IS) || P5 = [FP-40];  		   		   	
		   	I0 = SP;
		   	R6.H = -3;		   	
		   	LOOP D4i40_17_fastLoop7_1 LC1 = P1 >> 1;
		   	P5 += 4;
		   	LOOP_BEGIN D4i40_17_fastLoop7_1;
		       	A0 = R4 || R7.L = W[P5++P2];
			   	R7.L = R7.H + R7.L(S) || R2.L = W[I3++];
			   	A0 += R2.L * R3.L || R2.L = W[I0++];
			   	R2.L = (A0 += R2.L * R5.L);
			   	R2.H = R7.L * R7.L(T);			   
			   	R6.H = R6.H + R5.H(S);
		   	   	A0 = R1.L * R2.H, A1 = R1.H * R2.L ;
			   	CC = A0 <= A1;
			   	IF !CC R1 = R2;
				IF !CC R0 = R6;			   
		   	LOOP_END D4i40_17_fastLoop7_1;	   	   
    	    R6.L = R6.L + R5.H(S) || R4=[FP-44];  
	   	LOOP_END D4i40_17_fastLoop7;
		[FP-24] = R1;  // R1.H = sq2 R1.L = alp_16
	   	[FP-16] = R0;
	   	R3 = [FP-4];   
	   	R6 = R3.L * R1.H, R7 = R3.H * R1.L || R3 = [FP-28];   // track
	   	CC = R7 < R6;
	   	IF !CC JUMP D4i40_17_fastLoop8;
	    R6 = [FP-32];     
	    R2 = PACK(R0.L,R6.H) || [FP-4] = R1;
		R1 = PACK(R6.L, R0.H) || [FP-8] = R2;
		[FP-12] = R1;
D4i40_17_fastLoop8:
        R3 += 1;
		CC = R3 < 5 (IU);//R4;
		IF !CC JUMP D4i40_17_fastLoopEND;
		[FP-28] = R3;
		
//		CC = R3 < 3 ;
//		IF !CC JUMP D4i40_17_fastLoopBegin;
		B0.H = rri0i4;
		B0.L = rri0i4;
		B1.H = rri1i4;
		B1.L = rri1i4;
		B2.H = rri2i4;
		B2.L = rri2i4;
		B3.H = rri4i4;
		B3.L = rri4i4;
		JUMP D4i40_17_fastLoopBegin;
D4i40_17_fastLoopEND: 

	  	R5 = SP;
	  	R6 = 80;
	  	R5 = R6 + R5 (S) || R7 = [FP- 8] ;   // HIGH = ip1 LOW = ip0
		R4.L = 1;			
	  	R0 = R7.L * R4.L, R1 = R7.H * R4.L || R6 = [FP-12] ; 
	  	R2 = R6.L * R4.L, R3 = R6.H * R4.L || P5 = [FP-48];
	  	R0 = R0 + R5;
	  	I0 = R0;
	  	R1 = R1 + R5;
	  	I1 = R1;
		R7=R7-|-R7 || P3 = [FP-60];
	  	R2 = R2 + R5 (S) || R0.L = W[I0];
	   	I2 = R2;
	  	R3 = R3 + R5 (S) || R0.H = W[I1];	  	  	 
	  	I3 = R3;	 
	  	P0 = 40;	  	  	  
	  	LOOP D4i40_17_fast5 LC0 = P0 >> 1;
	  	LOOP_BEGIN D4i40_17_fast5;
	     	[P5++] = R7;
		 	[P3++] = R7;
	  	LOOP_END D4i40_17_fast5;
		R0 = R0 >>> 2(V,S) || R1.L = W[I2] || R1.H = W[I3];
	  	R1 = R1 >>> 2(V,S) || R7 = [FP- 8] ;   // HIGH = ip1 LOW = ip0
	  	R2 = R7.L * R4.L, R3 = R7.H * R4.L ||R5 = [FP-48] ;   // HIGH = ip3 LOW = ip2      
	  	R2 = R2 + R5 (S)||R6 = [FP-52];
	  	B0 = R6;
	  	R3 = R3 + R5 (S)||R6 = [FP-12];
	  	I0 = R2;
	  	I1 = R3;
      	R2 = R6.L * R4.L, R3 = R6.H * R4.L || P5 = [FP-60];
	  	R2 = R2 + R5 (S) ;	  
	  	R3 = R3 + R5 (S) || W[I0] = R0.L;	  
	  	I0 = R2;
	  	R4 = R7 >> 16 || W[I1] = R0.H;
	  	I1 = R3;
	  	R7 = R7.L;
	  	R5 = R6 >> 16 || W[I0] = R1.L;
	  	R6 = R6.L;
	  	P0 = R7;
	  	P3 = R5;
	  	P4 = 40;
	  	P1 = R4;  	  
	  	P2 = R6;
	  	P4 -= P0;
	  	P0 = P5 + (P0 << 1); 
	  	R5 = R3-|-R3 || W[I1] = R1.H;	 
	  	R4.H = 1;
			 
	  	I0 = B0;
	  	I1 = P0;
	    R4.L = R0.L >> 0 || R5.L = W[I0++];
		R3.H = R3.L = SIGN(R4.H)*R5.H + SIGN(R4.L) * R5.L || R5.L = W[I0++];
		LSETUP(D4i40_17_fast6_2,D4i40_17_fast6_2) LC0 = P4;
D4i40_17_fast6_2: R3.H = R3.L = SIGN(R4.H)*R5.H + SIGN(R4.L) * R5.L || W[I1++] = R3.L || R5.L = W[I0++];
		P4 = 40;
		I0 = B0;
		P4 -= P1;
		P1 = P5 + (P1 << 1);
		R4.L = 1;
		I1 = P1;
		I2 = P1;
		R4.H = R0.H >> 0 || R5.H = W[I0++] || R5.L = W[I1++];
		LOOP D4i40_17_fast7_1 LC0 = P4;
		LOOP_BEGIN D4i40_17_fast7_1;
			R3.H = R3.L = SIGN(R4.H)*R5.H + SIGN(R4.L) * R5.L || R5.H = W[I0++] || R5.L = W[I1++];
			W[I2++] = R3.L;
		LOOP_END D4i40_17_fast7_1;
        P4 = 40;
		I0 = B0;
		P4 -= P2;
		P2 = P5 + (P2 << 1);
		R4.L = 1;		
		I1 = P2;
		I2 = P2;
		R4.H = R1.L >> 0 || R5.H = W[I0++] || R5.L = W[I1++];
		LOOP D4i40_17_fast8_1 LC0 = P4;
		LOOP_BEGIN D4i40_17_fast8_1;
		     R3.H = R3.L = SIGN(R4.H)*R5.H + SIGN(R4.L) * R5.L || R5.H = W[I0++] || R5.L = W[I1++];
			 W[I2++] = R3.L;
		LOOP_END D4i40_17_fast8_1;
        P4 = 40;
		I0 = B0;
		P4 -= P3;
		P3 = P5 + (P3 << 1);
		R4.L = 1;		 
		I1 = P3;
		I2 = P3;
		R4.H = R1.H >> 0 || R5.H = W[I0++] || R5.L = W[I1++];
		LOOP D4i40_17_fast9_1 LC0 = P4;
		LOOP_BEGIN D4i40_17_fast9_1;
		     R3.H = R3.L = SIGN(R4.H)*R5.H + SIGN(R4.L) * R5.L || R5.H = W[I0++] || R5.L = W[I1++];
			 W[I2++] = R3.L;
		LOOP_END D4i40_17_fast9_1;
		 R7 = 0;
		 R6 = 15;
		 R4 = ROT R1 BY 1;
		 R7 = ROT R7 BY 1;
		 R4 = ROT R1 BY 17;
		 R7 = ROT R7 BY 1;
		 R4 = ROT R0 BY 1;
		 R7 = ROT R7 BY 1;
		 R4 = ROT R0 BY 17;
		 R7 = ROT R7 BY 1 || R5 = [FP-8];
		 R7 = R7 ^ R6;
		 R6.L = 6554;
		 R0.L = R5.L * R6.L, R0.H = R5.H * R6.L (T) || R4 = [FP-12];
		 R1.L = R4.L * R6.L, R1.H = R4.H * R6.L (T);		 
		 R6.H = 5;
		 R2 = R6.H * R1.H(IS);
		 R2 += 3;
		 R2.L = R4.H - R2.L(S);
		 R1.H = R1.H << 1(S);
		 R1.H = R1.H + R2.L(S);
		 R0.H = R0.H << 3(S);
		 R1.L = R1.L << 6(S);
		 R1.H = R1.H << 9(S);
		 R0.L = R0.L + R0.H(S);
		 R0.L = R0.L + R1.L(S);
		 R0.L = R0.L + R1.H(S);
		 R0 = PACK(R7.L,R0.L);
		 R5 = 0; //added code to make round mode bit 1
         ASTAT = R5;
		UNLINK;
		RTS;
_Pitch_fr3_fast:
	  .global _Pitch_fr3_fast;
      .type  _Pitch_fr3_fast,STT_FUNC;
	  LINK 20+80;
	  [FP-4] = R0;      // ADDRESS OF exc
	  [FP-8] = R1;      // t0_min t0_max
	  [FP-12] = R2;     // i_subfr
	  I3 = SP;
	  CALL _Cor_h_X;
      R7 = [FP-8];
	  R6.L = R7.H - R7.L(S) ||  R0 = [FP-4];
	  B0 = SP;
	  R6 = R6.L;
  	  R7 = R7.L;
  	  P0 = R6;
      R5 = R7 << 1;   
	  R6 = R7;
	  R0 = R0 - R5;
	  I3 = R0;
	  P0 += 1;
	  P1 = 40;
	  M0 = -84;
	  M1 = -88;
	  R5.H = MIN_32;          //0X8000;
	  R5.L = R0.L - R0.L (NS) || I3 -= 2;
	  I0 = B0;	   
	  I1 = I3;
	  R3.L = W[I1++];
/**************************************************
      for(t=t0_min; t<=t0_max; t++) {
         corr = Dot_Product(Dn, &exc[-t], L_subfr); L_temp = L_sub(corr, max);
         if(L_temp > 0) {max = corr; t0 = t;  }  }
****************************************************/	  
	  LOOP Pitch_fr3_fast1 LC0 = P0>>1;
	  LOOP_BEGIN Pitch_fr3_fast1;		  
		  A1 = A0 = 0 || R4 = [I0++] || R3.H = W[I1++];
		  LSETUP(Pitch_fr3_fast1_1,Pitch_fr3_fast1_2) LC1 = P1>>1;
          Pitch_fr3_fast1_1: A1 += R4.L * R3.L, A0 += R4.L * R3.H || R3.L = W[I1++];
          Pitch_fr3_fast1_2: R1 = (A1 += R4.H * R3.H), R0 = (A0 += R4.H * R3.L) || R4 = [I0++] || R3.H = W[I1++];
		  CC = R5 < R0;
		  IF CC R7 = R6;
		  R5 = MAX(R5,R0) || R0=[I0++M0] || I1 += M1;
		  R6 += 1;		  
		  CC = R5 < R1;
		  IF CC R7 = R6;
		  R5 = MAX(R5,R1) || R3.L = W[I1++];
		  R6 += 1;		  
	  LOOP_END Pitch_fr3_fast1;
	  		R0 = P0;
//	  		CC = BITTST(R0,0);
	  		R0 = ROT R0 BY -1;
	  		IF !CC JUMP Pitch_fr3_fast1_7;
		  	A0 = 0 || R4 = [I0++] || R3.L = W[I1++];
		  	LSETUP(Pitch_fr3_fast1_5,Pitch_fr3_fast1_6) LC1 = P1>>1;
          	Pitch_fr3_fast1_5: R0 = (A0 += R4.L * R3.L) || R3.L = W[I1++];
          	Pitch_fr3_fast1_6: R0 = (A0 += R4.H * R3.L) || R4 = [I0++] || R3.L = W[I1++];
		  	CC = R5 < R0;
		  	IF CC R7 = R6;
		  	R5 = MAX(R5,R0);
Pitch_fr3_fast1_7:	  		
	  		R6 = - R7;
	  		P5 = [FP-4];
	  		[FP-8] = R7;    // STORE t0;
	  		P3 = 0;
	  		P0 = 40;
	  		[FP-20] = R6;
	  		P4 = R6;
	  		CALL _Pred_lt_3; //Pred_lt_3(exc, t0, 0, L_subfr);
	  		P5 = [FP-4];
	  		I0 = SP;
	  		P0 = 40;  //max = Dot_Product(Dn, exc, L_subfr);	 	  
	  		LSETUP(Pitch_fr3_fast2,Pitch_fr3_fast2) LC0 = P0>>1;
	  		A1 = A0 = 0 || R7 = [P5++] || R6 = [I0++];
Pitch_fr3_fast2: A0 += R7.L * R6.L, A1 += R7.H * R6.H || R7 = [P5++] || R6 = [I0++]; 
	  		R0 = (A0 += A1) || R7 = [FP-12];
	  		CC = BITTST(R7,0);
	  		IF CC JUMP Pitch_fr3_fast3;
	      	R7 = [FP-8];
		  	R6 = 84;
		  	CC = R6 < R7;
		  	IF CC JUMP Pitch_fr3_fastEND;
Pitch_fr3_fast3:
         	P5 = [FP-4];   // exc
		 	I0.H = rri0i0;
		 	I0.L = rri0i0;		 
		 	[FP-16] = R0;  // max //Copy(exc, exc_tmp, L_subfr);
		 	R7 = [P5++];
		 	LSETUP(Pitch_fr3_fast4,Pitch_fr3_fast4) LC0 = P0>>1;
Pitch_fr3_fast4: 	MNOP || [I0++] = R7 || R7 = [P5++];
		  	P5 = [FP-4];
		  	P4 = [FP-20];
		  	P3 = 1;
//		  	P0 = 40;
		  	CALL _Pred_lt_3; //Pred_lt_3(exc, t0, -1, L_subfr);
		  //corr = Dot_Product(Dn, exc, L_subfr);
		  	P5 = [FP-4];
	  	  	I0 = SP;
    	  	P0 = 20;
	      	A0 = 0 || R1 = [FP-16];
    	  	A1 = 0 || R7 = [P5++] || R6 = [I0++];
	      	LSETUP(Pitch_fr3_fast5,Pitch_fr3_fast5) LC0 = P0;
Pitch_fr3_fast5: 	A0 += R7.L * R6.L, A1 += R7.H * R6.H || R7 = [P5++] || R6 = [I0++]; 
	      	R0 = (A0 += A1) || R2 = [FP-8];  // R1 = max
		  	R3 = ROT R2 BY 0 || P5 = [FP-4];    // exc
		  	R3.H = -1;
/***********************************************		  
		  if(L_temp > 0) {  max = corr; *pit_frac = -1; Copy(exc, exc_tmp, L_subfr); }
**************************************************/  
		  	CC = R1 < R0;
		  	IF !CC JUMP Pitch_fr3_fast5_2;		     
		    [FP-8] = R3;
			[FP-16] = R0;   // Update max
	        I0.H = rri0i0;
		    I0.L = rri0i0;
		    R7 = [P5++];
		    LSETUP(Pitch_fr3_fast5_1,Pitch_fr3_fast5_1) LC0 = P0;
Pitch_fr3_fast5_1: 	MNOP || [I0++] = R7 || R7 = [P5++];
Pitch_fr3_fast5_2:
		    P5 = [FP-4];
		    P4 = [FP-20];
		    P3 = -1;
		    P0 = 40;
		    CALL _Pred_lt_3;
 		    P5 = [FP-4];
	  	    I0 = SP;
    	    P0 = 20;    	     //corr = Dot_Product(Dn, exc, L_subfr);
            A0 = 0 || R1 = [FP-16];
    	    A1 = 0 || R7 = [P5++] || R6 = [I0++];
	        LSETUP(Pitch_fr3_fast6,Pitch_fr3_fast6) LC0 = P0;
Pitch_fr3_fast6: 	A0 += R7.L * R6.L, A1 += R7.H * R6.H || R7 = [P5++] || R6 = [I0++]; 
	        R0 = (A0 += A1) || R2 = [FP-8]; // R1 = max
		    I0.H = rri0i0;
		    I0.L = rri0i0;
	        R3 = ROT R2 BY 0 || R7 = [I0++] ||P5 = [FP-4];   // exc
		    R3.H = 1;
//		     L_temp = L_sub(corr, max);
//             if(L_temp > 0) { max = corr;  *pit_frac =  1; }
//             else  Copy(exc_tmp, exc, L_subfr);
		    CC = R1 < R0;
		    IF CC R2 = R3;
		    [FP-8] = R2;
		    IF CC JUMP Pitch_fr3_fastEND;		     		     
  		    LSETUP(Pitch_fr3_fast7,Pitch_fr3_fast7) LC0 = P0;
Pitch_fr3_fast7: 	MNOP || [P5++] = R7 || R7 = [I0++];
Pitch_fr3_fastEND:
      R0 = [FP-8];
	  UNLINK;
	  RTS;
.text;
.align 8;
_Autocorr:
	  .global _Autocorr;
      .type  _Autocorr,STT_FUNC;      
      P0 = -480;
      SP = SP + P0;  // B0 POINTS TO x B1 POINTS TO r
	  P0 = L_WINDOW;  //240;
	  B2.H = rri0i0;
	  B2.L = rri0i0;
	  I0 = B0;
	  I1.H = hamwindow;
	  I1.L = hamwindow;
	  I2 = B2;
	  R6=0x4000;
	  R6.H=1;
	  R7 = AUTOCORR_CONST1(Z);	  
//  for(i=0; i<L_WINDOW; i++) { y[i] = mult_r(x[i], hamwindow[i]); }  
	  A0=R6.H*R6.L,A1=R6.H*R6.L || R5 = [I0++] || R4 = [I1++];
	  LOOP Autocorr1 LC0 = P0 >> 1;
	  LOOP_BEGIN Autocorr1;	  
	  	R0.L = (A0 += R5.L * R4.L), R0.H = (A1 += R5.H * R4.H) (T) || R5 = [I0++] || R4 = [I1++];	  
	  	A0=R6.H*R6.L,A1=R6.H*R6.L || [I2++] = R0;
	  LOOP_END Autocorr1;
	  R7 = 1;
	  R6 = 0;
	  R3 = 1;       // *exp_R0 = 1;
//	  P1 = 8;
//	  LSETUP(Autocorr2,Autocorr2_3) LC1 = P1;
Autocorr2:
	  I2 = B2;      // I2 POINTS TO rri0i0 (y)
	  I0 = SP;
	  A0 = R7.L * R7.L, A1 = R7.H * R7.H (IS) || R5 = [I2++];
//	  A1 = 0;
	  LSETUP(Autocorr2_1,Autocorr2_1) LC0 = P0 >> 1;
      Autocorr2_1: A0 += R5.L * R5.L, A1 += R5.H * R5.H || R5 = [I2++] || [I0++]=R5;
	  A0 += A1 (W32);
	  CC = AV0;
	  IF !CC JUMP Autocorr3;
	  I0 = SP;
	  I1 = B2;
	  A1 = 0 || R5 = [I0++];
	  R4 = R5 >>> 2(V,S) || R5 = [I0++];
	  LSETUP(Autocorr2_2,Autocorr2_2) LC0 = P0 >> 1;
      Autocorr2_2:  R4 = R5 >>> 2(V,S) || R5 = [I0++] || [I1++] = R4;
Autocorr2_3:	  R3 += 4;
	  JUMP Autocorr2;
//  	norm = norm_l(sum);
//  	sum  = L_shl(sum, norm);
//  	L_Extract(sum, &r_h[0], &r_l[0]);     
//  	*exp_R0 = sub(*exp_R0, norm);
//  	for (i = 1; i <= m; i++) { sum = 0;
//    	for(j=0; j<L_WINDOW-i; j++) sum = L_mac(sum, y[j], y[j+i]);
//    	sum = L_shl(sum, norm);
//    	L_Extract(sum, &r_h[i], &r_l[i]); }
Autocorr3:
		R0=A0;
      I1 = B1;
      R7.L = SIGNBITS R0;	  
	  I0 = SP;	  
	  [--SP]=B2;
	  R0 = ASHIFT R0 BY R7.L || P2=[SP];
	  P1 = 10;
	  R0.L = R0.L >> 1;
	  P0 = 238;
	  R3.L = R3.L - R7.L(S) || [I1++] = R0;	  
	  I3 = I0;
		  A1 = 0 || R4 = [P2++] || R5 = [I3++];
	  LOOP Autocorr4 LC0 = P1>>1;
	  LOOP_BEGIN Autocorr4;
		  
		  A0 = R4.L * R5.H || R5 = [I3++];
		  LSETUP(Autocorr4_1,Autocorr4_2) LC1 = P0>>1;
Autocorr4_1: A1 += R4.L * R5.L , A0 += R4.H * R5.L || R4.L = W[P2];		  
Autocorr4_2: R1 = (A1 += R4.H * R5.H), R0 = (A0 += R4.L * R5.H) || R5 = [I3++] || R4 = [P2++];
		  P0 += -2;
			R0 = ASHIFT R0 BY R7.L(S)  || P2=[SP]; 
		  R1 = ASHIFT R1 BY R7.L(S) || I0 += 4; 
		  I3 = I0;
		  R0.L = R0.L >> 1 || R5 = [I3++];
		  R1.L = R1.L >> 1 || [I1++] = R0;
		  A1 = 0 || [I1++] = R1 || R4 = [P2++];		  
	  LOOP_END Autocorr4;
	   P0 = 480;
      SP = SP + P0;
      B2 = [SP++];
	  RTS;	  	  		
.global	_Chebps_11		; 
_Chebps_11:
      	R0.H = CHEBPS_CONST2;     //512;
	  	R1.H = CHEBPS_CONST1;     //b2_h = 256;256;
	  	R1.L = 0;                 //b2_l = 0;
	  	A1 = R0.H * R0.L || R3 = [I0++];//t0 = L_mult(x, 512);
	  	R4.H = 1;
	  	R0.H = CHEBPS_CONST3;     //4096;
	  	R4.L = CHEBPS_CONST4;     //-32768;
	  	R5 = (A1 += R3.H * R0.H); // t0 = L_mac(t0, f[1], 4096);  
	  	A1 = R1.H * R4.L(IS);
	  	R5.L = R5.L >> 1;         //L_Extract(t0, &b1_h, &b1_l);
	  	P0 = 3;                  	  	  	
		A1 -= R1.L * R4.H(IS); 
		LOOP Chebps_11_1 LC1 = P0;
	  	LOOP_BEGIN Chebps_11_1;	  	
	    	A1 += R5.H * R0.L, R2 = (A0 = R5.L * R0.L) || R3.L = W[I0++];	
			R1 = R5;
			A1 += R3.L * R0.H(IS);
			R5 = (A1 += R2.H * R4.H)(S2RND);
			A1 = R1.H * R4.L(IS);		
			R5.L = R5.L >> 1;
			A1 -= R1.L * R4.H(IS); 
	  	LOOP_END Chebps_11_1;	  	         
 		A0 = R1.H * R4.L;
      	A0 += R5.H * R0.L, R3 = (A1 = R5.L * R0.L) || R2.L = W[I0];	 	  
	  	A0 -= R1.L * R4.H;
	  	A0 += R3.H * R4.H;
	  	R2 = (A0 += R2.L * R0.H)(IS);
	  	NOP;
	  	R2 = R2 << 6(S);
	  	R0 = PACK(R2.H,R0.L);
	  	RTS;	  	  
.global _Chebps_10; 
_Chebps_10:
	  	R0.H = 256;
	  	R1.H = 128;
	  	R1.L = 0;
	  	A0 = R0.H * R0.L || R3 = [I0++];
	  	R5.H = 1;
	  	R0.H = 4096;
	  	R5.L = -32768;
	  	R4 = (A0 += R3.H * R0.H);
	  	A0 = R1.H * R5.L(IS);
	  	R4.L = R4.L >> 1;
	  	P0 = 3;	
		A0 -= R1.L * R5.H(IS);
		LOOP Chebps_10_1 LC1 = P0;
	  	LOOP_BEGIN Chebps_10_1;
	    	A0 += R4.H * R0.L, R2.H = (A1 = R4.L * R0.L) (T) || R3.L = W[I0++];		
			R1 = R4;
			A0 += R3.L * R0.H(IS);		
			R4=(A0 += R2.H * R5.H)(S2RND);
			A0 = R1.H * R5.L(IS);
			R4.L = R4.L >> 1;
			A0 -= R1.L * R5.H(IS);
	  	LOOP_END Chebps_10_1;	  
	  	A0 = R1.H * R5.L;
	  	A0 += R4.H * R0.L, R3 = (A1 = R4.L * R0.L) || R2.L = W[I0];	  	  
	  	A0 -= R1.L * R5.H ;
	  	A0 += R3.H * R5.H;	  
	  	R2 = (A0 += R2.L * R0.H)(IS);
	  	NOP;
	  	R2 = R2 << 7(S);	  
	  	R0 = PACK(R2.H,R0.L);
	  	RTS;	  	  
_Az_lsp:
	  .global _Az_lsp;
      .type  _Az_lsp,STT_FUNC;      
	  	LINK 8;	  
	  	P4 = B0;
	  	P5.H = _Chebps_11;
	  	P5.L = _Chebps_11;
	  	R7.H = 2048;
	  	R7.L = 16384;
	  	P4 += 20;        //P4 POINTS TO a[10]
  	  	I2 = B0;
	  	I0.H = rri0i0;   //f1
	  	I0.L = rri0i0;
	  	R6 = I0;
	  	B3 = I0;
	  	I1.H = rri1i1;   //f2
	  	I1.L = rri1i1;
	  	R4 = I1;
	  	I3 = P4;
	  	R6 = R6-|-R6 || [FP-4] = R6 || R0.L = W[I2++];
	  	R5 = 1;	  	  
      	P0 = CHEBPS_CNT;  //5;
	  	R2.L = R7.H >> 0  || R3.H = W[I2++];
   	  	R2.H = R7.H >> 0 || [FP-8] = R4 || R3.L = W[I3--];
   	  	ASTAT = R6;
		R6.L = 0x4000;
		LOOP Az_lsp1 LC0 = P0;
	  	LOOP_BEGIN Az_lsp1;
		 	A0=R3.H * R7.L, A1=R3.H * R7.L  || W[I0++] = R2.L;    
		 	R5.L = (A0+=R3.L * R7.L), R5.H=(A1-=R3.L * R7.L)(T) || R3.L = W[I3--] || W[I1++] = R2.H;
#ifdef FLAG533	  
			CC |= V;
#else		
	  		CC |= AV0;
#endif	  		 
			R2 = R5 +|- R2 (S) || R3.H = W[I2++];
#ifdef FLAG533	  
			CC |= V;
#else		
	  		CC |= AV0;
#endif	  		 
			
	  	LOOP_END Az_lsp1;	  	  
	  	W[I0++] = R2.L;
	  	R7 = R7 >>> 1(V,S) || W[I1++] = R2.H || P1 = [FP-8];     
	  	IF !CC JUMP Az_lsp3(bp);	  
	  	I2 = B0;               //I2 points to a[0]
		I0 = B3;
	  	I3 = P4;	  	
	  	P5.H = _Chebps_10;
	  	P5.L = _Chebps_10;	  	  		
	  	R4.H = R7.H >> 0 || R6.L = W[I3--] || I2 += 2;
      	r4.L = R7.H >> 0 || W[I0++] = R7.H || R6.H = W[I2++];	  	
	  	A0 = R6.H * R7.L, A1 = R6.H * R7.L ;
	  	LOOP Az_lsp2 LC0 = P0;	  	
	  	LOOP_BEGIN Az_lsp2;
		  	R2.L = (A0-=R6.L * R7.L), R2.H = (A1+=R6.L * R7.L) (T) || R6.H = W[I2++] || W[P1++] = R4; 
		  	R4 = R2 -|+ R4(S) || R6.L = W[I3--];
		  	A0 = R6.H * R7.L, A1 = R6.H * R7.L || W[I0++] = R4.H;		  
	  	LOOP_END Az_lsp2;
	  	W[P1++] = R4;
Az_lsp3:
      	I1 = B1;
      	P1 = 0;                   //nf = 0
	  	P3.H = grid;
	  	P3.L = grid;
	  	R0 = W[P3++](Z);              //xlow = grid[0]
	  	I0 = B3;
	  	CALL (P5);                 //ylow = (*pChebps)(xlow, coef, NC);
	  	R6 = R0;                   //R6.H = ylow R6.L = xlow	  
	  	P0 = 61;
	  	LSETUP(Az_lsp4,Az_lsp11)LC0=P0;
Az_lsp4:	R7 = ROT R6 BY 0 || R0 = W[P3++](Z);              //xlow = grid[j]
	  		I0 = B3;	  	
	  		CALL (P5);                 //ylow  = (*pChebps)(xlow,coef,NC);
	  		R6 = R0;
	  		R0 = R7.H * R6.H;          //L_temp = L_mult(ylow ,yhigh);
	  		CC = R0 <= 0;
	  		IF !CC JUMP Az_lsp10_1(bp);// if ( L_temp <= (Word32)0)
	  	
	      	R0 = R6 >>> 1(V,S);
		  	R1 = R7 >>> 1(V,S);
          	R0 = R0 +|+ R1(S);
		  	I0 = B3;		  
		  	CALL (P5);		  	
			R1 = R6.H * R0.H;
		  	CC = R1 <= 0;
		  	IF CC R7 = R0;
		  	IF !CC R6 = R0;
		  	R0 = R6 >>> 1(V,S);
		  	R1 = R7 >>> 1(V,S);
          	R0 = R0 +|+ R1(S);
		  	I0 = B3;		  	
		  	CALL (P5);		  	
			R1 = R6.H * R0.H;
		  	CC = R1 <= 0;
		  	IF CC R7 = R0;
		  	IF !CC R6 = R0;		  	
	  
        	R5 = R7 -|- R6(S);        
			R0 = R5 >> 16 || R3 = [FP-8];
			CC = R0 == 0;
			IF CC JUMP Az_lsp8;
			R4 = ABS R5(V);             //y   = abs_s(y);
			R3.L = SIGNBITS R4.H;       //exp = norm_s(y);
			R1.L = ASHIFT R4.H BY R3.L; //y   = shl(y, exp);
			R2=0;
			R2.H = 16383;             
			R1 = R1.L(X);      
       		P0 = 15;
       		DIVS(R2,R1);    // get sign bit
       		LSETUP(_LP_STW,_LP_STW)LC1=P0;
_LP_STW:  		DIVQ(R2,R1);          
          	R3.H = 20;
		  	R1 = R5.L * R2.L;
		  	R3.L = R3.L - R3.H(S);
		  	R1 = ASHIFT R1 BY R3.L(S);		  
			R1.H=0;
			r1.h=r1.l=sign(r0.h)*r1.h+sign(r0.l)*r1.l ; 		  
          	NOP;
		  	R0 = R6.H * R1.L;
		  	NOP;
		  	R0 = R0 >>> 11(S);
		  	R6.L = R6.L - R0.L(S) || R3 = [FP-8];
Az_lsp8:	R0 = ROT R6 BY 0 || W[I1++] = R6.L ;
		  	P1 += 1;		  
		  	R1 = P1;
		  	R1 = ROT R1 BY -1 || R2 = [FP-4];
		  	

			IF CC R2 = R3;
			I0 = R2;
			B3 = R2;            
			CALL (P5);
			R6 = R0;
Az_lsp10_1:  
            P0 = 10;
			CC = P1 < P0;
Az_lsp11:   IF !CC JUMP Az_lspEND;
			I2 = B2;
			I1 = B1;
			R0 = [I2++];
			LSETUP(Az_lsp12,Az_lsp12) LC0 = P0 >> 1;
			Az_lsp12: MNOP || [I1++] = R0 || R0 = [I2++];
Az_lspEND:
	  		UNLINK;
	  		RTS;
_Cor_h_X:
	  	.global _Cor_h_X;
      	.type  _Cor_h_X,STT_FUNC;
      	P0 = -160;
      	SP = SP + P0;
      	P5 = SP;
      	[--SP]=I0;
      	P4 = I0;
	  // I0 POINTS TO h
	  // I1 POINTS TO X
	  // I3 POINTS TO D
	  	B0 = I0;
	  	P1 = 38;
//     for (i = 0; i < L_SUBFR; i++) { s = 0;
//       for (j = i; j <  L_SUBFR; j++) s = L_mac(s, X[j], h[j-i]);
//       y32[i] = s; s = L_abs(s); L_temp =L_sub(s,max); if(L_temp>0L)  max = s; }  
	  	I2 = I1;              //X[]
	  	R7 = R7 -|- R7 || R5 = [P4++] || R4 = [I2++];
		LOOP Cor_h_X1 LC0 = P1 >> 1;
	  	LOOP_BEGIN Cor_h_X1;
		 	LSETUP(Cor_h_X1_1,Cor_h_X1_2) LC1 = P1 >> 1;
         		A0 = R5.L * R4.L, A1 = R5.L * R4.H || R4.L = W[I2];
Cor_h_X1_1: 	A0 += R5.H * R4.H, A1 += R5.H * R4.L || R5 = [P4++] || R4 = [I2++];
Cor_h_X1_2: 	A0 += R5.L * R4.L, R1 = (A1 += R5.L * R4.H) || R4.L = W[I2];
         	R0 = (A0 += R5.H * R4.H) || P4=[SP];
		 	R3 = ABS R0 || I1 += 4;
		 	I2 = I1;              //X[]
		 	R7 = MAX(R7,R3) || [P5++] = R0 ;          
		 	R3 = ABS R1 || [P5++] = R1;
		 	P1 += -2;
         	R7 = MAX(R7,R3)  || R5 = [P4++] || R4 = [I2++]; 
      	LOOP_END Cor_h_X1;
        A0 = R5.L * R4.L ,R1 = (A1=R5.L * R4.H);
        R0=(A0 += R5.H * R4.H) || [P5+4] = R1;		 
		R3 = ABS R0 || [P5] = R0;
		R7 = MAX(R7,R3) ;          
		R3 = ABS R1;
        R7 = MAX(R7,R3);
//       j = norm_l(max);
//       if( sub(j,16) > 0) j = 16; j = sub(18, j);
//       for(i=0; i<L_SUBFR; i++) D[i] = extract_l( L_shr(y32[i], j) );
       	R6.L = SIGNBITS R7;
	   	CC = R7 == 0;
	   	R5.L = 16;
	   	R5.H = 18;
	   	IF CC R6 = R7;
	   	I0 = SP;
	   	R6 = MIN(R6,R5)(V) || I0 +=4;
	   	P0 = 40;
	   	R6.L = R6.L - R5.H(S) || R4 = [I0++];
	   	R3 = ASHIFT R4 BY R6.L(S) || R4 = [I0++];
	  	LSETUP(Cor_h_X2,Cor_h_X2) LC0 = P0;
Cor_h_X2: 	R3 = ASHIFT R4 BY R6.L(S) || R4 = [I0++] || W[I3++] = R3.L;  
       	P0 = 164;
       	SP = SP + P0;
	  	RTS;	  
