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
Title:			lpc
Description     :      coder lpc related functions
Prototype       :      _Levinson()
			_Lsp_lsf()
			_Lsp_lsf2()

*******************************************************************************/

#include "G729_const.h"
.extern old_A ;
.extern old_rc ;         
.extern rri0i1 ;             
.extern rri0i2 ;            
.extern slope  ;        
.extern slope_acos ;
.extern table ;           
.extern  table2; 
//.extern Levinson2_0;
.text;
.align 8;
_Levinson:
	  .global _Levinson;
      .type  _Levinson,STT_FUNC;
	  LINK 48;
	  //*** [FP-4] = K
	  //*** [FP-8] = alp
	  //*** [FP-12] = alp_exp
	  //*** [FP-16] = t0
	  //*** B0 = ADDRESS OF Rh AND Rl
	  //*** B1 = ADDRESS OF A
	  //*** B2 = ADDRESS OF rc
	  	I0 = B0;
	  	R2 = R2 -|- R2 || R1 = [I0++];
	  	R6 = I0;
	  	R5 = R1 >> 16  || R7 = [I0--];	  
	  	R7.L = R7.L << 1 || [FP-36]=R6;
	  	R2.H = 0X3FFF;	   			   	   		          	  	  	  	 
	  	R0 = ABS R7 || [FP-40]=R2;
	   	P0 = 15;      
       	DIVS(R2,R5);            // get sign bit
       	LSETUP(_LP_ST,_LP_ST)LC1=P0;
_LP_ST:  	DIVQ(R2,R5);
	   	R3 = 1;
	   	A0 = R1.H * R2.L, R5 = (A1 = R1.L * R2.L) || P2=[FP-36];
	   	R1.H = MAX_NO2; //0X7FFF;	  
	   	R4 = (A0 += R5.H * R3.L);
	   	R1.L = MAX_NO1; //0XFFFF;
	   	R6 = R1 - R4(S)|| [FP-20]=R1;
	   	R6.L = R6.L >> 1;
	   	R4.H = rri0i1 + 4;              // A	  
		R4.L = rri0i1 + 4;
	   	A0 = R6.H * R2.L, R5 = (A1 = R6.L * R2.L);
	   	R6 = (A0 += R5.H * R3.L) || [FP-32] = R4;
	   	R0.L = R0.L >> 1;
	   	R6.L = R6.L >> 1;
	   	I3 = B2;                    // I3 OINTS TO rc
	   	R1.L = R6.L * R0.H, R1.H = R6.H * R0.L (T) ;	   
	   	A0 = R6.H * R0.H; 	   
	   	A0 += R1.L * R3.L;
	   	R0 = (A0 += R1.H * R3.L) || P3=[FP-32];		
	   	P1 = 1;                     // SECONDE LOOP TIMES
	   	R2 = R0 << 2(S) || R7 = [P2++];    	   
	  	R1 = - R2;	  
	  	CC = R7 <= 0;
	  	IF !CC R2 = R1;             //if(t1 > 0) t0= L_negate(t0);
	  	R0 = R2 >>> 4(S) ;           //t0 = L_shr(t0,4);
	  	R2.L = R2.L >> 1 || W[I3++] = R0.H;	 	  
	  	R0.L = R0.L >> 1;
	  	A0 = R2.H * R2.H, R5 = (A1 = R2.H * R2.L) || [P3] = R0;	  
	  	R5.L = LEVINSON_CONST1;     //2
	  	R0 = (A0 += R5.H * R5.L)  || [FP-4] = R2;	  
	  	R0 = ABS R0 || R1 = [FP-20];	  
	  	R6 = R1 - R0(S) || R7 = [I0++];
	  	R6.L = R6.L >> 1 || P5=[FP-36];
	  	R4.H = rri0i2 + 4;
	  	R4.L = rri0i2 + 4;
	  	A0 = R7.H * R6.H, R5 = (A1 = R7.H * R6.L) || [FP-48]=R5;
	  	R0 = R7.L * R6.H || [FP-28] = P3;   	  	  
	  	A0 += R5.H * R3.L || [FP-24] = R4;
	  	R0 = (A0 += R0.H * R3.L) || [FP-44]=R3;
	  	P0 = 9;//M-1;                   //9 FIRST LOOP TIMES
	  	R4.L = SIGNBITS R0 || R7 = [P5++];
	  	R1 = ASHIFT R0 BY R4.L ;
	  	R1.L = R1.L >> 1 || [FP-12] = R4;		  
	  LOOP Levinson1 LC0 = P0;
	  LOOP_BEGIN Levinson1;
			A1 = A0 = 0 || R6 = [P3--];  
			LOOP Levinson1_1 LC1 = P1;
			LOOP_BEGIN Levinson1_1;		     
			 	R4.L = R7.L * R6.H , R4.H = R7.H * R6.L (T);
			 	A0 += R7.H * R6.H || R7 = [P5++] ;
			 	A0 += R3.L * R4.H, A1 += R3.L * R4.L || R6 = [P3--];
			LOOP_END Levinson1_1;
			R0 = (A0+=A1) || R4 = [FP-20];			 						
	   		R5 = R1 >> 16 || R2 = [FP-40];	   
	   		P0 = 15;
       		DIVS(R2,R5);            // get sign bit
       		LSETUP(_LP_ST_Levinson,_LP_ST_Levinson)LC1=P0;
_LP_ST_Levinson:  DIVQ(R2,R5);
			A0 = R4 || R7 = [P2++];	   		
	   		A0 -= R1.H * R2.L, R5 = (A1 = R1.L * R2.L) || P3=[FP-28];
			R7.L = R7.L << 1;
	   		R4 = (A0 -= R5.H * R3.L);
			R0 = R0 << 4(S) || [FP-8] = R1;		
	   		R4.L = R4.L >> 1;	   
	   		R0 = R0 + R7(S) ;
	   		A0 = R4.H * R2.L, R5 = (A1 = R4.L * R2.L);		
	   		R0 = ABS R0 || [FP-16] = R0;
	   		R4 = (A0 += R5.H * R3.L);
	   		R0.L = R0.L >> 1;
	   		R4.L = R4.L >> 1;			   		 
	   		R5 = LEVINSON_CONST2;       //32750;
	   		R1.L = R4.L * R0.H, R1.H = R4.H * R0.L (T);	   
	   		A0 = R4.H * R0.H; 	  
	   		A0 += R1.L * R3.L || R4 = [FP-48];	   	
	   		R0 = (A0 += R1.H * R3.L) (S2RND) || R6 = [FP-12];		
			R6 += 1;    
			R6 = ASHIFT R0 BY R6.L(S) || R7 = [FP-16];
			
			R1 = - R6 ;
			CC = R7 <= 0;
			IF !CC R6 = R1;
			R2 = R6 >>> 4 (S) || R7 = [P3--];
			R6.L = R6.L >> 1 || W[I3++] = R6.H;						
			R1 = ABS R6 (V) || [FP-4] = R6;
			R1 = R1 >> 16 || P0 = [FP-32];
			CC = R1 <= R5;
			IF !CC JUMP Levinson2_0 ;
			A0 = R6.H * R6.H, R4.H = (A1 = R6.H * R6.L) (T) || R3=[FP-44];
			A1 = R7.H * R6.H || P4 = [FP-24];			  
			LOOP Levinson1_4 LC1 = P1;
			LOOP_BEGIN Levinson1_4;			   
			   	R1.L = R7.H * R6.L , R1.H = R7.L * R6.H (T) || R7 = [P0++];
			   	R7.L = R7.L << 1;
 			   	A1 += R1.H * R4.L(IS);			   
			   	R1 = (A1 += R1.L * R4.L)(IS);
			   	R0 = R1 + R7(S);
			   	R0.L = R0.L >> 1 ||  R7 = [P3--];
			   	A1 = R7.H * R6.H  || [P4++] = R0;			   	
			LOOP_END Levinson1_4;
			R2.L = R2.L >> 1 || P3=[FP-28];
			R0 = (A0 += R4.H * R4.L) || [P4] = R2 ;			
			R0 = ABS R0 || R1 = [FP-20];
			R6 = R1 - R0(S) || R7 = [FP-8];    // alp
			R6.L = R6.L >> 1 || P5=[FP-36];
			P1 += 1;
			A0 = R6.H * R7.H, R1 = (A1 = R6.H * R7.L)||P4=[FP-24];
 		    R5 = R6.L * R7.H || R0 = [P3++];
			A0 += R1.H * R4.L(IS) || [FP-28]=P3;
			R0 = (A0 += R5.H * R4.L)(IS) || R7 = [FP-32];
			I1 = R7;
			R6.L = SIGNBITS R0 || R4 = [P4++];                    //j = norm_l(t0);
			R1 = ASHIFT R0 BY R6.L || R5 = [FP-12];//t0 = L_shl(t0, j);
			R5.L = R6.L + R5.L(S) || R7=[P5++];
			R1.L = R1.L >> 1 || [FP-12] = R5;		    
			LSETUP(Levinson1_5,Levinson1_5) LC1 = P1;
            Levinson1_5: MNOP || [I1++] = R4 || R4 = [P4++];
	  LOOP_END Levinson1;
	  		[FP-8] = R1 ;
		JUMP Levinson2;
Levinson2_0:
		    P0 = 6;
			I0.H = old_A;
			I0.L = old_A;
			I1 = B1;
			I2.H = old_rc;
			I2.L = old_rc;
			R7 = [I0++];
			LSETUP(Levinson1_2,Levinson1_2) LC1 = P0;
Levinson1_2: 	MNOP || [I1++] = R7 || R7 = [I0++];
			I0 = B2;
			R7 = [I2++];
			[I0] = R7;			 
Levinson2:
			P5 = [FP-32];
          	R7 = 4096;
		  	I1 = B1;
	      	P0 = 10;
		  	I2.H = old_A + 2;
		  	I2.L = old_A + 2;
		  	R6 = [P5++] ;
/************************************************		  
		  for(i=1; i<=M; i++) { t0   = L_Comp(Ah[i], Al[i]);
           old_A[i] = A[i] = round(L_shl(t0, 1)); }
*************************************************/  
		  	R6.L = R6.L << 1 || W[I1++] = R7.L;
		  	R0 = R6 << 1(S) || R6 = [P5++];
		  R0.L = R0(RND)  || R7 = [FP-12];	
		 LOOP Levinson3 LC0 = P0;
		 LOOP_BEGIN Levinson3;
		 	R6.L = R6.L << 1   || W[I1++] = R0.L;
		 	R0   = R6 << 1(S)  ||  W[I2++] = R0.L;
		 	R0.L = R0(RND)     || R6 = [P5++];
		 LOOP_END Levinson3;
		    I0 = B2;
			I1.H = old_rc;
			I1.L = old_rc;			 		 
			R7 = - R7(V) || R6 = [FP-8] || R4 = [I0]; 
			R0.L = ASHIFT R6.H BY R7.L(S) || [I1] = R4;
            UNLINK;
	        RTS;

.text;
.align 8;
_Lsp_lsf:
	   .global _Lsp_lsf;
      .type  _Lsp_lsf,STT_FUNC;
	  M0 = 18;
	  P2.H = table + 126;
	  P2.L = table + 126;
	  P1.H = slope + 126;
	  P1.L = slope + 126;
	  I0 += M0;  
	  R6.H = W[I0--] || I1 += M0; 
	  P5 = 64;
	  R7 = W[P2--](Z);
	  LOOP Lsp_lsf_1 LC0 = P0;
	  LOOP_BEGIN Lsp_lsf_1;
	   LSETUP(Lsp_lsf_1_1,Lsp_lsf_1k2) LC1 = P5;
Lsp_lsf_1_1: 	P5 += -1;
		 		R6.L = R6.H - R7.L(S) || R4 = W[P1--](Z);
		 		R5 = ROT R6 BY 17 || R7 = W[P2--](Z);
Lsp_lsf_1k2:	IF CC JUMP Lsp_lsf_1_2;
Lsp_lsf_1_2:    R0 = R6.L * R4.L;
        		R5 = P5;
				R0 = R0 << 3(S);
				R5.L = R5.L << 8(S);
				R0.L = R0(RND);
				R0.L = R5.L + R0.L(S)||R6.H = W[I0--]; 
				W[I1--] = R0.L;
	  LOOP_END Lsp_lsf_1;
	  RTS;

	  _Lsp_lsf2:
	  .global _Lsp_lsf2;
      .type  _Lsp_lsf2,STT_FUNC;
      SP += -4;
	  M0 = 18;
	  P5 = LSPLSF_CONST1 * 2;   //63;
	  P4.H = table2;
	  P4.L = table2;
	  P3.H = slope_acos;
	  P3.L = slope_acos;	  
	  I0 += M0;	  
	  R3.L = 25736;	  
/***************************************************************	 
  for(i= m-(Word16)1; i >= 0; i--)  {
    //find value in table2 that is just greater than lsp[i] 
    while( sub(table2[ind], lsp[i]) < 0 ) { ind = sub(ind,1);
      if ( ind <= 0 ) break; }
    offset = sub(lsp[i], table2[ind]);
    // acos(lsp[i])= ind*512 + (slope_acos[ind]*offset >> 11) 
    L_tmp  = L_mult( slope_acos[ind], offset ); 
    freq = add(shl(ind, 9), extract_l(L_shr(L_tmp, 12)));
    lsf[i] = mult(freq, 25736);           
  } 
******************************************************************/	  
      R7.H = W[I0--] || I1 += M0;  
      P2 = P4 + P5 ;
      R5 = W[P2--](Z);
//      R0 = W[P3](Z);
      P1 = 64;
      LOOP Lsp_lsf2_1 LC0 = P0;
//      P0 = -2;
	  LOOP_BEGIN Lsp_lsf2_1;	    		  		  
	  	LSETUP(Lsp_lsf2_1_1,Lsp_lsf2_1_2) LC1 = P1;
//	  	P1 = -2;
Lsp_lsf2_1_1:   
          R6.L = R7.H - R5.L(S) ;
		  R2 = ROT R6 BY 17 || R5 = W[P2--](Z);
		  IF CC JUMP Lsp_lsf2_1_3;
//		  		 R0=W[P3--](Z);
Lsp_lsf2_1_2: 	 P5 += -2;
Lsp_lsf2_1_3:   
			
		  	R4 = P5;  	  	
		  	P1 = P3 + P5;
		  	R1.L = R4.L << 8 (S) || R0.L = W[P1];
//		  	P3 = [SP];
		  	R0 = R0.L * R6.L ;
		  	P2 = P4 + P5;
		  	R0 = R0 >>> 12(S) ;
		  	R3.H = R1.L + R0.L(S) ||   R7.H = W[I0--];// || R0=W[P3--](Z);
			P1 = 64;	
		  	R2 = R3.H * R3.L || R5 = W[P2--](Z);
		  	W[I1--] = R2.H;
      LOOP_END Lsp_lsf2_1;
      SP += 4;
	  RTS;
