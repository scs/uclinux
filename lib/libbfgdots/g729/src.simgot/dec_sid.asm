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
// *** Author: Xiangzhi,wu   xiangzhi.wu@analog.com    2001/03/19	       ***
// *** Performance:                       								   ***
// ****************************************************************************
//#include "proc_select.h"

//.extern Az_dec;              
//.extern Az_dec_1;            
.extern D_L_exc_err;         
.extern D_exc;               
.extern D_freq_prev;         
.extern D_lsp_old;           
.extern D_noise_fg;          
.extern D_noise_fg_1;        
.extern D_past_ftyp;         
.extern D_seed;              
.extern D_sh_sid_sav;        
.extern D_sid_sav;           
.extern Dec_sid_cur_gain;    
.extern Dec_sid_sid_gain;    
.extern PtrTab_1;            
.extern PtrTab_2_0;          
.extern PtrTab_2_1;          
.extern _Calc_exc_rand;      
.extern _Int_qlpc;           
.extern _Lsf_lsp2;           
.extern _Lsp_prev_compose;   
.extern _Lsp_stability;      
//.extern _Qua_Sidgain;        
.extern _Log2;
.extern lspSid;              
.extern lspcb1;              
.extern lspcb2;              
.extern noise_fg_sum;        
.extern noise_fg_sum_1;      
.extern tab_Sidgain;         


.text;
.align 8;

_DQua_Sidgain:

	  LINK 4;
	  // P5 POINTS TO ener
	  // I0 POINTS TO sh_ener
	  // R1 = nb_ener
	  		
       		R3.L = W[I0++];       		
       		R0 = W[P5](X);
	  		R3 = ASHIFT R0 BY R3.L(S);
		 	R1.L = 410;
		 	R2 = (A0 = R3.H * R1.L), R3 = ( A1 = R3.L * R1.L) (m);
		 	R7 = 1024;		 		 
		 	R6.H = 1;
		 	R0 = (A0 += R6.H * R3.H);
           	CALL _Log2;                             		   	
		   	//R2 = R7.L * R0.L, R3 = R7.L * R0.H (m); 
		   	R2 = (A0 = R7.L * R0.L), R3 = ( A1 = R7.L * R0.H) (m); 
		   	R4.L = -12;
		   	R2.L = R2 (RND);
		   	R2.L = R2.L + R3.L(S);   
		   	R3 = -2721;
		   	R2  = R2.L(X);
		   	CC = R2 <= R3;			
			R4.H = 0;
			IF CC R0 = R4;
            IF CC JUMP DQua_SidgainEND;
			R3 = 22111;
			CC = R3 < R2;
			R4.L = 66;
			R4.H = 31;
			IF CC R0 = R4;
            IF CC JUMP DQua_SidgainEND;
            R3 = 4762;
			CC = R2 <= R3;
			IF !CC JUMP DQua_Sidgain6;
			R0.L = 3401;					   
			R2.L = R2.L + R0.L(S);
			R0.H = 192;
			R3.H = 1;
			R0 = R2.L * R0.H (IS);
			R0 = MAX(R0,R3)(V);
			
	  		JUMP DQua_SidgainEND;
DQua_Sidgain6:
            R0.L = -340;			
			R2.L = R2.L + R0.L(S);
			R0.H = 193;
			R0 = R2.L * R0.H (IS);
			R3.H = 6;
			R4.L = 1;
			R0.H = R0.H >>> 1 (S);
			R0.H = R0.H - R4.L(S);
			R0 = MAX(R0,R3)(V);
DQua_SidgainEND:
			R0 = R0 >> 16;
		 	P4 = R0;
      		UNLINK;
	  		RTS;

_Dec_cng:
	   		.global _Dec_cng;
      		.type  _Dec_cng,STT_FUNC;
	  		LINK 8;
	  		[FP-8] = R7;
	  		[FP-4] = P5;   // P5 POINTS TO parm[1]
	  		P4 = 8;
	  		P5 += -2;
	  		R7 = W[P5++P4](Z);
	  		
	  		CC = R7 == 0;	  	
	  		IF CC JUMP Dec_cng2;
	     	R7 = W[P5](Z);
	     	P2 = R7;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+136]; // Dec_sid_sid_gain
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P2;
	P2 = M2;
	R0 = [P2+520]; // tab_Sidgain
	P3 = R0
	P2 = [SP++];
	R0 = [SP++];
		 	P3 = P3 + (P2 << 1);
		 	R6.L = W[P3];
		 	MNOP || W[I1] = R6.L || P5 = [FP-4];
		 	CALL _sid_lsfq_decode;
		 	JUMP Dec_cng3;
Dec_cng2:
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+120]; // D_past_ftyp
	P0 = R0
	P3 = [SP++];
	R0 = [SP++];
		 	R7 = W[P0](Z);
		 	CC = R7 == 1;
		 	IF !CC JUMP Dec_cng3;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+148]; // D_sid_sav
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+128]; // D_sh_sid_sav
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
		 	CALL _DQua_Sidgain;
		 		
	[--SP] = R0;
	[--SP] = P2;
	P2 = M2;
	R0 = [P2+520]; // tab_Sidgain
	P3 = R0
	P2 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+136]; // Dec_sid_sid_gain
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
		 	P3 = P3 + (P4 << 1);
		 	R7.L = W[P3];
		 	W[I1] = R7.L;
Dec_cng3:
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+120]; // D_past_ftyp
	P0 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+136]; // Dec_sid_sid_gain
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+124]; // Dec_sid_cur_gain
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
		 R4.H = 1;
		 R4.L = 0x4000;
		 R6.H = 28672;
		 R6.L = 4096;
		 A0 = R4.L * R4.H, A1 = R4.H * R4.L || R5.L = W[I0];
		 R5.H = W[I1];
		 R0 = (A0 += R5.H * R6.H), R1 = (A1 += R5.L * R6.L) || R2 = W[P0](Z);
		 CC = R2 == 1;		 		             		 						
			R0.L = R0.H + R1.H(S);
			IF CC R0 = R5;
        R0.H = R0.H - R0.H (NS) || W[I1] = R0.L;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+24]; // D_exc
	R1 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+144]; // D_seed
	R2 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+100]; // D_L_exc_err
	B0 = R0
	P3 = [SP++];
	R0 = [SP++];
		CALL _Calc_exc_rand;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+92]; // D_lsp_old
	B0 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+88]; // lspSid
	B1 = R0
	P3 = [SP++];
	R0 = [SP++];
		R7 = [FP-8];
		B2 = R7;
		R7 += 24;
		B3 = R7;
		CALL _Int_qlpc;
		I0 = B1;
		I1 = B0;
		P0 = 5;
		R7 = [I0++];
		LSETUP(Dec_cng6,Dec_cng6) LC0 = P0;
Dec_cng6: 	MNOP || [I1++] = R7 || R7 = [I0++];
      	UNLINK;
	  	RTS;


_sid_lsfq_decode:
	   .global _sid_lsfq_decode;
	  	LINK 44;
	  	[FP-4] = P5;
	  	P5 += 2;	  
	  	R7 = W[P5++](Z);	  
	  	P3 = R7;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+564]; // lspcb1
	R3 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+500]; // PtrTab_1
	P4 = R0
	P3 = [SP++];
	R0 = [SP++];
	  	P3 = P4 + (P3 << 1);
	  	R7.L = 10;
	  	A1 = R3 || R6.L = W[P3];
	  	R1 = (A1+=R7.L * R6.L) || R5 = W[P5](Z);
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+504]; // PtrTab_2_0
	P4 = R0
	P3 = [SP++];
	R0 = [SP++];
	  	P5 = R1;
	  	P3 = R5;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+508]; // PtrTab_2_1
	P2 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R1;
	[--SP] = P3;
	P3 = M2;
	R1 = [P3+568]; // lspcb2
	R0 = R1
	P3 = [SP++];
	R1 = [SP++];
	  	A1 = R0 || R4 = [P5];
	  	P4 = P4 + (P3 << 1);
	  	P2 = P2 + (P3 << 1);
	  	A0 = R0 || R5.H = W[P4];
	  		R3 = (A1+=R5.H * R7.L) || R5.L = W[P2];
	  		I1 = R3;	  		  
	  		R7.H = 16384;
	  		P1 = 7;	  	
	  		P0 = 20;
	  		P0 = SP + P0;
	  		B0 = P0;
//	  		I0 = P0;
//	  		I3 = B0;	  	
	  		R2 = (A0+=R5.L * R7.L)  || R6 = [I1++];	  		 	  	
			R2 += 10;
	  		I2 = R2;
			R6 = R4 +|+ R6(S)  || R1 = [I1++] || R5 = [P5+4];
			R4 = R5 +|+ R1(S)  || [SP+20] = R6 ;	
      		A0 = R7.L * R7.H, A1 = R7.L * R7.H || R5 = [P5+8];
      		A0 += R6.L * R7.H, A1 += R6.L * R7.H || R1 = [I1];
      		I1 = B0;
		    R0.L = (A0 -= R6.H * R7.H), R0.H = (A1 -= R6.H * R7.H)(T) || R1.H = W[I2++];		   
		    R2 = R5 +|+ R1(S) || [SP+24] = R4 ;
			R4 = R6 +|- R0 (S) || R1 = [I2++] || I1 += 4;
			R0 = ROT R0 BY 17  || R5 = [P5+12];
            IF ! CC R6 = R4;    	    
            [SP+28] = R2 || R1 = R5 +|+ R1(S) ; 
    	    W[P0++] = R6 || R6.L = R6.H >> 0 ;
    	    A0 = R7.L * R7.H, A1 = R7.L * R7.H || R2 = [I2];
    		A0 += R6.L * R7.H, A1 += R6.L * R7.H || R6.H = W[I1++];
		    R0.L = (A0 -= R6.H * R7.H), R0.H = (A1 -= R6.H * R7.H)(T) || R5 = [P5+16];		   
		    R2 = R5 +|+ R2(S)  || P3 = [FP-4] ;
			[SP+32] = R1 || R4 = R6 +|- R0 (S)  ;
			[SP+36] = R2 || R0 = ROT R0 BY 17   ;
            IF ! CC R6 = R4;    	                
    	    W[P0++] = R6 || R6.L = R6.H >> 0 ;
    	    A0 = R7.L * R7.H, A1 = R7.L * R7.H || R1 = W[P3](Z);	 
	  	LOOP sid_lsfq_decode4 LC0 = P1;
	  	LOOP_BEGIN sid_lsfq_decode4;	 	  		
		   			A0 += R6.L * R7.H,          A1 += R6.L * R7.H || R6.H = W[I1++];
		    R0.L = (A0 -= R6.H * R7.H), R0.H = (A1 -= R6.H * R7.H)(T);		   
			R4 = R6 +|- R0 (S);
			R0 = ROT R0 BY 17;
            IF ! CC R6 = R4;    	    
    	    W[P0++] = R6 || R6.L = R6.H >> 0 ;
    	    A0 = R7.L * R7.H, A1 = R7.L * R7.H ;
	  LOOP_END sid_lsfq_decode4;	  	  		  		 		  			  		
	  		P5 = SP;	  		
	  		R7 = ROT R1 BY -1 || W[P0] = R6.L;	
	  		I0 = B0;
	[--SP] = R0;
	[--SP] = P2;
	P2 = M2;
	R0 = [P2+72]; // D_noise_fg
	P3 = R0
	P2 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+512]; // noise_fg_sum
	R6 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+76]; // D_noise_fg_1
	P4 = R0
	P3 = [SP++];
	R0 = [SP++];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+516]; // noise_fg_sum_1
	R7 = R0
	P3 = [SP++];
	R0 = [SP++];
	  	 	IF CC P3 = P4;
	  	 	IF CC R6 = R7;
	  	 	I1 = R6;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+80]; // D_freq_prev
	P4 = R0
	P3 = [SP++];
	R0 = [SP++];
		 	CALL _Lsp_prev_compose;
		 	P3 = 76;
		 	I3 = P4;
		 	P3 = P4 + P3;
		 	P4 += 56;
		 	I2 = SP;
	  		P1 = SP;    
	  		P0 = 7;
	  		R5.L = 40;
	  		R5.H = 321;
	  		R2 = [P1];
	  		R1.H = R2.H - R2.L(S) || I2+=4;//
	  		R7 = ROT R1 BY 1 || R4 = [P1];
	  		R3 = PACK(R2.L, R2.H)|| R1.L = W[I2++];
		    IF CC R4 = R3;
			R1.H = R1.L - R2.L(S) || R0 = [P4--];
			R7 = MAX(R4,R5)(V) || [P3--] = R0;	   
	  		R4 = PACK(R1.L, R4.H) || R0 = [P4--];	  	  		
	  LOOP Lsp_stability1 LC0 = P0;
	  LOOP_BEGIN Lsp_stability1;
      	   R3 = ROT R1 BY 1 || [P3--] = R0 ;
		   R3 = PACK(R2.L, R1.L)|| R1.L = W[I2++];
		   IF CC R4 = R3;
		   R1.H = R1.L - R2.L(S) || R0 = [P4--];
		   R6.L = R7.L + R5.H(S)|| [P3--] = R0 ;
		   R7 = MAX(R4,R6)(V)|| W[P1++] = R7; 
	       R4 = PACK(R1.L, R4.H) || R0 = [P4--];
	   LOOP_END Lsp_stability1;	          
	   		R0 = [SP+20];	   
	   		R3 = ROT R1 BY 1 || [I3++] = R0 || R0 = [SP+24];
		   	R3 = PACK(R2.L, R1.L)|| R1.L = W[I2++];
		   	IF CC R4 = R3;
		   	R1.H = R1.L - R2.L(S) || [I3++] = R0 || R0 = [SP+28];
		   	R6.L = R7.L + R5.H(S) || [I3++] = R0 || R0 = [SP+32];
		   	R7 = MAX(R4,R6)(V)|| W[P1++] = R7; 
	       	R4 = PACK(R1.L, R4.H) || [I3++] = R0 || R0 = [SP+36];
      		R6.L = R7.L + R5.H(S) || R1 = W[P1+2](Z);
	  		R7 = MAX(R1,R6)(V)|| W[P1++] = R7; 	  
	  		R1.L = 25681;
	  		R1 = MIN(R1,R7)(V) || [I3++] = R0;
	  		W[P1] = R1.L;	  			  
		 	I0 = SP;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+88]; // lspSid
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
	     	P0 = 10;
	     	CALL _Lsf_lsp2;
	  		UNLINK;
	  		RTS;
