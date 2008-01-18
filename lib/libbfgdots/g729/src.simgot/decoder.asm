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
$RCSfile: Decoder.asm,v $
$Revision: 1.4 $
$Date: 2006/05/24 07:46:55 $

Project:		G.729AB for Blackfin
Title:			Coder
Author(s):		wuxiangzhi,
Revised by:		E. HSU

Description     :      Deoder Entry with diverse input formats 

Prototype       :      	_G729AB_DEC_PROCESS()												

******************************************************************************
Tab Setting:			4
Target Processor:		ADSP-21535
Target Tools Revision:	2.2.2.0
******************************************************************************

Modification History:
====================
$Log: Decoder.asm,v $
Revision 1.4  2006/05/24 07:46:55  adamliyi
Fixed the failing case for g729ab decoder for tstseq6. The issue is the uClinux GAS bug: it cannot treat the (m) option correctly.

Revision 1.4  2004/01/27 23:40:52Z  ehsu
Revision 1.3  2004/01/23 00:40:06Z  ehsu
Revision 1.2  2004/01/13 01:33:59Z  ehsu
Revision 1.1  2003/12/01 00:12:30Z  ehsu
Initial revision

Version         Date            Authors        		  Comments
0.0         11/19/2002          wuxiangzhi            Original

*******************************************************************************/ 

.extern Input_Format;//_parm;
.extern _Decod_ld8a;                 
.extern _Decoder_Buffer_Memory;                                          
.extern _Decoder_Memory_Buffer;                                          
.extern _Post_Filter;                                                 
.extern _Post_Process;                                  
.extern _bits2prm_ld8k;                                   
.extern synth;                       
.extern _ebitsno;    
.extern _ebitsno2;    
   
.data;
.global imap1;
#if defined(__GNUC__)
imap1:
.short 5, 1, 7, 4, 2, 0, 6, 3;
#else
.byte2 imap1[8] = 5, 1, 7, 4, 2, 0, 6, 3;
#endif


.global imap2;
#if defined(__GNUC__)
imap2:
.short 2,14, 3,13, 0,15, 1,12, 6,10, 7, 9, 4,11, 5, 8;
#else
.byte2 imap2[16] = 2,14, 3,13, 0,15, 1,12, 6,10, 7, 9, 4,11, 5, 8;
#endif

.type	_G729AB_DEC_PROCESS, STT_FUNC ; 
.text;
.align 8;
_G729AB_DEC_PROCESS:
	  .global _G729AB_DEC_PROCESS;
	  LINK 24;	  

#if defined(FDPIC)	
	  M2 = P3;  /* M2 used to store GOT table offset */
#endif
		
	  [--SP] = (R7:4,P5:3);
	  P5 = -80;
	  SP = SP + P5;
	  SP = SP + P5;
	  [FP-24]=SP;//wxzcode
	  SP = SP + P5;
	  [FP-20]=SP;//xn2
	  SP += -48;
	  [FP-16]=SP;
	  SP += -28;
  	  [FP-4] = R2;    // OUTPUT BUFFER 
	  [FP-8] = R1;    // INPUT BUFFER
	  [FP-12] = R0;   // THE CURRENT CHANNEL POINTER
	  R0=[FP-12];
	  CALL _Decoder_Buffer_Memory;
		P1=[FP-8];
		P2 = SP;		
		R5 = 0x6b21(Z);		
		R1 = 1;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+156]; // Input_Format
	P0 = R0
	P3 = [SP++];
	R0 = [SP++];
		R2=W[P0](Z);
		R0 = R0 -|- R0 || R7 = W[P1++](X);		
		R5=R5-R7(S) || R3 = W[P1++] (X);		
		CC = R5;
		R6 = 80 (X);
		R5 = CC;		
		P4 = 11;	
		R4 = R1 << 1 ||	[P2++] = R5;		
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+620]; // _ebitsno
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
		CC = R2;
		IF !CC JUMP INDEXPACKED;									
		CC = R6 == R3;
		IF CC R0=R1;
		W[P2-2] = R0; 						
		IF CC JUMP  P2L10;				
		R2 = 16;
		CC = R2 == R3;
		IF !CC JUMP Parity_check_word;
		W[P2-2] = R4;
		P4 = 4;		
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+616]; // _ebitsno2
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
P2L10:	
		R3=R3-|-R3 || P3 = [P5++];
		R4=1;
		R2 = 129 (X);
		R1=W[P1++] (X);		
		LSETUP(P2L12,P2L14) LC1=P4 ;		
P2L12:		LSETUP(P1L2,P1L8) LC0 = P3;			
			R0 = R0-|-R0 || P3 = [P5++];
P1L2:			CC = R1 == 0;
				IF CC R3=R4;
				CC = R2 == R1;
P1L8:			R0 = ROT R0 BY 1 || R1=W[P1++] (X);							
P2L14:		W[P2++] = R0;	
		W[SP] = R3;
Parity_check_word:
		R6 = [SP];
      	R4 = ROT R6 BY 16 || R0 = [SP + 8];
	  	IF !CC JUMP DecoderAB1;
	  	R3.L = 0X0206;
	  	R1 = EXTRACT(R0,R3.L)(Z);
	  	R2.H = 1;
	  	R2.L = ONES R1;
	  	R2.L = R2.L + R2.H(S);
	  	R2.L = R2.L + R0.H(S);
	  	CC = BITTST(R2,0);
	  	R0 = CC;
	  	W[SP + 10] = R0;	  	  
	  	JUMP DecoderAB1;
INDEXPACKED:
		CC = R6 == R3;
		IF CC R0=R1;
		W[P2-2] = R0;
		P4 = 5; 						
		IF CC JUMP  P3L10;				
		R2 = 16;
		CC = R2 == R3;
		IF !CC JUMP Parity_check_word1;
		W[P2-2] = R4;
		P4 = 4;		
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+616]; // _ebitsno2
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
P3L10:	
		R7=R3-|-R3 || R0 = W[P1++] (Z);
		R4 = 1;
		
		R2 = R0 >> 8 || P3 = [P5++];		
		A0.X = R2.L; 
		R0 = R0 << 24 || R2 = W[P1++](Z);
		R2 = R2 << 8  || R5 = W[P1++](Z);
		R0 = R0 + R2;				
		R2 = R5 >> 8;
		R2 = R0 + R2;			
		A0.W = R2;		
		LSETUP(P3L12,P3L14) LC1=P4 ;		
P3L12:		LSETUP(P3L2,P3L8) LC0 = P3;			
			R0 = R0-|-R0 || P3 = [P5++];
P3L2:			A0 = ROT A0 BY 1;
P3L8:			R0 = ROT R0 BY 1;
			R4.L = ones r0;
P3L14:		W[P2++] = R0 || R7 = R4 + R7 (S);	
		CC=R7;
		CC=!CC;
		R4 = CC;
		W[SP] = R4;
		R2 = 80;
		CC = R2 == R3;
		IF !CC JUMP Parity_check_word1;
		P4=6;
		R2 = R5.B (Z);
		R0 = W[P1++](Z);
		R1 = W[P1++](Z);
		R1.H = R0.L >> 0;
		A1.W = R1;
		A1.X = R2.L;
		LSETUP(P3L15,P3L19) LC1=P4 ;		
P3L15:		LSETUP(P3L16,P3L17) LC0 = P3;			
			R0 = R0-|-R0 || P3 = [P5++];
P3L16:			A1 = ROT A1 BY 1;
				IF !CC R7=R4;			
P3L17:			R0 = ROT R0 BY 1;
				R4.L = ones r0;
P3L19:		W[P2++] = R0 || R7 = R4 + R7 (S);
		CC=R7;
		CC=!CC;
		R7=CC;	
		W[SP] = R7;				
Parity_check_word1:
		R6 = [SP];
      	R4 = ROT R6 BY 16 || R0 = [SP + 8];
	  	IF !CC JUMP DecoderAB1;
	  	R3.L = 0X0206;
	  	R1 = EXTRACT(R0,R3.L)(Z);
	  	R2.H = 1;
	  	R2.L = ONES R1;
	  	R2.L = R2.L + R2.H(S);
	  	R2.L = R2.L + R0.H(S);
	  	CC = BITTST(R2,0);
	  	R0 = CC;
	  	W[SP + 10] = R0;	  	  
	    
DecoderAB1:
	  	R0 = SP;
	  	R1 = [FP-16];
	  	R3 = [FP-24];//wxzcode
//	  	R3.H = wxzcode; 
//	  	R3.L = wxzcode;
	  CALL _Decod_ld8a;
		R1 = [FP-16];	
		R2 = [FP-20];//xn2
		R3 = [FP-24];
//		R2.H = xn2;
//		R2.L = xn2;
//		R3.H = wxzcode; 
//	  	R3.L = wxzcode;
	  CALL _Post_Filter;
	[--SP] = R1;
	[--SP] = P3;
	P3 = M2;
	R1 = [P3+4]; // synth
	R0 = R1
	P3 = [SP++];
	R1 = [SP++];
	  	P0 = 80;
	  CALL _Post_Process;
	  R1 = [FP-4];
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+4]; // synth
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
	  I1 = R1;
	  P0 = 40;
	  R7 = [I0++];
	  LSETUP(Decoder2,Decoder2) LC0 = P0;
      Decoder2: MNOP || [I1++] = R7 || R7 = [I0++];

#ifndef NOTIMER
		[--SP]	= ASTAT; 
		[--SP] = (R7:0,P5:0);
		P0.L = dd_TIMER_CNTR;
		P0.H = dd_TIMER_CNTR;				
		R0   = [P0];
		R0  += 1;
		[P0] = R0;
		R1.L = 0x7690;
		R1.H = 0;	
		R2.L = 20 ;
		R2.H = 0;
		R3.L = 0x7610;
		R3.H = 0;
		CC = R0 < R1 ;
		if CC jump normal_operation;
		P2.L = dd_BEEPS_CNTR;
		P2.H = dd_BEEPS_CNTR;
		R0 = [P2];
		CC = R0 < R2 ;
		if CC jump do_sine_wave;
		[P0] = R3 || R0 = R0 -|- R0;
		[P2] = R0;
normal_operation:
		(R7:0,P5:0) = [SP++];		
		ASTAT	= [SP++];
#endif		                  
	  	R0 = [FP-12];
	  	CALL _Decoder_Memory_Buffer;
	  	P5 = 316;
	  	SP = SP + P5;
	  	(R7:3,P5:3) = [SP++];	  	
	  	UNLINK;
	  	RTS;
	  
#ifndef NOTIMER
do_sine_wave:
		P0=[FP-4];
		R0 = [P2];
		R0 += 1;
		[P2] = R0;
		P2 = 80 ;
		P1.L = dd_CURNT_CNTR;
		P1.H = dd_CURNT_CNTR;
	LSETUP (output_xfer_loopb , output_xfer_loopt) LC0=P2;
output_xfer_loopb:
		r2 = r1 -|- r1 || R1 = [P1];
		R1 += 1;
		[P1] = R1 || R0 = ROT R1 BY -2;
		if !CC jump output_xfer_loopt;
not_zero:	
		R0 = 1 (X);
		R2 = -1 (X);
		CC = BITTST (R1,0);
		if !CC R0=R2;
		r0.h = 2000;
		r2 = r0.h*r0.l;
output_xfer_loopt:
		W[P0++] = r2;		

		jump normal_operation;

	.size _G729AB_DEC_PROCESS, .-_G729AB_DEC_PROCESS	
.data;
.align 4;

#if defined(__GNUC__)
.align 4;
dd_TIMER_CNTR:
.long 0;
.align 4;
dd_CURNT_CNTR:
.long 0;
.align 4;
dd_BEEPS_CNTR:
.long 0;
#else
dd_TIMER_CNTR: 		.byte4 = 0;
dd_CURNT_CNTR:    	.byte4 = 0;
dd_BEEPS_CNTR:     	.byte4 = 0;
#endif
#endif	  
