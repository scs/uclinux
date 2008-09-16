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
$RCSfile: Coder.asm,v $
$Revision: 1.4 $
$Date: 2006/05/24 07:46:55 $

Project:		G.729AB for Blackfin
Title:			Coder
Author(s):		wuxiangzhi,
Revised by:		E. HSU

Description     :      Coder Entry with diverse output formats 

Prototype       :      	_G729AB_ENC_PROCESS()												

******************************************************************************
Tab Setting:			4
Target Processor:		ADSP-21535
Target Tools Revision:	2.2.2.0
******************************************************************************

Modification History:
====================
$Log: Coder.asm,v $
Revision 1.4  2006/05/24 07:46:55  adamliyi
Fixed the failing case for g729ab decoder for tstseq6. The issue is the uClinux GAS bug: it cannot treat the (m) option correctly.

Revision 1.4  2004/01/27 23:40:23Z  ehsu
Revision 1.3  2004/01/23 00:39:43Z  ehsu
Revision 1.2  2004/01/13 01:33:40Z  ehsu
Revision 1.1  2003/12/01 00:12:13Z  ehsu
Initial revision

Version         Date            Authors        		  Comments
0.0         11/01/2002          wuxiangzhi            Original

*******************************************************************************/ 

.extern _Vad_enable;
.extern new_speech;
.extern count_frame;
.extern _Pre_Process;
.extern _Coder_ld8a;
.extern _Coder_Buffer_Memory;
.extern _Coder_Memory_Buffer;
.extern outputformat;
.extern _ebitsno;
.extern _ebitsno2;

.type	_G729AB_ENC_PROCESS, STT_FUNC ; 
.text;
.align 8;
_G729AB_ENC_PROCESS:
	  .global _G729AB_ENC_PROCESS;
	  LINK 16;
	  L0 = 0;
	  L1 = 0;
	  L2 = 0;
	  L3 = 0;
		
#if defined(FDPIC)	
	  M2 = P3;  /* M2 used to store GOT table offset */
#endif
	
	  [--SP] = (R7:4,P5:3);
	  SP += -24;
	  [FP-4] = R2;
	 // [FP- 8] = R2;  // VAD_ENABLE
	 // [FP-12] = R3;  // CHANNEL NUMBER
	  [FP-12] = R0;    // Channel memory pointer
	  [FP-16] = R1;    // INPUT BUFFER1	  	  	  
	  R1 = R2;
	  CALL _Coder_Buffer_Memory;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+236]; // count_frame
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
	  R7 = 0X7FFF;
	  R2 = R2-|-R2 || R6 = W[P5](Z);
	  R4=1;	  
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+412]; // _Vad_enable
	I1 = R0
	P3 = [SP++];
	R0 = [SP++];
	  R4 = R6 + R4 (S) || R0 = [FP-16] || R2.L = W[I1];
	  //Added code for retriving Vad_enable from channel
	  //memory instead of getting as an argument to encoder.	  	  
	  	[FP- 8] = R2;   // VAD_ENABLE	  	  
	  	R5 = 256;
	  	CC = R7 == R6;
	  	IF CC R6 = R5;
		IF !CC R6=R4;
      	W[P5] = R6;
	  I2 = R0;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+208]; // new_speech
	I0 = R0
	P3 = [SP++];
	R0 = [SP++];
	  P0 = 80;
//	  I0 = I3;
//	  R7 = [I2++];
//	  LSETUP(Coder1,Coder1) LC0 = P0 >> 1;
//      Coder1: MNOP || [I3++] = R7 || R7 = [I2++];
	  CALL _Pre_Process;	  
	  	 
#if 1
	  R0 = SP;
#else
      R0 = [FP-4];
#endif
      R1 = [FP-8];      // VAD ENABLE OR DISABLE
	  CALL _Coder_ld8a;	  	  
/*	  
	  	  		[--SP]	= ASTAT; 
		[--SP] = (R7:0,P5:0);         		
		[--SP]	= LC0;
		[--SP]	= LT0;
		[--SP]	= LB0;
		CC = BITTST(R6,0);
		P1=40;
		P0.H = prm;
	  	P0.L = prm;
		P2.H	= _memdump;
		P2.L	= _memdump;	

	LSETUP(mcpy4,mcpy5) LC0 = P1;			  	
mcpy4:	R1=W[P0++](Z);		
mcpy5:	W[P2++]=R1;					
		
		LB0		= [SP++];
		LT0		= [SP++];
		LC0		= [SP++];		
		(R7:0,P5:0) = [SP++];
		ASTAT	= [SP++];		
*/		
	  R0 = [FP-12];     // Current channel memory pointer
	  CALL _Coder_Memory_Buffer;
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+420]; // outputformat
	P0 = R0
	P3 = [SP++];
	R0 = [SP++];
	  	R7 = [P0];
	  	P1 = [FP-4];
	  	P2 = SP;      
		
		R3 = W[P2++] (X);
		R0 =  27425 (X);		
		[P1++] = R0 || R0 = R1-|-R1;						
		CC = R3 ==0;
		IF CC JUMP  EP8L7;		
	  	CC = R7;	  
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+616]; // _ebitsno2
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
		R1 = 16;		
		P0 = 4;		
	  	IF CC JUMP DOINDEXPACKING;	 
	  	
	  	CC = R3 ==  2;				
		IF CC JUMP  EP1L2 ;
		CC = R3 ==  1;	
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+620]; // _ebitsno
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
		R1 =  80;
		P0 = 5;		
		
		IF !CC JUMP EP8L7;
		
EP1L2:	A1=A0=0 || P4 = [P5] ;
		R6 = [P5++] ;
		W[P1-2] = R1;		
		R7 = 32;
		R2 =  0xFF;
		R6 = R7 - R6 (S) || R0 = W[P2++] (X);	
		LSETUP(EP1L3,EP1L6) LC1=P0;		
EP1L3:		R0 = LSHIFT R0 BY R6.L || R6 = [P5];
			LSETUP(EP1L4,EP1L5) LC0 = P4;		
			P4 = [P5++];
EP1L4:			R0 = ROT R0 BY 1;				
EP1L5:			A0 = ROT A0 BY 1;				
EP1L6:		R6 = R7 - R6 (S) || R0 = W[P2++] (X); 
		CC = R3 ==  2;	
		IF !CC JUMP EP0L0;		
		A0 = A0 << 1;
		R4 = A0.W;
		[P1]=R4;
		JUMP EP8L7;	
EP0L0:		
		R5.L = A0.X;
		R4   = A0.W;
		
		P0 = 6;					
		LSETUP(EP1L7,EP1L10) LC1=P0;		
EP1L7:		R0 = LSHIFT R0 BY R6.L || R6 = [P5];
			LSETUP(EP1L8,EP1L9) LC0 = P4;		
			P4 = [P5++];
EP1L8:		R0 = ROT R0 BY 1; 						
EP1L9:		A1 = ROT A1 BY 1;				
EP1L10:		R6 = R7 - R6 (S) || R0 = W[P2++] (X);
		R7.L = A1.X;
		R5 = R5 & R2;
		R7 = R7 & R2;
		R3   = A1.W; 		
		R6.L = R5.L << 8;
		R2.L = R4.H >> 8;	
		R5   = R2 | R6;				
		W[P1++]=R5 || R5 = R4 >> 8;
		W[P1++]=R5 || R6 = R4 << 8;		
		R5   = R6 | R7 ;
		W[P1++]=R5;				
		R5 = R3 >> 16;
		W[P1++]=R5;
		W[P1]=R3;
	  JUMP  EP8L7;

DOINDEXPACKING:
		CC = R3 ==  2;				
		IF CC JUMP  EP8L2 ;
		CC = R3 ==  1;	
	[--SP] = R0;
	[--SP] = P3;
	P3 = M2;
	R0 = [P3+620]; // _ebitsno
	P5 = R0
	P3 = [SP++];
	R0 = [SP++];
		R1 =  80;
		P0 = 11;		
		
		IF !CC JUMP EP8L7;
EP8L2:	P4 = [P5] ;
		R6 = [P5++] ;
		W[P1-2] = R1;
		R1 =  127 (X);
		W[P1+30] = R1;		
		R7 = 32;
		R2 =  129 (X);
		R6 = R7 - R6 (S) || R0 = W[P2++] (X);	
		LSETUP(EP8L3,EP8L6) LC1=P0;		
EP8L3:		R0 = LSHIFT R0 BY R6.L || R6 = [P5];
			LSETUP(EP8L4,EP8L5) LC0 = P4;		
			R0 = ROT R0 BY 1  || P4 = [P5++];
EP8L4:			R1 =  127 (X);
				IF CC R1=R2;
EP8L5:			W[P1++] = R1 || R0 = ROT R0 BY 1;				
EP8L6:		R6 = R7 - R6 (S) || R0 = W[P2++] (X);
EP8L7:


		SP  += 24;
	  (R7:4,P5:3) = [SP++];
	  UNLINK;
	  RTS;

	.size _G729AB_ENC_PROCESS, .-_G729AB_ENC_PROCESS







