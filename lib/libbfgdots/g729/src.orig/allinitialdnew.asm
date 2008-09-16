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
$RCSfile: AllInitialdnew.asm,v $
$Revision: 1.4 $
$Date: 2006/05/24 07:46:54 $

Project:		G.729AB for Blackfin
Title:			AllInitialdnew
Author(s):		wuxiangzhi,
Revised by:		E. HSU

Description     :      Initilization, Post-process, instance load/unload 

Prototype       :      	_G729AB_DEC_RESET()						
						_Post_Process()
						_Decoder_Buffer_Memory()
						_Decoder_Memory_Buffer()

******************************************************************************
Tab Setting:			4
Target Processor:		ADSP-21535
Target Tools Revision:	2.2.2.0
******************************************************************************

Modification History:
====================
$Log: AllInitialdnew.asm,v $
Revision 1.4  2006/05/24 07:46:54  adamliyi
Fixed the failing case for g729ab decoder for tstseq6. The issue is the uClinux GAS bug: it cannot treat the (m) option correctly.

Revision 1.4  2004/01/27 23:40:18Z  ehsu
Revision 1.3  2004/01/23 00:39:31Z  ehsu
Revision 1.2  2004/01/13 01:33:37Z  ehsu
Revision 1.1  2003/12/01 00:12:06Z  ehsu
Initial revision

Version         Date            Authors        		  Comments
0.0         11/01/2002          wuxiangzhi            Original

*******************************************************************************/ 

   .GLOBAL D_lsp_old,D_mem_syn;
   .GLOBAL D_old_exc,D_old_exc_1,D_exc,D_exc_1;
   .GLOBAL D_mem_syn_pst,D_sharp,D_old_T0;
   .GLOBAL D_gain_code,D_gain_pitch,D_res2_buf;
   .GLOBAL D_bad_lsf,D_scal_res2_buf,D_scal_res2,D_res2,D_res2_buf;
   .GLOBAL D_prev_ma,D_freq_prev,D_prev_lsp;
   .GLOBAL seed_fer,D_past_qua_en;
   .GLOBAL D_mem_pre,D_past_gain;
   .GLOBAL synth,synth_1,synth_2;
   .GLOBAL synth_buf;
   .GLOBAL D_scal_res2_buf_1,D_res2_buf_1, Post_y;
.data;
   .align 4;
#if defined(__GNUC__)
   synth_buf:
   .short 0,0,0,0,0,0,0,0,0,0;
   
   .align 2;
   synth:
   .space 80; /* Synthesis                   */

   .align 2;
   synth_1:
   .space 60;

   .align 2;
   synth_2:
   .space 20;

   .align 4;
   Post_y:
   .long 0,0,0;

   .align 2;
   D_old_exc:
   .space 160;

   .align 2;
   D_old_exc_1:
   .space 148;
   
   .align 2;
   D_exc:
   .space 80;

   .align 2;
   D_exc_1:
   .space 80;

   D_mem_syn:
   .short 0,0,0,0,0,0,0,0,0,0;

   D_mem_syn_pst:
   .short  0,0,0,0,0,0,0,0,0,0;
   //350

   .align 2;	
   D_res2_buf:
   .space 80;
   
   .align 2;
   D_res2_buf_1:
   .space 206;

   .align 2;   
   D_res2:
   .space 80;
   
   .align 2;
   D_bad_lsf:
   .short 0;
   
   .align 2;
   D_scal_res2_buf:
   .space 80;

   .align 2;
   D_scal_res2_buf_1:
   .space 206
   
   .align 2;
   D_scal_res2:
   .space 80;

   .align 2;
   D_prev_ma:
   .short 0;

   //368   
   .align 2;
   D_noise_fg:
   .space 80;

   .align 2;
   D_noise_fg_1:
   .space 80;

   D_freq_prev:
   .short 2339, 4679, 7018, 9358, 11698, 14037, 16377, 18717, 21056, 23396, 2339, 4679, 7018, 9358, 11698, 14037, 16377, 18717, 21056, 23396, 2339, 4679, 7018, 9358, 11698, 14037, 16377, 18717, 21056, 23396, 2339, 4679, 7018, 9358, 11698, 14037, 16377, 18717, 21056, 23396;
   D_prev_lsp:
   .short 2339, 4679, 7018, 9358, 11698, 14037, 16377, 18717, 21056, 23396;
   lspSid:
   .short 2339, 4679, 7018, 9358, 11698, 14037, 16377, 18717, 21056, 23396;
   D_lsp_old:
   .short 30000, 26000, 21000, 15000, 8000, 0, -8000,-15000,-21000,-26000;
   D_past_qua_en:
   .short -14336, -14336, -14336, -14336;
   
   .align 4;
   D_L_exc_err:
   .long 0x00004000,0x00004000,0x00004000,0x00004000;
 
   D_sharp:
   .short 3277;          //* pitch sharpening of previous frame */
   D_old_T0:
   .short 60;         //* integer delay of previous frame    */         
   seed_fer:
   .short 21845;
   D_mem_pre:
   .short 0;      
   D_past_ftyp:
   .short 1;   
   Dec_sid_cur_gain:
   .short 0;
   D_sh_sid_sav:
   .short 1;
   D_gain_code:
   .short 0;       //* Code gain      
   Dec_sid_sid_gain:
   .short 2;   
   D_gain_pitch:
   .short 0 ;      //* Pitch gain       
   D_seed:
   .short  11111;   
   D_sid_sav:
   .short 0;                             
   D_past_gain:
   .short 4096;
   Input_Format:
   .short 1;         
#else   
   .byte2  synth_buf[10] = 0,0,0,0,0,0,0,0,0,0;
   .byte2  synth[40]; /* Synthesis                   */
   .byte2  synth_1[30];
   .byte2  synth_2[10];
   .byte4 Post_y[3] = 0,0,0;
   .byte2 D_old_exc[80];
   .byte2 D_old_exc_1[74];
   .byte2 D_exc[40];
   .byte2 D_exc_1[40];
   .byte2 D_mem_syn[10] = 0,0,0,0,0,0,0,0,0,0;
   .bytE2 D_mem_syn_pst[10] =  0,0,0,0,0,0,0,0,0,0;
   //350
   .byte2 D_res2_buf[40];
   .byte2 D_res2_buf_1[103];   
   .byte2 D_res2[40];
   .byte2 D_bad_lsf = 0;
   .byte2 D_scal_res2_buf[40];
   .byte2 D_scal_res2_buf_1[103];   
   .byte2 D_scal_res2[40];
   .byte2 D_prev_ma = 0;
   //368   
   .byte2 D_noise_fg[40];
   .byte2 D_noise_fg_1[40];
   .byte2 D_freq_prev[40]  = 2339, 4679, 7018, 9358, 11698, 14037, 16377, 18717, 21056, 23396,
                             2339, 4679, 7018, 9358, 11698, 14037, 16377, 18717, 21056, 23396,
						     2339, 4679, 7018, 9358, 11698, 14037, 16377, 18717, 21056, 23396,
						     2339, 4679, 7018, 9358, 11698, 14037, 16377, 18717, 21056, 23396;
   .byte2 D_prev_lsp[10]   = 2339, 4679, 7018, 9358, 11698, 14037, 16377, 18717, 21056, 23396;
   .byte2 lspSid[10] 	   = 2339, 4679, 7018, 9358, 11698, 14037, 16377, 18717, 21056, 23396;
   .byte2 D_lsp_old[10]    = 30000, 26000, 21000, 15000, 8000, 0, -8000,-15000,-21000,-26000;
   .byte2 D_past_qua_en[4] =  -14336, -14336, -14336, -14336;
   .byte4 D_L_exc_err[4]   = 0x00004000,0x00004000,0x00004000,0x00004000; 
   .byte2 D_sharp = 3277;          //* pitch sharpening of previous frame */
   .byte2 D_old_T0 = 60;         //* integer delay of previous frame    */         
   .byte2 seed_fer = 21845;
   .byte2 D_mem_pre = 0;      
   .byte2 D_past_ftyp = 1;   
   .byte2 Dec_sid_cur_gain = 0;
   .byte2 D_sh_sid_sav = 1;
   .byte2 D_gain_code = 0;       //* Code gain      
   .byte2 Dec_sid_sid_gain = 2;   
   .byte2 D_gain_pitch = 0 ;      //* Pitch gain       
   .byte2 D_seed = 11111;   
   .byte2 D_sid_sav = 0;                             
   .byte2 D_past_gain = 4096;
   .byte2 Input_Format = 1;         
#endif
   .global D_noise_fg,D_noise_fg_1,lspSid;
   .global Dec_sid_cur_gain,Dec_sid_sid_gain,seed_fer;
   .global D_past_ftyp,D_seed,D_sid_sav,D_sh_sid_sav;
   .global D_L_exc_err;
   .global Input_Format;         

.extern _freq_prev_reset;
.extern _lsp_old_reset;
.extern fg_0;
.extern fg_1;

.type	_G729AB_DEC_RESET, STT_FUNC ;
	
.text;
.align 8;	  	  
_G729AB_DEC_RESET:
	  .global _G729AB_DEC_RESET;//      .type  _Decoder_All_Initialize,STT_FUNC;
       [--SP] = (R7:4,P5:3);      //R0 - Channel memory pointer	
	  L0 = 0;
	  L1 = 0;
	  L2 = 0;
	  L3 = 0;

#if defined(FDPIC)	
	  M2 = P3;  /* M2 used to store GOT table offset */
#endif
		
      I3 = R0;    
      R7 = 0;           
      P0 = 718;
	  LSETUP(Decoder_All_Initialize3,Decoder_All_Initialize3) LC0 = P0 >> 1;
      Decoder_All_Initialize3: 	[I3++] = R7;
	  P0 = 20;
	  I0.H = fg_0;
	  I0.L = fg_0;
	  R0 = [I0++];
	  LSETUP(Decoder_All_Initialize6,Decoder_All_Initialize6) LC0 = P0;
	  Decoder_All_Initialize6: [I3++] = R0 || R0 = [I0++];      
	  R6.L = 19660;
	  R6.H = 13107;
	  I0.H = fg_0;
	  I0.L = fg_0;
	  I2.H = fg_1;
	  I2.L = fg_1;	  
	  R5 = [I0++];
	  LOOP Decoder_All_Initialize8 LC0 = P0;
	  LOOP_BEGIN Decoder_All_Initialize8;
	      	A0 = R5.L * R6.L, A1 = R5.H * R6.L || R4 = [I2++];
		  	R2.L = (A0 += R4.L * R6.H), R2.H = (A1 += R4.H * R6.H) (T) ||  R5 = [I0++];
			[I3++] = R2;
	  LOOP_END Decoder_All_Initialize8;	  
	  	P3 = 10;		
		I0.H = _freq_prev_reset;
		I0.L = _freq_prev_reset;
		P5 = I3;
	  	I1.H = _lsp_old_reset;	  
	  	I1.L = _lsp_old_reset;
	  	LSETUP(Coder_All_Initialize9_0,Coder_All_Initialize9_1) LC0 = P3 >> 1;
      Coder_All_Initialize9_0:  R7 = [I0++];
      							R6 = [I1++];
      							[P5+120] = R6;	
      							[P5+80] = R7;						
      							[P5+100] = R7;	
	  							[P5+20] = R7;
	  							[P5+40] = R7;
	  							[P5+60] = R7;
	  	Coder_All_Initialize9_1: [P5++] = R7;	  
	  	R7.L =  -14336;					  
   		R6 = 0x4000(Z);
   		P4 = 120;   		
   		P4 = P5 + P4;
   		P5 = 8;
   		P0 = P5 + P4;
   		P3 = 4;		
	  	LSETUP(Coder_All_Initialize9_2,Coder_All_Initialize9_3) LC0 = P3;
      Coder_All_Initialize9_2: 	W[P4++] = R7;						
      Coder_All_Initialize9_3: 	[P0++] = R6;      
      	R6   = 3277;
      	R6.H = 60;
	  	[P0++] = R6;
	  	R6 = 21845;   
   		[P0++] = R6;
   		R6 = 1;      
   		[P0++] = R6;
   		R6 = 1;         
   		[P0++] = R6;
   		R6 = 2;            
   		[P0++] = R6;
   		R6 = 11111;      
   		[P0++] = R6;
   		R6 = 4096;   
   		R6.H = 1;
	  	[P0++] = R6;	  		  			       
      (R7:4,P5:3) = [SP++];
	  RTS;

	.size	_G729AB_DEC_RESET,.-_G729AB_DEC_RESET 
.text;
.align 8;
_Post_Process:
	  .global _Post_Process;
      .type  _Post_Process,STT_FUNC;
      SP += -4;
	  I3.H = Post_y;
	  I3.L = Post_y;
	  I0 = R0;
	  R7 = [I3++];
	  R4.L = 15836;   // a100[1]
	  R4.H = -7667;   // a100[2]
	  R6 = [I3++];
	  R3.L = 7699;    // b100[0] AND b100[2]
	  R3.H = -15398;  // b100[1]
	  R5 = [I3];
	  R2.H = 1;
      R2.L = R2.H * R5.L (IU) ;
	  LOOP Post_Process1 LC0 = P0;
	  LOOP_BEGIN Post_Process1;
//	      R2  = PACK(R2.H,R5.L) 
	      
		  A1  = R6.H * R4.L, R0 = (A0 = R6.L * R4.L) || [SP]=R6;
		  A1 += R7.H * R4.H, R0.L = (A0 = R7.L * R4.H)(T) || R5.L = W[I0];
		  R5  = PACK(R5.L,R5.H);
		  A0  = R0.H * R2.H, A1 += R0.L * R2.H;
		  A0 += R5.L * R3.H, A1 += R5.H * R3.L || R7 = [SP];		  
		  A0 += R2.L * R3.L;
		  R0 = (A0 += A1);		  		  
		  R2.L = R2.H * R5.L (IU) ;
//		  R7 = ROT R6 BY 0;
		  R6 = R0 << 2(S);
		  R1 = R0 << 3(S);		  
		  R1.L = R1(RND);		  		  
		  R6.L = R6.L >> 1 || W[I0++] = R1.L;
     LOOP_END Post_Process1;
	 [I3--] = R5;
	 [I3--] = R6;
	 [I3] = R7;
	 SP += 4;
	 RTS;


.text;
.align 8;
_Decoder_Buffer_Memory:
	  .global _Decoder_Buffer_Memory;
      .type  _Decoder_Buffer_Memory,STT_FUNC;
	  //R7 = 890;            // Modified 886 to 890
	  //R1.H = Decoder_Buffer;
	  //R1.L = Decoder_Buffer;
	  //R6 = R7.L * R0.L;     // THE SIZE OF A CHANNEL
	  //R1 = R1 + R6;
	  //I1 = R1;
	  
	  I1 = R0;
	  I0.H = synth_buf;
	  I0.L = synth_buf;
//	  P0 = 886;
	  P0 = 894;
	  R7 = [I1++];
	  LSETUP(Decoder_Buffer_Memory1,Decoder_Buffer_Memory1) LC0 = P0 >> 1;
	  Decoder_Buffer_Memory1: MNOP || [I0++] = R7 || R7 = [I1++];
	  RTS;

_Decoder_Memory_Buffer:
      .global _Decoder_Memory_Buffer;
      .type  _Decoder_Memory_Buffer,STT_FUNC;
	 // R7 = 890;             // Modified 886 to 890
	 // R1.H = Decoder_Buffer;
	 // R1.L = Decoder_Buffer;
	 // R6 = R7.L * R0.L;     // THE SIZE OF A CHANNEL
	 // R1 = R1 + R6; 
	 // I1 = R1;
	  
	  I1 = R0;
	  I0.H = synth_buf;
	  I0.L = synth_buf;
//	  P0 = 886;
	  P0 = 894;
	  R7 = [I0++];
	  LSETUP(Decoder_Memory_Buffer1,Decoder_Memory_Buffer1) LC0 = P0 >> 1;
      Decoder_Memory_Buffer1: MNOP || [I1++] = R7 || R7 = [I0++];
	  RTS;
