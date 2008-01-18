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
$RCSfile: AllInitialenew.asm,v $
$Revision: 1.4 $
$Date: 2006/05/24 07:46:54 $

Project:		G.729AB for Blackfin
Title:			AllInitialenew
Author(s):		wuxiangzhi,
Revised by:		E. HSU

Description     :      Initilization, Pre-process, instance load/unload 

Prototype       :      	_G729AB_ENC_RESET()						
						_Pre_Process()
						_Coder_Buffer_Memory()
						_Coder_Memory_Buffer()

******************************************************************************
Tab Setting:			4
Target Processor:		ADSP-21535
Target Tools Revision:	2.2.2.0
******************************************************************************

Modification History:
====================
$Log: AllInitialenew.asm,v $
Revision 1.4  2006/05/24 07:46:54  adamliyi
Fixed the failing case for g729ab decoder for tstseq6. The issue is the uClinux GAS bug: it cannot treat the (m) option correctly.

Revision 1.4  2004/01/27 23:40:20Z  ehsu
Revision 1.3  2004/01/23 00:39:31Z  ehsu
Revision 1.2  2004/01/13 01:33:38Z  ehsu
Revision 1.1  2003/12/01 00:12:08Z  ehsu
Initial revision

Version         Date            Authors        		  Comments
0.0         11/01/2002          wuxiangzhi            Original

*******************************************************************************/ 
  
   .global old_speech,speech,new_speech,old_wsp,wsp,old_exc,wsp_1;
   .global exc,lsp_old,lsp_old_q; 
   .global exc_1;
   .global mem_w0,mem_w,sharp,mem_zero;
   .global freq_prev ,L_exc_err;
   .global old_speech_1,old_wsp_1,old_exc_1;
   .global past_qua_en;
   .global old_A,old_rc;
.data;
#if defined(__GNUC__)
   .align 4;
   old_exc:
   .space 160;

   .align 2; 
   old_exc_1:
   .space 148;

   .align 2; 
   exc:
   .space 80;

   .align 2;
   exc_1: 
   .space 80;

   .align 2;
   old_wsp:
   .space 160;
   
   .align 2;
   old_wsp_1:
   .space 126;

   .align 2;
   wsp:
   .space 80;

   .align 2;
   wsp_1:
   .space 82;
#else   
   .align 4;
   .byte2 old_exc[80];
   .byte2 old_exc_1[74];
   .byte2 exc[40];
   .byte2 exc_1[40];
   .byte2 old_wsp[80];
   .byte2 old_wsp_1[63];
   .byte2 wsp[40];
   .byte2 wsp_1[41];
#endif   
.data;
#if defined(__GNUC__)
   .align 4;
   old_speech:
   .space 160;

   .align 2; 
   old_speech_1:
   .space 80;
   
   .align 2;
   speech:
   .space 80;

   .align 2;
   new_speech:
   .space 160;
#else
   .align 4;
   .byte2 old_speech[80];
   .byte2 old_speech_1[40];
   .byte2 speech[40];
   .byte2 new_speech[80];
#endif
.data;
//.data;
#if defined(__GNUC__)
   .align 4;
   freq_prev:
   .short 2339
   .short 4679, 7018, 9358, 11698, 14037, 16377, 18717, 21056, 23396;
   .short 2339, 4679, 7018, 9358, 11698, 14037, 16377, 18717, 21056, 23396;
   .short 2339, 4679, 7018, 9358, 11698, 14037, 16377, 18717, 21056, 23396;
   .short 2339, 4679, 7018, 9358, 11698, 14037, 16377, 18717, 21056, 23396;
			
   lsp_old:
   .short 30000, 26000, 21000, 15000, 8000, 0, -8000,-15000,-21000,-26000;
  
   lsp_old_q:
   .short 30000, 26000, 21000, 15000, 8000, 0, -8000,-15000,-21000,-26000;
  
   past_qua_en:
   .short -14336, -14336, -14336, -14336;

   .align 4;
   L_exc_err:
   .long 0x00004000,0x00004000,0x00004000,0x00004000;

   sharp:
   .short 3277;
  
   count_frame:
   .short  0;
  
   old_A:
   .short 4096,0,0,0,0,0,0,0,0,0,0,0;
   
   .align 4;
   Pre_y:
   .long 0,0,0;

   old_rc:
   .short 0,0;
   
   mem_w0:
   .short 0,0,0,0,0,0,0,0,0,0;   	
   
   mem_w:
   .short 0,0,0,0,0,0,0,0,0,0;
   
   mem_zero:
   .short 0,0,0,0,0,0,0,0,0,0;
#else
   .align 4;
   .byte2 freq_prev[40] = 2339, 4679, 7018, 9358, 11698, 14037, 16377, 18717, 21056, 23396,
                          2339, 4679, 7018, 9358, 11698, 14037, 16377, 18717, 21056, 23396,
						  2339, 4679, 7018, 9358, 11698, 14037, 16377, 18717, 21056, 23396,
						  2339, 4679, 7018, 9358, 11698, 14037, 16377, 18717, 21056, 23396;
						  
	.byte2 lsp_old[10]   = 30000, 26000, 21000, 15000, 8000, 0, -8000,-15000,-21000,-26000;
	.byte2 lsp_old_q[10] = 30000, 26000, 21000, 15000, 8000, 0, -8000,-15000,-21000,-26000;
	.byte2 past_qua_en[4] =  -14336, -14336, -14336, -14336;					  
	.byte4 L_exc_err[4] = 0x00004000,0x00004000,0x00004000,0x00004000;
	.byte2 sharp = 3277;
   	.byte2  count_frame = 0;
   	.byte2 old_A[12] = 4096,0,0,0,0,0,0,0,0,0,0,0;
   	.byte4 Pre_y[3] = 0,0,0;
   	.byte2 old_rc[2]=0,0;
   	.byte2 mem_w0[10] = 0,0,0,0,0,0,0,0,0,0;   	
   	.byte2 mem_w[10] = 0,0,0,0,0,0,0,0,0,0;
   	.byte2 mem_zero[10] = 0,0,0,0,0,0,0,0,0,0;
#endif	
.data;
//.data;
#if defined(__GNUC__)
   	.align 4;
	noise_fg:
        .space 80;
   	
	.align 2;
	noise_fg_1:
        .space 80;

   	pastVad_flag:
   	.short 7;   // BIT 0 = pastVad BIT 1 = ppastVad BIT 2 = flag BIT 3 =  v_flag
   	seed:
   	.short 11111;
   	MinValue:
   	.short 	0x7fff;
   	prev_energy:
   	.short 	0;
   	sh_Acf:
   	.short 40,40;
   	sh_ener:
   	.short  40,40;
   	sh_sumAcf:
   	.short  40,40,40,0;   
   	MeanLSF:
  	.short  0,0,0,0,0,0,0,0,0,0;
   	
	.align 2;
	Min_buffer:
	.space 32;
 
   	MeanSLE:
   	.short 	0;
   	MeanE:
   	.short 	0;
   	MeanSE:
   	.short 	0;
   	MeanSZC:
   	.short 	0;
   	Prev_Min:
   	.short 	0;
   	Next_Min:
   	.short 	0;
   	count_sil:
   	.short 	0;
   	count_update:
   	.short 	0;
   	count_ext:
   	.short 	0;
   	less_count:
   	.short 	0;
   	//128   
   	.align 2;
	lspSid_q:
 	.space 20;
   	
	.align 2;
	pastCoeff:
	.space 24;

	.align 2; 
   	RCoeff:
	.space 24;

	.align 2; 
   	Acf:
	.space 24;

	.align 2; 
   	Acf_1:
	.space 24;

	.align 2; 
   	sumAcf:
	.space 44;

	.align 2; 
   	sumAcf_1:
	.space 24;
	
	.align 2; 
   	sumAcf_2:
	.space 4;
   	
	ener:
   	.short 0,0;
	
	.align 2;
	sh_RCoeff:
	.space 2;
 
   	fr_cur:
   	.short 0;
   	Dtx_cur_gain:
   	.short 0;
   	nb_ener:
   	.short 0;
   	Dtx_sid_gain:
   	.short 0;
   	flag_chang:
   	.short 0;
   	V_prev_energy:
   	.short 0;
   	count_fr0:
   	.short 0;
   	
	.align 2;
	_Vad_enable:
	.space 2;     //Added Vad_enable anf G729_debug
   	
	.align 2;
	extra:
	.space 2;

   	.align 2;
	outputformat:
	.long 1; 	
#else   
   	.align 4;
   	.byte2 noise_fg[40];
   	.byte2 noise_fg_1[40];
   	.byte2 	pastVad_flag = 7;   // BIT 0 = pastVad BIT 1 = ppastVad BIT 2 = flag BIT 3 =  v_flag
   	.byte2 	seed = 11111;
   	.byte2 	MinValue = 0x7fff;
   	.byte2 	prev_energy=0;
   	.byte2 sh_Acf[2] = 40,40;
   	.byte2 sh_ener[2] = 40,40;
   	.byte2 sh_sumAcf[4] = 40,40,40,0;   
  	.byte2  	MeanLSF[10] = 0,0,0,0,0,0,0,0,0,0;
   	.byte2  	Min_buffer[16];
   	.byte2 	MeanSLE = 0;
   	.byte2 	MeanE = 0;
   	.byte2 	MeanSE = 0;
   	.byte2 	MeanSZC = 0;
   	.byte2 	Prev_Min=0;
   	.byte2 	Next_Min=0;
   	.byte2 	count_sil = 0;
   	.byte2 	count_update = 0;
   	.byte2 	count_ext = 0;
   	.byte2 	less_count=0;
   	//128   
   	.byte2 lspSid_q[10];
   	.byte2 pastCoeff[12];
   	.byte2 RCoeff[12];
   	.byte2 Acf[12];
   	.byte2 Acf_1[12];
   	.byte2 sumAcf[22];
   	.byte2 sumAcf_1[12];
   	.byte2 sumAcf_2[2];
   	.byte2 ener[2] = 0,0;
   	.byte2 sh_RCoeff;
   	.byte2 fr_cur = 0;
   	.byte2 Dtx_cur_gain = 0;
   	.byte2 nb_ener = 0;
   	.byte2 Dtx_sid_gain = 0;
   	.byte2 flag_chang = 0;
   	.byte2 V_prev_energy = 0;
   	.byte2 count_fr0 = 0;
   	.byte2 _Vad_enable;     //Added Vad_enable anf G729_debug
   	.byte2 extra;
	.byte4 outputformat=1; 	
#endif
   .global count_frame;
   .global MeanLSF,Min_buffer,Prev_Min, Next_Min, MinValue;
   .global MeanE, MeanSE, MeanSLE, MeanSZC;
   .global prev_energy;
   .global count_sil, count_update, count_ext;
   .global less_count;
   .global pastVad_flag,seed;
   .global noise_fg,noise_fg_1;
   .global lspSid_q,pastCoeff,RCoeff,sh_RCoeff,Acf,Acf_1;
   .global sh_Acf,sumAcf,sh_sumAcf,ener,sh_ener;
   .global sumAcf_1,sumAcf_2;
   .global fr_cur,nb_ener;
   .global flag_chang,prev_energy,count_fr0;
   .global noise_fg,noise_fg_1;
   .global Dtx_sid_gain,Dtx_cur_gain;
   .global extra;
   .global V_prev_energy;
   .global _Vad_enable;
   .global outputformat, Pre_y;
   // the size of coder is 1644 byte
.extern _freq_prev_reset;
.extern _lsp_old_reset;
.extern fg_0;
.extern fg_1;

		 
.type	_G729AB_ENC_RESET, STT_FUNC;	

		  .text;
.align 8

.global _G729AB_ENC_RESET;

_G729AB_ENC_RESET: //Coder_All_Initialize:
	       [--SP] = (R7:4,P5:3);
	  L0 = 0;
	  L1 = 0;
	  L2 = 0;
	  L3 = 0;

#if defined(FDPIC)
	  M2 = P3;  /* M2 used to store GOT table offset */
#endif

			      // R0 - Channel Memory pointer
      // R1 - VAD enable or Disable      
      I3 = R0;     //Channel memory pointer
      R3 = R1;           
      R7 = 0; 
      P0 = 458;
//	  LSETUP(Coder_All_Initialize1,Coder_All_Initialize2) LC0 = P0 >> 1;
//      Coder_All_Initialize1: //[P1++] = R7;
//      Coder_All_Initialize2: [I3++] = R7;      
	  LSETUP(Coder_All_Initialize1,Coder_All_Initialize2) LC0 = P0 >> 1;
      Coder_All_Initialize1: //[P1++] = R7;
      Coder_All_Initialize2: [I3++] = R7;      
	  P0 = 240;
	  P1.H = old_speech;
	  P1.L = old_speech;	  
	  LSETUP(Coder_All_Initialize3,Coder_All_Initialize4) LC0 = P0 >> 1;
      Coder_All_Initialize3: //[P1++] = R7;
      Coder_All_Initialize4: [I3++] = R7;	  
		P3 = 10;		
		I0.H = _freq_prev_reset;
		I0.L = _freq_prev_reset;
		P5 = I3;
	  	I1.H = _lsp_old_reset;	  
	  	I1.L = _lsp_old_reset;
	  	LSETUP(Coder_All_Initialize9_0,Coder_All_Initialize9_1) LC0 = P3 >> 1;
      Coder_All_Initialize9_0:  R7 = [I0++];
      							R6 = [I1++];
      							[P5+80] = R6;						
      							[P5+100] = R6;	
	  							[P5+20] = R7;
	  							[P5+40] = R7;
	  							[P5+60] = R7;
	  	Coder_All_Initialize9_1: [P5++] = R7;
	  	R7.L =  -14336;					  
   		R6 = 0x4000(Z);
   		P4 = 100;   		
   		P4 = P5 + P4;
   		P5 = 8;
   		P0 = P5 + P4;
   		P3 = 4;		
	  	LSETUP(Coder_All_Initialize9_2,Coder_All_Initialize9_3) LC0 = P3;
      Coder_All_Initialize9_2: 	W[P4++] = R7;						
      Coder_All_Initialize9_3: 	[P0++] = R6;      
      R6=3277(Z);
	  [P0++] = R6 || R7=R6-|-R6;
	  R6=4096(Z);
	  [P0++] = R6;	
	  P3 = 48;		
	  	LSETUP(Coder_All_Initialize9_4,Coder_All_Initialize9_4) LC0 = P3>>1;
      Coder_All_Initialize9_4: 	[P0++] = R7;						  
      I3=P0;
//	  P3 = 124;   
//	  I0.H = freq_prev;
//	  I0.L = freq_prev;
//	  R7 = [I0++];
//	  LSETUP(Coder_All_Initialize10_3,Coder_All_Initialize10_3) LC0 = P3 >> 1;
//    Coder_All_Initialize10_3: MNOP || [I3++] = R7 || R7 = [I0++];
      
      P0 = 20;
	  I0.H = fg_0;
	  I0.L = fg_0;
	  I1.H = noise_fg;
	  I1.L = noise_fg;
	  R7 = [I0++];
	  LSETUP(Coder_All_Initialize70,Coder_All_Initialize71) LC0 = P0;
      Coder_All_Initialize70: //[I1++] = R7 ;
	  Coder_All_Initialize71: MNOP || [I3++] = R7 || R7 = [I0++];
	  R6.L = 19660;
	  R6.H = 13107;
	  I0.H = fg_0;
	  I0.L = fg_0;
	  I2.H = fg_1;
	  I2.L = fg_1;	  
	  R5 = [I0++];
	  LOOP Coder_All_Initialize8 LC0 = P0;
	  LOOP_BEGIN Coder_All_Initialize8;
	      A0 = R5.L * R6.L, A1 = R5.H * R6.L || R4 = [I2++];
		  R2.L = (A0 += R4.L * R6.H), R2.H = (A1 += R4.H * R6.H) (T) ||  R5 = [I0++];
//		  R2 = PACK(R0.H, R1.H);
		  [I3++] = R2;
	  LOOP_END Coder_All_Initialize8;	  
	  	R1.L = 40; 
      	R2.L   = 7;   
   		R2.H   = 11111;   		
   		[I3++] = R2 || R1.H = R1.L >> 0; 
   		R2 	   = 0x7fff (Z);
   		[I3++] = R2;    		
   		[I3++] = R1;   		
   		[I3++] = R1;
   		[I3++] = R1;
   		W[I3++] = R1.L;   		
   		R2=0;
   		W[I3++] = R2.L;
   		P0=140;
   		LSETUP(Coder_All_Initialize80,Coder_All_Initialize81) LC0 = P0 >> 1;
   		 Coder_All_Initialize80: //[I1++] = R2;
      Coder_All_Initialize81: [I3++] = R2;      
      R3 = 1; // VAD ON by default
      [I3++] = R3;    //VAD      
      [I3] = R3; // outputformat ITU
	      (R7:4,P5:3) = [SP++];
		  RTS;

	.size	_G729AB_ENC_RESET,.-_G729AB_ENC_RESET 
.text;
.align 8;	  
	  
_Pre_Process:
	  .global _Pre_Process;
      .type  _Pre_Process,STT_FUNC;
      /***************************************************************	  
	  for(i=0; i<lg; i++) { x2 = x1; x1 = x0; x0 = signal[i];     
         L_tmp     = Mpy_32_16(y1_hi, y1_lo, a140[1]);
         L_tmp     = L_add(L_tmp, Mpy_32_16(y2_hi, y2_lo, a140[2]));
         L_tmp     = L_mac(L_tmp, x0, b140[0]);
         L_tmp     = L_mac(L_tmp, x1, b140[1]);
         L_tmp     = L_mac(L_tmp, x2, b140[2]);
         L_tmp     = L_shl(L_tmp, 3);  signal[i] = round(L_tmp);
         y2_hi = y1_hi; y2_lo = y1_lo; L_Extract(L_tmp, &y1_hi, &y1_lo); }
*********************************************************************/	  
	  // I0  POINTS TO signal[0]
	  // P0 lg
	  P2.H = Pre_y + 8;
	  P2.L = Pre_y + 8;
	  P4.H = Pre_y;
	  P4.L = Pre_y;
	  R4.H = 7807;   // a140[1]	  
	  R4.L = -3733;  // a140[2]	  
	  R3.H = 1899;   // b140[0], b140[2]	  
	  R3.L = -3798;  // b140[1]
	  R7.H = 1;
	  R7.L = R7.H << 14 || R5 = [P4 + 8];
	  A0  = R5.L * R3.H || R6 = [P4];
	  A0  += R6.H * R4.L, R1.H = (A1 = R6.L * R4.L) (T) || R6 = [P4 + 4];

		R5.L = R5.H >> 0; 	
	  loop Pre_Process1 lC0 = P0;
	  loop_begin Pre_Process1;	      
	  			   
	      	A0 += R6.H * R4.H, R0.H = (A1 = R6.L * R4.H) (T) || W[P2]=R5.H;			
	      	A0 += R5.H * R3.L(W32) || R5.H = W[I2++];
 		  	A0 += R0.H * R7.H(W32) || [P4] = R6; 		  	
		  	A0 += R5.H * R3.H(W32);  		  
		  	R0  = (A0 += R1.H * R7.H) ;
		  	
			A0  = R6.H * R4.L, R1.H = (A1 = R6.L * R4.L) (T) || R5.L=W[P2];
			A0  += R5.L * R3.H (W32);
		  	R6  = R0 << 3(S) ;
			R1.L = R6 (RND);	  
		  	R6.L = R6.L >> 1 || W[I0++] = R1.L;
	  loop_end Pre_Process1;
	  [P4 + 8] = R5;
	  [P4 + 4] = R6;	  
	  RTS;
	.size _Pre_Process,.-_Pre_Process
	
.text;
.align 8;
_Coder_Buffer_Memory:
	   .global _Coder_Buffer_Memory;
      .type  _Coder_Buffer_Memory,STT_FUNC;
	 // R7 = 1060;           
	 // R1.H = Coder_Buffer;
	 // R1.L = Coder_Buffer;
	 // R6 = R0.L * R7.L;
     // R1 = R1 + R6;
	 // I3 = R1;
      
	 //modified Channel memory pointer coming as argument
	  I3 = R0;
	  I0.H = old_exc;
	  I0.L = old_exc;
	 
	  P1 = 458;   // data2
	  P2 = 240;   // data4
	 
	  P3 = 124;   // data7
	  P4 = 236;   // data3  
	  R7 = [I3++];
	  LSETUP(Coder_Buffer_Memory1,Coder_Buffer_Memory1) LC0 = P1 >> 1;
      Coder_Buffer_Memory1: MNOP || [I0++] = R7 || R7 = [I3++];
	  I0.H = old_speech;
	  I0.L = old_speech;
	  LSETUP(Coder_Buffer_Memory2,Coder_Buffer_Memory2) LC0 = P2 >> 1;
      Coder_Buffer_Memory2: MNOP || [I0++] = R7 || R7 = [I3++];
	  I0.H = freq_prev;
	  I0.L = freq_prev;
	  LSETUP(Coder_Buffer_Memory3,Coder_Buffer_Memory3) LC0 = P3 >> 1;
      Coder_Buffer_Memory3: MNOP || [I0++] = R7 || R7 = [I3++];
	  I0.H = noise_fg;//MeanLSF;
	  I0.L = noise_fg;//MeanLSF;
	  LSETUP(Coder_Buffer_Memory4,Coder_Buffer_Memory4) LC0 = P4 >> 1;
      Coder_Buffer_Memory4: MNOP || [I0++] = R7 || R7 = [I3++];
	       
      RTS;
	.size _Coder_Buffer_Memory, .-_Coder_Buffer_Memory
	
_Coder_Memory_Buffer:
	   .global _Coder_Memory_Buffer;
      .type  _Coder_Memory_Buffer,STT_FUNC;
	 // R7 = 1060;          //modified 1056 to 1060
	 // R1.H = Coder_Buffer;
	 // R1.L = Coder_Buffer;
	 // R6 = R0.L * R7.L;
     // R1 = R1 + R6;
	 // I3 = R1;
      I3 = R0;     
      I0.H = old_exc;
	  I0.L = old_exc;	 
	  P1 = 458;   // data2
	  P2 = 240;   // data4
	  P3 = 124;   // data7
	  P4 = 236;   // data3
	  R7 = [I0++];	  
	  LSETUP(Coder_Memory_Buffer1,Coder_Memory_Buffer1) LC0 = P1 >> 1;
      Coder_Memory_Buffer1: MNOP || [I3++] = R7 || R7 = [I0++];
	  I0.H = old_speech;
	  I0.L = old_speech;
	  R7 = [I0++];
	  LSETUP(Coder_Memory_Buffer2,Coder_Memory_Buffer2) LC0 = P2 >> 1;
      Coder_Memory_Buffer2: MNOP || [I3++] = R7 || R7 = [I0++];
	  I0.H = freq_prev;
	  I0.L = freq_prev;
	  R7 = [I0++];
	  LSETUP(Coder_Memory_Buffer3,Coder_Memory_Buffer3) LC0 = P3 >> 1;
      Coder_Memory_Buffer3: MNOP || [I3++] = R7 || R7 = [I0++];
	  I0.H = noise_fg;//MeanLSF;
	  I0.L = noise_fg;//MeanLSF;
	  R7 = [I0++];
	  LSETUP(Coder_Memory_Buffer4,Coder_Memory_Buffer4) LC0 = P4 >> 1;
      Coder_Memory_Buffer4: MNOP || [I3++] = R7 || R7 = [I0++];
	  RTS;

