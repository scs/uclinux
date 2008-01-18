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
$RCSfile: g729comd.asm,v $
$Revision: 1.4 $
$Date: 2006/05/24 07:46:55 $

Project:		G.729AB for Blackfin
Title:			G729COMD
Author(s):		wuxiangzhi,
Revised by:		E. HSU

Description     :      Common Scratch variables      

Prototype       :      					  					   
						
******************************************************************************
Tab Setting:			4
Target Processor:		ADSP-21535
Target Tools Revision:	2.2.2.0
******************************************************************************

Modification History:
====================
$Log: g729comd.asm,v $
Revision 1.4  2006/05/24 07:46:55  adamliyi
Fixed the failing case for g729ab decoder for tstseq6. The issue is the uClinux GAS bug: it cannot treat the (m) option correctly.

Revision 1.4  2004/01/27 23:41:29Z  ehsu
Revision 1.3  2004/01/23 00:40:35Z  ehsu
Revision 1.2  2004/01/13 01:34:39Z  ehsu
Revision 1.1  2003/12/01 00:13:01Z  ehsu
Initial revision

Version         Date            Authors        		  Comments
0.0         04/19/2001          wuxiangzhi            Original

*******************************************************************************/ 

.data;
//		.global xn2,wxzcode;
    .global rri0i0,rri1i1,rri2i2,rri3i3,rri4i4,rri0i1,rri2i4;
	.global rri0i2,rri0i3,rri0i4,rri1i2,rri1i3,rri1i4,rri2i3;
	.global scaled_signal,scal_sig;
	.align 4;
//	.byte2	 xn2[40];           // syn_pst use the buffer in Decoder     
//    .byte2	 wxzcode[40]; 
#if defined(__GNUC__)
	.align 4;
	rri0i0:
	.space	4;  //y[240] in Autocorr use the buffer 

	.align 2;
	scaled_signal:
	.space 12;
	
	.align 2;
	rri1i1: 
	.space 16;

	.align 2;
	rri2i2: 
	.space 16;
	

	.align 2;
	rri3i3: 
	.space 16;

	.align 2;
	rri4i4: 
	.space 16;

	.align 2;
	rri0i1: 
	.space 128;
	
	.align 2;
	rri0i2: 
	.space 82;

	.align 2;
	scal_sig: 
	.space 46;

	.align 2;
	rri0i3: 
	.space 128;
	
	.align 2;
	rri0i4: 
	.space 128;

	.align 2;
	rri1i2: 
	.space 128;

	.align 2;
	rri1i3: 
	.space 128;

	.align 2;
	rri1i4: 
	.space 128;

	.align 2;
	rri2i3: 
	.space 128;
	
	.align 2;
	rri2i4: 
	.space 128;
#else
	.align 4;
	.byte2	rri0i0[2];  //y[240] in Autocorr use the buffer 
	.byte2  scaled_signal[6];
    	.byte2  rri1i1[8];
	.byte2  rri2i2[8];
	.byte2  rri3i3[8];
	.byte2  rri4i4[8];
	.byte2  rri0i1[64];
	.byte2  rri0i2[41];
	.byte2  scal_sig[23];
	.byte2  rri0i3[64];
	.byte2  rri0i4[64];
	.byte2  rri1i2[64];
	.byte2  rri1i3[64];
	.byte2  rri1i4[64];
	.byte2  rri2i3[64];
	.byte2  rri2i4[64];
#endif
