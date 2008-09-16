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
$RCSfile: tab_dtxe.asm,v $
$Revision: 1.4 $
$Date: 2006/05/24 07:46:55 $

Project:		G.729AB for Blackfin
Title:			Tab_DTXE
Author(s):		wuxiangzhi,
Revised by:		E. HSU

Description     :      G729A DTX tables for encoder only 

Prototype       :      	
						
******************************************************************************
Tab Setting:			4
Target Processor:		ADSP-21535
Target Tools Revision:	2.2.2.0
******************************************************************************

Modification History:
====================
$Log: tab_dtxe.asm,v $
Revision 1.4  2006/05/24 07:46:55  adamliyi
Fixed the failing case for g729ab decoder for tstseq6. The issue is the uClinux GAS bug: it cannot treat the (m) option correctly.

Revision 1.4  2004/01/27 23:41:53Z  ehsu
Revision 1.3  2004/01/23 00:40:59Z  ehsu
Revision 1.2  2004/01/13 01:34:54Z  ehsu
Revision 1.1  2003/12/01 00:13:26Z  ehsu
Initial revision

Version         Date            Authors        		  Comments
0.0         03/24/2003          wuxiangzhi            Original

*******************************************************************************/ 

 
.data;
.align 4;
.global lbf_corr;
#if defined(__GNUC__)
lbf_corr:
.short 7869, 7011, 4838, 2299, 321, -660, -782, -484, -164, 3, 39, 21, 4,0;
#else
.byte2 lbf_corr[14] = 7869, 7011, 4838, 2299, 321, -660, -782, -484, -164, 3, 39, 21, 4,0;
#endif

.global shift_fx;
#if defined(__GNUC__)
shift_fx:
.short 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 5,0,0;
#else
.byte2 shift_fx[34] =
            0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 5,0,0;
#endif

.global factor_fx;
#if defined(__GNUC__)
factor_fx:
.short    32767, 16913, 17476, 18079, 18725, 19418, 20165, 20972, 21845, 22795, 23831, 24966, 26214, 27594, 29127, 30840, 32767, 17476, 18725, 20165, 21845, 23831, 26214, 29127, 32767, 18725, 21845, 26214, 32767, 21845, 32767, 32767,0,0;
#else
.byte2 factor_fx[34] =    32767, 16913, 17476, 18079, 18725, 19418,
                          20165, 20972, 21845, 22795, 23831, 24966,
                          26214, 27594, 29127, 30840, 32767, 17476,
                          18725, 20165, 21845, 23831, 26214, 29127,
                          32767, 18725, 21845, 26214, 32767, 21845,
                          32767, 32767,0,0;
#endif

.global noise_fg_sum_inv;
#if defined(__GNUC__)
noise_fg_sum_inv:
.short 17210, 15888, 16357, 16183, 16516, 15833, 15888, 15421, 14840, 15597;
#else
.byte2 noise_fg_sum_inv[10] = 
17210, 15888, 16357, 16183, 16516, 15833, 15888, 15421, 14840, 15597;
#endif
.global noise_fg_sum_inv_1;
#if defined(__GNUC__)
noise_fg_sum_inv_1:
.short 12764, 10821, 10458, 11264, 11724, 11500, 12056, 11865, 11331, 11724;
#else
.byte2 noise_fg_sum_inv_1[10] = 
12764, 10821, 10458, 11264, 11724, 11500, 12056, 11865, 11331, 11724;
#endif

