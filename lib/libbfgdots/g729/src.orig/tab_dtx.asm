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
$RCSfile: tab_dtx.asm,v $
$Revision: 1.4 $
$Date: 2006/05/24 07:46:55 $

Project:		G.729AB for Blackfin
Title:			Tab_DTX
Author(s):		wuxiangzhi,
Revised by:		E. HSU

Description     :      G729A DTX tables for encoder and decoder 

Prototype       :      	
						
******************************************************************************
Tab Setting:			4
Target Processor:		ADSP-21535
Target Tools Revision:	2.2.2.0
******************************************************************************

Modification History:
====================
$Log: tab_dtx.asm,v $
Revision 1.4  2006/05/24 07:46:55  adamliyi
Fixed the failing case for g729ab decoder for tstseq6. The issue is the uClinux GAS bug: it cannot treat the (m) option correctly.

Revision 1.4  2004/01/27 23:41:51Z  ehsu
Revision 1.3  2004/01/23 00:40:58Z  ehsu
Revision 1.2  2004/01/13 01:34:53Z  ehsu
Revision 1.1  2003/12/01 00:13:24Z  ehsu
Initial revision

Version         Date            Authors        		  Comments
0.0         03/24/2003          wuxiangzhi            Original

*******************************************************************************/ 


.data;
.global PtrTab_1;
#if defined(__GNUC__)
PtrTab_1:
.short 96,52,20,54,86,114,82,68,36,121,48,92,18,120,94,124,50,125,4,100,28,76,12,117,81,22,90,116,127,21,108,66;
#else
.byte2  PtrTab_1[32] = 
96,52,20,54,86,114,82,68,36,121,48,92,18,120,
94,124,50,125,4,100,28,76,12,117,81,22,90,116,
127,21,108,66;
#endif

.global PtrTab_2_0;
#if defined(__GNUC__)
PtrTab_2_0:
.short 31,21,9,3,10,2,19,26,4,3,11,29,15,27,21,12;
#else
.byte2 PtrTab_2_0[16]= 
31,21,9,3,10,2,19,26,4,3,11,29,15,27,21,12;
#endif

.global PtrTab_2_1;
#if defined(__GNUC__)
PtrTab_2_1:
.short 16,1,0,0,8,25,22,20,19,23,20,31,4,31,20,31;
#else
.byte2 PtrTab_2_1[16]=
16,1,0,0,8,25,22,20,19,23,20,31,4,31,20,31;
#endif

//.data;
.global noise_fg_sum;
#if defined(__GNUC__)
noise_fg_sum:
.short 7798, 8447, 8205, 8293, 8126, 8477, 8447, 8703, 9043, 8604;
#else
.byte2  noise_fg_sum[10] = 
7798, 8447, 8205, 8293, 8126, 8477, 8447, 8703, 9043, 8604;
#endif

.global noise_fg_sum_1;
#if defined(__GNUC__)
noise_fg_sum_1:
.short 10514, 12402, 12833, 11914, 11447, 11670, 11132, 11311, 11844, 11447;
#else
.byte2  noise_fg_sum_1[10] = 
10514, 12402, 12833, 11914, 11447, 11670, 11132, 11311, 11844, 11447;
#endif

.global tab_Sidgain;
#if defined(__GNUC__)
tab_Sidgain:
.short 2,    5,    8,   13,   20,   32,   50,   64, 80,  101,  127,  160,  201,  253,  318,  401, 505,  635,  800, 1007, 1268, 1596, 2010, 2530, 3185, 4009, 5048, 6355, 8000,10071,12679,15962;
#else
.byte2 tab_Sidgain[32] = 
    2,    5,    8,   13,   20,   32,   50,   64,
   80,  101,  127,  160,  201,  253,  318,  401,
  505,  635,  800, 1007, 1268, 1596, 2010, 2530,
 3185, 4009, 5048, 6355, 8000,10071,12679,15962;
#endif
