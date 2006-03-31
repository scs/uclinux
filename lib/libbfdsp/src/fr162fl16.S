/*
** Convert fract 16 to float16
** Copyright (C) 2003 Analog Devices, Inc
** This file is subject to the terms and conditions of the GNU Library General
** Public License. See the file "COPYING.LIB" in the main directory of this
** archive for more details.

** Non-LGPL License also available as part of VisualDSP++
** http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

*/

.section program;
.align 2;

_fr16_to_fl16:
	CC = R0 == 0;
	IF CC JUMP finished;
	R1.L = SIGNBITS R0.L;
	R0.H = ASHIFT R0.L BY R1.L;
	R1 = -R1 (V);
	R0.L = R1.L >> 0;
finished:
	RTS;
._fr16_to_fl16.end:
.global _fr16_to_fl16;
.type _fr16_to_fl16, STT_FUNC;
