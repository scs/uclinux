/*
** Normalise a float16.
** Copyright (C) 2003 Analog Devices, Inc
** This file is subject to the terms and conditions of the GNU Library General
** Public License. See the file "COPYING.LIB" in the main directory of this
** archive for more details.

** Non-LGPL License also available as part of VisualDSP++
** http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

*/

.section program;
.align 2;

_norm_fl16:
	R1 = R0;
	R1 >>>= 16;
	R3.L = SIGNBITS R0.H;
	R0.H = ASHIFT R0.H BY R3.L;
	R0.L = R0.L - R3.L (NS);
	CC = R1 == 0;
	IF CC R0 = R1;
	RTS;
._norm_fl16.end:
.global _norm_fl16;
.type _norm_fl16, STT_FUNC;

