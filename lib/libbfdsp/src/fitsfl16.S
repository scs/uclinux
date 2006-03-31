/*
** Whether a float will fit into a float16 without losing precision.
** Copyright (C) 2003 Analog Devices, Inc
** This file is subject to the terms and conditions of the GNU Library General
** Public License. See the file "COPYING.LIB" in the main directory of this
** archive for more details.

** Non-LGPL License also available as part of VisualDSP++
** http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

*/

.section program;
.align 2;
_fits_in_fl16:
	R1 = R0.B (X);
	R0 = 0;
	CC = R1 == 0;
	R0 = ROT R0 BY 1;
	RTS;
._fits_in_fl16.end:
.global _fits_in_fl16;
.type _fits_in_fl16, STT_FUNC;
