/*
** Float16 negate
** Copyright (C) 2003 Analog Devices, Inc
** This file is subject to the terms and conditions of the GNU Library General
** Public License. See the file "COPYING.LIB" in the main directory of this
** archive for more details.

** Non-LGPL License also available as part of VisualDSP++
** http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

*/

.text;
.align 2;
_negate_fl16:
	R1 = 0;
	R0.H = R1.H - R0.H (NS);
	RTS;
._negate_fl16.end:
.global _negate_fl16;
.type _negate_fl16, STT_FUNC;
