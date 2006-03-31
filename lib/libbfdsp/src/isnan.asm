/* Copyright (C) 2002 Analog Devices, Inc
 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

/*
** Check whether the supplied value is Not A Number.
** Returns non-zero if so, zero if not.
*/

.text;
.align 2;
_isnan:
    BITCLR(R0, 31);     // Remove sign bit
    R1 = 0xFF;
    R1 <<= 23;      // R1 now +Inf.
    CC = R1 < R0;
    R0 = CC;
    RTS;
._isnan.end:
.global _isnan;
.type _isnan, STT_FUNC;

