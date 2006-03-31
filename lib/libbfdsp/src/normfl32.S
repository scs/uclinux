/************************************************************************
 *
 * normfl32.s : $Revision$
 *
 * (c) Copyright 2000-2003 Analog Devices, Inc.
** This file is subject to the terms and conditions of the GNU Library General
** Public License. See the file "COPYING.LIB" in the main directory of this
** archive for more details.

** Non-LGPL License also available as part of VisualDSP++
** http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 *
 ************************************************************************/

/*
** Normalise a 32-bit float.
*/

.section program;

.align 2;
_norm_fl32:
   R2.L = SIGNBITS R1;
   R2 = R2.L (X);
   R1 <<= R2;
   R0 = R0 - R1;
   RTS;
._norm_fl32.end:
.global _norm_fl32;
.type _norm_fl32, STT_FUNC;

// end of file
