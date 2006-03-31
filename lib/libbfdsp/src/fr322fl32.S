/************************************************************************
 *
 * fr322fl32.s : $Revision$
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
** fract32 to 32-bit float.
*/

.section program;

.align 2;
_fr32_to_fl32:
   R1 = R0;
   CC = R0 == 0;
   IF CC JUMP finished;
   R0.L = SIGNBITS R1;
   R0 = R0.L (X);
   R1 <<= R0;
   R0 = -R0;
finished:
   RTS;

._fr32_to_fl32.end:
.global _fr32_to_fl32;
.type _fr32_to_fl32, STT_FUNC;


// end of file
