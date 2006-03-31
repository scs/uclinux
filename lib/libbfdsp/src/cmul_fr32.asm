/*  cmul_fr32 - Multiplication Routine For Complex_Fract32 
    Copyright Analog Devices Inc. 2003
 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
*/
    .text;
    .epctext:
    .align 2;
_cmul_fr32:
	[--SP]=(R7:6);
	R7 = ROT R0 by 0  || R6=[SP+ 20] || NOP;
	R3 = R2 ;
	R2 *= R1 ;
	R3 *= R0 ;
	R0 = R6 ;
	R6 *= R7 ;
	R0 *= R1 ;
	R1 = R2 + R6;
	(R7:6)=[SP++];
	R0 = R3 - R0;
	RTS;
._cmul_fr32.end:
    .global _cmul_fr32;
    .type _cmul_fr32,STT_FUNC;
    .epctext.end:
