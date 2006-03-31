/*****************************************************************
    Copyright(c) 2000-2004 Analog Devices Inc. IPDC BANGALORE, India.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 *****************************************************************                

    File name   :   copysign_fr16.asm
    Module name :   Sign copy
    Label name  :   __copysign_fr16
    Description :   This program attaches the sign of the second
		    parameted to firat one
     
    Registers used   :   

    RL0 - First argument        (16 bits)
    RL1 - Second argument       (16 bits)   

    Other registers used:
    R2

    Cycle count     :   8 cycles per sample

    Code size       :   12 bytes
 *******************************************************************/   

.text;
.align 2;
.global __copysign_fr16;
__copysign_fr16:

	R0 = ABS R0;            // TAKE ABS(INPUT) 
	R2 = -R0;
	CC = R1 < 0;            // IF POSITIVE RETURN ABS(INPUT)
	IF CC R0 = R2;          // IF NEGATIVE, Y = -ABS(CLIP VALUE)  
	RTS;
.__copysign_fr16.end:       




