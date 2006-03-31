/************************************************************************
 *
 * fpsub.asm : $Revision$
 *
 * (c) Copyright 2000-2005 Analog Devices, Inc.
 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 *
 ************************************************************************/

#if 0
   This function performs 32 bit floating point subtraction.
   It calls  floating point addition function.
     
  Registers used:
     Operands in  R0 & R1 
     R0 - X operand, R1 - Y operand,R2   
		  
  Special case: 
     IF Y == 0,RETURN X
#endif
  
.text;

.global ___float32_sub;
.type ___float32_sub, STT_FUNC;

.extern ___float32_add;
.type ___float32_add, STT_FUNC;

.align 2;
___float32_sub:
   BITTGL(R1,31);          // Flip sign bit of Y 
   JUMP.X ___float32_add;  // Call addition routine
.___float32_sub.end:

// end of file
