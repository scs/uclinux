/************************************************************************
 *
 * f32tou32z.asm : $Revision$
 *
 * (c) Copyright 2003-2004 Analog Devices, Inc.
 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 *
 ************************************************************************/

#if 0
    This program converts a floating point number to a 32-bit unsigned integer.

    Does not support:
      denormalized numbers 

    returns:
      0 for -0.0
      0 for NaN's
      0xffffffff for Inf 
      0 for -Inf 

    Registers used :
     R0 - Input/output parameter 
     R1 - R3, CC
#endif
     
.text;

.align 2;
___float32_to_unsigned_int32:
	   
				     // Check for zero input
   R2 = R0 << 1;                     // remove sign bit
   CC = R2 == 0;
   IF CC JUMP .ret_zero;
       
				     // Check for other exceptional values.
   R3 = 0xff (Z);
   R3 <<= 24;
   CC = R3 <= R2 (IU);
   IF CC JUMP .inf_or_nan;


   R2 = R2 >> 24;                    // Bring exponent to LSB 

   R1 = 150;                         // 127 + 23 offset for float to int 1 
   R3 = R2 - R1;                     // unbiased exponent                   
   R2 = R0 << 9;                     // MSB r2 will have mantissa 
       
   R2 = R2 >> 9;                     // Position mantissa 
   BITSET(R2,23);                    // Implicit 1 for hidden bit made explicit, 

				     // clip the shift magnitude. No need to
				     // do clip of R3 to +31 as if R3 > 31 at
				     // this point the C standard says
   R0 = -32;                         // the behaviour is undefined.
   R3 = MAX(R3,R0);
   R0 = ASHIFT R2 BY R3.L;           // Shift mantissa by exponent 
   RTS;    

.inf_or_nan:
   // It's an Inf or a NaN. If it's an Inf, then mantissa will be all zero.

   CC = R3 < R2 (IU);
   IF CC JUMP .is_nan;

   CC = BITTST(R0, 31);              // Check for sign of input 
   IF CC JUMP .neg_inf;              // if negative, return negative inf

.ret_inf:
   R0 = -1;
   RTS;

.is_nan:
.neg_inf:
.ret_zero:                           // if we jump here R0==(+/-)0.0/NaN/-Inf
				     // We just return zero.
   R0 = 0;
   RTS;
.___float32_to_unsigned_int32.end:

.global ___float32_to_unsigned_int32;
.type ___float32_to_unsigned_int32, STT_FUNC;

// end of file
