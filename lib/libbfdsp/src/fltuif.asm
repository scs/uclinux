/************************************************************************
 *
 * fltuif.asm : $Revision$
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
   This function converts a integer to a floating point number. 

   As floating point number is represented by 23 bits of mantissa, 
   converted value is accurate only  to 23 most significant bits 
   (MSB) of the given integer number excluding sign bit. 
   if the given number is power of 2,then float value of it matches
   exactly.    
    
   Registers used  :
    R0 -         Input/output  parameter
    R1-R3, CC

   This function implements ieee 754 'round to nearest' rounding. If
   two numbers are equally near (i.e. the only bit set in the lost bits
   is the most significant one), we choose the even number to return.
#endif
 
.text;

.align 2;
___unsigned_int32_to_float32:
   /* 
   ** We check our input value (R0) for zero, and return zero if it's zero.
   */
   CC = R0 == 0;              // Test for zero input
   IF CC JUMP .return_zero;   // Return zero on zero input

   /*
   ** We normalise our input into R2 (that is shift our input so that
   ** the bit immediately to the right of the sign bit is the most significant
   ** set bit).  If we are doing a right shift (the MSB of the input is set), 
   ** we take care to store the lost bit to R3 so we can use it for rounding
   ** purposes later.
   */
   R1.L = SIGNBITS R0;        // Get redundant sign bits
   R1 = R1.L (Z);
   CC = BITTST(R0,31);        // if msb set need to shift by -1
   R2 = -1;
   IF CC R1 = R2;             // if msb set set shift to -1
   R2 = 1;
   R3 = R2 & R0;              // get bit to be lost
   R2 = 0;
   IF !CC R3 = R2;            // If we are shifting right by 1, r3
			      // will here contain the bit that will
			      // get shifted off. Otherwise zero.

   R2 = LSHIFT R0 BY R1.L;    // do the normalisation


   /*
   ** We calculate our exponent.  To save an instruction we put the MSB of the
   ** normalised number into the LSB of the exponent (this saves a bitclr for
   ** the hidden bit) so our calculation is 127 (bias) + 29 (would be 30 if
   ** it wasn't for the lack of bitclr) = 156.  We then subtract our signbits
   ** result from it: 156 - R1;  
   **
   ** It's a very clever thing to do, cos say I have:
   **   0x00ffffff
   ** and I add 1 to that (rounding), I'll get:
   **   0x01000000
   ** which is a '2' in the exponent field.  Because we add the exponent into
   ** the above value, the overflow that occurred due to rounding is
   ** automatically included into the result!
   */
   R0 = 156;
   R1 = R0 - R1;

   /*
   ** We then calculate the bits that are going to be lost.  We'll or in the 
   ** bit that we may already have lost - all that is important in rounding is
   ** that if the msb lost bit set we need to know if any other lost bits are
   ** set.  If there are other lost bits set then we need to round up; 
   ** otherwise we round to the nearest even... (because the distance between
   ** the two numbers are the same)
   */
   R0 = R2 << 25;             // extract the bits that will be lost
   R3 = R0 | R3;
   BITTGL(R3,31);

   /*
   ** Add one to the most significant bit in the normalised number (R2) that 
   ** will be lost after the shift.  If this bit is set, it'll ripple into the
   ** bits that will be kept.  This is the first stage of the rounding work.
   */
   R2 += 63;                  // adding 0x40
   R2 += 1;

   /*
   ** Shift our normalised number into the correct position for the mantissa
   */
   R2 >>= 7;

   /* Do the round to nearest even work. 
   **   mantissa &= ~((round bits (R3) ^ 0x40)==0)
   ** In other words, if the most significant round bit is set, and none of the
   ** other round bits are set, set the least significant bit of the mantissa
   ** to zero.
   */
				   // mantissa(R2)&=((round bits(R3) ^ 0x40)==0)
   CC = R3 == 0;
   R3 = CC;
   R3 = ~R3;
   R2 = R2 & R3;

   /*
   ** Shift the exponent into place, and add in the mantissa (with a couple 
   ** of exponent bits)
   */
   R0 = R1 << 23;
   R0 = R2 + R0;

.return_zero:
   RTS;
.___unsigned_int32_to_float32.end:

.global ___unsigned_int32_to_float32;
.global .___unsigned_int32_to_float32.end;
.type ___unsigned_int32_to_float32, STT_FUNC;

// end of file
