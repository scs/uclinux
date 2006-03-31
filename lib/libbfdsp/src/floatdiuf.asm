/*
 Copyright (C) 2003-2005 Analog Devices, Inc
 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


 Convert an unsigned long long to a float (i.e. I8 to R4)

 How it works:
   This function implements ieee 754 'round to nearest' rounding. If
   two numbers are equally near (i.e. the only bit set in the lost bits
   is the most significant one), we choose the even number to return.


*/

.text;

.align 2;
__unsigned_longlong64_to_float32:
   /* 
   ** If our long long is really an 32 bit integer, call the support routine
   ** ___unsigned_int32_to_float32.
   */
   CC = R1 == 0;           // is this an I8 or I4?
   IF CC JUMP u4tor4;

   /* 
   ** We shift our long long such that the MSB of R1 is set.  Our shift amount
   ** is stored in R7.  We move any bits that need to be moved from R0 into R1.
   */

   CC = R1 < 0;            // Check if in unsigned range with MSB set
   R2.L = SIGNBITS R1;
   R2 += 1;                // increment shift by 1 - want MSB to be set
   R3 = 0;
   IF CC R2 = R3;          // if msb set, set shift amount to zero
   R1 = LSHIFT R1 BY R2.L; // do the normalising shift
   R3 = R2.L (Z);          // number of bits to lshift to get '1' in msb
   R2 = 32;                // move necessary bits from low reg to high reg
   R2 = R3 - R2;
   R2 = LSHIFT R0 BY R2.L; // Get the bits that move to the high half
   R1 = R1 | R2;           // and mask them in

   /* 
   ** We do the necessary rounding calculations.  We first get rid of all
   ** the bits in the low register that have been shifted to the high one.  We
   ** then mask off the bits that will be lost in the high register, saving this
   ** in R3.  We shift our result register right by one (to avoid overflow in
   ** the next stage) then add one to the most significant bit that is going to 
   ** be lost (in our result register R1): this will ripple into the bits that
   ** will be kept if that bit is set.
   */

   /*
   ** have:      mmmm mmmm mmmm mmmm mmmm mmmm mmmm mmmm
   **                                           ^
   **                                           ms-lost bit
   ** producing: seee eeee emmm mmmm mmmm mmmm mmmm mmmm
   */

   R0 <<= R3;              // get rid of any bits in R0 that were shifted
   R2 = R1 << 25;          // get the bits to be lost from R1
   BITTGL(R2,31);
   R2 = R2 | R0;           // zero if only the MSB lost bit is set,
			   // non-zero otherwise

   R1 >>= 1;               // avoids overflow if all bits are set.
   R0 = 0x40;
   R1 = R1 + R0;           // add one to the msb lost bit.  This will
			   // carry into the kept bits if the msb lost
			   // bit is 1.
   /*
   ** We then do the round to nearest even work. If the most significant round
   ** bit is set, and none of the other round bits are set, we set the least
   ** significant bit of the mantissa to zero (IEEE says that if the two
   ** options for rounding are equally near, round to even)
   **
   ** This is encapsulated in the expression
   **   mantissa &= ~((round bits (R2) ^ 0x40)==0)
   */

   CC = R2 == 0;
			   // cc set only if out of all the lost bits, we have
			   // only the most significant lost bit set.
   R2 = CC;
   R2 = ~R2;
   R1 >>= 7;               // shift the mantissa into place
   R1 = R1 & R2;           // if only msb lost bit is set, ieee says we
			   // must round to the nearest even number.

   /* 
   ** We calculate our exponent.  To save an instruction we put the MSB of the
   ** normalised number into the LSB of the exponent (this saves a bitclr for
   ** the hidden bit) so our calculation is 127 (bias) + 62 (would be 63 if
   ** it wasn't for the lack of bitclr) = 189.  We then subtract our signbits
   ** result from it: 189 - R1;
   **
   ** It's a very clever thing to do, cos say I have:
   **   0x00ffffff
   ** and I add 1 to that (rounding), I'll get:
   **   0x01000000
   ** which is a '2' in the exponent field.  Because we add the exponent into
   ** the above value, the overflow that occurred due to rounding is
   ** automatically included into the result!
   **
   ** We then add in the mantissa, and return the result.
   */

   R0 = 189;
   R0 = R0 - R3;
   R0 <<= 23;
   R0 = R1 + R0;
   RTS;

u4tor4:
   /* The input value is a 32-bit unsigned value, zero-extended
   ** to a 64-bit value. So convert that to a real.
   */
   JUMP.X ___unsigned_int32_to_float32;

.__unsigned_longlong64_to_float32.end:
.global __unsigned_longlong64_to_float32;
.global .__unsigned_longlong64_to_float32.end;
.type __unsigned_longlong64_to_float32, STT_FUNC;

.extern ___unsigned_int32_to_float32;

