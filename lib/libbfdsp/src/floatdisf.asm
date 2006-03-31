/*
   Copyright (C) 2003-2005 Analog Devices, Inc
 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

  
   Convert a signed long long to a float (i.e. I8 to R4)
  
   It's very similar to the algorithm in floatdiuf.asm.  
*/

#if defined(__ADSPBF535__) || defined(__AD6532__)
#define CARRY AC
#else
#define CARRY AC0
#endif

.text;

.align 2;
__longlong64_to_float32:
   /* 
   ** Begin by checking whether this is an I8 or an I4. 
   */
   R2 = R0 >>> 31;
   CC = R2 == R1;
   IF CC JUMP i4tor4;    // top 32-bits all signs, do in 32-bits

   CC = R1 == 0;
   IF CC JUMP u4tor4;    // top 32-bits zero's, do un unsigned 32-bits

   /*
   ** get absolute value of input and record if negative.
   */
   CC = R1 < 0;          // Check whether it's negative
   P0 = 0;               // Assume positive value
   IF !CC JUMP no_neg;

   P0 = 1;               // It's negative, so negate int.
   R0 = -R0;
   CC = CARRY;
   CC = !CC;
   R2 = CC;
   R1 = -R1;
   R1 = R1 - R2;

no_neg:
   /*
   ** Normalize positive long long input. Our shift amount
   ** is stored in R3. We move any bits that need to be moved 
   ** from R0 into R1.
   */
   R2 = 32;              // here to avoid anomaly #05000127 and #05000209
   R3.L = SIGNBITS R1;   // get number of sign bits
   R3 = R3.L (X);        // Our record of the exponent

			 // normalize
   R1 = LSHIFT R1 BY R3.L;  
   R2 = R3 - R2;         // how much to align bits that cross halves

			 // Get the bits that move to high half
   R2 = LSHIFT R0 BY R2.L; 
   R1 = R1 | R2;         // and mask in

   /*
   ** Here R1 is the normalised high half (bit 30 is ms bit set), R0
   ** is the untouched low half.
   */

   /* 
   ** We do the necessary rounding calculations. We first get rid of all
   ** the bits in the low register that have been shifted to the high one. We
   ** then mask off the bits that will be lost in the high register, saving this
   ** in R3. We shift our result register right by one (to avoid overflow in
   ** the next stage) then add one to the most significant bit that is going to
   ** be lost (in our result register R1): this will ripple into the bits that
   ** will be kept if that bit is set.
   */

   /* 
   ** have:      smmm mmmm mmmm mmmm mmmm mmmm mmmm mmmm
   **                                           ^        
   **                                           ms-lost bit
   ** producing: seee eeee emmm mmmm mmmm mmmm mmmm mmmm 
   */
   R2 = 0x40;
   R1 = R1 + R2;
   R0 = LSHIFT R0 BY R3.L;
   R2 = R1 << 25;        // Get the bits to be lost once mantissa added

   /*
   ** We then do the round to nearest even work. If the most significant round
   ** bit is set, and none of the other round bits are set, we set the least
   ** significant bit of the mantissa to zero (IEEE says that if the two
   ** options for rounding are equally near, round to even)
   **
   ** This is encapsulated in the expression
   **     mantissa &= ~((round bits (R2) ^ 0x80)==0)
   */

   BITTGL(R2,31);
   R2 = R2 | R0;
   CC = R2 == 0; // cc set only if out of all the lost bits, we have
		 // only the most significant lost bit set.
   R2 = CC;
   R2 = ~R2;
   R1 >>= 7;
   R1 = R1 & R2;

   /*
   ** We calculate our exponent. To save an instruction we put the MSB of the
   ** normalised number into the LSB of the exponent (this saves a bitclr for
   ** the hidden bit) so our calculation is 127 (bias) + 62 (would be 63 if
   ** it wasn't for the lack of bitclr) = 189.  We then subtract our signbits
   ** result from it: 189 - R0;
   **
   ** It's a very clever thing to do, cos say I have:
   **   0x00ffffff
   ** and I add 1 to that ( as part of rounding), I'll get:
   **   0x01000000
   ** which is a '2' in the exponent field.  Because we add the exponent into
   ** the above value, the overflow that occurred due to rounding is
   ** automatically included into the result!
   **
   ** We then add in the mantissa, and return the result.
   */

   R0 = 188;
   R0 = R0 - R3;
   R0 <<= 23;
   R0 = R0 + R1;
   R2 = P0;              // set sign if required
   R2 <<= 31;
   R0 = R0 | R2;

   RTS;

i4tor4:
   // The input value is a 32-bit value, sign-extended to
   // a 64-bit value. So just convert as a normal int-to-float.
   JUMP.X ___int32_to_float32;

u4tor4:
   // The input value is a 32-bit unsigned value, zero-extended
    // to a 64-bit value. So convert that to a real.
   JUMP.X ___unsigned_int32_to_float32;


.__longlong64_to_float32.end:
.global __longlong64_to_float32;
.global .__longlong64_to_float32.end;
.type __longlong64_to_float32, STT_FUNC;

.extern ___int32_to_float32;
.extern ___unsigned_int32_to_float32;

