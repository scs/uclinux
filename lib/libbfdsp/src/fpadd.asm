/************************************************************************
 *
 * fpadd.asm : $Revision$
 *
 * (c) Copyright 2000-2005 Analog Devices, Inc.
 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 *
 ************************************************************************/

// Single-precision IEEE floating-point addition, with
// rounding to nearest even.
//
// A single-precision (32-bit) float has one sign bit,
// eight bits of exponent, biased by 127 (0-255, not -128..+127),
// and twenty-three bits of mantissa.
// 31                                    0
// seee eeee emmm mmmm mmmm mmmm mmmm mmmm

.text;
.align 2;

// Bits in R7 (flag reg)
#define RESULT_SIGN 0
#define COMPLEMENTED_X  1
#define COMPLEMENTED_Y  2

// Reg usage:
// P0 - result exponent
// P2 - "remainder" bits (aligned at MSB)

#if defined(__ADSPBF535__) || defined(__AD6532__)
#define CARRYFLAG   AC
#else
#define CARRYFLAG   AC0
#endif

___float32_add:
    [--SP] = (R7:4);

    // Extract and compare the two exponents. Since there are
    // 23 bits of mantissa, if the difference between exponents (D)
    // is greater than 24, the operand with the smaller exponent
    // is too insignificant to affect the other. If the difference
    // is exactly, the 24th (hidden) bit will be shifted into the
    // R position for rounding, and so can still affect the result.
    // (R is the most significant bit of the remainder, which is
    // all the bits shifted off when adjusting exponents to match)

    R2 = R0 << 1;
    // Check to see if X is zero. If so, return Y.
    CC = R2;
    IF !CC JUMP return_y;
    R2 = R2 >> 24;      // X exponent
    R3 = R1 << 1;
    // Check to see if Y is zero. If so, return X.
    CC = R3;
    IF !CC JUMP return_x;
    R3 = R3 >> 24;      // Y exponent
    R4 = R2 - R3;       // D
    R5 = 24 (X);
    CC = R5 < R4;       // difference > 24
    IF CC JUMP return_x;
    R5 = -R5;
    CC = R4 < R5;       // difference > -24
    IF CC JUMP return_y;

    // Exponents are close enough to affect the result.

    // If the exponents are different, then we arrange the
    // operands so that X is the larger, and we're adding
    // a less-significant number to it. Because the exponents
    // are biased (the eeeeeeee bits are the true exponent,
    // with +127 added), we remove the sign bits of X and Y,
    // and then compare directly.

    R2 = R0 << 1;
    R3 = R1 << 1;
    CC = R3 <= R2 (IU); // compare X and Y values (exp and mant)
    IF CC JUMP no_swap; // okay if Y exp is smallest

    // Y exp is biggest. Swap.
    R5 = R0;        // swap x and y
    R0 = R1;
    R1 = R5;
    R4 = -R4;       // negate D.

no_swap:

    // At this point, we know that X is the larger, more significant
    // number of X and Y, and therefore that D, the difference between
    // exponents, will be zero or greater.

    // Set the result's exponent and sign to those of X, by default.

    R2 = R0 << 1;
    R2 = R2 >> 24;
    P0 = R2;        // default exp of result
    R7 = R0 >> 31;      // default sign of result in R7.0

    // extract mantissas of X and Y, and make their hidden bits explicit.
    R2 = R0 << 9;       // remove sign and exp of X
    R2 = R2 >> 9;
    BITSET(R2,23);      // make hidden explicit
    R3 = R1 << 9;
    R3 = R3 >> 9;
    BITSET(R3,23);

    // If the X and Y operands have different signs, then
    // we negate one of the mantissas, so that the sums
    // come out correctly (the mantissas are unsigned, so
    // we negate the mantissa that is from a negative operand).

    R5 = R0 ^ R1;       // compare X and Y signs
    CC = R5 < 0;
    IF !CC JUMP no_negate;  // if not negative, signs are same.

    // X and Y have different signs.

    // Check sign of Y.
    CC = BITTST(R1,31);
    IF !CC JUMP test_x_neg;
    R3 = -R3;
    BITSET(R7,COMPLEMENTED_Y);
    JUMP no_negate;
test_x_neg:
    // Check sign of X.
    CC = BITTST(R0,31);
    IF !CC JUMP no_negate;
    R2 = -R2;
    BITSET(R7,COMPLEMENTED_X);

no_negate:

    // Now adjust the Y mantissa, so that its point aligns with
    // that of X (so that they have the same exponent). Since X
    // has the larger exponent, we shift Y right D places, which
    // implies its exponent increments by D. Note that D might be
    // zero, in which case no shift happens.
    // Logically, D bits of Y get shifted beyond the LSB of X.
    // These are shifted into the most significant bits of the
    // remainder. We hold onto them for later, because they
    // affect the result. So we have before:
    //     x = xxxxxxx
    //     y = yyyyyyy
    // after:
    //     x = xxxxxxx
    //     y = sssyyyyrrr
    // where there are 24 x bits, and 24 (s+y) bits, and D r bits.
    

    // Take the bottom D bits of Y, shift them *up* 32-D bits,
    // so that they are at the top part of the register, and store
    // for later.
    R6 = 32 (Z);
    R6 = R6 - R4;           // 32-D
    R5 = ASHIFT R3 BY R6.L;     // leave D bits, at MSB.
#if !defined(__ADSPBF535__) && !defined(__AD6532__)
    // if D==0, then we'd like to shift all bits out, leaving
    // R5 empty. But while BF535 will do, that, later processors
    // treat a shift-count of 32 as signed 6-bit number, which is
    // -32, so fills R5 instead. Work around this.
    CC = R4 == 0;
    IF CC R5 = R4;
#endif
    P2 = R5;            // save the bits for later.

    // now need to do the actual shifting, and shift in
    // 1s if we complemented Y, 0s otherwise. D might be
    // 0, in which case we don't want to have done any
    // shifts at all. So we shift left one place, then
    // shift in the complemented_y bit (which will be 0
    // if we haven't complemented, 1 if we have, and so
    // will match what we shifted out). Then we're back
    // where we started, and can shift by D (which may
    // have no effect whatsoever).

    R3 = R3 << 1;
    CC = BITTST(R7, COMPLEMENTED_Y);
    R3 = ROT R3 BY -1;      // put in first bit
    R5 = -R4;           // -D means "right by D bits"
    R3 = ASHIFT R3 BY R5.L;     // propagate bits.

    // We start tweaking the result exponent soon afterwards.
    // Restore it to somewhere usable.

    R6 = P0;            // result exponent

    // At this point, X and Y mantissas are aligned at LSB.
    // We shift them up to the MSB first, before adding, so that
    // we can easily see when there's a carry-out.
    
    R2 = R2 << 8;           // Align at MSB
    R3 = R3 << 8;
    R5 = R2 + R3;

    // After the addition, we take the 23 most significant
    // bits of the sum, shifting the sum so that the leading
    // 1 bit is in the IEEE hidden-bit place (bit 24 of mantissa).
    // If shifting is necessary, we also have shift the bits
    // in the remainder, and transfer bits across the gap from
    // sum to remainder, or vice versa. Note that sum is currently
    // aligned at MSB, so there's an 8-bit "gap" between bottom
    // of sum and top of remainder.

    // If a carry-out occurs, and X and Y have the same sign, then
    // we have an overflow of the result mantissa. If they're
    // different signs, it's not a problem.

    CC = CARRYFLAG;
    IF !CC JUMP no_carry;
    R3 = R0 ^ R1;
    CC = R3 < 0;
    IF CC JUMP no_carry;

    // Overflow has occurred, which means that the most significant
    // bit is in the carry bit. We need to shift the sum right one
    // space to normalise, and increment the exponent accordingly.
    // Shift bit from bottom of sum into top of remainder.

    R3 = P2;
    R5 = ROT R5 BY -1;      // shift carry into result
    CC = BITTST(R5,7);      // (which is currently at MSG)
    R3 = ROT R3 BY -1;      // and ripple through to lost
    P2 = R3;            // bits
    R6 += 1;            // increment exponent
    JUMP no_shift;


no_carry:
    // Since there was no carry-out, we don't need to shift
    // right to normalise. We may need to shift left, though.
    // Before that, if we negated the X mantissa, we also need
    // to negate the sum and remainder now.

    CC = BITTST(R7, COMPLEMENTED_X);
    IF !CC JUMP wasnt_complemented;

    // We do need to negate sum and remainder. We can't just
    // use -R5, -R3 because negation is invert-and-add-one, and
    // we need to ensure that the carry from that addition
    // ripples through the remainder and into the sum.

    R3 = P2;            // the bits we shifted off
    R5 = R5 >> 8;           // close the gap
    R5 = ~R5;           // get one's complements
    R3 = ~R3;           // and then add one, and ripple
    R3 += 1;            // through the carry. Note that
    CC = CARRYFLAG;         // negating sets all the clear
    R4 = CC;            // bottom bits, so the one ripples
    R5 = R5 + R4;           // up to bottom of lost words,
		    // and also clears them.
    R5 = R5 << 8;           // realign at MSB
    P2 = R3;            // save the negated lost bits

wasnt_complemented:

    // Now we can normalise, by shifting left until there is a 1
    // in the IEEE hidden bit position, which is bit 24 in the
    // mantissa, which is residing at MSB of sum, at present.
    // Signbits will return the number of 0s or 1s in the word,
    // less one. So we'd need to shift one more space than this,
    // unless the MSB is already a 1, in which case no shift is
    // necessary at all. If we do shift, we also have to shift
    // the same number of bits from the remainder into the bottom
    // of the sum, crossing the "gap" which exists because the
    // sum is at the MSB of the register.
    // After shifting, we decrement the result's exponent by the
    // number of bits we shifted.

    CC = BITTST(R5, 31);
    IF CC JUMP check_zero;      // don't need to shift
    R2.H = 0;
    R2.L = SIGNBITS R5;     // get number of sign bits
    R2 += 1;
    R5 = LSHIFT R5 BY R2.L;     // shift to remove leading zeroes

    // We also have to shift *in* the appropriate amount of the lost
    // bits from the remainder.
    R3 = 32;
    R3 = R2 - R3;           // want negative result
    R4 = P2;            // Lost bits
    R3 = LSHIFT R4 BY R3.L;     // Get just the bits we want
    R3 = R3 << 8;           // Align with the current sum
    R5 = R5 | R3;           // and include.
#ifdef __WORKAROUND_SHIFT
    R4 = LSHIFT R4 BY R2.L;     // R2 in range 0 to 32.
#else
    R4 <<= R2;          // Remove those bits from lost bits.
#endif
    P2 = R4;            // and store back.

    R6 = R6 - R2;           // update exponent

check_zero:
    // We can now check whether the sum is zero (it may have been
    // before, and then become none-zero after shifting in remainder
    // bits). If it is, then we also set the exponent to zero, because
    // that's how IEEE represents zero.

    CC = R5 == 0;           // Have we got a zero sum?
    IF CC R6 = R5;          // If so, exponent also becomes zero.

no_shift:

    // At this point, the sum is normalised, aligned with MSB,
    // and still has the IEEE hidden bit explicit. We remove the
    // hidden bit, so that it's implicit, and align against LSB
    // ready for rounding.

    R5 = R5 << 1;           // remove leading 1
    R5 = R5 >> 9;           // Realign back on LSB.
    P0 = R6;            // Store exponent back

    // Now rounding. We round up or down, if there's a clear
    // choice (remainder less or more than 0.5). If remainder
    // is exactly 0.5, then we round to nearest even value of sum.
    // The MSB of the remainder is called R. Has value 0.5 or 0.
    // The LSB of the sum is called G (guard bit).
    // The rest of the remainder is all ORed together, and is
    // called S ("sticky").
    // 
    // if (remainder < 0.5 (R==0)) {
    //  don't round
    // } else if ( remainder > 0.5 (R==1 and S==1)) {
    //  do round
    // } else if (remainder==0.5 && LSB set (R==1 and G==1)) {
    //  do round
    // } else {
    //  don't round
    // }
    // which is R & (S | G)

    R3 = P2;            // Lost bits
    R2 = R3 >> 31;          // R bit
    R3 = R3 << 1;           // rest of remainder, without R
    CC = R3;            // S bit
    R3 = CC;
    R4 = R5 << 31;          // G is LSB of Sum
    R4 = R4 >> 31;
    R3 = R3 | R4;           // (S | G)
    R2 = R2 & R3;           // R & (S | G)

    // R2 is now the amount by which we'll round - 0 or 1.
    // When we add it, this might be enough to overflow the
    // sum past 23 bits. If that happens, we also need to
    // increment the exponent. Therefore, we OR the exponent
    // into the word first - if the mantissa overflows, it'll
    // cause the exponent to be incremented too. We need to
    // remove the hidden bit first, but since we know it's a
    // 1, we know it'd propagate the overflow, if it were
    // present.

    R6 <<= 23;          // position exponent
    BITCLR(R5,23);          // remove hidden bit
    R5 = R5 | R6;           // combine exponent and result
    R5 = R5 + R2;           // round

    R6 = R7 << 31;          // result's sign
    R0 = R5 | R6;
return_x:
    (R7:4) = [SP++];
    RTS;

return_y:
    R0 = R1;
    (R7:4) = [SP++];
    RTS;
.___float32_add.end:
.global ___float32_add;
.type ___float32_add, STT_FUNC;
