/******************************************************************************
  Copyright(c) 2000-2004 Analog Devices Inc. IPDC BANGALORE, India. 

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

******************************************************************************
  File Name      : fpdiv32.asm
  Module Name    : floating point division
  Label name     :  __float32_div
  Description    : This function computes single precision signed floating point
		   division. Implemention is based on the algorithm mentioned in 
		   the reference. Some more conditions are added in the present 
		   algorithm to take care of various testcases.
  Registers used:
    Operands in  R0 & R1
    R0- Numerator(X),R1- Denominator(Y)
    R2 - R7 and P0 - P2 

******************************************************************************
  Special cases :
    1) If(X == 0) Return   0.0 or -0.0  depending on sign of X,Y
    2) If(Y == 0) Return   INF or -INF  depending on sign of X,Y
    3) If(X == Y) Return   1.0 or -1.0  depending on sign of X,Y
    4) If(Y == 1) Return   X or -X      depending on sign of X,Y
    5) Underflow : If(EXP(X) - EXP(Y) < -149),return 0,
    6) Overflow  : If((EXP(X) - EXP(Y) + 126) > 254), return NAN  or -NAN 
       depending on sign of X,Y

  Reference  : Computer Architecture a Quantitative Approach 
	       second edition
	       by John L Hennessy and David Patterson 

********************************************************************************/
#define BIASEXP         0x7F
#define MAXEXP          0XFF  
#define EXP_EXTRACT     0x1708  
#define MANT_EXTRACT    0x17
#define ONE             0x3f80000
.text;
.align 2;

.global   ___float32_div;
.type ___float32_div, STT_FUNC;

___float32_div:
    [--SP]=(R7:4);          // Push R7-R4 on stack

    // The sign bit of the result is the XOR of the operands'
    // sign bits. This is always true, even if the result is
    // zero.

    R3=R0 ^ R1;         // Get sign information
    R3 >>= 31;          // Store sign bit of result
    R3 <<= 31;          // and clear rest of R3.

    // Check for common mathematical identities. Get rid of
    // the sign bits on the operands, so that it's easier to
    // compare with zero (without worrying about +0 == -0).

    BITCLR(R0,31);          // Clear sign bit
    BITCLR(R1,31);

    // If we find a match for an identity, we return a known value.
    // This value will be nnnn0000. We store the high half (nnnn)
    // of the potential return value in the *low* half of R2, before
    // testing.

    R2.L = 0x7F80;          // If X/0, return +/- Infinity.
    CC = R1 == 0;           // (or -NaN, iff 0/0)
    IF CC JUMP  DIV_ZERO;

    R2 = R0;            // If 0/Y, return +/0 Zero.
    CC = R0 == 0;
    IF CC JUMP  RET_DIVR;

    R2.L = 0x3F80;          // If X/X, return +/- 1.
    CC = R0 == R1;
    IF CC JUMP  RET_DIVR;

    R6 = R2 << 16;          // Set R6 = 1.0.
    R2 = R0;            // If X/1.0, return X.
    CC = R1 == R6;
    IF CC JUMP DENUM_EQ_ONE;

EXTRACT_EXP:
    // Extract the exponents of the two operands, and compute the
    // result exponent. The result exponent is the difference
    // between the two operand exponents, biased.

    R2.L = EXP_EXTRACT;     // Set RL2 to extract exponent
    R4 = BIASEXP;           // Initialised to bias(127)
    R6 = EXTRACT(R0, R2.L) (Z); // Get exponent of numerator
    R5 = EXTRACT(R1, R2.L) (Z); // Get exponent of denominator
    R6 = R6 - R5;
    R6 = R6 + R4;           // bias result exponent

    // The final result exponent may not be larger than 254. However,
    // depending on the operand mantissas, we may need to normalise the
    // result mantissa, which would have the effect of reducing the
    // result exponent. Therefore, it's permissible for the result
    // exponent to be 255 at this point, and still not produce an
    // exponent overflow. If it's 256 or greater, though, then we
    // just return Infinity.

    R7 = MAXEXP;            // Emax - can be 255 at this point -
    CC = R6 <= R7;          // may get adjusted later.
#if defined(__WORKAROUND_DREG_COMP_LATENCY)
    R2.L=MANT_EXTRACT;      // Initialise to get mantissa
#endif
    IF !CC JUMP DIV_OVERFLOW;

EXTRACT_MANTISSA:

    // Extract the two mantissas. We discard the rest of the input
    // operands, since we have already finished with their signs and
    // exponents.
#if !defined(__WORKAROUND_DREG_COMP_LATENCY)
    R2.L=MANT_EXTRACT;      // Initialise to get mantissa
#endif
    R0=EXTRACT(R0, R2.L) (Z);   // Get mantissa of numerator
    R1=EXTRACT(R1, R2.L) (Z);   // Get mantissa of denominator

    // We also initialise the mantissa of the result (R2) to zero, and
    // do the same for the rounding bit (R7).

    R2 = 0;             // Clear the result mantissa
    R7 = R2;            // Clear the rounding bit

MANTI_NOT_EQUAL:

    // Make the IEEE hidden bits explicit.

    BITSET(R0,23);          // Set hidden bit of
    BITSET(R1,23);          // Numerator and denominator

CHECK_NUM:
    
    // The core division loop, using a restoring algorithm.
    // For X/Y, if X > Y, then subtract Y from X, and count
    // that Y goes into X once. Do this once for each bit in
    // an n-bit number, shifting both X and the previous
    // counts left one place each time. Here, n==32.
    // Because we're doing unsigned arithmetic, the first
    // iteration is different. There's no shift of X and
    // result. Instead, if Y goes into X, it reduces the
    // number *remaining* iterations from 32 to 31.

    CC = R1 < R0;
    R5 = CC;
    R4 = R0 - R1;
    IF CC R0 = R4;          // If X > Y, then subtract
    R4 = 32;            // Y from X, and only do
    R4 = R4 - R5;           // 31 iterations. Otherwise,
    P0 = R4;            // do 32.

    // Now the n-bit loop. Here, CC is set to true if Y < X,
    // and hence Y "goes into" X. Our quotient is built up in R2:
    // when we Rotate left, we rotate CC into bit 0. Thus, the
    // bottom bit becomes 1 if Y goes into X, and 0 otherwise.
    // All previous answers are shifted up one, as is X, for the
    // next iteration.

    LSETUP(SUB_START,SUB_END) LC0 = P0;
SUB_START:
    CC = R1 < R0;           // Check if Y goes into X.
    R4 = R0 - R1;
    IF CC R0 = R4;          // If so, subtract Y from X, and
    R2 = ROT R2 BY 1;       // set LSB of quotient. Otherwise, clear it.
SUB_END:
    R0 <<= 1;           // Shift numerator to get next quotient bit

    // We have now computed our quotient in R2. IEEE only has 24 bits of
    // mantissa, but we've got 32-bit registers, so our inputs are in 8.24 format.
    // The result is 2.30.
    // This needs normalising, and we want to preserve the lower bits of the
    // quotient since they'll be needed for computing the rounding bits. These
    // lost bits are saved in R4 when we shift them out of the quotient in R2.
    // We keep them aligned at the top of R4, so R2:R4 makes up the whole value.

    R4 = R2 << 25;          // Save 7 lost bits, at top of R4.
    R2 >>= 7;           // Adjust quotient, so 24 MSB are aligned at LSB.

    // The quotient may have the IEEE hidden bit set at this point. If this is
    // the case, the mantissa has overflowed into exponent space. If so, then
    // we adjust the exponent by one.

    R5 = R2 << 8;           // get hidden bit
    R5 >>>= 31;         // and align. (R5 0 or 1)
    R6 = R6 + R5;           // Adjust exponent, if necessary.
    BITCLR(R2, 23);         // Make hidden bit implicit


chk_denorm:

    // If the result exponent is less than zero, the result is a
    // denormalised number, and so the mantissa needs denormalising.
    // Otherwise, it's okay.
    CC = R6 < 0;            // Is result denormalised?
    IF !CC JUMP not_denorm;

    // The result is denormalised, so adjust even further. R2 is our quotient,
    // and R4 contains our "lost" bits. If our exponent is -E, we need to
    // shift right by E+1 spaces (to include IEEE hidden bit), then set the
    // exponent to be zero. When the bits are shifted out of R2, we need to
    // shift them into the top of R4, so that we still have them for rounding.

    // -130 (approx) < R6 < 0
    BITSET(R2, 23);         // Make hidden bit explicit again
    R5 = 32;
    R6 += -1;
#ifdef __WORKAROUND_SHIFT
    R7 = R5 + R6;           // 32 or less (may be negative)
#else
    R6 = -R6;           // Make positive
    R7 = R5 - R6;           // 32 or less (may be negative)
#endif
    R5 = R2;
#ifdef __WORKAROUND_SHIFT
    R0 = -32;
    R0 = MAX(R6,R0);
    R4 = LSHIFT R4 BY R0.L;
    R2 = LSHIFT R2 BY R0.L;
#else
    R4 >>= R6;          // shift quotient and lost bits to make
    R2 >>= R6;          // room
#endif
    R6 = R6 - R6;           // Make exponent zero
#ifdef __WORKAROUND_SHIFT
    CC = R7 < 0;            // save bits (if R7<0, will produce 0)
    R5 <<= R7;
    IF CC R5 = R6;
#else
    R5 <<= R7;          // save bits (if R7<0, will produce 0)
#endif
    R4 = R5 | R4;           // and include them in "lost" bits.

not_denorm:

    // The result mantissa now needs to be rounded. This is normally
    // based on the R, S and G bitss, which are:
    //  R: MSB of remainder;
    //  G: LSB of result;
    //  S: Rest of remainder, ORed together.
    // and the rounding bit is usually R & (S|G).
    // Division's a little unusual, though: we round on R instead.
    // That way, we get 1.0000...01 for very similar numbers, and only
    // get 1.0 where X==Y.
    // Our rounding bit is computed into R4, as either 0 or 1. It'll get
    // added to the mantissa later.

    R4 >>= 31;          // Round bit R

    // If the final mantissa is zero, we have a zero result, and the
    // exponent also needs to be set to zero to indicate this. But
    // at this point, because of potential denormalising, it's possible that
    // we have a quotient of 0, but a round-bit of 1. Therefore, we need to
    // include the rounding bit before we can check whether the final mantissa
    // is zero.

    R5 = R2 + R4;           // check whether rounded quotient
    CC = R5 == 0;           // is zero, and if so,
    IF CC R6 = R5;          // make exponent too

    // At this point, R2 contains the (unrounded) mantissa, R4 the
    // rounding bit, R6 is the exponent, and R3 contains the sign.
    // It's now safe to check whether the exponent has overflowed.

    R5 = MAXEXP;
    CC = R6 < R5;
    IF !CC JUMP DIV_OVERFLOW;

    // Reposition the exponent and combine with the unrounded mantissa,
    // then add in the rounding bit. It's possible that incrementing the
    // mantissa to round it will overflow the mantissa space. If this happens,
    // it will increment the exponent and leave the mantissa as zero, which
    // is the right thing to do. It's also possible that if this occurs, it
    // could nudge the exponent from valid (<=254) to invalid (255), in which
    // case we've overflowed, and should return Infinity. Which happens to be
    // represented by exponent of 255 and mantissa of 0, so we'll have the
    // correct result then, too.

    R6 <<= 23;          // Shift to keep exponent in proper position
    R0 = R2 | R6;           // Or with mantissa and store final result in R0
    R0 = R0 + R4;           // Add in rounding bit
    R0 = R3 | R0;           // Or with sign bit
    (R7:4)=[SP++];          // Pop R7-R4 from stack
    RTS;

    // Exit points for special cases, because we're returning known values. We
    // arrange for the high half of the return value to be in the low half of
    // R2. We shift it up to the high half, leaving the result as nnnn0000,
    // mask in the appropriate sign bit, and return.

DIV_ZERO:
    R0 <<= 1;           // If 0/0, then we should return a NaN instead.
    CC = R0 == 0;
    R0 = ~R0;           // make result 0xFFFFFFFF (-NaN) iff X was 0.
    IF CC JUMP DIV_FINISHED;    // and skip over the Infinity/sign handling.
DIV_OVERFLOW:
    R2.L = 0x7F80;          // Infinity.
RET_DIVR:
    R2 <<= 16;          // R2.L has been loaded with the *high* half of the
		    // return value; shifting up is short than loading.
DENUM_EQ_ONE:
    R0 = R2 | R3;           // R3.31 contains the sign bit needed.
DIV_FINISHED:
    (R7:4)=[SP++];          // Pop R7-R4 from stack
    RTS;
.___float32_div.end:
.global .___float32_div.end;
