/* Copyright (C) 2002 Analog Devices, Inc
 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

/* Floating-point square root. */

.text;
.align 2;
__sqrtf:
    // If X == 0.0, then we return 0.0.
    // If X < 0.0, we also return 0.0, and should also set
    // EDOM, but we don't do that for the fast version.
    // This means we don't need to care about -0.0 (which
    // would be a 0.0 return without setting EDOM)

    CC = R0 <= 0;
    IF CC JUMP ret_zero;

    // We know X > 0.0. Check for Inf and Nan.
    // If we find a match, return
    R1 = 0xFF;
    R1 <<= 23;  // R1 now +Inf;
    CC = R1 <= R0;
    IF CC JUMP ret_X;

    // From here on in, X is a real number, and we have to
    // work out the result. Save some working regs, and
    // Separate the exponent and mantissa.

    P2 = R4;        // Save R4 for later

    R2 = 127;
    R1 = R0 >> 23;      // Get exponent
    CC = R1;        // Check X is normalised
    R1 = R1 - R2;       // Unbias

    R0 <<= 9;       // Remove exponent from X
    R0 >>= 9;

    // If X is normalised, make hidden bit explicit;
    R3 = CC;        // 0 if denormalised
    R2 = R3 << 23;      // into hidden position
    R0 = R0 | R2;       // no-op if denormalised

    // If the exponent is an odd number, then make it even
    // by decrementing one, and shifting mantissa left once.

    CC = BITTST(R1, 0);
    R2 = CC;
    R1 = R1 - R2;       // If odd, decrement exponent
    R0 <<= R2;      // If odd, shift left by one

    // Now divide exponent by two, since (a*a) means we'd add
    // a's exponent to itself.

    R1 >>= 1;

    // If the number was normalised, then our mantissa is
    // 1.x. Shift right one, to make it 0.1x, and nudge
    // exponent accordingly.

    R1 = R1 + R3;
    R0 >>= R3;

    P0 = R1;        // Save the exponent for later.

    // At this point, we should have an exponent and mantissa
    // that accords with a 24-bit fract, aligned at MSB.

    // Our algorithm does N iterations to get N bits of
    // precision. We compute using fractional arithmetic,
    // aligned at the MSB.
    // 
    //  A = 0.5
    //  Y = 0
    //  FOR I = 1 TO 16
    //      Y2 = Y + A
    //      Z = X - (Y2 * Y2)
    //      IF Z >= 0 THEN Y = Y2
    //      A >>= 1
    //  Return Y
    //  X = R0
    //  A = R1.L
    //  Y = R2.L
    //  Y2 = R3.L
    //  Z = R4

    R0 <<= 7;   // leave sign bit clear, so we're down by one.
    P1 = 24;    // Iteration count
    R2 = 0;     // Y = 0
    R3 = R2;
    R1.L = 0x4000;  // 0.5
    R1 <<= 16;
    LSETUP (.lps, .lpe) LC0 = P1;
.lps:   R3 = R2 + R1;   // Y2 = Y + A

    // 32-bit fractional multiply of Y2*Y2 (R3*R3)
    A1 = R3.L * R3.L (FU);
    A1 = A1 >> 16;
    A0 = R3.H * R3.H, A1 += R3.H * R3.L (M);
    A1 += R3.H * R3.L (M);
    A1 = A1 >>> 15;
    R4 = (A0 += A1);

    CC = R4 <= R0;
    IF CC R2 = R3;  // If still okay, Y = Y2;
.lpe:   R1 >>= 1;

    // R2 holds mantissa result at present.

    // We've now computed the mantissa and exponent. We need
    // to normalise now.

    R1.H = 0;
    R1.L = SIGNBITS R2;
    R1 += 1;
    R2 <<= R1;      // Adjust to make leading bit MSB
    R3 = P0;        // Get exponent
    R3 = R3 - R1;       // and correct it (XXX may be denormed)
    R2 >>= 8;       // Reposition mantissa
    BITCLR(R2, 23);     // and hide hidden bit.
    R1 = 127;       // Bias exponent
    R3 = R3 + R1;
    R3 <<= 23;      // Position biased exponent
    R0 = R3 | R2;       // and reassemble
    R4 = P2;        // Restore R4.
    RTS;
ret_zero:
    R0 = 0;
ret_X:
    RTS;
.__sqrtf.end:

.global __sqrtf;
.type __sqrtf, STT_FUNC;
