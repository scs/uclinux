/*
** Floating point comparison.
** Copyright (C) Analog Devices, Inc. 2002
 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

*/

.text;
.align 2;
___float32_cmp:
    // Test for NaNs, which must compare as not-equal,
    // no matter to what they are compared.
    // A NaN has an exponent of 255, and a non-zero
    // mantissa. Sign is irrelevant. We check whether
    // either input is a NaN by getting rid of the
    // sign bit, and then comparing against 0x7F80000;
    // if the operand is larger, it's got a 255 exponent
    // and non-zero mantissa, hence it's a NaN.
    // If R0 is a NaN, it's a suitable return value, since
    // it's non-zero.

    R2 = R0 << 1;
    R2 >>= 1;
    R3 = 0XFF;
    R3 <<= 23;
    CC = R3 < R2;
    IF CC JUMP nan;

    // If R1 is a NaN, then it's also a suitable return
    // value, so move it into R0 before jumping to the return.

    R2 = R1 << 1;
    R2 >>= 1;
    CC = R3 < R2;
    IF CC R0 = R1;
    IF CC JUMP nan;

    // Neither operand is a NaN. If they're both zero,
    // then they must compare equal, regardless of their
    // sign bits. Otherwise, we can treat the floats as
    // signed integers, since the remaining values are
    // properly ordered (sign bit is the same, tiny
    // exponents are smaller than huge exponents).

    R2 = R0 - R1;       // check whether the two
    CC = R2 == 0;       // are equal, and return zero
    IF CC JUMP res;     // if so.

    R2 = R0 | R1;       // check whether both are
    R2 <<= 1;       // zero, ignoring sign bits.
    CC = R2 == 0;
    IF CC JUMP res;

    R2 = 1;
    R3 = -R2;
    CC = R0 < R1;       // if R0 < R1, then
    IF CC R2 = R3;      // R2 == -1, else R2 == 1
    R3 = R0 & R1;       // If both R0 and R1 are negative
    CC = BITTST(R3,31); // then toggle the sign bit on
    R3 = -R2;       // R2 before returning.
    IF CC R2 = R3;
res:
    R0 = R2;
nan:
    RTS;
.___float32_cmp.end:
.type ___float32_cmp, STT_FUNC;
.global ___float32_cmp;

