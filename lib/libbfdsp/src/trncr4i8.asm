/*
** Copyright (C) Analog Devices, Inc
 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

**
** Convert float to signed long long (R4 to I8).
*/

#if defined(__ADSPBF535__) || defined(__AD6532__)
#define CARRY AC
#else
#define CARRY AC0
#endif

.text;
.align 2;

__float32_to_longlong64:
    P0 = R0;        // Store for sign, later
    R1 = R0 << 1;       // Extract mantissa
    R1 >>= 24;
    R2 = 150 (X);       // 127 for unbiasing, 23 for adjusting
    R1 = R1 - R2;       // exponent value, since the 1.xxx is
		// actually shifted 23 bits into low half.
		// R1 now e'.

    // cases 0 and 6 both will mean we shift everything off one
    // end or the other, so we return the same value in both cases.

    R3 = -24 (X);       // case 0: e' < -24
    CC = R1 < R3;
    IF CC JUMP ret_zero;
    R3 = 64;        // case 6: 64 <= e'
    CC = R3 <= R1;
    IF CC JUMP ret_zero;

    // Other cases will leave at least some of the bits within
    // high or low halves (or both), so need to extract the
    // mantissa.

    R0 <<= 8;       // extract mantissa bits
    R0 >>= 8;
    BITSET(R0, 23);     // and restore hidden bit.

    CC = R1 < 0;        // case 1: -24 <= e' < 0
    IF CC JUMP case_1;
    R3 = 8;
    CC = R1 < R3;       // case 2: 0 <= e' < 8
    IF CC JUMP case_2;
    R3 <<= 2;
    CC = R1 < R3;       // case 3: 8 <= e' < 32;
    IF CC JUMP case_3;

    // The two remaining cases are:
    // case 4: 32 <= e' < 40    mantissa entirely in high half
    // case 5: 40 <= e' < 64    mantissa partially off the top
    // of high half. Both treated the same.

case_4:
case_5:
    // we've shifted the value off the top of the high half.
    // set high = mantisa << (e'-32), low = 0
    R3 = 32;
    R3 = R1 - R3;
    R1 = ASHIFT R0 BY R3.L;
    R0 = 0;
    CC = P0 < 0;
    IF CC JUMP need_neg;
    RTS;

case_1:
case_2:
    // We have either:
    // case 1: -24 <= e' < 0    mantissa partially off bottom of low
    // case 2:   0 <= e' < 8    mantissa entirely in low half
    // both are treated the same
    R0 = ASHIFT R0 BY R1.L;
    R1 = 0;
    CC = P0 < 0;
    IF CC JUMP need_neg;
    RTS;

case_3:
    // case 3: 8 <= e' < 32     mantissa split between high and low
    R2 = R0;            // Save L, for computing H
    R0 = ASHIFT R0 BY R1.L;     // L=L>>e'
    R3 = 32;            // Want H=L>>(32-e'), which is
    R3 = R1 - R3;           // H=L<<(e'-32)
    R1 = ASHIFT R2 BY R3.L;
    CC = P0 < 0;
    IF CC JUMP need_neg;
    RTS;

ret_zero:
    R0 = 0;
    R1 = R0;
    RTS;

need_neg:
    // The float was negative, so negate the shifted result.
    R0 = -R0;
    CC = CARRY;
    CC = !CC;
    R2 = CC;
    R1 = -R1;
    R1 = R1 - R2;
    RTS;

.__float32_to_longlong64.end:
.global __float32_to_longlong64;
.type __float32_to_longlong64, STT_FUNC;
