/*
** Copyright (C) 2002-2003 Analog Devices, Inc
 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

** Arithmetic shift, on signed long long.
** inline long long __ashrdi3 (long long  ll1, int i1);
*/

.text;

.align 2;
___ashftli:
    CC = R2 == 0;
    IF CC JUMP finished;    // nothing to do
    CC = R2 < 0;
    IF CC JUMP rshift;
    R3 = 64;
    CC = R2 < R3;
    IF !CC JUMP retzero;

    // We're shifting left, and it's less than 64 bits, so
    // a valid result will be returned.

    R3 >>= 1;   // R3 now 32
    CC = R2 < R3;

    IF !CC JUMP zerohalf;

    // We're shifting left, between 1 and 31 bits, which means
    // some of the low half will be shifted into the high half.
    // Work out how much.

    R3 = R3 - R2;

    // Save that much data from the bottom half.

    P0 = R7;
    R7 = R0;
    R7 >>= R3;

    // Adjust both parts of the parameter.

    R0 <<= R2;
    R1 <<= R2;

    // And include the bits moved across.

    R1 = R1 | R7;
    R7 = P0;
    RTS;

zerohalf:
    // We're shifting left, between 32 and 63 bits, so the
    // bottom half will become zero, and the top half will
    // lose some bits. How many?

    R2 = R2 - R3;   // N - 32
    R1 = R0;
    R1 <<= R2;
    R0 = 0;
    RTS;

retzero:
    R0 = 0;
    R1 = R0;
finished:
    RTS;

rshift:
    // We're shifting right, but by how much?
    R2 = -R2;
    R3 = 64;
    CC = R2 < R3;
    IF !CC JUMP allsign;

    // Shifting right less than 64 bits, so some result bits will
    // be retained.

    R3 >>= 1;   // R3 now 32
    CC = R2 < R3;
    IF !CC JUMP signhalf;

    // Shifting right between 1 and 31 bits, so need to copy
    // data across words.

    P0 = R7;
    R3 = R3 - R2;
    R7 = R1;
    R7 <<= R3;
    R1 >>>= R2;
    R0 >>= R2;
    R0 = R7 | R0;
    R7 = P0;
    RTS;

signhalf:
    // Shifting right between 32 and 63 bits, so the top half
    // will become all sign-bits, and the bottom half is some
    // of the top half. But how much?

    R2 = R2 - R3;
    R0 = R1;
    R0 >>>= R2;
    R1 >>>= 31;
    RTS;

allsign:
    // Shifting more than 63 bits right, so the result becomes
    // nothing but sign bits.

    R1 >>>= 31;
    R0 = R1;
    RTS;

.___ashftli.end:
.global ___ashftli;
.type ___ashftli, STT_FUNC;
