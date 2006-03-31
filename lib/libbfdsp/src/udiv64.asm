/*
** Copyright (C) 2003-2004 Analog Devices, Inc
 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

** unsigned long long division.
*/

#if defined(__ADSPBF535__) || defined(__AD6532__)
#define CARRY AC
#else
#define CARRY AC0
#endif

.text;
.global ___udivdi3;
.type ___udivdi3,STT_FUNC;
.extern ___mulli3;

.align 2;
___udivdi3:
    /* Save reg-based params first - we're likely to need them. */
    [SP+0] = R0;
    [SP+4] = R1;
    [SP+8] = R2;
    R3 = [SP+12];
    LINK 4;         // We'll store whether to inc div, here
    [--SP] = (R7:4, P5:3);

    /* Attempt to use divide primitive first; these will handle
    most cases, and they're quick - avoids stalls incurred by
    testing for identities. */

    R4 = R2 | R3;
    CC = R4 == 0;
    IF CC JUMP DIV_BY_ZERO;
    R4.H = 0x8000;
    R4 >>>= 16;         /* R4 now 0xFFFF8000 */
    R5 = R0 | R2;           /* If either dividend or */
    R4 = R5 & R4;           /* divisor have bits in */
    CC = R4;            /* top half or low half's sign */
    IF CC JUMP .IDENTS;     /* bit, skip builtins. */
    R4 = R1 | R3;           /* Also check top halves */
    CC = R4;
    IF CC JUMP .IDENTS;

    /* Can use the builtins. */

    AQ = CC;            /* Clear AQ (CC==0) */
    DIVQ(R0, R2);
    DIVQ(R0, R2);
    DIVQ(R0, R2);
    DIVQ(R0, R2);
    DIVQ(R0, R2);
    DIVQ(R0, R2);
    DIVQ(R0, R2);
    DIVQ(R0, R2);
    DIVQ(R0, R2);
    DIVQ(R0, R2);
    DIVQ(R0, R2);
    DIVQ(R0, R2);
    DIVQ(R0, R2);
    DIVQ(R0, R2);
    DIVQ(R0, R2);
    DIVQ(R0, R2);
    DIVQ(R0, R2);
    R0 = R0.L (Z);
    R1 = 0;
    (R7:4, P5:3) = [SP++];
    UNLINK;
    RTS;

.IDENTS:
    /* Test for common identities. Value to be returned is
       placed in R6,R7. */
    // Check for 0/y, return 0
    R4 = R0 | R1;
    CC = R4 == 0;           /* NR==0 => 0 */
    IF CC JUMP RETURN_R0;

    // Check for x/x, return 1
    R6 = R0 - R2;           // If x == y, then both
    R7 = R1 - R3;           // R6 and R7 will be zero,
    R4 = R6 | R7;           // making R4 zero.
    R6 += 1;            // which would now make R6,R7==1.
    CC = R4 == 0;           /* NR==DR => 1 */
    IF CC JUMP RETURN_IDENT;

    // Check for x/1, return x
    R6 = R0;
    R7 = R1;
    CC = R3 == 0;
    IF !CC JUMP nexttest;
    CC = R2 == 1;
    IF CC JUMP RETURN_IDENT;

nexttest:
    // Check for x < y, return 0
    R6 = 0;
    R7 = R6;
    CC = R1 < R3 (IU);
    IF CC JUMP RETURN_IDENT;
    CC = R1 == R3;
    IF !CC JUMP no_idents;
    CC = R0 < R2 (IU);
    IF CC JUMP RETURN_IDENT;    /* NR < DR => 0 */

no_idents:
    /* Idents don't match. Go for the full operation. */

    // If X, or X and Y have high bit set, it'll affect the
    // results, so shift right one to stop this. If we shift
    // set bits off the right, then that can also affect the
    // result: If X's lsb is set, and Y's isn't, then the
    // result will come out to one less than it should. So we
    // record whether this is the case. Note: we've already
    // checked that X >= Y, so Y's msb won't be set unless X's
    // is.

    R4 = 0;
    CC = R1 < 0;
    IF !CC JUMP x_msb_clear;
    CC = !CC;           // 1 -> 0;
    R1 = ROT R1 BY -1;      // Shift X >> 1
    R0 = ROT R0 BY -1;      // lsb -> CC
    R4 = CC;            // (x lsb)
    BITSET(R4,31);          // to record only x msb was set
    CC = R3 < 0;
    IF !CC JUMP y_msb_clear;
    CC = !CC;
    R3 = ROT R3 BY -1;      // Shift Y >> 1
    R2 = ROT R2 BY -1;
    R4 = ROT R4 BY 1;       // (x lsb, y lsb)
		    // and will clear only-x-msb bit
y_msb_clear:
x_msb_clear:
    // R4 will now be 0, 1, 2 or 3, although msb may also be set.
    // 2 indicates we shifted 1 out of X, and 0 out of Y,
    // so we have to increment result by one.
    // bit 31 indicates X msb set, but Y msb wasn't, and no bits
    // were lost, so we should shift result left by one.
    // All other cases indicate that an increment of the
    // result at the end is unnecessary, because the shifted
    // values didn't lose any bits that change the result.

    [FP-4] = R4;        // save for later

    // In the loop that follows, each iteration we add
    // either Y' or -Y' to the Remainder. We compute the
    // negated Y', and store, for convenience. Y' goes
    // into P0,P1, while -Y' goes into P2,P3.

    P0 = R2;
    P1 = R3;
    R2 = -R2;
    CC = CARRY;
    CC = !CC;
    R4 = CC;
    R3 = -R3;
    R3 = R3 - R4;
    P2 = R2;
    P3 = R3;

    /* In the loop that follows, we use the following
       register assignments:
	R0,R1   X, workspace
	R2,R3   Y, workspace
	R4,R5   partial Div
	R6,R7   partial remainder
	P5  AQ
      The remainder and div form a 128-bit number, with
      the remainder in the high 64-bits.
    */
    P4 = 64;            /* Iterate once per bit */
    R4 = R0;            /* Div = X' */
    R5 = R1;
    R6 = 0;             /* remainder = 0 */
    R7 = R6;
    P5 = R6;            /* AQ = 0 */

    LSETUP(ULST,ULEND) LC0 = P4;    /* Set loop counter */
ULST:   
    /* Shift Div and remainder up by one. The bit shifted
    out of the top of the quotient is shifted into the bottom
    of the remainder. */
    R0 = 0;
    CC = R0;
    R4 = ROT R4 BY 1;
    R5 = ROT R5 BY 1;       // low q to high q
    R6 = ROT R6 BY 1;       // high q to low r
    R7 = ROT R7 BY 1;       // low r to high r

    R0 = P2;            // Assume add -Y'
    R1 = P3;
    CC = P5 < 0;            // But if AQ is set...
    IF CC R0 = P0;          // then add Y' instead
    IF CC R1 = P1;

    R6 = R6 + R0;           // Rem += (Y' or -Y')
    CC = CARRY;
    R0 = CC;
    R7 = R7 + R1;
    R7 = R7 + R0;

    R1 = P1;            // Set the next AQ bit
    R1 = R7 ^ R1;           // from Remainder and Y'
    P5 = R1;            // and save for next time
    R1 >>= 31;          // Negate AQ's value, and
    BITTGL(R1, 0);          // add that to the Div
ULEND:  R4 = R4 + R1;

    // Now restore our Inc value, which recorded what we
    // shifted out at the start.
    R6 = [FP-4];
    CC = R6 == 2;           // This is the only case
    R1 = CC;            // that matters
    R0 = R4 + R1;           // Add it (1 or 0) to Div
    CC = CARRY;         // Putting the result into
    R4 = CC;            // R0,R1 for returning.
    R1 = R5 + R4;

    CC = BITTST(R6,30);     // Just set CC=0
    R4 = ROT R0 BY 1;       // but if we had to shift X,
    R5 = ROT R1 BY 1;       // and didn't shift any bits out,
    CC = BITTST(R6,31);     // then the result will be half as
    IF CC R0 = R4;          // much as required, so shift left
    IF CC R1 = R5;          // one space.

    (R7:4, P5:3) = [SP++];
    UNLINK;
    RTS;

RETURN_IDENT:
    R0 = R6;
    R1 = R7;
RETURN_R0:
    (R7:4, P5:3) = [SP++];
    UNLINK;
    RTS;
DIV_BY_ZERO:
    R0 = ~R2;
    R1 = R0;
    (R7:4, P5:3) = [SP++];
    UNLINK;
    RTS;
    
.___udivdi3.end:
