/*
** Copyright (c) 2003-2004 Analog Devices Inc
 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

** Signed long long division.
*/

#if defined(__ADSPBF535__) || defined(__AD6532__)
#define CARRY AC
#else
#define CARRY AC0
#endif

.text;
.global ___divdi3;
.align 2;

___divdi3 :
    /* Save reg-based params - likely to need to restore them later */
    [SP+0] = R0;
    [SP+4] = R1;
    [SP+8] = R2;
    R3 = [SP+12];
    LINK 4;         // Storage space for the sign of the result
    [--SP] = (R7:4, P5:3);

    /* Attempt to use divide primitives first; these will handle
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

    /* We now know that the two 64-bit parameters contain positive
       16-bit values, so we can use the internal primitives */
    DIVS(R0, R2);
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
    R0 = R0.L (X);
    R1 = R0 >>> 31;
    (R7:4, P5:3) = [SP++];
    UNLINK;
    RTS;

    /* Can't use the primitives. Test common identities. */
    /* If the identity is true, return the value in R6,R7. */

.IDENTS:
    // Check for 0/y, return zero
    R4 = R0 | R1;
    CC = R4 == 0;           /* NR==0 => 0 */
    IF CC JUMP ZERO_RETURN;

    // Check for x/x, return 1
    R6 = R0 - R2;
    R7 = R1 - R3;
    R4 = R6 | R7;           /* if x==y, R4 will now be zero */
    R6 += 1;            /* so R6 would now be 1 */
    CC = R4 == 0;
    IF CC JUMP IDENT_RETURN;

    // Check for x/1, return x
    R6 = R0;
    R7 = R1;
    CC = R3 == 0;
    IF !CC JUMP nexttest (bp);
    CC = R2 == 1;
    IF CC JUMP IDENT_RETURN;

nexttest:

    // Check for x/-1, return -x
    // first, negate R6/R7
    R6 = -R6;
    CC = CARRY;
    CC = !CC;
    R7 = -R7;
    R4 = CC;
    R7 = R7 - R4;
    // then check whether y is -1
    R4 = R2 & R3;
    CC = R4 == -1;
    IF CC JUMP IDENT_RETURN;

    /* Identities haven't helped either. Perform the full
       division process. */

    R4 = R1 ^ R3;           // Note the sign of the result
    [FP -4] = R4;           // and store for later.

    CC = R1 < 0;
    IF !CC JUMP xispos;
    // negate x to get positive value X'=ABS(X)
    R0 = -R0;
    CC = CARRY;
    CC = !CC;
    R1 = -R1;
    R4 = CC;
    R1 = R1 - R4;
xispos:
    // We also want to get Y'=ABS(Y), but the inner loop involves us
    // either adding or subtracting Y'. I.e. Adding Y' or -Y', i.e.
    // Adding Y' or Y. So we want to negate regardless.

    P0 = R2;            // First save Y in P0,P1.
    P1 = R3;
    R2 = -R2;           // Then negate Y.
    CC = CARRY;
    CC = !CC;
    R3 = -R3;
    R4 = CC;
    R3 = R3 - R4;
    P2 = R2;            // And store into P2,P3.
    P3 = R3;

    // Assume Y positive, and P0,P1=Y, and P2,P3=-Y.
    // But if Y is negative, need to swap them over.
    CC = R3 < 0;
    IF !CC P2 = P0;
    IF !CC P3 = P1;
    IF !CC P0 = R2;
    IF !CC P1 = R3;

    // At this point, P0,P1 == Y', and P2,P3 == -Y'


    /* We now need to start computing a quotient and remainder.
       We use the following register assignments:
       R0-R1    x, workspace
       R2-R3    y, workspace
       R4-R5    partial division
       R6-R7    partial remainder
       P5       AQ;
       The division and remainder form a 128-bit value, with
       the Remainder in the higher bits.
    */
    R6 = 0;             // remainder = 0
    R7 = R6;

    // Set the quotient to X' << 1. So we want to shift in 0:

    CC = R6;            // i.e. zero
    R4 = ROT R0 BY 1;
    R5 = ROT R1 BY 1;       // Now X'<<1.

    P5 = R6;            // Set AQ = 0

    P4 = 63;            /* Set loop counter   */

    LSETUP(LST,LEND)  LC0 = P4; /* Setup loop */
LST:    
    /* Shift quotient and remainder up by one; the bit shifted out
       of quotient is shifted into the bottom of the remainder. */

    R0 = 0;
    CC = R0;
    R4 = ROT R4 BY 1;       // bit from low q to high q
    R5 = ROT R5 BY 1;       // bit from high q to low r
    R6 = ROT R6 BY 1;       // bit from low r to high r
    R7 = ROT R7 BY 1;       // bit discarded

    R2 = P2;            // Recover -Y'
    R3 = P3;
    CC = P5 < 0;            // Check AQ
    IF CC R2 = P0;          // If set, then use Y' instead of -Y'
    IF CC R3 = P1;
    R6 = R6 + R2;           // remainder += Y' (or -= Y')
    CC = CARRY;
    R0 = CC;
    R7 = R7 + R3;
    R7 = R7 + R0;

    R0 = P1;            // Get high half of Y'.
    R0 = R7 ^ R0;           // Next AQ comes from remainder^Y'
    P5 = R0;            // Save for next iteration
    R0 >>= 31;          // Position for "shifting" into quotient
    BITCLR(R4,0);           // Assume AQ==1, shift in zero
    BITTGL(R0,0);           // tweak AQ to be what we want to shift in
LEND:   R4 = R4 + R0;           // then set shifted-in value to tweaked AQ.

#if 0
// This part is breaking -2/2 (means we get -2 instead of -1)
    R0 = [FP+12];           // Get high part of X
    R0 >>= 31;          // and if negative, then
    R4 = R4 + R0;           // add into quotient
    CC = CARRY;
    R0 = CC;
    R5 = R5 + R0;
#endif

    R0 = -R4;           // Set result to -quotient
    CC = CARRY;
    CC = !CC;
    R1 = -R5;
    R6 = CC;
    R1 = R1 - R6;

    R6 = [FP-4];            /* Get sign of result from X^Y */
    CC = R6 < 0;
    IF !CC R0 = R4;         // and if not negative, then set
    IF !CC R1 = R5;         // result to quotient after all.

    (R7:4, P5:3)= [SP++];
    UNLINK;
    RTS;

IDENT_RETURN:
    R0 = R6;            /* Return an identity value */
    R1 = R7;
ZERO_RETURN:
    (R7:4, P5:3) = [SP++];
    UNLINK;
    RTS;                /* ...including zero */
DIV_BY_ZERO:
    R1 = ROT R1 BY 1;       /* save sign bit in CC */
    R0 = ~R2;           /* R2==0, so R0 = all-ones */
    R1 = ROT R0 BY -1;      /* and copy to R1, but restore sign */
    (R7:4, P5:3) = [SP++];      /* to give us 7fff.... or ffff.... */
    UNLINK;
    RTS;

.___divdi3.end:
