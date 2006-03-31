/******************************************************************************
  Copyright(c) 2000-2005 Analog Devices Inc.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

******************************************************************************
  File Name      : udiv32.asm
  Module Name    : Runtime Support
  Label name     : ___udiv32
  Description    : 32 / 32 bit unsigned integer division .
******************************************************************************/

.text;
.global   ___udiv32;

.type     ___udiv32, STT_FUNC;

.align 2;
___udiv32:
    CC = R0 < R1 (IU);    /* If X < Y, always return 0 */
    R2 = 0;
    IF CC JUMP .RETURN_IDENT;

    R2 = R1 << 16;
    CC = R2 <= R0 (IU);
    IF CC JUMP .IDENTS;

    P0 = 17;
    R2 = R0 >> 31;       /* if X is a 31-bit number */
    R3 = R1 >> 15;       /* and Y is a 15-bit number */
    R2 = R2 | R3;        /* then it's okay to use the DIVQ builtins */
    CC = R2;             
    IF CC JUMP .y_16bit;

.fast:
    AQ = CC;             /* Clear AQ (CC==0) */
    LSETUP(.lp, .lp) LC0 = P0;
.lp:    DIVQ(R0, R1);
    R0 = R0.L (Z);
    RTS;

.y_16bit:
    /* We know that the upper 17 bits of Y might have bits set,
    ** or that the sign bit of X might have a bit. If Y is a
    ** 16-bit number, but not bigger, then we can use the builtins
    ** with a post-divide correction.
    ** R3 currently holds Y>>15, which means R3's LSB is the
    ** bit we're interested in. 
    */

    CC = R3 == 1;        /* if so, Y is 0x8nnn */
    IF CC JUMP .shift_and_correct;

    /* Fall through to the identities */

.IDENTS:
    /* Test for common identities. Value to be returned is placed in R2. */
    CC = R0 == 0;        /* 0/Y => 0 */
    IF CC JUMP .RETURN_R0;

    R2 = -1 (X);         /* X/0 => 0xFFFFFFFF */
    CC = R1 == 0;
    IF CC JUMP .RETURN_IDENT;

    R2 = -R2;            /* R2 now 1 */
    CC = R0 == R1;       /* X==Y => 1 */
    IF CC JUMP .RETURN_IDENT;

    R2 = R0;
    CC = R1 == 1;        /* X/1 => X */
    IF CC JUMP .RETURN_IDENT;

    R2.L = ONES R1;
    R2 = R2.L (Z);
    CC = R2 == 1;
    IF CC JUMP .power_of_two;

    /* Idents don't match. Go for the full operation. */

    [--SP] = (R7:4, P5:5);          /* Push registers R4-R7 and P5 */

    P1 = R0;
    P2 = R1;
				   /* If either R0 or R1 have sign set, */
				   /* divide them by two, and note it's */
				   /* been done. */
    R6 = 2;                         /* assume we'll shift two */
    R7 = 1;
    R3 = 0;
    R5 = R1 >> 1;
    R4 = R0 >> 1;
    CC = R1 < 0;
    IF !CC R6 = R7;                 /* R1 doesn't, so at most 1 shifted */
    IF !CC R5 = R1;                 /* and use original value. */
    CC = R0 < 0;
    IF CC R3 = R6;                  /* Number of values divided */
    IF CC R0 = R4;                  /* Shifted R0 */
    R1 = R5;                        /* Possibly-shifted R1 */
    P0 = R3;                        /* 0, 1 (NR/=2) or 2 (NR/=2, DR/=2) */

    R2 = R0;                        /* Copy dividend  */
    R3 = 0;                         /* Clear partial remainder */
    P5 = 32;                        /* Set loop counter */
    R4 = R3;                        /* Initialise quotient bit */

    LSETUP(.ULST, .ULEND) LC0 = P5; /* Set loop counter */
.ULST:  R6 = R2 >> 31;             /* R6 = sign bit of R2, for carry */
	 R2 = R2 << 1;              /* Shift 64 bit dividend up by 1 bit */
	 R3 = R3 << 1;
	 R3 = R3 | R6;              /* Include any carry */
	 CC = R4 < 0;               /* Check quotient(AQ) */
	 R5 = -R1;                  /* If AQ==0, we'll sub divisor */
	 IF CC R5 = R1;             /* and if AQ==1, we'll add it. */
	 R3 = R3 + R5;              /* Add/sub divsor to partial remainder */
	 R4 = R3 ^ R1;              /* Generate next quotient bit */
	 BITCLR(R2,0);              /* Assume AQ==1, so "shift in" 0 */
	 R5 = R4 >> 31;             /* Get AQ */
	 BITTGL(R5, 0);             /* Invert it, to get what we'll shift */
.ULEND: R2 = R2 + R5;              /* and "shift" it in. */

    CC = P0 == 0;                   /* Check how many inputs we shifted */
    IF CC JUMP .NO_MULT;            /* if none... */
    R6 = R2 << 1;
    CC = P0 == 1;
    IF CC R2 = R6;                  /* if 1, Q = Q*2 */
    IF !CC R1 = P2;                 /* if 2, restore stored divisor */

    R3 = R2;                        /* Copy of R2 */
    R3 *= R1;                       /* Q * divisor */
    R4 = P1;                        /* Get stored dividend(R0)  */
    R5 = R4 - R3;                   /* Z = (dividend - Q * divisor) */
    CC = R1 <= R5 (IU);             /* Check if divisor <= Z? */
    R6 = CC;                        /* if yes, R6 = 1 */
    R2 = R2 + R6;                   /* if yes, add one to quotient(Q) */
.NO_MULT:
    (R7:4,P5:5) = [SP++];           /* Pop registers R4-R7 and P5 */
    R0 = R2;                        /* Store quotient */
    RTS;

.RETURN_IDENT:
    R0 = R2;
.RETURN_R0:
    RTS;

.power_of_two:
    /* Y has a single bit set, which means it's a power of two.
    ** That means we can perform the division just by shifting
    ** X to the right the appropriate number of bits 
    */

    /* signbits returns the number of sign bits, minus one.
    ** 1=>30, 2=>29, ..., 0x40000000=>0. Which means we need
    ** to shift right n-signbits spaces. It also means 0x80000000
    ** is a special case, because that *also* gives a signbits of 0 
    */

    R2 = R0 >> 31;
    CC = R1 < 0;
    IF CC JUMP .RETURN_IDENT;

    R1.l = SIGNBITS R1;
    R1 = R1.L (Z);
    R1 += -30;
    R0 = LSHIFT R0 by R1.L;
    RTS;

.shift_and_correct:
    /* Y is known to be in the range 0x8000 - 0x8FFF. To handle this case, we:
       - prescale:
	    X' = X>>1
	    Y' = Y>>1
	- divide
	    R' = X' / Y'
	- reverse the division
	    T = R' * Y
	- Compare accuracy:
	    E = X - T
	- Correct result:
	    if E >= Y
		R = R'+1
	    if E < 0
		R = R'-1
	    else
		R = R'
    */

    R2 = R0 >> 1;                   /* X' = X>>1 */
    R3 = R1 >> 1;                   /* Y' = Y>>1 */
    CC = !CC;                       /* we got here via cc==1. now cc==0 */
    AQ = CC;                        /* Clear AQ */
    LSETUP (.lp2, .lp2) LC0 = P0;   /* P0 set previously */
.lp2:   DIVQ(R2, R3);
    R2 = R2.L (Z);                  /* R' = X' / Y' */
    P1 = R1;                        /* Save Y */
    P0 = R2;                        /* Save R' */
    R2 *= R1;                       /* T = R' * Y */
    R2 = R0 - R2;                   /* E = X - T */
    R0 = P0;

.retest:
    CC = R2 < 0;
    IF CC JUMP .correct;
    CC = R1 <= R2;
    IF CC JUMP .correct;
    RTS;

.correct:
    R3 = 1 (X);
    R0 = R0 + R3, R1 = R0 - R3;
    CC = R2 < 0;
    IF CC R0 = R1;
    R3 = P1;                        /* adjust E */
    R2 = R2 + R3, R3 = R2 - R3;
    IF !CC R2 = R3;
    R1 = P1;                        /* Restore Y */
    JUMP .retest;                   /* check for further correction */

.___udiv32.end:

