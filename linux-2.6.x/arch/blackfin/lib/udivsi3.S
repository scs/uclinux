/* Copyright (C) 2003 Analog Devices, Inc. All Rights Reserved. 
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License. 
 *
 * Blackfin BF533/2.6 support : LG Soft India	
 *
 * libgcc1 routines for Blackfin 533
 * Copyright (C) 2004-2005 LG Soft India. 
 *
 */

	.text
	.globl	___udivsi3
___udivsi3:
     
	/* Attempt to use divide primitive first; these will handle
        most cases, and they're quick - avoids stalls incurred by
        testing for identities. */

        R2.H = 0x8000;
        R2 >>>= 16;                     /* R2 now 0xFFFF8000 */
        R3 = R0 | R1;                   /* If either dividend or */
        R2 = R3 & R2;                   /* divisor have bits in */
        CC = R2;                        /* top half or low half's sign */
        IF CC JUMP IDENTS;             /* bit, skip builtins. */

     /* Can use the builtins. */

        AQ = CC;                        /* Clear AQ (CC==0) */
        DIVQ(R0, R1);
        DIVQ(R0, R1);
        DIVQ(R0, R1);
        DIVQ(R0, R1);
        DIVQ(R0, R1);
        DIVQ(R0, R1);
        DIVQ(R0, R1);
        DIVQ(R0, R1);
        DIVQ(R0, R1);
        DIVQ(R0, R1);
        DIVQ(R0, R1);
        DIVQ(R0, R1);
        DIVQ(R0, R1);
        DIVQ(R0, R1);
        DIVQ(R0, R1);
        DIVQ(R0, R1);
        DIVQ(R0, R1);
        R0 = R0.L (Z);
        RTS;

IDENTS:
       /* Test for common identities. Value to be returned is
          placed in R2. */
        CC = R0 == 0;                   /* NR==0 => 0 */
        IF CC JUMP RETURN_R0;
        R2 = -1 (X);                    /* DR==0 => 0xFFFFFFFF */
        CC = R1 == 0;
        IF CC JUMP RETURN_IDENT;
        R2 = -R2;                       /* R2 now 1 */
        CC = R0 == R1;                  /* NR==DR => 1 */
        IF CC JUMP RETURN_IDENT;
        R2 = R0;
        CC = R1 == 1;                   /* DR==1 => NR */
        IF CC JUMP RETURN_IDENT;
        R2 = 0 (Z);
        CC = R0 < R1 (IU);
        IF CC JUMP RETURN_IDENT;        /* NR < DR => 0 */

       /* Idents don't match. Go for the full operation. */

        [--SP] = (R7:4);                /* Push registers R4-R7 */
        [--SP] = P3;                    /* Push P3 */
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
        P3 = 32;                        /* Set loop counter */
        R4 = 0;                         /* Initialise quotient bit */ 

        LSETUP( ULST,ULEND ) LC0 = P3;  /* Set loop counter */
ULST:   R6 = R2 >> 31;                  /* R6 = sign bit of R2, for carry */
//        R2 = R2 << 1;                   /* Shift 64 bit dividend up by 1 bit */
//        R3 = R3 << 1;

        R2 <<= 1;                   /* Shift 64 bit dividend up by 1 bit */
        R3 <<= 1;
        R3 = R3 | R6;                   /* Include any carry */
        CC = R4 < 0;                    /* Check quotient(AQ) */
        R5 = -R1;                       /* If AQ==0, we'll sub divisor */
        IF CC R5 = R1;                  /* and if AQ==1, we'll add it. */
        R3= R3 + R5;                    /* Add/sub divsor to partial remainder */ 
        R4 = R3^R1;                     /* Generate next quotient bit */
        BITCLR(R2,0);                   /* Assume AQ==1, so "shift in" 0 */
        R5 = R4 >> 31;                  /* Get AQ */
        BITTGL(R5, 0);                  /* Invert it, to get what we'll shift */
ULEND:  R2 = R2 + R5;                   /* and "shift" it in. */

        CC = P0 == 0;                   /* Check how many inputs we shifted */
        IF CC JUMP NO_MULT;             /* if none... */
//      R6 = R2 << 1;
	R2 <<= 0x1;
        R6 = R2;
        CC = P0 == 1;
        IF CC R2 = R6;                  /* if 1, Q = Q*2 */
        IF !CC R1 = P2;                 /* if 2, restore stored divisor */

        R3 = R2;                        /* Copy of R2 */ 
        R3 *= R1;                       /* Q * divisor */
        R4 = P1;                        /* Get stored dividend(R0)  */
        R5 = R4 - R3;                   /* Z = (dividend - Q * divisor) */  
        CC = R1<= R5 (IU);              /* Check if divisor <= Z? */ 
        R6 = CC;                        /* if yes, R6 = 1 */
        R2 = R2 + R6;                   /* if yes, add one to quotient(Q) */  
NO_MULT:
        P3 = [SP++];                    /* Pop register P3 */
        ( R7:4) = [SP++];                /* Pop registers R4-R7 */
        R0 = R2;                        /* Store quotient */
        RTS;

RETURN_IDENT:
        R0 = R2;
RETURN_R0:
        RTS;

