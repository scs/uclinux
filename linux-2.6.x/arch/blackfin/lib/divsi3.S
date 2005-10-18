/*
 * File:         arch/blackfin/lib/divsi3.S
 * Based on:     
 * Author:       
 *               
 * Created:      
 * Description:   16 / 32 bit signed division .
 *                 Special cases :
 *                      1)  If(numerator == 0)
 *                             return 0
 *                      2)  If(denominator ==0)
 *                             return positive max = 0x7fffffff
 *                      3)  If(numerator == denominator)
 *                             return 1
 *                      4)  If(denominator ==1)
 *                             return numerator
 *                      5)  If(denominator == -1)
 *                             return -numerator
 *
 *		Operand         : R0 - Numerator   (i)
 *              		  R1 - Denominator (i)
 *                 		  R0 - Quotient    (o)
 *			  	  Registers Used : R2-R7,P0-P2
 * Rev:          $Id$
 *
 * Modified:     
 *               Copyright 2004-2005 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.
 * If not, write to the Free Software Foundation,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

.global   ___divsi3;

.align 8;
___divsi3 :
/*
 * Attempt to use divide primitives first; these will handle
 *  most cases, and they're quick - avoids stalls incurred by
 *  testing for identities. 
 */
	R2.H = 0x8000;
	R2 >>>= 16;                     /* R2 now 0xFFFF8000 */
	R3 = R0 | R1;                   /* If either dividend or */
	R2 = R3 & R2;                   /* divisor have bits in */
	CC = R2;                        /* top half or low half's sign */
	IF CC JUMP IDENTS;             /* bit, skip builtins. */
	DIVS(R0, R1);
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
	R0 = R0.L (X);
	RTS;

	/* Can't use the primitives. Test common identities. 
	 * If the identity is true, return the value in R2. 
	 */

IDENTS:
	CC = R0 == 0;                   /* NR==0 => 0 */
	IF CC JUMP ZERO_RETURN;

	R2.L = -1;                      /* DR==0 => 0x7FFFFFFF */
	R2.H = 0x7FFF;
	CC = R1 == 0;
	IF CC JUMP IDENT_RETURN;

	R2 = 1 (Z);                     /* NR==DR => 1 */
	CC = R0 == R1;
	IF CC JUMP IDENT_RETURN;

	R2 = R0;                        /* DR==1 => NR */
	CC = R1 == 1;
	IF CC JUMP IDENT_RETURN;

	R2 = -R0;                       /* DR==-1 => -NR */
	CC = R1 == -1;
	IF CC JUMP IDENT_RETURN;

	/* Identities haven't helped either.
	 * Perform the full division process.  
	 */

	P0 = R0;                        /* Copy R0,R1 */
	P1 = R1;
	R0 = ABS R0;                    /* Absolute of R0,R1 */
	CC = V;
	[--SP] = (R7:4);                /* Push registers R4-R7 */
	R7 = CC;

	R1 = ABS R1;
	R3 = 0 ;                        /* Clear msw partial remainder */ 
	R2 = R0<< 1;                    /* R2 lsw of dividend  */ 
	R4 = R0^R1;                     /* Get sign */
	R5 = R4 >> 31;                  /* Shift sign to LSB */

	R2 = R2|R5;                     /* Shift quotient bit */ 
	P2 = 31;                        /* Set loop counter   */
	R4 = R3^R1;                     /* Get new quotient bit */  

	LSETUP ( LST,LEND )  LC0 = P2;     /* Setup loop */
LST:    R5 = R2 >> 31;                  /* record copy of carry from R2 */
	R2 = R2 << 1;                   /* Shift 64 bit dividend up by 1 bit */
	R3 = R3 << 1;
	R3 = R3|R5;                     /* and add carry */
	CC = R4 < 0;                    /* Check quotient(AQ) */
	R5 = -R1;                       /* we might be subtracting divisor (AQ==0) */
	IF CC R5 = R1;                  /* or we might be adding divisor  (AQ==1)*/
	R3 = R3 + R5;                   /* do add or subtract, as indicated by AQ */
	R4 = R3^R1;                     /* Generate next quotient bit */
	R5 = R4 >> 31;
	BITCLR(R2,0);                   /* Assume AQ==1, shift in zero */
	BITTGL(R5,0);                   /* tweak AQ to be what we want to shift in */
LEND:   R2 = R2 + R5;                   /* and then set shifted-in value to tweaked AQ. */

	R2 = R2 + R7;
	R0 = P0;
	R1 = P1;
	R3 = R0^R1;
	CC = R3<0;                      /* Check sign of R0 and R1 */
	(R7:4)= [SP++];                 /* Pop registers R4-R7 */
	R0 = -R2;                       /* If negative, return -R2 */
	IF !CC R0 = R2;                 /* If positive, return R2 */
	RTS;

IDENT_RETURN:
	R0 = R2;                        /* Return an identity value */
ZERO_RETURN:
	RTS;                            /* ...including zero */
