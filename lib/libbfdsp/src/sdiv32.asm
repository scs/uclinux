/******************************************************************************
  Copyright(c) 2000-2004 Analog Devices Inc. 

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

******************************************************************************
  File Name      : sdiv32.asm
  Module Name    : Runtime Support
  Label name     : ___div32

  Description    : 16 / 32 bit signed division .
******************************************************************************/

.text;
.global   ___div32;

.align 2;
___div32:
	/* Attempt to use divide primitives first; these will handle
	   most cases, and they're quick - avoids stalls incurred by
	   testing for identities. */

    r3 = r0 ^ r1;
    r0 = abs r0;
#if defined(__ADSPBF535__) || defined(__AD6532__)
   CC = AV0;
#else
   CC = V;
#endif
    r3 = rot r3 by -1;
    r1 = abs r1;            /* now both positive, r3.30 means */
		    /* "negate result", r3.31 means */
		    /* overflow, add one to result */
    cc = r0 < r1;
    if cc jump .ret_zero;
    r2 = r1 >> 15;
    cc = r2;
    if cc jump .IDENTS;
    p0 = 16;
    r2 = r1 << 16;
    cc = r2 <= r0;
    if cc jump .IDENTS;
	DIVS(R0, R1);
    lsetup (.dl, .dl) lc0 = p0;
.dl:    DIVQ(R0, R1);
	R0 = R0.L (Z);
    r1 = r3 >> 31;      /* add overflow issue back in */
    r0 = r0 + r1;
    r1 = -r0;
    cc = bittst(r3, 30);
    if cc r0 = r1;
	RTS;

	/* Can't use the primitives. Test common identities. 
	 * If the identity is true, return the value in R2. 
	 */

.IDENTS:
	R2 = -1 (X);                      /* DR==0 => 0x7FFFFFFF */
    R2 >>= 1;
	CC = R1 == 0;
	IF CC JUMP IDENT_RETURN;

	CC = R0 == 0;                   /* NR==0 => 0 */
	IF CC JUMP ZERO_RETURN;

	R2 = 1 (Z);                     /* NR==DR => 1 */
	CC = R0 == R1;
	IF CC JUMP IDENT_RETURN;

	R2 = R0;                        /* DR==1 => NR */
	CC = R1 == 1;
	IF CC JUMP IDENT_RETURN;

	/* Identities haven't helped either.
	 * Perform the full division process.  
	 */

    i0 = r3;
	[--SP] = (R7:4);                /* Push registers R4-R7 */
	R3 = 0 ;                        /* Clear msw partial remainder */ 
	R2 = R0<< 1;                    /* R2 lsw of dividend  */ 
	R4 = R0^R1;                     /* Get sign */
	R5 = R4 >> 31;                  /* Shift sign to LSB */

	R2 = R2|R5;                     /* Shift quotient bit */ 
	P2 = 31;                        /* Set loop counter   */
	R4 = R3^R1;                     /* Get new quotient bit */  

	LSETUP(LST,LEND)  LC0 = P2;     /* Setup loop */
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

    r3 = i0;
    r1 = r3 >> 31;
    r2 = r2 + r1;
    cc = bittst(r3,30);
    r0 = -r2;
    if !cc r0 = r2;
	(R7:4)= [SP++];                 /* Pop registers R4-R7 */
	RTS;

IDENT_RETURN:
	R0 = R2;                        /* Return an identity value */
    r2 = -r2;
    cc = bittst(r3,30);
    if cc r0 = r2;
ZERO_RETURN:
	RTS;                            /* ...including zero */
.ret_zero:
    r0 = 0;
    rts;

.___div32.end:
