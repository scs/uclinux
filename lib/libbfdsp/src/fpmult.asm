/***************************************************************************
Copyright (c) 2000-2004 Analog Devices Inc
 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


****************************************************************************
  File name :  fpmult.asm 
 
  This function performs 32 bit floating point multiplication. Implemention
  is based on the algorithm mentioned in the reference. Some more conditionS
  are added in the present algorithm to take care of various testcases.
     
  Registers used:
		  Operands in  R0 & R1 
		  R0 - X operand, R1 - Y operand
		  R2 - R7 and P0 - P5 
	
		  
  Special case: 
		1)If(x AND y)==0,Return 0, 
		2)Overflow  : If(Exp(x) + Exp(y) > 254,
			      Return 0X7F80000 or 0xFF80000
			      depending upon sign of X and y. 
			      
		3)Underflow : If(Exp(x) + Exp(y) <= -149,
			      RETURN 0.
  
  Reference  : Computer Architecture a Quantitative Approach 
	       second edition 
	       by Jhon L Hennessy and David Patterson 
		
  BLACKFIN  Floating point hidden function
  IPDC, Bangalore,   10 July 2000.

  Modified for new instruction set 
  and tested using Dev13 toolset on : 13 October 2000 

  Changed branch to RETURN_ZERO to RETURN_MULTZERO.
	    
**************************************************************/
#define  BIASEXP    127
#define  MAXBIASEXP 254
#if defined(__ADSPBF535__) || defined(__AD6532__)
#define CARRYFLAG   AC
#else
#define CARRYFLAG   AC0
#endif

.text;
.align 2;

.global ___float32_mul;
.type ___float32_mul, STT_FUNC;
___float32_mul:
    [--SP] = (R7:4,P5:3);       /* Push registers R4-R7,P3-P5 */
    R7 = R0^R1;         /* R7 extracts sign of the X & Y */   
    P0 = R7;            /* Store sign  */
    R4 = 0;
	R2= R0<< 1;         /* Remove the sign bit of X */
    R3= R1<< 1;         /* Remove the sign bit of Y */
    CC = R2 == R4;          /* Check if == 0 */
    IF CC JUMP RETURN_MULTZERO; /* Return zero, if true */
    CC = R3 == R4;
    IF CC JUMP RETURN_MULTZERO; /* Return zero, if true */
				
    /* Get exponents. */
    R2= R2 >> 24;           /* Exponent of X operand */
    R3= R3 >> 24;           /* Exponent of Y operand */
	
    // Compute result exponent, and check for overflow
    R4 = BIASEXP;
    R5 = R2 + R3;
    R5 = R5 - R4;
    P1 = R5;            // store biased result exponent
    R4 <<= 1;           // R4 now 254, max allowed exponent
    CC = R4 < R5;
    IF CC JUMP OVERFLOW;

GET_X_MANTISSA:
    R5= R0<< 8;         /* Remove sign and exponent bits of */
	BITSET(R5,31);          /* X operand and make hidden bit explicit */
	R0 = R5 >> 8;           /* bring back x_mantissa to position with hidden bit set */ 
GET_Y_MANTISSA:
    R6= R1 << 8;            /* Remove sign and exponent bits*/
    BITSET(R6,31);          /* Make hidden bit explicit */  
    R1 = R6 >> 8;           /* Bring back y_mantissa to position with hidden bit set */ 
DO_INT32_MULT:
	A1 = A0 = 0;

    R3=(A1=R0.L*R1.L),R2=(A0=R0.H*R1.L)(FU);    /* Multiply R0 by lsb 16 bits of R1 */  
	R5=(A1=R0.H*R1.H),R4=(A0=R0.L*R1.H)(FU);    /* Multiply R0 by msb 16 bits of R1 */

	R4 = R2+R4;         /* Add middle products */
    CC = CARRYFLAG;         /* Check for carry */
    R7 = CC;            /* R7 is 1 if true, 0 if false */
    R7 =  R7 << 16;         /* If true, add one to msb 16 bit */ 
    R5 = R5+R7;         /* of last product (R5)           */  
    R6 =  R4 >> 16;         /* Extract  msb 16 bits from accumlated sum */
    R4 =  R4 << 16;         /* Take only lsb 16 bits */
    R4 = R3+R4;         /* Get least significant 32 bit result */
    CC = CARRYFLAG;         /* Check for carry */
    R7 = R6;
    R7 += 1;            /* If true, add one to  */
    IF CC R6 = R7;          /* msb 16 bit middle product sum (R6)  */
    R5 = R5+R6;         /* Get most significant 32 bit result */
		    /* Multiplication result stored in reg. pair R5:R4 */
    R5 = R5 << 8;           /* Arrange the result in 24 bit format */ 
    R6 = R4 >> 24;          /* Extract only 8 msbits */
    R4 = R4 << 8 ;          /* R4 = A */  
    R5 = R5|R6;         /* R5 = P */                

    // At this point, R5 holds the result, aligned at LSB, and R4 holds
    // the remainder, aligned at MSB. P1 holds the biased exponent (0..255).
    R2 = P1;
    CC = R2 < 1;
    IF CC JUMP denorm;

    CC = BITTST(R5,23);
    R3 = CC;
    R2 = R2 + R3;           // if bit is set, increment exponent
    BITTGL(R3,0);           // if bit, R3==0, else R3==1
    R4 = ROT R4 BY R3.L;        // rotate 0 in, only if bit was clear
    R5 = ROT R5 BY R3.L;        // and propagate from remainder to result.

rounding:
    // R is MSB of remainder, S is rest of remainder, G is LSB of result.
    R3 = R4 >> 31;          // R bit
    R6 = R5 << 31;          // G bit
    R4 = R6 | R4;           // G | S
    CC = R4;
    R4 = CC;
    R3 = R3 & R4;           // R & (S | G)
    R6 = R5 + R3;           // check whether mantissa is zero,
    CC = R6 == 0;           // even with any rounding added in
    IF CC R2 = R6;          // and if so, also make exponent zero.
    BITCLR(R5,23);
    R2 = R2 << 23;
    R0 = R2 | R5;
    R0 = R0 + R3;
    R1 = P0;
    R1 = R1 >> 31;
    R1 = R1 << 31;
    R0 = R0 | R1;
    (R7:4,P5:3) = [SP++];       /* Pop registers R4-R7, P3-P5 */
    RTS;

denorm:
    // The result is underflowing the exponent, so we need to
    // denormalise until the exponent is within range. This
    // means shifting right N=exp+126 bits, and incrementing
    // the exponent by N; Except that here, the exponent is already
    // biased, so we need to increment it back to 1, not to -126.

    // -130 (approx) < R2 < 0
    R6 = 32;
#ifdef __WORKAROUND_SHIFT
    R6 = R6 + R2;           // may produce a negative number
#else
    R2 = -R2;           // exponent now 0 or positive
    R6 = R6 - R2;           // may produce a negative number
#endif
    R3 = R5;
#ifdef __WORKAROUND_SHIFT
    R0 = -32;
    R2 = MAX(R2,R0);
    R5 = LSHIFT R5 BY R2.L;
    R4 = LSHIFT R4 BY R2.L;
#else
    R5 >>= R2;          // move result and remainder down
    R4 >>= R2;
#endif
    R2 = R2 - R2;           // set exponent to 0.
#ifdef __WORKAROUND_SHIFT
    CC = R6 < 0;
    R3 <<= R6;
    IF CC R3 = R2;
#else
    R3 <<= R6;          // R6 unsigned, so R6<0 => 0
#endif
    R4 = R3 | R4;           // then incorporate saved bits
    JUMP rounding;

RETURN_MULTZERO:
	R0 = P0;            /* Return zero, with appropriate */ 
    R0 >>= 31;          /* sign bit */
    R0 <<= 31;
    (R7:4,P5:3) = [SP++];       /* Pop registers R4-R7, P3-P5 */
    RTS;

OVERFLOW:
    R0.L = 0X7F80;          /* Overflow occured,return NaN */
    R0 <<= 17;          /* R0 now 0x7F800000, shifted left one. */
    R1 = P0;            /* Extract sign, and set into result */
    CC = BITTST(R1,31);
    R0 = ROT R0 BY -1;      /* by rotating back to 0x7F800000, with CC */
    (R7:4,P5:3) = [SP++];       /* Pop registers R4-R7, P3-P5 */
    RTS;
.___float32_mul.end:

