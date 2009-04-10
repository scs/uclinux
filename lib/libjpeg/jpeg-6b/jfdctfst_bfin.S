/*
* jfdctfst BlackFin
*
* Copyright (C) 2008 Frank Van Hooft  <frank@frankvh.com>
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, see the file COPYING, or write
* to the Free Software Foundation, Inc.,
* 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

/*
* This program is a hand-coded assembly-language implementation of the libjpeg
* function "jfdctfst.c", written for the Analog Devices Blackfin processor.
* As much as possible of the original jfdctfst comments & C code has been
* preserved in this file as comments, to make it possible to see the mapping
* of the original C source to Blackfin assembler.
*
* The author makes no claims that this is in any way an "optimised" routine.
* There is no doubt whatsoever that this code could be improved.
* For a very good assembler example, look at the FFMPEG file: fdct_bfin.S
*
*
* Performance numbers (cycle counts) as measured by the author:
*
* Original jfdctfst.c function:		2507 cycles
*
* This jfdctfst_bfin.S function:		1058 cycles
*/


/*
* jfdctfst.c
*
* Copyright (C) 1994-1996, Thomas G. Lane.
* This file is part of the Independent JPEG Group's software.
* For conditions of distribution and use, see the accompanying README file.
*
* This file contains a fast, not so accurate integer implementation of the
* forward DCT (Discrete Cosine Transform).
*
* A 2-D DCT can be done by 1-D DCT on each row followed by 1-D DCT
* on each column.  Direct algorithms are also available, but they are
* much more complex and seem not to be any faster when reduced to code.
*
* This implementation is based on Arai, Agui, and Nakajima's algorithm for
* scaled DCT.  Their original paper (Trans. IEICE E-71(11):1095) is in
* Japanese, but the algorithm is described in the Pennebaker & Mitchell
* JPEG textbook (see REFERENCES section in file README).  The following code
* is based directly on figure 4-8 in P&M.
* While an 8-point DCT cannot be done in less than 11 multiplies, it is
* possible to arrange the computation so that many of the multiplies are
* simple scalings of the final outputs.  These multiplies can then be
* folded into the multiplications or divisions by the JPEG quantization
* table entries.  The AA&N method leaves only 5 multiplies and 29 adds
* to be done in the DCT itself.
* The primary disadvantage of this method is that with fixed-point math,
* accuracy is lost due to imprecise representation of the scaled
* quantization values.  The smaller the quantization table entry, the less
* precise the scaled value, so this implementation does worse with high-
* quality-setting files than with low-quality ones.
*/


/* Scaling decisions are generally the same as in the LL&M algorithm;
* see jfdctint.c for more details.  However, we choose to descale
* (right shift) multiplication products as soon as they are formed,
* rather than carrying additional fractional bits into subsequent additions.
* This compromises accuracy slightly, but it lets us save a few shifts.
* More importantly, 16-bit arithmetic is then adequate (for 8-bit samples)
* everywhere except in the multiplications proper; this saves a good deal
* of work on 16-bit-int machines.
*
* Again to save a few shifts, the intermediate results between pass 1 and
* pass 2 are not upscaled, but are represented only to integral precision.
*
* A final compromise is to represent the multiplicative constants to only
* 8 fractional bits, rather than 13.  This saves some shifting work on some
* machines, and may also reduce the cost of multiplication (since there
* are fewer one-bits in the constants).
*/

/* #define CONST_BITS  8 */


/* Some C compilers fail to reduce "FIX(constant)" at compile time, thus
* causing a lot of useless floating-point operations at run time.
* To get around this we use the following pre-calculated constants.
* If you change CONST_BITS you may want to add appropriate values.
* (With a reasonable C compiler, you can just rely on the FIX() macro...)
*/

/*
#if CONST_BITS == 8
#define FIX_0_382683433  ((INT32)   98)		// FIX(0.382683433)
#define FIX_0_541196100  ((INT32)  139)		// FIX(0.541196100)
#define FIX_0_707106781  ((INT32)  181)		// FIX(0.707106781)
#define FIX_1_306562965  ((INT32)  334)		// FIX(1.306562965)
#else
#define FIX_0_382683433  FIX(0.382683433)
#define FIX_0_541196100  FIX(0.541196100)
#define FIX_0_707106781  FIX(0.707106781)
#define FIX_1_306562965  FIX(1.306562965)
#endif
*/

/* We can gain a little more speed, with a further compromise in accuracy,
* by omitting the addition in a descaling shift.  This yields an incorrectly
* rounded result half the time...
*/

/*
#ifndef USE_ACCURATE_ROUNDING
#undef DESCALE
#define DESCALE(x,n)  RIGHT_SHIFT(x, n)
#endif
*/

/* Multiply a DCTELEM variable by an INT32 constant, and immediately
* descale to yield a DCTELEM result.
*/

/* #define MULTIPLY(var,const)  ((DCTELEM) DESCALE((var) * (const), CONST_BITS)) */

/* void ff_bfin_fdct (DCTELEM *buf); */


/*
* Perform the forward DCT on one block of samples.
*/

#include "arch-opts.h"
#ifdef LIBJPEG_BFIN

#define ENTRY(name) \
   .global name; \
   .align 4; \
   name:
#define END(name) \
   .size name, .-name
#define ENDPROC(name) \
   .type name, @function; \
   END(name)

	/* Note the coefficients order here is: FIX_0_707, FIX_0_382, FIX_0_541, FIX_1_306   */
	/* Also note they've been shifted left 8 bits, eg, 0.707 * 256 = 181 */
.section .rodata
ENTRY(dct_coeff)
.short 181, 98, 139, 334;
END(dct_coeff)

.section .text;

ENTRY(_jpeg_fdct_ifast_bfin)

	[--SP] = (R7:4, P5:3);

	/* Pass 1: process rows. */

	/*
	dataptr = data;
	*/

	/*
	P0 -> start of data[];
	I0/B0 -> start of coeffs;
	L0 set to 8, to make I0 circular
	*/

	P0 = R0;
	B1 = R0;
	P1 = 16 (X);
	R0.H = dct_coeff;
	R0.L = dct_coeff;
	//R0 = [P3];
	I0 = R0;
	B0 = R0;
	L0 = 8;

	/*
	for (ctr = DCTSIZE-1; ctr >= 0; ctr--) {
	*/
	/* Loop 8 times */

	lsetup (.Lrowtop, .Lrowend) LC0 = P1>>1;
.Lrowtop:

	/*
	Note: When doing a 32-bit read of two 16-bit words, the first word goes into
	the low half, and the second word goes into the high half, of the destination register.

	Also note that on the blackfin, a libjpeg DCTELEM type is 32 bits, even though we only
	care about the low 16 bits of it. This is a problem when saving results, as we have to
	sign-extend our 16-bit result to 32-bits before doing a 32-bit save.

	To reduce the amount of 32-bit stuff we have to do, the first half of this code (the
	"rows" is all calculated, & saved, as signed 16-bit numbers. The second half of this
	code, the "columns", loads those 16-bit results, performs its calculations & saves
	its results as 32-bit signed numbers. So the final results from this routine are
	signed 32-bit numbers, which keeps libjpeg happy.

	I expect this routine could be made faster by storing those intermediate 16-bit
	results into internal RAM, rather than just writing them back into the data[] array
	as is done right now.  */

	/*
	tmp0 = dataptr[0] + dataptr[7];
	tmp7 = dataptr[0] - dataptr[7];
	tmp1 = dataptr[1] + dataptr[6];
	tmp6 = dataptr[1] - dataptr[6];
	tmp2 = dataptr[2] + dataptr[5];
	tmp5 = dataptr[2] - dataptr[5];
	tmp3 = dataptr[3] + dataptr[4];
	tmp4 = dataptr[3] - dataptr[4];
	*/

	/* Load order: 3,2,pack,5,4,7,6,0,1 */
	R4 = W[P0+12];
	R1 = W[P0+8];
	R1 = PACK (R4.L, R1.L) || R4 = W[P0+16];
	R3 = W[P0+20];
	R3 = PACK (R4.L, R3.L) || R4 = W[P0+28];
	R1 = R1 +|+ R3, R3 = R1 -|- R3 || R0 = W[P0+24];
	R0 = PACK (R4.L, R0.L) || R2 = W[P0+4];
	R2.H = W[P0];
	R0 = R2 +|+ R0, R2 = R2 -|- R0;

	/* At this point we have:
	tmp0 = R0.H, tmp1 = R0.L, tmp2 = R1.L, tmp3 = R1.H,
	tmp4 = R3.H, tmp5 = R3.L, tmp6 = R2.L, tmp7 = R2.H    */

	/* Even part
	tmp10 = tmp0 + tmp3;
	tmp13 = tmp0 - tmp3;
	tmp11 = tmp1 + tmp2;
	tmp12 = tmp1 - tmp2;
	*/

	/* preload FIX_0_707 (R5.L) & FIX_0_382 (R5.H) */
	R0 = R0 +|+ R1, R1 = R0 -|- R1 || R5 = [I0++]; 
	/* Now we have:
	tmp10 = R0.H, tmp11 = R0.L, tmp12 = R1.L, tmp13 = R1.H   */
	/*
	dataptr[0] = tmp10 + tmp11;
	dataptr[4] = tmp10 - tmp11;
	*/

	R4.L = R0.H + R0.L;
	R4.L = R0.H - R0.L || W[P0] = R4;
	R4.L = R1.L + R1.H || W[P0+16] = R4;

	/* At this point we're finished with tmp10 & tmp11, so R0 is free again */

	/*
	z1 = MULTIPLY(tmp12 + tmp13, FIX_0_707106781);    <-- (tmp12 + tmp13) already calc'd above
	dataptr[2] = tmp13 + z1;
	dataptr[6] = tmp13 - z1;
	*/

	R4 = R4.L * R5.L (IS);				/* (tmp12 + tmp13) * FIX_0_707 */
	R4 >>>= 8;							/* shift result right 8 bits to undo FIX leftshift = z1 */
	R0.L = R1.H + R4.L;					/* tmp13 + z1 */
	R0.L = R1.H - R4.L || W[P0+8] = R0;	/* store dataptr[2] & calculate (tmp13 - z1) */
	R0.H = R3.H + R3.L || W[P0+24] = R0;/* store dataptr[6], calc R0.H = tmp10 = tmp4 + tmp5 */

	/* Register usage at this point: tmp4 = R3.H, tmp5 = R3.L, tmp6 = R2.L, tmp7 = R2.H, tmp10 = R0.H,
	FIX_0_707 = R5.L, FIX_0_382 = R5.H  */

	/* Odd part
	tmp10 = tmp4 + tmp5;		<-- already calculated above
	tmp11 = tmp5 + tmp6;
	tmp12 = tmp6 + tmp7;
	*/

	R1.H = R3.L + R2.L || R4 = [I0++];		/* tmp11 = R1.H, R4.L = FIX_0_541, R4.H = FIX_1_306 */
	R0.L = R2.L + R2.H;						/* tmp12 = R0.L */

	/* The rotator is modified from fig 4-8 to avoid extra negations.
	z5 = MULTIPLY(tmp10 - tmp12, FIX_0_382683433); 
	z2 = MULTIPLY(tmp10, FIX_0_541196100) + z5; 
	z4 = MULTIPLY(tmp12, FIX_1_306562965) + z5; 
	z3 = MULTIPLY(tmp11, FIX_0_707106781);
	*/

	R1.L = R0.H - R0.L;							/* (tmp10 - tmp12) = R1.L */
	A0 = R1.L * R5.H, A1 = R1.L * R5.H (IS);	/* z5 = (tmp10 - temp12) * FIX_0_382 into both A0 & A1 (results leftshifted due to FIX) */
	R6=(A0+=R0.H*R4.L),R7=(A1+=R0.L*R4.H) (IS);	/* z2 = R6, z4 = R7, results still left-shifted */
	R6 >>>= 8;									/* z2 = R6.L  leftshift undone */
	R7 >>>= 8;									/* z4 = R7.L  leftshift undone */
	R0 = R1.H * R5.L (IS);						/* z3 = R0 = tmp11 * FIX_0_707, result leftshifted */
	R0 <<= 8;									/* z3 = R0.H  leftshift undone (note z3 in high half now) */

	/* At this point we're finished with the four FIX values, so R4 & R5 are free again. Also note
	that I0 will have wrapped around and be pointing at the start of the FIX coefficients again. */

	/*
	z11 = tmp7 + z3;
	z13 = tmp7 - z3;
	*/

	R4 = R2 +|+ R0, R5 = R2 -|- R0;				/* z11 = R4.H, z13 = R5.H */

	/*
	dataptr[5] = z13 + z2;
	dataptr[3] = z13 - z2;
	dataptr[1] = z11 + z4;
	dataptr[7] = z11 - z4;
	*/

	R4.L = R5.H + R6.L;							/* calc z13 + z2 */
	R4.L = R5.H - R6.L || W[P0+20] = R4;		/* calc z13 - z2, write dataptr[5] */
	R4.L = R4.H + R7.L || W[P0+12] = R4;		/* calc z11 + z4, write dataptr[3] */
	R4.L = R4.H - R7.L || W[P0+4] = R4;			/* calc z11 - z4, write dataptr[1] */
	W[P0+28] = R4;								/* write dataptr[7] */

	/*
	dataptr += DCTSIZE;							advance pointer to next row
	}
	*/
.Lrowend:	P0 += 32;							/* 8 DCTELEMs equals 32 bytes */



	/* Pass 2: process columns. */

	/*
	dataptr = data;
	for (ctr = DCTSIZE-1; ctr >= 0; ctr--) {
	*/


	lsetup (.Lcoltop, .Lcolend) LC0 = P1>>1;		// setup to loop 8 times

	/* Here's the "before the loop" setup stuff. Basically we just need to setup the P registers.
	P0 is used as the data address pointer; it'll step through the data word addresses in this order:
	read:  1, 2, 3, 4, 5, 6, 7, 0, then,
	write: 0, 2, 4, 6, 1, 3, 5, 7
	then reset back to 1++ (reset to 1, but then +1 word to point to the start of the next column)

	In all these comments, data[2] corresponds to dataptr[DCTSIZE*2], similarly for the others.

	Registers P1 - P5 are used to hold offsets, to post-increment (or post-decrement in the
	case of a negative offset) the P0 register, so that P0 can step through the data words
	in the order shown above.

	Because a libjpeg DCTELEM is 4 bytes, there are (8 x 4 =) 32 bytes per row.  */

	P0 = B1;						/* B1 points to data[0], first column */
	P0 += 32;						/* now P0 points to data[1] of the first column */
	P1 = 32;						/* P1 steps forward by 1  (eg from data[3] to data[4]) */
	P2 = -224 (X);					/* P2 steps us back by 7  (eg from data[7] -> data[0]) */
	P3 = 64 (X);					/* P3 steps forward by 2  (eg data[2] -> data[4]) */
	P4 = -160 (X);					/* P4 steps backward by 5, eg data[6] -> data[1] */
	P5 = -188 (X);					/* P5 steps backward by 6, plus forward one DCTELEM to the next column */

.Lcoltop:

	/*
	tmp0 = dataptr[DCTSIZE*0] + dataptr[DCTSIZE*7];
	tmp7 = dataptr[DCTSIZE*0] - dataptr[DCTSIZE*7];
	tmp1 = dataptr[DCTSIZE*1] + dataptr[DCTSIZE*6];
	tmp6 = dataptr[DCTSIZE*1] - dataptr[DCTSIZE*6];
	tmp2 = dataptr[DCTSIZE*2] + dataptr[DCTSIZE*5];
	tmp5 = dataptr[DCTSIZE*2] - dataptr[DCTSIZE*5];
	tmp3 = dataptr[DCTSIZE*3] + dataptr[DCTSIZE*4];
	tmp4 = dataptr[DCTSIZE*3] - dataptr[DCTSIZE*4];
	*/

	R2.L = W[P0++P1];									/* R2.L = data[1] */
	R1.L = W[P0++P1];									/* R1.L = data[2] */
	R1.H = W[P0++P1];									/* R1.H = data[3] */
	R3.H = W[P0++P1];									/* R3.H = data[4] */
	R3.L = W[P0++P1];									/* R3.L = data[5] */
	R1 = R1 +|+ R3, R3 = R1 -|- R3 || R0.L = W[P0++P1];	/* calculate tmp2,3,4,5, R0.L = data[6] */
	R0.H = W[P0++P2];									/* R0.H = data[7] */
	R2.H = W[P0];										/* R2.H = data[0] */
	R0 = R2 +|+ R0, R2 = R2 -|- R0;						/* calculate tmp0,1,6,7 /

	/* At this point we have:
	tmp0 = R0.H, tmp1 = R0.L, tmp2 = R1.L, tmp3 = R1.H,
	tmp4 = R3.H, tmp5 = R3.L, tmp6 = R2.L, tmp7 = R2.H
	P0 is pointing at data[0]  */

	/* Even part
	tmp10 = tmp0 + tmp3;
	tmp13 = tmp0 - tmp3;
	tmp11 = tmp1 + tmp2;
	tmp12 = tmp1 - tmp2;
	*/

	R0 = R0 +|+ R1, R1 = R0 -|- R1 || R5 = [I0++];	/* preload FIX_0_707 (R5.L) & FIX_0_382 (R5.H) */
	//R0 = R0 +|+ R1, R1 = R0 -|- R1 || R5 = 30;	/* preload FIX_0_707 (R5.L) & FIX_0_382 (R5.H) */
	/* Now we have:
	tmp10 = R0.H, tmp11 = R0.L, tmp12 = R1.L, tmp13 = R1.H   */

	/*
	dataptr[DCTSIZE*0] = tmp10 + tmp11;
	*/
	R4.L = R0.H + R0.L;						/* calculate tmp10 + tmp11 */
	R4 = R4.L (X);							/* sign-extend the result to 32 bits */
	R4.L = R1.L + R1.H || [P0++P3] = R4;	/* store data[0], also precalc R4.L = (tmp12 + tmp13) */

	/*
	dataptr[DCTSIZE*4] = tmp10 - tmp11;
	z1 = MULTIPLY(tmp12 + tmp13, FIX_0_707106781);   <-- (tmp12 + tmp13) already calc'd above
	dataptr[DCTSIZE*2] = tmp13 + z1;
	dataptr[DCTSIZE*6] = tmp13 - z1;
	Note we want to save in the order data[2], data[4], data[6] so we'll calc data[2] first
	*/

	R4 = R4.L * R5.L (IS);					/* (tmp12 + tmp13) * FIX_0_707, result is left-shifted */
	R4 >>>= 8;								/* shift result 8 bits to undo FIX, result z1 in R4 */
	R1 >>>= 16;								/* R1 = tmp13 (as a signed 32-bit) */
	R1 = R1 + R4, R4 = R1 - R4;				/* R1 = (tmp13 + z1), R4 = (tmp13 - z1) */
	R1.L = R0.H - R0.L || [P0++P3] = R1;	/* store data[2], calc (tmp10 - tmp11) */
	R1 = R1.L (X);							/* R1 contains (tmp10 - tmp11) as signed 32-bit */
	R0.H = R3.H + R3.L || [P0++P3] = R1;	/* store data[4], precalc R0.H = tmp10 = tmp4 + tmp5 */
	R1.H = R3.L + R2.L || [P0++P4] = R4;	/* store data[6], precalc R1.H = tmp11 = tmp5 + tmp6 */

	/* Register usage at this point: tmp4 = R3.H, tmp5 = R3.L, tmp6 = R2.L, tmp7 = R2.H,
	tmp10 = R0.H, tmp11 = R1.H,  FIX_0_707 = R5.L,  FIX_0_382 = R5.H
	P0 now points to data[1]  */

	/* Odd part
	tmp10 = tmp4 + tmp5;		<-- already calculated above
	tmp11 = tmp5 + tmp6;		<-- already calculated above
	tmp12 = tmp6 + tmp7;
	*/

	R0.L = R2.L + R2.H || R4 = [I0++];		/* tmp12 = R0.L, R4.L = FIX_0_541, R4.H = FIX_1_306 */

	/* The rotator is modified from fig 4-8 to avoid extra negations.
	z5 = MULTIPLY(tmp10 - tmp12, FIX_0_382683433);
	z2 = MULTIPLY(tmp10, FIX_0_541196100) + z5; 
	z4 = MULTIPLY(tmp12, FIX_1_306562965) + z5; 
	z3 = MULTIPLY(tmp11, FIX_0_707106781);
	*/

	R1.L = R0.H - R0.L;							/* (tmp10 - tmp12) = R1.L */
	A0 = R1.L * R5.H, A1 = R1.L * R5.H (IS);	/* z5 = (tmp10 - temp12) * FIX_0_382 into both A0 & A1 (results leftshifted due to FIX) */
	R6=(A0+=R0.H*R4.L),R7=(A1+=R0.L*R4.H) (IS);	/* z2 = R6, z4 = R7, results still left-shifted */
	R6 >>>= 8;									/* z2 = R6.L  leftshift undone */
	R7 >>>= 8;									/* z4 = R7.L  leftshift undone */
	R0 = R1.H * R5.L (IS);						/* z3 = R0 = tmp11 * FIX_0_707, result leftshifted */
	R0 <<= 8;									/* z3 = R0.H  leftshift undone (note z3 in high half now) */

	/* At this point we're finished with the four FIX values, so R4 & R5 are free again. Also note
	that I0 will have wrapped around and be pointing at the start of the FIX coefficients again. */

	/*
	z11 = tmp7 + z3;
	z13 = tmp7 - z3;
	*/

	R4 = R2 +|+ R0, R5 = R2 -|- R0;			/* z11 = R4.H, z13 = R5.H */

	/*
	dataptr[DCTSIZE*5] = z13 + z2;
	dataptr[DCTSIZE*3] = z13 - z2;
	dataptr[DCTSIZE*1] = z11 + z4;
	dataptr[DCTSIZE*7] = z11 - z4;
	Note we want to save in the order data[1], data[3], data[5], data[7], so we calc z11 + z4 first

	dataptr++;								advance pointer to next column
	}
	*/

	R4.L = R4.H + R7.L;						/* calc z11 + z4 */
	R0 = R4.L (X);							/* R0 = (z11 + z4), 32-bit signed */
	R4.L = R5.H - R6.L || [P0++P3] = R0;	/* calc z13 - z2, write dataptr[1] */
	R0 = R4.L (X);							/* R0 = (z13 - z2), 32-bit signed */
	R4.L = R5.H + R6.L || [P0++P3] = R0;	/* calc z13 + z2, write dataptr[3] */
	R0 = R4.L (X);							/* R0 = (z13 + z2), 32-bit signed */
	R4.L = R4.H - R7.L || [P0++P3] = R0;	/* calc z11 - z4, write dataptr[5] */
	R0 = R4.L (X);							/* R0 = (z11 - z4), 32-bit signed */
.Lcolend: 	[P0++P5] = R0;					/* write dataptr[7], adjust P0 to data[1] of next column */



	L0 = 0;
	(r7:4,p5:3) = [sp++];					/* restore registers from stack */
	RTS;
ENDPROC(_jpeg_fdct_ifast_bfin)

#endif /* LIBJPEG_BFIN */

#if defined(__linux__) && defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
