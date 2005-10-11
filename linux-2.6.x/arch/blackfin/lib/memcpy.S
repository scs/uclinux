/*Copyright (C) 2000 Analog Devices Inc., All Rights Reserved. 
** This contains Analog Devices Background IP and Development IP as
** defined in the ADI/Intel Collaboration Agreement.
*/

/* _memcpy: internal version of memcpy(), issued by the compiler
* to copy blocks of data around.
* This is really memmove() - it has to be able to deal with
* possible overlaps, because that ambiguity is when the compiler
* gives up and calls a function. We have our own, internal version
* so that we get something we trust, even if the user has redefined
* the normal symbol. 
*/
#include <linux/linkage.h>

	.align 2;
ENTRY(_memcpy)
		CC = R2 <=  0;	/* length not positive?*/
		P0 = R0 ;	/* dst*/
		P1 = R1 ;	/* src*/
		P2 = R2 ;	/* length */
		IF CC JUMP  ._P1L2147483647 ;	/* Nothing to do */

		/* check for overlapping data */
		CC = R1 < R0;	/* src < dst */
		IF !CC JUMP .no_overlap;
		R3 = R1 + R2;
		CC = R0 < R3;	/* and dst < src+len */
		IF CC JUMP .has_overlap;

.no_overlap:
		/* Check for aligned data.*/

		R3 = R1 | R0;
		R0 = 0x3;
		R3 = R3 & R0;
		CC = R3;	/* low bits set on either address? */
		IF CC JUMP .not_aligned;

		/* Both addresses are word-aligned, so we can copy
		at least part of the data using word copies.*/
		P2 = P2 >> 2;
		CC = P2 <= 2;
		IF !CC JUMP .more_than_seven;
		/* less than eight bytes... */
		P2 = R2;
		LSETUP(.three_start, .three_end) LC0=P2;
		R0 = R1;	/* setup src address for return */
.three_start:	R3 = B[P1++] (X);
.three_end:	B[P0++] = R3;
		RTS;

.more_than_seven:
		/* There's at least eight bytes to copy. */
		P2 += -1;	/* because we unroll one iteration */
		LSETUP(.word_loop, .word_loop) LC0=P2;
		R0 = R1;
		I1 = P1;
		R3 = [I1++];
.word_loop:	MNOP || [P0++] = R3 || R3 = [I1++];
		[P0++] = R3;
		/* Any remaining bytes to copy? */
		R3 = 0x3;
		R3 = R2 & R3;
		CC = R3 == 0;
		P1 = I1;	/* in case there's something left, */
		IF !CC JUMP .bytes_left;
		RTS;
.bytes_left:	P2 = R3;
.not_aligned:
		/* From here, we're copying byte-by-byte. */
		LSETUP (.byte_start , .byte_end) LC0=P2;
		R0 = R1;	/* Save src address for return */
.byte_start:	R1 = B[P1++] (X);
.byte_end:	B[P0++] = R1;

._P1L2147483647:
		RTS;

.has_overlap:
		/* Need to reverse the copying, because the
		 dst would clobber the src.
		 Don't bother to work out alignment for
		 the reverse case. */
		R0 = R1;	/* save src for later. */
		P0 = P0 + P2;
		P0 += -1;
		P1 = P1 + P2;
		P1 += -1;
		LSETUP(.over_start, .over_end) LC0=P2;
.over_start:	R1 = B[P1--] (X);
.over_end:	B[P0--] = R1;
		RTS;
