/*
 *    File:         b4copy.S
 *    Rev:          $Id$
 *    Created:      Sun May 30 21:14:26 CEST 2004
 *    Author:       Luuk van Dijk, Bas Vermeulen
 *    mail:         lvd@mndmttr.nl
 *    Description:  bcopy by mem-to-mem dma
 *                  does not handle dest/src overlap
 *                  src, dst and count must be word-aligned
 *
 *    Copyright (C) 2004 Luuk van Dijk/Bas Vermeulen
 *                       Mind over Matter/BuyWays B.V.
 *
 */


.section .text;
.global _b4copy;

/*
 * void b4copy(u32_t *src, u32_t *dst, u32_t count_bytes);
 */


_b4copy:
        P0 = R0;
        P1 = R1;
        P2 = R2;
        P2 = P2 >> 2;
	[--SP] = LC0;
	[--SP] = LB0;
	[--SP] = LT0;	  
        LSETUP (__b4copy_loop, __b4copy_loop_end) LC0 = P2;
__b4copy_loop:
        R0 = [P0++];
        [P1++] = R0;
__b4copy_loop_end:
	LT0 = [SP++]; 
	LB0 = [SP++]; 
	LC0 = [SP++]; 
        RTS;
