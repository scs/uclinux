/*
 * File:         drivers/video/rgb2ycbcr.S
 * Based on:     
 * Author:	 Aubrey.Li <aubrey.Li@analog.com> 
 *
 * Created:	
 * Description:  In this function the range of R, G and B is 0 to 255 and the
 *               output range of Y, Cb and Cr is also 0 to 255. 
 *		 Input format: RGBRGB..., Output format: CbYCrYCbYCrY...
 *               The formula implemented is as below:
 *                  Y  = 0.299R  +  0.587G  +  0.114B
 *                  Cb = -0.169R -  0.331G  +  0.500B + 128
 *                  Cr = 0.500R  -  0.419G  -  0.081B + 128
 *                128 is added to Cb and Cr to get the output in the range 0 to
 *                255.
 * Prototype: void rgb2yuv(unsigned char rgb[], unsigned char yuv[], int n);
 *
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

.global         _rgb2yuv;
.align          8;

_rgb2yuv:   
	[--SP] = (R7:4);	/* Push R7-4 the Registers on stack.	*/
	P1 = R2;                /* pixel number of inputs,		*/ 
	P2 = R1;		/* Address of output array		*/
	P0 = R0;		/* Address of input RGB array		*/
	
	/* Store the coefficients to the register */ 
	R3.L = 0xEA5F;		/* 	-0.169				*/
	R3.H = 0xCA5F;		/* 	-0.331				*/
	R4.L = 0x4000;		/* 	0.5				*/
	R4.H = 0xF5A2;		/* 	-0.081				*/
	R5.L = 0x4000;		/* 	0.5				*/
	R5.H = 0xD5A2;		/* 	-0.419				*/
	R6.L = 0x2645;		/* 	0.299				*/
	R6.H = 0x4B22;		/* 	0.587				*/
	R7.H = 0x0E97;		/* 	0.114				*/
	R2.L = 0x80;  		/* 	128				*/
	R2.H = 0x7FFF;		/* 	1.0				*/

	LSETUP(L1_STRT, L1_END) LC0=P1;
L1_STRT:
        R0 = LC0;
        NOP;
        CC = BITTST(R0, 0);
	R0 = B[P0++] (Z);       /* fetch R to R0.L                      */
        R1 = B[P0++] (Z);       /* fetch G to R1.L                      */
        R1 = R1 << 16;          /* shift G to R1.H                      */
        R0 = R0 | R1;           /* store G to R0.H                      */
        IF !CC JUMP PIXEL_CR;
PIXEL_CB:
	/* -0.169 * R, -0.331 * G, and fetch B to R1.L */
	A0 = R0.L * R3.L, A1 = R0.H * R3.H || R1 = B[P0++] (Z);
	A0 += R1.L * R4.L;	/* -0.169 * R + 0.5 * B			*/
	A0 += A1;		/* -0.169 * R -0.331 *G + 0.5 *B	*/
	R7.L = (A0 += R2.L * R2.H); /* R7.L contain Cb			*/
	JUMP PIXEL_Y;
PIXEL_CR:
	/* 0.5 * R, -0.419 * G, and fetch B to R1.L */
	A0 = R0.L * R5.L, A1 = R0.H * R5.H || R1 = B[P0++] (Z);
	A0 += R1.L * R4.H;	/* 0.5 * R  - 0.081 * B			*/
	A0 += A1;		/* 0.5 * R - 0.419 * G - 0.081 * B	*/
	R7.L = (A0 += R2.L * R2.H); /* R7.L contain Cr			*/
PIXEL_Y:
	/* 0.299 * R, 0.587 * G, and store Cb/Cr to the output matrix */
	A0 = R0.L * R6.L, A1 = R0.H * R6.H || B[P2++] = R7;
	A0 += R1.L * R7.H;	/* 0.299 * R + 0.114 * B		*/
	R7.L = (A0 += A1);	/* 0.299 * R + 0.587 * G + 0.114 *B	*/
L1_END:
        B[P2++] = R7;		/* Store Y to the output matrix		*/
    	(R7:4)  =  [SP++];      /* Pop up the saved registers from stack*/
        RTS;
