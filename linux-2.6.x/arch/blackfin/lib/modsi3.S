/*
 * File:         arch/blackfin/lib/modsi3.S
 * Based on:     
 * Author:       
 *               
 * Created:      
 * Description:  This program computes 32 bit signed remainder. It calls div32 function
 *  		 for quotient estimation.
 *
 *		 Registers used :
 *		 Numerator/ Denominator in  R0, R1
 *		  R0  -  returns remainder.
 *		  R2-R7
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

.global ___modsi3;
.type ___modsi3, STT_FUNC;
.extern ___divsi3;
.type ___divsi3, STT_FUNC;
___modsi3:

	CC=R0==0;
	IF CC JUMP RETURN_R0;		/* Return 0, if numerator  == 0 */
	CC=R1==0;
	IF CC JUMP RETURN_ZERO;		/* Return 0, if denominator == 0 */
	CC=R0==R1;
	IF CC JUMP RETURN_ZERO;		/* Return 0, if numerator == denominator */
	CC = R1 == 1;
	IF CC JUMP RETURN_ZERO;		/* Return 0, if denominator ==  1 */
	CC = R1 == -1;
	IF CC JUMP RETURN_ZERO;		/* Return 0, if denominator == -1 */

	/* Valid input. Use __divsi3() to compute the quotient, and then
	   derive the remainder from that. */

	[--SP] = (R7:6);		/* Push  R7 and R6 */
	[--SP] = RETS;			/* and return address */
	R7 = R0;			/* Copy of R0 */   
	R6 = R1;			/* Save for later */
	SP += -12;			/* Should always provide this space */
	CALL ___divsi3;			/* Compute signed quotient using ___divsi3()*/
	SP += 12;
	R0 *= R6;			/* Quotient * divisor */
	R0 = R7 - R0;			/* Dividend - ( quotient *divisor) */
	RETS = [SP++];			/* Get back return address */
	(R7:6) = [SP++];		/* Pop registers R7 and R4 */
	RTS;				/* Store remainder    */

RETURN_ZERO:
	R0 = 0;
RETURN_R0:
	RTS;
