/* 
 * File:	outs.S
 * Description:	Implementation of outs{bwl} for BlackFin processors using zero overhead loops.
 * Rev:		$Id$
 * Created:	Tue Mar 22 15:27:24 CEST 2005
 * Author:	Bas Vermeulen
 * Email:	bas@buyways.nl
 *
 * Copyright (C) 2005 Bas Vermeulen, BuyWays BV <bas@buyways.nl>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTIBILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.
 * If not, write to the Free Software Foundation,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
 
#include <linux/linkage.h>
	.align 2;
	   
ENTRY(outsl)
	LINK 0x0;
	P0 = R0;	/* P0 = port */
	P1 = R1;	/* P1 = address */
	P2 = R2;	/* P2 = count */

	LSETUP( long_loop_s, long_loop_e) LC0 = P2;
long_loop_s: R0 = W[P1++];
long_loop_e: W[P0] = R0;
	UNLINK;
	RTS;

ENTRY(outsw)
	LINK 0x0;
	P0 = R0;	/* P0 = port */
	P1 = R1;	/* P1 = address */
	P2 = R2;	/* P2 = count */

	LSETUP( word_loop_s, word_loop_e) LC0 = P2;
word_loop_s: R0 = W[P1++];
word_loop_e: W[P0] = R0;
	UNLINK;
	RTS;

ENTRY(outsb)
	LINK 0x0;
	P0 = R0;	/* P0 = port */
	P1 = R1;	/* P1 = address */
	P2 = R2;	/* P2 = count */

	LSETUP( byte_loop_s, byte_loop_e) LC0 = P2;
byte_loop_s: R0 = B[P1++];
byte_loop_e: B[P0] = R0;
	UNLINK;
	RTS;
