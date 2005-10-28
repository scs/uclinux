/*
 * File:	ins.S
 * Description:	Implementation of ins{bwl} for BlackFin processors using zero overhead loops.
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

ENTRY(_insl)
	P0 = R0;	/* P0 = port */
	P1 = R1;	/* P1 = address */
	P2 = R2;	/* P2 = count */
	cli R2;
	NOP;
	NOP;

	LSETUP( long_loop_s, long_loop_e) LC0 = P2;
long_loop_s: R0 = [P0];
long_loop_e: [P1++] = R0;

    sti R2;
	RTS;

ENTRY(_insw)
	P0 = R0;	/* P0 = port */
	P1 = R1;	/* P1 = address */
	P2 = R2;	/* P2 = count */
	cli R2;
	NOP;
	NOP;

	LSETUP( word_loop_s, word_loop_e) LC0 = P2;
word_loop_s: R0 = W[P0];
word_loop_e: W[P1++] = R0;

	sti R2;
	RTS;

ENTRY(_insb)
	P0 = R0;	/* P0 = port */
	P1 = R1;	/* P1 = address */
	P2 = R2;	/* P2 = count */
	cli R2;
	NOP;
	NOP;

	LSETUP( byte_loop_s, byte_loop_e) LC0 = P2;
byte_loop_s: R0 = B[P0];
byte_loop_e: B[P1++] = R0;
	sti R2;
	RTS;
