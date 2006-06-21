/*
 * File:	arch/blackfin/lib/outs.S
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

ENTRY(_outsl)
	P0 = R0;	/* P0 = port */
	P1 = R1;	/* P1 = address */
	P2 = R2;	/* P2 = count */

	LSETUP( .Llong_loop_s, .Llong_loop_e) LC0 = P2;
.Llong_loop_s: R0 = [P1++];
.Llong_loop_e: [P0] = R0;
	RTS;

ENTRY(_outsw)
	P0 = R0;	/* P0 = port */
	P1 = R1;	/* P1 = address */
	P2 = R2;	/* P2 = count */

	LSETUP( .Lword_loop_s, .Lword_loop_e) LC0 = P2;
.Lword_loop_s: R0 = W[P1++];
.Lword_loop_e: W[P0] = R0;
	RTS;

ENTRY(_outsb)
	P0 = R0;	/* P0 = port */
	P1 = R1;	/* P1 = address */
	P2 = R2;	/* P2 = count */

	LSETUP( .Lbyte_loop_s, .Lbyte_loop_e) LC0 = P2;
.Lbyte_loop_s: R0 = B[P1++];
.Lbyte_loop_e: B[P0] = R0;
	RTS;
