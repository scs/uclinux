/*
 * File:         arch/blackfin/lib/memchr.S
 * Based on:
 * Author:
 *
 * Created:
 * Description:
 *
 * Rev:          $Id$
 *
 * Modified:     Roy Huang <royhuang@blackfin.uclinux.org>
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

#include <linux/linkage.h>
	.align 2;

	   /*
	   * C Library function MEMCHR
	   * R0 = address
	   * R1 = sought byte
	   * R2 = count
	   * Returns pointer to located character.
	   */

ENTRY(_memchr)
	     P0 = R0 ;             /* P0 = address */
	     P2 = R2 ;             /* P2 = count */
	     R1 = R1.B(Z);
	     CC = R2 == 0;
	     IF CC JUMP .Lfailed;

.Lbytes:       LSETUP (.Lbyte_loop_s , .Lbyte_loop_e) LC0=P2;

.Lbyte_loop_s:
	     R3 = B[P0++](Z);
	     CC = R3 == R1;
	     IF CC JUMP .Lfound;
	     NOP;
.Lbyte_loop_e:

.Lfailed:      R0=0;
	     RTS;

.Lfound:       R0 = P0;
	     R0 += -1;
	     RTS;
