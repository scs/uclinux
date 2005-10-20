 /*
 * File:        arch/blackfin/mach-common/cacheinit.S
 * Based on:    
 * Author:      LG Soft India
 *              COPYRIGHT 2005 Analog Devices
 * Created:     ?
 * Description: cache initialization
 *
 * Rev:
 *
 * Modified:
 *
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

/* This function sets up the data and instruction cache. The 
 * tables like icplb table, dcplb table and Page Descriptor table
 * are defined in cplbtab.h. You can configure those tables for
 * your suitable requirements
 */

#include <linux/linkage.h>
#include <asm/blackfin.h>
#include <asm/cplbtab.h>

.text

#if defined (CONFIG_BLKFIN_CACHE)
ENTRY(_icache_init)

	/* Initialize Instruction CPLBS */
	
	I0.L = (ICPLB_ADDR0 & 0xFFFF);
	I0.H = (ICPLB_ADDR0 >> 16);

	I1.L = (ICPLB_DATA0 & 0xFFFF);
	I1.H = (ICPLB_DATA0 >> 16);

	I2.L = _icplb_table;
	I2.H = _icplb_table;

	r1 = -1;	/* end point comparison */
	r3 = 15;	/* max counter */

/* read entries from table */

read_iaddr:
	R0 = [I2++];
	CC = R0 == R1;
	IF CC JUMP idone;
	[I0++] = R0;

read_idata:
	R2 = [I2++];
	[I1++] = R2;
	R3 = R3 + R1;
	CC = R3 == R1;
	IF !CC JUMP read_iaddr;
	
idone:
	/* Enable Instruction Cache */
	P0.l = (IMEM_CONTROL & 0xFFFF);
	P0.h = (IMEM_CONTROL >> 16);
	R1 = [P0];
	R0 = (IMC | ENICPLB);
	R0 = R0 | R1;
	
	/*Anamoly 05000125 */
	CLI R2;
	SSYNC;		/* SSYNC required before writing to IMEM_CONTROL. */
	.align 8;
	[P0] = R0;
	SSYNC;
	STI R2;
	RTS;
#endif

#if defined (CONFIG_BLKFIN_DCACHE)
ENTRY(_dcache_init)
	
	/* Initialize Data CPLBS */
	
	I0.L = (DCPLB_ADDR0 & 0xFFFF);
	I0.H = (DCPLB_ADDR0 >> 16);

	I1.L = (DCPLB_DATA0 & 0xFFFF);
	I1.H = (DCPLB_DATA0 >> 16);

	I2.L = _dcplb_table;
	I2.H = _dcplb_table;

	R1 = -1;	/* end point comparison */
	R3 = 15;	/* max counter */

	/* read entries from table */
read_daddr:
	R0 = [I2++];
	cc = R0 == R1;
	IF CC JUMP ddone;
	[I0++] = R0;

read_ddata:
	R2 = [I2++];
	[I1++] = R2;
	R3 = R3 + R1;
	CC = R3 == R1;
	IF !CC JUMP read_daddr;
ddone:
	P0.L = (DMEM_CONTROL & 0xFFFF);
	P0.H = (DMEM_CONTROL >> 16);
	R1 = [P0];

	R0 = DMEM_CNTR;

	R0 = R0 | R1;
	/*Anamoly 05000125 */
	CLI R2;
	SSYNC;		/* SSYNC required before writing to DMEM_CONTROL. */
	.align 8;
	[P0] = R0;
	SSYNC;
	STI R2;
	RTS;
#endif
