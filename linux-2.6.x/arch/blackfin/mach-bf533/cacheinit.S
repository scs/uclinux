/* Copyright (C) 2003 Analog Devices, Inc. All Rights Reserved. 
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License. 
 * 	
 * Blackfin BF533/2.6 support : LG Soft India	
 */

/* This function sets up the data and instruction cache. The 
 * tables like icplb table, dcplb table and Page Descriptor table
 * are defined in cplbtab.h. You can configure those tables for
 * your suitable requirements - Nidhi 
 */

#include <asm/cplb.h>
#include <asm/board/bf533.h>
#include <linux/linkage.h>
#include <asm/entry.h>
#include <asm/cplbtab.h>

.text

.global icache_init
.type icache_init, STT_FUNC

.global dcache_init
.type dcache_init, STT_FUNC

ENTRY(icache_init)
	
	/* Initialize Instruction CPLBS */
	
	I0.L = (ICPLB_ADDR0 & 0xFFFF);
	I0.H = (ICPLB_ADDR0 >> 16);

	I1.L = (ICPLB_DATA0 & 0xFFFF);
	I1.H = (ICPLB_DATA0 >> 16);

	I2.L = icplb_table;
	I2.H = icplb_table;

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

	R0 = (IMC | ENICPLB);
	[P0] = R0;
	CSYNC;

	RTS;

dcache_init:
	
	/* Initialize Data CPLBS */
	
	I0.L = (DCPLB_ADDR0 & 0xFFFF);
	I0.H = (DCPLB_ADDR0 >> 16);

	I1.L = (DCPLB_DATA0 & 0xFFFF);
	I1.H = (DCPLB_DATA0 >> 16);

	I2.L = dcplb_table;
	I2.H = dcplb_table;

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

	R0 = (DMC_531_ENABLE | ENDCPLB);
	[P0] = R0;
	CSYNC;
	RTS;	
