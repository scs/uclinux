/* Copyright (C) 2003 Analog Devices, Inc. All Rights Reserved. 
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License. 
 *
 * Blackfin BF533/2.6 support : LG Soft India	
 *
 * libgcc1 routines for Blackfin 533
 * Copyright (C) 2004-2005 LG Soft India. 
 */

	.text
	.globl	__modsi3
__modsi3:
	LINK 0x0;
	[--SP] = ( R7:6 );
	R6 = R0;
	R7 = R1;
	CALL __divsi3;
	R7 *= R0;
	R0 = R6 - R7;
	( R7:6 ) = [SP++]
	UNLINK;
	RTS;

