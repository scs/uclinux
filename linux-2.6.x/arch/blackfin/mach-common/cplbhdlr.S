 /*
 * File:        arch/blackfin/mach-common/cplbhdlr.S
 * Based on:
 * Author:      LG Soft India
 *              COPYRIGHT 2005 Analog Devices
 * Created:     ?
 * Description: CPLB exception handler
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

#include <linux/linkage.h>
#include <asm/cplb.h>
#include <asm/entry.h>


.text

.globl __cplb_hdr;
.type __cplb_hdr, STT_FUNC;
.extern _cplb_mgr;
.type _cplb_mgr, STT_FUNC;
.extern __unknown_exception_occurred;
.type __unknown_exception_occurred, STT_FUNC;
.extern __cplb_miss_all_locked;
.type __cplb_miss_all_locked, STT_FUNC;
.extern __cplb_miss_without_replacement;
.type __cplb_miss_without_replacement, STT_FUNC;
.extern __cplb_protection_violation;
.type __cplb_protection_violation, STT_FUNC;
.extern _panic_pv;

.align 2;

ENTRY(__cplb_hdr)
	SSYNC;
	[--SP] = ASTAT;
	[--SP] = SEQSTAT;
	[--SP] = I0;
	[--SP] = I1;
	[--SP] = I2;
	[--SP] = I3;
	R2 = SEQSTAT;

	/*Mask the contents of SEQSTAT and leave only EXCAUSE in R2*/
	R2 <<= 26;
	R2 >>= 26;

	R1 = 0x23; /* Data access CPLB protection violation */
	CC = R2 == R1;
	IF !CC JUMP .Lnot_data_write;
	R0 = 2;		/* is a write to data space*/
	JUMP .Lis_icplb_miss;

.Lnot_data_write:
	R1 = 0x2C; /* CPLB miss on an instruction fetch */
	CC = R2 == R1;
	R0 = 0;		/* is_data_miss == False*/
	IF CC JUMP .Lis_icplb_miss;

	R1 = 0x26;
	CC = R2 == R1;
	IF !CC JUMP .Lunknown;

	R0 = 1;		/* is_data_miss == True*/

.Lis_icplb_miss:

#if ( defined (CONFIG_BLKFIN_CACHE) || defined (CONFIG_BLKFIN_DCACHE))
#if ( defined (CONFIG_BLKFIN_CACHE) && !defined (CONFIG_BLKFIN_DCACHE))
	R1 = CPLB_ENABLE_ICACHE;
#endif
#if ( !defined (CONFIG_BLKFIN_CACHE) && defined (CONFIG_BLKFIN_DCACHE))
	R1 = CPLB_ENABLE_DCACHE;
#endif
#if ( defined (CONFIG_BLKFIN_CACHE) && defined (CONFIG_BLKFIN_DCACHE))
	R1 = CPLB_ENABLE_DCACHE | CPLB_ENABLE_ICACHE;
#endif
#else
	R1 = 0;
#endif

	[--SP] = RETS;
	CALL _cplb_mgr;
	RETS = [SP++];
	CC = R0 == 0;
	IF !CC JUMP .Lnot_replaced;
	I3 = [SP++];
	I2 = [SP++];
	I1 = [SP++];
	I0 = [SP++];
	SEQSTAT = [SP++];
	ASTAT = [SP++];
	RTS;

.Lunknown:
	[--SP] = RETS;
	CALL __unknown_exception_occurred;
	RETS = [SP++];
	JUMP .Lunknown;
.Lnot_replaced:
	CC = R0 == CPLB_NO_UNLOCKED;
	IF !CC JUMP .Lnext_check;
	[--SP] = RETS;
	CALL __cplb_miss_all_locked;
	RETS = [SP++];
.Lnext_check:
	CC = R0 == CPLB_NO_ADDR_MATCH;
	IF !CC JUMP .Lnext_check2;
	[--SP] = RETS;
	CALL __cplb_miss_without_replacement;
	RETS = [SP++];
	JUMP .Lnot_replaced;
.Lnext_check2:
	CC = R0 == CPLB_PROT_VIOL;
	IF !CC JUMP .Lstrange_return_from_cplb_mgr;
	[--SP] = RETS;
	CALL __cplb_protection_violation;
	RETS = [SP++];
	JUMP .Lnot_replaced;
.Lstrange_return_from_cplb_mgr:
	IDLE;
	CSYNC;
	JUMP .Lstrange_return_from_cplb_mgr;

/************************************
 * Diagnostic exception handlers
 */

__cplb_miss_all_locked:
	sp += -12;
	R0 = CPLB_NO_UNLOCKED;
	call _panic_bfin;
	SP += 12;
	RTS;

__cplb_miss_without_replacement:
	sp += -12;
	R0 = CPLB_NO_ADDR_MATCH;
	call _panic_bfin;
	SP += 12;
	RTS;

__cplb_protection_violation:
	sp += -12;
	R0 = CPLB_PROT_VIOL;
	call _panic_bfin;
	SP += 12;
	RTS;

__unknown_exception_occurred:

	/* This function is invoked by the default exception
	 * handler, if it does not recognise the kind of
	 * exception that has occurred. In other words, the
	 * default handler only handles some of the system's
	 * exception types, and it does not expect any others
	 * to occur. If your application is going to be using
	 * other kinds of exceptions, you must replace the
	 * default handler with your own, that handles all the
	 * exceptions you will use.
	 *
	 * Since there's nothing we can do, we just loop here
	 * at what we hope is a suitably informative label.
	 */

	IDLE;
.Ldo_not_know_what_to_do:
	NOP;
	CSYNC;
	JUMP __unknown_exception_occurred;

	RTS;
.global __unknown_exception_occurred;
.type __unknown_exception_occurred, STT_FUNC;
