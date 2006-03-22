/*This file is subject to the terms and conditions of the GNU General Public
 * License.
 *
 * Blackfin BF533/2.6 support : LG Soft India
 * Updated : Ashutosh Singh / Jahid Khan : Rrap Software Pvt Ltd
 * Updated : 1. SDRAM_KERNEL, SDRAM_DKENEL are added as initial cplb's
 *	        shouldn't be victimized. cplbmgr.S search logic is corrected
 *	        to findout the appropriate victim.
 *	     2. SDRAM_IGENERIC in dpdt_table is replaced with SDRAM_DGENERIC
 *	     : LG Soft India
 */

#ifndef __ARCH_BLACKFIN_CPLBTAB_H
#define __ARCH_BLACKFIN_CPLBTAB_H

/*************************************************************************
 *  			ICPLB TABLE
 *************************************************************************/

.data
/* This table is configurable */
    .align 4;

.global _icplb_table
_icplb_table:
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 10 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 20 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 30 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0xffffffff;		/* end of section - termination */

.align 4;
.global _ipdt_table
_ipdt_table:
.byte4        0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 10 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 20 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 30 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 40 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 50 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 60 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 70 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 80 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 90 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 100 */
.byte4 0xffffffff;		/* end of section - termination */

/*********************************************************************
 *			DCPLB TABLE
 ********************************************************************/

.global _dcplb_table
_dcplb_table:
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 10 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 20 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 30 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0xffffffff;		/*end of section - termination */

/**********************************************************************
 *		PAGE DESCRIPTOR TABLE
 *
 **********************************************************************/

/* Till here we are discussing about the static memory management model.
 * However, the operating envoronments commonly define more CPLB
 * descriptors to cover the entire addressable memory than will fit into
 * the available on-chip 16 CPLB MMRs. When this happens, the below table
 * will be used which will hold all the potentially required CPLB descriptors
 *
 * This is how Page descriptor Table is implemented in uClinux/Blackfin.
 */
.global _dpdt_table
_dpdt_table:
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 10 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 20 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 30 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 40 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 50 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 60 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 70 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 80 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 90 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 100 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 110 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 120 */

.byte4 0xffffffff;		/*end of section - termination */

#ifdef CONFIG_CPLB_INFO
.global _ipdt_swapcount_table;	/* swapin count first, then swapout count */
_ipdt_swapcount_table:
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 10 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 20 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 30 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 40 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 50 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 60 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 70 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 80 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 90 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 100 */

.global _dpdt_swapcount_table;	/* swapin count first, then swapout count */
_dpdt_swapcount_table:
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 10 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 20 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 30 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 40 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 50 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 60 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 70 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 80 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 80 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 100 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 110 */
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;		/* 120 */

#endif

#endif	/*__ARCH_BLACKFIN_CPLBTAB_H*/
