/* Copyright (C) 2004 LG Soft India. All Rights Reserved.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.
 *
 * Blackfin BF533/2.6 support : LG Soft India
 */

#ifndef __ARCH_BFINNOMMU_CPLBTAB_H
#define __ARCH_BFINNOMMU_CPLBTAB_H

#include <linux/config.h>

/*************************************************************************
 *  			ICPLB TABLE					  	
 *************************************************************************/

/*.section .scratch*/		/*Move the entire table into the scratchpad memory*/
.data

/* This table is configurable */ 	

.align 4;

/* Data Attibutes*/
	
#define SDRAM_IGENERIC		(PAGE_SIZE_4MB | CPLB_L1_CHBL | CPLB_USER_RD | CPLB_VALID)

#define SDRAM_GENERIC		(PAGE_SIZE_4MB | CPLB_L1_CHBL | CPLB_USER_RD | ~CPLB_VALID)
#define SDRAM_INON_CHBL  	(PAGE_SIZE_4MB | CPLB_USER_RD | CPLB_VALID)
#define L1_IMEMORY		(PAGE_SIZE_1MB | CPLB_LOCK  | CPLB_VALID)	

.global table_start
table_start:

.global icplb_table
icplb_table:

.byte4 0xFFA00000;
.byte4 (L1_IMEMORY);
.byte4 0x00000000;
.byte4 (SDRAM_IGENERIC);		/*SDRAM_Page1*/
.byte4 0x00400000;
.byte4 (SDRAM_IGENERIC);		/*SDRAM_Page1*/
.byte4 0x00800000;
.byte4 (SDRAM_IGENERIC);		/*SDRAM_Page2*/
.byte4 0x00C00000;
.byte4 (SDRAM_IGENERIC);		/*SDRAM_Page2*/
.byte4 0x01000000;
.byte4 (SDRAM_IGENERIC);		/*SDRAM_Page4*/
.byte4 0x01400000;
.byte4 (SDRAM_IGENERIC);		/*SDRAM_Page5*/
.byte4 0x01800000;
.byte4 (SDRAM_IGENERIC);		/*SDRAM_Page6*/
.byte4 0x01C00000;
.byte4 (SDRAM_IGENERIC);		/*SDRAM_Page7*/
#ifndef CONFIG_EZKIT			/*STAMP Memory regions*/
.byte4 0x02000000;
.byte4 (SDRAM_IGENERIC);		/*SDRAM_Page8*/
.byte4 0x02400000;
.byte4 (SDRAM_IGENERIC);		/*SDRAM_Page9*/
.byte4 0x02800000;
.byte4 (SDRAM_IGENERIC);		/*SDRAM_Page10*/
.byte4 0x02C00000;
.byte4 (SDRAM_IGENERIC);		/*SDRAM_Page11*/
.byte4 0x03000000;
.byte4 (SDRAM_IGENERIC);		/*SDRAM_Page12*/
.byte4 0x03400000;
.byte4 (SDRAM_IGENERIC);		/*SDRAM_Page13*/
.byte4 0x03800000;
.byte4 (SDRAM_IGENERIC);		/*SDRAM_Page14*/
#endif
.byte4 0xffffffff;			/* end of section - termination*/

/*********************************************************************
 *			DCPLB TABLE		
 ********************************************************************/

#define SDRAM_DNON_CHBL		(PAGE_SIZE_1MB | CPLB_SUPV_WR | CPLB_LOCK  | CPLB_VALID)
#define L1_DMEMORY		(PAGE_SIZE_1MB | CPLB_SUPV_WR | CPLB_LOCK  | CPLB_VALID)	

/*Use the menuconfig cache policy here - CONFIG_BLKFIN_WT/CONFIG_BLKFIN_WB*/

#ifdef DCACHE_WB
	#define SDRAM_DGENERIC	(PAGE_SIZE_4MB | CPLB_L1_CHBL | CPLB_DIRTY | CPLB_SUPV_WR | CPLB_USER_WR | CPLB_USER_RD | CPLB_VALID)
#else
	#define SDRAM_DGENERIC	(PAGE_SIZE_4MB | CPLB_L1_CHBL | CPLB_WT | CPLB_SUPV_WR | CPLB_USER_WR | CPLB_USER_RD | CPLB_VALID)
#endif 	/* DCACHE_WB*/

#define SDRAM_EBIU		(PAGE_SIZE_1MB | CPLB_L1_CHBL | CPLB_DIRTY | CPLB_SUPV_WR | CPLB_USER_WR | CPLB_USER_RD | CPLB_VALID)

.global dcplb_table
dcplb_table:
.byte4	0x00000000;
.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page1*/
.byte4	0x00400000; 
.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page1*/
.byte4	0x00800000; 
.byte4 	(SDRAM_DGENERIC);	/*SDRAM_Page2*/
.byte4 	0x00C00000; 
.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page3*/
.byte4	0x01000000;
.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page4*/
.byte4	0x01400000;
.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page5*/
.byte4	0x01800000;
.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page6*/
.byte4	0x01C00000;
.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page7*/
#ifndef CONFIG_EZKIT	
.byte4	0x02000000;
.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page8*/
.byte4	0x02400000;
.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page9*/
.byte4	0x02800000;
.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page10*/
.byte4	0x02C00000;
.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page11*/
.byte4	0x03000000;
.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page12*/
.byte4	0x03400000;
.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page13*/
.byte4	0x03800000;
.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page14*/
.byte4	0x03C00000;
.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page15*/
#endif
.byte4	0xffffffff;		/*end of section - termination*/

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

.global pdt_table;

pdt_table:

.byte4	0x20200000;
.byte4	(SDRAM_DNON_CHBL);	/* Async Memory Bank 2 (Secnd)*/
.byte4	0x20100000;
.byte4	(SDRAM_DNON_CHBL);	/* Async Memory Bank 1 (Prim B)*/
.byte4	0x20000000;	
.byte4	(SDRAM_DNON_CHBL);	/* Async Memory Bank 0 (Prim A)*/
.byte4	0x20300000;		/*Fix for Network*/
.byte4  (SDRAM_DNON_CHBL);	/*Async Memory bank 3*/

#ifdef CONFIG_BLKFIN_STAMP	
.byte4	0x04000000;.byte4  (SDRAM_DNON_CHBL);
//.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page16*/
.byte4	0x04400000;.byte4  (SDRAM_DNON_CHBL);
//.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page17*/
.byte4	0x04800000;.byte4  (SDRAM_DNON_CHBL);
//.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page18*/
.byte4	0x04C00000;.byte4  (SDRAM_DNON_CHBL);
//.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page20*/
.byte4	0x05000000;.byte4  (SDRAM_DNON_CHBL);
//.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page21*/
.byte4	0x05400000;.byte4  (SDRAM_DNON_CHBL);
//.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page22*/
.byte4	0x05800000;.byte4  (SDRAM_DNON_CHBL);
//.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page23*/
.byte4	0x05C00000;.byte4  (SDRAM_DNON_CHBL);
//.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page24*/
.byte4	0x06000000;
.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page25*/
.byte4	0x06400000;
.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page26*/
.byte4	0x06800000;
.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page27*/
.byte4	0x06C00000;
.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page28*/
.byte4	0x07000000;
.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page29*/
.byte4	0x07400000;
.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page30*/
.byte4	0x07800000;
.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page31*/
.byte4	0x07C00000;
.byte4	(SDRAM_DGENERIC);	/*SDRAM_Page32*/
#endif
.byte4	0xffffffff;		/*end of section - termination*/

.global table_end
table_end:

#endif	/*__ARCH_BFINNOMMU_CPLBTAB_H*/
