/************************************************************************
 *
 * cplb.h
 *
 * This file is subject to the terms and conditions of the GNU Public 
 * License. See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Non-GPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 *
 * (c) Copyright 2001-2003 Analog Devices, Inc. All rights reserved
 *
 * Revision 1.7 - Thu Oct 30 12:59:34 2003 UTC 
 * This file under source code control, please send bugs or changes to:
 * dsptools.support@analog.com
 *
 ************************************************************************/

/* Defines necessary for cplb initialisation routines. */

#ifndef _CPLB_H
#define _CPLB_H

#if defined(__ADSPBF535__) || defined(__AD6532__)
# include <defblackfin.h>
#else
# include <def_LPBlackfin.h>
#endif

#define CPLB_ENABLE_ICACHE_P	0
#define CPLB_ENABLE_DCACHE_P	1
#define CPLB_ENABLE_DCACHE2_P	2
#define CPLB_ENABLE_CPLBS_P	3	// Deprecated!
#define CPLB_ENABLE_ICPLBS_P	4
#define CPLB_ENABLE_DCPLBS_P	5

#define CPLB_ENABLE_ICACHE	(1<<CPLB_ENABLE_ICACHE_P)
#define CPLB_ENABLE_DCACHE	(1<<CPLB_ENABLE_DCACHE_P)
#define CPLB_ENABLE_DCACHE2	(1<<CPLB_ENABLE_DCACHE2_P)
#define CPLB_ENABLE_CPLBS	(1<<CPLB_ENABLE_CPLBS_P)
#define CPLB_ENABLE_ICPLBS	(1<<CPLB_ENABLE_ICPLBS_P)
#define CPLB_ENABLE_DCPLBS	(1<<CPLB_ENABLE_DCPLBS_P)
#define CPLB_ENABLE_ANY_CPLBS	CPLB_ENABLE_CPLBS | \
				CPLB_ENABLE_ICPLBS | \
				CPLB_ENABLE_DCPLBS

#define CPLB_RELOADED		0x0000
#define CPLB_NO_UNLOCKED	0x0001
#define CPLB_NO_ADDR_MATCH	0x0002
#define CPLB_PROT_VIOL		0x0003

#define CPLB_DEF_CACHE		CPLB_L1_CHBL | CPLB_WT
#define CPLB_CACHE_ENABLED	CPLB_L1_CHBL | CPLB_DIRTY

#define CPLB_ALL_ACCESS	CPLB_SUPV_WR | CPLB_USER_RD | CPLB_USER_WR

#define CPLB_I_PAGE_MGMT	CPLB_LOCK | CPLB_VALID
#define CPLB_D_PAGE_MGMT	CPLB_LOCK | CPLB_ALL_ACCESS | CPLB_VALID
#define CPLB_DNOCACHE		CPLB_ALL_ACCESS | CPLB_VALID
#define CPLB_DDOCACHE		CPLB_DNOCACHE | CPLB_DEF_CACHE
#define CPLB_INOCACHE   	CPLB_USER_RD | CPLB_VALID
#define CPLB_IDOCACHE   	CPLB_INOCACHE | CPLB_L1_CHBL

#endif /* _CPLB_H */
