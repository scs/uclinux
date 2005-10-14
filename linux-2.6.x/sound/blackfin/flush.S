/*
 *    File:         flush_cache.S
 *    Rev:          $Id$
 *    Created:      Sun May 30 21:14:26 CEST 2004
 *    Author:       Luuk van Dijk, Bas Vermeulen
 *    mail:         lvd@mndmttr.nl
 *    Description:  bcopy by mem-to-mem dma
 *                  does not handle dest/src overlap
 *                  src, dst and count must be word-aligned
 *
 *    Copyright (C) 2004 Luuk van Dijk/Bas Vermeulen
 *                       Mind over Matter/BuyWays B.V.
 *
 */

/*
 * note: it is not clear (to me) wether the bfin ABI requires that LTx, LBx and LCx are preserved!
 */
	
.section .text;
.global _bf53x_cache_flush;
.global _bf53x_cache_flushinv;

#define LOG_CACHE_LINE_SIZE 5  /* 1 cache line = 32 bytes */
	
/*
 * void cache_flush(void* start, unsigned int size_bytes);
 */


_bf53x_cache_flush:
        R1 = R1 >> LOG_CACHE_LINE_SIZE;  /* count bytes->cache lines */
	P1 = R1; 
        P0 = R0;  /* start */
#if 0
	[--SP] = LC0;
	[--SP] = LB0;
	[--SP] = LT0;
#endif
        LSETUP (__flush_loop, __flush_loop_end) LC0 = P1;
__flush_loop:
	FLUSH[ P0++ ]; 
	csync;    /* cf adsp-bf533-0.1 anomaly list 2003/06/12 13:52  #10 */
__flush_loop_end:
	NOP; 
#if 0
	LT0 = [SP++]; 
	LB0 = [SP++]; 
	LC0 = [SP++];
#endif
        RTS;


/*
 * void cache_flushinv(void* start, unsigned int size_bytes);
 */


_bf53x_cache_flushinv:
        R1 = R1 >> LOG_CACHE_LINE_SIZE;  /* count bytes->cache lines */
	P1 = R1; 
        P0 = R0;  /* start */
#if 0
	[--SP] = LC0;
	[--SP] = LB0;
	[--SP] = LT0;	 
#endif
        LSETUP (__flushinv_loop, __flushinv_loop_end) LC0 = P1;
__flushinv_loop:
	FLUSHINV[ P0++ ];
	csync;    /* cf adsp-bf533-0.1 anomaly list 2003/06/12 13:52  #10 */
__flushinv_loop_end:	
	NOP;
#if 0
	LT0 = [SP++]; 
	LB0 = [SP++]; 
	LC0 = [SP++]; 
#endif
        RTS;
