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


.section .text;
.global cache_flush;
.global cache_flushinv;

#define LOG_CACHE_LINE_SIZE 5  /* 1 cache line = 32 bytes */
	
/*
 * void cache_flush(void* start, unsigned int size_bytes);
 */


cache_flush:
        R1 = R1 >> LOG_CACHE_LINE_SIZE;  /* count bytes->cache lines */
	P1 = R1; 
        P0 = R0;  /* start */
        LSETUP (_flush_loop, _flush_loop_end) LC0 = P1;
_flush_loop:
	FLUSH[ P0++ ]; 
	csync;    /* cf adsp-bf533-0.1 anomaly list 2003/06/12 13:52  #10 */
_flush_loop_end:	
        RTS;


/*
 * void cache_flushinv(void* start, unsigned int size_bytes);
 */


cache_flushinv:
        R1 = R1 >> LOG_CACHE_LINE_SIZE;  /* count bytes->cache lines */
	P1 = R1; 
        P0 = R0;  /* start */
        LSETUP (_flushinv_loop, _flushinv_loop_end) LC0 = P1;
_flushinv_loop:
	FLUSHINV[ P0++ ];
	csync;    /* cf adsp-bf533-0.1 anomaly list 2003/06/12 13:52  #10 */
_flushinv_loop_end:	
        RTS;
