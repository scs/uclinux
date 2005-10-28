#ifndef __ARCH_BLACKFIN_CACHE_H
#define __ARCH_BLACKFIN_CACHE_H

/* bytes per L1 cache line */
#define        L1_CACHE_SHIFT  5	/* BlackFin loads 32 bytes for cache */
#define        L1_CACHE_BYTES  (1 << L1_CACHE_SHIFT)

/* For speed we do need to align these ...MaTed---*/
/*  But include/linux/cache.h does this for us if we DO not define ...MaTed---*/
#define __cacheline_aligned	/***** maybe no need this   Tony *****/
#define ____cacheline_aligned

#endif
