#ifndef _BFINNOMMU_DELAY_H
#define _BFINNOMMU_DELAY_H

/*
 * Copyright (C) 1994 Hamish Macdonald
 *
 * Delay routines, using a pre-computed "loops_per_second" value.
 */

extern __inline__ void __delay(unsigned long loops)
{
	__asm__ __volatile__ (	"1:\t cc = %0 == 0;\n\t"
				"%0 += -1;\n\t"
				"if ! cc jump 1b;\n"
				: "=d" (loops) 
				: "0" (loops));
}

#include <linux/param.h> /* need for HZ */

/*
 * Use only for very small delays ( < 1 msec).  Should probably use a
 * lookup table, really, as the multiplications take much too long with
 * short delays.  This is a "reasonable" implementation, though (and the
 * first constant multiplications gets optimized away if the delay is
 * a constant)  
 */
extern __inline__ void udelay(unsigned long usecs)
{
	  extern unsigned long loops_per_jiffy;
       __delay(usecs * loops_per_jiffy / (1000000/HZ));
}


#endif /* defined(_BFINNOMMU_DELAY_H) */
