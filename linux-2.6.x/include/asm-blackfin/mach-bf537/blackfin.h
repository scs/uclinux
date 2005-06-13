/*
 * Common header file for blackfin family of processors.
 *
 */

#ifndef _MACH_BLACKFIN_H_
#define _MACH_BLACKFIN_H_


#include "bf537.h"	
#include "mem_map.h"
#include "defBF534.h"

#if CONFIG_BF537
#include "defBF537.h"
#endif

#if !(defined(__ASSEMBLY__) || defined(ASSEMBLY)) 
#include "cdefBF534.h"
#if CONFIG_BF537
#include "cdefBF537.h"
#endif
#endif	

#endif /* _MACH_BLACKFIN_H_ */
