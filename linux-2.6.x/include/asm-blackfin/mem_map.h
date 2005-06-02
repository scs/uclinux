/*
 * mem_map.h 
 * Common header file for blackfin family of processors. 
 *
 */

#ifndef _MEM_MAP_H_
#define _MEM_MAP_H_

#include <linux/config.h>

#ifdef CONFIG_BF535
		#error "Create file !!! mem_map_bf535.h"
#endif

#ifdef CONFIG_BF533
#include <asm/board/mem_map_bf533.h>	
#endif
#ifdef CONFIG_BF532
#include <asm/board/mem_map_bf533.h>	
#endif
#ifdef CONFIG_BF531
#include <asm/board/mem_map_bf533.h>	
#endif

#endif /* _MEM_MAP_H_ */
