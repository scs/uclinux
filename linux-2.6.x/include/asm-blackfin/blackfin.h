/*
 * Common header file for blackfin family of processors.
 * Copyright (C) 2004 LG Soft India.
 *
 */

#ifndef _BLACKFIN_H_
#define _BLACKFIN_H_

#include <linux/config.h>

#ifdef CONFIG_BF535
#include <asm/board/bf535.h>	
#include <asm/mem_map.h>	
#include <asm/board/defBF535.h>
#include <asm/board/cdefBF535.h>
#endif
#ifdef CONFIG_BF533
#include <asm/board/bf533.h>	
#include <asm/board/defBF533.h>
#include <asm/board/cdefBF533.h>
#include <asm/mem_map.h>	
#endif
#ifdef CONFIG_BF532
#include <asm/board/bf533.h>	
#include <asm/board/defBF533.h>
#include <asm/board/cdefBF533.h>
#include <asm/mem_map.h>	
#endif
#ifdef CONFIG_BF531
#include <asm/board/bf533.h>	
#include <asm/board/defBF533.h>
#include <asm/board/cdefBF533.h>
#include <asm/mem_map.h>	
#endif
#endif /* _BLACKFIN_H_ */
