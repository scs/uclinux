/*
 * Common header file for blackfin family of processors.
 * Copyright (C) 2004 LG Soft India.
 *
 */

#ifndef _BLACKFIN_H_
#define _BLACKFIN_H_

#include <linux/config.h>

#ifdef CONFIG_PUB
/*Include your header file here*/
#endif
#ifdef CONFIG_HAWK
/*Include your header file here*/
#endif
#ifdef CONFIG_EAGLE
/*Include your header file here*/
#endif
#ifdef CONFIG_EZKIT
#include <asm/board/bf533.h>	
#include <asm/board/defBF533.h>
#include <asm/board/cdefBF533.h>
#endif
#ifdef CONFIG_BLKFIN_STAMP
#include <asm/board/bf533.h>	
#include <asm/board/defBF533.h>
#include <asm/board/cdefBF533.h>
#endif
#endif /* _BLACKFIN_H_ */
