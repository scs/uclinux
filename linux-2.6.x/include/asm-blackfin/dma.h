/*
 * include/asm-blackfin/dma.h
 * Data structures and register support for DMA on Blackfin
 * 
 * Copyright (C) 2004 LG Soft India. 
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or (at your option) any later version as  published by the Free Software 
 * Foundation.
 *
 */

#ifndef _BLACKFIN_DMA_H
#define _BLACKFIN_DMA_H 

#include <linux/config.h>
#include <linux/mm.h>  
#include <asm/blackfin.h>

#define MAX_DMA_ADDRESS PAGE_OFFSET

#if defined (CONFIG_BLKFIN_DMA) 
#include <asm/bf533_dma.h>
#endif

#if defined (CONFIG_BLKFIN_SIMPLE_DMA)
#include <asm/simple_bf533_dma.h>
#endif

#endif /* _BLACKFIN_DMA_H */

