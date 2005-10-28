/*
 * File:         include/asm-blackfin/dma.h
 * Based on:     include/asm-m68knommu/dma.h
 * Author:       LG Soft India
 *               Copyright (C) 2004-2005 Analog Devices Inc.
 * Created:      Tue Sep 21 2004
 * Description:  Data structures and register support for DMA on Blackfin
 * Rev:          $Id$
 *
 * Modified:
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.
 * If not, write to the Free Software Foundation,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
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

#endif				/* _BLACKFIN_DMA_H */
