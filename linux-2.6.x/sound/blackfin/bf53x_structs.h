/*
 * File:         sound/blackfin/bf53x_structs.h
 * Based on:
 * Author:       Luuk van Dijk, Bas Vermeulen <blackfin@buyways.nl>
 *
 * Created:
 * Description:  bf53x symbols as structs: sport and dma
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright (C) 2003 Luuk van Dijk, Bas Vermeulen BuyWays B.V.
 *               Copyright 2003-2006 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see the file COPYING, or write
 * to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __BF53X_STRUCTS_H__
#define __BF53X_STRUCTS_H__

#include <linux/types.h>
#include <asm/blackfin.h>


// memory mapped register structures

//// SPORT0 Controller (0xFFC00800 - 0xFFC008FF)
//// SPORT1 Controller (0xFFC00900 - 0xFFC009FF)

struct bf53x_sport {
  __u16 TCR1;    __u16 _dum2; // 0x00 Transmit Configuration 1 Register
  __u16 TCR2;    __u16 _dum6; // 0x04 Transmit Configuration 2 Register
  __u16 TCLKDIV; __u16 _duma; // 0x08 Transmit Clock Divider
  __u32 TFSDIV;  __u16 _dume; // 0x0C Transmit Frame Sync Divider
  __u32 TX;                      // 0x10 TX Data Register
  __u32 _dum14;
  __u32 RX;                      // 0x18 RX Data Register
  __u32 _dum1c;

  __u16 RCR1;    __u16 _dum22; // 0x20 Transmit Configuration 1 Register
  __u16 RCR2;    __u16 _dum26; // 0x24 Transmit Configuration 2 Register
  __u16 RCLKDIV; __u16 _dum2a; // 0x28 Receive Clock Divider
  __u16 RFSDIV;  __u16 _dum2e; // 0x2C Receive Frame Sync Divider

  __u16 STAT;    __u16 _dum32; // 0x30 Status Register
  __u16 CHNL;    __u16 _dum36; // 0x34 Current Channel Register
  __u16 MCMC1;   __u16 _dum3a; // 0x38 Multi-Channel Configuration Register 1
  __u16 MCMC2;   __u16 _dum3e; // 0x3C Multi-Channel Configuration Register 2

  __u32 MTCS0;                   // 0x40 Multi-Channel Transmit Select Register 0
  __u32 MTCS1;                   // 0x44 Multi-Channel Transmit Select Register 1
  __u32 MTCS2;                   // 0x48 Multi-Channel Transmit Select Register 2
  __u32 MTCS3;                   // 0x4C Multi-Channel Transmit Select Register 3
  __u32 MRCS0;                   // 0x50 Multi-Channel Receive Select Register 0
  __u32 MRCS1;                   // 0x54 Multi-Channel Receive Select Register 1
  __u32 MRCS2;                   // 0x58 Multi-Channel Receive Select Register 2
  __u32 MRCS3;                   // 0x5C Multi-Channel Receive Select Register 3
};

#define SPORT0 ((struct bf53x_sport*)((unsigned long) SPORT0_TCR1_ADDR)) // 0xFFC00800
#define SPORT1 ((struct bf53x_sport*)((unsigned long) SPORT1_TCR1_ADDR)) // 0xFFC00900



//// DMA Controller (0xFFC00C00 - 0xFFC00FFF (in steps of 0x40))
struct bf53x_dma {
  struct bf53x_dma*  NEXT_DESC_PTR;        // 0x00 Next Descriptor Pointer Register
  void*              START_ADDR;           // 0x04 Start Address Register
  __u16 CONFIG;   __u16 duma;        // 0x08 Configuration Register
  __u32 dumc;
  __u16 X_COUNT;  __u16 dum12;       // 0x10 X Count Register
  __u16 X_MODIFY; __u16 dum16;       // 0x14 X Modify Register
  __u16 Y_COUNT;  __u16 dum1a;       // 0x18 Y Count Register
  __u16 Y_MODIFY; __u16 dum1e;       // 0x1C Y Modify Register
  struct bf53x_dma*  CURR_DESC_PTR;        // 0x20 Current Descriptor Pointer Register
  void*    CURR_ADDR;                      // 0x24 Current Address Register
  __u16 IRQ_STATUS; __u16 dum2a;     // 0x28 Interrupt/Status Register
  __u16 PERIPHERAL_MAP; __u16 dum2e; // 0x2C Peripheral Map Register
  __u16 CURR_X_COUNT; __u16 dum32;   // 0x30 Current X Count Register
  __u16 CURR_Y_COUNT; __u16 dum3a;   // 0x38 Current Y Count Register
  __u32 dum3c;
};

#define DMA0 ((struct bf53x_dma*)((unsigned long) DMA0_NEXT_DESC_PTR_ADDR)) // 0xFFC00C00
#define DMA1 ((struct bf53x_dma*)((unsigned long) DMA1_NEXT_DESC_PTR_ADDR)) // 0xFFC00C40
#define DMA2 ((struct bf53x_dma*)((unsigned long) DMA2_NEXT_DESC_PTR_ADDR)) // 0xFFC00C80
#define DMA3 ((struct bf53x_dma*)((unsigned long) DMA3_NEXT_DESC_PTR_ADDR)) // 0xFFC00CC0
#define DMA4 ((struct bf53x_dma*)((unsigned long) DMA4_NEXT_DESC_PTR_ADDR)) // 0xFFC00D00
#define DMA5 ((struct bf53x_dma*)((unsigned long) DMA5_NEXT_DESC_PTR_ADDR)) // 0xFFC00D40
#define DMA6 ((struct bf53x_dma*)((unsigned long) DMA6_NEXT_DESC_PTR_ADDR)) // 0xFFC00D80
#define DMA7 ((struct bf53x_dma*)((unsigned long) DMA7_NEXT_DESC_PTR_ADDR)) // 0xFFC00DC0

#define MDMA_D0 ((struct bf53x_dma*)((unsigned long) MDMA_D0_NEXT_DESC_PTR_ADDR)) // 0xFFC00E00
#define MDMA_S0 ((struct bf53x_dma*)((unsigned long) MDMA_S0_NEXT_DESC_PTR_ADDR)) // 0xFFC00E40
#define MDMA_D1 ((struct bf53x_dma*)((unsigned long) MDMA_D1_NEXT_DESC_PTR_ADDR)) // 0xFFC00E80
#define MDMA_S1 ((struct bf53x_dma*)((unsigned long) MDMA_S1_NEXT_DESC_PTR_ADDR)) // 0xFFC00EC0

#endif
