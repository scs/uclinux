/*
 * File:         include/asm-blackfin/mach-bf535/cdefBF535.h
 * Based on:
 * Author:
 *
 * Created:
 * Description:
 *	include all Core registers and bit definition
 * Rev:
 *
 * Modified:
 *
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

#ifndef _CDEF_BF535_H
#define _CDEF_BF535_H

//
/*
#if defined(__ADSPLPBLACKFIN__)
#warning cdefBF535.h should only be included for 535 compatible chips.
#endif
*/
#include "defBF535.h"

// include core specific register pointer definitions
#include "cdefblackfin.h"

// Clock and System Control (0xFFC0 0400-0xFFC0 07FF)

// JTAG/Debug Communication Channel (0xFFC0 0800-0xFFC0 0BFF)

// System Interrupt Controller (0xFFC0 0C00-0xFFC0 0FFF)
/*
#define SIC_RVECT              0xFFC00C00  // Reset Vector Register
*/

// Watchdog Timer (0xFFC0 1000-0xFFC0 13FF)

// Real Time Clock (0xFFC0 1400-0xFFC0 17FF)

// General Purpose IO (0xFFC0 2400-0xFFC0 27FF)

// Aysnchronous Memory Controller - External Bus Interface Unit (0xFFC0 3C00-0xFFC0 3FFF)

// USB Registers (0xFFC0 4400 - 0xFFC0 47FF)

// SDRAM Controller External Bus Interface Unit (0xFFC0 4C00-0xFFC0 4FFF)

// Memory Map

// Core MMRs

// System MMRs

// L1 cache/SRAM internal memory

// L2 SRAM external memory

// PCI Spaces

// Async Memory Banks

// Sync DRAM Banks

// System MMR Register Map
/*
// L2 MISR MMRs (0xFFC0 0000-0xFFC0 03FF)
#define MISR_CTL               0xFFC00000     // Control Register
#define MISR_RMISR0            0xFFC00004     // coreL2[31:0] read bus
#define MISR_RMISR1            0xFFC00008     // coreL2[63:32] read bus
#define MISR_RMISR2            0xFFC0000C     // sysL2[31:0] read bus
#define MISR_WMISR0            0xFFC00010     // coreL2[31:0] write bus
#define MISR_WMISR1            0xFFC00014     // coreL2[63:32] write bus
#define MISR_WMISR2            0xFFC00018     // sysL2[31:0] write bus
*/

// UART 0 Controller (0xFFC0 1800-0xFFC0 1BFF)

// UART 1 Controller (0xFFC0 1C00-0xFFC0 1FFF)

// TIMER 0, 1, 2 Registers (0xFFC0 2000-0xFFC0 23FF)

// SPORT0 Controller (0xFFC0 2800-0xFFC0 2BFF)

// SPORT1 Controller (0xFFC0 2C00-0xFFC0 2FFF)

// SPI 0 Controller (0xFFC0 3000-0xFFC0 33FF)

// SPI 1 Controller (0xFFC0 3400-0xFFC0 37FF)

// Memory DMA Controller (0xFFC0 3800-0xFFC0 3BFF)

// PCI Bridge PAB Registers (0xFFC0 4000-0xFFC0 43FF)

// PCI Bridge External Access Bus Registers (0xEEFF FF00-0xEEFF FFFF)

// System Bus Interface Unit (0xFFC0 4800-0xFFC0 4FFF)
/*
#define L1SBAR                 0xFFC04840  // L1 SRAM Base Address Register
#define L1CSR                  0xFFC04844  // L1 SRAM Control Initialization Register
*/

#endif				/* _CDEF_BF535_H */
